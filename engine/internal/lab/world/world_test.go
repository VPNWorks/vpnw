// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package world

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"vpnw.com/vpnw/internal/lab"
	"vpnw.com/vpnw/internal/lab/netlink"
	"vpnw.com/vpnw/internal/lab/wire"
	"vpnw.com/vpnw/internal/testnet"
)

func TestMain(m *testing.M) {
	if err := testnet.Reexec(); err != nil {
		fmt.Println("world tests need user namespaces, skipping:", err)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func build(t *testing.T) *World {
	t.Helper()
	if err := Check(); err != nil {
		t.Skip(err)
	}
	w, err := Build(filepath.Join(t.TempDir(), "run"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.Close)
	return w
}

// waitFor waits until the observers saw n arrivals of the run.
func waitFor(t *testing.T, w *World, run string, n int) []lab.Event {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		got := w.Arrivals(run)
		if len(got) >= n {
			return got
		}
		if time.Now().After(deadline) {
			t.Fatalf("waited for %d arrivals of %s, got %d: %+v", n, run, len(got), got)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func dialIn(t *testing.T, ns *testnet.NS, network, addr string) net.Conn {
	t.Helper()
	var c net.Conn
	err := ns.Do(func() (err error) {
		c, err = net.DialTimeout(network, addr, 3*time.Second)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestDirectTraffic sends a probe of each kind from the device with no VPN
// in the way: everything arrives from the home network's address, and the
// DNS query is seen at the home router's resolver as well.
func TestDirectTraffic(t *testing.T) {
	w := build(t)
	run := "r-direct"
	c := dialIn(t, w.Device, "udp4", "198.51.100.10:9")
	c.Write([]byte(wire.Probe{Kind: lab.UDP, Via: lab.Direct, Run: run, Seq: 1}.Tag()))
	c.Close()
	c = dialIn(t, w.Device, "tcp4", "198.51.100.10:80")
	c.Write([]byte(wire.Probe{Kind: lab.TCP, Via: lab.Direct, Run: run, Seq: 2}.Tag()))
	c.Close()
	ns, err := ReadResolv(w.Resolv)
	if err != nil || ns != RouterAddr {
		t.Fatalf("the device's resolver: %v %v", ns, err)
	}
	c = dialIn(t, w.Device, "udp4", netip.AddrPortFrom(ns, 53).String())
	q, _ := wire.Query(42, wire.Probe{Kind: lab.DNS, Via: lab.Direct, Run: run, Seq: 3}.Name())
	c.Write(q)
	c.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 512)
	n, err := c.Read(buf)
	c.Close()
	if err != nil {
		t.Fatal(err)
	}
	if r, err := wire.ParseAnswer(buf[:n]); err != nil || r.ID != 42 || len(r.Addrs) != 1 || r.Addrs[0] != Observer {
		t.Fatalf("answer: %v %+v", err, r)
	}
	got := waitFor(t, w, run, 4)
	want := map[string]netip.Addr{"udp 1 udp": HomePublic, "tcp 2 tcp": HomePublic, "dns 3 home-dns": DeviceAddr, "dns 3 zone-dns": HomePublic}
	for _, a := range got {
		k := fmt.Sprintf("%s %d %s", a.Kind, a.Seq, a.At)
		if want[k] != a.Src {
			t.Errorf("%s from %s, want %s", k, a.Src, want[k])
		}
		h := Header(run, "none", "steady", 1, 50)
		if lab.Classify(h, a) != lab.Outside {
			t.Errorf("%s classified as through the tunnel", k)
		}
	}
	if len(w.Arrivals("r-other")) != 0 {
		t.Fatal("arrivals of another run")
	}
}

// ipv4UDP builds an IPv4 UDP packet with a valid header checksum and no UDP
// checksum.
func ipv4UDP(src, dst netip.AddrPort, payload []byte) []byte {
	b := make([]byte, 28+len(payload))
	b[0], b[8], b[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	s, d := src.Addr().As4(), dst.Addr().As4()
	copy(b[12:], s[:])
	copy(b[16:], d[:])
	var sum uint32
	for i := 0; i < 20; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i:]))
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	binary.BigEndian.PutUint16(b[10:], ^uint16(sum))
	binary.BigEndian.PutUint16(b[20:], src.Port())
	binary.BigEndian.PutUint16(b[22:], dst.Port())
	binary.BigEndian.PutUint16(b[24:], uint16(8+len(payload)))
	copy(b[28:], payload)
	return b
}

func exchange(t *testing.T, c net.Conn, typ byte, want byte) []byte {
	t.Helper()
	nonce := []byte("01234567")
	c.Write(wire.AppendFrame(nil, typ, nonce))
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 2048)
	for {
		n, err := c.Read(buf)
		if err != nil {
			t.Fatalf("frame %d: no answer: %v", typ, err)
		}
		got, payload, err := wire.ParseFrame(buf[:n])
		if err == nil && got == want {
			return append([]byte(nil), payload...)
		}
	}
}

// TestTunnelServer speaks the tunnel's frames to the stand-in server: a
// handshake, a keepalive, a UDP probe and a DNS query carried inside, which
// arrive from the exit address and at the VPN's resolver.
func TestTunnelServer(t *testing.T) {
	w := build(t)
	run := "r-tunnel"
	c := dialIn(t, w.Device, "udp4", "192.0.2.10:51820")
	defer c.Close()
	if got := exchange(t, c, wire.Hello, wire.Welcome); string(got) != "01234567" {
		t.Fatalf("welcome %q", got)
	}
	exchange(t, c, wire.Ping, wire.Pong)
	me := netip.AddrPortFrom(TunnelAddr, 40000)
	tag := wire.Probe{Kind: lab.UDP, Via: lab.Direct, Run: run, Seq: 7}.Tag()
	c.Write(wire.AppendFrame(nil, wire.Data, ipv4UDP(me, netip.AddrPortFrom(Observer, UDPPort), []byte(tag))))
	q, _ := wire.Query(9, wire.Probe{Kind: lab.DNS, Via: lab.Direct, Run: run, Seq: 7}.Name())
	c.Write(wire.AppendFrame(nil, wire.Data, ipv4UDP(me, netip.AddrPortFrom(TunnelPeer, 53), q)))
	// The resolver's answer comes back through the tunnel.
	pkt := exchange(t, c, wire.Data+0, wire.Data)
	if len(pkt) < 28 || netip.AddrFrom4([4]byte(pkt[12:16])) != TunnelPeer || binary.BigEndian.Uint16(pkt[20:]) != 53 {
		t.Fatalf("not the resolver's answer: %x", pkt)
	}
	if r, err := wire.ParseAnswer(pkt[28:]); err != nil || r.ID != 9 || r.Addrs[0] != Observer {
		t.Fatalf("answer: %v %+v", err, r)
	}
	got := waitFor(t, w, run, 3)
	h := Header(run, "x", "steady", 1, 50)
	for _, a := range got {
		if lab.Classify(h, a) != lab.Tunnel {
			t.Errorf("%s at %s from %s: not through the tunnel", a.Kind, a.At, a.Src)
		}
	}
	st := w.ServerStats()
	if st.Hellos != 1 || st.Pings != 1 || st.In != 2 || st.Out < 1 {
		t.Fatalf("server stats: %+v", st)
	}
}

// TestServerFaults turns the server silent, then gone, then back.
func TestServerFaults(t *testing.T) {
	w := build(t)
	c := dialIn(t, w.Device, "udp4", "192.0.2.10:51820")
	defer c.Close()
	exchange(t, c, wire.Ping, wire.Pong)
	if err := w.SetServerFault(ServerSilent); err != nil {
		t.Fatal(err)
	}
	c.Write(wire.AppendFrame(nil, wire.Ping, []byte("silent!!")))
	// A silent server passes nothing on either: a probe carried in a frame
	// must not arrive.
	run := "r-faults"
	me := netip.AddrPortFrom(TunnelAddr, 40000)
	carry := func(seq int) {
		tag := wire.Probe{Kind: lab.UDP, Via: lab.Direct, Run: run, Seq: seq}.Tag()
		c.Write(wire.AppendFrame(nil, wire.Data, ipv4UDP(me, netip.AddrPortFrom(Observer, UDPPort), []byte(tag))))
	}
	carry(1)
	c.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	if _, err := c.Read(make([]byte, 64)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("a silent server answered: %v", err)
	}
	if got := w.Arrivals(run); len(got) != 0 {
		t.Fatalf("a silent server passed a probe on: %+v", got)
	}
	if err := w.SetServerFault(ServerGone); err != nil {
		t.Fatal(err)
	}
	c.Write(wire.AppendFrame(nil, wire.Ping, []byte("gone!!!!")))
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Read(make([]byte, 64)); !errors.Is(err, syscall.ECONNREFUSED) {
		t.Fatalf("a gone server should refuse: %v", err)
	}
	carry(2)
	// Its refusal comes back too; read it so the socket is clean again.
	c.SetReadDeadline(time.Now().Add(time.Second))
	c.Read(make([]byte, 64))
	err := w.Device.Do(func() error {
		_, err := net.DialTimeout("tcp4", "192.0.2.10:1080", 2*time.Second)
		return err
	})
	if !errors.Is(err, syscall.ECONNREFUSED) {
		t.Fatalf("the proxy of a gone server should refuse: %v", err)
	}
	time.Sleep(200 * time.Millisecond)
	if got := w.Arrivals(run); len(got) != 0 {
		t.Fatalf("a gone server passed a probe on: %+v", got)
	}
	if err := w.SetServerFault(""); err != nil {
		t.Fatal(err)
	}
	exchange(t, c, wire.Ping, wire.Pong)
	carry(3)
	if got := waitFor(t, w, run, 1); got[0].Seq != 3 {
		t.Fatalf("after the fault: %+v", got)
	}
	if err := w.SetServerFault("flood"); err == nil {
		t.Fatal("an unknown fault")
	}
}

func socksConnect(t *testing.T, w *World, atyp byte, addr []byte, port uint16, cmd byte) (net.Conn, byte) {
	t.Helper()
	c := dialIn(t, w.Device, "tcp4", "192.0.2.10:1080")
	c.SetDeadline(time.Now().Add(5 * time.Second))
	c.Write([]byte{5, 1, 0})
	var m [2]byte
	if _, err := io.ReadFull(c, m[:]); err != nil || m != [2]byte{5, 0} {
		t.Fatalf("method: %v %v", err, m)
	}
	req := append([]byte{5, cmd, 0, atyp}, addr...)
	req = binary.BigEndian.AppendUint16(req, port)
	c.Write(req)
	var rep [10]byte
	if _, err := io.ReadFull(c, rep[:]); err != nil {
		t.Fatalf("reply: %v", err)
	}
	return c, rep[1]
}

// TestProxy connects through the SOCKS5 proxy by address and by name.
func TestProxy(t *testing.T) {
	w := build(t)
	run := "r-proxy"
	obs := Observer.As4()
	c, code := socksConnect(t, w, 1, obs[:], TCPPort, 1)
	if code != 0 {
		t.Fatalf("connect by address: reply %d", code)
	}
	c.Write([]byte(wire.Probe{Kind: lab.TCP, Via: lab.Proxy, Run: run, Seq: 1}.Tag()))
	c.Close()
	name := wire.Probe{Kind: lab.DNS, Via: lab.Proxy, Run: run, Seq: 2}.Name()
	c, code = socksConnect(t, w, 3, append([]byte{byte(len(name))}, name...), TCPPort, 1)
	if code != 0 {
		t.Fatalf("connect by name: reply %d", code)
	}
	c.Write([]byte(wire.Probe{Kind: lab.DNS, Via: lab.Proxy, Run: run, Seq: 2}.Tag()))
	c.Close()
	got := waitFor(t, w, run, 3)
	for _, a := range got {
		if a.Src != ExitAddr || a.Via != lab.Proxy {
			t.Errorf("%+v: want it from the exit address", a)
		}
	}
	bad := "nowhere.example"
	if c, code := socksConnect(t, w, 3, append([]byte{byte(len(bad))}, bad...), TCPPort, 1); code != socksHostUnreach {
		t.Errorf("a name outside the zone: reply %d", code)
	} else {
		c.Close()
	}
	if c, code := socksConnect(t, w, 1, obs[:], TCPPort, 2); code != socksNoCommand {
		t.Errorf("BIND: reply %d", code)
	} else {
		c.Close()
	}
	if c, code := socksConnect(t, w, 1, obs[:], 81, 1); code != socksRefused {
		t.Errorf("a closed port: reply %d", code)
	} else {
		c.Close()
	}
	if c, code := socksConnect(t, w, 4, make([]byte, 16), 80, 1); code != socksNoAddress {
		t.Errorf("IPv6: reply %d", code)
	} else {
		c.Close()
	}
	c = dialIn(t, w.Device, "tcp4", "192.0.2.10:1080")
	c.SetDeadline(time.Now().Add(3 * time.Second))
	c.Write([]byte{5, 1, 2})
	var m [2]byte
	if _, err := io.ReadFull(c, m[:]); err != nil || m[1] != 0xff {
		t.Errorf("a client that offers only passwords: %v %v", err, m)
	}
	c.Close()
}

// TestDeviceChanges drops and restores the link, pushes and withdraws a
// route, and changes the DNS server.
func TestDeviceChanges(t *testing.T) {
	w := build(t)
	routes := func() string {
		var rs []netlink.Route
		w.Device.Do(func() (err error) { rs, err = netlink.Routes(0); return err })
		var s []string
		for _, r := range rs {
			s = append(s, r.String())
		}
		return strings.Join(s, "; ")
	}
	if r := routes(); !strings.Contains(r, "default via 192.168.1.1 dev eth0") {
		t.Fatalf("no default route: %s", r)
	}
	if err := w.LinkDown(); err != nil {
		t.Fatal(err)
	}
	if r := routes(); strings.Contains(r, "eth0") {
		t.Fatalf("routes through a link that is down: %s", r)
	}
	if err := w.LinkUp(); err != nil {
		t.Fatal(err)
	}
	if err := w.LinkUp(); err != nil {
		t.Fatalf("a second LinkUp: %v", err)
	}
	if r := routes(); !strings.Contains(r, "default via 192.168.1.1 dev eth0") {
		t.Fatalf("the default route did not come back: %s", r)
	}
	if err := w.PushRoute(true); err != nil {
		t.Fatal(err)
	}
	if r := routes(); !strings.Contains(r, "198.51.100.0/24 via 192.168.1.1 dev eth0") {
		t.Fatalf("no pushed route: %s", r)
	}
	if err := w.PushRoute(false); err != nil {
		t.Fatal(err)
	}
	if err := w.PushRoute(false); err == nil {
		t.Fatal("withdrawing a route that isn't there")
	}
	if err := w.SetDNS(RouterDNS2); err != nil {
		t.Fatal(err)
	}
	if a, err := ReadResolv(w.Resolv); err != nil || a != RouterDNS2 {
		t.Fatalf("%v %v", a, err)
	}
	b, _ := os.ReadFile(w.Resolv)
	if string(b) != "nameserver 192.168.1.53\n" {
		t.Fatalf("resolv.conf: %q", b)
	}
	// The second resolver address answers, and records.
	c := dialIn(t, w.Device, "udp4", "192.168.1.53:53")
	q, _ := wire.Query(1, wire.Probe{Kind: lab.DNS, Via: lab.Direct, Run: "r-dns2", Seq: 0}.Name())
	c.Write(q)
	c.Close()
	if got := waitFor(t, w, "r-dns2", 2); got[0].At != lab.AtHomeDNS {
		t.Fatalf("%+v", got)
	}
}

func TestResolvFiles(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "resolv.conf")
	for content, want := range map[string]string{
		"# nothing\n":                "no nameserver line",
		"search lab\nnameserver x\n": "resolv.conf:2: \"x\" is not an IPv4 address",
		"nameserver 2001:db8::1\n":   "is not an IPv4 address",
		"options x\nnameserver 10.0.0.1\nnameserver 10.0.0.2\n": "",
	} {
		os.WriteFile(p, []byte(content), 0o644)
		a, err := ReadResolv(p)
		if want == "" {
			if err != nil || a.String() != "10.0.0.1" {
				t.Errorf("%q: %v %v", content, a, err)
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v, want %q", content, err, want)
		}
	}
	if _, err := ReadResolv(filepath.Join(dir, "missing")); err == nil {
		t.Fatal("a missing file")
	}
	if err := WriteResolv(filepath.Join(dir, "no", "such", "dir"), RouterAddr); err == nil {
		t.Fatal("a missing directory")
	}
	h := Header("r-1", "correct", "steady", 3, 50)
	if h.Exit != ExitAddr || h.Home != HomePublic || h.Check() == nil {
		// Check fails only for the missing time.
		t.Fatalf("%+v", h)
	}
	h.T = time.Now()
	if err := h.Check(); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	buf.Write(h.AppendJSON(nil))
	if !strings.Contains(buf.String(), `"exit":"192.0.2.20","home":"203.0.113.2"`) {
		t.Fatal(buf.String())
	}
}

// TestForwarder asks the zone's name server through a forwarder: an
// answer comes back with the query's own id, a message too short to be DNS
// is refused, one the server ignores times out, and old entries go.
func TestForwarder(t *testing.T) {
	w := build(t)
	q, _ := wire.Query(4242, "anything."+wire.Zone)
	ans, err := w.exitDNS.query(q)
	if err != nil {
		t.Fatal(err)
	}
	if r, err := wire.ParseAnswer(ans); err != nil || r.ID != 4242 || r.Addrs[0] != Observer {
		t.Fatalf("%v %+v", err, r)
	}
	if err := w.exitDNS.ask([]byte{1, 2, 3}, nil); err == nil {
		t.Fatal("a short message was sent on")
	}
	bad := append([]byte{}, q...)
	bad[2] |= 0x80 // a response: the name server ignores it
	if _, err := w.exitDNS.query(bad); err == nil || !strings.Contains(err.Error(), "no answer") {
		t.Fatalf("an ignored query: %v", err)
	}
	w.exitDNS.mu.Lock()
	w.exitDNS.pending[9999] = pending{at: time.Now().Add(-time.Hour)}
	w.exitDNS.mu.Unlock()
	w.exitDNS.query(q)
	w.exitDNS.mu.Lock()
	_, stale := w.exitDNS.pending[9999]
	w.exitDNS.mu.Unlock()
	if stale {
		t.Fatal("an old entry stayed")
	}
}
