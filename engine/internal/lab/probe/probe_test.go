// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package probe

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"vpnw.com/vpnw/internal/lab"
	"vpnw.com/vpnw/internal/lab/wire"
)

// local is a stand-in for the observers, the resolver and a SOCKS5 proxy,
// all on 127.0.0.1.
type local struct {
	mu      sync.Mutex
	tags    []wire.Probe // TCP and UDP tags, from either path
	names   []string     // DNS names asked about
	targets []string     // what the proxy was asked to connect to

	tcp, socks net.Listener
	udp, dns   *net.UDPConn
	user, pass string // the proxy's password, if it wants one
	refuse     byte   // the proxy's reply to every CONNECT, 0 to accept
}

func startLocal(t *testing.T) *local {
	t.Helper()
	l := &local{}
	var err error
	if l.tcp, err = net.Listen("tcp4", "127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	if l.socks, err = net.Listen("tcp4", "127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	if l.udp, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}); err != nil {
		t.Fatal(err)
	}
	if l.dns, err = net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.tcp.Close(); l.socks.Close(); l.udp.Close(); l.dns.Close() })
	go func() {
		for {
			c, err := l.tcp.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				line, _ := bufio.NewReader(c).ReadString('\n')
				l.tag(line)
			}()
		}
	}()
	go func() {
		buf := make([]byte, 512)
		for {
			n, _, err := l.udp.ReadFrom(buf)
			if err != nil {
				return
			}
			l.tag(string(buf[:n]))
		}
	}()
	go func() {
		buf := make([]byte, 512)
		for {
			n, from, err := l.dns.ReadFromUDPAddrPort(buf)
			if err != nil {
				return
			}
			if q, err := wire.ParseQuery(buf[:n]); err == nil {
				l.mu.Lock()
				l.names = append(l.names, q.Name)
				l.mu.Unlock()
				l.dns.WriteToUDPAddrPort(wire.Answer(buf[:n], q, wire.RcodeOK, netip.MustParseAddr("127.0.0.1"), 1), from)
			}
		}
	}()
	go func() {
		for {
			c, err := l.socks.Accept()
			if err != nil {
				return
			}
			go l.serveSOCKS(c)
		}
	}()
	return l
}

func (l *local) tag(s string) {
	if p, err := wire.ParseTag(s); err == nil {
		l.mu.Lock()
		l.tags = append(l.tags, p)
		l.mu.Unlock()
	}
}

func (l *local) port(ln net.Listener) uint16 { return uint16(ln.Addr().(*net.TCPAddr).Port) }

// serveSOCKS is a small SOCKS5 server that hands the connection's first line
// to the TCP observer's tag reader.
func (l *local) serveSOCKS(c net.Conn) {
	defer c.Close()
	var h [2]byte
	if _, err := io.ReadFull(c, h[:]); err != nil {
		return
	}
	methods := make([]byte, h[1])
	io.ReadFull(c, methods)
	want := byte(0)
	if l.user != "" {
		want = 2
	}
	c.Write([]byte{5, want})
	if want == 2 {
		var v [2]byte
		io.ReadFull(c, v[:])
		user := make([]byte, v[1])
		io.ReadFull(c, user)
		var pl [1]byte
		io.ReadFull(c, pl[:])
		pass := make([]byte, pl[0])
		io.ReadFull(c, pass)
		if string(user) != l.user || string(pass) != l.pass {
			c.Write([]byte{1, 1})
			return
		}
		c.Write([]byte{1, 0})
	}
	var req [4]byte
	io.ReadFull(c, req[:])
	host := ""
	switch req[3] {
	case 1:
		var a [4]byte
		io.ReadFull(c, a[:])
		host = netip.AddrFrom4(a).String()
	case 3:
		var n [1]byte
		io.ReadFull(c, n[:])
		b := make([]byte, n[0])
		io.ReadFull(c, b)
		host = string(b)
	}
	var p [2]byte
	io.ReadFull(c, p[:])
	l.mu.Lock()
	l.targets = append(l.targets, host)
	l.mu.Unlock()
	if l.refuse != 0 {
		c.Write([]byte{5, l.refuse, 0, 1, 0, 0, 0, 0, 0, 0})
		return
	}
	c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 80})
	line, _ := bufio.NewReader(c).ReadString('\n')
	l.tag(line)
}

func resolvFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "resolv.conf")
	if err := os.WriteFile(p, []byte("nameserver 127.0.0.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestRunSendsEveryKind(t *testing.T) {
	l := startLocal(t)
	var log bytes.Buffer
	start := time.Now()
	o := Options{Run: "r-test", Interval: 20 * time.Millisecond, Epoch: start, Until: start.Add(200 * time.Millisecond),
		Resolv: resolvFile(t), Target: netip.MustParseAddr("127.0.0.1"), TCPPort: l.port(l.tcp),
		UDPPort: uint16(l.udp.LocalAddr().(*net.UDPAddr).Port), DNSPort: uint16(l.dns.LocalAddr().(*net.UDPAddr).Port),
		Direct: true, Proxy: "socks5h://127.0.0.1:" + itoa(l.port(l.socks))}
	st, err := Run(o, &log, nil)
	if err != nil {
		t.Fatal(err)
	}
	if st.Ticks < 5 || st.Ticks > 11 || st.Sent != 5*st.Ticks {
		t.Fatalf("stats: %+v", st)
	}
	kinds := map[string]int{}
	_, err = lab.ReadEvents(&log, "probe.jsonl", func(e lab.Event) error {
		if e.Ev != lab.EvSent || e.T.Before(start.Add(-time.Millisecond)) {
			t.Errorf("bad line: %+v", e)
		}
		kinds[e.Kind+" "+e.Via]++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"dns direct", "tcp direct", "udp direct", "tcp proxy", "dns proxy"} {
		if kinds[k] != st.Ticks {
			t.Errorf("%s: %d lines for %d ticks", k, kinds[k], st.Ticks)
		}
	}
	time.Sleep(100 * time.Millisecond)
	l.mu.Lock()
	defer l.mu.Unlock()
	got := map[string]int{}
	for _, p := range l.tags {
		if p.Run != "r-test" {
			t.Errorf("tag of another run: %+v", p)
		}
		got[p.Kind+" "+p.Via]++
	}
	if got["tcp direct"] != st.Ticks || got["udp direct"] != st.Ticks || got["tcp proxy"] != st.Ticks || got["dns proxy"] != st.Ticks {
		t.Errorf("tags: %v for %d ticks", got, st.Ticks)
	}
	if len(l.names) != st.Ticks || !strings.HasPrefix(l.names[0], "d") || !strings.HasSuffix(l.names[0], ".r-test.lab.test") {
		t.Errorf("DNS names: %v", l.names)
	}
	byName := 0
	for _, h := range l.targets {
		if strings.HasPrefix(h, "p") && strings.HasSuffix(h, ".lab.test") {
			byName++
		}
	}
	if byName != st.Ticks {
		t.Errorf("the proxy resolved %d names for %d ticks: %v", byName, st.Ticks, l.targets)
	}
}

func itoa(n uint16) string { return strconv.Itoa(int(n)) }

// TestRestartedProbeGoesOnCounting starts a probe after its epoch: its
// first sequence number follows on from the time that has passed.
func TestRestartedProbeGoesOnCounting(t *testing.T) {
	l := startLocal(t)
	var log bytes.Buffer
	epoch := time.Now().Add(-time.Second)
	o := Options{Run: "r-late", Interval: 50 * time.Millisecond, Epoch: epoch, Until: time.Now().Add(60 * time.Millisecond),
		Resolv: filepath.Join(t.TempDir(), "missing"), Target: netip.MustParseAddr("127.0.0.1"), TCPPort: l.port(l.tcp),
		UDPPort: uint16(l.udp.LocalAddr().(*net.UDPAddr).Port), Direct: true}
	if _, err := Run(o, &log, nil); err != nil {
		t.Fatal(err)
	}
	first := -1
	lab.ReadEvents(&log, "p", func(e lab.Event) error {
		if first < 0 {
			first = e.Seq
		}
		if e.Kind == lab.DNS {
			t.Error("a DNS probe without a resolver setting")
		}
		return nil
	})
	if first < 20 {
		t.Fatalf("first sequence number %d, want about 21", first)
	}
}

type slowWriter struct {
	once sync.Once
	buf  bytes.Buffer
}

func (s *slowWriter) Write(p []byte) (int, error) {
	s.once.Do(func() { time.Sleep(60 * time.Millisecond) })
	return s.buf.Write(p)
}

// TestStallSkipsAhead stalls the probe on its first write: it skips the
// ticks it missed instead of sending them in a burst.
func TestStallSkipsAhead(t *testing.T) {
	l := startLocal(t)
	var w slowWriter
	start := time.Now()
	o := Options{Run: "r-stall", Interval: 5 * time.Millisecond, Epoch: start, Until: start.Add(100 * time.Millisecond),
		Target: netip.MustParseAddr("127.0.0.1"), UDPPort: uint16(l.udp.LocalAddr().(*net.UDPAddr).Port), TCPPort: l.port(l.tcp), Direct: true}
	st, err := Run(o, &w, nil)
	if err != nil {
		t.Fatal(err)
	}
	if st.Ticks >= 20 {
		t.Fatalf("%d ticks: the stall's ticks were sent anyway", st.Ticks)
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestRunErrorsAndStop(t *testing.T) {
	base := Options{Run: "r", Interval: 10 * time.Millisecond, Target: netip.MustParseAddr("127.0.0.1"), TCPPort: 9, UDPPort: 9, Direct: true}
	for want, o := range map[string]Options{
		"run id":          func() Options { o := base; o.Run = "R!"; return o }(),
		"interval":        func() Options { o := base; o.Interval = 0; return o }(),
		"nothing to send": func() Options { o := base; o.Direct = false; return o }(),
		"only socks5":     func() Options { o := base; o.Proxy = "http://127.0.0.1:3128"; return o }(),
		"disk full":       base,
	} {
		o.Epoch = time.Now()
		o.Until = o.Epoch.Add(30 * time.Millisecond)
		if _, err := Run(o, failWriter{}, nil); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("want %q, got %v", want, err)
		}
	}
	stop := make(chan struct{})
	close(stop)
	o := base
	o.Epoch = time.Now().Add(time.Hour)
	if st, err := Run(o, io.Discard, stop); err != nil || st.Ticks != 0 {
		t.Fatalf("a stopped probe: %+v %v", st, err)
	}
	o.Epoch = time.Now().Add(-time.Hour)
	if st, err := Run(o, io.Discard, stop); err != nil || st.Ticks != 0 {
		t.Fatalf("a stopped probe that is behind: %+v %v", st, err)
	}
}

func TestParseProxy(t *testing.T) {
	p, err := ParseProxy("socks5h://vpnw:s3cret@127.0.0.1:1080")
	if err != nil || p.Addr != "127.0.0.1:1080" || p.User != "vpnw" || p.Pass != "s3cret" {
		t.Fatalf("%v %+v", err, p)
	}
	if p, err := ParseProxy("socks5://[::1]:9"); err != nil || p.User != "" {
		t.Fatalf("%v %+v", err, p)
	}
	for _, raw := range []string{"", "127.0.0.1:1080", "http://127.0.0.1:3128", "socks5://127.0.0.1", "socks5://" + strings.Repeat("u", 256) + "@h:1", "socks5://%zz"} {
		if _, err := ParseProxy(raw); err == nil {
			t.Errorf("ParseProxy(%q) should fail", raw)
		}
	}
}

func TestConnect(t *testing.T) {
	l := startLocal(t)
	addr := "127.0.0.1:" + itoa(l.port(l.socks))
	px := Proxy{Addr: addr}
	c, err := px.Connect("198.51.100.10", 80, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	c, err = px.Connect("p1.r.lab.test", 80, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if _, err := px.Connect(strings.Repeat("a", 256), 80, time.Second); err == nil {
		t.Fatal("a 256-character name")
	}
	l.user, l.pass = "vpnw", "token"
	if _, err := px.Connect("1.2.3.4", 80, time.Second); err == nil || !strings.Contains(err.Error(), "authentication method") {
		t.Fatalf("no password offered: %v", err)
	}
	if _, err := (Proxy{Addr: addr, User: "vpnw", Pass: "wrong"}).Connect("1.2.3.4", 80, time.Second); err == nil || !strings.Contains(err.Error(), "user name and password") {
		t.Fatalf("wrong password: %v", err)
	}
	c, err = (Proxy{Addr: addr, User: "vpnw", Pass: "token"}).Connect("1.2.3.4", 80, time.Second)
	if err != nil {
		t.Fatalf("right password: %v", err)
	}
	c.Close()
	l.user, l.refuse = "", 5
	if _, err := px.Connect("1.2.3.4", 80, time.Second); err == nil || !strings.Contains(err.Error(), "reply 5") {
		t.Fatalf("a refusal: %v", err)
	}
	if _, err := (Proxy{Addr: "127.0.0.1:1"}).Connect("1.2.3.4", 80, 200*time.Millisecond); err == nil {
		t.Fatal("no proxy there")
	}
}

// TestReplyAddressTypes answers with each kind of bound address.
func TestReplyAddressTypes(t *testing.T) {
	for _, tail := range [][]byte{
		append([]byte{4}, make([]byte, 18)...),
		{3, 3, 'a', 'b', 'c', 0, 80},
		{9},
	} {
		ln, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		go func(tail []byte) {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			defer c.Close()
			buf := make([]byte, 64)
			c.Read(buf)
			c.Write([]byte{5, 0})
			c.Read(buf)
			c.Write(append([]byte{5, 0, 0}, tail...))
			time.Sleep(100 * time.Millisecond)
		}(tail)
		_, err = (Proxy{Addr: ln.Addr().String()}).Connect("1.2.3.4", 80, time.Second)
		if (tail[0] == 9) != (err != nil) {
			t.Errorf("address type %d: %v", tail[0], err)
		}
		ln.Close()
	}
}
