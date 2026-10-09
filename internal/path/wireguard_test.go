// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package path_test

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/VPNWorks/vpnw/internal/path"
	"github.com/VPNWorks/vpnw/internal/path/wgtest"
)

func TestParseWGConf(t *testing.T) {
	good := `# from a provider
[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = 10.64.0.2/32, fc00:bbbb::2/128
DNS = 10.64.0.1, corp.example
MTU = 1380

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
PresharedKey = /UwcSPg38hW/D9Y3tcS1FOV0K1wuURMbS0sesJEP5ak=
Endpoint = vpn.example.com:51820
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
`
	c, err := path.ParseWGConf(good)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Addresses) != 2 || len(c.DNS) != 1 || c.MTU != 1380 || len(c.Peers) != 1 {
		t.Fatalf("%+v", c)
	}
	p := c.Peers[0]
	if p.Endpoint != "vpn.example.com:51820" || p.Keepalive != 25 || p.PresharedKey == nil || len(p.AllowedIPs) != 2 {
		t.Errorf("peer %+v", p)
	}
	if peer, ok := c.Covers(netip.MustParseAddr("93.184.215.14")); !ok || peer != &c.Peers[0] {
		t.Error("0.0.0.0/0 should cover a public address")
	}
	if s := fmt.Sprintf("%v %+v %#v", c, c, c); strings.Contains(s, "yAnz5") || strings.Contains(s, fmt.Sprint(c.PrivateKey[0:4])) {
		t.Errorf("printing a config shows its private key: %s", s)
	}

	// What real files carry: wg-quick's routing settings, IPv6 endpoints,
	// keepalive written Off.
	real := strings.Replace(good, "MTU = 1380\n", "MTU = 1380\nTable = off\nSaveConfig = true\nFwMark = 0x1234\n", 1)
	real = strings.Replace(real, "vpn.example.com:51820", "[2001:db8::1]:51820", 1)
	real = strings.Replace(real, "PersistentKeepalive = 25", "PersistentKeepalive = Off", 1)
	if c, err := path.ParseWGConf(real); err != nil || c.Peers[0].Endpoint != "[2001:db8::1]:51820" {
		t.Errorf("real-world file: %v", err)
	}

	key := "PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\nAddress = 10.0.0.2/32\n"
	peer := "[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nEndpoint = 1.2.3.4:51820\nAllowedIPs = 10.0.0.0/8\n"
	for _, tc := range []struct{ src, want string }{
		{"[Interface]\n" + key + "PostUp = iptables -A ...\n" + peer, "shell hook; vpnw runs no commands"},
		{"[Interface]\n" + key + "Colour = blue\n" + peer, "unknown key Colour in [Interface]"},
		{"[Interface]\n" + key, "no [Peer] section"},
		{"[Interface]\nAddress = 10.0.0.2/32\n" + peer, "no PrivateKey"},
		{"[Interface]\nPrivateKey = short\nAddress = 10.0.0.2/32\n" + peer, "not a WireGuard key"},
		{"[Interface]\n" + key + "[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nAllowedIPs = 10.0.0.0/8\n", "has no Endpoint"},
		{"[Interface]\n" + key + "[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nEndpoint = nowhere\nAllowedIPs = 10.0.0.0/8\n", "needs a host and a port"},
		{"[Interface]\n" + key + "[Interface]\n" + peer, "a second [Interface]"},
		{"[Wat]\n", "unknown section"},
		{"Address = 1.2.3.4/32\n", "comes before any [Interface]"},
		{"[Interface]\n" + key + "MTU = 9\n" + peer, "MTU must be"},
		{"[Interface]\n" + key + "[Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nEndpoint = 2001:db8::1:51820\nAllowedIPs = 10.0.0.0/8\n", "an IPv6 endpoint is written [address]:port"},
	} {
		if _, err := path.ParseWGConf(tc.src); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("got %v, want %q\n%s", err, tc.want, tc.src)
		}
	}
}

func startPeer(t *testing.T) *wgtest.Server {
	t.Helper()
	s, err := wgtest.Start()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

func tunnel(t *testing.T, conf, dns string) *path.WireGuard {
	t.Helper()
	c, err := path.ParseWGConf(conf)
	if err != nil {
		t.Fatal(err)
	}
	w, err := path.NewWireGuard("office", c, dns)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { w.Close() })
	return w
}

// The tunnel comes up, the peer sees our tunnel address, and the path
// names the peer that carried the connection.
func TestWireGuardThroughTheTunnel(t *testing.T) {
	s := startPeer(t)
	w := tunnel(t, s.ClientConfig(), "")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := w.Health(ctx); err != nil {
		t.Fatal(err)
	}
	if w.Kind() != "wireguard" || w.RemoteDNS() || !strings.Contains(w.Describe(), "dns 10.9.0.1 through the tunnel") {
		t.Errorf("kind %q, describe %q", w.Kind(), w.Describe())
	}
	if strings.Contains(w.Describe(), "PrivateKey") {
		t.Error("describe shows a private key")
	}
	ci := &path.Conn{Run: "r", ID: 1}
	c, err := w.Dial(path.WithConn(ctx, ci), "", net.IPv4(10, 9, 0, 1), 80)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fmt.Fprintf(c, "GET / HTTP/1.0\r\nHost: web\r\n\r\n")
	body, _ := io.ReadAll(bufio.NewReader(c))
	if !strings.Contains(string(body), "hello through the tunnel, 10.9.0.2") {
		t.Fatalf("reply %q", body)
	}
	if ci.Exit != fmt.Sprintf("127.0.0.1:%d", s.Port) {
		t.Errorf("exit %q", ci.Exit)
	}
}

// Names are looked up at the tunnel's DNS server, inside the tunnel.
func TestWireGuardDNSThroughTheTunnel(t *testing.T) {
	s := startPeer(t)
	w := tunnel(t, s.ClientConfig(), "")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ips, err := w.Resolver().LookupIP(ctx, "web.tunnel.test")
	if err != nil || len(ips) != 1 || !ips[0].Equal(net.IPv4(10, 9, 0, 1)) {
		t.Fatalf("ips %v err %v", ips, err)
	}
	if s.DNS.Load() == 0 {
		t.Error("the tunnel's DNS server saw no query")
	}
	if _, err := w.Resolver().LookupIP(ctx, "nosuch.tunnel.test"); err == nil {
		t.Error("an unknown name resolved")
	}
	// dns = "local" uses this machine's resolver instead.
	if _, ok := tunnel(t, s.ClientConfig(), "local").Resolver().(path.SystemResolver); !ok {
		t.Error("dns local does not use the system resolver")
	}
}

// Names never go outside the tunnel unless asked: a config without a DNS
// server needs dns = "local", and a DNS server the tunnel would drop is
// refused at the start.
func TestWireGuardDNSChecks(t *testing.T) {
	s := startPeer(t)
	noDNS, _ := path.ParseWGConf(strings.Replace(s.ClientConfig(), "DNS = 10.9.0.1\n", "", 1))
	if _, err := path.NewWireGuard("x", noDNS, ""); err == nil || !strings.Contains(err.Error(), "names no DNS server") {
		t.Errorf("no DNS, default: %v", err)
	}
	if w, err := path.NewWireGuard("x", noDNS, "local"); err != nil || w.DNS != "local" {
		t.Errorf("no DNS, local: %v", err)
	}
	outside, _ := path.ParseWGConf(strings.Replace(s.ClientConfig(), "DNS = 10.9.0.1", "DNS = 1.1.1.1", 1))
	if _, err := path.NewWireGuard("x", outside, ""); err == nil || !strings.Contains(err.Error(), "1.1.1.1 is outside every peer's AllowedIPs") {
		t.Errorf("DNS outside AllowedIPs: %v", err)
	}
}

// An address no peer's AllowedIPs cover is refused with a reason, not left
// to time out.
func TestWireGuardOutsideAllowedIPs(t *testing.T) {
	s := startPeer(t)
	w := tunnel(t, s.ClientConfig(), "")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := w.Dial(ctx, "", net.IPv4(192, 0, 2, 1), 443)
	if err == nil || !strings.Contains(err.Error(), "192.0.2.1 is outside the tunnel") {
		t.Fatalf("err = %v", err)
	}
}

// A peer that doesn't know our key never answers; Health says so, rather
// than letting the program start on a dead tunnel.
func TestWireGuardUnknownKey(t *testing.T) {
	s := startPeer(t)
	w := tunnel(t, s.StrangerConfig(), "")
	t0 := time.Now()
	err := w.Health(context.Background())
	if err == nil || !strings.Contains(err.Error(), "no WireGuard handshake from 127.0.0.1:") {
		t.Fatalf("err = %v", err)
	}
	if d := time.Since(t0); d > path.HandshakeTimeout+3*time.Second {
		t.Errorf("took %v", d)
	}
}

// Benchmarks for test/results: opening a connection through the tunnel,
// and how fast it carries data, both on this machine's loopback.

func BenchmarkWireGuardConnect(b *testing.B) {
	s, err := wgtest.Start()
	if err != nil {
		b.Fatal(err)
	}
	defer s.Close()
	c, _ := path.ParseWGConf(s.ClientConfig())
	w, _ := path.NewWireGuard("b", c, "")
	defer w.Close()
	ctx := context.Background()
	if err := w.Health(ctx); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn, err := w.Dial(ctx, "", net.IPv4(10, 9, 0, 1), 80)
		if err != nil {
			b.Fatal(err)
		}
		conn.Close()
	}
}

func BenchmarkWireGuardThroughput(b *testing.B) {
	s, err := wgtest.Start()
	if err != nil {
		b.Fatal(err)
	}
	defer s.Close()
	c, _ := path.ParseWGConf(s.ClientConfig())
	w, _ := path.NewWireGuard("b", c, "")
	defer w.Close()
	ctx := context.Background()
	if err := w.Health(ctx); err != nil {
		b.Fatal(err)
	}
	b.SetBytes(wgtest.BigSize)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn, err := w.Dial(ctx, "", net.IPv4(10, 9, 0, 1), 80)
		if err != nil {
			b.Fatal(err)
		}
		fmt.Fprintf(conn, "GET /big HTTP/1.0\r\nHost: web\r\n\r\n")
		n, _ := io.Copy(io.Discard, conn)
		conn.Close()
		if n < wgtest.BigSize {
			b.Fatalf("read %d bytes", n)
		}
	}
}
