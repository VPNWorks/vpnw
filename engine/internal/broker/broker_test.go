// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package broker

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"vpnw.com/vpnw/internal/config"
	"vpnw.com/vpnw/internal/events"
	"vpnw.com/vpnw/internal/path"
	"vpnw.com/vpnw/internal/policy"
)

// fakeDNS maps names to addresses; every name maps to the echo server's
// loopback address unless listed.
type fakeDNS struct {
	m       map[string][]net.IP
	queries []string
}

func (f *fakeDNS) LookupIP(_ context.Context, host string) ([]net.IP, error) {
	f.queries = append(f.queries, host)
	if ips, ok := f.m[host]; ok {
		return ips, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

// echoServer answers "hello <first line>" and records what it received.
func echoServer(t *testing.T) (port int, got chan string) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	got = make(chan string, 16)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				line, _ := br.ReadString('\n')
				got <- line
				fmt.Fprintf(c, "hello %s", line)
			}(c)
		}
	}()
	return l.Addr().(*net.TCPAddr).Port, got
}

// httpOrigin answers any HTTP request with a keep-alive response and
// reports the request head.
func httpOrigin(t *testing.T) (int, chan string) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	heads := make(chan string, 4)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				var sb strings.Builder
				for {
					l, err := br.ReadString('\n')
					if err != nil {
						return
					}
					sb.WriteString(l)
					if l == "\r\n" {
						break
					}
				}
				heads <- sb.String()
				io.WriteString(c, "HTTP/1.1 200 OK\r\nConnection: keep-alive\r\nKeep-Alive: timeout=5\r\nContent-Length: 2\r\n\r\nok")
			}(c)
		}
	}()
	return l.Addr().(*net.TCPAddr).Port, heads
}

type rig struct {
	b    *Broker
	addr string
	mem  *events.Memory
	dns  *fakeDNS
}

func newRig(t *testing.T, pol *policy.Policy) *rig {
	t.Helper()
	mem := &events.Memory{}
	bus := events.NewBus("r-test", nil)
	bus.Add(mem)
	dns := &fakeDNS{m: map[string][]net.IP{
		"echo.test":    {net.ParseIP("127.0.0.1")},
		"allowed.test": {net.ParseIP("127.0.0.1")},
		"rebind.test":  {net.ParseIP("127.0.0.1")},
	}}
	b := &Broker{Policy: pol, Path: &path.Direct{}, Resolver: dns, Bus: bus, DialTimeout: 3 * time.Second}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go b.Serve(l)
	t.Cleanup(func() { l.Close(); b.Shutdown(time.Second) })
	return &rig{b: b, addr: l.Addr().String(), mem: mem, dns: dns}
}

func (r *rig) types() []string {
	var out []string
	for _, e := range r.mem.Snapshot() {
		out = append(out, e.Type)
	}
	return out
}

func pol(t *testing.T, spec config.PolicySpec) *policy.Policy {
	p, err := policy.New(&spec, "t")
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func waitEvents(r *rig, typ string, n int) {
	for i := 0; i < 200; i++ {
		c := 0
		for _, e := range r.mem.Snapshot() {
			if e.Type == typ {
				c++
			}
		}
		if c >= n {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func connect(t *testing.T, addr, target string, extra string) (net.Conn, string) {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n%s\r\n", target, target, extra)
	br := bufio.NewReader(c)
	status, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("no reply: %v", err)
	}
	for {
		l, err := br.ReadString('\n')
		if err != nil || l == "\r\n" {
			break
		}
	}
	return &bufConn{c, br}, strings.TrimSpace(status)
}

type bufConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufConn) Read(p []byte) (int, error) { return b.r.Read(p) }

func TestConnectAllowedAndTraced(t *testing.T) {
	port, got := echoServer(t)
	r := newRig(t, nil)
	c, status := connect(t, r.addr, fmt.Sprintf("echo.test:%d", port), "")
	if status != "HTTP/1.1 200 Connection established" {
		t.Fatalf("status %q", status)
	}
	io.WriteString(c, "ping\n")
	reply, _ := io.ReadAll(c)
	c.Close()
	if string(reply) != "hello ping\n" || <-got != "ping\n" {
		t.Fatalf("reply %q", reply)
	}
	waitEvents(r, events.ConnectionClose, 1)
	want := []string{"connection.attempt", "dns.query", "dns.result", "connection.open", "connection.close"}
	if strings.Join(r.types(), ",") != strings.Join(want, ",") {
		t.Errorf("events %v, want %v", r.types(), want)
	}
	st := r.b.Stats()
	if st.Allowed != 1 || st.BytesUp != 5 || st.BytesDown != 11 {
		t.Errorf("stats %+v", st)
	}
}

func TestConnectDenied(t *testing.T) {
	port, _ := echoServer(t)
	r := newRig(t, pol(t, config.PolicySpec{Allow: []string{"allowed.test"}}))
	_, status := connect(t, r.addr, fmt.Sprintf("evil.test:%d", port), "")
	if !strings.HasPrefix(status, "HTTP/1.1 403") {
		t.Fatalf("status %q", status)
	}
	waitEvents(r, events.PolicyDeny, 1)
	if strings.Join(r.types(), ",") != "connection.attempt,policy.deny" {
		t.Errorf("events %v", r.types())
	}
	if len(r.dns.queries) != 0 {
		t.Errorf("a denied name was looked up: %v", r.dns.queries)
	}
}

func TestDenyPrivateAfterDNS(t *testing.T) {
	port, _ := echoServer(t)
	r := newRig(t, pol(t, config.PolicySpec{Allow: []string{"rebind.test"}, DenyPrivate: true}))
	_, status := connect(t, r.addr, fmt.Sprintf("rebind.test:%d", port), "")
	if !strings.HasPrefix(status, "HTTP/1.1 403") {
		t.Fatalf("status %q", status)
	}
	waitEvents(r, events.PolicyDeny, 1)
	evs := r.mem.Snapshot()
	last := evs[len(evs)-1]
	if last.Type != events.PolicyDeny || last.Str("rule") != "deny_private" || !strings.Contains(last.Str("reason"), "resolved to 127.0.0.1") {
		t.Errorf("last event %+v", last)
	}
}

func TestPlainHTTPForward(t *testing.T) {
	port, heads := httpOrigin(t)
	r := newRig(t, pol(t, config.PolicySpec{Allow: []string{"allowed.test"}}))
	c, err := net.Dial("tcp", r.addr)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(c, "GET http://allowed.test:%d/path?q=1 HTTP/1.1\r\nHost: wrong.test\r\nProxy-Connection: keep-alive\r\nProxy-Authorization: Basic eDp5\r\nUser-Agent: t\r\n\r\n", port)
	resp, _ := io.ReadAll(c)
	c.Close()
	h := <-heads
	if !strings.HasPrefix(h, "GET /path?q=1 HTTP/1.1\r\n") || !strings.Contains(h, fmt.Sprintf("Host: allowed.test:%d\r\n", port)) {
		t.Errorf("origin saw %q", h)
	}
	if strings.Contains(h, "Proxy-") || !strings.Contains(h, "Connection: close") || strings.Contains(h, "wrong.test") {
		t.Errorf("proxy headers leaked or connection not closed: %q", h)
	}
	rs := string(resp)
	if !strings.Contains(rs, "Connection: close\r\n") || strings.Contains(rs, "keep-alive") || !strings.HasSuffix(rs, "ok") {
		t.Errorf("client got %q", rs)
	}
}

func TestSOCKS5(t *testing.T) {
	port, _ := echoServer(t)
	r := newRig(t, pol(t, config.PolicySpec{Allow: []string{"echo.test", "127.0.0.1"}}))
	up := &path.Proxy{Name: "t", Scheme: "socks5", Addr: r.addr, Remote: true}
	for _, host := range []string{"echo.test", "127.0.0.1"} {
		c, err := up.Dial(context.Background(), host, net.ParseIP(host), port)
		if err != nil {
			t.Fatalf("%s: %v", host, err)
		}
		io.WriteString(c, "x\n")
		b, _ := io.ReadAll(c)
		c.Close()
		if string(b) != "hello x\n" {
			t.Errorf("%s: %q", host, b)
		}
	}
	if _, err := up.Dial(context.Background(), "evil.test", nil, port); err == nil || !strings.Contains(err.Error(), "not allowed") {
		t.Errorf("denied SOCKS request: %v", err)
	}
	for _, q := range r.dns.queries {
		if q == "evil.test" {
			t.Error("an unlisted name was looked up")
		}
	}
}

func TestSOCKS5UDPRefused(t *testing.T) {
	r := newRig(t, pol(t, config.PolicySpec{Default: "allow"}))
	c, err := net.Dial("tcp", r.addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte{5, 1, 0})
	var rep [2]byte
	io.ReadFull(c, rep[:])
	c.Write([]byte{5, 3, 0, 1, 8, 8, 8, 8, 0, 53})
	var r2 [10]byte
	io.ReadFull(c, r2[:])
	if r2[1] != 0x07 {
		t.Errorf("UDP ASSOCIATE reply %d, want 7", r2[1])
	}
	waitEvents(r, events.PolicyDeny, 1)
	evs := r.mem.Snapshot()
	if evs[len(evs)-1].Str("rule") != "unsupported" {
		t.Errorf("want an 'unsupported' denial, got %+v", evs[len(evs)-1])
	}
}

func TestProxyChainHTTPConnect(t *testing.T) {
	// vpnw's HTTP CONNECT client, pointed at a second broker.
	port, _ := echoServer(t)
	exit := newRig(t, nil)
	up := &path.Proxy{Name: "exit", Scheme: "http", Addr: exit.addr, Remote: true}
	c, err := up.Dial(context.Background(), "echo.test", nil, port)
	if err != nil {
		t.Fatal(err)
	}
	io.WriteString(c, "chain\n")
	b, _ := io.ReadAll(c)
	if string(b) != "hello chain\n" {
		t.Errorf("%q", b)
	}
}

func TestMalformed(t *testing.T) {
	r := newRig(t, nil)
	cases := map[string]string{
		"GARBAGE\r\n\r\n":                            "400",
		"GET / HTTP/1.1\r\n\r\n":                     "400",
		"GET https://x.test/ HTTP/1.1\r\n\r\n":       "400",
		"CONNECT nohost HTTP/1.1\r\n\r\n":            "400",
		"CONNECT a.test:0 HTTP/1.1\r\n\r\n":          "400",
		"CONNECT a.test:443 HTTP/2.0\r\n\r\n":        "400",
		"CONNECT a.test:443 HTTP/1.1\r\nBad\r\n\r\n": "400",
		"GET http://x.test/ HTTP/1.1\r\n" + strings.Repeat("X-A: "+strings.Repeat("a", 900)+"\r\n", 80) + "\r\n": "431",
	}
	for req, want := range cases {
		c, err := net.Dial("tcp", r.addr)
		if err != nil {
			t.Fatal(err)
		}
		io.WriteString(c, req)
		b, _ := io.ReadAll(c)
		c.Close()
		if !strings.HasPrefix(string(b), "HTTP/1.1 "+want) {
			t.Errorf("%.40q: got %.60q, want %s", req, b, want)
		}
	}
}

func TestInvalidHostDenied(t *testing.T) {
	r := newRig(t, pol(t, config.PolicySpec{Default: "allow"}))
	_, status := connect(t, r.addr, "2130706433:80", "")
	if !strings.HasPrefix(status, "HTTP/1.1 403") {
		t.Errorf("numeric host: %q", status)
	}
	waitEvents(r, events.PolicyDeny, 1)
}

func TestToken(t *testing.T) {
	port, _ := echoServer(t)
	r := newRig(t, nil)
	r.b.Token = "s3cret"
	_, status := connect(t, r.addr, fmt.Sprintf("echo.test:%d", port), "")
	if !strings.HasPrefix(status, "HTTP/1.1 407") {
		t.Errorf("no credentials: %q", status)
	}
	cred := base64.StdEncoding.EncodeToString([]byte("vpnw:s3cret"))
	_, status = connect(t, r.addr, fmt.Sprintf("echo.test:%d", port), "Proxy-Authorization: Basic "+cred+"\r\n")
	if !strings.HasPrefix(status, "HTTP/1.1 200") {
		t.Errorf("with credentials: %q", status)
	}
	up := &path.Proxy{Name: "t", Scheme: "socks5", Addr: r.addr, Remote: true, User: "vpnw", Pass: "s3cret"}
	if c, err := up.Dial(context.Background(), "echo.test", nil, port); err != nil {
		t.Errorf("socks with credentials: %v", err)
	} else {
		c.Close()
	}
	up.Pass = "wrong"
	if _, err := up.Dial(context.Background(), "echo.test", nil, port); err == nil {
		t.Error("socks with a wrong password succeeded")
	}
}

func TestDialFailure(t *testing.T) {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	port := l.Addr().(*net.TCPAddr).Port
	l.Close() // nothing listens there now
	r := newRig(t, nil)
	_, status := connect(t, r.addr, fmt.Sprintf("echo.test:%d", port), "")
	if !strings.HasPrefix(status, "HTTP/1.1 502") {
		t.Errorf("status %q", status)
	}
	waitEvents(r, events.ConnectionError, 1)
	if r.b.Stats().Failed != 1 {
		t.Errorf("stats %+v", r.b.Stats())
	}
}

// Every attempt ends exactly one way: opened, denied or failed. The run
// summary relies on these three adding up to the number of connections.
func TestOutcomesAddUp(t *testing.T) {
	port, _ := echoServer(t)
	r := newRig(t, pol(t, config.PolicySpec{Default: "deny", Allow: []string{"echo.test", "missing.test", "allowed.test:1"}}))
	cases := []string{
		fmt.Sprintf("echo.test:%d", port),    // opened
		fmt.Sprintf("denied.test:%d", port),  // denied: not on the list
		fmt.Sprintf("missing.test:%d", port), // failed: allowed, but no such host
		"allowed.test:1",                     // failed: allowed, nothing listens there
		"bad..name:80",                       // denied: not a valid name
	}
	for _, target := range cases {
		c, _ := connect(t, r.addr, target, "")
		c.Close()
	}
	waitEvents(r, events.ConnectionClose, 1)
	time.Sleep(50 * time.Millisecond)
	st := r.b.Stats()
	if st.Connections != 5 || st.Opened != 1 || st.Denied != 2 || st.Failed != 2 {
		t.Errorf("stats %+v, want 5 connections: 1 opened, 2 denied, 2 failed", st)
	}
	if st.Opened+st.Denied+st.Failed != st.Connections {
		t.Errorf("outcomes do not add up: %+v", st)
	}
}
