// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"vpnw.com/vpnw/internal/events"
	"vpnw.com/vpnw/internal/exit"
)

// fakeDNS answers from a map.
type fakeDNS struct {
	mu      sync.Mutex
	m       map[string][]net.IP
	queries []string
}

func (f *fakeDNS) LookupIP(_ context.Context, host string) ([]net.IP, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.queries = append(f.queries, host)
	if ips, ok := f.m[host]; ok {
		return ips, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

// whoami answers every connection with the address it came from.
func whoami(t testing.TB) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				host, _, _ := net.SplitHostPort(c.RemoteAddr().String())
				fmt.Fprintf(c, "from %s\n", host)
				io.Copy(io.Discard, c)
			}(c)
		}
	}()
	return l.Addr().(*net.TCPAddr).Port
}

const testConfig = `version = 1
name = "exit-test"
listen = "127.0.0.1:0"
cert = "c"
key = "k"

[clients.agent-1]
token_sha256 = "%s"
source = "127.0.0.2"
default = "deny"
allow = ["echo.test", "127.0.0.1", "intranet.test", "v6.test"]
deny_private = false

[clients.agent-2]
token_sha256 = "%s"
source = "127.0.0.3"
default = "deny"
deny_private = true
allow = ["echo.test", "intranet.test"]

[clients.ci]
token_sha256 = "%s"
pool = "lo"
default = "deny"
allow = ["127.0.0.1"]

[pools.lo]
addresses = ["127.0.0.4", "127.0.0.5"]
`

type rig struct {
	s    *Server
	addr string
	mem  *events.Memory
	dns  *fakeDNS
}

func newRig(t testing.TB, cfg *tls.Config) *rig {
	t.Helper()
	c, err := exit.ParseConfig(fmt.Sprintf(testConfig, exit.HashHex("tok-1"), exit.HashHex("tok-2"), exit.HashHex("tok-ci")), "exit-test.toml", nil)
	if err != nil {
		t.Fatal(err)
	}
	mem := &events.Memory{}
	bus := events.NewBus("x-test", nil)
	bus.Add(mem)
	dns := &fakeDNS{m: map[string][]net.IP{
		"echo.test":     {net.ParseIP("127.0.0.1")},
		"intranet.test": {net.ParseIP("10.50.0.5")},
		"v6.test":       {net.ParseIP("2001:db8::1")},
	}}
	s := &Server{Config: c, TLS: cfg, Resolver: dns, Bus: bus, DialTimeout: 3 * time.Second}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go s.Serve(l)
	t.Cleanup(func() { l.Close(); s.Shutdown(time.Second) })
	return &rig{s: s, addr: l.Addr().String(), mem: mem, dns: dns}
}

func basic(tok string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte("vpnw:"+tok))
}

// connect sends a CONNECT with extra header lines and returns the status
// line, the headers and the connection.
func connect(t testing.TB, addr, target string, extra ...string) (string, map[string]string, net.Conn, *bufio.Reader) {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(10 * time.Second))
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", target, target)
	for _, h := range extra {
		fmt.Fprintf(c, "%s\r\n", h)
	}
	io.WriteString(c, "\r\n")
	br := bufio.NewReader(c)
	status, _ := br.ReadString('\n')
	hs := map[string]string{}
	for {
		l, err := br.ReadString('\n')
		if err != nil || l == "\r\n" {
			break
		}
		k, v, _ := strings.Cut(strings.TrimSpace(l), ":")
		hs[strings.ToLower(k)] = strings.TrimSpace(v)
	}
	return strings.TrimSpace(status), hs, c, br
}

func (r *rig) wait(typ string, n int) []events.Event {
	for i := 0; i < 400; i++ {
		var out []events.Event
		for _, e := range r.mem.Snapshot() {
			if e.Type == typ {
				out = append(out, e)
			}
		}
		if len(out) >= n {
			return out
		}
		time.Sleep(5 * time.Millisecond)
	}
	return nil
}

func TestConnectFromFixedAddress(t *testing.T) {
	port := whoami(t)
	r := newRig(t, nil)
	for _, c := range []struct{ tok, want string }{{"tok-1", "127.0.0.2"}, {"tok-ci", ""}} {
		target := fmt.Sprintf("127.0.0.1:%d", port)
		if c.tok == "tok-1" {
			target = fmt.Sprintf("echo.test:%d", port)
		}
		status, _, conn, br := connect(t, r.addr, target, "Proxy-Authorization: "+basic(c.tok), "VPNW-Run: r-abc123", "VPNW-Conn: 7")
		if status != "HTTP/1.1 200 Connection established" {
			t.Fatalf("%s: %q", c.tok, status)
		}
		line, _ := br.ReadString('\n')
		conn.Close()
		want := c.want
		if want == "" {
			cl := r.s.Config.Client("ci")
			a, _ := cl.SourceFor("")
			want = a.String()
		}
		if line != "from "+want+"\n" {
			t.Errorf("%s: the destination saw %q, want %s", c.tok, line, want)
		}
	}
	opens := r.wait(events.ConnectionOpen, 2)
	attempts := r.wait(events.ConnectionAttempt, 2)
	if len(opens) != 2 || opens[0].Str("source") != "127.0.0.2" || opens[0].Str("host") != "echo.test" || opens[0].Path != "exit-test" {
		t.Errorf("opens %+v", opens)
	}
	a := attempts[0]
	if a.Str("client") != "agent-1" || a.Str("client_run") != "r-abc123" || a.Int("client_conn") != 7 || a.Str("proto") != "http-connect" || a.Str("peer") == "" {
		t.Errorf("attempt %+v", a)
	}
	r.wait(events.ConnectionClose, 2)
	if st := r.s.Stats(); st.Opened != 2 || st.Connections != 2 || st.BytesDown == 0 {
		t.Errorf("stats %+v", st)
	}
}

// What the policy refuses, the exit refuses before it dials, and says why.
func TestRefusals(t *testing.T) {
	port := whoami(t)
	r := newRig(t, nil)
	cases := []struct {
		tok, target, status, rule string
	}{
		{"tok-2", "169.254.169.254:80", "403", "deny_private"},
		{"tok-2", fmt.Sprintf("intranet.test:%d", port), "403", "deny_private"},
		{"tok-2", "attacker.test:443", "403", "default"},
		{"tok-2", "2130706433:80", "403", "invalid"},
		{"tok-1", fmt.Sprintf("127.0.0.1:%d", port+0), "200", ""},
		{"tok-1", "missing.test:80", "403", "default"},
	}
	for _, c := range cases {
		status, hs, conn, _ := connect(t, r.addr, c.target, "Proxy-Authorization: "+basic(c.tok))
		conn.Close()
		if !strings.HasPrefix(status, "HTTP/1.1 "+c.status) || hs["vpnw-rule"] != c.rule {
			t.Errorf("%s %s: %q %v", c.tok, c.target, status, hs)
		}
		if c.status == "403" && hs["vpnw-reason"] == "" {
			t.Errorf("%s: no reason", c.target)
		}
	}
	// The refused names were never looked up, except where an address
	// decides: intranet.test is allowed by name and refused by address.
	for _, q := range r.dns.queries {
		if q == "attacker.test" || q == "missing.test" {
			t.Errorf("%s was looked up", q)
		}
	}
	if st := r.s.Stats(); st.Denied != 5 || st.Opened != 1 {
		t.Errorf("stats %+v", st)
	}
}

func TestTokens(t *testing.T) {
	r := newRig(t, nil)
	for _, auth := range []string{"", "Proxy-Authorization: " + basic("wrong"), "Proxy-Authorization: Bearer tok-1", "Proxy-Authorization: Basic !!!"} {
		var extra []string
		if auth != "" {
			extra = append(extra, auth)
		}
		status, hs, conn, _ := connect(t, r.addr, "echo.test:80", extra...)
		conn.Close()
		if !strings.HasPrefix(status, "HTTP/1.1 407") || !strings.Contains(hs["proxy-authenticate"], "vpnw-exit") {
			t.Errorf("%q: %q", auth, status)
		}
	}
	denials := r.wait(exit.AuthDeny, 4)
	if len(denials) != 4 || denials[0].Str("reason") != "no token" || denials[1].Str("reason") != "unknown token" || denials[0].Str("host") != "echo.test" {
		t.Errorf("auth denials %+v", denials)
	}
	for _, e := range r.mem.Snapshot() {
		for _, v := range e.Fields {
			if s, ok := v.(string); ok && strings.Contains(s, "wrong") {
				t.Errorf("a presented token was recorded: %+v", e)
			}
		}
	}
	if r.s.Stats().AuthDenied != 4 || r.s.Stats().Connections != 0 {
		t.Errorf("stats %+v", r.s.Stats())
	}
}

// A client may ask for another address of its own pool, never for another
// client's address.
func TestSourceRequests(t *testing.T) {
	port := whoami(t)
	r := newRig(t, nil)
	target := fmt.Sprintf("127.0.0.1:%d", port)
	status, _, conn, br := connect(t, r.addr, target, "Proxy-Authorization: "+basic("tok-ci"), "VPNW-Source: 127.0.0.5")
	line, _ := br.ReadString('\n')
	conn.Close()
	if status != "HTTP/1.1 200 Connection established" || line != "from 127.0.0.5\n" {
		t.Errorf("own pool address: %q %q", status, line)
	}
	for _, src := range []string{"127.0.0.2", "127.0.0.9"} {
		status, hs, conn, _ := connect(t, r.addr, target, "Proxy-Authorization: "+basic("tok-ci"), "VPNW-Source: "+src)
		conn.Close()
		if !strings.HasPrefix(status, "HTTP/1.1 403") || hs["vpnw-rule"] != "source" || !strings.Contains(hs["vpnw-reason"], src+" is not one of the source addresses of client ci") {
			t.Errorf("%s: %q %v", src, status, hs)
		}
	}
	status, _, conn, _ = connect(t, r.addr, target, "Proxy-Authorization: "+basic("tok-ci"), "VPNW-Source: nonsense")
	conn.Close()
	if !strings.HasPrefix(status, "HTTP/1.1 400") {
		t.Errorf("bad source: %q", status)
	}
}

func TestBadRequests(t *testing.T) {
	r := newRig(t, nil)
	auth := "Proxy-Authorization: " + basic("tok-1") + "\r\n"
	cases := map[string]string{
		"GARBAGE\r\n\r\n":                                                                                        "400",
		"GET http://echo.test/ HTTP/1.1\r\n\r\n":                                                                 "405",
		"POST /health HTTP/1.1\r\n\r\n":                                                                          "405",
		"CONNECT nohost HTTP/1.1\r\n" + auth + "\r\n":                                                            "400",
		"CONNECT a.test:0 HTTP/1.1\r\n\r\n":                                                                      "400",
		"CONNECT a.test:443 HTTP/2.0\r\n\r\n":                                                                    "400",
		"CONNECT a.test:443 HTTP/1.1\r\nBad\r\n\r\n":                                                             "400",
		"CONNECT a.test:443 HTTP/1.1\r\n" + auth + auth + "\r\n":                                                 "400",
		"CONNECT a.test:443 HTTP/1.1\r\n" + auth + "VPNW-Run: r-1\r\n\r\n":                                       "400",
		"CONNECT a.test:443 HTTP/1.1\r\n" + auth + "VPNW-Run: r 1\r\nVPNW-Conn: 1\r\n\r\n":                       "400",
		"CONNECT a.test:443 HTTP/1.1\r\n" + auth + "VPNW-Run: r-1\r\nVPNW-Conn: 01\r\n\r\n":                      "400",
		"CONNECT a.test:443 HTTP/1.1\r\n" + strings.Repeat("X-A: "+strings.Repeat("a", 900)+"\r\n", 80) + "\r\n": "431",
		"CONNECT a.test:443 HTTP/1.1\r\n" + strings.Repeat("X: y\r\n", 101) + "\r\n":                             "431",
		"CONNECT a.test:443 HTTP/1.1\r\nX: \x01\r\n\r\n":                                                         "400",
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
			t.Errorf("%.50q: got %.60q, want %s", req, b, want)
		}
	}
	if r.s.Stats().Connections != 0 {
		t.Errorf("a bad request was opened: %+v", r.s.Stats())
	}
}

func TestHealth(t *testing.T) {
	r := newRig(t, nil)
	for auth, want := range map[string]string{
		"Proxy-Authorization: " + basic("tok-2"): "200",
		"Authorization: " + basic("tok-2"):       "200",
		"Authorization: Bearer tok-2":            "200",
		"Authorization: Bearer nope":             "407",
		"":                                       "407",
	} {
		c, _ := net.Dial("tcp", r.addr)
		fmt.Fprintf(c, "GET /health HTTP/1.1\r\nHost: x\r\n%s\r\n\r\n", auth)
		b, _ := io.ReadAll(c)
		c.Close()
		if !strings.HasPrefix(string(b), "HTTP/1.1 "+want) {
			t.Errorf("%q: %.80q", auth, b)
		}
		if want == "200" && !strings.HasSuffix(string(b), `{"exit":"exit-test","version":"0.1.0","status":"ok","client":"agent-2"}`+"\n") {
			t.Errorf("health body %q", b)
		}
	}
	if st := r.s.Stats(); st.Health != 3 || st.AuthDenied != 2 {
		t.Errorf("stats %+v", st)
	}
}

// socksDial runs a SOCKS5 login and request and returns the reply code.
func socksDial(t testing.TB, addr, user, pass string, cmd byte, host string, port int) (byte, net.Conn, []byte) {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(10 * time.Second))
	c.Write([]byte{5, 1, 2})
	var m [2]byte
	if _, err := io.ReadFull(c, m[:]); err != nil || m[1] != 2 {
		return 0xfe, c, nil
	}
	auth := append([]byte{1, byte(len(user))}, user...)
	auth = append(append(auth, byte(len(pass))), pass...)
	c.Write(auth)
	var a [2]byte
	if _, err := io.ReadFull(c, a[:]); err != nil || a[1] != 0 {
		return 0xff, c, nil
	}
	req := []byte{5, cmd, 0}
	if ip := net.ParseIP(host); ip != nil && ip.To4() != nil {
		req = append(append(req, 1), ip.To4()...)
	} else {
		req = append(append(req, 3, byte(len(host))), host...)
	}
	req = append(req, byte(port>>8), byte(port))
	c.Write(req)
	rep := make([]byte, 10)
	if _, err := io.ReadFull(c, rep); err != nil {
		return 0xfd, c, nil
	}
	return rep[1], c, rep
}

func TestSOCKS5(t *testing.T) {
	port := whoami(t)
	r := newRig(t, nil)
	code, c, rep := socksDial(t, r.addr, "r-sock01/42", "tok-1", 1, "echo.test", port)
	if code != 0 || !bytes.Equal(rep[4:8], []byte{127, 0, 0, 2}) {
		t.Fatalf("connect: %d %v", code, rep)
	}
	line, _ := bufio.NewReader(c).ReadString('\n')
	if line != "from 127.0.0.2\n" {
		t.Errorf("the destination saw %q", line)
	}
	a := r.wait(events.ConnectionAttempt, 1)[0]
	if a.Str("client_run") != "r-sock01" || a.Int("client_conn") != 42 || a.Str("proto") != "socks5" {
		t.Errorf("attempt %+v", a)
	}
	for _, c := range []struct {
		user, pass, host string
		cmd, want        byte
	}{
		{"vpnw", "tok-2", "169.254.169.254", 1, 0x02},
		{"vpnw", "tok-2", "missing.test", 1, 0x02},
		{"vpnw", "tok-1", "missing.test", 1, 0x02},
		{"vpnw", "tok-1", "127.0.0.1", 2, 0x07},
		{"vpnw", "tok-1", "127.0.0.1", 3, 0x07},
		{"vpnw", "wrong", "127.0.0.1", 1, 0xff},
		{"r-1/0", "tok-1", "127.0.0.1", 1, 0xff},
		{"r-1/5/127.0.0.3", "tok-1", "127.0.0.1", 1, 0x02},
	} {
		if got, _, _ := socksDial(t, r.addr, c.user, c.pass, c.cmd, c.host, port); got != c.want {
			t.Errorf("%s %s cmd %d: reply %#x, want %#x", c.user, c.host, c.cmd, got, c.want)
		}
	}
	// No user-and-password login offered: refused, and recorded.
	nc, _ := net.Dial("tcp", r.addr)
	nc.Write([]byte{5, 1, 0})
	var m [2]byte
	io.ReadFull(nc, m[:])
	nc.Close()
	if m[1] != 0xff {
		t.Errorf("no login: %v", m)
	}
	r.wait(exit.AuthDeny, 3)
	denied := r.wait(events.PolicyDeny, 6)
	rules := []string{}
	for _, e := range denied {
		rules = append(rules, e.Str("rule"))
	}
	if strings.Join(rules, ",") != "deny_private,default,default,unsupported,unsupported,source" {
		t.Errorf("rules %v", rules)
	}
}

// testCert makes a self-signed certificate for 127.0.0.1.
func testCert(t testing.TB) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "exit-test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true, IsCA: true, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	pool := x509.NewCertPool()
	pool.AddCert(c)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}

// Over TLS, with a large transfer both ways, and a client that never
// finishes TLS.
func TestTLSAndRelay(t *testing.T) {
	cert, pool := testCert(t)
	r := newRig(t, &tls.Config{Certificates: []tls.Certificate{cert}})
	// A destination that sends back what it receives.
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) { io.Copy(c, c); c.Close() }(c)
		}
	}()
	tc, err := tls.Dial("tcp", r.addr, &tls.Config{RootCAs: pool, ServerName: "127.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(tc, "CONNECT 127.0.0.1:%d HTTP/1.1\r\nProxy-Authorization: %s\r\n\r\n", l.Addr().(*net.TCPAddr).Port, basic("tok-1"))
	br := bufio.NewReader(tc)
	status, _ := br.ReadString('\n')
	br.ReadString('\n')
	if !strings.HasPrefix(status, "HTTP/1.1 200") {
		t.Fatalf("%q", status)
	}
	payload := bytes.Repeat([]byte("vpnw-exit "), 100000)
	go func() { tc.Write(payload); tc.CloseWrite() }()
	got, _ := io.ReadAll(br)
	tc.Close()
	if !bytes.Equal(got, payload) {
		t.Fatalf("echoed %d bytes of %d", len(got), len(payload))
	}
	cl := r.wait(events.ConnectionClose, 1)
	if len(cl) != 1 || cl[0].Int("bytes_up") != int64(len(payload)) || cl[0].Int("bytes_down") != int64(len(payload)) {
		t.Errorf("close %+v", cl)
	}
	// A client that does not speak TLS is dropped and counted.
	c, _ := net.Dial("tcp", r.addr)
	io.WriteString(c, "CONNECT x:1 HTTP/1.1\r\n\r\n")
	io.ReadAll(c)
	c.Close()
	for i := 0; i < 100 && r.s.Stats().TLSFailed == 0; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if r.s.Stats().TLSFailed != 1 {
		t.Errorf("stats %+v", r.s.Stats())
	}
}

func TestDialFailures(t *testing.T) {
	r := newRig(t, nil)
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	dead := l.Addr().(*net.TCPAddr).Port
	l.Close()
	status, hs, conn, _ := connect(t, r.addr, fmt.Sprintf("127.0.0.1:%d", dead), "Proxy-Authorization: "+basic("tok-1"))
	conn.Close()
	if !strings.HasPrefix(status, "HTTP/1.1 502") || !strings.Contains(hs["vpnw-reason"], "refused") {
		t.Errorf("dead destination: %q %v", status, hs)
	}
	// An IPv6 destination from an IPv4 source address.
	status, hs, conn, _ = connect(t, r.addr, "v6.test:443", "Proxy-Authorization: "+basic("tok-1"))
	conn.Close()
	if !strings.HasPrefix(status, "HTTP/1.1 502") || !strings.Contains(hs["vpnw-reason"], "reachable from source 127.0.0.2") {
		t.Errorf("v6: %q %v", status, hs)
	}
	if r.s.Stats().Failed != 2 {
		t.Errorf("stats %+v", r.s.Stats())
	}
}

func TestShutdownAndLimits(t *testing.T) {
	r := newRig(t, nil)
	c, _ := net.Dial("tcp", r.addr)
	io.WriteString(c, "CONN")
	time.Sleep(50 * time.Millisecond)
	r.s.Shutdown(time.Second)
	if _, err := io.ReadAll(c); err != nil && !strings.Contains(err.Error(), "reset") {
		t.Errorf("read after shutdown: %v", err)
	}
	c.Close()
	c2, err := net.Dial("tcp", r.addr)
	if err == nil {
		c2.SetDeadline(time.Now().Add(time.Second))
		n, _ := c2.Read(make([]byte, 1))
		if n != 0 {
			t.Error("a connection was served after shutdown")
		}
		c2.Close()
	}
}

func TestText(t *testing.T) {
	var all, dec bytes.Buffer
	bus := events.NewBus("x-1", func() time.Time { return time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC) })
	bus.Add(NewText(&all, events.All))
	bus.Add(NewText(&dec, events.Decisions))
	bus.Emit(events.RunStart, 0, "exit-de", 0, map[string]any{"version": "0.1.0", "listen": "198.51.100.2:8443", "clients": 2})
	bus.Emit(events.ConnectionAttempt, 0, "exit-de", 1, map[string]any{"host": "api.partner.test", "port": 443, "proto": "http-connect", "client": "agent-1", "client_run": "r-1", "client_conn": 4})
	bus.Emit(events.DNSResult, 0, "exit-de", 1, map[string]any{"host": "api.partner.test", "ips": []string{"51.15.0.10"}})
	bus.Emit(events.PolicyAllow, 0, "exit-de", 1, map[string]any{"rule": "allow[0]"})
	bus.Emit(events.ConnectionOpen, 0, "exit-de", 1, map[string]any{"ip": "51.15.0.10", "source": "198.51.100.10", "ms": 3})
	bus.Emit(events.ConnectionClose, 0, "exit-de", 1, map[string]any{"bytes_up": 100, "bytes_down": 2000, "ms": 9})
	bus.Emit(events.ConnectionAttempt, 0, "exit-de", 2, map[string]any{"ip": "169.254.169.254", "port": 80, "client": "agent-2"})
	bus.Emit(events.PolicyDeny, 0, "exit-de", 2, map[string]any{"rule": "deny_private", "reason": "link-local"})
	bus.Emit(events.DNSResult, 0, "exit-de", 3, map[string]any{"host": "x.test", "error": "no such host"})
	bus.Emit(events.ConnectionError, 0, "exit-de", 3, map[string]any{"error": "dns: no such host"})
	bus.Emit(exit.AuthDeny, 0, "exit-de", 0, map[string]any{"peer": "192.0.2.2:5000", "proto": "socks5", "reason": "unknown token"})
	bus.Emit(events.RunEnd, 0, "exit-de", 0, map[string]any{"connections": 3, "opened": 1, "denied": 1, "failed": 1, "auth_denied": 1})
	want := []string{
		"exit-de 0.1.0 on 198.51.100.2:8443  run x-1  2 clients",
		"#2     DENY   agent-2  169.254.169.254:80  deny_private: link-local",
		"#3     dns x.test failed: no such host",
		"refused a client at 192.0.2.2:5000 (socks5): unknown token",
		"summary  3 connections: 1 opened, 1 denied, 1 failed; 1 refused for a missing or unknown token",
	}
	for _, w := range want {
		if !strings.Contains(dec.String(), w) {
			t.Errorf("decisions lack %q:\n%s", w, dec.String())
		}
	}
	for _, w := range []string{"agent-1 r-1/4  -> api.partner.test:443", "open   51.15.0.10 from 198.51.100.10", "close  sent 100 B  received 2.0 KB"} {
		if !strings.Contains(all.String(), w) {
			t.Errorf("all lacks %q:\n%s", w, all.String())
		}
	}
	if strings.Count(dec.String(), "\n") != 6 {
		t.Errorf("decisions:\n%s", dec.String())
	}
}
