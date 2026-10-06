// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package path

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// request is what a stand-in exit was asked.
type request struct {
	proto      string // "http" or "socks5"
	target     string
	headers    map[string]string // lower-case names
	user, pass string
}

// standIn is a small proxy reached over TLS that stands in for a VPN Works
// exit: it records each request and answers as told.
type standIn struct {
	ln       net.Listener
	addr     string
	got      chan request
	accepted atomic.Int64
	// answer, if set, is the head of the answer to a CONNECT ("HTTP/1.1
	// 403 Forbidden\r\nVPNW-Rule: x\r\n"); otherwise 200.
	answer string
	// health is the status line for GET /health; default 200.
	health string
	// socksReply is the SOCKS5 reply code; socksPass, if set, the only
	// password accepted.
	socksReply byte
	socksPass  string
	// closeEarly closes each connection after TLS, before any answer.
	closeEarly bool
	// silent accepts TCP and never speaks TLS.
	silent bool
	mu     sync.Mutex
	conns  []net.Conn
}

func newStandIn(t testing.TB, cert tls.Certificate, setup func(*standIn)) *standIn {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &standIn{ln: ln, addr: ln.Addr().String(), got: make(chan request, 64)}
	if setup != nil {
		setup(s)
	}
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			s.accepted.Add(1)
			s.mu.Lock()
			s.conns = append(s.conns, c)
			s.mu.Unlock()
			if s.silent {
				continue
			}
			go s.serve(tls.Server(c, cfg))
		}
	}()
	t.Cleanup(s.stop)
	return s
}

func (s *standIn) setAnswer(a string) {
	s.mu.Lock()
	s.answer = a
	s.mu.Unlock()
}

func (s *standIn) getAnswer() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.answer
}

// stop closes the listener and every connection, as a killed exit would.
func (s *standIn) stop() {
	s.ln.Close()
	s.mu.Lock()
	for _, c := range s.conns {
		c.Close()
	}
	s.mu.Unlock()
}

func (s *standIn) serve(c *tls.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if err := c.Handshake(); err != nil || s.closeEarly {
		return
	}
	br := bufio.NewReader(c)
	first, err := br.Peek(1)
	if err != nil {
		return
	}
	if first[0] == 0x05 {
		s.socks(c, br)
		return
	}
	line, _ := br.ReadString('\n')
	r := request{proto: "http", headers: map[string]string{}}
	for {
		l, err := br.ReadString('\n')
		if err != nil || l == "\r\n" {
			break
		}
		name, value, _ := strings.Cut(strings.TrimSpace(l), ":")
		r.headers[strings.ToLower(name)] = strings.TrimSpace(value)
	}
	f := strings.Fields(line)
	if len(f) == 3 && f[0] == "GET" && f[1] == "/health" {
		status := s.health
		if status == "" {
			status = "200 OK"
		}
		io.WriteString(c, "HTTP/1.1 "+status+"\r\nContent-Length: 0\r\n\r\n")
		return
	}
	if len(f) == 3 {
		r.target = f[1]
	}
	s.got <- r
	if a := s.getAnswer(); a != "" {
		io.WriteString(c, a+"Content-Length: 0\r\n\r\n")
		return
	}
	io.WriteString(c, "HTTP/1.1 200 Connection established\r\n\r\nhello")
}

func (s *standIn) socks(c net.Conn, br *bufio.Reader) {
	var hdr [2]byte
	io.ReadFull(br, hdr[:])
	methods := make([]byte, hdr[1])
	io.ReadFull(br, methods)
	r := request{proto: "socks5"}
	if strings.Contains(string(methods), "\x02") {
		c.Write([]byte{0x05, 0x02})
		var v [2]byte
		io.ReadFull(br, v[:])
		u := make([]byte, v[1])
		io.ReadFull(br, u)
		var pl [1]byte
		io.ReadFull(br, pl[:])
		pw := make([]byte, pl[0])
		io.ReadFull(br, pw)
		r.user, r.pass = string(u), string(pw)
		if s.socksPass != "" && r.pass != s.socksPass {
			c.Write([]byte{0x01, 0x01})
			return
		}
		c.Write([]byte{0x01, 0x00})
	} else {
		c.Write([]byte{0x05, 0x00})
	}
	var req [4]byte
	if _, err := io.ReadFull(br, req[:]); err != nil {
		return // a health check logs in and leaves
	}
	switch req[3] {
	case 0x01:
		var a [4]byte
		io.ReadFull(br, a[:])
		r.target = net.IP(a[:]).String()
	case 0x03:
		var l [1]byte
		io.ReadFull(br, l[:])
		n := make([]byte, l[0])
		io.ReadFull(br, n)
		r.target = string(n)
	}
	var port [2]byte
	io.ReadFull(br, port[:])
	s.got <- r
	c.Write([]byte{0x05, s.socksReply, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	if s.socksReply == 0 {
		io.WriteString(c, "hello")
	}
}

func ctx5(t testing.TB) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func build(t testing.TB, urls []string, o Options) Path {
	t.Helper()
	p, err := Build("exits", urls, o)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// Over TLS, a request carries the run and connection IDs and the token, and
// the name goes to the exit.
func TestTLSProxiesSendIDs(t *testing.T) {
	ca := newCA(t, "test CA")
	s := newStandIn(t, ca.good(t), nil)
	caFile := ca.file(t)
	tok := writeFile(t, "token", "  s3cret-token\n")
	for _, scheme := range []string{"https", "socks5+tls"} {
		p := build(t, []string{scheme + "://" + s.addr}, Options{CAFile: caFile, TokenFile: tok})
		if !p.RemoteDNS() || p.Kind() != scheme {
			t.Errorf("%s: kind %s remote %v", scheme, p.Kind(), p.RemoteDNS())
		}
		info := &Conn{Run: "r-abc123", ID: 7}
		c, err := p.Dial(WithConn(ctx5(t), info), "api.partner.test", nil, 443)
		if err != nil {
			t.Fatalf("%s: %v", scheme, err)
		}
		b, _ := io.ReadAll(c)
		c.Close()
		r := <-s.got
		if string(b) != "hello" || info.Exit != s.addr {
			t.Errorf("%s: relayed %q, exit %q", scheme, b, info.Exit)
		}
		switch scheme {
		case "https":
			wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte("vpnw:s3cret-token"))
			if r.target != "api.partner.test:443" || r.headers["vpnw-run"] != "r-abc123" || r.headers["vpnw-conn"] != "7" || r.headers["proxy-authorization"] != wantAuth {
				t.Errorf("https request: %+v", r)
			}
		case "socks5+tls":
			if r.target != "api.partner.test" || r.user != "r-abc123/7" || r.pass != "s3cret-token" {
				t.Errorf("socks5+tls request: %+v", r)
			}
		}
		// Without a connection in the context there are no IDs.
		c, err = p.Dial(ctx5(t), "api.partner.test", nil, 443)
		if err != nil {
			t.Fatal(err)
		}
		c.Close()
		r = <-s.got
		if r.headers["vpnw-run"] != "" || (r.proto == "socks5" && r.user != "vpnw") {
			t.Errorf("%s without IDs: %+v", scheme, r)
		}
	}
}

// Plain proxies are as before: no IDs, and the exit is not noted.
func TestPlainProxyHasNoIDs(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	head := make(chan string, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		br := bufio.NewReader(c)
		var sb strings.Builder
		for {
			l, err := br.ReadString('\n')
			if err != nil || l == "\r\n" {
				break
			}
			sb.WriteString(l)
		}
		head <- sb.String()
		io.WriteString(c, "HTTP/1.1 403 Forbidden\r\nVPNW-Reason: nope\r\n\r\n")
	}()
	p := build(t, []string{"http://" + ln.Addr().String()}, Options{})
	info := &Conn{Run: "r-abc123", ID: 3}
	_, err = p.Dial(WithConn(ctx5(t), info), "example.com", nil, 443)
	if err == nil || err.Error() != "http exit answered 403 Forbidden" {
		t.Errorf("plain refusal: %v", err)
	}
	if h := <-head; strings.Contains(h, "VPNW") || info.Exit != "" {
		t.Errorf("a plain proxy got VPN Works headers or noted an exit: %q %q", h, info.Exit)
	}
}

// The certificate is always checked: a wrong CA, an expired certificate
// and a certificate for another name all fail, at Dial and at Health.
func TestTLSCertificateChecks(t *testing.T) {
	ca := newCA(t, "test CA")
	other := newCA(t, "someone else")
	now := time.Now()
	cases := []struct {
		name, host, want string
		cert             tls.Certificate
	}{
		{"wrong CA", "127.0.0.1", "unknown authority", other.good(t)},
		{"expired", "127.0.0.1", "expired", ca.leaf(t, nil, []net.IP{net.ParseIP("127.0.0.1")}, now.Add(-48*time.Hour), now.Add(-24*time.Hour))},
		{"wrong name", "localhost", "not localhost", ca.good(t)},
	}
	caFile := ca.file(t)
	for _, c := range cases {
		s := newStandIn(t, c.cert, nil)
		_, port, _ := net.SplitHostPort(s.addr)
		p := build(t, []string{"https://vpnw:tok@" + net.JoinHostPort(c.host, port)}, Options{CAFile: caFile})
		_, err := p.Dial(ctx5(t), "example.com", nil, 443)
		if err == nil || !strings.Contains(err.Error(), c.want) || !isDown(err) {
			t.Errorf("%s: dial error %v, want one containing %q", c.name, err, c.want)
		}
		if err := p.Health(ctx5(t)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: health %v", c.name, err)
		}
		select {
		case r := <-s.got:
			t.Errorf("%s: the exit was sent a request: %+v", c.name, r)
		default:
		}
	}
	// Without the private CA, the system's roots do not know the exit.
	s := newStandIn(t, ca.good(t), nil)
	p := build(t, []string{"https://" + s.addr}, Options{})
	if err := p.Health(ctx5(t)); err == nil || !strings.Contains(err.Error(), "unknown authority") {
		t.Errorf("system roots: %v", err)
	}
}

func TestTLSHealth(t *testing.T) {
	ca := newCA(t, "test CA")
	caFile := ca.file(t)
	cases := []struct {
		health, want string
	}{
		{"200 OK", ""},
		{"407 Proxy Authentication Required", "refused the token"},
		{"503 Service Unavailable", "not taking connections"},
		{"400 Bad Request", ""}, // a proxy without a health page still answered
	}
	for _, c := range cases {
		s := newStandIn(t, ca.good(t), func(s *standIn) { s.health = c.health })
		p := build(t, []string{"https://vpnw:tok@" + s.addr}, Options{CAFile: caFile})
		err := p.Health(ctx5(t))
		if (c.want == "" && err != nil) || (c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want))) {
			t.Errorf("health %s: %v", c.health, err)
		}
	}
	s := newStandIn(t, ca.good(t), func(s *standIn) { s.socksPass = "right" })
	if err := build(t, []string{"socks5+tls://vpnw:right@" + s.addr}, Options{CAFile: caFile}).Health(ctx5(t)); err != nil {
		t.Errorf("socks5+tls health: %v", err)
	}
	if err := build(t, []string{"socks5+tls://vpnw:wrong@" + s.addr}, Options{CAFile: caFile}).Health(ctx5(t)); err == nil || !strings.Contains(err.Error(), "refused the token") {
		t.Errorf("socks5+tls health with a wrong token: %v", err)
	}
	if err := build(t, []string{"https://vpnw:tok@127.0.0.1:1"}, Options{CAFile: caFile}).Health(ctx5(t)); err == nil || !strings.Contains(err.Error(), "not reachable") {
		t.Errorf("health of a dead exit: %v", err)
	}
}

// When the exit refuses, its reason reaches the error, the exit is noted,
// and that is not a reason to move to another exit.
func TestExitRefusal(t *testing.T) {
	ca := newCA(t, "test CA")
	s := newStandIn(t, ca.good(t), func(s *standIn) {
		s.answer = "HTTP/1.1 403 Forbidden\r\nVPNW-Rule: deny_private\r\nVPNW-Reason: intranet.test resolved to 10.0.0.5: private\x01 network\r\n"
	})
	p := build(t, []string{"https://vpnw:tok@" + s.addr}, Options{CAFile: ca.file(t)})
	info := &Conn{Run: "r-1", ID: 1}
	_, err := p.Dial(WithConn(ctx5(t), info), "intranet.test", nil, 80)
	if err == nil || err.Error() != "the exit refused it (deny_private): intranet.test resolved to 10.0.0.5: private? network" || isDown(err) {
		t.Errorf("refusal: %v", err)
	}
	if info.Exit != s.addr {
		t.Errorf("exit not noted: %q", info.Exit)
	}
	for answer, want := range map[string]string{
		"HTTP/1.1 407 Proxy Authentication Required\r\n":       "the exit refused the token",
		"HTTP/1.1 502 Bad Gateway\r\nVPNW-Reason: refused\r\n": "the exit answered 502: refused",
		"HTTP/1.1 500 Oops\r\n":                                "http exit answered 500 Oops",
	} {
		s.setAnswer(answer)
		if _, err := p.Dial(ctx5(t), "x.test", nil, 80); err == nil || err.Error() != want {
			t.Errorf("%q: %v, want %q", answer, err, want)
		}
	}
}

func TestBuildErrors(t *testing.T) {
	ca := newCA(t, "test CA")
	caFile := ca.file(t)
	tok := writeFile(t, "token", "tok\n")
	cases := []struct {
		urls []string
		o    Options
		want string
	}{
		{nil, Options{}, "no proxy URL"},
		{[]string{"https://h:1"}, Options{DNS: "both"}, "dns must be local or remote"},
		{[]string{"https://h:1"}, Options{CAFile: "/nonexistent/ca.pem"}, "CA file /nonexistent/ca.pem: no such file"},
		{[]string{"https://h:1"}, Options{CAFile: tok}, "holds no PEM certificate"},
		{[]string{"socks5://h:1"}, Options{CAFile: caFile}, "for proxies reached over TLS"},
		{[]string{"https://h:1"}, Options{TokenFile: "/nonexistent/token"}, "token file /nonexistent/token: no such file"},
		{[]string{"https://h:1"}, Options{TokenFile: writeFile(t, "empty", " \n")}, "is empty"},
		{[]string{"https://h:1"}, Options{TokenFile: writeFile(t, "two", "a b\n")}, "must hold one token"},
		{[]string{"https://h:1"}, Options{TokenFile: writeFile(t, "long", strings.Repeat("x", 256))}, "longer than 255"},
		{[]string{"https://vpnw:pw@h:1"}, Options{TokenFile: tok}, "has a password already"},
		{[]string{"https://h:1", "https://h:1"}, Options{}, "listed twice"},
		{[]string{"https://h:1", "socks5://h:2"}, Options{}, "resolve names the same way"},
		{[]string{"https://h:1", "bogus"}, Options{}, "not a proxy URL"},
	}
	for _, c := range cases {
		_, err := Build("x", c.urls, c.o)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%v %+v: %v, want %q", c.urls, c.o, err, c.want)
		}
	}
	// A file name relative to the configuration's folder.
	p, err := Build("x", []string{"https://h:1"}, Options{TokenFile: "token", Dir: tok[:len(tok)-len("/token")]})
	if err != nil || p.(*Proxy).Pass != "tok" {
		t.Errorf("relative token file: %v", err)
	}
}

// Tokens never appear in descriptions or messages.
func TestTokenNeverShown(t *testing.T) {
	tok := writeFile(t, "token", "s3cret-token")
	p := build(t, []string{"https://exit-a.test:8443", "socks5+tls://exit-b.test:8443"}, Options{TokenFile: tok})
	if d := p.Describe(); strings.Contains(d, "s3cret") || !strings.Contains(d, "https://exit-a.test:8443 (in use), socks5+tls://exit-b.test:8443; DNS at the exit") {
		t.Errorf("Describe: %s", d)
	}
	q := build(t, []string{"https://vpnw:s3cret-token@exit-a.test:8443"}, Options{})
	if d := q.Describe(); strings.Contains(d, "s3cret") || d != "https://***@exit-a.test:8443, DNS at the exit" {
		t.Errorf("Describe: %s", d)
	}
	if _, err := Build("x", []string{"https://vpnw:s3cret-token@exit-a.test"}, Options{}); err == nil || strings.Contains(err.Error(), "s3cret") {
		t.Errorf("error leaks the token: %v", err)
	}
}

// failoverPair is two exits in a list, A first.
func failoverPair(t *testing.T, setupA func(*standIn)) (*Exits, *standIn, *standIn, *testCA) {
	ca := newCA(t, "test CA")
	a := newStandIn(t, ca.good(t), setupA)
	b := newStandIn(t, ca.good(t), nil)
	p := build(t, []string{"https://vpnw:tok@" + a.addr, "https://vpnw:tok@" + b.addr}, Options{CAFile: ca.file(t)})
	e := p.(*Exits)
	// Short enough that a silent exit is given up on quickly, long enough
	// for a handshake on a busy machine.
	e.Limit = time.Second
	return e, a, b, ca
}

type switchLog struct {
	mu   sync.Mutex
	seen []string
}

func (l *switchLog) conn(id uint64) *Conn {
	return &Conn{Run: "r-fo", ID: id, Switched: func(from, to, reason string, ms int64) {
		l.mu.Lock()
		l.seen = append(l.seen, from+">"+to+" "+reason)
		l.mu.Unlock()
	}}
}

func (l *switchLog) list() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.seen...)
}

func TestExitsHealthPicksFirstThatAnswers(t *testing.T) {
	e, a, b, _ := failoverPair(t, nil)
	if err := e.Health(ctx5(t)); err != nil || e.Current() != a.addr {
		t.Fatalf("both up: %v, in use %s", err, e.Current())
	}
	a.stop()
	if err := e.Health(ctx5(t)); err != nil || e.Current() != b.addr {
		t.Fatalf("first down: %v, in use %s", err, e.Current())
	}
	if d := e.Describe(); !strings.Contains(d, "(no answer at start: proxy "+a.addr+" is not reachable") || !strings.Contains(d, b.addr+" (in use)") {
		t.Errorf("Describe: %s", d)
	}
	b.stop()
	if err := e.Health(ctx5(t)); err == nil || !strings.HasPrefix(err.Error(), "no exit answered: ") {
		t.Errorf("both down: %v", err)
	}
}

// A first exit that never answers does not hold up the start: the health
// check gives up on it after the list's limit.
func TestExitsHealthSilentFirst(t *testing.T) {
	e, _, b, _ := failoverPair(t, func(s *standIn) { s.silent = true })
	t0 := time.Now()
	if err := e.Health(ctx5(t)); err != nil || e.Current() != b.addr {
		t.Fatalf("silent first: %v, in use %s", err, e.Current())
	}
	// Well under the 5 seconds the test's context allows: a list that
	// ignored its own limit would wait for the context.
	if d := time.Since(t0); d > 4*time.Second {
		t.Errorf("health took %s", d)
	}
}

func TestExitsFailover(t *testing.T) {
	for _, how := range []string{"killed", "silent", "closes early"} {
		t.Run(how, func(t *testing.T) {
			var setup func(*standIn)
			if how == "silent" {
				setup = func(s *standIn) { s.silent = true }
			}
			if how == "closes early" {
				setup = func(s *standIn) { s.closeEarly = true }
			}
			e, a, b, _ := failoverPair(t, setup)
			if how == "killed" {
				// A works, then dies.
				c, err := e.Dial(ctx5(t), "x.test", nil, 80)
				if err != nil {
					t.Fatal(err)
				}
				c.Close()
				<-a.got
				a.stop()
			}
			var log switchLog
			info := log.conn(2)
			c, err := e.Dial(WithConn(ctx5(t), info), "x.test", nil, 80)
			if err != nil {
				t.Fatalf("failover: %v", err)
			}
			c.Close()
			r := <-b.got
			if r.headers["vpnw-conn"] != "2" || info.Exit != b.addr || e.Current() != b.addr {
				t.Errorf("after the switch: %+v, exit %s, in use %s", r, info.Exit, e.Current())
			}
			if s := log.list(); len(s) != 1 || !strings.HasPrefix(s[0], a.addr+">"+b.addr+" ") {
				t.Errorf("switches: %v", s)
			}
			// The next connection goes straight to B.
			before := a.accepted.Load()
			info = log.conn(3)
			c, err = e.Dial(WithConn(ctx5(t), info), "x.test", nil, 80)
			if err != nil {
				t.Fatal(err)
			}
			c.Close()
			<-b.got
			if a.accepted.Load() != before || len(log.list()) != 1 || info.Exit != b.addr {
				t.Errorf("the next connection went back to A or switched again: %v", log.list())
			}
		})
	}
}

// An exit that answers, even with a refusal, keeps the list where it is.
func TestExitsNoFailoverOnRefusal(t *testing.T) {
	e, a, b, _ := failoverPair(t, func(s *standIn) {
		s.answer = "HTTP/1.1 403 Forbidden\r\nVPNW-Rule: default\r\nVPNW-Reason: no allow rule matches\r\n"
	})
	var log switchLog
	info := log.conn(1)
	_, err := e.Dial(WithConn(ctx5(t), info), "x.test", nil, 80)
	if err == nil || !strings.Contains(err.Error(), "the exit refused it (default)") {
		t.Fatalf("refusal: %v", err)
	}
	<-a.got
	if e.Current() != a.addr || len(log.list()) != 0 || b.accepted.Load() != 0 || info.Exit != a.addr {
		t.Errorf("a refusal moved the list: in use %s, switches %v", e.Current(), log.list())
	}
}

func TestExitsAllDown(t *testing.T) {
	e, a, b, _ := failoverPair(t, nil)
	a.stop()
	b.stop()
	var log switchLog
	_, err := e.Dial(WithConn(ctx5(t), log.conn(1)), "x.test", nil, 80)
	if err == nil || !strings.HasPrefix(err.Error(), "no exit answered: proxy "+a.addr) {
		t.Errorf("all down: %v", err)
	}
	if len(log.list()) != 2 {
		t.Errorf("switches: %v", log.list())
	}
	if e.Kind() != "exits" || e.ID() != "exits" {
		t.Error("kind or id")
	}
}

// Many connections at once, while the first exit dies: every one opens,
// and the list ends on B.
func TestExitsFailoverConcurrent(t *testing.T) {
	e, a, b, _ := failoverPair(t, nil)
	// Sixteen TLS handshakes at once on a busy machine can take longer than
	// the short limit the other tests use, and B would count as dead too.
	e.Limit = ExitLimit
	go func() {
		for range b.got {
		}
	}()
	go func() {
		for range a.got {
		}
	}()
	a.stop()
	var wg sync.WaitGroup
	var failed atomic.Int64
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(id uint64) {
			defer wg.Done()
			var log switchLog
			c, err := e.Dial(WithConn(ctx5(t), log.conn(id)), "x.test", nil, 80)
			if err != nil {
				failed.Add(1)
				return
			}
			c.Close()
		}(uint64(i + 1))
	}
	wg.Wait()
	if failed.Load() != 0 || e.Current() != b.addr {
		t.Errorf("%d failed, in use %s", failed.Load(), e.Current())
	}
}

func TestConnContext(t *testing.T) {
	if ConnOf(context.Background()) != nil {
		t.Error("an empty context has no Conn")
	}
	c := &Conn{Run: "r-1", ID: 9}
	if ConnOf(WithConn(context.Background(), c)) != c {
		t.Error("Conn lost")
	}
	x := &exitIDs{conn: &Conn{Run: "bad run\r\nX: y", ID: 1}}
	if x.headers() != nil || x.socksUser("u", "p") != "u" {
		t.Error("a run ID that is not safe to send was sent")
	}
}
