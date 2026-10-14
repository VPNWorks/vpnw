// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package broker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/VPNWorks/vpnw/internal/config"
	"github.com/VPNWorks/vpnw/internal/events"
	"github.com/VPNWorks/vpnw/internal/path"
)

// tokens is a test's set of exit clients, by token.
type tokens map[string]*Client

func (m tokens) Login(tok string) *Client { return m[tok] }

// exitRig is a broker serving as an exit, with two clients: a, whose policy
// allows echo.test and missing.test, and b, whose policy allows only
// other.test. It speaks plain TCP; TLS is the listener's business.
func exitRig(t *testing.T, guards ...Guard) *rig {
	t.Helper()
	old := RefusedLoginDelay
	RefusedLoginDelay = 0
	t.Cleanup(func() { RefusedLoginDelay = old })
	mem := &events.Memory{}
	bus := events.NewBus("x-test", nil)
	bus.Add(mem)
	dns := &fakeDNS{m: map[string][]net.IP{
		"echo.test":     {net.ParseIP("127.0.0.1")},
		"other.test":    {net.ParseIP("127.0.0.1")},
		"db.corp.test":  {net.ParseIP("10.2.3.4")},
		"nopolicy.test": {net.ParseIP("127.0.0.1")},
	}}
	a := &Client{Name: "a", Policy: pol(t, config.PolicySpec{Default: "deny", Allow: []string{"echo.test", "missing.test"}}), Path: &path.Direct{}, Source: "127.0.0.1"}
	b := &Client{Name: "b", Policy: pol(t, config.PolicySpec{Default: "deny", Allow: []string{"other.test"}}), Path: &path.Direct{}, Source: "127.0.0.1"}
	c := &Client{Name: "c", Policy: pol(t, config.PolicySpec{Default: "allow", DenyPrivate: true}), Path: &path.Direct{}, Source: "127.0.0.1"}
	n := &Client{Name: "n", Path: &path.Direct{}, Source: "127.0.0.1"}
	br := &Broker{Exit: &Exit{Name: "exit-test", Clients: tokens{"tok-a": a, "tok-b": b, "tok-c": c, "tok-n": n}}, Resolver: dns, Bus: bus, DialTimeout: 3 * time.Second, Guards: guards}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go br.Serve(l)
	t.Cleanup(func() { l.Close(); br.Shutdown(time.Second) })
	return &rig{b: br, addr: l.Addr().String(), mem: mem, dns: dns}
}

func basic(tok string) string {
	return "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("vpnw:"+tok)) + "\r\n"
}

// exitAsk sends a raw HTTP request and reads the answer's status line and
// headers.
func exitAsk(t *testing.T, addr, raw string) (net.Conn, *bufio.Reader, string, map[string]string) {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(5 * time.Second))
	io.WriteString(c, raw)
	br := bufio.NewReader(c)
	status, _ := br.ReadString('\n')
	h := map[string]string{}
	for {
		l, err := br.ReadString('\n')
		if err != nil || l == "\r\n" {
			break
		}
		k, v, _ := strings.Cut(strings.TrimSpace(l), ":")
		h[strings.ToLower(k)] = strings.TrimSpace(v)
	}
	return c, br, strings.TrimSpace(status), h
}

func (r *rig) events(typ string) []events.Event {
	var out []events.Event
	for _, e := range r.mem.Snapshot() {
		if e.Type == typ {
			out = append(out, e)
		}
	}
	return out
}

// An allowed CONNECT is carried, and its first event names the client and
// its IDs; the connection's open event says where it really left from.
func TestExitConnect(t *testing.T) {
	port, _ := echoServer(t)
	r := exitRig(t)
	c, br, status, _ := exitAsk(t, r.addr, fmt.Sprintf("CONNECT echo.test:%d HTTP/1.1\r\n%sVPNW-Run: r-3f9a1c\r\nVPNW-Conn: 17\r\n\r\n", port, basic("tok-a")))
	if status != "HTTP/1.1 200 Connection established" {
		t.Fatalf("status %q", status)
	}
	io.WriteString(c, "hi\n")
	line, _ := br.ReadString('\n')
	if strings.TrimSpace(line) != "hello hi" {
		t.Fatalf("relay: %q", line)
	}
	c.Close()
	waitEvents(r, events.ConnectionClose, 1)
	at := r.events(events.ConnectionAttempt)
	if len(at) != 1 {
		t.Fatalf("attempts: %v", r.types())
	}
	f := at[0].Fields
	if f["client"] != "a" || f["client_run"] != "r-3f9a1c" || f["client_conn"] != uint64(17) || f["source"] != "127.0.0.1" || !strings.HasPrefix(f["peer"].(string), "127.0.0.1:") || f["host"] != "echo.test" {
		t.Errorf("attempt: %v", f)
	}
	op := r.events(events.ConnectionOpen)
	if len(op) != 1 || op[0].Fields["source"] != "127.0.0.1" || op[0].Path != "direct" {
		t.Errorf("open: %+v", op)
	}
	if got := r.types(); strings.Join(got, " ") != "connection.attempt policy.allow dns.query dns.result connection.open connection.close" {
		t.Errorf("steps: %v", got)
	}
}

// Requests an exit refuses, and what it answers. The token is never in its
// record.
func TestExitRefusals(t *testing.T) {
	port, _ := echoServer(t)
	r := exitRig(t)
	target := fmt.Sprintf("echo.test:%d", port)
	cases := []struct {
		name, raw, status, has string
		authDeny               bool
	}{
		{"no token", "CONNECT " + target + " HTTP/1.1\r\n\r\n", "407", "no token", true},
		{"unknown token", "CONNECT " + target + " HTTP/1.1\r\n" + basic("tok-x") + "\r\n", "407", "not known here", true},
		{"not Basic", "CONNECT " + target + " HTTP/1.1\r\nProxy-Authorization: Bearer tok-a\r\n\r\n", "407", "not Basic", true},
		{"not base64", "CONNECT " + target + " HTTP/1.1\r\nProxy-Authorization: Basic !!!\r\n\r\n", "407", "base64", true},
		{"empty token", "CONNECT " + target + " HTTP/1.1\r\nProxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("vpnw:")) + "\r\n\r\n", "407", "no token", true},
		{"the token as the user name", "CONNECT " + target + " HTTP/1.1\r\nProxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("tok-a:x")) + "\r\n\r\n", "407", "not known here", true},
		{"no colon", "CONNECT " + target + " HTTP/1.1\r\nProxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte("tok-a")) + "\r\n\r\n", "407", "no token", true},
		{"two tokens", "CONNECT " + target + " HTTP/1.1\r\n" + basic("tok-a") + basic("tok-b") + "\r\n", "400", "Proxy-Authorization is given more than once", false},
		{"two runs", "CONNECT " + target + " HTTP/1.1\r\n" + basic("tok-a") + "VPNW-Run: r-1\r\nvpnw-run: r-2\r\nVPNW-Conn: 1\r\n\r\n", "400", "VPNW-Run is given more than once", false},
		{"run without conn", "CONNECT " + target + " HTTP/1.1\r\n" + basic("tok-a") + "VPNW-Run: r-1\r\n\r\n", "400", "go together", false},
		{"conn 0", "CONNECT " + target + " HTTP/1.1\r\n" + basic("tok-a") + "VPNW-Run: r-1\r\nVPNW-Conn: 0\r\n\r\n", "400", "from 1 up", false},
		{"conn 01", "CONNECT " + target + " HTTP/1.1\r\n" + basic("tok-a") + "VPNW-Run: r-1\r\nVPNW-Conn: 01\r\n\r\n", "400", "from 1 up", false},
		{"conn too large", "CONNECT " + target + " HTTP/1.1\r\n" + basic("tok-a") + "VPNW-Run: r-1\r\nVPNW-Conn: 18446744073709551616\r\n\r\n", "400", "too large", false},
		{"bad run", "CONNECT " + target + " HTTP/1.1\r\n" + basic("tok-a") + "VPNW-Run: r!1\r\nVPNW-Conn: 1\r\n\r\n", "400", "letters, digits", false},
		{"plain HTTP", "GET http://" + target + "/ HTTP/1.1\r\n" + basic("tok-a") + "\r\n", "400", "an exit takes CONNECT", false},
		{"health without token", "GET /health HTTP/1.1\r\n\r\n", "407", "no token", true},
		{"refused by the policy", "CONNECT evil.test:443 HTTP/1.1\r\n" + basic("tok-a") + "\r\n", "403", "vpnw exit: blocked evil.test:443 (default:", false},
		{"another client's policy", "CONNECT " + target + " HTTP/1.1\r\n" + basic("tok-b") + "\r\n", "403", "no allow rule matches " + target, false},
		{"cannot reach", "CONNECT missing.test:443 HTTP/1.1\r\n" + basic("tok-a") + "\r\n", "502", "cannot reach missing.test:443: dns: no such host", false},
		{"what the exit's DNS says stays at the exit", "CONNECT db.corp.test:443 HTTP/1.1\r\n" + basic("tok-c") + "\r\n", "403", "an address db.corp.test resolves to at the exit is refused by deny_private", false},
		{"a client without a policy", "CONNECT nopolicy.test:443 HTTP/1.1\r\n" + basic("tok-n") + "\r\n", "403", "the exit has no policy for client n", false},
	}
	denials := 0
	for _, k := range cases {
		_, br, status, h := exitAsk(t, r.addr, k.raw)
		body, _ := io.ReadAll(br)
		if !strings.HasPrefix(status, "HTTP/1.1 "+k.status) || !strings.Contains(string(body)+h["vpnw-reason"], k.has) {
			t.Errorf("%s: %q %v %q", k.name, status, h, body)
		}
		if k.status == "403" && (h["vpnw-rule"] == "" || h["vpnw-reason"] == "") {
			t.Errorf("%s: no VPNW-Rule and VPNW-Reason: %v", k.name, h)
		}
		if strings.Contains(string(body)+h["vpnw-reason"], "10.2.3.4") {
			t.Errorf("%s: the answer holds the exit's DNS answer: %v %q", k.name, h, body)
		}
		if k.status == "407" && h["proxy-authenticate"] == "" {
			t.Errorf("%s: no Proxy-Authenticate", k.name)
		}
		if k.authDeny {
			denials++
		}
		if n := len(r.events(events.AuthDeny)); n != denials {
			t.Errorf("%s: %d auth.deny events, want %d", k.name, n, denials)
		}
	}
	// The health check, with a token.
	_, br, status, _ := exitAsk(t, r.addr, "GET /health HTTP/1.1\r\n"+basic("tok-b")+"\r\n")
	if body, _ := io.ReadAll(br); status != "HTTP/1.1 200 OK" || string(body) != "exit-test\n" {
		t.Errorf("health: %q %q", status, body)
	}
	ad := r.events(events.AuthDeny)
	if ad[0].Fields["proto"] != "http-connect" || ad[0].Fields["host"] != "echo.test" || ad[0].Fields["port"] != port {
		t.Errorf("auth.deny: %v", ad[0].Fields)
	}
	if st := r.b.Stats(); st.AuthDenied != int64(denials) || st.HealthChecks != 1 || st.Denied != 4 || st.Failed != 1 {
		t.Errorf("stats: %+v", st)
	}
	// The record keeps the whole reason.
	found := false
	for _, e := range r.events(events.PolicyDeny) {
		found = found || strings.Contains(e.Fields["reason"].(string), "db.corp.test resolved to 10.2.3.4")
	}
	if !found {
		t.Error("the exit's record lost the reason")
	}
	b, _ := json.Marshal(r.mem.Snapshot())
	for _, tok := range []string{"tok-a", "tok-b", "tok-x", base64.StdEncoding.EncodeToString([]byte("vpnw:tok-a"))} {
		if strings.Contains(string(b), tok) {
			t.Errorf("the record holds the token %q", tok)
		}
	}
}

// socksTalk logs in with user and pass and asks to CONNECT host:port. It
// returns the login status and the reply code; -1 means no answer.
func socksTalk(t *testing.T, addr string, methods []byte, user, pass string, cmd byte, host string, port int) (net.Conn, int, int) {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	c.SetDeadline(time.Now().Add(5 * time.Second))
	c.Write(append([]byte{0x05, byte(len(methods))}, methods...))
	var m [2]byte
	if _, err := io.ReadFull(c, m[:]); err != nil || m[1] != 0x02 {
		return c, -int(m[1]), -1
	}
	auth := append([]byte{0x01, byte(len(user))}, user...)
	auth = append(append(auth, byte(len(pass))), pass...)
	c.Write(auth)
	var a [2]byte
	if _, err := io.ReadFull(c, a[:]); err != nil {
		return c, -1, -1
	}
	if a[1] != 0x00 {
		return c, int(a[1]), -1
	}
	req := []byte{0x05, cmd, 0x00, 0x03, byte(len(host))}
	req = append(append(req, host...), byte(port>>8), byte(port))
	c.Write(req)
	var rep [10]byte
	if _, err := io.ReadFull(c, rep[:]); err != nil {
		return c, 0, -1
	}
	return c, 0, int(rep[1])
}

func TestExitSOCKS5(t *testing.T) {
	port, _ := echoServer(t)
	r := exitRig(t)
	// No user-and-password login offered.
	if _, login, _ := socksTalk(t, r.addr, []byte{0x00}, "", "", 1, "echo.test", port); login != -0xff {
		t.Errorf("no login: %d", login)
	}
	if _, login, _ := socksTalk(t, r.addr, []byte{0x00, 0x02}, "vpnw", "tok-x", 1, "echo.test", port); login != 1 {
		t.Errorf("unknown token: %d", login)
	}
	if _, login, _ := socksTalk(t, r.addr, []byte{0x02}, "r-1/0", "tok-a", 1, "echo.test", port); login != 1 {
		t.Errorf("bad IDs: %d", login)
	}
	if n := len(r.events(events.AuthDeny)); n != 3 {
		t.Errorf("%d auth.deny events, want 3", n)
	}
	// IDs in the user name.
	c, login, rep := socksTalk(t, r.addr, []byte{0x02}, "r-3f9a1c/9", "tok-a", 1, "echo.test", port)
	if login != 0 || rep != 0 {
		t.Fatalf("connect: login %d reply %d", login, rep)
	}
	io.WriteString(c, "x\n")
	if line, _ := bufio.NewReader(c).ReadString('\n'); strings.TrimSpace(line) != "hello x" {
		t.Errorf("relay: %q", line)
	}
	// No IDs, a denial, another client, and BIND.
	if _, login, rep := socksTalk(t, r.addr, []byte{0x02}, "vpnw", "tok-a", 1, "evil.test", 443); login != 0 || rep != 2 {
		t.Errorf("denied: %d %d", login, rep)
	}
	if _, login, rep := socksTalk(t, r.addr, []byte{0x02}, "vpnw", "tok-b", 1, "echo.test", port); login != 0 || rep != 2 {
		t.Errorf("b's policy: %d %d", login, rep)
	}
	if _, login, rep := socksTalk(t, r.addr, []byte{0x02}, "vpnw", "tok-a", 2, "echo.test", port); login != 0 || rep != 7 {
		t.Errorf("bind: %d %d", login, rep)
	}
	waitEvents(r, events.PolicyDeny, 3)
	at := r.events(events.ConnectionAttempt)
	if len(at) != 4 || at[0].Fields["client_run"] != "r-3f9a1c" || at[0].Fields["client_conn"] != uint64(9) || at[0].Fields["proto"] != "socks5" {
		t.Fatalf("attempts: %+v", at)
	}
	if _, ok := at[1].Fields["client_run"]; ok || at[2].Fields["client"] != "b" || at[3].Fields["proto"] != "socks5-bind" || at[3].Fields["client"] != "a" {
		t.Errorf("attempts: %+v", at[1:])
	}
}

// guardFunc is a Guard in a function.
type guardFunc func(GuardRequest) (bool, string)

func (guardFunc) Name() string { return "test" }
func (g guardFunc) Check(_ context.Context, r GuardRequest) (bool, string, error) {
	d, why := g(r)
	return d, why, nil
}

// A Guard at the exit is told which client asked.
func TestExitGuardSeesClient(t *testing.T) {
	port, _ := echoServer(t)
	var seen []string
	r := exitRig(t, guardFunc(func(q GuardRequest) (bool, string) {
		seen = append(seen, q.Client+" "+q.Host+" "+q.Path)
		return q.Client == "a", "not today, " + q.Client
	}))
	_, br, status, h := exitAsk(t, r.addr, fmt.Sprintf("CONNECT echo.test:%d HTTP/1.1\r\n%s\r\n", port, basic("tok-a")))
	io.ReadAll(br)
	if !strings.HasPrefix(status, "HTTP/1.1 403") || h["vpnw-rule"] != "plugin:test" || h["vpnw-reason"] != "not today, a" {
		t.Errorf("%q %v", status, h)
	}
	if len(seen) != 1 || seen[0] != "a echo.test direct" {
		t.Errorf("guard saw %q", seen)
	}
}

// ids are parsed strictly, the same in a header and in a user name.
func TestExitIDs(t *testing.T) {
	for user, want := range map[string]string{
		"vpnw":                           "|0",
		"":                               "|0",
		"r-3f9a1c/17":                    "r-3f9a1c|17",
		"ci_job.42/18446744073709551615": "ci_job.42|18446744073709551615",
	} {
		run, conn, err := idsFromUser(user)
		if err != nil || fmt.Sprintf("%s|%d", run, conn) != want {
			t.Errorf("%q: %s %d %v", user, run, conn, err)
		}
	}
	for _, bad := range []string{"r/0", "r/01", "r/-1", "r/1x", "r/18446744073709551616", "/1", "r r/1", "r/1/", "r/1/x", strings.Repeat("r", 65) + "/1", "r/"} {
		if _, _, err := idsFromUser(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if _, _, err := idsFromHeaders("", "5"); err == nil {
		t.Error("a conn without a run")
	}
}

// failPath never connects: both ends of the comparison below fail the same
// way after they decide.
type failPath struct{}

func (failPath) ID() string       { return "same" }
func (failPath) Kind() string     { return "direct" }
func (failPath) RemoteDNS() bool  { return false }
func (failPath) Describe() string { return "same" }
func (failPath) Dial(context.Context, string, net.IP, int) (net.Conn, error) {
	return nil, fmt.Errorf("not connecting in this test")
}
func (failPath) Health(context.Context) error { return nil }

// steps is what a record says about each connection, without who asked:
// one line per event after the attempt.
func steps(evs []events.Event) map[uint64][]string {
	out := map[uint64][]string{}
	for _, e := range evs {
		if e.Conn == 0 || e.Type == events.ConnectionAttempt {
			continue
		}
		f := map[string]any{}
		for k, v := range e.Fields {
			switch k {
			case "ms", "source", "client", "peer", "client_run", "client_conn":
				continue
			}
			f[k] = v
		}
		b, _ := json.Marshal(f)
		out[e.Conn] = append(out[e.Conn], e.Type+" "+string(b))
	}
	return out
}

// The exit decides with the code that decides a run's connections, so the
// two can't drift apart: for every destination and policy here, a run's
// broker deciding for its program and an exit deciding for a client with
// the same policy take the same steps, reach the same decision by the same
// rule, and give the same reason.
func TestSameDecisionAtBothEnds(t *testing.T) {
	dns := map[string][]net.IP{
		"api.partner.test":      {net.ParseIP("51.15.0.10")},
		"www.partner.test":      {net.ParseIP("51.15.0.11"), net.ParseIP("2001:db8::11")},
		"intranet.partner.test": {net.ParseIP("10.50.0.5")},
		"rebind.test":           {net.ParseIP("51.15.0.12"), net.ParseIP("127.0.0.1")},
		"metadata.test":         {net.ParseIP("169.254.169.254")},
		"cdn.example":           {net.ParseIP("93.184.215.14")},
	}
	hosts := []string{"api.partner.test", "API.Partner.Test.", "www.partner.test", "partner.test", "intranet.partner.test",
		"rebind.test", "metadata.test", "cdn.example", "missing.test", "bad..name", "-x.test", "51.15.0.99", "10.0.0.7",
		"127.0.0.1", "169.254.169.254", "::1", "2001:db8::99", "192.168.1.1", "0.0.0.0"}
	ports := []int{443, 8080, 22}
	policies := []config.PolicySpec{
		{},
		{Default: "allow"},
		{Default: "allow", DenyPrivate: true},
		{Default: "deny", Allow: []string{"api.partner.test", "*.partner.test"}},
		{Default: "deny", DenyPrivate: true, Allow: []string{"*.partner.test", "rebind.test", "metadata.test"}},
		{Allow: []string{"51.15.0.0/24", "cdn.example:443"}},
		{Default: "allow", Deny: []string{"10.0.0.0/8", "*.partner.test:22", "::1"}},
		{Default: "deny", Allow: []string{"api.partner.test:443", "127.0.0.1:8080", "2001:db8::/32"}, Deny: []string{"api.partner.test:22"}},
		{Default: "allow", DenyPrivate: true, Deny: []string{"cdn.example"}, Allow: []string{"10.50.0.5"}},
	}
	total, same := 0, 0
	for i, spec := range policies {
		p := pol(t, spec)
		runMem, exitMem := &events.Memory{}, &events.Memory{}
		runBus, exitBus := events.NewBus("r-same", nil), events.NewBus("x-same", nil)
		runBus.Add(runMem)
		exitBus.Add(exitMem)
		run := &Broker{Policy: p, Path: failPath{}, Resolver: &fakeDNS{m: dns}, Bus: runBus}
		ex := &Broker{Exit: &Exit{Name: "x", Clients: tokens{"tok": {Name: "c", Policy: p, Path: failPath{}}}}, Resolver: &fakeDNS{m: dns}, Bus: exitBus}
		for _, h := range hosts {
			for _, port := range ports {
				target := net.JoinHostPort(h, fmt.Sprint(port))
				run.Handle(&fakeConn{r: bytes.NewReader([]byte("CONNECT " + target + " HTTP/1.1\r\n\r\n"))})
				ex.Handle(&fakeConn{r: bytes.NewReader([]byte("CONNECT " + target + " HTTP/1.1\r\n" + basic("tok") + "\r\n"))})
				total++
			}
		}
		a, b := steps(runMem.Snapshot()), steps(exitMem.Snapshot())
		if len(a) != len(hosts)*len(ports) || len(b) != len(a) {
			t.Fatalf("policy %d: %d and %d connections", i, len(a), len(b))
		}
		for id := range a {
			if strings.Join(a[id], "\n") != strings.Join(b[id], "\n") {
				t.Errorf("policy %d, connection %d:\n run:  %q\n exit: %q", i, id, a[id], b[id])
				continue
			}
			same++
		}
		if rs, es := run.Stats(), ex.Stats(); rs.Allowed != es.Allowed || rs.Denied != es.Denied || rs.Failed != es.Failed {
			t.Errorf("policy %d: totals %+v and %+v", i, rs, es)
		}
	}
	if same == total && !t.Failed() {
		t.Logf("%d of %d requests decided the same way at both ends", same, total)
	}
}

// Before a token, little is held: a peer gets MaxPendingPerPeer
// connections that haven't logged in, each for ExitHandshakeTime, and a
// flood of wrong tokens fills the record only up to authDenyBurst in each
// window, with a count of the rest.
func TestExitLimitsBeforeLogin(t *testing.T) {
	oldPer, oldTime := MaxPendingPerPeer, ExitHandshakeTime
	MaxPendingPerPeer, ExitHandshakeTime = 3, 300*time.Millisecond
	defer func() { MaxPendingPerPeer, ExitHandshakeTime = oldPer, oldTime }()
	var now time.Time
	var mu sync.Mutex
	r := exitRig(t)
	r.b.Clock = func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	mu.Lock()
	now = time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	mu.Unlock()
	var idle []net.Conn
	for i := 0; i < 3; i++ {
		c, err := net.Dial("tcp", r.addr)
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		idle = append(idle, c)
	}
	time.Sleep(50 * time.Millisecond)
	// The fourth from this address is closed at once.
	c, _ := net.Dial("tcp", r.addr)
	c.SetDeadline(time.Now().Add(2 * time.Second))
	t0 := time.Now()
	if _, err := c.Read(make([]byte, 1)); err == nil || time.Since(t0) > 200*time.Millisecond {
		t.Errorf("a fourth waiting connection was kept: %v after %v", err, time.Since(t0))
	}
	c.Close()
	// The idle ones are closed after ExitHandshakeTime, and then there is
	// room again.
	idle[0].SetDeadline(time.Now().Add(3 * time.Second))
	t0 = time.Now()
	if _, err := idle[0].Read(make([]byte, 1)); err == nil || time.Since(t0) > 2*time.Second {
		t.Errorf("an idle connection stayed: %v after %v", err, time.Since(t0))
	}
	time.Sleep(100 * time.Millisecond)
	_, _, status, _ := exitAsk(t, r.addr, "GET /health HTTP/1.1\r\n"+basic("tok-a")+"\r\n")
	if status != "HTTP/1.1 200 OK" {
		t.Errorf("after the idle ones went: %q", status)
	}
	// 25 wrong tokens: 20 recorded, then a count of the 5 left out.
	for i := 0; i < 25; i++ {
		exitAsk(t, r.addr, "GET /health HTTP/1.1\r\n"+basic("nope")+"\r\n")
	}
	if n := len(r.events(events.AuthDeny)); n != 20 {
		t.Errorf("%d auth.deny events in the first window, want 20", n)
	}
	mu.Lock()
	now = now.Add(authDenyWindow)
	mu.Unlock()
	exitAsk(t, r.addr, "GET /health HTTP/1.1\r\n"+basic("nope")+"\r\n")
	ad := r.events(events.AuthDeny)
	if len(ad) != 21 || ad[20].Fields["unrecorded"] != int64(5) || r.b.Stats().AuthDenied != 26 {
		t.Errorf("after the window: %d events, last %v, %d counted", len(ad), ad[len(ad)-1].Fields, r.b.Stats().AuthDenied)
	}
}
