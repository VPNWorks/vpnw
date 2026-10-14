// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// Exit: the real vpnw exit serve, with the real vpnw as its client, on this
// machine. All of 127.0.0.0/8 is on a Linux machine's loopback, so clients
// get fixed addresses from 127.0.0.2 up, and servers on 127.0.0.1 report
// which address each connection came from.
//
// Set VPNW_EXIT_OUT to a file to get the results as a Markdown table.

var (
	exitMu   sync.Mutex
	exitRows []string
	exitSeen = map[string]int{}
)

func exitRecord(t *testing.T, check, want, got string, ok bool) {
	res := "passed"
	if !ok {
		res = "FAILED"
	}
	exitMu.Lock()
	exitRows = append(exitRows, fmt.Sprintf("| %s | %s | %s | %s |", check, want, got, res))
	exitSeen[t.Name()]++
	exitMu.Unlock()
}

// exitGuard gives a test that stops before its check a FAILED row.
func exitGuard(t *testing.T) {
	t.Cleanup(func() {
		exitMu.Lock()
		defer exitMu.Unlock()
		if t.Failed() && exitSeen[t.Name()] == 0 {
			exitRows = append(exitRows, fmt.Sprintf("| %s | (see the test) | stopped before its check | FAILED |", t.Name()))
		}
	})
}

func exitWrite() {
	fn := os.Getenv("VPNW_EXIT_OUT")
	if fn == "" {
		return
	}
	exitMu.Lock()
	defer exitMu.Unlock()
	os.WriteFile(fn, []byte("| Check | What must happen | What happened | Result |\n|---|---|---|---|\n"+strings.Join(exitRows, "\n")+"\n"), 0o644)
}

// sourceServer answers each HTTP request with "from ADDRESS", the address
// the connection came from, and keeps a list of them.
type sourceServer struct {
	port int
	mu   sync.Mutex
	seen []string
}

func newSourceServer(t *testing.T) *sourceServer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &sourceServer{port: ln.Addr().(*net.TCPAddr).Port}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			from := c.RemoteAddr().(*net.TCPAddr).IP.String()
			s.mu.Lock()
			s.seen = append(s.seen, from)
			s.mu.Unlock()
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				for {
					l, err := br.ReadString('\n')
					if err != nil || l == "\r\n" || l == "\n" {
						break
					}
				}
				body := "from " + from + "\n"
				fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
			}(c)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return s
}

func (s *sourceServer) list() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.seen...)
}

// pyFetch fetches each URL in turn and prints GOT URL BODY or FAILED URL.
func pyFetch(urls ...string) string {
	var b strings.Builder
	b.WriteString("import urllib.request as u, sys\n")
	for _, url := range urls {
		fmt.Fprintf(&b, "try:\n    b = u.urlopen(%q, timeout=5).read().decode().strip()\n    sys.stdout.write('GOT %s ' + b + '\\n')\nexcept Exception as e:\n    sys.stdout.write('FAILED %s ' + type(e).__name__ + '\\n')\nsys.stdout.flush()\n", url, url, url)
	}
	return b.String()
}

var tokenLine = regexp.MustCompile(`token_sha256 = "([0-9a-f]{64})"`)

// exitKit is a folder with a private CA and the exits' files.
type exitKit struct {
	t *testing.T
	e *env
}

func newExitKit(t *testing.T) exitKit {
	t.Helper()
	skipIfNoSeal(t)
	exitGuard(t)
	return exitKit{t: t, e: newEnv(t)}
}

// token makes a client's token file and returns its name and hash.
func (k exitKit) token(name string) (string, string) {
	k.t.Helper()
	out := k.e.must("exit", "token", "--out", name+".token")
	m := tokenLine.FindStringSubmatch(out)
	if m == nil {
		k.t.Fatalf("token: %s", out)
	}
	return name + ".token", m[1]
}

type exitProc struct {
	*running
	name, addr, record string
}

// serve writes an exit's file with the given clients and starts it.
func (k exitKit) serve(name, clients string, extra ...string) *exitProc {
	k.t.Helper()
	k.e.must("exit", "cert", "--host", "127.0.0.1", "--name", name)
	conf := writeFile(k.t, k.e.dir, name+".toml", fmt.Sprintf("version = 1\nname = %q\nlisten = \"127.0.0.1:0\"\ncert = \"%s.crt\"\nkey = \"%s.key\"\n\n%s", name, name, name, clients))
	rec := filepath.Join(k.e.dir, name+".jsonl")
	p := &exitProc{running: k.e.start(append([]string{"exit", "serve", "--config", conf, "--out", rec}, extra...)...), name: name, record: rec}
	k.t.Cleanup(func() {
		p.cmd.Process.Signal(syscall.SIGTERM)
		select {
		case <-p.done:
		case <-time.After(20 * time.Second):
			p.cmd.Process.Kill()
			<-p.done
		}
	})
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if b, err := os.ReadFile(rec); err == nil && len(b) > 0 {
			for _, ev := range readTrace(k.t, rec) {
				if ev["type"] == "run.start" {
					p.addr = ev["fields"].(map[string]any)["listen"].(string)
					return p
				}
			}
		}
		select {
		case <-p.done:
			k.t.Fatalf("exit %s ended at once:\n%s", name, p.output())
		case <-time.After(100 * time.Millisecond):
		}
	}
	k.t.Fatalf("exit %s did not start:\n%s", name, p.output())
	return nil
}

func (p *exitProc) events(t *testing.T, typ string) []map[string]any {
	var out []map[string]any
	for _, ev := range readTrace(t, p.record) {
		if ev["type"] == typ {
			out = append(out, ev)
		}
	}
	return out
}

func fields(ev map[string]any) map[string]any {
	f, _ := ev["fields"].(map[string]any)
	return f
}

// direct is a client without vpnw: it speaks to the exit itself, over TLS,
// with a token, and checks nothing on its own side.
type direct struct {
	t           *testing.T
	addr, token string
	roots       *x509.CertPool
}

func (k exitKit) direct(addr, tokenFile string) *direct {
	k.t.Helper()
	tok, err := os.ReadFile(filepath.Join(k.e.dir, tokenFile))
	if err != nil {
		k.t.Fatal(err)
	}
	pem, _ := os.ReadFile(filepath.Join(k.e.dir, "ca.pem"))
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM(pem)
	return &direct{t: k.t, addr: addr, token: strings.TrimSpace(string(tok)), roots: roots}
}

func (d *direct) dial() *tls.Conn {
	d.t.Helper()
	c, err := tls.Dial("tcp", d.addr, &tls.Config{RootCAs: d.roots, ServerName: "127.0.0.1"})
	if err != nil {
		d.t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(10 * time.Second))
	d.t.Cleanup(func() { c.Close() })
	return c
}

// connect asks for target over HTTP CONNECT and returns the status code and
// the VPNW-Rule header; on 200 it fetches / and returns the body too.
func (d *direct) connect(target string) (string, string, string) {
	d.t.Helper()
	c := d.dial()
	fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\n\r\n", target, target, base64.StdEncoding.EncodeToString([]byte("vpnw:"+d.token)))
	br := bufio.NewReader(c)
	status, _ := br.ReadString('\n')
	rule := ""
	for {
		l, err := br.ReadString('\n')
		if err != nil || l == "\r\n" {
			break
		}
		if k, v, ok := strings.Cut(l, ":"); ok && strings.EqualFold(k, "VPNW-Rule") {
			rule = strings.TrimSpace(v)
		}
	}
	f := strings.Fields(status)
	if len(f) < 2 {
		return "no answer", "", ""
	}
	if f[1] != "200" {
		return f[1], rule, ""
	}
	io.WriteString(c, "GET / HTTP/1.0\r\n\r\n")
	b, _ := io.ReadAll(br)
	_, body, _ := strings.Cut(string(b), "\r\n\r\n")
	return "200", "", strings.TrimSpace(body)
}

// socks asks for host:port over SOCKS5 with cmd and returns the reply code.
func (d *direct) socks(cmd byte, host string, port int) int {
	d.t.Helper()
	c := d.dial()
	c.Write([]byte{0x05, 0x01, 0x02})
	var m [2]byte
	if _, err := io.ReadFull(c, m[:]); err != nil || m[1] != 0x02 {
		return -1
	}
	c.Write(append(append([]byte{0x01, 4}, "vpnw"...), append([]byte{byte(len(d.token))}, d.token...)...))
	var a [2]byte
	if _, err := io.ReadFull(c, a[:]); err != nil || a[1] != 0 {
		return -2
	}
	req := append([]byte{0x05, cmd, 0x00, 0x03, byte(len(host))}, host...)
	c.Write(append(req, byte(port>>8), byte(port)))
	var rep [10]byte
	if _, err := io.ReadFull(c, rep[:]); err != nil {
		return -3
	}
	return int(rep[1])
}

func countOf(lines []string, s string) int {
	n := 0
	for _, l := range lines {
		if l == s {
			n++
		}
	}
	return n
}

// Each client leaves from its own fixed address, or from one address of a
// pool it shares, every time.
func TestExitFixedAddresses(t *testing.T) {
	k := newExitKit(t)
	srv := newSourceServer(t)
	t1, h1 := k.token("agent-1")
	t2, h2 := k.token("agent-2")
	t3, h3 := k.token("ci")
	pol := "default = \"deny\"\nallow = [\"127.0.0.1\"]\n"
	x := k.serve("exit-a", fmt.Sprintf(`[clients.agent-1]
token_sha256 = %q
source = "127.0.0.2"
%s
[clients.agent-2]
token_sha256 = %q
source = "127.0.0.3"
%s
[clients.ci]
token_sha256 = %q
pool = "shared"
%s
[pools.shared]
addresses = ["127.0.0.4", "127.0.0.5"]
`, h1, pol, h2, pol, h3, pol))
	url := fmt.Sprintf("http://127.0.0.1:%d/", srv.port)
	for _, c := range []struct{ token, want string }{{t1, "127.0.0.2"}, {t2, "127.0.0.3"}} {
		out, code := k.e.run("guard", "--proxy", "https://"+x.addr, "--ca", "ca.pem", "--token-file", c.token, "--allow", "127.0.0.1",
			"--", "python3", "-c", pyFetch(url, url, url))
		n := strings.Count(out, "GOT "+url+" from "+c.want)
		name := strings.TrimSuffix(c.token, ".token")
		exitRecord(t, name+", with an address of its own, fetches 3 times through vpnw", "every connection leaves from "+c.want,
			fmt.Sprintf("%d of 3 from %s, exit %d", n, c.want, code), code == 0 && n == 3)
		if code != 0 || n != 3 {
			t.Errorf("%s: exit %d\n%s", name, code, out)
		}
	}
	d := k.direct(x.addr, t3)
	var froms []string
	for i := 0; i < 10; i++ {
		_, _, body := d.connect(fmt.Sprintf("127.0.0.1:%d", srv.port))
		froms = append(froms, strings.TrimPrefix(body, "from "))
	}
	first := froms[0]
	n := countOf(froms, first)
	ok := n == 10 && (first == "127.0.0.4" || first == "127.0.0.5")
	exitRecord(t, "ci, with a pool it shares, connects 10 times without vpnw", "one address of its pool, every time",
		fmt.Sprintf("%d of 10 from %s", n, first), ok)
	if !ok {
		t.Errorf("pool: %v", froms)
	}
	seen := srv.list()
	other := 0
	for _, a := range seen {
		if a != "127.0.0.2" && a != "127.0.0.3" && a != first {
			other++
		}
	}
	exitRecord(t, "what the server saw", "only the clients' own addresses", fmt.Sprintf("%d connections, %d from any other address", len(seen), other), other == 0 && len(seen) == 16)
	if other != 0 || len(seen) != 16 {
		t.Errorf("server saw %v", seen)
	}
}

// A client that skips its own policy, or someone holding its token, gets
// nothing that policy refuses: the exit decides again, and resolves names
// itself, so deny_private sees where a name really points.
func TestExitTamperedClient(t *testing.T) {
	k := newExitKit(t)
	srv := newSourceServer(t)
	tok, h := k.token("agent")
	x := k.serve("exit-a", fmt.Sprintf(`[clients.agent]
token_sha256 = %q
source = "127.0.0.2"
default = "deny"
deny_private = true
allow = ["localhost", "*.partner.test"]
`, h))
	d := k.direct(x.addr, tok)
	p := srv.port
	type ask struct{ what, target string }
	asks := []ask{
		{"by address", fmt.Sprintf("127.0.0.1:%d", p)},
		{"by an allowed name that points at loopback", fmt.Sprintf("localhost:%d", p)},
		{"the same name in capitals with a dot", fmt.Sprintf("LOCALHOST.:%d", p)},
		{"IPv6 loopback", fmt.Sprintf("[::1]:%d", p)},
		{"cloud metadata", "169.254.169.254:80"},
		{"a private address", "10.0.0.1:80"},
		{"a name the policy doesn't allow", "attacker.example:443"},
		{"a name in an allowed domain's parent", "partner.test:443"},
	}
	refused := 0
	rules := map[string]int{}
	for _, a := range asks {
		code, rule, _ := d.connect(a.target)
		if code == "403" {
			refused++
			rules["refused by "+rule]++
		} else {
			t.Errorf("%s (%s): %s", a.what, a.target, code)
		}
	}
	for _, s := range []struct {
		cmd  byte
		host string
	}{{1, "127.0.0.1"}, {1, "localhost"}, {2, "localhost"}} {
		rep := d.socks(s.cmd, s.host, p)
		if rep == 2 || rep == 7 {
			refused++
			rules[map[int]string{2: "refused over SOCKS5", 7: "BIND refused over SOCKS5"}[rep]]++
		} else {
			t.Errorf("socks5 %d %s: reply %d", s.cmd, s.host, rep)
		}
	}
	total := len(asks) + 3
	var rl []string
	for r, n := range rules {
		rl = append(rl, fmt.Sprintf("%d %s", n, r))
	}
	sort.Strings(rl)
	reached := len(srv.list())
	ok := refused == total && reached == 0
	exitRecord(t, fmt.Sprintf("a client sends %d forbidden requests straight to the exit, with its valid token", total),
		"every one refused by the client's own policy at the exit; none reaches a server",
		fmt.Sprintf("%d of %d refused (%s), %d reached a server", refused, total, strings.Join(rl, ", "), reached), ok)
	if !ok {
		t.Errorf("refused %d of %d, reached %d", refused, total, reached)
	}
}

// One policy file at both ends: the exit allows exactly what the client let
// through, by the same rule, and the two records line up on the client's
// run and connection IDs.
func TestExitAgreesWithClient(t *testing.T) {
	k := newExitKit(t)
	s1, s2 := newSourceServer(t), newSourceServer(t)
	tok, h := k.token("agent")
	writeFile(t, k.e.dir, "agent.toml", fmt.Sprintf("version = 1\nname = \"agent\"\n[policy]\ndefault = \"deny\"\nallow = [\"localhost:%d\", \"127.0.0.1:%d\"]\n", s1.port, s2.port))
	x := k.serve("exit-a", fmt.Sprintf("[clients.agent]\ntoken_sha256 = %q\nsource = \"127.0.0.2\"\npolicy = \"agent.toml\"\n", h))
	urls := []string{
		fmt.Sprintf("http://localhost:%d/", s1.port),
		fmt.Sprintf("http://127.0.0.1:%d/", s2.port),
		fmt.Sprintf("http://127.0.0.1:%d/", s1.port),
		"http://attacker.example/",
		fmt.Sprintf("http://localhost:%d/", s2.port),
	}
	rec := filepath.Join(k.e.dir, "client.jsonl")
	out, code := k.e.run("guard", "--proxy", "https://"+x.addr, "--ca", "ca.pem", "--token-file", tok, "--policy", "agent.toml",
		"--out", rec, "--", "python3", "-c", pyFetch(urls...))
	if code != 120 || strings.Count(out, "GOT ") != 2 {
		t.Fatalf("client: exit %d\n%s", code, out)
	}
	type conn struct{ host, rule, exitRule string }
	client := map[float64]*conn{}
	run := ""
	denied := 0
	for _, ev := range readTrace(t, rec) {
		id, _ := ev["conn"].(float64)
		f := fields(ev)
		switch ev["type"] {
		case "run.start":
			run = ev["run"].(string)
		case "connection.attempt":
			h, _ := f["host"].(string)
			if h == "" {
				h, _ = f["ip"].(string)
			}
			client[id] = &conn{host: fmt.Sprintf("%s:%v", h, f["port"])}
		case "policy.allow":
			client[id].rule = f["rule"].(string)
		case "policy.deny":
			denied++
		}
	}
	atExit := 0
	matched := 0
	for _, ev := range x.events(t, "connection.attempt") {
		atExit++
		f := fields(ev)
		c, ok := client[f["client_conn"].(float64)]
		h, _ := f["host"].(string)
		if h == "" {
			h, _ = f["ip"].(string)
		}
		if ok && f["client_run"] == run && c.host == fmt.Sprintf("%s:%v", h, f["port"]) {
			matched++
		}
	}
	exitRules := map[float64]string{}
	attempts := map[float64]float64{}
	for _, ev := range readTrace(t, x.record) {
		f := fields(ev)
		id, _ := ev["conn"].(float64)
		if ev["type"] == "connection.attempt" {
			attempts[id] = f["client_conn"].(float64)
		}
		if ev["type"] == "policy.allow" {
			exitRules[attempts[id]] = f["rule"].(string)
		}
	}
	same := 0
	for id, c := range client {
		if c.rule != "" && exitRules[id] == c.rule {
			same++
		}
	}
	ok := denied == 3 && atExit == 2 && matched == 2 && same == 2
	exitRecord(t, "one policy file at both ends; the program asks for 5 destinations", "the client's 3 refusals never reach the exit; the exit allows the other 2 by the same rules; the records line up",
		fmt.Sprintf("%d refused by the client, %d seen at the exit, %d allowed there by the same rule, %d of %d lined up on run and connection IDs", denied, atExit, same, matched, atExit), ok)
	if !ok {
		t.Errorf("denied %d, at exit %d, matched %d, same rule %d\n%s", denied, atExit, matched, same, out)
	}
}

// A list of exits: when the exit in use dies partway through, the rest go
// through the next one, from that exit's address, and none fails. Every
// connection the client made is in one exit's record.
func TestExitFailover(t *testing.T) {
	k := newExitKit(t)
	srv := newSourceServer(t)
	tok, h := k.token("agent")
	client := func(src string) string {
		return fmt.Sprintf("[clients.agent]\ntoken_sha256 = %q\nsource = %q\ndefault = \"deny\"\nallow = [\"127.0.0.1\"]\n", h, src)
	}
	a := k.serve("exit-a", client("127.0.0.2"))
	b := k.serve("exit-b", client("127.0.0.3"))
	url := fmt.Sprintf("http://127.0.0.1:%d/", srv.port)
	prog := fmt.Sprintf(`import urllib.request as u, sys, time
for i in range(10):
    try:
        sys.stdout.write('FETCH ' + u.urlopen(%q, timeout=10).read().decode().strip() + '\n')
    except Exception as e:
        sys.stdout.write('FAILED ' + type(e).__name__ + '\n')
    sys.stdout.flush()
    time.sleep(0.4)
`, url)
	rec := filepath.Join(k.e.dir, "client.jsonl")
	p := k.e.start("run", "--proxy", "https://"+a.addr, "--proxy", "https://"+b.addr, "--ca", "ca.pem", "--token-file", tok, "--out", rec, "--", "python3", "-c", prog)
	p.waitFor(t, "FETCH", 3, 60*time.Second)
	a.cmd.Process.Kill()
	code := p.wait(t, 60*time.Second)
	out := p.output()
	var lines []string
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, "FETCH") || strings.HasPrefix(l, "FAILED") {
			lines = append(lines, l)
		}
	}
	viaA, viaB := countOf(lines, "FETCH from 127.0.0.2"), countOf(lines, "FETCH from 127.0.0.3")
	switches := 0
	var ms float64
	clientConns := map[float64]string{}
	runID := ""
	for _, ev := range readTrace(t, rec) {
		f := fields(ev)
		switch ev["type"] {
		case "run.start":
			runID = ev["run"].(string)
		case "path.switch":
			switches++
			ms, _ = f["ms"].(float64)
		case "connection.open":
			clientConns[ev["conn"].(float64)], _ = f["exit"].(string)
		}
	}
	found := 0
	for _, x := range []*exitProc{a, b} {
		for _, ev := range x.events(t, "connection.attempt") {
			f := fields(ev)
			if f["client_run"] == runID && clientConns[f["client_conn"].(float64)] == x.addr {
				found++
			}
		}
	}
	ok := code == 0 && len(lines) == 10 && viaA >= 3 && viaA+viaB == 10 && switches == 1
	exitRecord(t, "the exit in use is killed after 3 of 10 fetches", "the rest go through the next exit, from its address; none fails",
		fmt.Sprintf("%d through exit-a from 127.0.0.2, %d through exit-b from 127.0.0.3, %d failed; the switch took %.0f ms", viaA, viaB, 10-viaA-viaB, ms), ok)
	if !ok {
		t.Errorf("exit %d, %d switches\n%s", code, switches, out)
	}
	ok = found == len(clientConns) && found == 10
	exitRecord(t, "the client's record and the exits' records", "every connection the client opened is in the record of the exit that carried it, by run and connection ID",
		fmt.Sprintf("%d of %d found", found, len(clientConns)), ok)
	if !ok {
		t.Errorf("found %d of %d", found, len(clientConns))
	}
}

// A client with the wrong token, or that trusts another CA, or asks for
// the exit by a name its certificate doesn't have, never starts its program.
func TestExitRefusesBadClients(t *testing.T) {
	k := newExitKit(t)
	_, h := k.token("agent")
	writeFile(t, k.e.dir, "wrong.token", "not-the-token\n")
	x := k.serve("exit-a", fmt.Sprintf("[clients.agent]\ntoken_sha256 = %q\nsource = \"127.0.0.2\"\ndefault = \"deny\"\n", h))
	os.Mkdir(filepath.Join(k.e.dir, "other"), 0o755)
	k.e.must("exit", "cert", "--host", "127.0.0.1", "--dir", "other")
	_, port, _ := net.SplitHostPort(x.addr)
	cases := []struct{ what, url, ca, token, want string }{
		{"with the wrong token", "https://" + x.addr, "ca.pem", "wrong.token", "the exit refused the token"},
		{"that trusts another CA", "https://" + x.addr, "other/ca.pem", "agent.token", "certificate not accepted"},
		{"asking for the exit by a name its certificate doesn't have", "https://localhost:" + port, "ca.pem", "agent.token", "certificate not accepted"},
	}
	for _, c := range cases {
		marker := filepath.Join(k.e.dir, "ran")
		out, code := k.e.run("run", "--proxy", c.url, "--ca", c.ca, "--token-file", c.token, "--", "touch", marker)
		_, err := os.Stat(marker)
		ok := code == 123 && err != nil && strings.Contains(out, c.want)
		exitRecord(t, "a client "+c.what, "the program never starts (exit 123), and vpnw says why",
			fmt.Sprintf("exit %d, program started: %v, %q", code, err == nil, c.want), ok)
		if !ok {
			t.Errorf("%s: exit %d\n%s", c.what, code, out)
		}
	}
	if ad := x.events(t, "auth.deny"); len(ad) != 1 || fields(ad[0])["proto"] != "health" {
		t.Errorf("auth.deny: %v", ad)
	}
	b, _ := os.ReadFile(x.record)
	if strings.Contains(string(b), "not-the-token") {
		t.Error("the exit's record holds a token")
	}
}

// serve refuses what it can't do: a source address this machine doesn't
// have, a listening address in use, and a broken file.
func TestExitServeChecks(t *testing.T) {
	k := newExitKit(t)
	_, h := k.token("agent")
	k.e.must("exit", "cert", "--host", "127.0.0.1", "--name", "exit-a")
	write := func(listen, source string) string {
		return writeFile(t, k.e.dir, "exit-a.toml", fmt.Sprintf("version = 1\nlisten = %q\ncert = \"exit-a.crt\"\nkey = \"exit-a.key\"\n[clients.agent]\ntoken_sha256 = %q\nsource = %q\ndefault = \"deny\"\n", listen, h, source))
	}
	conf := write("127.0.0.1:0", "192.0.2.99")
	out, code := k.e.run("exit", "serve", "--config", conf)
	ok := code == 122 && strings.Contains(out, "source address 192.0.2.99 is not on this machine")
	exitRecord(t, "a client's source address the machine doesn't have", "serve refuses to start (exit 122)", fmt.Sprintf("exit %d", code), ok)
	if !ok {
		t.Errorf("source: exit %d\n%s", code, out)
	}
	if out := k.e.must("exit", "check", "--config", conf); !strings.Contains(out, "agent: source 192.0.2.99; policy in its table (default deny") || !strings.Contains(out, "not on this machine; serve needs them") {
		t.Errorf("check:\n%s", out)
	}
	busy, _ := net.Listen("tcp", "127.0.0.1:0")
	defer busy.Close()
	conf = write(busy.Addr().String(), "127.0.0.2")
	if out, code := k.e.run("exit", "serve", "--config", conf); code != 122 || !strings.Contains(out, "cannot listen on") {
		t.Errorf("busy: exit %d\n%s", code, out)
	}
	bad := writeFile(t, k.e.dir, "bad.toml", "version = 1\nlisten = \"127.0.0.1:0\"\ncert = \"c\"\nkey = \"k\"\n[clients.a]\ntoken_sha256 = \"abc\"\n")
	if out, code := k.e.run("exit", "serve", "--config", bad); code != 121 || !strings.Contains(out, "bad.toml:6: token_sha256 must be 64 hexadecimal characters") {
		t.Errorf("bad file: exit %d\n%s", code, out)
	}
	if out, code := k.e.run("exit", "token", "--out", "agent.token"); code != 121 || !strings.Contains(out, "never overwritten") {
		t.Errorf("token over a token: exit %d\n%s", code, out)
	}
	if out, code := k.e.run("exit", "cert", "--host", "127.0.0.1", "--name", "exit-a"); code != 121 || !strings.Contains(out, "never overwritten") {
		t.Errorf("cert over a cert: exit %d\n%s", code, out)
	}
}

// Apps run at the exit too: a Guard plugin refuses what a client's policy
// allowed, and Ledger seals the exit's record. The exit stops cleanly on
// SIGTERM and says so in its record.
func TestExitPlugins(t *testing.T) {
	k := newExitKit(t)
	srv := newSourceServer(t)
	k.e.must("plugin", "add", "--allow-unsigned", testPlugin(t, "blocker"))
	tok, h := k.token("agent")
	ledger := filepath.Join(k.e.dir, "exit.ledger")
	x := k.serve("exit-a", fmt.Sprintf("[clients.agent]\ntoken_sha256 = %q\nsource = \"127.0.0.2\"\ndefault = \"deny\"\nallow = [\"localhost\", \"127.0.0.1\"]\n", h),
		"--plugin", "blocker", "--set", "blocker.deny=localhost", "--plugin", "ledger", "--plugin-file", "ledger="+ledger)
	d := k.direct(x.addr, tok)
	codeL, rule, _ := d.connect(fmt.Sprintf("localhost:%d", srv.port))
	codeI, _, body := d.connect(fmt.Sprintf("127.0.0.1:%d", srv.port))
	x.cmd.Process.Signal(syscall.SIGTERM)
	exitCode := x.wait(t, 20*time.Second)
	ends := x.events(t, "run.end")
	out, vcode := k.e.run("verify", ledger)
	verdict := strings.TrimSpace(strings.SplitN(out, "\n", 2)[0])
	if i := strings.Index(verdict, "holds "); i >= 0 && strings.HasPrefix(verdict, "intact") {
		verdict = "intact, " + strings.SplitN(verdict[i+len("holds "):], " of run", 2)[0]
	}
	ok := codeL == "403" && rule == "plugin:blocker" && codeI == "200" && body == "from 127.0.0.2" && exitCode == 0 && len(ends) == 1 && vcode == 0 && strings.Contains(out, "intact")
	exitRecord(t, "a Guard plugin and Ledger at the exit", "the Guard refuses what the client's policy allowed; Ledger seals the exit's record; SIGTERM ends it cleanly",
		fmt.Sprintf("localhost: %s by %s; 127.0.0.1: %s, %s; exit code %d; ledger: %s", codeL, rule, codeI, body, exitCode, verdict), ok)
	if !ok {
		t.Errorf("%s %s %s %q exit %d ends %d verify %d\n%s\n%s", codeL, rule, codeI, body, exitCode, len(ends), vcode, out, x.output())
	}
}
