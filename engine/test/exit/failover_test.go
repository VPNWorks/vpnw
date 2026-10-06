// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package exittest

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"vpnw.com/vpnw/internal/events"
)

// loop is a workload that fetches a URL n times, a pause apart, and prints
// one line per fetch with the fetch's own time in milliseconds.
func loop(url string, n int, pause time.Duration) string {
	return fmt.Sprintf("import urllib.request, time\n"+
		"for i in range(1, %d):\n"+
		"    t0 = time.time()\n"+
		"    try:\n"+
		"        body = urllib.request.urlopen(%q, timeout=20).read().decode().strip()\n"+
		"        print('OK', i, body, int((time.time() - t0) * 1000), flush=True)\n"+
		"    except Exception as e:\n"+
		"        print('ERR', i, str(e).replace('\\n', ' '), flush=True)\n"+
		"    time.sleep(%f)\n", n+1, url, pause.Seconds())
}

type failover struct {
	conn               uint64
	from, to, reason   string
	gaveUp, open       int64 // ms
	errors, after, via int
}

// runFailover runs agent-1 through the two exits with a loop of fetches and
// calls breakDE after the third, then reads the switch from the trace.
func runFailover(t *testing.T, w *world, breakDE func()) (failover, []events.Event) {
	t.Helper()
	p := w.startAgent("agent-1", guard(agent1), loop("http://api.partner.test/", 10, 100*time.Millisecond))
	sc := bufio.NewScanner(p.stdout)
	var out []string
	for sc.Scan() {
		l := sc.Text()
		out = append(out, l)
		if strings.HasPrefix(l, "OK 3 ") {
			breakDE()
		}
	}
	p.cmd.Wait()
	if p.cmd.ProcessState.ExitCode() != 0 {
		t.Fatalf("vpnw exited %d:\n%s\n%s", p.cmd.ProcessState.ExitCode(), strings.Join(out, "\n"), p.out.String())
	}
	evs := readRecord(t, p.trace)
	var f failover
	opens := map[uint64]*events.Event{}
	for _, e := range evs {
		switch e.Type {
		case events.PathSwitch:
			if f.conn == 0 {
				f.conn, f.from, f.to, f.reason, f.gaveUp = e.Conn, e.Str("from"), e.Str("to"), e.Str("error"), e.Int("ms")
			}
		case events.ConnectionOpen:
			e := e
			opens[e.Conn] = &e
		}
	}
	if f.conn == 0 {
		t.Fatalf("no switch in the trace:\n%s\n%s", strings.Join(out, "\n"), p.out.String())
	}
	f.open = opens[f.conn].Int("ms")
	for c, e := range opens {
		if c > f.conn {
			f.after++
			if e.Str("exit") == fmt.Sprintf("%s:%d", nlListen, exitPort) {
				f.via++
			}
		}
	}
	for _, l := range out {
		if strings.HasPrefix(l, "ERR") {
			f.errors++
		}
	}
	var de, nl int
	for _, l := range lines(strings.Join(out, "\n"), "OK") {
		switch {
		case strings.Contains(l, "seen-from 198.51.100.10 "):
			de++
		case strings.Contains(l, "seen-from 203.0.113.10 "):
			nl++
		}
	}
	if f.from != fmt.Sprintf("%s:%d", deListen, exitPort) || f.to != fmt.Sprintf("%s:%d", nlListen, exitPort) || f.errors != 0 || de < 3 || de+nl != 10 || f.via != f.after {
		t.Fatalf("failover %+v; %d answers through exit-de, %d through exit-nl:\n%s", f, de, nl, strings.Join(out, "\n"))
	}
	return f, evs
}

// When exit-de is killed, the next connection moves to exit-nl, and so does
// every connection after it. The workload sees no error.
func TestFailoverKilled(t *testing.T) {
	w := build(t)
	de, _ := w.twoExits()
	f, _ := runFailover(t, w, de.kill)
	t.Logf("RESULT failover-killed: exit-de's process killed after the 3rd of 10 fetches; connection #%d gave up on exit-de after %d ms (%s) and was open through exit-nl %d ms after its dial started; the %d connections after it went straight to exit-nl; 0 fetches failed",
		f.conn, f.gaveUp, f.reason, f.open, f.after)
}

// When exit-de stops answering without a word (its packets dropped), the
// list waits up to its limit for TLS, then moves on.
func TestFailoverSilent(t *testing.T) {
	if _, err := exec.LookPath("nft"); err != nil {
		t.Skip("nft is not installed")
	}
	w := build(t)
	w.twoExits()
	rules := w.write("silent.nft", fmt.Sprintf("table ip silent {\n\tchain input {\n\t\ttype filter hook input priority 0; policy accept;\n\t\ttcp dport %d drop\n\t}\n}\n", exitPort))
	f, _ := runFailover(t, w, func() {
		if out, err := w.de.Run("nft", "-f", rules); err != nil {
			t.Errorf("nft: %v %s", err, out)
		}
	})
	if f.gaveUp < 2500 {
		t.Errorf("gave up after %d ms, before the list's limit", f.gaveUp)
	}
	t.Logf("RESULT failover-silent: exit-de's packets dropped after the 3rd of 10 fetches; connection #%d gave up on exit-de after %d ms (the list's 3 s limit; %s) and was open through exit-nl %d ms after its dial started; the %d connections after it went straight to exit-nl; 0 fetches failed",
		f.conn, f.gaveUp, f.reason, f.open, f.after)
}

// An exit that is down when the run starts is passed over by the health
// check, and the run starts on the next.
func TestHealthPicksFirstHealthy(t *testing.T) {
	w := build(t)
	de, _ := w.twoExits()
	de.stop()
	out, p, evs := w.runAgent("agent-1", guard(agent1), fetch("http://api.partner.test/"))
	if !strings.Contains(out, "OK http://api.partner.test/ seen-from 203.0.113.10 ") || p.code != 0 {
		t.Fatalf("%s\n%s", out, p.out.String())
	}
	desc := ""
	for _, e := range evs {
		if e.Type == events.RunStart {
			desc = e.Str("path")
		}
	}
	want := fmt.Sprintf("exits in order: https://%s:%d (no answer at start: proxy %s:%d is not reachable: connect: connection refused), https://%s:%d (in use); DNS at the exit",
		deListen, exitPort, deListen, exitPort, nlListen, exitPort)
	if desc != want {
		t.Errorf("run.start path:\n got %s\nwant %s", desc, want)
	}
	t.Logf("RESULT health: with exit-de down at the start, the health check passed it over and the run started on exit-nl; the trace's run.start says so")
}

// A client that skips its own policy and talks to the exit directly is
// refused all the same, and no server sees anything.
func TestTamperedClient(t *testing.T) {
	w := build(t)
	w.twoExits()
	since := time.Now()
	cases := []struct {
		tok, target, rule string
	}{
		{agent2.token, "169.254.169.254:80", "deny_private"},
		{agent2.token, "attacker.test:443", "default"},
		{agent2.token, "10.50.0.5:80", "deny_private"},
		{agent2.token, "api.partner.test:443", "default"},
		{agent2.token, "meta.partner.test:80", "default"},
		{agent1.token, "intranet.partner.test:80", "deny_private"},
		{agent1.token, "meta.partner.test:80", "deny_private"},
		{agent1.token, "evilpartner.test:80", "default"},
	}
	for _, c := range cases {
		a := w.tamper(c.tok, "exit-de", c.target, "")
		if a.status != 403 || a.rule != c.rule || a.reason == "" {
			t.Errorf("%s: %+v", c.target, a)
		}
	}
	socks := 0
	for _, target := range []struct {
		host string
		port int
	}{{"169.254.169.254", 80}, {"attacker.test", 443}, {"intranet.partner.test", 80}} {
		code, err := w.socksTamper(agent2.token, "r-tamper/1", "exit-de", target.host, target.port)
		if err != nil || code != 0x02 {
			t.Errorf("socks5 %s: %#x %v", target.host, code, err)
		}
		socks++
	}
	if hits := w.hitsSince(since); len(hits) != 0 {
		t.Errorf("servers saw %+v", hits)
	}
	// What it may do, it still can, from its own address.
	if a := w.tamper(agent2.token, "exit-de", "files.partner.test:80", ""); a.status != 200 || !strings.HasPrefix(a.body, "seen-from 198.51.100.11 ") {
		t.Errorf("allowed request: %+v", a)
	}
	t.Logf("RESULT tampered: %d forbidden requests sent straight to exit-de (%d over HTTP CONNECT, %d over SOCKS5) with valid tokens, skipping any policy at the client: %d refused by the exit, 0 reached a server; an allowed request still left from the client's own address",
		len(cases)+socks, len(cases), socks, len(cases)+socks)
}

// A wrong token, a certificate that fails the check, and a client asking for
// another client's address are all refused.
func TestRefusals(t *testing.T) {
	w := build(t)
	w.twoExits()
	var notes []string
	// A wrong token: the exit refuses it, and an Agent holding one does not
	// start.
	if a := w.tamper("not-a-token", "exit-de", "api.partner.test:80", ""); a.status != 407 {
		t.Errorf("wrong token: %+v", a)
	}
	if code, err := w.socksTamper("not-a-token", "vpnw", "exit-de", "api.partner.test", 80); code != 0xff || err != nil {
		t.Errorf("wrong token over SOCKS5: %#x %v", code, err)
	}
	intruder := client{name: "intruder", token: "not-a-token", policy: "default = \"deny\"\nallow = [\"api.partner.test\"]\n"}
	w.tokenFile(intruder)
	w.policyFile(intruder)
	out, p, _ := w.runAgent("intruder", guard(intruder), fetch("http://api.partner.test/"))
	if p.code != 123 || !strings.Contains(p.out.String(), "the exit refused the token") || strings.Contains(p.out.String(), "not-a-token") || out != "" {
		t.Errorf("Agent with a wrong token: exit %d\n%s", p.code, p.out.String())
	}
	notes = append(notes, "a wrong token: 407 over HTTP CONNECT, login refused over SOCKS5, and an Agent holding it did not start (exit 123)")
	// Certificates: expired, from another CA, for another name. Each exit
	// runs in exit-de's namespace on a port of its own.
	other := newCA(t, "someone else's CA")
	now := time.Now()
	certs := []struct {
		name, want string
		c          certPEM
	}{
		{"expired", "certificate has expired", w.ca.leaf(t, nil, []string{deListen}, now.Add(-48*time.Hour), now.Add(-time.Hour))},
		{"wrong-ca", "certificate signed by unknown authority", other.leaf(t, nil, []string{deListen}, now.Add(-time.Hour), now.Add(time.Hour))},
		{"wrong-name", "certificate is valid for 203.0.113.2, not 198.51.100.2", w.ca.leaf(t, nil, []string{nlListen}, now.Add(-time.Hour), now.Add(time.Hour))},
	}
	for i, c := range certs {
		port := 9443 + i
		w.writeCert(c.name, c.c)
		w.startExit("exit-de", w.exitConfig("exit-de", deListen, port, c.name, clients))
		cfg := w.write("cert-"+c.name+".toml", fmt.Sprintf("version = 1\n[paths.x]\ntype = \"proxy\"\nurl = \"https://%s:%d\"\nca_file = \"ca.pem\"\ntoken_file = \"agent-1.token\"\n[policy]\nallow = [\"api.partner.test\"]\n", deListen, port))
		_, p, _ := w.runAgent("cert", []string{"guard", "--backend", "sealed", "--policy", cfg, "--via", "x"}, fetch("http://api.partner.test/"))
		if p.code != 123 || !strings.Contains(p.out.String(), c.want) {
			t.Errorf("%s: exit %d\n%s", c.name, p.code, p.out.String())
		}
	}
	notes = append(notes, "an expired certificate, one from another CA and one for another name: the Agent did not start (exit 123) and named the reason")
	// Another client's address, over both front ends.
	since := time.Now()
	a := w.tamper(agent2.token, "exit-de", "api.partner.test:80", agent1.sources["exit-de"])
	if a.status != 403 || a.rule != "source" || a.reason != "198.51.100.10 is not one of the source addresses of client agent-2" {
		t.Errorf("another client's address: %+v", a)
	}
	if code, _ := w.socksTamper(agent2.token, "r-x/1/198.51.100.10", "exit-de", "api.partner.test", 80); code != 0x02 {
		t.Errorf("another client's address over SOCKS5: %#x", code)
	}
	for _, h := range w.hitsSince(since) {
		t.Errorf("a server saw %+v", h)
	}
	notes = append(notes, "agent-2 asking for agent-1's address: 403 (rule source) and SOCKS5 reply 2, nothing reached a server")
	// A configuration that gives two clients one address.
	cfg := w.exitConfig("exit-de", deListen, 9500, "exit-de", clients)
	b, _ := os.ReadFile(cfg)
	shared := w.write("shared.toml", strings.Replace(string(b), agent2.sources["exit-de"], agent1.sources["exit-de"], 1))
	cmd := exec.Command(exitBin, "check", "--config", shared)
	cmd.Env = exitEnv()
	msg, _ := cmd.CombinedOutput()
	if cmd.ProcessState.ExitCode() != 121 || !strings.Contains(string(msg), "shared.toml:") || !strings.Contains(string(msg), "source 198.51.100.10 is already client agent-1's") {
		t.Errorf("shared address: %d %s", cmd.ProcessState.ExitCode(), msg)
	}
	notes = append(notes, "a configuration giving two clients one address: refused with its file and line (exit 121)")
	t.Logf("RESULT refusals: %s", strings.Join(notes, "; "))
}

// Every connection's record at the Agent joins the record at the exit, on
// the run and connection IDs, through a refusal at the exit and a failover.
func TestRecordsJoin(t *testing.T) {
	w := build(t)
	de, nl := w.twoExits()
	// agent-2 asks for something only the Agent can refuse, something only
	// the exit can refuse, and fetches before and after exit-de dies.
	_, p2, _ := w.runAgent("agent-2", guard(agent2), fetch("http://files.partner.test/", "http://attacker.test/", "http://api.partner.test/"))
	_, p1a, _ := w.runAgent("agent-1", guard(agent1), fetch("http://api.partner.test/", "http://intranet.partner.test/", "http://www.partner.test/"))
	w.tamper(agent2.token, "exit-de", "169.254.169.254:80", "")
	de.kill()
	_, p1b, _ := w.runAgent("agent-1", guard(agent1), fetch("http://api.partner.test/", "http://deep.a.partner.test/"))
	nl.stop()
	args := []string{"join", "--agent", p2.trace, "--agent", p1a.trace, "--agent", p1b.trace, "--exit", de.record, "--exit", nl.record}
	cmd := exec.Command(exitBin, args...)
	cmd.Env = exitEnv()
	out, _ := cmd.CombinedOutput()
	if cmd.ProcessState.ExitCode() != 0 || !strings.Contains(string(out), "Joined: 7 of the 7 connections that reached an exit.") {
		t.Fatalf("join: exit %d\n%s", cmd.ProcessState.ExitCode(), out)
	}
	// The second agent-1 run started on exit-nl: exit-de was down.
	if !strings.Contains(string(out), "deep.a.partner.test:80  exit-nl  Agent: open; exit: open from 203.0.113.10") ||
		!strings.Contains(string(out), "intranet.partner.test:80  exit-de  Agent: failed: the exit refused it (deny_private)") {
		t.Errorf("join rows:\n%s", out)
	}
	first := strings.SplitN(string(out), "\n", 4)
	t.Logf("RESULT join: %s %s %s", first[0], first[1], first[2])
}
