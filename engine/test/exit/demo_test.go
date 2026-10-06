// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package exittest

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vpnw.com/vpnw/internal/events"
)

// driven is an agent whose workload fetches the URLs the test sends it,
// one at a time.
type driven struct {
	name  string
	p     *agentProc
	in    io.WriteCloser
	lines chan string
}

const fetchStdin = "import sys, time, urllib.request, urllib.error\n" +
	"for line in sys.stdin:\n" +
	"    u = line.strip()\n" +
	"    if not u: continue\n" +
	"    t0 = time.time()\n" +
	"    try:\n" +
	"        body = urllib.request.urlopen(u, timeout=20).read().decode().strip()\n" +
	"        print('OK', u, body, flush=True)\n" +
	"    except urllib.error.HTTPError as e:\n" +
	"        print('HTTP', u, e.code, e.read().decode().strip(), flush=True)\n" +
	"    except Exception as e:\n" +
	"        print('ERR', u, str(e).replace('\\n', ' '), flush=True)\n"

func (w *world) drive(c client) *driven {
	w.t.Helper()
	p := &agentProc{out: &syncBuf{}, trace: filepath.Join(w.dir, c.name+"-demo.jsonl"), done: make(chan struct{})}
	args := append(guard(c), "--no-save", "--out", p.trace, "--", "python3", "-u", "-c", fetchStdin)
	p.cmd = exec.Command(vpnwBin, args...)
	p.cmd.Dir = w.dir
	p.cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + w.dir, "NO_COLOR=1"}
	p.cmd.Stderr = p.out
	d := &driven{name: c.name, p: p, lines: make(chan string, 16)}
	var err error
	if d.in, err = p.cmd.StdinPipe(); err != nil {
		w.t.Fatal(err)
	}
	if p.stdout, err = p.cmd.StdoutPipe(); err != nil {
		w.t.Fatal(err)
	}
	if err := w.agents.Start(p.cmd); err != nil {
		w.t.Fatal(err)
	}
	go func() {
		sc := bufio.NewScanner(p.stdout)
		for sc.Scan() {
			d.lines <- sc.Text()
		}
		close(d.lines)
	}()
	return d
}

// step is one thing that happened in the demo, as the test saw it.
type step struct {
	At     time.Time `json:"t"`
	Actor  string    `json:"actor"`
	What   string    `json:"what"`
	Target string    `json:"target,omitempty"`
	Result string    `json:"result"`
}

type demo struct {
	t     *testing.T
	w     *world
	steps []step
}

func (d *demo) get(a *driven, url string) string {
	d.t.Helper()
	at := time.Now()
	fmt.Fprintln(a.in, url)
	select {
	case l, ok := <-a.lines:
		if !ok {
			d.t.Fatalf("%s's workload ended:\n%s", a.name, a.p.out.String())
		}
		d.steps = append(d.steps, step{At: at.UTC(), Actor: a.name, What: "fetch", Target: url, Result: l})
		time.Sleep(350 * time.Millisecond)
		return l
	case <-time.After(60 * time.Second):
		d.t.Fatalf("%s: no answer for %s:\n%s", a.name, url, a.p.out.String())
	}
	return ""
}

func (a *driven) end() {
	a.in.Close()
	for range a.lines {
	}
	a.p.cmd.Wait()
}

// TestDemoScenario is the run the browser demo replays: two agents with exits
// in two countries, a tampered client asking for forbidden destinations, and
// exit-de killed partway. With VPNW_EXIT_RECORD=DIR it also writes the
// records and what the test saw to DIR.
func TestDemoScenario(t *testing.T) {
	w := build(t)
	de, nl := w.twoExits()
	d := &demo{t: t, w: w}
	start := time.Now()
	a1, a2 := w.drive(agent1), w.drive(agent2)
	expect := func(got, want string) {
		t.Helper()
		if !strings.HasPrefix(got, want) {
			t.Errorf("got  %s\nwant %s...", got, want)
		}
	}
	// Both exits up: each agent leaves from its own address in Germany.
	expect(d.get(a1, "http://api.partner.test/"), "OK http://api.partner.test/ seen-from 198.51.100.10 ")
	expect(d.get(a2, "http://files.partner.test/"), "OK http://files.partner.test/ seen-from 198.51.100.11 ")
	expect(d.get(a1, "http://www.partner.test:8080/"), "OK http://www.partner.test:8080/ seen-from 198.51.100.10 ")
	// The Agent refuses what agent-1's policy does not allow; it never
	// reaches an exit.
	expect(d.get(a1, "http://attacker.test/"), "HTTP http://attacker.test/ 403 vpnw: blocked attacker.test:80 (default")
	// The Agent allows intranet.partner.test by name and cannot see where it
	// points; the exit resolves it and refuses the private address.
	expect(d.get(a1, "http://intranet.partner.test/"), "HTTP http://intranet.partner.test/ 502 vpnw: cannot reach intranet.partner.test:80: the exit refused it (deny_private)")
	expect(d.get(a2, "http://api.partner.test/"), "OK http://api.partner.test/ seen-from 198.51.100.11 ")
	// A tampered client with a copy of agent-2's token skips any policy of
	// its own and asks exit-de directly.
	tampered := []struct {
		proto, target, rule string
	}{
		{"http-connect", "169.254.169.254:80", "deny_private"},
		{"http-connect", "attacker.test:443", "default"},
		{"socks5", "intranet.partner.test:80", ""},
	}
	refusedAtExit := 0
	since := time.Now()
	for _, x := range tampered {
		at := time.Now()
		var res string
		if x.proto == "socks5" {
			code, err := w.socksTamper(agent2.token, "r-tampered/1", "exit-de", "intranet.partner.test", 80)
			res = fmt.Sprintf("SOCKS5 reply %d", code)
			if err != nil || code != 0x02 {
				t.Errorf("tampered socks5: %#x %v", code, err)
			} else {
				refusedAtExit++
			}
		} else {
			a := w.tamper(agent2.token, "exit-de", x.target, "")
			res = fmt.Sprintf("%d %s: %s", a.status, a.rule, a.reason)
			if a.status != 403 || a.rule != x.rule {
				t.Errorf("tampered %s: %+v", x.target, a)
			} else {
				refusedAtExit++
			}
		}
		d.steps = append(d.steps, step{At: at.UTC(), Actor: "tampered", What: x.proto, Target: x.target, Result: res})
		time.Sleep(350 * time.Millisecond)
	}
	if h := w.hitsSince(since); len(h) != 0 {
		t.Errorf("the tampered client reached %+v", h)
	}
	// exit-de dies. The next connections move to exit-nl, and the partner
	// sees each agent's address in the Netherlands.
	killed := time.Now()
	de.kill()
	d.steps = append(d.steps, step{At: killed.UTC(), Actor: "exit-de", What: "killed", Result: "SIGKILL"})
	time.Sleep(350 * time.Millisecond)
	expect(d.get(a1, "http://api.partner.test/"), "OK http://api.partner.test/ seen-from 203.0.113.10 ")
	expect(d.get(a2, "http://files.partner.test/"), "OK http://files.partner.test/ seen-from 203.0.113.11 ")
	expect(d.get(a1, "http://www.partner.test:8080/"), "OK http://www.partner.test:8080/ seen-from 203.0.113.10 ")
	expect(d.get(a2, "http://api.partner.test/"), "OK http://api.partner.test/ seen-from 203.0.113.11 ")
	a1.end()
	a2.end()
	nl.stop()
	end := time.Now()

	// The records join up.
	cmd := exec.Command(exitBin, "join", "--json", "--agent", a1.p.trace, "--agent", a2.p.trace, "--exit", de.record, "--exit", nl.record)
	cmd.Env = exitEnv()
	out, _ := cmd.Output()
	var j struct {
		ViaExit, Joined, Other int
		Problems               []string
	}
	json.Unmarshal(out, &struct {
		ViaExit  *int      `json:"via_exit"`
		Joined   *int      `json:"joined"`
		Other    *int      `json:"other_runs"`
		Problems *[]string `json:"problems"`
	}{&j.ViaExit, &j.Joined, &j.Other, &j.Problems})
	if cmd.ProcessState.ExitCode() != 0 || j.Joined != j.ViaExit || j.ViaExit != 9 {
		t.Errorf("join: exit %d, %+v\n%s", cmd.ProcessState.ExitCode(), j, out)
	}
	switches := map[string]int64{}
	for _, a := range []*driven{a1, a2} {
		for _, e := range readRecord(t, a.p.trace) {
			if e.Type == events.PathSwitch {
				switches[a.name] = e.Int("ms")
			}
		}
	}
	if len(switches) != 2 {
		t.Errorf("switches %v", switches)
	}
	t.Logf("RESULT demo: two agents, two exits, %d fetches and %d requests from a tampered client in %.1f s; exit-de killed partway; both agents moved to exit-nl (gave up on exit-de after %d ms and %d ms); the tampered client's %d requests refused at the exit; %d of %d connections that reached an exit joined the exits' records",
		len(d.steps)-len(tampered)-1, len(tampered), end.Sub(start).Seconds(), switches["agent-1"], switches["agent-2"], refusedAtExit, j.Joined, j.ViaExit)

	dir := os.Getenv("VPNW_EXIT_RECORD")
	if dir == "" {
		return
	}
	must(t, os.MkdirAll(dir, 0o755))
	copyFile := func(from, to string) {
		b, err := os.ReadFile(from)
		must(t, err)
		must(t, os.WriteFile(filepath.Join(dir, to), b, 0o644))
	}
	copyFile(a1.p.trace, "agent-1.jsonl")
	copyFile(a2.p.trace, "agent-2.jsonl")
	copyFile(de.record, "exit-de.jsonl")
	copyFile(nl.record, "exit-nl.jsonl")
	copyFile(filepath.Join(w.dir, "agent-1.toml"), "agent-1.toml")
	copyFile(filepath.Join(w.dir, "agent-2.toml"), "agent-2.toml")
	copyFile(filepath.Join(w.dir, "ci.toml"), "ci.toml")
	copyFile(filepath.Join(w.dir, fmt.Sprintf("exit-de-%d.toml", exitPort)), "exit-de.toml")
	copyFile(filepath.Join(w.dir, fmt.Sprintf("exit-nl-%d.toml", exitPort)), "exit-nl.toml")
	must(t, os.WriteFile(filepath.Join(dir, "join.json"), out, 0o644))
	var buf strings.Builder
	enc := json.NewEncoder(&buf)
	for _, s := range d.steps {
		enc.Encode(s)
	}
	must(t, os.WriteFile(filepath.Join(dir, "steps.jsonl"), []byte(buf.String()), 0o644))
	buf.Reset()
	for _, h := range w.hitsSince(start) {
		enc.Encode(h)
	}
	must(t, os.WriteFile(filepath.Join(dir, "servers.jsonl"), []byte(buf.String()), 0o644))
	w.dns.mu.Lock()
	table := map[string][]string{}
	for n, ips := range w.dns.names {
		for _, ip := range ips {
			table[n] = append(table[n], ip.String())
		}
	}
	w.dns.mu.Unlock()
	b, _ := json.MarshalIndent(table, "", " ")
	must(t, os.WriteFile(filepath.Join(dir, "dns.json"), append(b, '\n'), 0o644))
	b, _ = json.MarshalIndent(map[string]any{"start": start.UTC(), "killed": killed.UTC(), "end": end.UTC(),
		"tokens": "test tokens, made for this run; the exits keep only their SHA-256"}, "", " ")
	must(t, os.WriteFile(filepath.Join(dir, "marks.json"), append(b, '\n'), 0o644))
}
