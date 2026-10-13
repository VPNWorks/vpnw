// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"
)

// A run sealed by the Ledger plugin checks out, with its trace and on its
// own; an edit to it is caught at its line; and the plugin's file is new,
// never one that exists.
func TestLedgerRun(t *testing.T) {
	skipIfNoSeal(t)
	e := newEnv(t)
	srv := newServer(t)
	url := fmt.Sprintf("http://localhost:%d/", srv.port)
	led := filepath.Join(e.dir, "run.ledger")
	tr := filepath.Join(e.dir, "run.jsonl")
	out := e.must("trace", "--plugin", "ledger", "--plugin-file", "ledger="+led, "--set", "ledger.every=5", "--out", tr,
		"--", "python3", "-c", pyGet(url, url, url))
	m := regexp.MustCompile(`ledger: last hash ([0-9a-f]{64})`).FindStringSubmatch(out)
	if m == nil || !strings.Contains(out, "entries sealed in "+led) {
		t.Fatalf("no ledger summary:\n%s", out)
	}
	head := m[1]

	got := e.must("verify", led, tr, "--head", head)
	if !strings.HasPrefix(got, "intact: ") || !regexp.MustCompile(`checkpoint copies in \S+run.jsonl that match the ledger: ([1-9]\d*) of ([1-9]\d*)`).MatchString(got) || !allMatch(got) ||
		!strings.Contains(got, "the last hash is the one you kept") {
		t.Fatalf("verify:\n%s", got)
	}
	// The same through vpnw advise, the way any Advisor runs.
	if got := e.must("advise", "ledger-verify", "--from", led, "--from", tr); !strings.HasPrefix(got, "intact: ") {
		t.Fatalf("advise ledger-verify:\n%s", got)
	}

	// One byte changed in the third line.
	b, _ := os.ReadFile(led)
	lines := strings.SplitAfter(string(b), "\n")
	lines[2] = strings.Replace(lines[2], `"pid":`, `"pid":1`, 1)
	bad := filepath.Join(e.dir, "bad.ledger")
	os.WriteFile(bad, []byte(strings.Join(lines, "")), 0o600)
	got, code := e.run("verify", bad, tr)
	if code != 1 || !strings.Contains(got, "CHANGED: "+bad+":3: the event doesn't match its hash") {
		t.Fatalf("changed ledger: exit %d\n%s", code, got)
	}
	// A wrong head.
	if got, code := e.run("verify", led, "--head", strings.Repeat("0", 64)); code != 1 || !strings.Contains(got, "not the one you kept") {
		t.Fatalf("wrong head: exit %d\n%s", code, got)
	}
	// Not a ledger.
	if got, code := e.run("verify", tr); code == 0 || !strings.Contains(got, "is not a VPN Works ledger") {
		t.Fatalf("a trace given as the ledger: exit %d\n%s", code, got)
	}

	// The file must be new.
	if got, code := e.run("trace", "--plugin", "ledger", "--plugin-file", "ledger="+led, "--", "true"); code != 121 || !strings.Contains(got, "exists already") {
		t.Fatalf("existing file: exit %d\n%s", code, got)
	}
	if got, code := e.run("run", "--plugin-file", "ledger=x", "--", "true"); code != 121 || !strings.Contains(got, "not used in this run") {
		t.Fatalf("--plugin-file without the plugin: exit %d\n%s", code, got)
	}

	// Without --plugin-file the ledger goes under the state folder, and
	// verify finds the checkpoint copies in the saved trace by itself.
	out = e.must("trace", "--plugin", "ledger", "--", "python3", "-c", pyGet(url))
	m = regexp.MustCompile(`entries sealed in (\S+\.ledger)`).FindStringSubmatch(out)
	if m == nil || !strings.HasPrefix(m[1], filepath.Join(e.dir, "state", "vpnw", "ledger")+"/r-") {
		t.Fatalf("default ledger path:\n%s", out)
	}
	if fi, err := os.Stat(m[1]); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("ledger file: %v %v", fi, err)
	}
	if got := e.must("verify", m[1]); !strings.Contains(got, "checkpoint copies in last that match the ledger: 1 of 1") {
		t.Fatalf("verify with the saved trace:\n%s", got)
	}
}

// A run killed in the middle leaves a ledger that checks out up to where it
// stops, and verify says it was cut short. A run stopped with SIGTERM ends
// its ledger properly.
func TestLedgerKilledRun(t *testing.T) {
	skipIfNoSeal(t)
	srv := newServer(t)
	loop := fmt.Sprintf("import urllib.request as u, time\nwhile True:\n    try:\n        u.urlopen('http://localhost:%d/', timeout=3).read()\n    except Exception:\n        pass\n    time.sleep(0.02)\n", srv.port)
	for _, sig := range []syscall.Signal{syscall.SIGKILL, syscall.SIGTERM} {
		t.Run(sig.String(), func(t *testing.T) {
			e := newEnv(t)
			led := filepath.Join(e.dir, "run.ledger")
			cmd := exec.Command(vpnw, "run", "--plugin", "ledger", "--plugin-file", "ledger="+led, "--set", "ledger.every=10", "--", "python3", "-c", loop)
			cmd.Env = e.vars
			var out bytes.Buffer
			cmd.Stdout, cmd.Stderr = &out, &out
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			deadline := time.Now().Add(20 * time.Second)
			for {
				b, _ := os.ReadFile(led)
				if bytes.Count(b, []byte("\n")) > 40 {
					break
				}
				if time.Now().After(deadline) {
					cmd.Process.Kill()
					t.Fatalf("the ledger never grew:\n%s", out.String())
				}
				time.Sleep(50 * time.Millisecond)
			}
			cmd.Process.Signal(sig)
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			select {
			case <-done:
			case <-time.After(20 * time.Second):
				cmd.Process.Kill()
				t.Fatal("vpnw did not stop")
			}
			got, code := e.run("verify", led)
			if sig == syscall.SIGTERM {
				if code != 0 || !strings.HasPrefix(got, "intact: ") {
					t.Fatalf("after SIGTERM: exit %d\n%s\nvpnw:\n%s", code, got, out.String())
				}
				return
			}
			if code != 1 || !strings.HasPrefix(got, "cut short: ") || !regexp.MustCompile(`entries 1 to \d+ check out`).MatchString(got) {
				t.Fatalf("after SIGKILL: exit %d\n%s", code, got)
			}
		})
	}
}

// allMatch says the report's "N of M" copies line has N == M.
func allMatch(report string) bool {
	m := regexp.MustCompile(`match the ledger: (\d+) of (\d+)`).FindStringSubmatch(report)
	return m != nil && m[1] == m[2]
}
