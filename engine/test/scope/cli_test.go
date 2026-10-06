// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package scopetest

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"vpnw.com/vpnw/internal/scope"
	"vpnw.com/vpnw/internal/scope/office"
)

// binCover is where tools/measure-scope.sh wants the command's coverage.
var binCover = os.Getenv("VPNW_SCOPE_BINCOVER")

// buildScope builds the vpnw-scope command for the tests, with coverage on
// when tools/measure-scope.sh asks for it.
func buildScope(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "vpnw-scope")
	args := []string{"build", "-o", bin}
	if binCover != "" {
		args = append(args, "-cover", "-coverpkg=vpnw.com/vpnw/...")
	}
	cmd := exec.Command("go", append(args, "vpnw.com/vpnw/cmd/vpnw-scope")...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	return bin
}

// TestRecordCommand runs "vpnw-scope record" on the gateway while clients
// connect, and checks what it wrote and that it removed its table.
func TestRecordCommand(t *testing.T) {
	o := office.Demo()
	w := build(t, o)
	bin := buildScope(t)
	dir := t.TempDir()
	people := filepath.Join(dir, "people.toml")
	out := filepath.Join(dir, "recorded.jsonl")
	os.WriteFile(people, []byte(o.PeopleFile()), 0o644)
	cmd := exec.Command(bin, "record", "--people", people, "--out", out, "--group", "9", "--duration", "4s")
	if binCover != "" {
		cmd.Env = append(os.Environ(), "GOCOVERDIR="+binCover)
	}
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for exec.Command("nft", "list", "table", "inet", "vpnw_scope_record").Run() != nil {
		if time.Now().After(deadline) {
			cmd.Process.Kill()
			t.Fatalf("the recording table never appeared: %s", stderr.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	attempts := o.StolenLogin("alice", office.DemoStolenAt)[:60]
	for _, f := range attempts {
		if _, err := w.probe(f); err != nil {
			t.Fatal(err)
		}
	}
	if err := cmd.Wait(); err != nil {
		t.Fatalf("record: %v: %s", err, stderr.String())
	}
	if !strings.Contains(stderr.String(), "recorded 60 new connections from 10.8.0.0/24") {
		t.Fatalf("summary: %s", stderr.String())
	}
	if exec.Command("nft", "list", "table", "inet", "vpnw_scope_record").Run() == nil {
		t.Fatal("record left its nftables table behind")
	}
	f, err := os.Open(out)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	got := map[tuple]int{}
	if _, err := scope.ReadFlows(f, out, func(fl scope.Flow) error { got[tupleOf(fl)]++; return nil }); err != nil {
		t.Fatal(err)
	}
	for _, a := range attempts {
		if got[tupleOf(a)] != 1 {
			t.Fatalf("%v recorded %d times", tupleOf(a), got[tupleOf(a)])
		}
	}
	t.Logf("RESULT record-command: 60 connections, 60 lines written, table removed on exit")
}
