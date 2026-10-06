// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"vpnw.com/vpnw/internal/scope"
	"vpnw.com/vpnw/internal/scope/office"
)

type files struct{ dir, people, learn, replay, draft string }

func setup(t *testing.T) files {
	t.Helper()
	dir := t.TempDir()
	o := office.Demo()
	f := files{dir: dir, people: filepath.Join(dir, "people.toml"), learn: filepath.Join(dir, "learn.jsonl"),
		replay: filepath.Join(dir, "replay.jsonl"), draft: filepath.Join(dir, "draft.toml")}
	if err := os.WriteFile(f.people, []byte(o.PeopleFile()), 0o644); err != nil {
		t.Fatal(err)
	}
	write := func(name string, from, to int) {
		var b bytes.Buffer
		fw := scope.NewFlowWriter(&b)
		o.Flows(from, to, office.DemoSeed, func(fl scope.Flow) { fw.Write(fl) })
		fw.Flush()
		if err := os.WriteFile(name, b.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(f.learn, office.DemoLearnFrom, office.DemoLearnTo)
	write(f.replay, office.DemoReplayFrom, office.DemoReplayTo)
	return f
}

func call(stdin string, args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := run(args, strings.NewReader(stdin), &out, &errb)
	return code, out.String(), errb.String()
}

func TestLearnReplayExport(t *testing.T) {
	f := setup(t)
	code, _, stderr := call("", "learn", "--people", f.people, "--flows", f.learn, "-o", f.draft)
	if code != 0 || !strings.Contains(stderr, "learned from 20,232 of 20,232 flows") || !strings.Contains(stderr, "39 group rules for 5 groups, 11 personal rules for 11 people, 3 under review") {
		t.Fatalf("learn: %d %s", code, stderr)
	}
	code, out, _ := call("", "replay", "--people", f.people, "--draft", f.draft, "--flows", f.replay)
	if code != 0 || !strings.Contains(out, "Replayed 10,387 flows: 10,375 allowed, 12 would be blocked.") ||
		!strings.Contains(out, "farid      10.0.2.30:5432/tcp          9") {
		t.Fatalf("replay: %d\n%s", code, out)
	}
	if code, _, _ := call("", "replay", "--fail-on-deny", "--people", f.people, "--draft", f.draft, "--flows", f.replay); code != exitDenied {
		t.Fatalf("--fail-on-deny gave %d", code)
	}
	// Replaying the learning weeks blocks only what went under review.
	code, out, _ = call("", "replay", "--people", f.people, "--draft", f.draft, "--flows", f.learn, "--top", "1")
	if code != 0 || !strings.Contains(out, "20,226 allowed, 6 would be blocked") || !strings.Contains(out, "... and 2 more") {
		t.Fatalf("replay of the learning weeks:\n%s", out)
	}
	// Stdin, a window, and JSON lines.
	replay, _ := os.ReadFile(f.replay)
	code, out, _ = call(string(replay), "replay", "--json", "--from", "2026-09-21", "--to", "2026-09-21", "--people", f.people, "--draft", f.draft, "--flows", "-")
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if code != 0 || len(lines) < 100 || !strings.Contains(lines[0], `"verdict":"allowed"`) {
		t.Fatalf("json replay: %d, %d lines, %s", code, len(lines), lines[0])
	}
	for _, l := range lines {
		if !strings.Contains(l, `"t":"2026-09-21T`) {
			t.Fatalf("a flow outside the window: %s", l)
		}
	}
	code, out, _ = call("", "export", "--people", f.people, "--draft", f.draft)
	if code != 0 || !strings.Contains(out, "# Made from draft.toml and people.toml.") || !strings.Contains(out, "reject with icmpx type admin-prohibited") {
		t.Fatalf("export: %d\n%s", code, out)
	}
	nft := filepath.Join(f.dir, "rules.nft")
	if code, _, _ := call("", "export", "--watch", "--log-group", "5", "--people", f.people, "--draft", f.draft, "-o", nft); code != 0 {
		t.Fatal("export -o")
	}
	if b, _ := os.ReadFile(nft); !strings.Contains(string(b), "would be refused") {
		t.Fatal("watch export not written")
	}
	code, out, _ = call("", "export", "--format", "allowedips", "--people", f.people, "--draft", f.draft)
	if code != 0 || !strings.Contains(out, "# alice (Alice Martin)\nAllowedIPs = 10.0.0.53/32, 10.0.1.10/32, 10.0.1.11/32, 10.0.1.12/32, 10.0.1.20/32, 10.0.1.21/32\n") {
		t.Fatalf("allowedips: %d\n%s", code, out)
	}
	code, out, _ = call("", "check", "--people", f.people, "--draft", f.draft)
	if code != 0 || !strings.Contains(out, "30 people, 30 addresses, 5 groups, VPN range 10.8.0.0/24.") || !strings.Contains(out, "3 under review") {
		t.Fatalf("check: %d\n%s", code, out)
	}
}

func TestConntrackInput(t *testing.T) {
	f := setup(t)
	ct := filepath.Join(f.dir, "ct.log")
	os.WriteFile(ct, []byte("[1757235600.25] [NEW] tcp 6 120 SYN_SENT src=10.8.0.11 dst=10.0.1.20 sport=1 dport=443\n"+
		"[1757235600.30] [NEW] tcp 6 120 SYN_SENT src=10.8.0.11 dst=10.0.1.20 sport=2 dport=443\n"), 0o644)
	code, out, stderr := call("", "learn", "--min-days", "1", "--people", f.people, "--conntrack", ct)
	if code != 0 || !strings.Contains(stderr, "learned from 2 of 2 flows") || !strings.Contains(out, "[people.alice]\nallow = [\n  \"10.0.1.20:443/tcp\",") {
		t.Fatalf("%d %s\n%s", code, stderr, out)
	}
}

func TestWireGuardDump(t *testing.T) {
	dir := t.TempDir()
	people := filepath.Join(dir, "p.toml")
	dump := filepath.Join(dir, "dump")
	os.WriteFile(people, []byte("version = 1\nvpn_net = \"10.8.0.0/24\"\n[people.a]\nwireguard_keys = [\"xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\"]\n"), 0o644)
	os.WriteFile(dump, []byte("wg0\txTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\t(none)\t(none)\t10.8.0.20/32\t0\t0\t0\toff\n"), 0o644)
	if code, _, stderr := call("", "check", "--people", people); code != exitConfig || !strings.Contains(stderr, "no address yet for a") {
		t.Fatalf("without the dump: %d %s", code, stderr)
	}
	if code, out, _ := call("", "check", "--people", people, "--wg-dump", dump); code != 0 || !strings.Contains(out, "1 people, 1 addresses") {
		t.Fatalf("with the dump: %d %s", code, out)
	}
	if code, _, _ := call("", "check", "--people", people, "--wg-dump", filepath.Join(dir, "missing")); code != exitConfig {
		t.Fatal("missing dump")
	}
}

func TestErrors(t *testing.T) {
	f := setup(t)
	bad := filepath.Join(f.dir, "bad.toml")
	os.WriteFile(bad, []byte("version = 1\n[people.nobody]\nallow = []\n"), 0o644)
	overlap := filepath.Join(f.dir, "overlap.toml")
	os.WriteFile(overlap, []byte("version = 1\n[people.alice]\nallow = [\"10.0.1.0/24:400-500/tcp\", \"10.0.1.0/25:450-600/tcp\"]\n"), 0o644)
	learn := []string{"--people", f.people, "--flows", f.learn}
	cases := []struct {
		args []string
		code int
		want string
	}{
		{nil, exitConfig, "Usage:"},
		{[]string{"frobnicate"}, exitConfig, "unknown command"},
		{[]string{"learn"}, exitConfig, "--people FILE is required"},
		{[]string{"learn", "--people", f.people}, exitConfig, "at least one --flows"},
		{append([]string{"learn", "--min-days", "0"}, learn...), exitConfig, "--min-days"},
		{append([]string{"learn", "--group-share", "1.5"}, learn...), exitConfig, "--group-share"},
		{append([]string{"learn", "--from", "Sept"}, learn...), exitConfig, "--from"},
		{append([]string{"learn", "--to", "2026-13-01"}, learn...), exitConfig, "--to"},
		{append([]string{"learn", "--from", "2026-09-20", "--to", "2026-09-07"}, learn...), exitConfig, "before --from"},
		{append([]string{"learn", "extra"}, learn...), exitConfig, "unexpected argument"},
		{append([]string{"learn", "--nope"}, learn...), exitConfig, "flag provided but not defined"},
		{[]string{"learn", "--people", filepath.Join(f.dir, "none.toml"), "--flows", f.learn}, exitConfig, "no such file"},
		{[]string{"learn", "--people", f.people, "--flows", filepath.Join(f.dir, "none.jsonl")}, exitConfig, "no such file"},
		{[]string{"learn", "--people", f.people, "--conntrack", filepath.Join(f.dir, "none.log")}, exitConfig, "no such file"},
		{[]string{"learn", "--people", f.people, "--flows", f.people}, exitConfig, "people.toml:2: not a JSON object"},
		{[]string{"replay", "--people", f.people, "--flows", f.replay}, exitConfig, "--draft FILE is required"},
		{[]string{"replay", "--people", f.people, "--draft", bad, "--flows", f.replay}, exitConfig, "not in the people file"},
		{[]string{"replay", "--people", f.people, "--draft", bad + "x", "--flows", f.replay}, exitConfig, "no such file"},
		{[]string{"export", "--people", f.people, "--draft", bad}, exitConfig, "not in the people file"},
		{[]string{"export", "--people", f.people, "--draft", overlap}, exitConfig, "overlap"},
		{[]string{"export", "--format", "yaml", "--people", f.people, "--draft", overlap}, exitConfig, "want nft or allowedips"},
		{[]string{"export", "--watch", "--drop", "--people", f.people, "--draft", overlap}, exitConfig, "--drop does not apply"},
		{[]string{"check", "--people", f.people, "--draft", overlap}, exitConfig, "overlap"},
		{[]string{"check", "--people", f.people, "--draft", bad}, exitConfig, "not in the people file"},
		{[]string{"check", "--bogus"}, exitConfig, "check:"},
		{[]string{"replay", "--bogus"}, exitConfig, "replay:"},
		{[]string{"export", "--bogus"}, exitConfig, "export:"},
		{[]string{"record", "--group", "0", "--people", f.people}, exitConfig, "--group"},
		{[]string{"record", "--bogus"}, exitConfig, "record:"},
		{[]string{"record"}, exitConfig, "--people FILE is required"},
	}
	for _, c := range cases {
		code, out, stderr := call("", c.args...)
		if code != c.code || !strings.Contains(out+stderr, c.want) {
			t.Errorf("%v: exit %d, output %q; want %d and %q", c.args, code, out+stderr, c.code, c.want)
		}
	}
	if code, out, _ := call("", "version"); code != 0 || !strings.HasPrefix(out, "vpnw-scope 0.1.0 (") {
		t.Errorf("version: %s", out)
	}
	if code, out, _ := call("", "help"); code != 0 || !strings.Contains(out, "vpnw-scope record") {
		t.Errorf("help: %s", out)
	}
	if code, _, _ := call("", append([]string{"learn", "-o", f.draft}, learn...)...); code != 0 {
		t.Fatal("learn")
	}
	if code, _, stderr := call("", "export", "--people", f.people, "--draft", f.draft, "-o", filepath.Join(f.dir, "no", "rules.nft")); code != exitFailure || !strings.Contains(stderr, "no such file") {
		t.Errorf("export into a missing directory: %d %s", code, stderr)
	}
	draftOut := filepath.Join(f.dir, "sub", "draft.toml")
	if code, _, stderr := call("", append([]string{"learn", "-o", draftOut}, learn...)...); code != exitFailure || !strings.Contains(stderr, "no such file") {
		t.Errorf("learn into a missing directory: %d %s", code, stderr)
	}
}
