// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"vpnw.com/vpnw/internal/ledger"
	"vpnw.com/vpnw/internal/ledger/tamper"
)

// demoTrace is the Agent's recorded run the demo seals.
const demoTrace = "../../../recordings/1-trace-1.jsonl"

func mustRead(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func call(args ...string) (int, string, string) {
	var out, errb bytes.Buffer
	code := run(args, strings.NewReader(""), &out, &errb)
	return code, out.String(), errb.String()
}

// setup works in a fresh folder holding trace.jsonl, a copy of the demo
// trace, and a key pair named agent.
func setup(t *testing.T) []byte {
	t.Helper()
	trace, err := os.ReadFile(demoTrace)
	if err != nil {
		t.Fatal(err)
	}
	t.Chdir(t.TempDir())
	if err := os.WriteFile("trace.jsonl", trace, 0o644); err != nil {
		t.Fatal(err)
	}
	if code, out, errs := call("keygen", "-o", "agent"); code != 0 || !strings.Contains(out, "agent.key  the private key") {
		t.Fatalf("keygen: %d %s %s", code, out, errs)
	}
	return trace
}

func TestSealVerifyProve(t *testing.T) {
	trace := setup(t)
	if fi, err := os.Stat("agent.key"); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("agent.key: %v %v", fi.Mode(), err)
	}
	if code, _, errs := call("keygen", "-o", "agent"); code != exitInput || !strings.Contains(errs, "agent.key exists; vpnw-ledger never writes over a key") {
		t.Fatalf("keygen again: %d %s", code, errs)
	}
	code, out, errs := call("seal", "--key", "agent.key", "--every", "8", "trace.jsonl")
	if code != 0 || strings.Count(out, `{"cp":`) != 4 || !strings.Contains(errs, "sealed 28 new records of trace.jsonl in") ||
		!strings.Contains(errs, "trace.jsonl.ledger holds 28 records under 4 checkpoints signed by k-") {
		t.Fatalf("seal: %d\n%s\n%s", code, out, errs)
	}
	os.WriteFile("witness.log", []byte(out), 0o644)
	code, out, _ = call("verify", "--pub", "agent.pub", "--witness", "witness.log", "trace.jsonl")
	if code != 0 || !strings.Contains(out, "trace.jsonl is intact: 28 records, all sealed and signed. 4 checkpoints signed by k-") ||
		!strings.Contains(out, "The 4 checkpoints in witness.log are all in the ledger.") {
		t.Fatalf("verify: %d %s", code, out)
	}
	os.WriteFile("last.log", []byte(strings.Split(strings.TrimSpace(string(mustRead(t, "witness.log"))), "\n")[3]+"\n"), 0o644)
	if code, out, _ := call("verify", "--pub", "agent.pub", "--witness", "last.log", "trace.jsonl"); code != 0 || !strings.Contains(out, "The checkpoint in last.log is in the ledger.") {
		t.Fatalf("verify with one checkpoint: %d %s", code, out)
	}
	code, _, errs = call("prove", "--line", "25", "-o", "p.json", "trace.jsonl")
	if code != 0 || !strings.Contains(errs, "a proof that line 25 of trace.jsonl is in the log: 4 hashes to the root of checkpoint 4, which covers 28 records;") {
		t.Fatalf("prove: %d %s", code, errs)
	}
	code, out, _ = call("check-proof", "--pub", "agent.pub", "p.json")
	if code != 0 || !strings.Contains(out, "The proof holds. Line 25 of log trace.jsonl, under checkpoint 4 (28 records, signed ") ||
		!strings.Contains(out, `"host":"evil.example","ip":"45.77.10.10"`) {
		t.Fatalf("check-proof: %d %s", code, out)
	}
	line25 := strings.Split(string(trace), "\n")[24]
	os.WriteFile("rec.json", []byte(line25+"\n"), 0o644)
	if code, _, _ := call("check-proof", "--pub", "agent.pub", "p.json", "rec.json"); code != 0 {
		t.Fatal("check-proof with the record file")
	}
	os.WriteFile("rec.json", []byte(strings.Replace(line25, "evil.example", "cdn.example", 1)), 0o644)
	if code, out, _ := call("check-proof", "--pub", "agent.pub", "p.json", "rec.json"); code != exitFound ||
		!strings.Contains(out, "p.json: the proof doesn't hold: the record doesn't match the proof's hash: it was changed.") {
		t.Fatalf("check-proof with another record: %d %s", code, out)
	}
	code, out, _ = call("prove", "--line", "3", "trace.jsonl")
	if p, err := ledger.ParseProof([]byte(out)); code != 0 || err != nil || p.Line != 3 {
		t.Fatalf("prove to stdout: %d %v", code, err)
	}
	// Another key and its public half.
	call("keygen", "-o", "other")
	if code, out, _ := call("check-proof", "--pub", "other.pub", "p.json"); code != exitFound || !strings.Contains(out, "checkpoint 4: signed by key") {
		t.Fatalf("check-proof with another key: %d %s", code, out)
	}
	// A record changed afterwards has no proof.
	os.WriteFile("trace.jsonl", bytes.Replace(trace, []byte("evil.example"), []byte("cdn.example"), -1), 0o644)
	if code, _, errs := call("prove", "--line", "25", "trace.jsonl"); code != exitFound || !strings.Contains(errs, "trace.jsonl:25: the record doesn't match its sealed hash") {
		t.Fatalf("prove a changed record: %d %s", code, errs)
	}
}

func TestSealAgain(t *testing.T) {
	trace := setup(t)
	lines := strings.SplitAfter(string(trace), "\n")
	os.WriteFile("trace.jsonl", []byte(strings.Join(lines[:20], "")), 0o644)
	if code, _, errs := call("seal", "--key", "agent.key", "--every", "8", "trace.jsonl"); code != 0 {
		t.Fatal(errs)
	}
	os.WriteFile("trace.jsonl", trace, 0o644)
	code, out, errs := call("seal", "--key", "agent.key", "--every", "8", "trace.jsonl")
	if code != 0 || strings.Count(out, `{"cp":`) != 1 || !strings.Contains(errs, "sealed 8 new records") || !strings.Contains(errs, "28 records under 4 checkpoints") {
		t.Fatalf("seal again: %d %s %s", code, out, errs)
	}
	code, out, errs = call("seal", "--key", "agent.key", "trace.jsonl")
	if code != 0 || out != "" || !strings.Contains(errs, "sealed 0 new records") {
		t.Fatalf("nothing new: %d %s %s", code, out, errs)
	}
	if code, _, errs := call("seal", "--key", "agent.key", "--log", "other", "trace.jsonl"); code != exitInput || !strings.Contains(errs, `is the ledger of log "trace.jsonl"; --log can't change it`) {
		t.Fatalf("--log: %d %s", code, errs)
	}
	call("keygen", "-o", "other")
	if code, _, errs := call("seal", "--key", "other.key", "trace.jsonl"); code != exitInput || !strings.Contains(errs, "trace.jsonl.ledger was sealed with another key: checkpoint 1: signed by key") {
		t.Fatalf("another key: %d %s", code, errs)
	}
	os.WriteFile("trace.jsonl", append(bytes.Replace(trace, []byte("45.77.10.10"), []byte("45.77.10.11"), 1), lines[0]...), 0o644)
	if code, out, errs := call("seal", "--key", "agent.key", "trace.jsonl"); code != exitFound || !strings.Contains(out, "trace.jsonl:24: the record doesn't match its sealed hash") ||
		!strings.Contains(errs, "doesn't verify, so nothing more was sealed") {
		t.Fatalf("seal over a changed record: %d %s %s", code, out, errs)
	}
	// A new log with its own name, and an empty one.
	os.WriteFile("flows.jsonl", nil, 0o644)
	if code, _, errs := call("seal", "--key", "agent.key", "--log", "gateway flows", "--ledger", "f.ledger", "flows.jsonl"); code != 0 || !strings.Contains(errs, "flows.jsonl has no records yet; f.ledger has its header.") {
		t.Fatalf("empty: %d %s", code, errs)
	}
	if b, _ := os.ReadFile("f.ledger"); string(b) != `{"vpnw-ledger":1,"log":"gateway flows"}`+"\n" {
		t.Fatalf("f.ledger: %s", b)
	}
	if code, out, _ := call("verify", "--pub", "agent.pub", "--ledger", "f.ledger", "flows.jsonl"); code != 0 || !strings.Contains(out, "flows.jsonl holds no records yet, and nothing is sealed.") {
		t.Fatalf("verify empty: %d %s", code, out)
	}
}

// TestTamperMatrix runs the tamper matrix through the command line, the way
// an auditor would see it. tools/measure-ledger.sh turns its RESULT lines
// into results/ledger-alpha/tamper.txt.
func TestTamperMatrix(t *testing.T) {
	trace := setup(t)
	code, out, _ := call("seal", "--key", "agent.key", "--every", "8", "trace.jsonl")
	if code != 0 {
		t.Fatal("seal")
	}
	lastCP := strings.Split(strings.TrimSpace(out), "\n")[3]
	call("keygen", "-o", "other")
	led, _ := os.ReadFile("trace.jsonl.ledger")
	orig := tamper.Files{Records: tamper.Split(trace), Ledger: tamper.Split(led)}
	cases, err := tamper.Matrix(orig, 25)
	if err != nil {
		t.Fatal(err)
	}
	for i, c := range cases {
		dir := filepath.Join("case", string(rune('a'+i)))
		os.MkdirAll(dir, 0o755)
		recs, ledg := filepath.Join(dir, "trace.jsonl"), filepath.Join(dir, "trace.jsonl.ledger")
		os.WriteFile(recs, tamper.Join(c.Files.Records), 0o644)
		os.WriteFile(ledg, tamper.Join(c.Files.Ledger), 0o644)
		args := []string{"verify", "--pub", "agent.pub", recs}
		if c.WrongKey {
			args[2] = "other.pub"
		}
		if c.Witness {
			os.WriteFile("witness.log", []byte(lastCP+"\n"), 0o644)
			args = append(args, "--witness", "witness.log")
		}
		code, out, errs := call(args...)
		said := strings.SplitN(out, "\n", 2)[0]
		said = strings.TrimPrefix(said, dir+string(filepath.Separator))
		want := "trace.jsonl:" + strconv.Itoa(c.Line) + ":"
		if c.File == "ledger" {
			want = "trace.jsonl.ledger:" + strconv.Itoa(c.Line) + ":"
		}
		caught := code == exitFound && strings.HasPrefix(said, want)
		if !caught {
			t.Errorf("%s: exit %d, said %q %s; want %s", c.Name, code, said, errs, want)
		}
		t.Logf("RESULT tamper | %s | %s | %s", c.Name, said, map[bool]string{true: "yes", false: "no"}[caught])
	}
}

func TestFollow(t *testing.T) {
	trace := setup(t)
	lines := strings.SplitAfter(string(trace), "\n")
	os.WriteFile("trace.jsonl", []byte(strings.Join(lines[:5], "")), 0o644)
	stop := make(chan struct{})
	interrupt = func() <-chan struct{} { return stop }
	defer func() { interrupt = defaultInterrupt }()
	type result struct {
		code      int
		out, errs string
	}
	done := make(chan result)
	go func() {
		code, out, errs := call("seal", "--follow", "--interval", "1h", "--key", "agent.key", "trace.jsonl")
		done <- result{code, out, errs}
	}()
	f, err := os.OpenFile("trace.jsonl", os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, l := range lines[5:] {
		f.WriteString(l)
		time.Sleep(time.Millisecond)
	}
	f.Close()
	close(stop)
	var r result
	select {
	case r = <-done:
	case <-time.After(60 * time.Second):
		t.Fatal("seal --follow didn't stop")
	}
	if r.code != 0 || !strings.Contains(r.errs, "following trace.jsonl from line 1 into trace.jsonl.ledger; stop with Ctrl-C.") ||
		!strings.Contains(r.errs, "sealed 28 new records") || strings.Count(r.out, `{"cp":`) != 1 {
		t.Fatalf("follow: %+v", r)
	}
	if code, out, _ := call("verify", "--pub", "agent.pub", "trace.jsonl"); code != 0 {
		t.Fatalf("verify after follow: %s", out)
	}
}

// The default stop: a real SIGTERM, caught.
func TestInterrupt(t *testing.T) {
	stop := defaultInterrupt()
	syscall.Kill(os.Getpid(), syscall.SIGTERM)
	select {
	case <-stop:
	case <-time.After(60 * time.Second):
		t.Fatal("SIGTERM didn't stop it")
	}
}

func TestLock(t *testing.T) {
	setup(t)
	f, err := os.OpenFile("trace.jsonl.ledger", os.O_RDWR|os.O_CREATE, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := lock(f); err != nil {
		t.Fatal(err)
	}
	if code, _, errs := call("seal", "--key", "agent.key", "trace.jsonl"); code != exitFailure || !strings.Contains(errs, "trace.jsonl.ledger is in use by another vpnw-ledger seal") {
		t.Fatalf("a second seal: %d %s", code, errs)
	}
}

func TestErrors(t *testing.T) {
	setup(t)
	call("seal", "--key", "agent.key", "--every", "8", "trace.jsonl")
	call("prove", "--line", "2", "-o", "p.json", "trace.jsonl")
	os.WriteFile("open.key", nil, 0o644)
	key, _ := os.ReadFile("agent.key")
	os.WriteFile("open.key", key, 0o644)
	os.WriteFile("group.key", key, 0o640)
	os.Chmod("group.key", 0o640)
	os.WriteFile("two.json", []byte("{}\n{}\n"), 0o644)
	os.WriteFile("big.json", bytes.Repeat([]byte("x"), 1<<20+5), 0o644)
	os.WriteFile("long.jsonl", append(bytes.Repeat([]byte("x"), ledger.MaxLine+5), '\n'), 0o644)
	os.WriteFile("bad.jsonl", []byte("{}\nnot json\n"), 0o644)
	os.WriteFile("w.log", []byte("nothing\n"), 0o644)
	cases := []struct {
		args []string
		code int
		want string
	}{
		{nil, exitInput, "Usage:"},
		{[]string{"frobnicate"}, exitInput, "unknown command"},
		{[]string{"keygen"}, exitInput, "keygen: -o NAME is required"},
		{[]string{"keygen", "-o", "x", "extra"}, exitInput, `keygen: unexpected argument "extra"`},
		{[]string{"keygen", "-o", filepath.Join("no", "such", "dir")}, exitInput, "no such file or directory"},
		{[]string{"seal", "trace.jsonl"}, exitInput, "--key FILE is required"},
		{[]string{"seal", "--key", "agent.key"}, exitInput, "seal: give the records file"},
		{[]string{"seal", "--key", "agent.key", "a", "b"}, exitInput, `seal: unexpected argument "b"`},
		{[]string{"seal", "--every", "0", "--key", "agent.key", "trace.jsonl"}, exitInput, "--every must be 1 or more"},
		{[]string{"seal", "--interval", "0s", "--key", "agent.key", "trace.jsonl"}, exitInput, "--interval must be more than 0"},
		{[]string{"seal", "--bogus"}, exitInput, "seal: flag provided but not defined"},
		{[]string{"seal", "--key", "open.key", "trace.jsonl"}, exitInput, "open.key: its permissions 0644 let others read the private key; run chmod 600 open.key"},
		{[]string{"seal", "--key", "group.key", "trace.jsonl"}, exitInput, "group.key: its permissions 0640 let others read the private key"},
		{[]string{"seal", "--key", "none.key", "trace.jsonl"}, exitInput, "no such file"},
		{[]string{"seal", "--key", "agent.pub", "trace.jsonl"}, exitInput, "permissions"},
		{[]string{"seal", "--key", "agent.key", "none.jsonl"}, exitInput, "no such file"},
		{[]string{"seal", "--key", "agent.key", "--ledger", "p.json", "trace.jsonl"}, exitInput, "p.json:1: not a vpnw-ledger file"},
		{[]string{"seal", "--key", "agent.key", "--ledger", filepath.Join("no", "x"), "trace.jsonl"}, exitInput, "no such file"},
		{[]string{"seal", "--key", "agent.key", "--log", "a\"b", "two.json"}, exitInput, "give a name with --log"},
		{[]string{"seal", "--key", "agent.key", "bad.jsonl"}, exitInput, "bad.jsonl:2: not valid JSON"},
		{[]string{"seal", "--key", "agent.key", "long.jsonl"}, exitInput, "long.jsonl:1: longer than 65536 bytes"},
		{[]string{"verify", "trace.jsonl"}, exitInput, "--pub FILE is required"},
		{[]string{"verify", "--pub", "agent.key", "trace.jsonl"}, exitInput, "agent.key:4: this is a private key"},
		{[]string{"verify", "--pub", "agent.pub", "none.jsonl"}, exitInput, "none.jsonl.ledger: no such ledger: seal the records first"},
		{[]string{"verify", "--pub", "agent.pub", "--ledger", "trace.jsonl.ledger", "none.jsonl"}, exitInput, "no such file"},
		{[]string{"verify", "--pub", "agent.pub", "--ledger", "trace.jsonl", "trace.jsonl"}, exitInput, "trace.jsonl:1: not a vpnw-ledger file"},
		{[]string{"verify", "--pub", "agent.pub", "--witness", "w.log", "trace.jsonl"}, exitInput, "w.log: no checkpoint in it"},
		{[]string{"verify", "--pub", "agent.pub", "--witness", "none.log", "trace.jsonl"}, exitInput, "no such file"},
		{[]string{"verify", "--pub", "big.json", "trace.jsonl"}, exitInput, "larger than 1 MB"},
		{[]string{"verify", "--bogus"}, exitInput, "verify: flag provided"},
		{[]string{"prove", "trace.jsonl"}, exitInput, "--line N is required"},
		{[]string{"prove", "--line", "29", "trace.jsonl"}, exitInput, "trace.jsonl:29: the file has fewer lines"},
		{[]string{"prove", "--line", "1", "--ledger", "two.json", "two.json"}, exitInput, "two.json:1: not a vpnw-ledger file"},
		{[]string{"prove", "--line", "1", "--ledger", "trace.jsonl.ledger", "long.jsonl"}, exitFound, "long.jsonl:1: longer than any record seal accepts"},
		{[]string{"prove", "--line", "1", "--ledger", "trace.jsonl.ledger", "none.jsonl"}, exitInput, "no such file"},
		{[]string{"prove", "--line", "1", "-o", filepath.Join("no", "p.json"), "trace.jsonl"}, exitInput, "no such file"},
		{[]string{"prove", "--bogus"}, exitInput, "prove: flag provided"},
		{[]string{"check-proof", "--pub", "agent.pub"}, exitInput, "check-proof: give the proof file"},
		{[]string{"check-proof", "p.json"}, exitInput, "--pub FILE is required"},
		{[]string{"check-proof", "--pub", "agent.pub", "trace.jsonl"}, exitInput, "trace.jsonl: not a vpnw-ledger proof"},
		{[]string{"check-proof", "--pub", "agent.pub", "none.json"}, exitInput, "no such file"},
		{[]string{"check-proof", "--pub", "agent.pub", "p.json", "two.json"}, exitInput, "two.json: more than one line; give the one record"},
		{[]string{"check-proof", "--pub", "agent.pub", "p.json", "none.json"}, exitInput, "no such file"},
		{[]string{"check-proof", "--pub", "agent.pub", "p.json", "a", "b"}, exitInput, `unexpected argument "b"`},
	}
	for _, c := range cases {
		code, out, errs := call(c.args...)
		if code != c.code || !strings.Contains(out+errs, c.want) {
			t.Errorf("%v: exit %d, output %q; want %d and %q", c.args, code, out+errs, c.code, c.want)
		}
	}
	if code, out, _ := call("version"); code != 0 || !strings.HasPrefix(out, "vpnw-ledger 0.1.0 (") {
		t.Errorf("version: %s", out)
	}
	if code, out, _ := call("help"); code != 0 || !strings.Contains(out, "vpnw-ledger check-proof") {
		t.Errorf("help: %s", out)
	}
	for n, want := range map[int]string{0: "0", 999: "999", 1000: "1,000", 1234567: "1,234,567", -4500: "-4,500"} {
		if comma(n) != want {
			t.Errorf("comma(%d) = %s", n, comma(n))
		}
	}
}
