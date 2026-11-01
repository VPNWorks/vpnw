// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package integration

import (
	"bytes"
	"crypto/ed25519"
	crand "crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/VPNWorks/vpnw/plugins/ledger/chain"
)

// rechain writes a ledger again from its events, the way someone who can
// edit the file but has no key would: each event through edit, every hash
// computed afresh, and the signature lines copied over as they were. With a
// key, it signs the new ledger with that key instead.
func rechain(t *testing.T, ledger []byte, edit func(n uint64, ev []byte) []byte, key ed25519.PrivateKey) []byte {
	t.Helper()
	lines := bytes.Split(bytes.TrimSuffix(ledger, []byte("\n")), []byte("\n"))
	hd, err := chain.Parse(lines[0])
	if err != nil {
		t.Fatal(err)
	}
	pub := hd.Key
	if key != nil {
		pub = "vpnw-ed25519:" + base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey))
	}
	w, head, err := chain.NewSignedWriter(hd.Run, pub)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	out.Write(head)
	sign := func(old []byte, k uint64, stmt string) {
		if key == nil {
			out.Write(append(old, '\n'))
			return
		}
		out.Write(chain.SigLine(k, ed25519.Sign(key, chain.SignedMessage(hd.Run, stmt))))
	}
	for _, l := range lines[1:] {
		p, err := chain.Parse(l)
		if err != nil {
			t.Fatalf("%s: %v", l, err)
		}
		switch p.Kind {
		case chain.KEvent:
			b, err := w.Event(edit(p.N, p.Ev))
			if err != nil {
				t.Fatal(err)
			}
			out.Write(b)
		case chain.KLost:
			b, _ := w.Lost(p.Count)
			out.Write(b)
		case chain.KCheckpoint:
			b, k := w.Checkpoint()
			out.Write(b)
			pendingStmt, pendingK = chain.CheckpointStatement(k, w.Entries(), w.Head()), k
		case chain.KEnd:
			out.Write(w.End())
			pendingStmt, pendingK = chain.EndStatement(w.Entries(), w.Checkpoints(), w.Head()), 0
		case chain.KSig:
			sign(l, pendingK, pendingStmt)
		}
	}
	return out.Bytes()
}

var (
	pendingStmt string
	pendingK    uint64
)

var signedRows []string

func signedRecord(check, want, got string, ok bool) {
	res := "passed"
	if !ok {
		res = "FAILED"
	}
	signedRows = append(signedRows, fmt.Sprintf("| %s | %s | %s | %s |", check, want, got, res))
}

// Ledger's checkpoints are signed by vpnw with this machine's key, which
// the plugin never sees. A ledger written again after a checkpoint, chain
// and all, fails verify at that checkpoint; so do stripped signatures and a
// ledger signed by another key.
func TestLedgerSigned(t *testing.T) {
	skipIfNoSeal(t)
	e := newEnv(t)
	srv := newServer(t)
	url := fmt.Sprintf("http://localhost:%d/", srv.port)
	led := filepath.Join(e.dir, "run.ledger")
	tr := filepath.Join(e.dir, "run.jsonl")
	out := e.must("trace", "--plugin", "ledger", "--plugin-file", "ledger="+led, "--set", "ledger.every=5", "--out", tr,
		"--", "python3", "-c", pyGet(url, url, url, url))
	keyOut := e.must("key")
	pub := regexp.MustCompile(`public key:\s+(vpnw-ed25519:\S+)`).FindStringSubmatch(keyOut)
	made := strings.Contains(out, "made a signing key for this machine")
	ok := pub != nil && made && strings.Contains(out, "signed by "+pub[1])
	signedRecord("a first run with Ledger", "vpnw makes this machine's key, and the ledger is signed by it", fmt.Sprintf("key made: %v; ledger signed by it: %v", made, ok), ok)
	if !ok {
		t.Fatalf("run:\n%s\nkey:\n%s", out, keyOut)
	}
	b, _ := os.ReadFile(led)
	if bytes.Contains(b, []byte("private")) {
		t.Fatal("the private key is in the ledger")
	}
	sigs := bytes.Count(b, []byte(`{"sig":`))

	got, code := e.run("verify", led, tr)
	ok = code == 0 && strings.HasPrefix(got, "intact: ") && strings.Contains(got, "signed by this machine's key") && strings.Contains(got, "and the end")
	signedRecord("verify on the same machine", "intact, every checkpoint and the end signed by this machine's key", firstLine(strings.Split(got, "\n"), "signed by"), ok)
	if !ok {
		t.Fatalf("verify: exit %d\n%s", code, got)
	}

	// Elsewhere: another machine has no key of its own, or another one.
	other := newEnv(t)
	got, code = other.run("verify", led)
	ok = code == 0 && strings.Contains(got, "give vpnw verify --key")
	signedRecord("verify on another machine, with no key given", "intact, and it says the signatures weren't checked against a key it trusts", firstLine(strings.Split(got, "\n"), "signed by"), ok)
	if !ok {
		t.Fatalf("elsewhere: exit %d\n%s", code, got)
	}
	got, code = other.run("verify", led, "--key", pub[1])
	ok = code == 0 && strings.Contains(got, "signed by the key you gave")
	signedRecord("verify there with --key and the public key", "intact, checked against the key given", firstLine(strings.Split(got, "\n"), "signed by"), ok)
	if !ok {
		t.Fatalf("--key: exit %d\n%s", code, got)
	}

	nfile := 0
	check := func(name, want, wantText string, ledger []byte, args ...string) {
		t.Helper()
		nfile++
		fn := filepath.Join(e.dir, fmt.Sprintf("forged-%d.ledger", nfile))
		os.WriteFile(fn, ledger, 0o600)
		got, code := other.run(append([]string{"verify", fn, "--key", pub[1]}, args...)...)
		ok := code == 1 && strings.HasPrefix(got, "CHANGED: ") && strings.Contains(got, wantText)
		line := strings.ReplaceAll(firstLine(strings.Split(got, "\n"), "CHANGED"), e.dir+"/", "")
		signedRecord(name, want, line, ok)
		if !ok {
			t.Errorf("%s: exit %d\n%s", name, code, got)
		}
	}
	// The promise: an event after checkpoint 1 changed, the whole chain
	// computed again, the old signatures kept.
	rewritten := rechain(t, b, func(n uint64, ev []byte) []byte {
		if n == 7 {
			return bytes.Replace(ev, []byte(`"ts":"2`), []byte(`"ts":"1`), 1)
		}
		return ev
	}, nil)
	if bytes.Equal(rewritten, b) {
		t.Fatal("the rewrite changed nothing")
	}
	check("the ledger written again after checkpoint 1, chain recomputed, signatures kept", "CHANGED at checkpoint 2: it doesn't match its signature", "checkpoint 2 doesn't match its signature", rewritten)
	// The signatures stripped.
	var stripped []byte
	for _, l := range bytes.SplitAfter(b, []byte("\n")) {
		if !bytes.HasPrefix(l, []byte(`{"sig":`)) {
			stripped = append(stripped, l...)
		}
	}
	check(fmt.Sprintf("its %d signature lines removed", sigs), "CHANGED: the first checkpoint has no signature", "checkpoint 1 has no signature after it", stripped)
	// Signed again with a forger's own key.
	_, forger, _ := ed25519.GenerateKey(crand.Reader)
	check("written again and signed with another key", "CHANGED: signed by another key", "not by the key you gave", rechain(t, b, func(_ uint64, ev []byte) []byte { return ev }, forger))
	// Written unsigned.
	unsigned := regexp.MustCompile(`,"key":"[^"]+"`).ReplaceAll(stripped, nil)
	unsigned = rechain(t, unsigned, func(_ uint64, ev []byte) []byte { return ev }, nil)
	check("written again unsigned", "CHANGED: --key asks for a signed ledger", "isn't signed, and --key asks for one", unsigned)

	// The trace's copies carry the signatures too.
	tb, _ := os.ReadFile(tr)
	ok = bytes.Count(tb, []byte(`"type":"plugin.ledger.checkpoint"`)) == bytes.Count(tb, []byte(`"sig":"`)) && bytes.Count(tb, []byte(`"sig":"`)) > 0
	signedRecord("the checkpoint copies in the trace", "each carries its signature", fmt.Sprintf("%d copies, %d with a signature", bytes.Count(tb, []byte(`"type":"plugin.ledger.checkpoint"`)), bytes.Count(tb, []byte(`"sig":"`))), ok)

	// Unsigned on request, as before.
	led2 := filepath.Join(e.dir, "unsigned.ledger")
	e.must("run", "--plugin", "ledger", "--plugin-file", "ledger="+led2, "--set", "ledger.sign=false", "--", "true")
	got, code = e.run("verify", led2)
	ok = code == 0 && strings.Contains(got, "this ledger isn't signed")
	signedRecord("ledger.sign=false", "an unsigned ledger, as in 0.9; verify says it isn't signed", fmt.Sprintf("exit %d; %s", code, firstLine(strings.Split(got, "\n"), "isn't signed")), ok)
	if !ok {
		t.Errorf("unsigned: exit %d\n%s", code, got)
	}

	if fn := os.Getenv("VPNW_SIGNED_OUT"); fn != "" {
		os.WriteFile(fn, []byte("| Check | What must happen | What happened | Result |\n|---|---|---|---|\n"+strings.Join(signedRows, "\n")+"\n"), 0o644)
	}
}
