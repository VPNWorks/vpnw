// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package chain

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// unsignedLedger writes an unsigned (0.9-style) ledger with fresh hashes,
// as a forger without the key would.
func unsignedLedger(t *testing.T, run string, n, every int, edit func(i int, host string) string) []string {
	t.Helper()
	w, hd, err := NewWriter(run)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	add := func(b []byte) { out = append(out, strings.TrimSuffix(string(b), "\n")) }
	add(hd)
	for i := 1; i <= n; i++ {
		host := fmt.Sprintf("h%d.example", i)
		if edit != nil {
			host = edit(i, host)
		}
		ev, _ := json.Marshal(map[string]any{"v": 1, "type": "connection.attempt", "run": run, "conn": i, "fields": map[string]any{"host": host}})
		b, _ := w.Event(ev)
		add(b)
		if w.SinceCheckpoint() >= uint64(every) {
			b, _ := w.Checkpoint()
			add(b)
		}
	}
	b, _ := w.Checkpoint()
	add(b)
	add(w.End())
	return out
}

// Review 0.10.0, promise (b): an honest ledger from a run killed after the
// end line was written but before its signature (or in the middle of the
// signature line) must not be CHANGED. Ledger writes the end line, then
// asks vpnw to sign, then writes the signature line: a kill between the two
// is the same kind of stop as one between a checkpoint and its signature.
func TestReview0100KilledBeforeEndSignature(t *testing.T) {
	k := newKey(t)
	l := signedLedger(t, k, "r-abc123", 25, 10, nil)
	// Killed after the end line, before its signature.
	cut := l[:len(l)-1]
	if r := verifyKey(cut, k.pub, "given"); r.Verdict == Changed {
		t.Errorf("killed before the end signature: CHANGED: %s", r.Problem)
	}
	// Killed in the middle of the end signature line.
	v := &Verifier{Key: k.pub, KeyFrom: "given"}
	for i, line := range cut {
		v.Ledger("run.ledger", i+1, []byte(line), false)
	}
	half := l[len(l)-1][:30]
	v.Ledger("run.ledger", len(l), []byte(half), true)
	if r := v.Result(); r.Verdict == Changed {
		t.Errorf("killed mid end-signature line: CHANGED: %s", r.Problem)
	}
}

// Review 0.10.0, promise (a) and docs/reference.md ("on the machine that
// ran it, without --key: the same [as --key]"): a ledger written again
// unsigned, header key removed and the chain recomputed, must fail when
// checked against this machine's key. It is reported intact.
func TestReview0100MachineKeyUnsignedRewrite(t *testing.T) {
	k := newKey(t)
	forged := unsignedLedger(t, "r-abc123", 25, 10, func(i int, h string) string {
		if i == 14 {
			return "exfil.example"
		}
		return h
	})
	r := verifyKey(forged, k.pub, "machine")
	if r.Verdict != Changed {
		t.Errorf("unsigned rewrite checked against this machine's key: %s\n%s", r.Verdict, strings.Join(r.Lines, "\n"))
	}
}

// Review 0.10.0, promise (a): a ledger written again and signed by another
// key (the forger's own) must fail against this machine's key on the
// machine that ran it. It is reported intact (exit 0), with a note.
func TestReview0100MachineKeyOtherKeyRewrite(t *testing.T) {
	machine, forger := newKey(t), newKey(t)
	forged := signedLedger(t, forger, "r-abc123", 25, 10, func(i int, h string) string {
		if i == 14 {
			return "exfil.example"
		}
		return h
	})
	r := verifyKey(forged, machine.pub, "machine")
	if r.Verdict != Changed {
		t.Errorf("rewrite signed by another key, checked against this machine's key: %s\n%s", r.Verdict, strings.Join(r.Lines, "\n"))
	}
}

// Control: the signatures themselves can't be moved between runs.
func TestReview0100SignatureFromOtherRun(t *testing.T) {
	k := newKey(t)
	a := signedLedger(t, k, "r-aaaaaa", 5, 10, nil)
	stmt := "cp 1 5 " + strings.Repeat("0", 64)
	sig := ed25519.Sign(k.priv, SignedMessage("r-bbbbbb", stmt))
	if VerifySig(k.pub, "r-aaaaaa", stmt, sig) {
		t.Fatal("signature crosses runs")
	}
	_ = a
}

// Review 0.10.0 (low): a public key given in a non-canonical base64 form
// (same 32 bytes, other padding bits in the last character) passes ValidKey
// and vpnw verify --key's ParsePublicKey, and checks the signatures, but is
// compared as a string with the header's key: an honest ledger is CHANGED.
func TestReview0100NonCanonicalKeyGiven(t *testing.T) {
	k := newKey(t)
	l := signedLedger(t, k, "r-abc123", 5, 10, nil)
	b := []byte(k.pub)
	last := b[len(b)-2] // the character before "="
	const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	i := strings.IndexByte(alpha, last)
	b[len(b)-2] = alpha[i^1] // flip a padding bit
	alt := string(b)
	// Fixed by refusing the other spelling: only the canonical one is a key.
	if ValidKey(alt) {
		if r := verifyKey(l, alt, "given"); r.Verdict == Changed {
			t.Errorf("same key, other base64 spelling: CHANGED: %s", r.Problem)
		}
	}
}
