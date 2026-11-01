// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package chain

import (
	"crypto/ed25519"
	crand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

type testKey struct {
	priv ed25519.PrivateKey
	pub  string
}

func newKey(t *testing.T) testKey {
	pub, priv, err := ed25519.GenerateKey(crand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return testKey{priv, "vpnw-ed25519:" + base64.StdEncoding.EncodeToString(pub)}
}

// signedLedger writes a ledger of n events, a checkpoint every `every`,
// signed by k the way vpnw signs for Ledger, with the events changed by
// edit (the hashes are always computed afresh, as a forger would).
func signedLedger(t *testing.T, k testKey, run string, n, every int, edit func(i int, host string) string) []string {
	t.Helper()
	w, hd, err := NewSignedWriter(run, k.pub)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	add := func(b []byte) { out = append(out, strings.TrimSuffix(string(b), "\n")) }
	add(hd)
	sign := func(stmt string) []byte { return ed25519.Sign(k.priv, SignedMessage(run, stmt)) }
	for i := 1; i <= n; i++ {
		host := fmt.Sprintf("h%d.example", i)
		if edit != nil {
			host = edit(i, host)
		}
		ev, _ := json.Marshal(map[string]any{"v": 1, "type": "connection.attempt", "run": run, "conn": i, "fields": map[string]any{"host": host}})
		b, err := w.Event(ev)
		if err != nil {
			t.Fatal(err)
		}
		add(b)
		if w.SinceCheckpoint() >= uint64(every) {
			b, cp := w.Checkpoint()
			add(b)
			add(SigLine(cp, sign(CheckpointStatement(cp, w.Entries(), w.Head()))))
		}
	}
	b, cp := w.Checkpoint()
	add(b)
	add(SigLine(cp, sign(CheckpointStatement(cp, w.Entries(), w.Head()))))
	add(w.End())
	add(SigLine(0, sign(EndStatement(w.Entries(), w.Checkpoints(), w.Head()))))
	return out
}

func verifyKey(ledger []string, key, from string) Report {
	v := &Verifier{Key: key, KeyFrom: from}
	for i, l := range ledger {
		v.Ledger("run.ledger", i+1, []byte(l), false)
	}
	return v.Result()
}

func TestSignedIntact(t *testing.T) {
	k := newKey(t)
	l := signedLedger(t, k, "r-abc123", 25, 10, nil)
	for _, line := range l {
		if _, err := Parse([]byte(line)); err != nil {
			t.Fatalf("%s: %v", line, err)
		}
	}
	for _, from := range []string{"given", "machine"} {
		r := verifyKey(l, k.pub, from)
		if r.Verdict != Intact || !strings.Contains(strings.Join(r.Lines, "\n"), "checkpoints 1 to 3 and the end") {
			t.Fatalf("%s: %+v", from, r)
		}
	}
	// No key to check against: intact, and it says so.
	if r := verifyKey(l, "", ""); r.Verdict != Intact || !strings.Contains(strings.Join(r.Lines, "\n"), "give vpnw verify --key") {
		t.Fatalf("no key: %+v", r)
	}
}

// The promise: a ledger written again after a checkpoint, its chain
// recomputed and its old signatures kept, fails, and names the checkpoint.
func TestRewrittenAfterCheckpointFails(t *testing.T) {
	k := newKey(t)
	good := signedLedger(t, k, "r-abc123", 25, 10, nil)
	forged := signedLedger(t, k, "r-abc123", 25, 10, func(i int, h string) string {
		if i == 14 {
			return "exfil.example"
		}
		return h
	})
	// The forger has no key: keep the real signature lines in place.
	for i, l := range forged {
		if strings.HasPrefix(l, `{"sig":`) {
			forged[i] = good[i]
		}
	}
	r := verifyKey(forged, k.pub, "given")
	if r.Verdict != Changed || !strings.Contains(r.Problem, "checkpoint 2 doesn't match its signature: the ledger was written again after it was signed") {
		t.Fatalf("%+v", r)
	}
	// The same rewrite after the last checkpoint is caught at the end line.
	forged = signedLedger(t, k, "r-abc123", 25, 10, func(i int, h string) string {
		if i == 25 {
			return "exfil.example"
		}
		return h
	})
	for i, l := range forged {
		if strings.HasPrefix(l, `{"sig":`) {
			forged[i] = good[i]
		}
	}
	if r := verifyKey(forged, k.pub, "given"); r.Verdict != Changed || !strings.Contains(r.Problem, "checkpoint 3 doesn't match its signature") {
		t.Fatalf("after the last checkpoint: %+v", r)
	}
}

func TestSignatureTampering(t *testing.T) {
	k, other := newKey(t), newKey(t)
	good := signedLedger(t, k, "r-abc123", 25, 10, nil)
	without := func(pred func(string) bool) []string {
		var out []string
		for _, l := range good {
			if !pred(l) {
				out = append(out, l)
			}
		}
		return out
	}
	cases := []struct {
		name   string
		ledger []string
		key    string
		from   string
		want   string // in the problem; "" for a pass
	}{
		{"signatures stripped", without(func(l string) bool { return strings.HasPrefix(l, `{"sig":`) }), k.pub, "given", "checkpoint 1 has no signature after it"},
		{"the end's signature removed", without(func(l string) bool { return l == good[len(good)-1] }), k.pub, "given", "the end line has no signature after it"},
		{"one signature removed", without(func(l string) bool { return strings.HasPrefix(l, `{"sig":2,`) }), k.pub, "given", "checkpoint 2 has no signature after it"},
		{"a forger's own key", signedLedger(t, other, "r-abc123", 25, 10, nil), k.pub, "given", "not by the key you gave"},
		{"a forger's own key, checked on this machine", signedLedger(t, other, "r-abc123", 25, 10, nil), k.pub, "machine", ""},
		{"signed by a key it doesn't name", func() []string {
			l := signedLedger(t, other, "r-abc123", 25, 10, nil)
			hd, _ := SignedHeader("r-abc123", k.pub)
			l[0] = string(hd)
			return l
		}(), k.pub, "given", "doesn't match its hash"},
		{"another run's signature", func() []string {
			l := cp(good)
			o := signedLedger(t, k, "r-other1", 25, 10, nil)
			for i := range l {
				if strings.HasPrefix(l[i], `{"sig":1,`) {
					l[i] = o[i]
				}
			}
			return l
		}(), k.pub, "given", "checkpoint 1 doesn't match its signature"},
	}
	for _, c := range cases {
		r := verifyKey(c.ledger, c.key, c.from)
		if c.want == "" {
			if r.Verdict != Intact || !strings.Contains(strings.Join(r.Lines, "\n"), "not this machine's key") {
				t.Errorf("%s: %+v", c.name, r)
			}
			continue
		}
		if r.Verdict != Changed || !strings.Contains(r.Problem, c.want) {
			t.Errorf("%s: %+v", c.name, r)
		}
	}
}

func TestUnsignedWithKey(t *testing.T) {
	k := newKey(t)
	l, _ := sample(t, 25, 10, nil)
	if r := verifyKey(l, k.pub, "given"); r.Verdict != Changed || !strings.Contains(r.Problem, "isn't signed, and --key asks for one") {
		t.Fatalf("given: %+v", r)
	}
	if r := verifyKey(l, k.pub, "machine"); r.Verdict != Intact || !strings.Contains(strings.Join(r.Lines, "\n"), "this ledger isn't signed") {
		t.Fatalf("machine: %+v", r)
	}
	// A signature line added to an unsigned ledger.
	s := signedLedger(t, k, "r-abc123", 25, 10, nil)
	l = append(l[:12:12], append([]string{s[12]}, l[12:]...)...)
	if r := verifyKey(l, "", ""); r.Verdict != Changed || !strings.Contains(r.Problem, "names no key") {
		t.Fatalf("added: %+v", r)
	}
}

// A run killed after a checkpoint but before its signature: cut short, and
// the report says what the signatures cover.
func TestKilledBeforeSignature(t *testing.T) {
	k := newKey(t)
	l := signedLedger(t, k, "r-abc123", 25, 10, nil)
	// Up to checkpoint 2, without its signature line.
	var cut []string
	for _, line := range l {
		cut = append(cut, line)
		if strings.HasPrefix(line, `{"cp":2,`) {
			break
		}
	}
	r := verifyKey(cut, k.pub, "given")
	if r.Verdict != CutShort || !strings.Contains(strings.Join(r.Lines, "\n"), "checkpoint 2 was never signed") {
		t.Fatalf("%+v", r)
	}
}

func TestParseSigLine(t *testing.T) {
	sig := make([]byte, 64)
	for _, bad := range []string{
		`{"sig":0,"s":"` + base64.StdEncoding.EncodeToString(sig) + `"}`,
		`{"sig":1,"s":"` + base64.StdEncoding.EncodeToString(sig[:63]) + `"}`,
		`{"sig":"start","s":"` + base64.StdEncoding.EncodeToString(sig) + `"}`,
		`{"sig":1, "s":"` + base64.StdEncoding.EncodeToString(sig) + `"}`,
		`{"vpnw-ledger":1,"run":"r-1","key":"vpnw-ed25519:short"}`,
	} {
		if _, err := Parse([]byte(bad)); err == nil {
			t.Errorf("parsed %s", bad)
		}
	}
}
