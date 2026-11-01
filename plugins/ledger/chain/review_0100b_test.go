// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package chain

import (
	"strings"
	"testing"
)

// Review 0.10.0 round 2: a ledger cut short after its end line (no end
// signature) with --head: the head is checked against the end line, yet the
// report says it couldn't be, because "this ledger has none" (an end line).
func TestReview0100bHeadReportWhenEndUnsigned(t *testing.T) {
	k := newKey(t)
	l := signedLedger(t, k, "r-abc123", 5, 10, nil)
	cut := l[:len(l)-1]
	end, _ := Parse([]byte(cut[len(cut)-1]))
	h := end.H
	v := &Verifier{Key: k.pub, KeyFrom: "given", Head: &h}
	for i, line := range cut {
		v.Ledger("run.ledger", i+1, []byte(line), false)
	}
	r := v.Result()
	text := strings.Join(r.Lines, "\n")
	if r.Verdict != CutShort {
		t.Fatalf("%s: %s", r.Verdict, text)
	}
	if strings.Contains(text, "this ledger has none") {
		t.Errorf("the report says the ledger has no end line, but it has one and its hash was checked:\n%s", text)
	}
	// And a wrong head must not pass quietly as only "cut short".
	var wrong Hash
	v = &Verifier{Key: k.pub, KeyFrom: "given", Head: &wrong}
	for i, line := range cut {
		v.Ledger("run.ledger", i+1, []byte(line), false)
	}
	if r := v.Result(); r.Verdict != Changed {
		t.Errorf("wrong --head on an end line without signature: %s", r.Verdict)
	}
}
