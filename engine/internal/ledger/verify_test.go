// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"strings"
	"testing"
)

func hashes(lines []string) []Hash {
	var out []Hash
	for _, l := range lines {
		out = append(out, LeafHash([]byte(l)))
	}
	return out
}

// TestCompare checks what compare says for each way of changing records
// that were sealed: the line it names and what it calls it.
func TestCompare(t *testing.T) {
	sealed := agentLines(30)
	edit := func(f func(r []string) []string) []string { return f(append([]string(nil), sealed...)) }
	move := func(r []string, from, to int) []string { // 1-based lines
		rec := r[from-1]
		r = append(r[:from-1], r[from:]...)
		return append(r[:to-1], append([]string{rec}, r[to-1:]...)...)
	}
	cases := []struct {
		name string
		recs []string
		line int
		kind string
		msg  string
	}{
		{"edit", edit(func(r []string) []string { r[9] += " "; return r }), 10, "changed", "the record doesn't match its sealed hash: it was changed"},
		{"edit first", edit(func(r []string) []string { r[0] = "{}"; return r }), 1, "changed", "it was changed"},
		{"delete", edit(func(r []string) []string { return append(r[:9], r[10:]...) }), 10, "missing", "a record is missing here: the one sealed as line 10 was deleted"},
		{"delete three", edit(func(r []string) []string { return append(r[:9], r[12:]...) }), 10, "missing", "3 records are missing here: the ones sealed as lines 10 to 12 were deleted"},
		{"delete next to last", edit(func(r []string) []string { return append(r[:28], r[29]) }), 29, "missing", "the one sealed as line 29"},
		{"insert", edit(func(r []string) []string { return append(r[:9], append([]string{"{}"}, r[9:]...)...) }), 10, "inserted", "this line was never sealed: it was inserted"},
		{"insert two", edit(func(r []string) []string { return append(r[:9], append([]string{"{}", "[]"}, r[9:]...)...) }), 10, "inserted", "lines 10 to 11 were never sealed"},
		{"swap", edit(func(r []string) []string { r[9], r[10] = r[10], r[9]; return r }), 10, "swapped", "lines 10 and 11 were swapped"},
		{"swap apart", edit(func(r []string) []string { r[9], r[19] = r[19], r[9]; return r }), 10, "swapped", "lines 10 and 20 were swapped"},
		{"move up", edit(func(r []string) []string { return move(r, 20, 10) }), 10, "moved", "this line holds the record sealed as line 20"},
		{"move down", edit(func(r []string) []string { return move(r, 10, 20) }), 10, "moved", "this line holds the record sealed as line 11"},
		{"a copy of a later line", edit(func(r []string) []string { r[9] = r[14]; return r }), 10, "changed", "it was changed"},
	}
	for _, c := range cases {
		v := &verifier{recs: hashes(c.recs), recName: "r.jsonl", led: &Ledger{Leaves: hashes(sealed)}}
		p := v.compare(len(sealed))
		if p == nil || p.File != "r.jsonl" || p.Line != c.line || p.Kind != c.kind || !strings.Contains(p.Msg, c.msg) {
			t.Errorf("%s: got %+v, want line %d %s %q", c.name, p, c.line, c.kind, c.msg)
		}
	}
	// Only as far as the trusted checkpoint.
	v := &verifier{recs: hashes(cases[0].recs), led: &Ledger{Leaves: hashes(sealed)}}
	if p := v.compare(9); p != nil {
		t.Errorf("past the trusted records: %+v", p)
	}
}

func TestVerifyEnds(t *testing.T) {
	k := testKey(t, 1)
	all := agentLines(20)
	led := seal(t, k, text(all), 8)
	ls := lines(led)
	for _, c := range []struct {
		name          string
		records, ledg []byte
		tail          bool
		file          string
		line          int
		kind, msg     string
	}{
		{"records cut", text(all[:13]), led, false, "test.jsonl", 14, "cut", "the file ends after line 13, but checkpoint 3 covers 20 records: the end was cut off"},
		{"last line cut", text(all[:19]), led, false, "test.jsonl", 20, "cut", "the file ends after line 19, but checkpoint 3 covers 20 records"},
		{"records gone", nil, led, false, "test.jsonl", 1, "cut", "the file is empty, but checkpoint 3 covers 20 records"},
		{"last checkpoint cut", text(all), []byte(strings.Join(ls[:len(ls)-1], "\n") + "\n"), false, "test.jsonl.ledger", 20, "cut",
			"records 17 to 20 are sealed, but no checkpoint covers them"},
		{"one line added", text(append(all, all[0])), led, false, "test.jsonl", 21, "unsealed", "this line was never sealed: it came after the last checkpoint"},
		{"lines added", text(append(all, all[0], all[1])), led, false, "test.jsonl", 21, "unsealed", "lines 21 to 22 were never sealed"},
		{"lines added, for seal", text(append(all, all[0], all[1])), led, true, "", 0, "", ""},
		{"no checkpoint yet", text(all[:2]), []byte(ls[0] + "\n" + ls[1] + "\n" + ls[2] + "\n"), false, "test.jsonl.ledger", 2, "cut", "records 1 to 2 are sealed, but no checkpoint covers them"},
		{"nothing sealed yet", text(all[:2]), []byte(ls[0] + "\n"), false, "test.jsonl", 1, "unsealed", "lines 1 to 2 were never sealed"},
		{"nothing at all", nil, []byte(ls[0] + "\n"), false, "", 0, "", ""},
	} {
		rep := check(t, c.records, c.ledg, k.Public(), VerifyOptions{Tail: c.tail})
		p := rep.Problem
		if c.line == 0 {
			if p != nil {
				t.Errorf("%s: %v", c.name, p)
			}
			continue
		}
		if p == nil || p.File != c.file || p.Line != c.line || p.Kind != c.kind || !strings.Contains(p.Msg, c.msg) {
			t.Errorf("%s: got %+v, want %s:%d %s %q", c.name, p, c.file, c.line, c.kind, c.msg)
		}
	}
}

func TestVerifyCheckpoints(t *testing.T) {
	k := testKey(t, 1)
	all := agentLines(20)
	records := text(all)
	led := seal(t, k, records, 8) // checkpoints on ledger lines 10, 19 and 24
	ls := lines(led)
	join := func(ls []string) []byte { return []byte(strings.Join(ls, "\n") + "\n") }
	resign := func(line int, change func(*Checkpoint)) []byte {
		c, err := ParseCheckpoint([]byte(ls[line-1]))
		if err != nil {
			t.Fatal(err)
		}
		change(c)
		c.Sign(k)
		out := append([]string(nil), ls...)
		out[line-1] = string(c.AppendJSON(nil))
		return join(out)
	}
	leaf12 := LeafHash([]byte(all[11])).String()
	changed := append([]string(nil), all...)
	changed[11] = strings.Replace(changed[11], "h12.example", "h13.example", 1)
	bothChanged := append([]string(nil), ls...)
	bothChanged[13] = strings.Replace(ls[13], leaf12, LeafHash([]byte(changed[11])).String(), 1)
	forged := append([]string(nil), ls...)
	forged[18] = forge(t, ls[18])
	hashChanged := append([]string(nil), ls...)
	hashChanged[13] = strings.Replace(ls[13], leaf12, LeafHash(nil).String(), 1)

	for _, c := range []struct {
		name          string
		records, ledg []byte
		pub           *PublicKey
		line          int
		kind, msg     string
		checked       int
	}{
		{"another key", records, led, testKey(t, 2).Public(), 10, "key", "checkpoint 1: signed by key " + k.ID + ", not by", 0},
		{"a forged checkpoint", records, join(forged), k.Public(), 19, "signature", "checkpoint 2: the signature doesn't match key " + k.ID, 1},
		{"spliced", records, resign(19, func(c *Checkpoint) { c.Prev = LeafHash(nil) }), k.Public(), 19, "spliced", "checkpoint 2 doesn't follow checkpoint 1", 1},
		{"a sealed hash changed", records, join(hashChanged), k.Public(), 14, "ledger", "the hash sealed for record 12 was changed: the record itself still matches checkpoint 2", 1},
		{"record and hash changed", text(changed), join(bothChanged), k.Public(), 19, "changed", "checkpoint 2 doesn't match records 9 to 16: one of them was changed, and its hash in the ledger with it", 1},
		{"record and hash changed, records cut", text(changed[:12]), join(bothChanged), k.Public(), 19, "changed", "checkpoint 2 doesn't match records 9 to 16", 1},
		{"a checkpoint re-signed over other hashes", text(changed), resign(19, func(c *Checkpoint) { c.Root[0] ^= 1 }), k.Public(), 19, "changed", "", 1},
	} {
		rep := check(t, c.records, c.ledg, c.pub, VerifyOptions{})
		p := rep.Problem
		if p == nil || p.File != "test.jsonl.ledger" || p.Line != c.line || p.Kind != c.kind || !strings.Contains(p.Msg, c.msg) || rep.Checked != c.checked {
			t.Errorf("%s: got %+v (%d good checkpoints), want line %d %s %q", c.name, p, rep.Checked, c.line, c.kind, c.msg)
		}
	}

	// A record changed before a damaged ledger line is named first.
	damaged := append([]string(nil), ls...)
	damaged[20] = "garbage"
	early := append([]string(nil), all...)
	early[2] += " "
	if p := check(t, text(early), join(damaged), k.Public(), VerifyOptions{}).Problem; p == nil || p.File != "test.jsonl" || p.Line != 3 {
		t.Errorf("a changed record and a damaged ledger: %+v", p)
	}
	if p := check(t, records, join(damaged), k.Public(), VerifyOptions{}).Problem; p == nil || p.File != "test.jsonl.ledger" || p.Line != 21 {
		t.Errorf("a damaged ledger: %+v", p)
	}
	// So is a record changed under a good checkpoint, before a forged one.
	if p := check(t, text(early), join(forged), k.Public(), VerifyOptions{}).Problem; p == nil || p.File != "test.jsonl" || p.Line != 3 || p.Kind != "changed" {
		t.Errorf("a changed record and a forged checkpoint: %+v", p)
	}
	if p := check(t, records, join(forged), k.Public(), VerifyOptions{}).Problem; p == nil || p.Line != 19 || p.Kind != "signature" {
		t.Errorf("a forged checkpoint: %+v", p)
	}
}

// forge changes a checkpoint's root without signing it again.
func forge(t *testing.T, line string) string {
	c, err := ParseCheckpoint([]byte(line))
	if err != nil {
		t.Fatal(err)
	}
	c.Root[3] ^= 0x10
	return string(c.AppendJSON(nil))
}

func TestVerifyWitness(t *testing.T) {
	k := testKey(t, 1)
	pub := k.Public()
	all := agentLines(20)
	led := seal(t, k, text(all), 8)
	ls := lines(led)
	witness := func(src string) []Witness {
		w, err := ReadWitness(strings.NewReader(src), "w.log", pub)
		if err != nil {
			t.Fatal(err)
		}
		return w
	}
	last := "Oct  5 10:00:03 gw ledger: " + ls[23] + "\r\n"
	if rep := check(t, text(all), led, pub, VerifyOptions{Witness: witness("starting\n" + ls[9] + "\n" + last)}); rep.Problem != nil {
		t.Fatalf("a good witness: %v", rep.Problem)
	}
	// Both files cut back to checkpoint 2: only a witness tells.
	cutLed := []byte(strings.Join(ls[:19], "\n") + "\n")
	if rep := check(t, text(all[:16]), cutLed, pub, VerifyOptions{}); rep.Problem != nil {
		t.Fatalf("cut back, no witness: %v", rep.Problem)
	}
	p := check(t, text(all[:16]), cutLed, pub, VerifyOptions{Witness: witness(last)}).Problem
	if p == nil || p.File != "test.jsonl" || p.Line != 17 || p.Kind != "cut" ||
		!strings.Contains(p.Msg, "the end was cut off: the ledger ends at checkpoint 2, but checkpoint 3 in w.log line 1 covers 20 records; it was signed 2026-10-05 10:00:") {
		t.Fatalf("cut back, with a witness: %+v", p)
	}
	headerOnly := []byte(ls[0] + "\n")
	if p := check(t, nil, headerOnly, pub, VerifyOptions{Witness: witness(last)}).Problem; p == nil || p.Line != 1 || !strings.Contains(p.Msg, "the ledger has no checkpoint, but checkpoint 3") {
		t.Fatalf("all cut, with a witness: %+v", p)
	}
	// Signed again with other checkpoints: the witness's checkpoint 1 differs.
	again := seal(t, k, text(all), 5)
	if p := check(t, text(all), again, pub, VerifyOptions{Witness: witness(ls[9])}).Problem; p == nil || p.File != "test.jsonl.ledger" || p.Line != 7 || p.Kind != "rewritten" ||
		!strings.Contains(p.Msg, "checkpoint 1 differs from the copy in w.log line 1: the ledger was signed again from there") {
		t.Fatalf("signed again: %+v", p)
	}
	for src, want := range map[string]string{
		"nothing here\n":                      "w.log: no checkpoint in it",
		"x " + forge(t, ls[9]) + "\n":         "w.log:1: the signature doesn't match",
		"\n" + ls[9][:40] + "\n":              "w.log:2: not a checkpoint",
		strings.Repeat(`{"cp":`, 2000) + "\n": "w.log: a line longer than 4096 bytes",
	} {
		if _, err := ReadWitness(strings.NewReader(src), "w.log", pub); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%.30q: %v, want %q", src, err, want)
		}
	}
	if _, err := ReadWitness(strings.NewReader(ls[9]), "w.log", testKey(t, 2).Public()); err == nil || !strings.Contains(err.Error(), "w.log:1: signed by key") {
		t.Errorf("a witness signed by another key: %v", err)
	}
}

func TestProblemText(t *testing.T) {
	p := &Problem{File: "trace.jsonl", Line: 25, Kind: "changed", Msg: "it was changed"}
	if p.Error() != "trace.jsonl:25: it was changed" {
		t.Error(p.Error())
	}
}
