// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"vpnw.com/vpnw/internal/config"
)

func readLedger(t *testing.T, b []byte) *Ledger {
	t.Helper()
	led, err := ReadLedger(bytes.NewReader(b), "test.jsonl.ledger")
	if err != nil {
		t.Fatal(err)
	}
	return led
}

// Every line of logs of 1 to 37 records has a proof that checks, with a
// path as long as the tree is deep.
func TestProveEveryLine(t *testing.T) {
	k := testKey(t, 1)
	all := agentLines(37)
	for _, n := range []int{1, 2, 3, 8, 9, 37} {
		led := readLedger(t, seal(t, k, text(all[:n]), 8))
		depth := 0
		for 1<<depth < n {
			depth++
		}
		for line := 1; line <= n; line++ {
			p, err := Prove(led, "test.jsonl", line, []byte(all[line-1]))
			if err != nil {
				t.Fatalf("%d of %d: %v", line, n, err)
			}
			if len(p.Path) > depth || (line == 1 && len(p.Path) != depth) {
				t.Fatalf("%d of %d: a path of %d hashes", line, n, len(p.Path))
			}
			q, err := ParseProof(p.JSON())
			if err != nil {
				t.Fatalf("%d of %d: %v\n%s", line, n, err, p.JSON())
			}
			if err := q.Check(k.Public()); err != nil {
				t.Fatalf("%d of %d: %v\n%s", line, n, err, p.JSON())
			}
		}
	}
}

func TestProofFile(t *testing.T) {
	k := testKey(t, 1)
	all := agentLines(20)
	all[6] = `{"note":"<b>&é</b>"}`
	led := readLedger(t, seal(t, k, text(all), 8))
	p, err := Prove(led, "test.jsonl", 7, []byte(all[6]))
	if err != nil {
		t.Fatal(err)
	}
	js := string(p.JSON())
	if !strings.HasPrefix(js, "{\n  \"vpnw-ledger-proof\": 1,\n  \"line\": 7,\n  \"record\": \"{\\\"note\\\":") ||
		!strings.Contains(js, "\n  \"path\": [\n    \"") || !strings.Contains(js, "\n  \"checkpoint\": "+string(led.Checkpoints[2].AppendJSON(nil))+"\n}\n") {
		t.Fatalf("proof:\n%s", js)
	}
	// Any layout of the JSON works.
	var v any
	json.Unmarshal(p.JSON(), &v)
	other, _ := json.MarshalIndent(v, "", "\t")
	q, err := ParseProof(other)
	if err != nil || q.Check(k.Public()) != nil || string(q.Record) != all[6] {
		t.Fatalf("laid out again: %v\n%s", err, other)
	}
}

func TestProofTampered(t *testing.T) {
	k := testKey(t, 1)
	all := agentLines(20)
	led := readLedger(t, seal(t, k, text(all), 8))
	good, err := Prove(led, "test.jsonl", 13, []byte(all[12]))
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		change func(p *Proof)
		want   string
	}{
		"the record":      {func(p *Proof) { p.Record = []byte(all[13]) }, "the record doesn't match the proof's hash: it was changed"},
		"record and leaf": {func(p *Proof) { p.Record = []byte(all[13]); p.Leaf = LeafHash(p.Record) }, "the path doesn't lead to the root signed in checkpoint 3: this record isn't on line 13"},
		"a path hash":     {func(p *Proof) { p.Path[1][0] ^= 1 }, "the path doesn't lead to the root"},
		"the line":        {func(p *Proof) { p.Line = 14 }, "the path doesn't lead to the root"},
		"line 0":          {func(p *Proof) { p.Line = 0 }, "line 0 is outside checkpoint 3, which covers lines 1 to 20"},
		"a short path":    {func(p *Proof) { p.Path = p.Path[:2] }, "the path is too short"},
		"the checkpoint":  {func(p *Proof) { p.Checkpoint.Size = 19 }, "checkpoint 3: the signature doesn't match key " + k.ID},
		"another key":     {func(p *Proof) { p.Checkpoint.Sign(testKey(t, 2)) }, "checkpoint 3: signed by key"},
	} {
		p, _ := ParseProof(good.JSON())
		c.change(p)
		if err := p.Check(k.Public()); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s changed: %v, want %q", name, err, c.want)
		}
	}
}

func TestProveErrors(t *testing.T) {
	k := testKey(t, 1)
	all := agentLines(20)
	ledText := seal(t, k, text(all), 8)
	led := readLedger(t, ledText)
	var ce *config.Error
	for _, n := range []int{0, 21} {
		if _, err := Prove(led, "test.jsonl", n, []byte(all[0])); !errors.As(err, &ce) || !strings.Contains(err.Error(), "no checkpoint covers this line: the last one covers lines 1 to 20") {
			t.Errorf("line %d: %v", n, err)
		}
	}
	var p *Problem
	if _, err := Prove(led, "test.jsonl", 3, []byte(all[3])); !errors.As(err, &p) || p.Line != 3 || !strings.Contains(p.Msg, "there is no proof for it") {
		t.Errorf("a changed record: %v", err)
	}
	ls := lines(ledText)
	damaged := readLedger(t, []byte(strings.Join(ls[:20], "\n")+"\nbad\n"))
	if _, err := Prove(damaged, "test.jsonl", 3, []byte(all[2])); !errors.As(err, &p) || p.Line != 21 {
		t.Errorf("a damaged ledger: %v", err)
	}
	if _, err := Prove(readLedger(t, []byte(ls[0]+"\n")), "test.jsonl", 1, []byte(all[0])); !errors.As(err, &ce) || !strings.Contains(err.Error(), "no checkpoint yet") {
		t.Errorf("no checkpoint: %v", err)
	}
	// A ledger whose hashes don't give its checkpoint's root.
	hashed := append([]string(nil), ls...)
	hashed[2] = strings.Replace(ls[2], LeafHash([]byte(all[1])).String(), LeafHash(nil).String(), 1)
	if _, err := Prove(readLedger(t, []byte(strings.Join(hashed, "\n")+"\n")), "test.jsonl", 20, []byte(all[19])); !errors.As(err, &p) || p.Line != 24 || !strings.Contains(p.Msg, "run verify") {
		t.Errorf("hashes that don't match: %v", err)
	}
}

func TestParseProofErrors(t *testing.T) {
	k := testKey(t, 1)
	all := agentLines(9)
	led := readLedger(t, seal(t, k, text(all), 8))
	p, _ := Prove(led, "test.jsonl", 2, []byte(all[1]))
	good := string(p.JSON())
	for in, want := range map[string]string{
		"":          "not a vpnw-ledger proof",
		"[]":        "not a vpnw-ledger proof",
		good + "{}": "something follows it",
		strings.Replace(good, `"line"`, `"lime"`, 1):                                 "unknown field",
		strings.Replace(good, `"vpnw-ledger-proof": 1`, `"vpnw-ledger-proof": 2`, 1): "want \"vpnw-ledger-proof\": 1",
		strings.Replace(good, `"record": `, `"recorded": 0, "x": `, 1):               "unknown field",
		strings.Replace(good, p.Leaf.String(), "12", 1):                              "leaf: a hash is 64",
		strings.Replace(good, p.Path[0].String(), "zz", 1):                           "path[0]: a hash is 64",
		strings.Replace(good, `"cp":`, `"cq":`, 1):                                   "checkpoint: not a checkpoint: json: unknown field",
		strings.Replace(good, `"checkpoint": {`, `"checkpoint": [{`, 1):              "not a vpnw-ledger proof",
	} {
		if _, err := ParseProof([]byte(in)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%.60q: %v, want %q", in, err, want)
		}
	}
	noRecord := strings.Replace(good, good[strings.Index(good, `  "record"`):strings.Index(good, `  "leaf"`)], "", 1)
	if _, err := ParseProof([]byte(noRecord)); err == nil || !strings.Contains(err.Error(), "the proof holds no record") {
		t.Errorf("no record: %v", err)
	}
	long := strings.Replace(good, `"path": [`, `"path": [`+strings.Repeat(`"`+p.Leaf.String()+`",`, MaxPath), 1)
	if _, err := ParseProof([]byte(long)); err == nil || !strings.Contains(err.Error(), "no log is that big") {
		t.Errorf("a long path: %v", err)
	}
}
