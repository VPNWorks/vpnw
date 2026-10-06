// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"strings"
	"testing"
	"time"
)

func testCheckpoint(t *testing.T, k *PrivateKey) *Checkpoint {
	t.Helper()
	leaves := vecLeaves()
	var tree Tree
	for _, h := range leaves {
		tree.Add(h)
	}
	c := &Checkpoint{Log: "trace.jsonl", Seq: 3, Size: tree.Size(), Root: tree.Root(), Chain: tree.Chain(),
		Prev: LeafHash([]byte("before")), Time: t0}
	c.Sign(k)
	return c
}

func TestCheckpointText(t *testing.T) {
	k := testKey(t, 1)
	c := testCheckpoint(t, k)
	want := "vpnw-ledger checkpoint v1\nlog trace.jsonl\ncp 3\nsize 8\nroot " + vecRoots[8] + "\nchain " + c.Chain.String() +
		"\nprev " + c.Prev.String() + "\ntime 2026-10-05T10:00:00Z\nkey " + k.ID + "\n"
	if string(c.Message()) != want {
		t.Fatalf("message:\n%s\nwant:\n%s", c.Message(), want)
	}
	line := c.AppendJSON(nil)
	if !strings.HasPrefix(string(line), `{"cp":3,"size":8,"root":"`+vecRoots[8]+`","chain":"`) ||
		!strings.Contains(string(line), `"time":"2026-10-05T10:00:00Z","key":"`+k.ID+`","log":"trace.jsonl","sig":"`) {
		t.Fatalf("line: %s", line)
	}
	got, err := ParseCheckpoint(line)
	if err != nil || string(got.Message()) != want || string(got.Sig) != string(c.Sig) {
		t.Fatalf("round trip: %v", err)
	}
	if err := got.Check(k.Public()); err != nil {
		t.Fatal(err)
	}
	if c.When() != "2026-10-05 10:00:00 UTC" {
		t.Error(c.When())
	}
}

// Every field is signed: changing any one breaks the signature, and another
// key never passes.
func TestCheckpointSigned(t *testing.T) {
	k := testKey(t, 1)
	pub := k.Public()
	for name, change := range map[string]func(*Checkpoint){
		"log":   func(c *Checkpoint) { c.Log = "other.jsonl" },
		"cp":    func(c *Checkpoint) { c.Seq++ },
		"size":  func(c *Checkpoint) { c.Size-- },
		"root":  func(c *Checkpoint) { c.Root[0] ^= 1 },
		"chain": func(c *Checkpoint) { c.Chain[31] ^= 1 },
		"prev":  func(c *Checkpoint) { c.Prev = Hash{} },
		"time":  func(c *Checkpoint) { c.Time = c.Time.Add(-time.Hour) },
		"sig":   func(c *Checkpoint) { c.Sig[5] ^= 1 },
	} {
		c := testCheckpoint(t, k)
		change(c)
		if err := c.Check(pub); err == nil || !strings.Contains(err.Error(), "the signature doesn't match key "+k.ID) {
			t.Errorf("%s changed: %v", name, err)
		}
	}
	other := testKey(t, 2)
	c := testCheckpoint(t, other)
	if err := c.Check(pub); err == nil || !strings.Contains(err.Error(), "signed by key "+other.ID+", not by "+k.ID) {
		t.Errorf("another key: %v", err)
	}
	c.Key = k.ID // the right name on the wrong signature
	if err := c.Check(pub); err == nil || !strings.Contains(err.Error(), "the signature doesn't match") {
		t.Errorf("another key's signature: %v", err)
	}
}

func TestParseCheckpointErrors(t *testing.T) {
	line := string(testCheckpoint(t, testKey(t, 1)).AppendJSON(nil))
	field := func(name string) string { // the field's whole "name":value text
		i := strings.Index(line, `"`+name+`":`)
		j := strings.IndexAny(line[i+len(name)+3:], ",}")
		return line[i : i+len(name)+3+j]
	}
	set := func(name, val string) string { return strings.Replace(line, field(name), `"`+name+`":`+val, 1) }
	for in, want := range map[string]string{
		`[]`:                                    "not a checkpoint",
		`{"cp":"1"}`:                            "not a checkpoint",
		set("cp", "0"):                          "cp must be 1 or more",
		set("size", "0"):                        "size must be 1 or more",
		set("log", `""`):                        "log: want 1 to 128",
		set("log", `"a\tb"`):                    "log: want 1 to 128",
		set("key", `"k-1234"`):                  "key: want k- and 8 hex digits",
		set("root", `"abc"`):                    "root: a hash is 64 lowercase hex digits",
		set("chain", `"`+vecRoots[1][:63]+`G"`): "chain:",
		set("prev", `"`+strings.ToUpper(vecRoots[1])+`"`): "prev:",
		set("time", `"yesterday"`):                        "time: want a time",
		set("sig", `"AAAA"`):                              "sig: want 88 characters",
		set("cp", "3.0"):                                  "not a checkpoint",
		set("time", `"2026-10-05T12:00:00+02:00"`):        "not exactly as seal writes",
		strings.Replace(line, `,"size"`, ` ,"size"`, 1):   "not exactly as seal writes",
		strings.TrimSuffix(line, "}") + `,"extra":1}`:     "unknown field",
	} {
		_, err := ParseCheckpoint([]byte(in))
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s\n  error %v, want %q", in, err, want)
		}
	}
	for _, s := range []string{"trace.jsonl", "a", strings.Repeat("x", 128), "gateway 2026-10-05 / flows"} {
		if !ValidLogName(s) {
			t.Errorf("%q refused", s)
		}
	}
	for _, s := range []string{"", strings.Repeat("x", 129), `a"b`, `a\b`, "é", "a\nb"} {
		if ValidLogName(s) {
			t.Errorf("%q accepted", s)
		}
	}
}
