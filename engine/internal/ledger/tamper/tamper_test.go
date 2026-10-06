// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package tamper

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"vpnw.com/vpnw/internal/ledger"
)

// DemoTrace is the Agent's recorded run that the demo seals: the coding
// agent that sent a deploy token to evil.example. Line 25 is its
// connection.open to evil.example.
const DemoTrace = "../../../../recordings/1-trace-1.jsonl"

func key(t *testing.T, b byte) *ledger.PrivateKey {
	t.Helper()
	k, err := ledger.NewKey(bytes.NewReader(bytes.Repeat([]byte{b}, 32)))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func sealFiles(t *testing.T, k *ledger.PrivateKey, records []byte, every int) Files {
	t.Helper()
	var led bytes.Buffer
	now := time.Date(2026, 10, 5, 10, 0, 0, 0, time.UTC)
	s, err := ledger.NewSealer(&led, k, "trace.jsonl", ledger.Options{Every: every, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.SealAll(bytes.NewReader(records), "trace.jsonl", 0); err != nil {
		t.Fatal(err)
	}
	return Files{Split(records), Split(led.Bytes())}
}

type row struct {
	name string
	file string
	line int
	kind string
	said string
}

func runMatrix(t *testing.T, f Files, target int, want []row) {
	t.Helper()
	k, other := key(t, 1), key(t, 2)
	cases, err := Matrix(f, target)
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) != len(want) {
		t.Fatalf("%d cases, want %d", len(cases), len(want))
	}
	for i, c := range cases {
		w := want[i]
		res, err := Run(c, f, k.Public(), other.Public())
		if err != nil {
			t.Fatal(err)
		}
		p := res.Problem
		if c.Name != w.name || c.File != w.file || c.Line != w.line || c.Kind != w.kind {
			t.Errorf("case %d is %q %s:%d %s, want %q %s:%d %s", i+1, c.Name, c.File, c.Line, c.Kind, w.name, w.file, w.line, w.kind)
		}
		if !res.Caught || p == nil || !strings.Contains(p.Msg, w.said) {
			t.Errorf("%s: verify said %+v, want %s:%d %s %q", c.Name, p, w.file, w.line, w.kind, w.said)
		}
		t.Logf("%-58s %s", c.Name, p)
	}
}

// TestDemoMatrix is the tamper matrix of the demo and of tamper.txt: the
// Agent's recorded trace sealed with a checkpoint every 8 records, changed
// around line 25, the connection to evil.example. Checkpoints sit on ledger
// lines 10, 19, 28 and 33 and cover 8, 16, 24 and 28 records.
func TestDemoMatrix(t *testing.T) {
	records, err := os.ReadFile(DemoTrace)
	if err != nil {
		t.Fatal(err)
	}
	f := sealFiles(t, key(t, 1), records, 8)
	if len(f.Records) != 28 || len(f.Ledger) != 33 {
		t.Fatalf("%d records, %d ledger lines", len(f.Records), len(f.Ledger))
	}
	if !strings.Contains(string(f.Records[24]), `"type":"connection.open"`) || !strings.Contains(string(f.Records[24]), "evil.example") {
		t.Fatalf("line 25 is %s", f.Records[24])
	}
	runMatrix(t, f, 25, []row{
		{"one byte edited", "records", 25, "changed", "the record doesn't match its sealed hash: it was changed"},
		{"a line deleted", "records", 25, "missing", "a record is missing here: the one sealed as line 25 was deleted"},
		{"a line inserted", "records", 25, "inserted", "this line was never sealed: it was inserted"},
		{"two lines swapped", "records", 25, "swapped", "lines 25 and 26 were swapped"},
		{"the end cut off", "records", 25, "cut", "the file ends after line 24, but checkpoint 4 covers 28 records: the end was cut off"},
		{"an old checkpoint replayed", "ledger", 33, "replayed", "checkpoint 1 again, where checkpoint 4 should be"},
		{"the wrong key", "ledger", 10, "key", "checkpoint 1: signed by key k-34750f98, not by k-6a3803d5, the key given"},
		{"a record and its sealed hash changed together", "ledger", 33, "changed", "checkpoint 4 doesn't match records 25 to 28"},
		{"a sealed hash changed", "ledger", 29, "ledger", "the hash sealed for record 25 was changed: the record itself still matches checkpoint 4"},
		{"a checkpoint's time moved back", "ledger", 33, "signature", "checkpoint 4: the signature doesn't match key k-34750f98"},
		{"a line added after the last checkpoint", "records", 29, "unsealed", "this line was never sealed: it came after the last checkpoint"},
		{"both files cut back to a checkpoint, checked with a witness", "records", 25, "cut", "the ledger ends at checkpoint 3, but checkpoint 4 in witness line 1 covers 28 records"},
	})
	// Without the witness, both files cut back to checkpoint 3 look whole:
	// that is what the witness is for.
	cases, _ := Matrix(f, 25)
	c := cases[len(cases)-1]
	c.Witness = false
	if res, _ := Run(c, f, key(t, 1).Public(), nil); res.Problem != nil {
		t.Errorf("cut back to a checkpoint, without a witness: %v", res.Problem)
	}
	// And the untouched log is clean.
	if res, _ := Run(Case{Files: f}, f, key(t, 1).Public(), nil); res.Problem != nil {
		t.Errorf("the untouched log: %v", res.Problem)
	}
}

// The same matrix on a larger log: 100 records, a checkpoint every 10
// (ledger line 1+11k for checkpoint k), changed around line 57.
func TestLargerMatrix(t *testing.T) {
	var b strings.Builder
	for i := 1; i <= 100; i++ {
		fmt.Fprintf(&b, `{"t":"2026-10-05T10:%02d:00Z","proto":"tcp","src":"10.8.0.%d","dst":"10.0.1.20","port":443}`+"\n", i%60, i)
	}
	f := sealFiles(t, key(t, 1), []byte(b.String()), 10)
	runMatrix(t, f, 57, []row{
		{"one byte edited", "records", 57, "changed", "it was changed"},
		{"a line deleted", "records", 57, "missing", "the one sealed as line 57 was deleted"},
		{"a line inserted", "records", 57, "inserted", "it was inserted"},
		{"two lines swapped", "records", 57, "swapped", "lines 57 and 58 were swapped"},
		{"the end cut off", "records", 57, "cut", "the file ends after line 56, but checkpoint 10 covers 100 records"},
		{"an old checkpoint replayed", "ledger", 111, "replayed", "checkpoint 1 again, where checkpoint 10 should be"},
		{"the wrong key", "ledger", 12, "key", "checkpoint 1: signed by key"},
		{"a record and its sealed hash changed together", "ledger", 67, "changed", "checkpoint 6 doesn't match records 51 to 60"},
		{"a sealed hash changed", "ledger", 63, "ledger", "the hash sealed for record 57 was changed"},
		{"a checkpoint's time moved back", "ledger", 67, "signature", "checkpoint 6: the signature doesn't match"},
		{"a line added after the last checkpoint", "records", 101, "unsealed", "this line was never sealed"},
		{"both files cut back to a checkpoint, checked with a witness", "records", 51, "cut", "the ledger ends at checkpoint 5, but checkpoint 10"},
	})
}

func TestMatrixNeedsRoom(t *testing.T) {
	f := sealFiles(t, key(t, 1), []byte("{}\n[]\n1\n2\n"), 2)
	for _, target := range []int{0, 1, 2, 4, 5} {
		if _, err := Matrix(f, target); err == nil {
			t.Errorf("target %d accepted", target)
		}
	}
	if _, err := Matrix(Files{Ledger: [][]byte{[]byte("x")}}, 1); err == nil {
		t.Error("not a ledger")
	}
	if Split(nil) != nil || string(Join(Split([]byte("a\nb")))) != "a\nb\n" || string(EditByte([]byte(`{"a":"b"}`))) != `{"a":"b"} ` {
		t.Error("Split, Join or EditByte")
	}
	if _, err := Run(Case{Files: Files{Ledger: [][]byte{[]byte("x")}}}, f, nil, nil); err == nil {
		t.Error("Run on no ledger")
	}
	if _, err := Run(Case{Witness: true, Files: f}, Files{Ledger: [][]byte{[]byte("x")}}, key(t, 1).Public(), nil); err == nil {
		t.Error("Run with no original ledger")
	}
}
