// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"

	"vpnw.com/vpnw/internal/config"
)

func TestEntryLines(t *testing.T) {
	h := LeafHash([]byte("x"))
	for _, n := range []int{1, 9, 10, 123456789, 999999999999999} {
		line := appendEntry(nil, n, h)
		got, leaf, err := parseEntry(line)
		if err != nil || got != n || leaf != h {
			t.Errorf("%s: %d %v", line, got, err)
		}
	}
	good := string(appendEntry(nil, 14, h))
	for _, bad := range []string{
		strings.Replace(good, "14", "014", 1), strings.Replace(good, "14", "0", 1), strings.Replace(good, "14", "1x", 1),
		strings.Replace(good, "14", "", 1), strings.Replace(good, "14", "1000000000000000", 1),
		strings.Replace(good, `"leaf"`, `"lead"`, 1), strings.Replace(good, h.String(), strings.ToUpper(h.String()), 1),
		strings.Replace(good, h.String(), h.String()[1:], 1), good + " ", " " + good, `{"n":14}`,
	} {
		if _, _, err := parseEntry([]byte(bad)); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
	if log, err := parseHeader(appendHeader(nil, "trace.jsonl")); err != nil || log != "trace.jsonl" {
		t.Fatal(log, err)
	}
	for in, want := range map[string]string{
		`{"vpnw-ledger":2,"log":"a"}`:    "version 2",
		`{"vpnw-ledger":1,"log":""}`:     "isn't as seal writes it",
		`{"vpnw-ledger":1, "log":"a"}`:   "isn't as seal writes it",
		`{"v":1,"type":"run.start"}`:     "isn't a vpnw-ledger header",
		`not json`:                       "isn't a vpnw-ledger header",
		`{"vpnw-ledger":1,"log":"a\tb"}`: "isn't as seal writes it",
	} {
		if _, err := parseHeader([]byte(in)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: %v, want %q", in, err, want)
		}
	}
}

func TestReadLedger(t *testing.T) {
	k := testKey(t, 1)
	good := seal(t, k, text(agentLines(20)), 8) // checkpoints after 8, 16 and 20 records
	led, err := ReadLedger(bytes.NewReader(good), "l")
	if err != nil || led.Problem != nil || len(led.Leaves) != 20 || len(led.Checkpoints) != 3 || led.Log != "test.jsonl" {
		t.Fatalf("%v %+v", err, led)
	}
	if want := []int{10, 19, 24}; led.CPLines[0] != want[0] || led.CPLines[1] != want[1] || led.CPLines[2] != want[2] {
		t.Fatalf("checkpoint lines %v", led.CPLines)
	}
	for n, want := range map[int]int{1: 2, 8: 9, 9: 11, 16: 18, 17: 20, 20: 23} {
		if got := led.EntryLine(n); got != want {
			t.Errorf("record %d is on ledger line %d, not %d", n, got, want)
		}
	}
	ls := lines(good)
	edit := func(f func(ls []string) []string) []byte {
		c := append([]string(nil), ls...)
		return []byte(strings.Join(f(c), "\n") + "\n")
	}
	cp1, cp2 := ls[9], ls[18]
	cases := []struct {
		in   []byte
		line int
		kind string
		msg  string
	}{
		{edit(func(l []string) []string { return append(l[:4], l[5:]...) }), 5, "ledger", "this is the hash of record 5, but record 4 comes next"},
		{edit(func(l []string) []string { l[4] = l[3]; return l }), 5, "ledger", "this is the hash of record 3 again, after record 3"},
		{edit(func(l []string) []string { l[4] = l[4] + " "; return l }), 5, "ledger", "not a record line as seal writes it"},
		{edit(func(l []string) []string { l[4] = `{"type":"dns.query"}`; return l }), 5, "ledger", "not a ledger line"},
		{edit(func(l []string) []string { l[18] = cp1; return l }), 19, "replayed", "checkpoint 1 again, where checkpoint 2 should be"},
		{edit(func(l []string) []string { return append(l[:18], l[19:]...) }), 23, "ledger", "checkpoint 3, but checkpoint 2 comes next"},
		{edit(func(l []string) []string { l[17], l[18] = l[18], l[17]; return l }), 18, "ledger", "checkpoint 2 covers 16 records, but it comes after record 15"},
		{edit(func(l []string) []string {
			cp := l[18]
			l = append(l[:18], l[19:]...)
			return append(l[:20], append([]string{cp}, l[20:]...)...)
		}), 21, "ledger", "checkpoint 2 covers 16 records, but it comes after record 18: it was moved"},
		{edit(func(l []string) []string { return append(l[:19], append([]string{cp2}, l[19:]...)...) }), 20, "replayed", "checkpoint 2 again, where checkpoint 3 should be"},
		{edit(func(l []string) []string { l[18] = strings.Replace(cp2, `"cp":2`, `"cp":3`, 1); return l }), 19, "ledger", "checkpoint 3, but checkpoint 2 comes next"},
		{edit(func(l []string) []string { l[18] = strings.Replace(l[18], "test.jsonl", "other.jsonl", 1); return l }), 19, "ledger", `checkpoint 2 is for log "other.jsonl", but this ledger is for "test.jsonl"`},
		{edit(func(l []string) []string { l[18] = l[18][:100]; return l }), 19, "ledger", "not a checkpoint"},
		{edit(func(l []string) []string { l[5] = strings.Repeat("x", 2000); return l }), 6, "ledger", "longer than any line seal writes"},
		{good[:len(good)-1], 24, "cut", "the last line has no newline"},
	}
	for _, c := range cases {
		led, err := ReadLedger(bytes.NewReader(c.in), "l")
		if err != nil || led.Problem == nil || led.Problem.Line != c.line || led.Problem.Kind != c.kind || !strings.Contains(led.Problem.Msg, c.msg) {
			t.Errorf("want line %d %s %q, got %v %+v", c.line, c.kind, c.msg, err, led.Problem)
		}
	}
	// Two checkpoints with no record between them.
	twice := edit(func(l []string) []string {
		c, _ := ParseCheckpoint([]byte(l[18]))
		c.Seq = 3
		c.Sign(k)
		return append(l[:19], append([]string{string(c.AppendJSON(nil))}, l[19:]...)...)
	})
	if led, _ := ReadLedger(bytes.NewReader(twice), "l"); led.Problem == nil || !strings.Contains(led.Problem.Msg, "checkpoint 3 adds no records to checkpoint 2") {
		t.Errorf("two checkpoints in a row: %+v", led.Problem)
	}
	for in, want := range map[string]string{
		"":                                  "l: not a vpnw-ledger file: it is empty",
		"{\"vpnw-ledger\":1,\"log\":\"a\"}": "l:1: not a vpnw-ledger file",
		"{\"v\":1}\n":                       "l:1: not a vpnw-ledger file: its first line isn't a vpnw-ledger header",
		strings.Repeat("y", 70000) + "\n":   "l:1: not a vpnw-ledger file",
	} {
		_, err := ReadLedger(strings.NewReader(in), "l")
		var ce *config.Error
		if !errors.As(err, &ce) || !strings.Contains(err.Error(), want) {
			t.Errorf("%.40q: %v, want %q", in, err, want)
		}
	}
	if _, err := ReadLedger(failReader{}, "l"); err == nil || !strings.Contains(err.Error(), "disk on fire") {
		t.Errorf("read error: %v", err)
	}
	// A header alone is a ledger with nothing sealed yet.
	if led, err := ReadLedger(strings.NewReader("{\"vpnw-ledger\":1,\"log\":\"a\"}\n"), "l"); err != nil || led.Problem != nil || len(led.Leaves) != 0 {
		t.Errorf("header only: %v %+v", err, led)
	}
}

type failReader struct{}

func (failReader) Read([]byte) (int, error) { return 0, errors.New("disk on fire") }

func TestHashRecords(t *testing.T) {
	long := strings.Repeat("z", 200000) // longer than the reader's buffer
	for _, c := range []struct {
		in   string
		want []string
		mark int
		end  int64
	}{
		{"a\nbb\nccc\n", []string{"a", "bb", "ccc"}, 2, 4},
		{"a\nbb\nccc", []string{"a", "bb", "ccc"}, 3, 8},
		{"a\r\n\nb", []string{"a\r", "", "b"}, 1, 2},
		{"", nil, 0, 0},
		{"\n", []string{""}, 1, 0},
		{long + "\nx\n", []string{long, "x"}, 1, 200000},
	} {
		got, end, err := HashRecords(strings.NewReader(c.in), c.mark)
		if err != nil || len(got) != len(c.want) || end != c.end {
			t.Errorf("%.20q: %d hashes, end %d, %v", c.in, len(got), end, err)
			continue
		}
		for i, w := range c.want {
			if got[i] != LeafHash([]byte(w)) {
				t.Errorf("%.20q: hash %d", c.in, i)
			}
		}
	}
	if _, _, err := HashRecords(failReader{}, 0); err == nil {
		t.Error("read error lost")
	}
}

func TestCheckRecord(t *testing.T) {
	for _, ok := range []string{`{"a":1}`, `[1,2]`, `"x"`, `3`, ` {"a":"é"} `, "{}\r"} {
		if err := CheckRecord([]byte(ok)); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for in, want := range map[string]string{
		"":            "an empty line",
		"  ":          "an empty line",
		`{"a":1`:      "not valid JSON: unexpected end",
		`{"a":1}{}`:   "not valid JSON: invalid character '{' after top-level value",
		"\"\xff\"":    "not valid UTF-8",
		`{"a":"x"} #`: "not valid JSON",
	} {
		if err := CheckRecord([]byte(in)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v, want %q", in, err, want)
		}
	}
}

// growing is a records file being written: reads stop at what has been
// written so far.
type growing struct{ data, read []byte }

func (g *growing) Read(p []byte) (int, error) {
	if len(g.data) == len(g.read) {
		return 0, io.EOF
	}
	n := copy(p, g.data[len(g.read):])
	g.read = g.data[:len(g.read)+n]
	return n, nil
}

func TestRecordReader(t *testing.T) {
	g := &growing{}
	rr := newRecordReader(g, "r.jsonl", 0, false)
	if _, err := rr.next(); err != io.EOF {
		t.Fatal(err)
	}
	g.data = append(g.data, "{\"a\":1}\n{\"b\":"...)
	if l, err := rr.next(); err != nil || string(l) != `{"a":1}` || rr.line != 1 {
		t.Fatalf("%q %v", l, err)
	}
	if _, err := rr.next(); err != io.EOF {
		t.Fatalf("a half-written line came back: %v", err)
	}
	g.data = append(g.data, "2}\n"...)
	if l, err := rr.next(); err != nil || string(l) != `{"b":2}` || rr.line != 2 {
		t.Fatalf("the line finished later: %q %v", l, err)
	}
	g.data = append(g.data, "{\"c\":3}"...)
	if _, err := rr.next(); err != io.EOF {
		t.Fatal(err)
	}
	if l := rr.rest(); string(l) != `{"c":3}` || rr.line != 3 || rr.rest() != nil {
		t.Fatalf("rest: %q", l)
	}

	// Carrying on after a sealed line: its newline may come later.
	rr = newRecordReader(strings.NewReader("\n{\"d\":4}\n"), "r.jsonl", 3, true)
	if l, err := rr.next(); err != nil || string(l) != `{"d":4}` || rr.line != 4 {
		t.Fatalf("after a sealed line: %q %v", l, err)
	}
	rr = newRecordReader(strings.NewReader("5}\n"), "r.jsonl", 3, true)
	var p *Problem
	if _, err := rr.next(); !errors.As(err, &p) || p.Line != 3 || !strings.Contains(p.Msg, "grew after it was sealed") {
		t.Fatalf("a sealed line that grew: %v", err)
	}

	big := strings.Repeat("x", MaxLine+1)
	for _, in := range []string{big + "\n", big, strings.Repeat("y", 3*MaxLine)} {
		rr = newRecordReader(strings.NewReader("{}\n"+in), "r.jsonl", 0, false)
		rr.next()
		var ce *config.Error
		if _, err := rr.next(); !errors.As(err, &ce) || ce.Line != 2 || !strings.Contains(ce.Msg, "longer than 65536 bytes") {
			t.Errorf("a long line: %v", err)
		}
	}
	rr = newRecordReader(strings.NewReader(strings.Repeat("x", MaxLine)+"\n"), "r.jsonl", 0, false)
	if l, err := rr.next(); err != nil || len(l) != MaxLine {
		t.Errorf("a line of exactly MaxLine bytes: %d %v", len(l), err)
	}
	rr = newRecordReader(failReader{}, "r.jsonl", 0, false)
	if _, err := rr.next(); err == nil || err == io.EOF {
		t.Error("read error lost")
	}
}
