// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package chain

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

// sample builds a ledger of n events with a checkpoint every `every`
// entries, and the matching trace: the same events, with the checkpoint
// copies Ledger emits.
func sample(t *testing.T, n, every int, lostAt map[int]uint64) (ledger, trace []string) {
	t.Helper()
	w, hd, err := NewWriter("r-abc123")
	if err != nil {
		t.Fatal(err)
	}
	ledger = append(ledger, strings.TrimSuffix(string(hd), "\n"))
	add := func(b []byte) { ledger = append(ledger, strings.TrimSuffix(string(b), "\n")) }
	cps := func(end bool) {
		b, cp := w.Checkpoint()
		add(b)
		f := map[string]any{"cp": cp, "n": w.Entries(), "h": w.Head().String()}
		if end {
			f["end"] = true
		}
		ev, _ := json.Marshal(map[string]any{"v": 1, "type": "plugin.ledger.checkpoint", "run": "r-abc123", "fields": f})
		trace = append(trace, string(ev))
	}
	for i := 1; i <= n; i++ {
		if c, ok := lostAt[i]; ok {
			b, err := w.Lost(c)
			if err != nil {
				t.Fatal(err)
			}
			add(b)
		}
		ev, _ := json.Marshal(map[string]any{"v": 1, "type": "connection.attempt", "run": "r-abc123", "conn": i,
			"fields": map[string]any{"host": fmt.Sprintf("h%d.example", i), "port": 443}})
		b, err := w.Event(ev)
		if err != nil {
			t.Fatal(err)
		}
		add(b)
		trace = append(trace, string(ev))
		if w.SinceCheckpoint() >= uint64(every) && i < n {
			cps(false)
		}
	}
	cps(true)
	add(w.End())
	return ledger, trace
}

type opts struct {
	trace   []string
	partial bool // the last ledger line has no newline
	head    *Hash
}

func verify(ledger []string, o opts) Report {
	v := &Verifier{Head: o.head}
	for i, l := range ledger {
		v.Ledger("run.ledger", i+1, []byte(l), o.partial && i == len(ledger)-1)
	}
	for i, l := range o.trace {
		v.Trace("last.jsonl", i+1, []byte(l))
	}
	return v.Result()
}

func TestIntact(t *testing.T) {
	l, tr := sample(t, 25, 10, nil)
	for _, o := range []opts{{}, {trace: tr}} {
		r := verify(l, o)
		if r.Verdict != Intact || r.Entries != 25 || r.Problem != "" {
			t.Fatalf("got %+v", r)
		}
	}
	// Lines round-trip: what Parse reads, Writer wrote.
	for _, line := range l {
		if _, err := Parse([]byte(line)); err != nil {
			t.Fatalf("%s: %v", line, err)
		}
	}
}

func cp(s []string) []string { return append([]string(nil), s...) }

// Every kind of change is caught, at the line where it was made.
func TestTamperMatrix(t *testing.T) {
	base, trace := sample(t, 25, 10, map[int]uint64{12: 3})
	// Line numbers (1-based): 1 header, 2..11 events 1..10, 12 cp1,
	// 13..23 events 11 and the lost mark etc.
	find := func(l []string, prefix string) int {
		for i, x := range l {
			if strings.HasPrefix(x, prefix) {
				return i
			}
		}
		t.Fatalf("no line %q", prefix)
		return -1
	}
	ev5 := find(base, `{"n":5,`)
	lostI := find(base, `{"n":12,"lost"`)
	cp1 := find(base, `{"cp":1,`)
	endI := len(base) - 1
	rewrite := func(from int) []string {
		// Change an event and write every hash after it again, as someone
		// who knows the format would.
		l := cp(base)
		w, hd, _ := NewWriter("r-abc123")
		out := []string{strings.TrimSuffix(string(hd), "\n")}
		for i := 1; i < len(l); i++ {
			p, err := Parse([]byte(l[i]))
			if err != nil {
				t.Fatal(err)
			}
			var b []byte
			switch p.Kind {
			case KEvent:
				ev := p.Ev
				if i == from {
					ev = bytes.Replace(ev, []byte(`"port":443`), []byte(`"port":444`), 1)
				}
				b, _ = w.Event(ev)
			case KLost:
				b, _ = w.Lost(p.Count)
			case KCheckpoint:
				b, _ = w.Checkpoint()
			case KEnd:
				b = w.End()
			}
			out = append(out, strings.TrimSuffix(string(b), "\n"))
		}
		return out
	}
	cases := []struct {
		name    string
		ledger  []string
		o       opts
		verdict string
		line    int // the line named, 1-based; 0 for none
		want    string
	}{
		{"one byte of an event", func() []string {
			l := cp(base)
			l[ev5] = strings.Replace(l[ev5], "h5.example", "h5.exampl3", 1)
			return l
		}(),
			opts{}, Changed, ev5 + 1, "doesn't match its hash"},
		{"an event's hash", func() []string { l := cp(base); l[ev5] = l[ev5][:len(l[ev5])-3] + "0\"}"; return l }(),
			opts{}, Changed, ev5 + 1, ""},
		{"a line removed", func() []string { l := cp(base); return append(l[:ev5], l[ev5+1:]...) }(),
			opts{}, Changed, ev5 + 1, "entry 5 is missing"},
		{"two lines removed", func() []string { l := cp(base); return append(l[:ev5], l[ev5+2:]...) }(),
			opts{}, Changed, ev5 + 1, "entries 5 to 6 are missing"},
		{"a line copied", func() []string { l := cp(base); return append(l[:ev5+1], append([]string{l[ev5]}, l[ev5+1:]...)...) }(),
			opts{}, Changed, ev5 + 2, "entry 5 again"},
		{"two lines swapped", func() []string { l := cp(base); l[ev5], l[ev5+1] = l[ev5+1], l[ev5]; return l }(),
			opts{}, Changed, ev5 + 1, "swapped"},
		{"the header", func() []string { l := cp(base); l[0] = strings.Replace(l[0], "abc123", "abc124", 1); return l }(),
			opts{}, Changed, 1, "the header was changed"},
		{"a checkpoint", func() []string { l := cp(base); l[cp1] = strings.Replace(l[cp1], `"n":10`, `"n":9`, 1); return l }(),
			opts{}, Changed, cp1 + 1, "checkpoint 1 covers entry 9"},
		{"a checkpoint removed", func() []string { l := cp(base); return append(l[:cp1], l[cp1+1:]...) }(),
			opts{}, Changed, cp1 + 1, "checkpoint 1, after entry 10, is missing before this line"},
		{"the last checkpoint removed", func() []string { l := cp(base); return append(l[:endI-1], l[endI]) }(),
			opts{}, Changed, endI, "counts 3 checkpoints, but there are 2"},
		{"a checkpoint added", func() []string {
			l := cp(base)
			return append(l[:endI], `{"cp":4,"n":26,"h":"`+strings.Repeat("a", 64)+`"}`, l[endI])
		}(), opts{}, Changed, endI + 1, "checkpoint 4 doesn't match its hash"},
		{"the end removed, with the end's copy in the trace", cp(base[:endI]),
			opts{trace: trace}, Changed, 0, "the end was removed"},
		{"the count of lost events", func() []string {
			l := cp(base)
			l[lostI] = strings.Replace(l[lostI], `"lost":3`, `"lost":2`, 1)
			return l
		}(),
			opts{}, Changed, lostI + 1, "count of lost events"},
		{"spaces added", func() []string { l := cp(base); l[ev5] = strings.Replace(l[ev5], `{"n":5,`, `{"n": 5,`, 1); return l }(),
			opts{}, Changed, ev5 + 1, "not a line Ledger writes"},
		{"a line after the end", append(cp(base), base[ev5]),
			opts{}, Changed, len(base) + 1, "after the end line"},
		{"bytes after the end, with no newline", append(cp(base), "GARBAGE"),
			opts{partial: true}, Changed, len(base) + 1, "after the end line"},
		{"the first event's run", func() []string {
			l := cp(base)
			l[1] = strings.Replace(l[1], `"run":"r-abc123"`, `"run":"r-abc124"`, 1)
			return l
		}(),
			opts{}, Changed, 2, "doesn't match its hash"},
		{"the end line", func() []string {
			l := cp(base)
			l[endI] = strings.Replace(l[endI], `"end":26`, `"end":27`, 1)
			return l
		}(),
			opts{}, Changed, endI + 1, "counts 27 entries"},
		{"the end removed, no trace", cp(base[:endI]),
			opts{}, Intact + "?", 0, ""}, // checked below: looks like a run cut short
		{"the end and the last lines removed, with copies", cp(base[:cp1+3]),
			opts{trace: trace}, Changed, 0, "the end was cut off"},
		{"rewritten from line 5 on, with the trace", rewrite(ev5),
			opts{trace: trace}, Changed, ev5 + 1, "differs from the same event in last.jsonl:5"},
		{"rewritten from line 5 on, with the kept head", rewrite(ev5),
			opts{head: func() *Hash { p, _ := Parse([]byte(base[endI])); return &p.H }()}, Changed, 0, "not the one you kept"},
	}
	var md strings.Builder
	md.WriteString("| Change | Verdict | What verify says |\n|---|---|---|\n")
	defer func() {
		if fn := os.Getenv("VPNW_LEDGER_MATRIX_OUT"); fn != "" {
			os.WriteFile(fn, []byte(md.String()), 0o644)
		}
	}()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := verify(c.ledger, c.o)
			fmt.Fprintf(&md, "| %s | %s | %s |\n", c.name, r.Verdict, strings.ReplaceAll(r.Problem, "|", "\\|"))
			if c.verdict == Intact+"?" {
				// Removing just the end line looks like a run cut short;
				// nothing in two files can tell the difference.
				if r.Verdict != CutShort {
					t.Fatalf("verdict %s, want %s: %s", r.Verdict, CutShort, r.Problem)
				}
				return
			}
			if r.Verdict != c.verdict {
				t.Fatalf("verdict %s, want %s: %s", r.Verdict, c.verdict, r.Problem)
			}
			if c.line > 0 && !strings.HasPrefix(r.Problem, fmt.Sprintf("run.ledger:%d: ", c.line)) {
				t.Errorf("problem %q, want it at line %d", r.Problem, c.line)
			}
			if !strings.Contains(r.Problem, c.want) {
				t.Errorf("problem %q, want %q", r.Problem, c.want)
			}
		})
	}
}

// What two files can't show: a ledger rewritten from some line on, with
// nothing kept elsewhere, checks out. The report says so.
func TestRewriteWithoutCopiesIsInvisible(t *testing.T) {
	l, _ := sample(t, 5, 10, nil)
	r := verify(l, opts{})
	if r.Verdict != Intact || !strings.Contains(strings.Join(r.Lines, "\n"), "give the run's trace too") {
		t.Fatalf("%+v", r)
	}
}

// A run killed in the middle leaves a ledger that ends without an end line,
// maybe in the middle of a line. What is there checks out, and the report
// says where it stops.
func TestCutShort(t *testing.T) {
	base, _ := sample(t, 25, 10, nil)
	whole := cp(base[:20])
	r := verify(whole, opts{})
	if r.Verdict != CutShort || r.Entries != 18 || !strings.Contains(r.Problem, "after line 20") {
		t.Fatalf("%+v", r)
	}
	half := cp(base[:21])
	half[20] = half[20][:30]
	r = verify(half, opts{partial: true})
	if r.Verdict != CutShort || r.Entries != 18 || !strings.Contains(r.Problem, "in the middle of line 21") {
		t.Fatalf("%+v", r)
	}
}

func TestLostEventsAreReported(t *testing.T) {
	l, tr := sample(t, 25, 10, map[int]uint64{12: 3})
	r := verify(l, opts{trace: tr})
	if r.Verdict != Intact || r.Lost != 3 || !strings.Contains(strings.Join(r.Lines, "\n"), "3 events never reached Ledger") {
		t.Fatalf("%+v", r)
	}
}

func TestNotALedger(t *testing.T) {
	r := verify([]string{`{"v":1,"type":"run.start"}`}, opts{})
	if r.Verdict != Changed || !strings.Contains(r.Problem, "not a VPN Works ledger") {
		t.Fatalf("%+v", r)
	}
	if r := verify(nil, opts{}); r.Verdict != Changed {
		t.Fatalf("%+v", r)
	}
}

func TestWriterRefuses(t *testing.T) {
	if _, _, err := NewWriter(`r"x`); err == nil {
		t.Error("a run id with a quote was accepted")
	}
	w, _, _ := NewWriter("r-1")
	for _, ev := range []string{"", "[1]", "{\n}", `{"a":`} {
		if _, err := w.Event([]byte(ev)); err == nil {
			t.Errorf("event %q accepted", ev)
		}
	}
	if _, err := w.Lost(0); err == nil {
		t.Error("lost 0 accepted")
	}
	w.End()
	if _, err := w.Event([]byte(`{}`)); err == nil {
		t.Error("an event after the end was accepted")
	}
}

// Parse accepts only what Writer writes: anything it reads, written again,
// is the same line.
func FuzzParse(f *testing.F) {
	w, hd, _ := NewWriter("r-abc")
	f.Add(bytes.TrimSuffix(hd, []byte("\n")))
	b, _ := w.Event([]byte(`{"v":1,"type":"x"}`))
	f.Add(bytes.TrimSuffix(b, []byte("\n")))
	b, _ = w.Lost(4)
	f.Add(bytes.TrimSuffix(b, []byte("\n")))
	b, _ = w.Checkpoint()
	f.Add(bytes.TrimSuffix(b, []byte("\n")))
	f.Add(bytes.TrimSuffix(w.End(), []byte("\n")))
	f.Fuzz(func(t *testing.T, line []byte) {
		p, err := Parse(line)
		if err != nil {
			return
		}
		var again string
		switch p.Kind {
		case KHeader:
			h, _ := Header(p.Run)
			again = string(h)
		case KEvent:
			again = fmt.Sprintf(`{"n":%d,"ev":%s,"h":"%s"}`, p.N, p.Ev, p.H)
		case KLost:
			again = fmt.Sprintf(`{"n":%d,"lost":%d,"h":"%s"}`, p.N, p.Count, p.H)
		case KCheckpoint:
			again = fmt.Sprintf(`{"cp":%d,"n":%d,"h":"%s"}`, p.CP, p.N, p.H)
		case KEnd:
			again = fmt.Sprintf(`{"end":%d,"cp":%d,"h":"%s"}`, p.N, p.CP, p.H)
		}
		if again != string(line) {
			t.Fatalf("read %q, which writes back as %q", line, again)
		}
	})
}

// The verifier never panics, whatever the lines.
func FuzzVerify(f *testing.F) {
	f.Add([]byte(`{"vpnw-ledger":1,"run":"r-1"}` + "\n" + `{"n":1,"ev":{},"h":"` + strings.Repeat("0", 64) + `"}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		v := &Verifier{}
		for i, l := range bytes.Split(data, []byte("\n")) {
			v.Ledger("f", i+1, l, false)
			v.Trace("t", i+1, l)
		}
		v.Result()
	})
}

// A kept hash can only be checked against an end line.
func TestHeadOnCutShort(t *testing.T) {
	l, _ := sample(t, 5, 10, nil)
	h := Hash{}
	r := verify(l[:4], opts{head: &h})
	if r.Verdict != CutShort || !strings.Contains(strings.Join(r.Lines, "\n"), "couldn't be checked") ||
		strings.Contains(strings.Join(r.Lines, "\n"), "is the one you kept") {
		t.Fatalf("%+v", r)
	}
}
