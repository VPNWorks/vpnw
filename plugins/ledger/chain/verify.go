// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package chain

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
)

// Verdicts.
const (
	Intact   = "intact"    // every line checks out and the run ended
	CutShort = "cut short" // what is there checks out, but the run never ended
	Changed  = "CHANGED"   // something was changed, added, removed or moved
)

// Verifier checks one ledger, line by line, and the checkpoint copies kept
// in the run's other records. Feed it the ledger's lines first (Ledger),
// then any traces (Trace), then call Result.
type Verifier struct {
	// Head, if set, is the end hash kept somewhere else; the ledger must
	// end with it.
	Head *Hash

	file    string
	run     string
	line    int  // the ledger's last line read
	started bool // the header was read
	prev    Hash
	n       uint64 // entries checked
	cp      uint64
	ended   bool
	endLine int
	partial bool

	// One line held back, to tell two swapped lines from a deletion.
	held     *Parsed
	heldLine int

	problem     string // the first problem, with its line
	problemLine int

	lost     []string // notes about events that never reached Ledger
	lostSum  uint64
	hashes   []Hash  // hashes[i] is entry i+1's
	evDigest []Hash  // SHA-256 of entry i+1's event, or zero for a lost mark
	lineOf   []int32 // the ledger line of entry i+1

	// From the traces.
	copies    []copyCP
	traceSeq  []traceEv
	traceFile string
}

type copyCP struct {
	file string
	line int
	cp   uint64
	n    uint64
	h    Hash
	end  bool
}

type traceEv struct {
	file   string
	line   int
	digest Hash
}

func (v *Verifier) fail(line int, format string, a ...any) {
	if v.problem == "" {
		at := fmt.Sprintf("%s:%d: ", v.file, line)
		if line == 0 {
			at = v.file + ": "
		}
		v.problem = at + fmt.Sprintf(format, a...)
		v.problemLine = line
	}
}

// Ledger reads the ledger's next line: its file name, line number, bytes
// without the newline, and whether it was the last line, with no newline.
func (v *Verifier) Ledger(file string, n int, text []byte, partial bool) {
	if v.file == "" {
		v.file = file
	}
	v.line = n
	if v.problem != "" {
		return
	}
	if partial {
		// A run killed while Ledger was writing leaves half a line.
		v.flush()
		v.partial = true
		return
	}
	if !v.started {
		p, err := Parse(text)
		if err != nil || p.Kind != KHeader {
			v.fail(n, "this is not a VPN Works ledger: its first line is not a ledger header")
			return
		}
		v.started, v.run, v.prev = true, p.Run, Start(text)
		return
	}
	if v.ended {
		v.fail(n, "a line after the end line: it was added")
		return
	}
	p, err := Parse(text)
	if err != nil {
		v.flush()
		v.fail(n, "not a line Ledger writes: it was changed")
		return
	}
	switch p.Kind {
	case KHeader:
		v.flush()
		v.fail(n, "a second header: lines were added")
	case KEvent, KLost:
		v.entry(n, p)
	case KCheckpoint:
		v.flush()
		if v.problem != "" {
			return
		}
		switch {
		case p.CP != v.cp+1:
			v.fail(n, "checkpoint %d where checkpoint %d belongs: checkpoints were removed, added or moved", p.CP, v.cp+1)
		case p.N != v.n:
			v.fail(n, "checkpoint %d covers entry %d, but the entries before it end at %d: lines were removed, added or moved", p.CP, p.N, v.n)
		case p.H != v.prev:
			v.fail(n, "checkpoint %d doesn't match the entries before it: it or they were changed", p.CP)
		default:
			v.cp = p.CP
		}
	case KEnd:
		v.flush()
		if v.problem != "" {
			return
		}
		switch {
		case p.N != v.n:
			v.fail(n, "the end line counts %d entries, but there are %d: lines were removed, added or moved", p.N, v.n)
		case p.H != v.prev:
			v.fail(n, "the end line doesn't match the entries before it: it or they were changed")
		default:
			v.ended, v.endLine = true, n
		}
	}
}

// entry checks an event or lost mark, holding back one that skips ahead in
// case the next line shows the two were swapped.
func (v *Verifier) entry(n int, p *Parsed) {
	want := v.n + 1
	if v.held != nil {
		h, hl := v.held, v.heldLine
		v.held = nil
		if p.N == want && h.N == want+1 {
			v.fail(hl, "this line and the next were swapped (entry %d comes after entry %d)", want, want+1)
			return
		}
		v.missing(hl, h.N, want)
		return
	}
	switch {
	case p.N == want:
		v.accept(n, p)
	case p.N == want+1:
		v.held, v.heldLine = p, n
	case p.N > want:
		v.missing(n, p.N, want)
	default:
		v.fail(n, "entry %d again, after entry %d: this line was added (inserted or copied)", p.N, v.n)
	}
}

func (v *Verifier) missing(line int, got, want uint64) {
	if got == want+1 {
		v.fail(line, "entry %d is missing before this line: a line was removed", want)
		return
	}
	v.fail(line, "entries %d to %d are missing before this line: lines were removed", want, got-1)
}

// flush settles a held line at a checkpoint, the end or the end of input:
// with nothing after it to swap with, the entry before it is missing.
func (v *Verifier) flush() {
	if v.held != nil {
		h, hl := v.held, v.heldLine
		v.held = nil
		v.missing(hl, h.N, v.n+1)
	}
}

func (v *Verifier) accept(line int, p *Parsed) {
	var h Hash
	var d Hash
	if p.Kind == KEvent {
		var e struct {
			Run string `json:"run"`
		}
		json.Unmarshal(p.Ev, &e)
		if e.Run != v.run {
			if p.N == 1 {
				v.fail(1, "the header names run %s, but the events are run %s's: the header was changed", v.run, e.Run)
			} else {
				v.fail(line, "the event belongs to run %s, not this ledger's run %s: it was changed", e.Run, v.run)
			}
			return
		}
		h = EventHash(v.prev, p.N, p.Ev)
		d = sha256.Sum256(p.Ev)
	} else {
		h = LostHash(v.prev, p.N, p.Count)
	}
	if h != p.H {
		if p.Kind == KEvent {
			v.fail(line, "the event doesn't match its hash: it was changed")
		} else {
			v.fail(line, "the count of lost events doesn't match its hash: it was changed")
		}
		return
	}
	if p.Kind == KLost {
		v.lostSum += p.Count
		v.lost = append(v.lost, fmt.Sprintf("%s:%d: %d events never reached Ledger here (it fell behind the run)", v.file, line, p.Count))
	}
	v.prev, v.n = h, p.N
	v.hashes = append(v.hashes, h)
	v.evDigest = append(v.evDigest, d)
	v.lineOf = append(v.lineOf, int32(line))
}

// Trace reads a line of the run's other record (a trace: --out, or the
// saved "last" trace). It keeps the checkpoint copies Ledger wrote there and
// the run's events, to compare with the ledger's.
func (v *Verifier) Trace(file string, n int, text []byte) {
	var e struct {
		Type   string         `json:"type"`
		Run    string         `json:"run"`
		Fields map[string]any `json:"fields"`
	}
	if len(text) == 0 || json.Unmarshal(text, &e) != nil || (v.run != "" && e.Run != v.run) {
		return
	}
	v.traceFile = file
	switch e.Type {
	case "plugin.ledger.checkpoint":
		c := copyCP{file: file, line: n}
		cp, ok1 := num(e.Fields["cp"])
		en, ok2 := num(e.Fields["n"])
		hs, _ := e.Fields["h"].(string)
		h, err := ParseHash(hs)
		if !ok1 || !ok2 || err != nil {
			return
		}
		c.cp, c.n, c.h = cp, en, h
		c.end, _ = e.Fields["end"].(bool)
		v.copies = append(v.copies, c)
		return
	}
	if strings.HasPrefix(e.Type, "plugin.ledger.") {
		return // Ledger never gets its own events
	}
	v.traceSeq = append(v.traceSeq, traceEv{file: file, line: n, digest: sha256.Sum256(text)})
}

func num(x any) (uint64, bool) {
	f, ok := x.(float64)
	if !ok || f < 0 || f != float64(uint64(f)) {
		return 0, false
	}
	return uint64(f), true
}

// Report is what verification found.
type Report struct {
	Verdict string
	Run     string
	File    string
	Entries uint64
	Lost    uint64
	Lines   []string // the report, a line each
	// Problem is the first problem, or "" when there is none.
	Problem string
}

// Result finishes the check.
func (v *Verifier) Result() Report {
	v.flush()
	r := Report{Run: v.run, File: v.file, Entries: v.n, Lost: v.lostSum}
	say := func(f string, a ...any) { r.Lines = append(r.Lines, fmt.Sprintf(f, a...)) }
	if !v.started && v.problem == "" {
		v.fail(1, "this is not a VPN Works ledger: it is empty")
	}
	if v.problem == "" {
		v.checkCopies()
	}
	if v.problem == "" && v.Head != nil && v.ended {
		if v.prev != *v.Head {
			v.fail(0, "the ledger's last hash is not the one you kept: it was rewritten")
		}
	}
	switch {
	case v.problem != "":
		r.Verdict, r.Problem = Changed, v.problem
		say("%s: %s", Changed, v.problem)
		if v.n > 0 {
			say("entries 1 to %d, before that, check out", v.n)
		}
	case !v.ended:
		r.Verdict = CutShort
		how := "after line " + fmt.Sprint(v.line)
		if v.partial {
			how = "in the middle of line " + fmt.Sprint(v.line)
		}
		r.Problem = fmt.Sprintf("%s: the ledger stops %s with no end line: the run was cut short there, or the end was removed", v.file, how)
		say("%s: %s", CutShort, r.Problem)
		say("entries 1 to %d check out", v.n)
	default:
		r.Verdict = Intact
		say("%s: %s holds %d entries of run %s, every one matching its hash, and ends normally", Intact, v.file, v.n, v.run)
	}
	for _, l := range v.lost {
		say("%s", l)
	}
	if len(v.copies) > 0 {
		say("%d checkpoint copies in %s match", v.goodCopies(), v.traceFile)
	} else if r.Verdict != Changed {
		say("no checkpoint copies were checked: give the run's trace too, so a ledger rewritten from some line on is caught")
	}
	if v.Head != nil && r.Verdict != Changed {
		say("the last hash is the one you kept")
	}
	return r
}

func (v *Verifier) goodCopies() int {
	n := 0
	for _, c := range v.copies {
		if c.n >= 1 && c.n <= uint64(len(v.hashes)) && v.hashes[c.n-1] == c.h {
			n++
		}
	}
	return n
}

// checkCopies compares the checkpoint copies kept in the traces with the
// ledger. A ledger whose lines all check out but whose hashes were written
// again from some line on fails here; the trace's events then name the line.
func (v *Verifier) checkCopies() {
	for _, c := range v.copies {
		switch {
		case c.n > v.n:
			v.fail(0, "%s:%d holds a copy of checkpoint %d at entry %d, but the ledger ends at entry %d: the end was cut off", c.file, c.line, c.cp, c.n, v.n)
			return
		case c.n == 0:
			continue
		case v.hashes[c.n-1] != c.h:
			if l, t := v.firstDifference(c.n); l > 0 {
				v.fail(l, "the event differs from the same event in %s, and the hashes from here on were written again to hide it (the copy of checkpoint %d in %s:%d doesn't match)", t, c.cp, c.file, c.line)
				return
			}
			v.fail(0, "the ledger doesn't match the copy of checkpoint %d in %s:%d: a line at or before entry %d was changed and the hashes after it written again", c.cp, c.file, c.line, c.n)
			return
		case c.end && c.n != v.n:
			v.fail(0, "%s:%d says the run ended at entry %d, but the ledger goes on to %d: entries were added", c.file, c.line, c.n, v.n)
			return
		}
	}
}

// firstDifference compares the ledger's events with the trace's, in order,
// and returns the ledger line of the first that differs and where the trace
// has it. The two line up only until the first lost mark: past it, which of
// the trace's events Ledger missed isn't known exactly.
func (v *Verifier) firstDifference(upto uint64) (int, string) {
	var zero Hash
	for i := uint64(0); i < upto && i < uint64(len(v.evDigest)); i++ {
		if v.evDigest[i] == zero || int(i) >= len(v.traceSeq) {
			return 0, ""
		}
		if v.evDigest[i] != v.traceSeq[i].digest {
			t := v.traceSeq[i]
			return int(v.lineOf[i]), fmt.Sprintf("%s:%d", t.file, t.line)
		}
	}
	return 0, ""
}

// IsLedger says whether a first line is a ledger header.
func IsLedger(first []byte) bool {
	return bytes.HasPrefix(first, []byte(`{"vpnw-ledger":`))
}
