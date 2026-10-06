// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"

	"vpnw.com/vpnw/internal/config"
)

// Problem is what Verify found wrong, tied to a line of the records file or
// of the ledger.
type Problem struct {
	File string // the records file or the ledger
	Line int    // the line, 1 for the first
	Kind string // in a word: changed, missing, inserted, swapped, moved, cut, unsealed, ledger, replayed, key, signature, spliced or rewritten
	Msg  string
}

func (p *Problem) Error() string { return fmt.Sprintf("%s:%d: %s", p.File, p.Line, p.Msg) }

// Report is what Verify found.
type Report struct {
	Records int         // lines in the records file
	Sealed  int         // records in the ledger
	Checked int         // checkpoints found good, from the first
	Last    *Checkpoint // the last of them, or nil
	Problem *Problem    // the first problem, or nil if there is none
}

// Witness is a checkpoint kept somewhere else, such as a copy of what seal
// printed. The ledger must hold it as it is.
type Witness struct {
	CP   *Checkpoint
	File string
	Line int
}

// ReadWitness reads the checkpoints in a file. A checkpoint is the text from
// {"cp": to the end of its line, so lines from a system log, or a ledger,
// work as they are; lines without one are skipped. Every checkpoint must be
// signed by pub.
func ReadWitness(r io.Reader, name string, pub *PublicKey) ([]Witness, error) {
	var out []Witness
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 4096), maxLedgerLine*4)
	for n := 1; sc.Scan(); n++ {
		i := bytes.Index(sc.Bytes(), []byte(`{"cp":`))
		if i < 0 {
			continue
		}
		c, err := ParseCheckpoint(bytes.TrimRight(sc.Bytes()[i:], " \t\r"))
		if err == nil {
			err = c.Check(pub)
		}
		if err != nil {
			return nil, &config.Error{File: name, Line: n, Msg: err.Error()}
		}
		out = append(out, Witness{c, name, n})
	}
	if err := sc.Err(); errors.Is(err, bufio.ErrTooLong) {
		return nil, &config.Error{File: name, Msg: fmt.Sprintf("a line longer than %d bytes: not a file of checkpoints", maxLedgerLine*4)}
	} else if err != nil {
		return nil, fmt.Errorf("%s: %v", name, err)
	}
	if len(out) == 0 {
		return nil, &config.Error{File: name, Msg: "no checkpoint in it"}
	}
	return out, nil
}

// VerifyOptions adjusts Verify.
type VerifyOptions struct {
	Witness []Witness // checkpoints kept elsewhere
	Tail    bool      // records after the last sealed one are fine: seal checks this way before it seals them
}

// Verify checks a log against its ledger and a public key. recs holds the
// leaf hash of every line of the records file, as HashRecords returns them.
// It trusts nothing in the ledger that a checkpoint signed by pub doesn't
// vouch for, and reports the first problem:
//
//  1. Every checkpoint, in order, must be signed by pub, carry the hash of
//     the checkpoint before it, and match the root and chain of the hashes
//     sealed before it. Those it vouches for are trusted.
//  2. Every record must match its trusted hash. A record that doesn't is
//     the first problem: it was changed, deleted, inserted or moved.
//  3. Then the ledger's first bad checkpoint, or its first bad line.
//  4. The ends: records cut off, sealed records no checkpoint covers, and
//     records never sealed.
//  5. Checkpoints kept elsewhere, which catch a ledger cut back to an
//     earlier checkpoint.
func Verify(recs []Hash, recName string, led *Ledger, pub *PublicKey, opt VerifyOptions) *Report {
	rep := &Report{Records: len(recs), Sealed: len(led.Leaves)}
	v := &verifier{recs: recs, recName: recName, led: led}

	var tree Tree
	var bad *Problem
	for i, c := range led.Checkpoints {
		if bad = v.checkpoint(i, c, pub, &tree); bad != nil {
			break
		}
		rep.Checked, rep.Last = i+1, c
	}
	trusted := 0
	if rep.Last != nil {
		trusted = rep.Last.Size
	}

	rep.Problem = v.compare(trusted)
	if rep.Problem == nil {
		rep.Problem = bad
	}
	if rep.Problem == nil {
		rep.Problem = led.Problem
	}
	if rep.Problem == nil {
		rep.Problem = v.ends(trusted, opt.Tail)
	}
	for _, w := range opt.Witness {
		if rep.Problem == nil {
			rep.Problem = v.witness(w, trusted)
		}
	}
	return rep
}

type verifier struct {
	recs    []Hash
	recName string
	led     *Ledger
}

func (v *verifier) recProblem(line int, kind, format string, a ...any) *Problem {
	return &Problem{File: v.recName, Line: line, Kind: kind, Msg: fmt.Sprintf(format, a...)}
}

func (v *verifier) ledProblem(line int, kind, format string, a ...any) *Problem {
	return &Problem{File: v.led.Name, Line: line, Kind: kind, Msg: fmt.Sprintf(format, a...)}
}

// checkpoint checks checkpoint i; tree holds the sealed hashes before it.
func (v *verifier) checkpoint(i int, c *Checkpoint, pub *PublicKey, tree *Tree) *Problem {
	line := v.led.CPLines[i]
	if err := c.Check(pub); err != nil {
		kind := "signature"
		if c.Key != pub.ID {
			kind = "key"
		}
		return v.ledProblem(line, kind, "checkpoint %d: %v", c.Seq, err)
	}
	var prev Hash
	if i > 0 {
		prev = v.led.Checkpoints[i-1].Hash()
	}
	if c.Prev != prev {
		return v.ledProblem(line, "spliced", "checkpoint %d doesn't follow checkpoint %d: it was signed for another history and spliced in", c.Seq, c.Seq-1)
	}
	for tree.Size() < c.Size {
		tree.Add(v.led.Leaves[tree.Size()])
	}
	if tree.Root() == c.Root && tree.Chain() == c.Chain {
		return nil
	}
	return v.blame(i, c)
}

// blame says which file changed when the hashes sealed before checkpoint i
// don't give its signed root: if the records still give it, a hash in the
// ledger was changed; if not, a record was changed in both files.
func (v *verifier) blame(i int, c *Checkpoint) *Problem {
	from := 0
	if i > 0 {
		from = v.led.Checkpoints[i-1].Size
	}
	if len(v.recs) >= c.Size {
		var t Tree
		for _, h := range v.recs[:c.Size] {
			t.Add(h)
		}
		if t.Root() == c.Root && t.Chain() == c.Chain {
			for n := from + 1; n <= c.Size; n++ {
				if v.led.Leaves[n-1] != v.recs[n-1] {
					return v.ledProblem(v.led.EntryLine(n), "ledger", "the hash sealed for record %d was changed: the record itself still matches checkpoint %d", n, c.Seq)
				}
			}
		}
	}
	return v.ledProblem(v.led.CPLines[i], "changed", "checkpoint %d doesn't match records %d to %d: one of them was changed, and its hash in the ledger with it", c.Seq, from+1, c.Size)
}

// index is the first k from from on with hs[k] == h, or -1.
func index(hs []Hash, h Hash, from int) int {
	for k := from; k < len(hs); k++ {
		if hs[k] == h {
			return k
		}
	}
	return -1
}

// compare finds the first record that doesn't match its trusted hash, and
// says what happened to it.
func (v *verifier) compare(trusted int) *Problem {
	recs, sealed := v.recs, v.led.Leaves
	i := 0
	for i < len(recs) && i < trusted && recs[i] == sealed[i] {
		i++
	}
	if i == len(recs) || i == trusted {
		return nil
	}
	line := i + 1
	j := index(sealed, recs[i], i+1) // where the record on this line was sealed
	k := index(recs, sealed[i], i+1) // where the record sealed for this line is now
	switch {
	case j >= 0 && j == k:
		return v.recProblem(line, "swapped", "lines %d and %d were swapped", line, j+1)
	case j >= 0 && k >= 0:
		return v.recProblem(line, "moved", "this line holds the record sealed as line %d: records were moved", j+1)
	case j >= 0 && (i+1 == len(recs) || j+1 == len(sealed) || recs[i+1] == sealed[j+1]):
		if j == i+1 {
			return v.recProblem(line, "missing", "a record is missing here: the one sealed as line %d was deleted", line)
		}
		return v.recProblem(line, "missing", "%d records are missing here: the ones sealed as lines %d to %d were deleted", j-i, line, j)
	case k >= 0 && (k+1 == len(recs) || i+1 == len(sealed) || recs[k+1] == sealed[i+1]):
		if k == i+1 {
			return v.recProblem(line, "inserted", "this line was never sealed: it was inserted")
		}
		return v.recProblem(line, "inserted", "lines %d to %d were never sealed: they were inserted", line, k)
	}
	return v.recProblem(line, "changed", "the record doesn't match its sealed hash: it was changed")
}

// ends checks that the records, the ledger and its last checkpoint all end
// together.
func (v *verifier) ends(trusted int, tail bool) *Problem {
	recs, sealed := len(v.recs), len(v.led.Leaves)
	switch {
	case recs < trusted:
		ends := fmt.Sprintf("the file ends after line %d", recs)
		if recs == 0 {
			ends = "the file is empty"
		}
		return v.recProblem(recs+1, "cut", "%s, but checkpoint %d covers %d records: the end was cut off", ends, len(v.led.Checkpoints), trusted)
	case sealed > trusted:
		return v.ledProblem(v.led.EntryLine(trusted+1), "cut", "records %d to %d are sealed, but no checkpoint covers them: the ledger's last checkpoint was cut off, or seal stopped before signing one", trusted+1, sealed)
	case recs > sealed && !tail:
		if recs == sealed+1 {
			return v.recProblem(sealed+1, "unsealed", "this line was never sealed: it came after the last checkpoint")
		}
		return v.recProblem(sealed+1, "unsealed", "lines %d to %d were never sealed: they came after the last checkpoint", sealed+1, recs)
	}
	return nil
}

// witness checks one checkpoint kept elsewhere against the ledger.
func (v *verifier) witness(w Witness, trusted int) *Problem {
	c, cps := w.CP, v.led.Checkpoints
	if c.Seq <= len(cps) {
		if have := cps[c.Seq-1]; !bytes.Equal(have.Message(), c.Message()) {
			return v.ledProblem(v.led.CPLines[c.Seq-1], "rewritten", "checkpoint %d differs from the copy in %s line %d: the ledger was signed again from there", c.Seq, w.File, w.Line)
		}
		return nil
	}
	ends := "has no checkpoint"
	if len(cps) > 0 {
		ends = fmt.Sprintf("ends at checkpoint %d", len(cps))
	}
	return v.recProblem(trusted+1, "cut", "the end was cut off: the ledger %s, but checkpoint %d in %s line %d covers %d records; it was signed %s",
		ends, c.Seq, w.File, w.Line, c.Size, c.When())
}
