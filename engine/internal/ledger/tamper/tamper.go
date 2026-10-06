// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

// Package tamper changes a sealed log the ways someone hiding a record
// would, for the tests and the demo. Each Case is one row of the tamper
// matrix: what was done, and the line Verify must name.
package tamper

import (
	"bytes"
	"fmt"
	"time"

	"vpnw.com/vpnw/internal/ledger"
)

// Files is a sealed log, line by line, without newlines.
type Files struct {
	Records [][]byte
	Ledger  [][]byte
}

// Split cuts a file into lines. A last newline doesn't start another line.
func Split(b []byte) [][]byte {
	if len(b) == 0 {
		return nil
	}
	lines := bytes.Split(b, []byte("\n"))
	if len(lines[len(lines)-1]) == 0 {
		lines = lines[:len(lines)-1]
	}
	return lines
}

// Join puts lines back into a file, each ending with a newline.
func Join(lines [][]byte) []byte {
	var b []byte
	for _, l := range lines {
		b = append(append(b, l...), '\n')
	}
	return b
}

func clone(lines [][]byte) [][]byte {
	out := make([][]byte, len(lines))
	for i, l := range lines {
		out[i] = append([]byte(nil), l...)
	}
	return out
}

// Case is one row of the tamper matrix.
type Case struct {
	Name     string // what was done
	Files    Files  // the files after it
	WrongKey bool   // checked with a key other than the one that signed
	Witness  bool   // checked with the untouched log's last checkpoint, kept elsewhere
	File     string // the file Verify must name: "records" or "ledger"
	Line     int    // the line it must name
	Kind     string // and the kind of problem
}

// EditByte changes one byte of a record: its last digit, so the line stays
// valid JSON.
func EditByte(rec []byte) []byte {
	out := append([]byte(nil), rec...)
	for i := len(out) - 1; i >= 0; i-- {
		if c := out[i]; c >= '0' && c <= '9' {
			out[i] = '0' + (c-'0'+1)%10
			return out
		}
	}
	return append(out, ' ')
}

// Matrix builds the tamper matrix around record line target of a sealed
// log. The log needs at least two checkpoints before the one that covers
// target, and a record after target.
func Matrix(f Files, target int) ([]Case, error) {
	led, err := ledger.ReadLedger(bytes.NewReader(Join(f.Ledger)), "ledger")
	if err != nil {
		return nil, err
	}
	cps := led.Checkpoints
	cover := 0 // the checkpoint that covers target
	for cover < len(cps) && cps[cover].Size < target {
		cover++
	}
	n := len(f.Records)
	if led.Problem != nil || target < 1 || target >= n || cover >= len(cps) || cover < 2 {
		return nil, fmt.Errorf("the log can't hold the matrix around line %d", target)
	}
	last := len(cps) - 1
	entry := led.EntryLine(target) - 1 // the entry's index in f.Ledger
	var cases []Case
	add := func(name string, ch func(*Files), file string, line int, kind string) *Case {
		g := Files{clone(f.Records), clone(f.Ledger)}
		ch(&g)
		cases = append(cases, Case{Name: name, Files: g, File: file, Line: line, Kind: kind})
		return &cases[len(cases)-1]
	}
	t := target - 1
	add("one byte edited", func(g *Files) { g.Records[t] = EditByte(g.Records[t]) }, "records", target, "changed")
	add("a line deleted", func(g *Files) { g.Records = append(g.Records[:t], g.Records[t+1:]...) }, "records", target, "missing")
	add("a line inserted", func(g *Files) {
		g.Records = append(g.Records[:t], append([][]byte{EditByte(f.Records[t])}, g.Records[t:]...)...)
	}, "records", target, "inserted")
	add("two lines swapped", func(g *Files) { g.Records[t], g.Records[t+1] = g.Records[t+1], g.Records[t] }, "records", target, "swapped")
	add("the end cut off", func(g *Files) { g.Records = g.Records[:t] }, "records", target, "cut")
	add("an old checkpoint replayed", func(g *Files) {
		g.Ledger[led.CPLines[last]-1] = g.Ledger[led.CPLines[0]-1]
	}, "ledger", led.CPLines[last], "replayed")
	add("the wrong key", func(*Files) {}, "ledger", led.CPLines[0], "key").WrongKey = true
	add("a record and its sealed hash changed together", func(g *Files) {
		g.Records[t] = EditByte(g.Records[t])
		g.Ledger[entry] = bytes.Replace(g.Ledger[entry], []byte(led.Leaves[t].String()), []byte(ledger.LeafHash(g.Records[t]).String()), 1)
	}, "ledger", led.CPLines[cover], "changed")
	add("a sealed hash changed", func(g *Files) {
		g.Ledger[entry] = bytes.Replace(g.Ledger[entry], []byte(led.Leaves[t].String()), []byte(ledger.LeafHash(nil).String()), 1)
	}, "ledger", led.EntryLine(target), "ledger")
	add("a checkpoint's time moved back", func(g *Files) {
		c := *cps[cover]
		c.Time = c.Time.Add(-time.Hour)
		g.Ledger[led.CPLines[cover]-1] = c.AppendJSON(nil)
	}, "ledger", led.CPLines[cover], "signature")
	add("a line added after the last checkpoint", func(g *Files) {
		g.Records = append(g.Records, EditByte(f.Records[n-1]))
	}, "records", n+1, "unsealed")
	add("both files cut back to a checkpoint, checked with a witness", func(g *Files) {
		keep := cps[cover-1]
		g.Records = g.Records[:keep.Size]
		g.Ledger = g.Ledger[:led.CPLines[cover-1]]
	}, "records", cps[cover-1].Size+1, "cut").Witness = true
	return cases, nil
}

// Result is what Verify said about one case.
type Result struct {
	Case    Case
	Problem *ledger.Problem // nil if Verify found nothing
	Caught  bool            // it named the expected file, line and kind
}

// Run checks one case: original is the untouched log, for its last
// checkpoint; pub signed it and other is any other key.
func Run(c Case, original Files, pub, other *ledger.PublicKey) (Result, error) {
	recs, _, err := ledger.HashRecords(bytes.NewReader(Join(c.Files.Records)), 0)
	if err != nil {
		return Result{}, err
	}
	led, err := ledger.ReadLedger(bytes.NewReader(Join(c.Files.Ledger)), "ledger")
	if err != nil {
		return Result{}, err
	}
	var opt ledger.VerifyOptions
	if c.Witness {
		orig, err := ledger.ReadLedger(bytes.NewReader(Join(original.Ledger)), "ledger")
		if err != nil {
			return Result{}, err
		}
		cps := orig.Checkpoints
		opt.Witness = []ledger.Witness{{CP: cps[len(cps)-1], File: "witness", Line: 1}}
	}
	key := pub
	if c.WrongKey {
		key = other
	}
	p := ledger.Verify(recs, "records", led, key, opt).Problem
	return Result{Case: c, Problem: p, Caught: p != nil && p.File == c.File && p.Line == c.Line && p.Kind == c.Kind}, nil
}
