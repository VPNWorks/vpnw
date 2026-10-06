// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"fmt"
	"io"
	"io/fs"
	"time"

	"vpnw.com/vpnw/internal/config"
)

// Options adjust a Sealer.
type Options struct {
	Every    int              // sign a checkpoint after this many records (default 1000)
	Interval time.Duration    // following: sign one when a record has waited this long (default 10s)
	Poll     time.Duration    // following: how often to look for new lines (default 200ms)
	Now      func() time.Time // the clock, for tests (default time.Now)
}

// Sealer adds records to a ledger. Record lines wait in memory and are
// written together with the checkpoint that covers them, in one write, so
// the ledger always ends with a checkpoint.
type Sealer struct {
	OnCheckpoint func(*Checkpoint) // called after each checkpoint is written

	w       io.Writer
	key     *PrivateKey
	log     string
	opt     Options
	tree    Tree
	last    *Checkpoint
	buf     []byte    // record lines waiting for a checkpoint
	pending int       // how many
	since   time.Time // when the first of them came
}

func newSealer(w io.Writer, key *PrivateKey, log string, opt Options) *Sealer {
	if opt.Every <= 0 {
		opt.Every = 1000
	}
	if opt.Interval <= 0 {
		opt.Interval = 10 * time.Second
	}
	if opt.Poll <= 0 {
		opt.Poll = 200 * time.Millisecond
	}
	if opt.Now == nil {
		opt.Now = time.Now
	}
	return &Sealer{w: w, key: key, log: log, opt: opt}
}

// NewSealer starts a new ledger for the named log on w, which should be
// empty: it writes the header.
func NewSealer(w io.Writer, key *PrivateKey, log string, opt Options) (*Sealer, error) {
	if !ValidLogName(log) {
		return nil, fmt.Errorf("log name %q: use 1 to 128 printable ASCII characters, without \" or \\", log)
	}
	s := newSealer(w, key, log, opt)
	if _, err := w.Write(append(appendHeader(nil, log), '\n')); err != nil {
		return nil, err
	}
	return s, nil
}

// ResumeSealer carries on a ledger, appending to w. rep must come from
// Verify with Tail set, and show no problem.
func ResumeSealer(w io.Writer, key *PrivateKey, led *Ledger, rep *Report, opt Options) (*Sealer, error) {
	if rep.Problem != nil {
		return nil, rep.Problem
	}
	if rep.Last != nil && rep.Last.Key != key.ID {
		return nil, fmt.Errorf("%s was sealed with key %s, not %s", led.Name, rep.Last.Key, key.ID)
	}
	s := newSealer(w, key, led.Log, opt)
	for _, h := range led.Leaves {
		s.tree.Add(h)
	}
	s.last = rep.Last
	return s, nil
}

// Sealed is the number of records in the ledger, those waiting included.
func (s *Sealer) Sealed() int { return s.tree.Size() }

// Last is the last checkpoint written, or nil.
func (s *Sealer) Last() *Checkpoint { return s.last }

// add seals one record that rr just read.
func (s *Sealer) add(rr *recordReader, rec []byte) error {
	if err := CheckRecord(rec); err != nil {
		return &config.Error{File: rr.name, Line: rr.line, Msg: err.Error()}
	}
	leaf := LeafHash(rec)
	s.tree.Add(leaf)
	s.buf = append(appendEntry(s.buf, s.tree.Size(), leaf), '\n')
	if s.pending == 0 {
		s.since = s.opt.Now()
	}
	s.pending++
	if s.pending >= s.opt.Every {
		return s.Checkpoint()
	}
	return nil
}

// Checkpoint signs a checkpoint over every record sealed so far, and writes
// it with the record lines waiting for it. With none waiting it does
// nothing.
func (s *Sealer) Checkpoint() error {
	if s.pending == 0 {
		return nil
	}
	c := &Checkpoint{Log: s.log, Seq: 1, Size: s.tree.Size(), Root: s.tree.Root(), Chain: s.tree.Chain(),
		Time: s.opt.Now().UTC().Truncate(time.Second)}
	if s.last != nil {
		c.Seq, c.Prev = s.last.Seq+1, s.last.Hash()
	}
	c.Sign(s.key)
	s.buf = append(c.AppendJSON(s.buf), '\n')
	if _, err := s.w.Write(s.buf); err != nil {
		return err
	}
	s.buf, s.pending, s.last = s.buf[:0], 0, c
	if s.OnCheckpoint != nil {
		s.OnCheckpoint(c)
	}
	return nil
}

// SealAll seals every line of r as a record, the last one even without a
// newline, then signs a checkpoint. r starts where line ends: after the
// last record sealed before, or at the start of the file when line is 0.
// name names the file in errors. It returns how many records it sealed.
func (s *Sealer) SealAll(r io.Reader, name string, line int) (int, error) {
	rr := newRecordReader(r, name, line, line > 0)
	n := 0
	for {
		rec, err := rr.next()
		if err == io.EOF {
			if rec = rr.rest(); rec == nil {
				break
			}
		} else if err != nil {
			return n, err
		}
		if err := s.add(rr, rec); err != nil {
			return n, err
		}
		n++
	}
	return n, s.Checkpoint()
}

// File is a records file to follow, such as an *os.File.
type File interface {
	io.ReadSeeker
	Stat() (fs.FileInfo, error)
}

// Follow seals the lines of f as they are written, like tail -f, from where
// line ends (as in SealAll), until stop is closed. It signs a checkpoint
// every Every records, and when a record has waited Interval. When stopped,
// it seals the complete lines already written and signs a last checkpoint;
// a line still without its newline is left for the next seal.
func (s *Sealer) Follow(f File, name string, line int, stop <-chan struct{}) (int, error) {
	rr := newRecordReader(f, name, line, line > 0)
	tick := time.NewTicker(s.opt.Poll)
	defer tick.Stop()
	n := 0
	drain := func() error {
		for {
			rec, err := rr.next()
			if err != nil {
				return err
			}
			if err := s.add(rr, rec); err != nil {
				return err
			}
			n++
			if s.due() {
				if err := s.Checkpoint(); err != nil {
					return err
				}
			}
		}
	}
	for {
		if err := drain(); err != io.EOF {
			return n, err
		}
		if s.due() {
			if err := s.Checkpoint(); err != nil {
				return n, err
			}
		}
		if err := shrunk(f, name, rr.line); err != nil {
			return n, err
		}
		select {
		case <-stop:
			if err := drain(); err != io.EOF {
				return n, err
			}
			return n, s.Checkpoint()
		case <-tick.C:
		}
	}
}

// due reports whether a record has waited Interval for its checkpoint.
func (s *Sealer) due() bool {
	return s.pending > 0 && s.opt.Now().Sub(s.since) >= s.opt.Interval
}

// shrunk catches a followed file that got shorter than what was read of it.
func shrunk(f File, name string, line int) error {
	pos, err := f.Seek(0, io.SeekCurrent)
	if err != nil {
		return err
	}
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if fi.Size() < pos {
		return &Problem{File: name, Line: line, Kind: "cut", Msg: fmt.Sprintf("the file got shorter while it was followed, from %d bytes to %d: it was cut or replaced", pos, fi.Size())}
	}
	return nil
}
