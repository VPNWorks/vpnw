// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"strconv"
	"unicode/utf8"

	"vpnw.com/vpnw/internal/config"
)

// A ledger file is JSON Lines, readable by eye: a header, then one line per
// record with its number and leaf hash, and a checkpoint after the last
// record it covers.
//
//	{"vpnw-ledger":1,"log":"trace.jsonl"}
//	{"n":1,"leaf":"5f2a…"}
//	…
//	{"n":8,"leaf":"0c4d…"}
//	{"cp":1,"size":8,"root":"…","chain":"…","prev":"000…","time":"2026-10-05T10:00:00Z","key":"k-1a2b3c4d","log":"trace.jsonl","sig":"…"}
//
// Seal writes record lines together with the checkpoint that covers them,
// so a complete ledger always ends with a checkpoint.

// maxLedgerLine is longer than any line seal writes.
const maxLedgerLine = 1024

func appendHeader(b []byte, log string) []byte {
	return fmt.Appendf(b, `{"vpnw-ledger":1,"log":"%s"}`, log)
}

func parseHeader(line []byte) (string, error) {
	var h struct {
		V   int    `json:"vpnw-ledger"`
		Log string `json:"log"`
	}
	if json.Unmarshal(line, &h) != nil || h.V == 0 {
		return "", errors.New("its first line isn't a vpnw-ledger header")
	}
	if h.V != 1 {
		return "", fmt.Errorf("it is version %d, and this vpnw-ledger reads version 1", h.V)
	}
	if !ValidLogName(h.Log) || !bytes.Equal(appendHeader(nil, h.Log), line) {
		return "", errors.New("its header isn't as seal writes it")
	}
	return h.Log, nil
}

func appendEntry(b []byte, n int, leaf Hash) []byte {
	b = append(b, `{"n":`...)
	b = strconv.AppendInt(b, int64(n), 10)
	b = append(b, `,"leaf":"`...)
	b = hex.AppendEncode(b, leaf[:])
	return append(b, `"}`...)
}

// parseEntry reads a record line, {"n":14,"leaf":"…"}, exactly as
// appendEntry writes it.
func parseEntry(line []byte) (int, Hash, error) {
	const pre, mid, end = `{"n":`, `,"leaf":"`, `"}`
	var leaf Hash
	bad := errors.New("not a record line as seal writes it")
	digits := len(line) - len(pre) - len(mid) - 64 - len(end)
	if digits < 1 || digits > 15 || !bytes.HasPrefix(line, []byte(pre)) || !bytes.HasSuffix(line, []byte(end)) ||
		string(line[len(pre)+digits:len(pre)+digits+len(mid)]) != mid {
		return 0, leaf, bad
	}
	n := 0
	for _, c := range line[len(pre) : len(pre)+digits] {
		if c < '0' || c > '9' {
			return 0, leaf, bad
		}
		n = n*10 + int(c-'0')
	}
	h := line[len(line)-len(end)-64 : len(line)-len(end)]
	if n < 1 || line[len(pre)] == '0' || !lowerHex(h) {
		return 0, leaf, bad
	}
	hex.Decode(leaf[:], h)
	return n, leaf, nil
}

// Ledger is a ledger file as read, up to its first line that isn't as seal
// writes it.
type Ledger struct {
	Name        string        // the file's name, for messages
	Log         string        // the log's name, from the header
	Leaves      []Hash        // the hash sealed for record n is Leaves[n-1]
	Checkpoints []*Checkpoint // in order
	CPLines     []int         // the ledger line of each checkpoint
	Problem     *Problem      // the first bad line, or nil
}

// EntryLine is the line of the ledger that holds the hash of record n.
func (l *Ledger) EntryLine(n int) int {
	line := 1 + n
	for _, c := range l.Checkpoints {
		if c.Size < n {
			line++
		}
	}
	return line
}

// ReadLedger reads a ledger. It stops at the first line that isn't as seal
// writes it and keeps that line as Problem. An error means the file can't
// be read or isn't a ledger at all.
func ReadLedger(r io.Reader, name string) (*Ledger, error) {
	l := &Ledger{Name: name}
	br := bufio.NewReaderSize(r, 64<<10)
	n := 0
	bad := func(kind, format string, a ...any) (*Ledger, error) {
		l.Problem = &Problem{File: name, Line: n, Kind: kind, Msg: fmt.Sprintf(format, a...)}
		return l, nil
	}
	for {
		b, err := br.ReadSlice('\n')
		if len(b) == 0 && err == io.EOF {
			break
		}
		n++
		if err != nil && err != io.EOF && err != bufio.ErrBufferFull {
			return nil, err
		}
		if n == 1 {
			if err != nil {
				return nil, &config.Error{File: name, Line: 1, Msg: "not a vpnw-ledger file: its first line isn't a vpnw-ledger header"}
			}
			log, err := parseHeader(b[:len(b)-1])
			if err != nil {
				return nil, &config.Error{File: name, Line: 1, Msg: "not a vpnw-ledger file: " + err.Error()}
			}
			l.Log = log
			continue
		}
		switch {
		case err == bufio.ErrBufferFull || len(b) > maxLedgerLine+1:
			return bad("ledger", "longer than any line seal writes: the ledger was changed")
		case err == io.EOF:
			return bad("cut", "the last line has no newline: the ledger was cut, or seal stopped while writing it")
		}
		line := b[:len(b)-1]
		switch {
		case bytes.HasPrefix(line, []byte(`{"n":`)):
			rec, leaf, err := parseEntry(line)
			if err != nil {
				return bad("ledger", "%v: the ledger was changed", err)
			}
			if want := len(l.Leaves) + 1; rec > want {
				return bad("ledger", "this is the hash of record %d, but record %d comes next: a ledger line is missing before it", rec, want)
			} else if rec < want {
				return bad("ledger", "this is the hash of record %d again, after record %d: a ledger line was copied or moved here", rec, want-1)
			}
			l.Leaves = append(l.Leaves, leaf)
		case bytes.HasPrefix(line, []byte(`{"cp":`)):
			c, err := ParseCheckpoint(line)
			if err != nil {
				return bad("ledger", "%v: the ledger was changed", err)
			}
			want := len(l.Checkpoints) + 1
			switch {
			case c.Seq < want:
				return bad("replayed", "checkpoint %d again, where checkpoint %d should be: an old checkpoint was replayed or moved here", c.Seq, want)
			case c.Seq > want:
				return bad("ledger", "checkpoint %d, but checkpoint %d comes next: a checkpoint is missing before it", c.Seq, want)
			case c.Size != len(l.Leaves):
				return bad("ledger", "checkpoint %d covers %d records, but it comes after record %d: it was moved", c.Seq, c.Size, len(l.Leaves))
			case want > 1 && c.Size == l.Checkpoints[want-2].Size:
				return bad("ledger", "checkpoint %d adds no records to checkpoint %d: it was copied", c.Seq, want-1)
			case c.Log != l.Log:
				return bad("ledger", "checkpoint %d is for log %q, but this ledger is for %q", c.Seq, c.Log, l.Log)
			}
			l.Checkpoints = append(l.Checkpoints, c)
			l.CPLines = append(l.CPLines, n)
		default:
			return bad("ledger", "not a ledger line: seal writes record hashes and checkpoints only")
		}
	}
	if n == 0 {
		return nil, &config.Error{File: name, Msg: "not a vpnw-ledger file: it is empty"}
	}
	return l, nil
}

// HashRecords returns the leaf hash of each line of r: the line's bytes
// without its newline, of any length. A last line without a newline counts
// too. end is where record mark ends, just before its newline, for seal to
// carry on from.
func HashRecords(r io.Reader, mark int) (leaves []Hash, end int64, err error) {
	br := bufio.NewReaderSize(r, 64<<10)
	d := sha256.New()
	var off int64
	open := false
	done := func() {
		leaves = append(leaves, sum(d))
		open = false
		if len(leaves) == mark {
			end = off
		}
	}
	for {
		b, err := br.ReadSlice('\n')
		if len(b) > 0 {
			if !open {
				d.Reset()
				d.Write([]byte{leafPrefix})
				open = true
			}
			nl := b[len(b)-1] == '\n'
			if nl {
				b = b[:len(b)-1]
			}
			d.Write(b)
			off += int64(len(b))
			if nl {
				done()
				off++
			}
		}
		switch {
		case err == bufio.ErrBufferFull:
		case err == io.EOF:
			if open {
				done()
			}
			return leaves, end, nil
		case err != nil:
			return nil, 0, err
		}
	}
}

func sum(d hash.Hash) Hash {
	var h Hash
	d.Sum(h[:0])
	return h
}

// CheckRecord says why a line can't be sealed as a record: a record is one
// JSON value, in UTF-8, on one line.
func CheckRecord(line []byte) error {
	if json.Valid(line) && utf8.Valid(line) {
		return nil
	}
	switch {
	case len(bytes.TrimSpace(line)) == 0:
		return errors.New("an empty line: a record is one JSON value per line")
	case !utf8.Valid(line):
		return errors.New("not valid UTF-8")
	}
	var v any
	return fmt.Errorf("not valid JSON: %v", json.Unmarshal(line, &v))
}

// recordReader reads whole lines for seal, from a file that may still be
// growing.
type recordReader struct {
	br      *bufio.Reader
	name    string
	line    int    // lines returned so far, counted from the start of the file
	partial []byte // the start of a line whose newline hasn't been read yet
	skipNL  bool   // a newline read first ends the last line sealed before
}

func newRecordReader(r io.Reader, name string, line int, skipNL bool) *recordReader {
	return &recordReader{br: bufio.NewReaderSize(r, 64<<10), name: name, line: line, skipNL: skipNL}
}

func (rr *recordReader) tooLong() error {
	return &config.Error{File: rr.name, Line: rr.line + 1, Msg: fmt.Sprintf("longer than %d bytes: a record has to be shorter", MaxLine)}
}

// next returns the next complete line, without its newline; it is valid
// until the next call. At the end of what has been written so far it
// returns io.EOF and keeps the start of an unfinished line for later.
func (rr *recordReader) next() ([]byte, error) {
	for {
		b, err := rr.br.ReadSlice('\n')
		if rr.skipNL && len(b) > 0 {
			rr.skipNL = false
			if b[0] != '\n' {
				return nil, &Problem{File: rr.name, Line: rr.line, Kind: "changed",
					Msg: "the last record sealed grew after it was sealed: it was changed"}
			}
			b = b[1:]
		}
		rr.partial = append(rr.partial, b...)
		switch {
		case err == nil:
			if len(rr.partial) == 0 { // the newline that ended the line sealed before
				continue
			}
			if len(rr.partial)-1 > MaxLine {
				return nil, rr.tooLong()
			}
			line := rr.partial[:len(rr.partial)-1]
			rr.partial = rr.partial[:0]
			rr.line++
			return line, nil
		case len(rr.partial) > MaxLine:
			return nil, rr.tooLong()
		case err == bufio.ErrBufferFull:
		default:
			return nil, err
		}
	}
}

// rest returns an unfinished last line as a complete one, or nil if there
// is none: at the end of a file that is done growing, a last line without a
// newline is still a record.
func (rr *recordReader) rest() []byte {
	if len(rr.partial) == 0 {
		return nil
	}
	line := rr.partial
	rr.partial = nil
	rr.line++
	return line
}
