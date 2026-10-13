// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

// Package chain is the Ledger file format: a run's events, each linked to
// everything before it by a SHA-256 hash chain, with checkpoints along the
// way and an end line when the run finishes.
//
// A ledger is JSON Lines, readable by eye, and every line has exactly one
// form:
//
//	{"vpnw-ledger":1,"run":"r-3f9a1c"}                 the header
//	{"n":1,"ev":{...the event as vpnw sent it...},"h":"…"}  an event
//	{"n":7,"lost":12,"h":"…"}                          12 events never arrived
//	{"cp":1,"n":100,"h":"…"}                           a checkpoint
//	{"end":143,"cp":2,"h":"…"}                         the run ended here
//
// Entries (events and lost-event marks) are numbered from 1. Each entry's
// hash covers the hash before it, its number and its content:
//
//	h0 = SHA-256("vpnw-ledger v1\n" || header line)
//	h  = SHA-256(h' || 0x00 || N as 8 bytes || the event)       event N
//	h  = SHA-256(h' || 0x01 || N as 8 bytes || count as 8)      lost mark N
//	h  = SHA-256(h' || 0x02 || K as 8 bytes || N as 8)          checkpoint K, after entry N
//	h  = SHA-256(h' || 0x03 || N as 8 bytes || K as 8)          the end, N entries, K checkpoints
//
// where h' is the hash of the line before (all numbers big-endian). Every
// line after the header is a link, so nothing can be removed, added or
// moved without breaking the chain from there on. Ledger also copies each
// checkpoint into the run's own record, as an event, so a ledger rewritten
// from some line on stops matching the copies kept elsewhere.
package chain

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
)

// Version is the format version in the header.
const Version = 1

// Hash is one link of the chain.
type Hash [32]byte

func (h Hash) String() string { return hex.EncodeToString(h[:]) }

// ParseHash reads 64 lower-case hex digits.
func ParseHash(s string) (Hash, error) {
	var h Hash
	if len(s) != 64 || !lowerHex(s) {
		return h, errors.New("a hash is 64 lower-case hex digits")
	}
	hex.Decode(h[:], []byte(s))
	return h, nil
}

func lowerHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

var runRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// Header returns the header line, without its newline.
func Header(run string) ([]byte, error) {
	if !runRe.MatchString(run) {
		return nil, fmt.Errorf("run %q is not a run identifier", run)
	}
	return []byte(`{"vpnw-ledger":1,"run":"` + run + `"}`), nil
}

// Start is h0, the hash a ledger with this header line starts from.
func Start(header []byte) Hash {
	s := sha256.New()
	s.Write([]byte("vpnw-ledger v1\n"))
	s.Write(header)
	var h Hash
	s.Sum(h[:0])
	return h
}

// EventHash is the hash of event entry n after prev.
func EventHash(prev Hash, n uint64, ev []byte) Hash {
	s := sha256.New()
	s.Write(prev[:])
	var b [9]byte
	b[0] = 0
	binary.BigEndian.PutUint64(b[1:], n)
	s.Write(b[:])
	s.Write(ev)
	var h Hash
	s.Sum(h[:0])
	return h
}

// LostHash is the hash of lost-events entry n, of count events, after prev.
func LostHash(prev Hash, n, count uint64) Hash { return link(prev, 1, n, count) }

// CheckpointHash is the hash of checkpoint k, after entry n, after prev.
func CheckpointHash(prev Hash, k, n uint64) Hash { return link(prev, 2, k, n) }

// EndHash is the hash of the end line, after n entries and k checkpoints.
func EndHash(prev Hash, n, k uint64) Hash { return link(prev, 3, n, k) }

func link(prev Hash, kind byte, a, b uint64) Hash {
	s := sha256.New()
	s.Write(prev[:])
	var x [17]byte
	x[0] = kind
	binary.BigEndian.PutUint64(x[1:], a)
	binary.BigEndian.PutUint64(x[9:], b)
	s.Write(x[:])
	var h Hash
	s.Sum(h[:0])
	return h
}

// Writer builds a ledger's lines, one at a time. Each method returns the
// line to append, with its newline.
type Writer struct {
	head   Hash
	n      uint64 // entries so far
	cp     uint64 // checkpoints so far
	cpAt   uint64 // the entry the last checkpoint covered
	ended  bool
	header []byte
}

// NewWriter starts a ledger for a run and returns it with the header line.
func NewWriter(run string) (*Writer, []byte, error) {
	hd, err := Header(run)
	if err != nil {
		return nil, nil, err
	}
	return &Writer{head: Start(hd), header: hd}, append(append([]byte{}, hd...), '\n'), nil
}

// Entries is how many entries the ledger holds; Head the hash of its
// latest line.
func (w *Writer) Entries() uint64 { return w.n }
func (w *Writer) Head() Hash      { return w.head }

// SinceCheckpoint is how many entries no checkpoint covers yet.
func (w *Writer) SinceCheckpoint() uint64 { return w.n - w.cpAt }

// Event adds one event, the JSON object exactly as vpnw sent it.
func (w *Writer) Event(ev []byte) ([]byte, error) {
	if w.ended {
		return nil, errors.New("the ledger has ended")
	}
	if len(ev) == 0 || ev[0] != '{' || bytes.IndexByte(ev, '\n') >= 0 || !json.Valid(ev) {
		return nil, errors.New("an event must be one JSON object on one line")
	}
	w.n++
	w.head = EventHash(w.head, w.n, ev)
	line := make([]byte, 0, len(ev)+100)
	line = append(line, `{"n":`...)
	line = strconv.AppendUint(line, w.n, 10)
	line = append(line, `,"ev":`...)
	line = append(line, ev...)
	line = append(line, `,"h":"`...)
	line = append(line, w.head.String()...)
	line = append(line, "\"}\n"...)
	return line, nil
}

// Lost marks count events that never reached Ledger.
func (w *Writer) Lost(count uint64) ([]byte, error) {
	if w.ended {
		return nil, errors.New("the ledger has ended")
	}
	if count == 0 {
		return nil, errors.New("a lost mark needs a count")
	}
	w.n++
	w.head = LostHash(w.head, w.n, count)
	return fmt.Appendf(nil, `{"n":%d,"lost":%d,"h":"%s"}`+"\n", w.n, count, w.head), nil
}

// Checkpoint covers every entry so far. It returns the line and the
// checkpoint's number.
func (w *Writer) Checkpoint() ([]byte, uint64) {
	w.cp++
	w.cpAt = w.n
	w.head = CheckpointHash(w.head, w.cp, w.n)
	return fmt.Appendf(nil, `{"cp":%d,"n":%d,"h":"%s"}`+"\n", w.cp, w.n, w.head), w.cp
}

// End closes the ledger.
func (w *Writer) End() []byte {
	w.ended = true
	w.head = EndHash(w.head, w.n, w.cp)
	return fmt.Appendf(nil, `{"end":%d,"cp":%d,"h":"%s"}`+"\n", w.n, w.cp, w.head)
}

// Line kinds.
const (
	KHeader = iota + 1
	KEvent
	KLost
	KCheckpoint
	KEnd
)

// Parsed is one ledger line, read back.
type Parsed struct {
	Kind  int
	Run   string // header
	N     uint64 // event, lost, checkpoint: the entry; end: entries in all
	Ev    []byte // event: the event's bytes, a slice of the line
	Count uint64 // lost
	CP    uint64 // checkpoint: its number; end: checkpoints in all
	H     Hash
}

// ErrForm is returned for a line that is not exactly as Ledger writes it.
var ErrForm = errors.New("not a line Ledger writes")

// Parse reads one line, without its newline, and accepts it only in the
// exact form Ledger writes: written out again, it is the same bytes.
func Parse(line []byte) (*Parsed, error) {
	switch {
	case bytes.HasPrefix(line, []byte(`{"vpnw-ledger":`)):
		var h struct {
			V   int    `json:"vpnw-ledger"`
			Run string `json:"run"`
		}
		if json.Unmarshal(line, &h) != nil || h.V != Version {
			return nil, ErrForm
		}
		if hd, err := Header(h.Run); err != nil || !bytes.Equal(hd, line) {
			return nil, ErrForm
		}
		return &Parsed{Kind: KHeader, Run: h.Run}, nil
	case bytes.HasPrefix(line, []byte(`{"n":`)):
		rest := line[len(`{"n":`):]
		n, rest, ok := number(rest)
		if !ok || n == 0 {
			return nil, ErrForm
		}
		const tail = len(`,"h":"`) + 64 + len(`"}`)
		if len(rest) < tail || !bytes.HasPrefix(rest[len(rest)-tail:], []byte(`,"h":"`)) || !bytes.HasSuffix(rest, []byte(`"}`)) {
			return nil, ErrForm
		}
		h, err := ParseHash(string(rest[len(rest)-tail+6 : len(rest)-2]))
		if err != nil {
			return nil, ErrForm
		}
		body := rest[:len(rest)-tail]
		switch {
		case bytes.HasPrefix(body, []byte(`,"ev":`)):
			ev := body[len(`,"ev":`):]
			if len(ev) == 0 || ev[0] != '{' || !json.Valid(ev) {
				return nil, ErrForm
			}
			return &Parsed{Kind: KEvent, N: n, Ev: ev, H: h}, nil
		case bytes.HasPrefix(body, []byte(`,"lost":`)):
			c, more, ok := number(body[len(`,"lost":`):])
			if !ok || c == 0 || len(more) != 0 {
				return nil, ErrForm
			}
			return &Parsed{Kind: KLost, N: n, Count: c, H: h}, nil
		}
		return nil, ErrForm
	case bytes.HasPrefix(line, []byte(`{"cp":`)):
		cp, rest, ok := number(line[len(`{"cp":`):])
		if !ok || cp == 0 || !bytes.HasPrefix(rest, []byte(`,"n":`)) {
			return nil, ErrForm
		}
		n, rest, ok := number(rest[len(`,"n":`):])
		if !ok {
			return nil, ErrForm
		}
		h, ok := hashTail(rest)
		if !ok {
			return nil, ErrForm
		}
		return &Parsed{Kind: KCheckpoint, CP: cp, N: n, H: h}, nil
	case bytes.HasPrefix(line, []byte(`{"end":`)):
		n, rest, ok := number(line[len(`{"end":`):])
		if !ok || !bytes.HasPrefix(rest, []byte(`,"cp":`)) {
			return nil, ErrForm
		}
		k, rest, ok := number(rest[len(`,"cp":`):])
		if !ok {
			return nil, ErrForm
		}
		h, ok := hashTail(rest)
		if !ok {
			return nil, ErrForm
		}
		return &Parsed{Kind: KEnd, N: n, CP: k, H: h}, nil
	}
	return nil, ErrForm
}

// number reads a decimal with no sign and no leading zero.
func number(b []byte) (uint64, []byte, bool) {
	i := 0
	for i < len(b) && i < 20 && b[i] >= '0' && b[i] <= '9' {
		i++
	}
	if i == 0 || (i > 1 && b[0] == '0') {
		return 0, b, false
	}
	n, err := strconv.ParseUint(string(b[:i]), 10, 64)
	if err != nil {
		return 0, b, false
	}
	return n, b[i:], true
}

// hashTail reads `,"h":"<64 hex>"}` and nothing after it.
func hashTail(b []byte) (Hash, bool) {
	if len(b) != len(`,"h":"`)+64+len(`"}`) || !bytes.HasPrefix(b, []byte(`,"h":"`)) || !bytes.HasSuffix(b, []byte(`"}`)) {
		return Hash{}, false
	}
	h, err := ParseHash(string(b[6:70]))
	return h, err == nil
}
