// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"
)

// Checkpoint is a signed statement about the first Size records of a log.
type Checkpoint struct {
	Log   string    // the log's name, the same in every checkpoint of a ledger
	Seq   int       // 1 for the first checkpoint, then 2, 3 and so on
	Size  int       // how many records it covers
	Root  Hash      // the Merkle tree hash of their leaf hashes
	Chain Hash      // the chain hash after the last of them
	Prev  Hash      // Hash() of the checkpoint before, zero for the first
	Time  time.Time // when it was signed, in UTC, to the second
	Key   string    // the ID of the key that signed it
	Sig   []byte    // Ed25519 signature of Message()
}

// Message is the text the signature covers, one field per line. Anyone can
// rebuild it from the checkpoint's JSON line and check it with any Ed25519
// tool.
func (c *Checkpoint) Message() []byte {
	return fmt.Appendf(nil, "vpnw-ledger checkpoint v1\nlog %s\ncp %d\nsize %d\nroot %s\nchain %s\nprev %s\ntime %s\nkey %s\n",
		c.Log, c.Seq, c.Size, c.Root, c.Chain, c.Prev, c.Time.UTC().Format(time.RFC3339), c.Key)
}

// Hash identifies a checkpoint: the SHA-256 of its Message. The next
// checkpoint carries it as Prev.
func (c *Checkpoint) Hash() Hash { return sha256.Sum256(c.Message()) }

// Sign signs the checkpoint with k and sets its Key.
func (c *Checkpoint) Sign(k *PrivateKey) {
	c.Key = k.ID
	c.Sig = ed25519.Sign(k.Key, c.Message())
}

// Check reports whether pub signed the checkpoint.
func (c *Checkpoint) Check(pub *PublicKey) error {
	if c.Key != pub.ID {
		return fmt.Errorf("signed by key %s, not by %s, the key given", c.Key, pub.ID)
	}
	if !ed25519.Verify(pub.Key, c.Message(), c.Sig) {
		return fmt.Errorf("the signature doesn't match key %s: the checkpoint was changed or forged", pub.ID)
	}
	return nil
}

// When is the time for people: "2026-10-05 10:00:00 UTC".
func (c *Checkpoint) When() string { return c.Time.UTC().Format("2006-01-02 15:04:05 UTC") }

// AppendJSON appends the checkpoint as one line of JSON, without the newline:
//
//	{"cp":3,"size":24,"root":"…","chain":"…","prev":"…","time":"2026-10-05T10:00:00Z","key":"k-1a2b3c4d","log":"trace.jsonl","sig":"…"}
func (c *Checkpoint) AppendJSON(b []byte) []byte {
	b = append(b, `{"cp":`...)
	b = strconv.AppendInt(b, int64(c.Seq), 10)
	b = append(b, `,"size":`...)
	b = strconv.AppendInt(b, int64(c.Size), 10)
	b = append(b, `,"root":"`...)
	b = append(b, c.Root.String()...)
	b = append(b, `","chain":"`...)
	b = append(b, c.Chain.String()...)
	b = append(b, `","prev":"`...)
	b = append(b, c.Prev.String()...)
	b = append(b, `","time":"`...)
	b = c.Time.UTC().AppendFormat(b, time.RFC3339)
	b = append(b, `","key":"`...)
	b = append(b, c.Key...)
	b = append(b, `","log":"`...)
	b = append(b, c.Log...)
	b = append(b, `","sig":"`...)
	b = base64.StdEncoding.AppendEncode(b, c.Sig)
	return append(b, `"}`...)
}

// ValidLogName reports whether s can name a log: 1 to 128 printable ASCII
// characters, without " or \.
func ValidLogName(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 || c > 0x7e || c == '"' || c == '\\' {
			return false
		}
	}
	return true
}

func validKeyID(s string) bool { return len(s) == 10 && s[:2] == "k-" && lowerHex(s[2:]) }

// ParseCheckpoint reads a checkpoint line of a ledger. It accepts the line
// only exactly as AppendJSON writes it, so every checkpoint in a ledger has
// one form.
func ParseCheckpoint(line []byte) (*Checkpoint, error) {
	c, err := decodeCheckpoint(line)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(c.AppendJSON(nil), line) {
		return nil, errors.New("not exactly as seal writes a checkpoint")
	}
	return c, nil
}

// decodeCheckpoint reads a checkpoint's fields from JSON in any layout, as
// in a proof that went through a JSON tool. The signature covers the fields,
// not their layout.
func decodeCheckpoint(b []byte) (*Checkpoint, error) {
	var j struct {
		CP                      int
		Size                    int
		Root, Chain, Prev, Time string
		Key, Log, Sig           string
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&j); err != nil {
		return nil, fmt.Errorf("not a checkpoint: %v", err)
	}
	c := &Checkpoint{Seq: j.CP, Size: j.Size, Key: j.Key, Log: j.Log}
	var err error
	switch {
	case c.Seq < 1:
		return nil, errors.New("cp must be 1 or more")
	case c.Size < 1:
		return nil, errors.New("size must be 1 or more")
	case !ValidLogName(c.Log):
		return nil, errors.New("log: want 1 to 128 printable characters")
	case !validKeyID(c.Key):
		return nil, errors.New("key: want k- and 8 hex digits")
	}
	for _, f := range []struct {
		name string
		s    string
		h    *Hash
	}{{"root", j.Root, &c.Root}, {"chain", j.Chain, &c.Chain}, {"prev", j.Prev, &c.Prev}} {
		if *f.h, err = ParseHash(f.s); err != nil {
			return nil, fmt.Errorf("%s: %v", f.name, err)
		}
	}
	if c.Time, err = time.Parse(time.RFC3339, j.Time); err != nil {
		return nil, fmt.Errorf("time: want a time such as 2026-10-05T10:00:00Z")
	}
	if c.Sig, err = base64.StdEncoding.DecodeString(j.Sig); err != nil || len(c.Sig) != ed25519.SignatureSize {
		return nil, errors.New("sig: want 88 characters of base64 for 64 bytes")
	}
	return c, nil
}
