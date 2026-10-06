// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"vpnw.com/vpnw/internal/config"
)

// Proof shows that one record is in a log. Checking it takes the public key
// and nothing else: no other record, no ledger.
type Proof struct {
	Line       int         // the record's line in the records file, 1 for the first
	Record     []byte      // the record itself
	Leaf       Hash        // its hash
	Path       []Hash      // the hashes from the leaf up to the root, nearest first
	Checkpoint *Checkpoint // the signed checkpoint whose root the path leads to
}

// MaxPath is the longest audit path a proof may hold: enough for 2^64
// records.
const MaxPath = 64

// Prove makes a proof that record, line n of the records file recName, is
// in the log, against the ledger's last checkpoint.
func Prove(led *Ledger, recName string, n int, record []byte) (*Proof, error) {
	if led.Problem != nil {
		return nil, led.Problem
	}
	if len(led.Checkpoints) == 0 {
		return nil, &config.Error{File: led.Name, Msg: "the ledger has no checkpoint yet: seal first"}
	}
	i := len(led.Checkpoints) - 1
	c := led.Checkpoints[i]
	if n < 1 || n > c.Size {
		return nil, &config.Error{File: recName, Line: n, Msg: fmt.Sprintf("no checkpoint covers this line: the last one covers lines 1 to %d", c.Size)}
	}
	leaf := LeafHash(record)
	if leaf != led.Leaves[n-1] {
		return nil, &Problem{File: recName, Line: n, Kind: "changed", Msg: "the record doesn't match its sealed hash: it was changed, so there is no proof for it"}
	}
	path := AuditPath(led.Leaves[:c.Size], n-1)
	if root, err := RootFromPath(leaf, n-1, c.Size, path); err != nil || root != c.Root {
		return nil, &Problem{File: led.Name, Line: led.CPLines[i], Kind: "changed", Msg: fmt.Sprintf("checkpoint %d doesn't match the hashes sealed before it: run verify", c.Seq)}
	}
	return &Proof{Line: n, Record: append([]byte(nil), record...), Leaf: leaf, Path: path, Checkpoint: c}, nil
}

// JSON is the proof as a small JSON document, one field per line.
func (p *Proof) JSON() []byte {
	var b bytes.Buffer
	rec, _ := json.Marshal(string(p.Record))
	fmt.Fprintf(&b, "{\n  \"vpnw-ledger-proof\": 1,\n  \"line\": %d,\n  \"record\": %s,\n  \"leaf\": \"%s\",\n  \"path\": [", p.Line, rec, p.Leaf)
	for i, h := range p.Path {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "\n    \"%s\"", h)
	}
	if len(p.Path) > 0 {
		b.WriteString("\n  ")
	}
	fmt.Fprintf(&b, "],\n  \"checkpoint\": %s\n}\n", p.Checkpoint.AppendJSON(nil))
	return b.Bytes()
}

// ParseProof reads a proof as JSON writes it; any layout of the JSON works.
func ParseProof(b []byte) (*Proof, error) {
	var j struct {
		V          int             `json:"vpnw-ledger-proof"`
		Line       int             `json:"line"`
		Record     *string         `json:"record"`
		Leaf       string          `json:"leaf"`
		Path       []string        `json:"path"`
		Checkpoint json.RawMessage `json:"checkpoint"`
	}
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&j); err != nil {
		return nil, fmt.Errorf("not a vpnw-ledger proof: %v", err)
	}
	if dec.Decode(&struct{}{}) != io.EOF {
		return nil, errors.New("not a vpnw-ledger proof: something follows it")
	}
	switch {
	case j.V != 1:
		return nil, errors.New(`not a vpnw-ledger proof: want "vpnw-ledger-proof": 1`)
	case j.Record == nil:
		return nil, errors.New("the proof holds no record")
	case len(j.Path) > MaxPath:
		return nil, fmt.Errorf("the path has %d hashes; no log is that big", len(j.Path))
	}
	p := &Proof{Line: j.Line, Record: []byte(*j.Record)}
	var err error
	if p.Leaf, err = ParseHash(j.Leaf); err != nil {
		return nil, fmt.Errorf("leaf: %v", err)
	}
	for i, s := range j.Path {
		h, err := ParseHash(s)
		if err != nil {
			return nil, fmt.Errorf("path[%d]: %v", i, err)
		}
		p.Path = append(p.Path, h)
	}
	if p.Checkpoint, err = decodeCheckpoint(j.Checkpoint); err != nil {
		return nil, fmt.Errorf("checkpoint: %v", err)
	}
	return p, nil
}

// Check checks the proof with the public key alone: the checkpoint is
// signed by pub, the record has the proof's hash, and the path leads from
// that hash at the record's line to the signed root.
func (p *Proof) Check(pub *PublicKey) error {
	c := p.Checkpoint
	if err := c.Check(pub); err != nil {
		return fmt.Errorf("checkpoint %d: %v", c.Seq, err)
	}
	if p.Line < 1 || p.Line > c.Size {
		return fmt.Errorf("line %d is outside checkpoint %d, which covers lines 1 to %d", p.Line, c.Seq, c.Size)
	}
	if LeafHash(p.Record) != p.Leaf {
		return errors.New("the record doesn't match the proof's hash: it was changed")
	}
	root, err := RootFromPath(p.Leaf, p.Line-1, c.Size, p.Path)
	if err != nil {
		return err
	}
	if root != c.Root {
		return fmt.Errorf("the path doesn't lead to the root signed in checkpoint %d: this record isn't on line %d of the log", c.Seq, p.Line)
	}
	return nil
}
