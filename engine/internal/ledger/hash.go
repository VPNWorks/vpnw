// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

// Package ledger makes a log of records tamper-evident, and checks it.
//
// The records stay untouched in their own JSON Lines file, one record per
// line. Ledger writes a second file next to it, also JSON Lines: one line
// per record with its number and hash, and at intervals a checkpoint signed
// with Ed25519. A checkpoint vouches for every record before it twice: by
// the root of a Merkle tree over their hashes, as in RFC 6962, which lets
// anyone check one record without seeing the others, and by a hash chain in
// which each link covers the one before. It also carries the hash of the
// checkpoint before it, so no checkpoint can be dropped, replayed or moved
// without it showing.
//
// Checking needs the two files and the public key, nothing else. Verify
// recomputes every hash from the records and names the first line that
// doesn't match. Records carry no payloads, so the files can go to an
// auditor as they are.
package ledger

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
)

// Version is the Ledger engine's version.
const Version = "0.1.0"

// MaxLine is the longest record seal accepts, in bytes.
const MaxLine = 64 << 10

// Hash is a SHA-256 hash.
type Hash [32]byte

// String is the hash in lowercase hex, as sha256sum prints it.
func (h Hash) String() string { return hex.EncodeToString(h[:]) }

func lowerHex[S ~string | ~[]byte](s S) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// ParseHash reads 64 lowercase hex digits.
func ParseHash(s string) (Hash, error) {
	var h Hash
	if len(s) != 64 || !lowerHex(s) {
		return h, errors.New("a hash is 64 lowercase hex digits")
	}
	hex.Decode(h[:], []byte(s))
	return h, nil
}

// The first byte of everything hashed says what it is, so that a record can
// never pass for a node of the tree or a link of the chain.
const (
	leafPrefix  = 0x00
	nodePrefix  = 0x01
	chainPrefix = 0x02
)

// LeafHash is a record's hash: SHA-256(0x00 || record).
func LeafHash(record []byte) Hash {
	d := sha256.New()
	d.Write([]byte{leafPrefix})
	d.Write(record)
	var h Hash
	d.Sum(h[:0])
	return h
}

// NodeHash joins two subtrees: SHA-256(0x01 || left || right).
func NodeHash(left, right Hash) Hash {
	var b [65]byte
	b[0] = nodePrefix
	copy(b[1:], left[:])
	copy(b[33:], right[:])
	return sha256.Sum256(b[:])
}

// ChainHash links a record to everything before it:
// SHA-256(0x02 || previous link || leaf). The link before the first record
// is 32 zero bytes.
func ChainHash(prev, leaf Hash) Hash {
	var b [65]byte
	b[0] = chainPrefix
	copy(b[1:], prev[:])
	copy(b[33:], leaf[:])
	return sha256.Sum256(b[:])
}

// Tree is the Merkle tree and the chain over the records sealed so far. It
// grows one leaf at a time and keeps only the roots of its complete
// subtrees, one for each bit set in its size.
type Tree struct {
	size  int
	full  []Hash // full[i] is the root of a complete subtree of 2^i leaves, when bit i of size is set
	chain Hash
}

// Add appends one leaf.
func (t *Tree) Add(leaf Hash) {
	t.chain = ChainHash(t.chain, leaf)
	h, i := leaf, 0
	for ; t.size>>i&1 == 1; i++ {
		h = NodeHash(t.full[i], h)
	}
	if i == len(t.full) {
		t.full = append(t.full, h)
	} else {
		t.full[i] = h
	}
	t.size++
}

// Size is the number of leaves.
func (t *Tree) Size() int { return t.size }

// Chain is the chain hash after the last leaf.
func (t *Tree) Chain() Hash { return t.chain }

// Root is the Merkle tree hash of the leaves, as RFC 6962 defines it: the
// complete subtrees joined from the smallest, on the right, to the largest.
func (t *Tree) Root() Hash {
	if t.size == 0 {
		return sha256.Sum256(nil)
	}
	var r Hash
	first := true
	for i := range t.full {
		if t.size>>i&1 == 0 {
			continue
		}
		if first {
			r, first = t.full[i], false
		} else {
			r = NodeHash(t.full[i], r)
		}
	}
	return r
}

// split is the largest power of two smaller than n, for n > 1.
func split(n int) int {
	k := 1
	for k<<1 < n {
		k <<= 1
	}
	return k
}

// RootOf is the Merkle tree hash of leaves, by RFC 6962's definition:
// the hash of the empty string for no leaves, the leaf itself for one, and
// otherwise the node over the first split(n) leaves and the rest.
func RootOf(leaves []Hash) Hash {
	switch len(leaves) {
	case 0:
		return sha256.Sum256(nil)
	case 1:
		return leaves[0]
	}
	k := split(len(leaves))
	return NodeHash(RootOf(leaves[:k]), RootOf(leaves[k:]))
}

// AuditPath is the list of hashes that links leaf m to the root of leaves,
// nearest first: RFC 6962's PATH(m, D[n]).
func AuditPath(leaves []Hash, m int) []Hash {
	if len(leaves) <= 1 {
		return nil
	}
	k := split(len(leaves))
	if m < k {
		return append(AuditPath(leaves[:k], m), RootOf(leaves[k:]))
	}
	return append(AuditPath(leaves[k:], m-k), RootOf(leaves[:k]))
}

// RootFromPath climbs from leaf number index of a tree of size leaves to
// its root along path, as in RFC 9162 section 2.1.3.2. The result matches
// the signed root only if the leaf is in the tree at that place.
func RootFromPath(leaf Hash, index, size int, path []Hash) (Hash, error) {
	if index < 0 || index >= size {
		return Hash{}, errors.New("the record's place is outside the tree")
	}
	fn, sn, r := index, size-1, leaf
	for _, p := range path {
		if sn == 0 {
			return Hash{}, errors.New("the path is too long for the tree")
		}
		if fn&1 == 1 || fn == sn {
			r = NodeHash(p, r)
			for fn&1 == 0 && fn != 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			r = NodeHash(r, p)
		}
		fn >>= 1
		sn >>= 1
	}
	if sn != 0 {
		return Hash{}, errors.New("the path is too short for the tree")
	}
	return r, nil
}
