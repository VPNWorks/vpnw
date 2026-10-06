// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"strings"

	"vpnw.com/vpnw/internal/config"
)

// PublicKey checks checkpoints. Its ID is written into every checkpoint it
// checks.
type PublicKey struct {
	ID  string
	Key ed25519.PublicKey
}

// PrivateKey signs checkpoints.
type PrivateKey struct {
	ID  string
	Key ed25519.PrivateKey
}

// KeyID names a public key: "k-" and the first 8 hex digits of its SHA-256.
func KeyID(pub ed25519.PublicKey) string {
	h := sha256.Sum256(pub)
	return "k-" + hex.EncodeToString(h[:4])
}

// NewKey makes a key pair from the random source, usually crypto/rand.
func NewKey(random io.Reader) (*PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(random)
	if err != nil {
		return nil, err
	}
	return &PrivateKey{ID: KeyID(pub), Key: priv}, nil
}

// Public is the key's public half.
func (k *PrivateKey) Public() *PublicKey {
	return &PublicKey{ID: k.ID, Key: k.Key.Public().(ed25519.PublicKey)}
}

// Text is the public key file:
//
//	# vpnw-ledger public key k-1a2b3c4d. ...
//	version = 1
//	id = "k-1a2b3c4d"
//	public = "ed25519 BASE64"
func (k *PublicKey) Text() string {
	return fmt.Sprintf("# vpnw-ledger public key %s. Whoever checks the ledger needs it. It can't sign.\n"+
		"version = 1\nid = %q\npublic = \"ed25519 %s\"\n", k.ID, k.ID, base64.StdEncoding.EncodeToString(k.Key))
}

// Text is the private key file. It holds the 32-byte Ed25519 seed.
func (k *PrivateKey) Text() string {
	return fmt.Sprintf("# vpnw-ledger private key %s. Keep it secret: whoever holds it can sign checkpoints.\n"+
		"version = 1\nid = %q\nprivate = \"ed25519 %s\"\n", k.ID, k.ID, base64.StdEncoding.EncodeToString(k.Key.Seed()))
}

func keyErr(file string, line int, format string, a ...any) error {
	return &config.Error{File: file, Line: line, Msg: fmt.Sprintf(format, a...)}
}

// readKey reads a key file and returns the 32 bytes after "ed25519" under
// want ("public" or "private"), and the ID the file gives.
func readKey(src, file, want string) (raw []byte, id string, idLine int, err error) {
	doc, err := config.Parse(src)
	if err != nil {
		if ce, ok := err.(*config.Error); ok {
			ce.File = file
		}
		return nil, "", 0, err
	}
	if len(doc.Order) > 1 {
		t := doc.Tables[doc.Order[1]]
		return nil, "", 0, keyErr(file, t.Line, "a key file has no tables")
	}
	other := map[string]string{"public": "private", "private": "public"}[want]
	root := doc.Tables[""]
	var val string
	valLine := 0
	for _, k := range root.Order {
		v := root.Keys[k]
		switch k {
		case "version":
			if v.Kind != config.KInt || v.Int != 1 {
				return nil, "", 0, keyErr(file, v.Line, "version must be 1")
			}
			continue
		case "id", want:
		case other:
			if want == "public" {
				return nil, "", 0, keyErr(file, v.Line, "this is a private key: give the public key, the .pub file")
			}
			return nil, "", 0, keyErr(file, v.Line, "this is a public key, which can't sign: give the private key, the .key file")
		default:
			return nil, "", 0, keyErr(file, v.Line, "unknown key %q (known: version, id, %s)", k, want)
		}
		if v.Kind != config.KString {
			return nil, "", 0, keyErr(file, v.Line, "%s must be a string", k)
		}
		if k == "id" {
			id, idLine = v.Str, v.Line
		} else {
			val, valLine = v.Str, v.Line
		}
	}
	if _, ok := root.Keys["version"]; !ok {
		return nil, "", 0, keyErr(file, 1, "missing version = 1: this is not a vpnw-ledger key file")
	}
	if valLine == 0 {
		return nil, "", 0, keyErr(file, 1, "missing %s = \"ed25519 ...\"", want)
	}
	if idLine == 0 {
		return nil, "", 0, keyErr(file, 1, "missing id = \"k-...\"")
	}
	alg, b64, _ := strings.Cut(val, " ")
	if alg != "ed25519" {
		return nil, "", 0, keyErr(file, valLine, "%s: want \"ed25519\" and the key in base64", want)
	}
	raw, err = base64.StdEncoding.DecodeString(b64)
	if err != nil || len(raw) != 32 {
		return nil, "", 0, keyErr(file, valLine, "%s: want 44 characters of base64 for 32 bytes", want)
	}
	return raw, id, idLine, nil
}

// ParsePublicKey reads a public key file; file names it in errors.
func ParsePublicKey(src, file string) (*PublicKey, error) {
	raw, id, idLine, err := readKey(src, file, "public")
	if err != nil {
		return nil, err
	}
	k := &PublicKey{ID: KeyID(raw), Key: ed25519.PublicKey(raw)}
	if id != k.ID {
		return nil, keyErr(file, idLine, "id %s doesn't match the key, whose ID is %s", id, k.ID)
	}
	return k, nil
}

// ParsePrivateKey reads a private key file; file names it in errors.
func ParsePrivateKey(src, file string) (*PrivateKey, error) {
	raw, id, idLine, err := readKey(src, file, "private")
	if err != nil {
		return nil, err
	}
	priv := ed25519.NewKeyFromSeed(raw)
	k := &PrivateKey{ID: KeyID(priv.Public().(ed25519.PublicKey)), Key: priv}
	if id != k.ID {
		return nil, keyErr(file, idLine, "id %s doesn't match the key, whose ID is %s", id, k.ID)
	}
	return k, nil
}
