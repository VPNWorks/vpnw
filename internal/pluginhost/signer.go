// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package pluginhost

import (
	"crypto/ed25519"
	crand "crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/tetratelabs/wazero/api"
)

// A plugin with the sign permission has vpnw sign short statements with
// this machine's key, which the plugin never sees. What is signed is
//
//	"vpnw-signed v1\n" || plugin name || "\n" || run || "\n" || statement
//
// so a plugin can only sign in its own name, for the run it is part of.
// Ledger signs its checkpoints this way.

// SignedDomain starts every statement vpnw signs for a plugin.
const SignedDomain = "vpnw-signed v1\n"

// MaxStatement is the longest statement a plugin may have signed.
const MaxStatement = 1024

// Signer holds a signing key for the plugins of one command.
type Signer struct {
	priv ed25519.PrivateKey
	// Public is the key that checks the signatures, "vpnw-ed25519:…".
	Public string
	// File is where the key is kept.
	File string
}

// SignedMessage is what a signature from plugin, in run, over statement
// covers.
func SignedMessage(plugin, run, statement string) []byte {
	return []byte(SignedDomain + plugin + "\n" + run + "\n" + statement)
}

// Sign signs a statement for a plugin in a run.
func (s *Signer) Sign(plugin, run, statement string) []byte {
	return ed25519.Sign(s.priv, SignedMessage(plugin, run, statement))
}

// DefaultSigningKey is where the key is kept unless --sign-key says
// otherwise: ~/.config/vpnw/signing.key, or under $XDG_CONFIG_HOME.
func DefaultSigningKey() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "vpnw", "signing.key"), nil
}

// LoadSigner reads a signing key file. With create, a missing file is made
// first, readable by its owner alone; made says so.
func LoadSigner(file string, create bool) (s *Signer, made bool, err error) {
	b, err := os.ReadFile(file)
	if errors.Is(err, os.ErrNotExist) && create {
		made, err = makeKeyFile(file)
		if err != nil {
			return nil, false, err
		}
		// Ours, or another command's that made it first: read what's there.
		b, err = os.ReadFile(file)
	}
	if err != nil {
		return nil, false, err
	}
	text := strings.TrimSpace(string(b))
	if !strings.HasPrefix(text, privPrefix) {
		return nil, false, fmt.Errorf("%s is not a vpnw signing key (a signing key starts with %q; a public key can't sign)", file, privPrefix)
	}
	seed, err := base64.StdEncoding.DecodeString(text[len(privPrefix):])
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, false, fmt.Errorf("%s is not a valid Ed25519 signing key", file)
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	return &Signer{priv: priv, Public: pubPrefix + base64.StdEncoding.EncodeToString(pub), File: file}, made, nil
}

// makeKeyFile writes a new key to file whole, then puts it in place, so no
// one reads half a key; when another command put one there first, it is
// kept and made is false.
func makeKeyFile(file string) (made bool, err error) {
	_, priv, err := GenerateKey()
	if err != nil {
		return false, err
	}
	if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
		return false, err
	}
	tmp, err := os.CreateTemp(filepath.Dir(file), ".signing-key-*")
	if err != nil {
		return false, err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return false, err
	}
	_, werr := tmp.WriteString(priv + "\n")
	if serr := tmp.Sync(); werr == nil {
		werr = serr
	}
	if cerr := tmp.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return false, werr
	}
	// A link never replaces a file that's there.
	if err := os.Link(tmp.Name(), file); err != nil {
		if errors.Is(err, os.ErrExist) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

// NewSigner makes a signer with a fresh key that is kept nowhere, for tests.
func NewSigner() *Signer {
	pub, priv, _ := ed25519.GenerateKey(crand.Reader)
	return &Signer{priv: priv, Public: pubPrefix + base64.StdEncoding.EncodeToString(pub)}
}

// VerifySigned checks a signature from plugin, in run, over statement, by
// the public key pub ("vpnw-ed25519:…").
func VerifySigned(pub, plugin, run, statement string, sig []byte) bool {
	k, err := ParsePublicKey(pub)
	return err == nil && len(sig) == ed25519.SignatureSize && ed25519.Verify(k, SignedMessage(plugin, run, statement), sig)
}

func signKey(opt Options, m *Manifest) string {
	if opt.Signer == nil || !m.Has(PermSign) {
		return ""
	}
	return opt.Signer.Public
}

// sign is the sign host call: the statement at p, n bytes, signed into the
// 64 bytes at out. 0 for success, 1 for failure, the reason in the
// plugin's log.
func (in *Instance) sign(m api.Module, p, n, out uint32) uint32 {
	if n == 0 || n > MaxStatement {
		in.signErr(fmt.Sprintf("a statement to sign is 1 to %d bytes", MaxStatement))
		return 1
	}
	st, ok := m.Memory().Read(p, n)
	if !ok {
		in.signErr("the statement is outside the plugin's memory")
		return 1
	}
	for _, c := range st {
		if c < 0x20 || c > 0x7e {
			in.signErr("a statement to sign is printable ASCII on one line")
			return 1
		}
	}
	sig := in.opt.Signer.Sign(in.Name(), in.opt.Run, string(st))
	if !m.Memory().Write(out, sig) {
		in.signErr("the place for the signature is outside the plugin's memory")
		return 1
	}
	return 0
}

func (in *Instance) signErr(why string) {
	if in.opt.Log != nil {
		in.opt.Log(in.Name(), "sign: "+why)
	}
}
