// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package pluginhost

import (
	"crypto/ed25519"
	crand "crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
)

// Plugin signatures are Ed25519 over a hash of the manifest and the module:
//
//	sha256("vpnw-plugin-signature-v1\n" || sha256(plugin.toml) || sha256(plugin.wasm))
//
// plugin.sig holds two lines: the signer's public key and the signature.
// A key is written "vpnw-ed25519:<base64>"; a private key file holds
// "vpnw-ed25519-private:<base64 seed>".

const (
	pubPrefix  = "vpnw-ed25519:"
	privPrefix = "vpnw-ed25519-private:"
	sigDomain  = "vpnw-plugin-signature-v1\n"
)

// GenerateKey makes a signing key pair, as text.
func GenerateKey() (public, private string, err error) {
	pub, priv, err := ed25519.GenerateKey(crand.Reader)
	if err != nil {
		return "", "", err
	}
	return pubPrefix + base64.StdEncoding.EncodeToString(pub),
		privPrefix + base64.StdEncoding.EncodeToString(priv.Seed()), nil
}

func digest(manifest, wasm []byte) []byte {
	m := sha256.Sum256(manifest)
	w := sha256.Sum256(wasm)
	h := sha256.New()
	h.Write([]byte(sigDomain))
	h.Write(m[:])
	h.Write(w[:])
	return h.Sum(nil)
}

// ParsePublicKey reads "vpnw-ed25519:<base64>".
func ParsePublicKey(s string) (ed25519.PublicKey, error) {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, pubPrefix) {
		return nil, fmt.Errorf("a public key starts with %q", pubPrefix)
	}
	b, err := base64.StdEncoding.DecodeString(s[len(pubPrefix):])
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, errors.New("not a valid Ed25519 public key")
	}
	return ed25519.PublicKey(b), nil
}

// Sign signs a plugin with a private key file's text.
func Sign(private string, manifest, wasm []byte) (string, error) {
	private = strings.TrimSpace(private)
	if !strings.HasPrefix(private, privPrefix) {
		return "", fmt.Errorf("a private key starts with %q", privPrefix)
	}
	seed, err := base64.StdEncoding.DecodeString(private[len(privPrefix):])
	if err != nil || len(seed) != ed25519.SeedSize {
		return "", errors.New("not a valid Ed25519 private key")
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	sig := ed25519.Sign(priv, digest(manifest, wasm))
	return pubPrefix + base64.StdEncoding.EncodeToString(pub) + "\n" + base64.StdEncoding.EncodeToString(sig) + "\n", nil
}

// Verify checks plugin.sig and returns the signer's key. The signer must be
// among trusted.
func Verify(sig string, manifest, wasm []byte, trusted []string) (string, error) {
	lines := strings.Fields(sig)
	if len(lines) != 2 {
		return "", errors.New("plugin.sig must hold the signer's key and the signature, one per line")
	}
	pub, err := ParsePublicKey(lines[0])
	if err != nil {
		return "", fmt.Errorf("plugin.sig: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(lines[1])
	if err != nil || len(raw) != ed25519.SignatureSize {
		return "", errors.New("plugin.sig: not a valid signature")
	}
	if !ed25519.Verify(pub, digest(manifest, wasm), raw) {
		return "", errors.New("the signature does not match plugin.toml and plugin.wasm: the files were changed after signing")
	}
	key := strings.TrimSpace(lines[0])
	for _, t := range trusted {
		if strings.TrimSpace(t) == key {
			return key, nil
		}
	}
	return key, fmt.Errorf("signed by %s, which is not a trusted key (vpnw plugin trust KEY)", key)
}
