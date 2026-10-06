// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package exit

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
)

// HashToken returns the SHA-256 of a token: what an exit keeps instead of the
// token itself.
func HashToken(token string) [32]byte { return sha256.Sum256([]byte(token)) }

// HashHex returns a token's token_sha256 value for the configuration file.
func HashHex(token string) string {
	h := HashToken(token)
	return hex.EncodeToString(h[:])
}

// NewToken makes a random token: 32 bytes from the system's random source,
// as 43 characters of URL-safe base64.
func NewToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// Lookup returns the client a token belongs to, or nil. It hashes the token
// and compares the hash with every client's in constant time, always all of
// them, so the time it takes does not say which client came close.
func (c *Config) Lookup(token string) *Client {
	if token == "" {
		return nil
	}
	h := HashToken(token)
	var found *Client
	for _, cl := range c.Clients {
		if subtle.ConstantTimeCompare(h[:], cl.Hash[:]) == 1 {
			found = cl
		}
	}
	return found
}
