// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

// Package exit holds what an exit (vpnw exit) needs besides the broker that
// serves it: its configuration, its clients' tokens, the addresses they
// leave from, and the certificates that make a private CA.
//
// An exit is the server end of a path. It runs on a machine with fixed
// addresses and takes requests over TLS from its clients, each known by a
// token. The broker decides each request with that client's own policy,
// with the same code that decides a run's requests, and connects from the
// client's fixed address (broker.Exit).
package exit

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/VPNWorks/vpnw/internal/broker"
	"github.com/VPNWorks/vpnw/internal/path"
)

// HashToken returns the SHA-256 of a token: what an exit keeps instead of
// the token itself.
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

// Clients are an exit's clients as the broker sees them: each with its
// policy and a direct path from its own address.
type Clients struct {
	hashes [][32]byte
	list   []*broker.Client
}

// BrokerClients makes the broker's view of the clients.
func (c *Config) BrokerClients() *Clients {
	out := &Clients{}
	for _, cl := range c.Clients {
		a := cl.Address()
		p := &path.Direct{Dialer: net.Dialer{LocalAddr: &net.TCPAddr{IP: a.AsSlice()}}}
		out.hashes = append(out.hashes, cl.Hash)
		out.list = append(out.list, &broker.Client{Name: cl.Name, Policy: cl.Policy, Path: p, Source: a.String()})
	}
	return out
}

// Login returns the client a token belongs to, or nil. It hashes the token
// and compares the hash with every client's in constant time, always all of
// them, so the time it takes doesn't say which client came close.
func (c *Clients) Login(token string) *broker.Client {
	if token == "" {
		return nil
	}
	h := HashToken(token)
	var found *broker.Client
	for i := range c.hashes {
		if subtle.ConstantTimeCompare(h[:], c.hashes[i][:]) == 1 {
			found = c.list[i]
		}
	}
	return found
}

// CheckSources makes sure every source address is on this machine, by
// binding a socket to each: a connection can't leave from an address the
// machine doesn't have.
func (c *Config) CheckSources() error {
	var missing []string
	for _, a := range c.Sources() {
		l, err := net.Listen("tcp", netip.AddrPortFrom(a, 0).String())
		if err != nil {
			missing = append(missing, a.String())
			continue
		}
		l.Close()
	}
	switch len(missing) {
	case 0:
		return nil
	case 1:
		return fmt.Errorf("source address %s is not on this machine", missing[0])
	}
	return fmt.Errorf("source addresses %s are not on this machine", strings.Join(missing, ", "))
}
