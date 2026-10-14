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
	"context"
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

// BrokerClients makes the broker's view of the clients. The exit's own
// addresses are taken from the machine now, when the exit starts.
func (c *Config) BrokerClients() *Clients {
	own := map[netip.Addr]bool{}
	if addrs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range addrs {
			if n, ok := a.(*net.IPNet); ok {
				if x, ok := netip.AddrFromSlice(n.IP); ok {
					own[x.Unmap()] = true
				}
			}
		}
	}
	for _, a := range c.Sources() {
		own[a] = true
	}
	out := &Clients{}
	for _, cl := range c.Clients {
		a := cl.Address()
		p := &exitPath{Direct: path.Direct{Dialer: net.Dialer{LocalAddr: &net.TCPAddr{IP: a.AsSlice()}}}, client: cl.Name, src: a, host: cl.ExitHost, own: own}
		out.hashes = append(out.hashes, cl.Hash)
		out.list = append(out.list, &broker.Client{Name: cl.Name, Policy: cl.Policy, Path: p, Source: a.String()})
	}
	return out
}

// exitPath is how a client's connections leave an exit: directly, from the
// client's own address. Whatever the client's policy says, it refuses the
// exit's own machine (its loopback and its addresses) unless the exit's
// file lets that client reach it (allow_exit_host), and link-local,
// multicast and unspecified addresses always: from an exit they could only
// reach its own network segment, where a cloud's metadata service lives.
// It also checks that each connection really left from the client's
// address.
type exitPath struct {
	path.Direct
	client string
	src    netip.Addr
	host   bool
	own    map[netip.Addr]bool
}

var broadcast = netip.AddrFrom4([4]byte{255, 255, 255, 255})

func (p *exitPath) Dial(ctx context.Context, host string, ip net.IP, port int) (net.Conn, error) {
	a, ok := netip.AddrFromSlice(ip)
	if !ok {
		return nil, fmt.Errorf("no address to dial")
	}
	a = a.Unmap()
	switch {
	case a.IsUnspecified() || a.IsMulticast() || a.IsLinkLocalUnicast() || a == broadcast:
		return nil, fmt.Errorf("%s is never reached from an exit: it's a link-local, multicast or unspecified address", a)
	case !p.host && (a.IsLoopback() || p.own[a]):
		return nil, fmt.Errorf("%s is the exit's own machine, which client %s may not reach (allow_exit_host)", a, p.client)
	}
	c, err := p.Direct.Dial(ctx, host, ip, port)
	if err != nil {
		return nil, err
	}
	la, _ := c.LocalAddr().(*net.TCPAddr)
	if la == nil {
		c.Close()
		return nil, fmt.Errorf("can't tell which address the connection left from")
	}
	if got, ok := netip.AddrFromSlice(la.IP); !ok || got.Unmap() != p.src {
		c.Close()
		return nil, fmt.Errorf("the connection left from %s, not from client %s's address %s", la.IP, p.client, p.src)
	}
	return c, nil
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
