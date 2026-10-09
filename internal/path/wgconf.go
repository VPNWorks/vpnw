// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package path

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
)

// WGConf is a WireGuard configuration in the wg-quick format, the one VPN
// providers hand out and `wg` and `wg-quick` read:
//
//	[Interface]
//	PrivateKey = <base64>
//	Address = 10.64.0.2/32, fc00:bbbb::2/128
//	DNS = 10.64.0.1
//
//	[Peer]
//	PublicKey = <base64>
//	Endpoint = vpn.example.com:51820
//	AllowedIPs = 0.0.0.0/0, ::/0
//
// As with vpnw's own files, anything it doesn't know is an error, never
// silently skipped. wg-quick's shell hooks (PreUp, PostUp, PreDown,
// PostDown) are refused: vpnw runs no commands from a config file.
type WGConf struct {
	PrivateKey [32]byte
	Addresses  []netip.Prefix
	DNS        []netip.Addr
	MTU        int
	ListenPort int
	Peers      []WGPeer
	Source     string
}

// WGPeer is one [Peer] section.
type WGPeer struct {
	PublicKey    [32]byte
	PresharedKey *[32]byte
	Endpoint     string // host:port as written
	AllowedIPs   []netip.Prefix
	Keepalive    int
}

// DefaultMTU is wg-quick's usual MTU for a tunnel over IPv4 or IPv6.
const DefaultMTU = 1420

// LoadWGConf reads a wg-quick file.
func LoadWGConf(file string) (*WGConf, error) {
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	c, err := ParseWGConf(string(b))
	if err != nil {
		return nil, fmt.Errorf("%s: %v", file, err)
	}
	c.Source = file
	return c, nil
}

func wgKey(s string) ([32]byte, error) {
	var k [32]byte
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil || len(b) != 32 {
		return k, fmt.Errorf("not a WireGuard key (32 bytes in base64)")
	}
	copy(k[:], b)
	return k, nil
}

func hexKey(k [32]byte) string { return hex.EncodeToString(k[:]) }

func list(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// ParseWGConf reads wg-quick text.
func ParseWGConf(src string) (*WGConf, error) {
	c := &WGConf{MTU: DefaultMTU}
	var peer *WGPeer
	section := ""
	seenIface := false
	have := map[string]bool{}
	sc := bufio.NewScanner(strings.NewReader(src))
	line := 0
	errf := func(format string, a ...any) error {
		return fmt.Errorf("line %d: "+format, append([]any{line}, a...)...)
	}
	for sc.Scan() {
		line++
		l := strings.TrimSpace(sc.Text())
		if i := strings.IndexAny(l, "#;"); i >= 0 {
			l = strings.TrimSpace(l[:i])
		}
		if l == "" {
			continue
		}
		if strings.HasPrefix(l, "[") {
			if !strings.HasSuffix(l, "]") {
				return nil, errf("a section is [Interface] or [Peer]")
			}
			switch strings.ToLower(strings.TrimSpace(l[1 : len(l)-1])) {
			case "interface":
				if seenIface {
					return nil, errf("a second [Interface]")
				}
				seenIface, section, peer = true, "interface", nil
			case "peer":
				c.Peers = append(c.Peers, WGPeer{})
				peer, section = &c.Peers[len(c.Peers)-1], "peer"
			default:
				return nil, errf("unknown section %s; a WireGuard file has [Interface] and [Peer]", l)
			}
			have = map[string]bool{}
			continue
		}
		k, v, ok := strings.Cut(l, "=")
		if !ok {
			return nil, errf("expected Key = Value")
		}
		key := strings.ToLower(strings.TrimSpace(k))
		v = strings.TrimSpace(v)
		if section == "" {
			return nil, errf("%s comes before any [Interface] or [Peer]", strings.TrimSpace(k))
		}
		multi := key == "address" || key == "dns" || key == "allowedips"
		if have[key] && !multi {
			return nil, errf("%s is given twice", strings.TrimSpace(k))
		}
		have[key] = true
		switch key {
		case "preup", "postup", "predown", "postdown":
			return nil, errf("%s is a wg-quick shell hook; vpnw runs no commands from a config file, so remove it", strings.TrimSpace(k))
		}
		switch section + "." + key {
		case "interface.privatekey":
			pk, err := wgKey(v)
			if err != nil {
				return nil, errf("PrivateKey: %v", err)
			}
			c.PrivateKey = pk
		case "interface.address":
			for _, a := range list(v) {
				p, err := netip.ParsePrefix(a)
				if err != nil {
					ad, err2 := netip.ParseAddr(a)
					if err2 != nil {
						return nil, errf("Address %q is not an address such as 10.64.0.2/32", a)
					}
					p = netip.PrefixFrom(ad, ad.BitLen())
				}
				c.Addresses = append(c.Addresses, p)
			}
		case "interface.dns":
			for _, a := range list(v) {
				ad, err := netip.ParseAddr(a)
				if err != nil {
					// wg-quick also takes search domains here; vpnw
					// looks names up as given, so it has no use for them.
					continue
				}
				c.DNS = append(c.DNS, ad)
			}
		case "interface.mtu":
			n, err := strconv.Atoi(v)
			if err != nil || n < 1280 || n > 9000 {
				return nil, errf("MTU must be a number from 1280 to 9000")
			}
			c.MTU = n
		case "interface.listenport":
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 || n > 65535 {
				return nil, errf("ListenPort must be a port number")
			}
			c.ListenPort = n
		case "peer.publickey":
			pk, err := wgKey(v)
			if err != nil {
				return nil, errf("PublicKey: %v", err)
			}
			peer.PublicKey = pk
		case "peer.presharedkey":
			pk, err := wgKey(v)
			if err != nil {
				return nil, errf("PresharedKey: %v", err)
			}
			peer.PresharedKey = &pk
		case "peer.endpoint":
			host, port, err := splitEndpoint(v)
			if err != nil {
				return nil, errf("Endpoint: %v", err)
			}
			peer.Endpoint = netjoin(host, port)
		case "peer.allowedips":
			for _, a := range list(v) {
				p, err := netip.ParsePrefix(a)
				if err != nil {
					return nil, errf("AllowedIPs %q is not a range such as 0.0.0.0/0", a)
				}
				peer.AllowedIPs = append(peer.AllowedIPs, p.Masked())
			}
		case "peer.persistentkeepalive":
			if v == "off" {
				continue
			}
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 || n > 65535 {
				return nil, errf("PersistentKeepalive must be a number of seconds, or off")
			}
			peer.Keepalive = n
		default:
			return nil, errf("unknown key %s in [%s]", strings.TrimSpace(k), map[string]string{"interface": "Interface", "peer": "Peer"}[section])
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	switch {
	case !seenIface:
		return nil, fmt.Errorf("no [Interface] section")
	case c.PrivateKey == [32]byte{}:
		return nil, fmt.Errorf("[Interface] has no PrivateKey")
	case len(c.Addresses) == 0:
		return nil, fmt.Errorf("[Interface] has no Address")
	case len(c.Peers) == 0:
		return nil, fmt.Errorf("no [Peer] section")
	}
	for i, p := range c.Peers {
		switch {
		case p.PublicKey == [32]byte{}:
			return nil, fmt.Errorf("[Peer] %d has no PublicKey", i+1)
		case p.Endpoint == "":
			return nil, fmt.Errorf("[Peer] %d has no Endpoint; vpnw starts the tunnel, so it needs to know where the peer is", i+1)
		case len(p.AllowedIPs) == 0:
			return nil, fmt.Errorf("[Peer] %d has no AllowedIPs", i+1)
		}
	}
	return c, nil
}

func splitEndpoint(v string) (string, int, error) {
	i := strings.LastIndex(v, ":")
	if i <= 0 {
		return "", 0, fmt.Errorf("%q needs a host and a port, such as vpn.example.com:51820", v)
	}
	host, ps := v[:i], v[i+1:]
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	port, err := strconv.Atoi(ps)
	if err != nil || port < 1 || port > 65535 || host == "" {
		return "", 0, fmt.Errorf("%q needs a host and a port, such as vpn.example.com:51820", v)
	}
	return host, port, nil
}

func netjoin(host string, port int) string {
	if strings.Contains(host, ":") {
		return "[" + host + "]:" + strconv.Itoa(port)
	}
	return host + ":" + strconv.Itoa(port)
}

// Covers reports whether a peer's AllowedIPs include ip, and which peer.
func (c *WGConf) Covers(ip netip.Addr) (*WGPeer, bool) {
	ip = ip.Unmap()
	var best *WGPeer
	bits := -1
	for i := range c.Peers {
		for _, p := range c.Peers[i].AllowedIPs {
			if p.Contains(ip) && p.Bits() > bits {
				best, bits = &c.Peers[i], p.Bits()
			}
		}
	}
	return best, best != nil
}
