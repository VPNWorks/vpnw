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

// String describes the config without its keys, so printing one by
// mistake can't leak the private key.
func (c *WGConf) String() string {
	var eps []string
	for _, p := range c.Peers {
		eps = append(eps, p.Endpoint)
	}
	return fmt.Sprintf("WireGuard config %s: addresses %v, dns %v, mtu %d, peers at %s", c.Source, c.Addresses, c.DNS, c.MTU, strings.Join(eps, ", "))
}

// GoString keeps %#v from printing the private key too.
func (c *WGConf) GoString() string { return c.String() }

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
				if w, ok := word(l[1 : len(l)-1]); ok {
					return nil, errf("unknown section [%s]; a WireGuard file has [Interface] and [Peer]", w)
				}
				return nil, errf("unknown section; a WireGuard file has [Interface] and [Peer]")
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
		name, isWord := word(k)
		if !isWord {
			name = "a setting"
		}
		if section == "" {
			return nil, errf("%s comes before any [Interface] or [Peer]", name)
		}
		multi := key == "address" || key == "dns" || key == "allowedips"
		if have[key] && !multi {
			return nil, errf("%s is given twice", name)
		}
		have[key] = true
		switch key {
		case "preup", "postup", "predown", "postdown":
			return nil, errf("%s is a wg-quick shell hook; vpnw runs no commands from a config file, so remove it", name)
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
						return nil, errf("%s is not an address such as 10.64.0.2/32", about("Address", a))
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
				return nil, errf("%s: %v", about("Endpoint", v), err)
			}
			peer.Endpoint = netjoin(host, port)
		case "peer.allowedips":
			for _, a := range list(v) {
				p, err := netip.ParsePrefix(a)
				if err != nil {
					return nil, errf("%s is not a range such as 0.0.0.0/0", about("AllowedIPs", a))
				}
				peer.AllowedIPs = append(peer.AllowedIPs, p.Masked())
			}
		case "interface.table", "interface.saveconfig", "interface.fwmark":
			// wg-quick's routing and saving settings. A tunnel inside vpnw
			// has no routing table or interface to apply them to.
		case "peer.persistentkeepalive":
			if strings.EqualFold(v, "off") {
				continue
			}
			n, err := strconv.Atoi(v)
			if err != nil || n < 0 || n > 65535 {
				return nil, errf("PersistentKeepalive must be a number of seconds, or off")
			}
			peer.Keepalive = n
		default:
			sec := map[string]string{"interface": "Interface", "peer": "Peer"}[section]
			if !isWord {
				return nil, errf("not a setting vpnw knows, in [%s]; each line is Key = Value, such as Address = 10.64.0.2/32", sec)
			}
			return nil, errf("unknown key %s in [%s]", name, sec)
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

// splitEndpoint takes an endpoint apart. Its errors leave the value out;
// the caller shows it when it safely can.
func splitEndpoint(v string) (string, int, error) {
	i := strings.LastIndex(v, ":")
	if i <= 0 {
		return "", 0, fmt.Errorf("needs a host and a port, such as vpn.example.com:51820")
	}
	host, ps := v[:i], v[i+1:]
	ipv6 := false
	if strings.HasPrefix(host, "[") {
		if !strings.HasSuffix(host, "]") {
			return "", 0, fmt.Errorf("an IPv6 endpoint is written [address]:port")
		}
		host, ipv6 = host[1:len(host)-1], true
	} else if strings.Contains(host, ":") {
		return "", 0, fmt.Errorf("an IPv6 endpoint is written [address]:port")
	}
	port, err := strconv.Atoi(ps)
	if err != nil || port < 1 || port > 65535 || host == "" {
		return "", 0, fmt.Errorf("needs a host and a port, such as vpn.example.com:51820")
	}
	if a, err := netip.ParseAddr(host); err == nil {
		// A zone names a network interface, and nothing else.
		if z := a.Zone(); z != "" && (len(z) > 15 || !hostName(z) || strings.Contains(z, ".")) {
			return "", 0, fmt.Errorf("an IPv6 zone is a network interface's name, such as eth0")
		}
	} else {
		if ipv6 {
			return "", 0, fmt.Errorf("an IPv6 endpoint is written [address]:port")
		}
		if !hostName(host) {
			return "", 0, fmt.Errorf("the host is neither an address nor a name such as vpn.example.com")
		}
	}
	return host, port, nil
}

// hostName reports a name DNS could hold: labels of letters, digits, "-"
// and "_", separated by dots, 253 characters at most.
func hostName(s string) bool {
	s = strings.TrimSuffix(s, ".")
	if s == "" || len(s) > 253 {
		return false
	}
	for _, l := range strings.Split(s, ".") {
		if l == "" || len(l) > 63 {
			return false
		}
		for _, r := range l {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
				return false
			}
		}
	}
	return true
}

// word is a key or section name from a config as an error may show it:
// letters only, as every real one is. A typo can put a private key where
// a key belongs (in "PrivateKey: <key>" the first "=" is the key's own
// padding), and errors from configs go to the record and the console, so
// anything else is left out of them.
func word(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 32 {
		return "", false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z') {
			return "", false
		}
	}
	return s, true
}

// about names a setting for an error message, with its value when that is
// safe to show: one that could be an address, a range or an endpoint. Any
// other value is left out, since it could be anything: a private key on
// the wrong line (a key has "=" or "+"), or text that draws on the
// terminal.
func about(key, v string) string {
	if v == "" || len(v) > 64 {
		return key
	}
	for _, r := range v {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune(".:/[]%_-", r)) {
			return key
		}
	}
	return key + " " + strconv.Quote(v)
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
