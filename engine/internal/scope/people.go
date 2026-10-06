// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package scope

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"vpnw.com/vpnw/internal/config"
)

// Person is someone who connects to the VPN.
type Person struct {
	ID     string
	Name   string
	Addrs  []netip.Addr
	Keys   []string
	Groups []string
	Line   int
}

// People is a parsed people file: who is behind each VPN address, and which
// groups they belong to.
//
//	version = 1
//	vpn_net = "10.8.0.0/24"
//
//	[people.alice]
//	name = "Alice Martin"
//	addresses = ["10.8.0.11"]
//	groups = ["finance"]
//
//	[people.bruno]
//	wireguard_keys = ["xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg="]
//	groups = ["engineering"]
type People struct {
	VPNNet     netip.Prefix
	List       []*Person
	GroupOrder []string
	Groups     map[string][]*Person

	byID   map[string]*Person
	byAddr map[netip.Addr]*Person
}

// Get returns a person by ID, or nil.
func (p *People) Get(id string) *Person { return p.byID[id] }

// ByAddr returns the person behind a VPN address, or nil.
func (p *People) ByAddr(a netip.Addr) *Person { return p.byAddr[a] }

// ValidName reports whether s can be a person or group name: letters,
// digits, _ and -, at most 64 of them.
func ValidName(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func errAt(file string, line int, format string, a ...any) error {
	return &config.Error{File: file, Line: line, Msg: fmt.Sprintf(format, a...)}
}

func stringList(file string, v *config.Value, key string) ([]string, error) {
	if v.Kind != config.KArray {
		return nil, errAt(file, v.Line, "%s must be an array of strings", key)
	}
	var out []string
	for _, e := range v.Arr {
		if e.Kind != config.KString {
			return nil, errAt(file, v.Line, "%s must be an array of strings", key)
		}
		out = append(out, e.Str)
	}
	return out, nil
}

// ParsePeople reads a people file. Every person needs at least one address
// or WireGuard key; keys become addresses with ResolveKeys.
func ParsePeople(src, file string) (*People, error) {
	doc, err := config.Parse(src)
	if err != nil {
		if ce, ok := err.(*config.Error); ok {
			ce.File = file
		}
		return nil, err
	}
	p := &People{Groups: map[string][]*Person{}, byID: map[string]*Person{}, byAddr: map[netip.Addr]*Person{}}
	root := doc.Tables[""]
	for _, k := range root.Order {
		v := root.Keys[k]
		switch k {
		case "version":
			if v.Kind != config.KInt || v.Int != 1 {
				return nil, errAt(file, v.Line, "version must be 1")
			}
		case "vpn_net":
			if v.Kind != config.KString {
				return nil, errAt(file, v.Line, "vpn_net must be a string such as \"10.8.0.0/24\"")
			}
			n, err := netip.ParsePrefix(v.Str)
			if err != nil || !n.Addr().Is4() {
				return nil, errAt(file, v.Line, "vpn_net %q: want an IPv4 range such as 10.8.0.0/24", v.Str)
			}
			if n != n.Masked() {
				return nil, errAt(file, v.Line, "vpn_net %s has host bits set; the range is %s", n, n.Masked())
			}
			p.VPNNet = n
		default:
			return nil, errAt(file, v.Line, "unknown key %q at the top level (known: version, vpn_net)", k)
		}
	}
	if _, ok := root.Keys["version"]; !ok {
		return nil, errAt(file, 1, "missing version = 1")
	}
	if !p.VPNNet.IsValid() {
		return nil, errAt(file, 1, "missing vpn_net, the VPN's address range, such as vpn_net = \"10.8.0.0/24\"")
	}
	keys := map[string]*Person{}
	for _, name := range doc.Order[1:] {
		t := doc.Tables[name]
		section, id, ok := strings.Cut(name, ".")
		if section != "people" || !ok {
			return nil, errAt(file, t.Line, "unknown table [%s]; people go in [people.NAME] tables", name)
		}
		if !ValidName(id) {
			return nil, errAt(file, t.Line, "person name %q: use letters, digits, _ and -", id)
		}
		per := &Person{ID: id, Line: t.Line}
		for _, k := range t.Order {
			v := t.Keys[k]
			switch k {
			case "name":
				if v.Kind != config.KString {
					return nil, errAt(file, v.Line, "name must be a string")
				}
				per.Name = v.Str
			case "addresses":
				list, err := stringList(file, v, k)
				if err != nil {
					return nil, err
				}
				seen := map[netip.Addr]bool{}
				for _, s := range list {
					a, err := netip.ParseAddr(s)
					if err != nil || !a.Is4() {
						return nil, errAt(file, v.Line, "address %q: want an IPv4 address", s)
					}
					if seen[a] {
						return nil, errAt(file, v.Line, "address %s is listed twice", a)
					}
					seen[a] = true
					if !p.VPNNet.Contains(a) {
						return nil, errAt(file, v.Line, "address %s is outside vpn_net %s", a, p.VPNNet)
					}
					per.Addrs = append(per.Addrs, a)
				}
			case "wireguard_keys":
				list, err := stringList(file, v, k)
				if err != nil {
					return nil, err
				}
				for _, s := range list {
					if b, err := base64.StdEncoding.DecodeString(s); err != nil || len(b) != 32 {
						return nil, errAt(file, v.Line, "WireGuard key %q: want 44 characters of base64 for 32 bytes", s)
					}
					if other, dup := keys[s]; dup {
						return nil, errAt(file, v.Line, "WireGuard key %s is also listed for %s", s, other.ID)
					}
					keys[s] = per
					per.Keys = append(per.Keys, s)
				}
			case "groups":
				list, err := stringList(file, v, k)
				if err != nil {
					return nil, err
				}
				seen := map[string]bool{}
				for _, g := range list {
					if !ValidName(g) {
						return nil, errAt(file, v.Line, "group name %q: use letters, digits, _ and -", g)
					}
					if seen[g] {
						return nil, errAt(file, v.Line, "group %s is listed twice", g)
					}
					seen[g] = true
					per.Groups = append(per.Groups, g)
				}
			default:
				return nil, errAt(file, v.Line, "unknown key %q for a person (known: name, addresses, wireguard_keys, groups)", k)
			}
		}
		if len(per.Addrs) == 0 && len(per.Keys) == 0 {
			return nil, errAt(file, t.Line, "%s has no addresses and no wireguard_keys", id)
		}
		p.List = append(p.List, per)
		p.byID[id] = per
	}
	if err := p.index(file); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *People) index(file string) error {
	p.byAddr = map[netip.Addr]*Person{}
	p.Groups = map[string][]*Person{}
	p.GroupOrder = nil
	for _, per := range p.List {
		for _, a := range per.Addrs {
			if other, dup := p.byAddr[a]; dup && other != per {
				return errAt(file, per.Line, "address %s belongs to both %s and %s", a, other.ID, per.ID)
			}
			p.byAddr[a] = per
		}
		for _, g := range per.Groups {
			if _, ok := p.Groups[g]; !ok {
				p.GroupOrder = append(p.GroupOrder, g)
			}
			p.Groups[g] = append(p.Groups[g], per)
		}
	}
	return nil
}

// Unresolved lists people who have no address yet: their WireGuard keys
// still need ResolveKeys.
func (p *People) Unresolved() []string {
	var out []string
	for _, per := range p.List {
		if len(per.Addrs) == 0 {
			out = append(out, per.ID)
		}
	}
	return out
}

// ResolveKeys reads the output of "wg show all dump" (or "wg show IFACE
// dump") and gives each person the single addresses (/32) that WireGuard
// routes to their keys.
func (p *People) ResolveKeys(dump, file string) error {
	routes := map[string][]netip.Addr{}
	sc := bufio.NewScanner(strings.NewReader(dump))
	line := 0
	for sc.Scan() {
		line++
		fields := strings.Split(sc.Text(), "\t")
		var key, allowed string
		switch len(fields) {
		case 4, 5: // an interface line: private key, public key, port, fwmark
			continue
		case 8: // a peer of one interface
			key, allowed = fields[0], fields[3]
		case 9: // a peer, with the interface name first
			key, allowed = fields[1], fields[4]
		default:
			if strings.TrimSpace(sc.Text()) == "" {
				continue
			}
			return errAt(file, line, "not a line of \"wg show dump\" output (%d fields)", len(fields))
		}
		if allowed == "(none)" {
			continue
		}
		for _, s := range strings.Split(allowed, ",") {
			pre, err := netip.ParsePrefix(strings.TrimSpace(s))
			if err != nil {
				return errAt(file, line, "allowed IP %q: %v", s, err)
			}
			if pre.Addr().Is4() && pre.Bits() == 32 {
				routes[key] = append(routes[key], pre.Addr())
			}
		}
	}
	for _, per := range p.List {
		for _, k := range per.Keys {
			addrs, ok := routes[k]
			if !ok {
				return errAt(file, 0, "the WireGuard key of %s (%s) is not in the dump", per.ID, k)
			}
			for _, a := range addrs {
				if !p.VPNNet.Contains(a) {
					return errAt(file, 0, "WireGuard gives %s the address %s, outside vpn_net %s", per.ID, a, p.VPNNet)
				}
				per.Addrs = append(per.Addrs, a)
			}
		}
		sort.Slice(per.Addrs, func(i, j int) bool { return per.Addrs[i].Less(per.Addrs[j]) })
		per.Addrs = compactAddrs(per.Addrs)
	}
	return p.index(file)
}

func compactAddrs(a []netip.Addr) []netip.Addr {
	out := a[:0]
	for i, x := range a {
		if i == 0 || x != a[i-1] {
			out = append(out, x)
		}
	}
	return out
}
