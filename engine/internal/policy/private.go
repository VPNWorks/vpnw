// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"fmt"
	"net"
)

type special struct {
	net *net.IPNet
	why string
}

func mustNets(list [][2]string) []special {
	out := make([]special, 0, len(list))
	for _, e := range list {
		_, n, err := net.ParseCIDR(e[0])
		if err != nil {
			panic(err)
		}
		if v4 := n.IP.To4(); v4 != nil {
			ones, _ := n.Mask.Size()
			n = &net.IPNet{IP: v4, Mask: net.CIDRMask(ones, 32)}
		}
		out = append(out, special{n, e[1]})
	}
	return out
}

// Private and special-purpose ranges refused by deny_private.
var private4 = mustNets([][2]string{
	{"0.0.0.0/8", "\"this network\" address (0.0.0.0/8)"},
	{"10.0.0.0/8", "private network address (10.0.0.0/8)"},
	{"100.64.0.0/10", "carrier-grade NAT address (100.64.0.0/10)"},
	{"127.0.0.0/8", "loopback address (127.0.0.0/8)"},
	{"169.254.0.0/16", "link-local address (169.254.0.0/16), where cloud metadata services live"},
	{"172.16.0.0/12", "private network address (172.16.0.0/12)"},
	{"192.0.0.0/24", "IETF special-purpose address (192.0.0.0/24)"},
	{"192.0.2.0/24", "documentation address (192.0.2.0/24)"},
	{"192.88.99.0/24", "deprecated 6to4 relay address (192.88.99.0/24)"},
	{"192.168.0.0/16", "private network address (192.168.0.0/16)"},
	{"198.18.0.0/15", "benchmarking address (198.18.0.0/15)"},
	{"198.51.100.0/24", "documentation address (198.51.100.0/24)"},
	{"203.0.113.0/24", "documentation address (203.0.113.0/24)"},
	{"224.0.0.0/4", "multicast address (224.0.0.0/4)"},
	{"240.0.0.0/4", "reserved address (240.0.0.0/4), including broadcast"},
})

var private6 = mustNets([][2]string{
	{"::/128", "unspecified IPv6 address (::)"},
	{"::1/128", "IPv6 loopback address (::1)"},
	{"100::/64", "IPv6 discard-only address (100::/64)"},
	{"64:ff9b:1::/48", "local-use NAT64 address (64:ff9b:1::/48)"},
	{"2001::/23", "IETF special-purpose IPv6 address (2001::/23)"},
	{"2001:db8::/32", "IPv6 documentation address (2001:db8::/32)"},
	{"fc00::/7", "unique local IPv6 address (fc00::/7), IPv6's private range"},
	{"fe80::/10", "link-local IPv6 address (fe80::/10)"},
	{"fec0::/10", "deprecated site-local IPv6 address (fec0::/10)"},
	{"ff00::/8", "IPv6 multicast address (ff00::/8)"},
})

var (
	nat64      = mustNets([][2]string{{"64:ff9b::/96", ""}})[0].net
	sixToFour  = mustNets([][2]string{{"2002::/16", ""}})[0].net
	compatible = mustNets([][2]string{{"::/96", ""}})[0].net
)

func check4(v4 net.IP) (string, bool) {
	for _, s := range private4 {
		if s.net.Contains(v4) {
			return s.why, true
		}
	}
	return "", false
}

// PrivateReason reports whether ip is private or special-purpose, and why.
// IPv4-mapped (::ffff:a.b.c.d), NAT64 (64:ff9b::/96) and 6to4 (2002::/16)
// addresses are judged by the IPv4 address they carry.
func PrivateReason(ip net.IP) (string, bool) {
	if ip == nil {
		return "no address", true
	}
	if v4 := ip.To4(); v4 != nil {
		// Go stores IPv4 and IPv4-mapped IPv6 (::ffff:a.b.c.d) the same way,
		// and dials both over IPv4, so they get the same answer.
		return check4(v4)
	}
	ip16 := ip.To16()
	if ip16 == nil {
		return "malformed address", true
	}
	for _, s := range private6 {
		if s.net.Contains(ip16) {
			return s.why, true
		}
	}
	if nat64.Contains(ip16) {
		v4 := net.IPv4(ip16[12], ip16[13], ip16[14], ip16[15]).To4()
		if why, bad := check4(v4); bad {
			return fmt.Sprintf("NAT64 form of %s, a %s", v4, why), true
		}
	}
	if sixToFour.Contains(ip16) {
		v4 := net.IPv4(ip16[2], ip16[3], ip16[4], ip16[5]).To4()
		if why, bad := check4(v4); bad {
			return fmt.Sprintf("6to4 form of %s, a %s", v4, why), true
		}
	}
	if compatible.Contains(ip16) {
		return "deprecated IPv4-compatible IPv6 address (::/96)", true
	}
	return "", false
}
