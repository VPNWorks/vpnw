// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package scope

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// Dest is what a rule allows: an address or an IPv4 range, a port or a
// range of ports, and a protocol. Written as ADDR[/BITS]:PORT[-PORT]/PROTO,
// for example "10.0.1.20:443/tcp" or "10.0.3.0/24:8000-8100/tcp".
type Dest struct {
	Net    netip.Prefix
	Lo, Hi uint16
	Proto  Proto
}

// DestOf returns the rule that allows exactly one flow key.
func DestOf(k Key) Dest {
	return Dest{Net: netip.PrefixFrom(k.Dst, 32), Lo: k.Port, Hi: k.Port, Proto: k.Proto}
}

// ParseDest reads a destination in the ADDR[/BITS]:PORT[-PORT]/PROTO form.
func ParseDest(s string) (Dest, error) {
	var d Dest
	slash := strings.LastIndexByte(s, '/')
	if slash < 0 {
		return d, fmt.Errorf("%q: missing /tcp or /udp at the end", s)
	}
	proto, err := ParseProto(s[slash+1:])
	if err != nil {
		return d, fmt.Errorf("%q: %v", s, err)
	}
	d.Proto = proto
	rest := s[:slash]
	colon := strings.LastIndexByte(rest, ':')
	if colon < 0 {
		return d, fmt.Errorf("%q: missing :PORT", s)
	}
	addr, ports := rest[:colon], rest[colon+1:]
	if strings.Contains(addr, "/") {
		p, err := netip.ParsePrefix(addr)
		if err != nil {
			return d, fmt.Errorf("%q: %v", s, err)
		}
		if p != p.Masked() {
			return d, fmt.Errorf("%q: %s has host bits set; the range is %s", s, p, p.Masked())
		}
		d.Net = p
	} else {
		a, err := netip.ParseAddr(addr)
		if err != nil {
			return d, fmt.Errorf("%q: %v", s, err)
		}
		d.Net = netip.PrefixFrom(a, 32)
	}
	if !d.Net.Addr().Is4() {
		return d, fmt.Errorf("%q: only IPv4 is supported in this version", s)
	}
	lo, hi, ok := strings.Cut(ports, "-")
	l, err := parsePort(lo)
	if err != nil {
		return d, fmt.Errorf("%q: %v", s, err)
	}
	h := l
	if ok {
		if h, err = parsePort(hi); err != nil {
			return d, fmt.Errorf("%q: %v", s, err)
		}
		if h < l {
			return d, fmt.Errorf("%q: port range %d-%d runs backwards", s, l, h)
		}
	}
	d.Lo, d.Hi = l, h
	return d, nil
}

func parsePort(s string) (uint16, error) {
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil || n == 0 {
		return 0, fmt.Errorf("%q is not a port from 1 to 65535", s)
	}
	return uint16(n), nil
}

func (d Dest) String() string {
	var b strings.Builder
	if d.Net.Bits() == 32 {
		b.WriteString(d.Net.Addr().String())
	} else {
		b.WriteString(d.Net.String())
	}
	b.WriteByte(':')
	b.WriteString(strconv.Itoa(int(d.Lo)))
	if d.Hi != d.Lo {
		b.WriteByte('-')
		b.WriteString(strconv.Itoa(int(d.Hi)))
	}
	b.WriteByte('/')
	b.WriteString(d.Proto.String())
	return b.String()
}

// Match reports whether the destination allows a connection to dst:port
// over proto.
func (d Dest) Match(dst netip.Addr, port uint16, proto Proto) bool {
	return proto == d.Proto && port >= d.Lo && port <= d.Hi && d.Net.Contains(dst)
}

// Single reports whether the destination is one address and one port.
func (d Dest) Single() bool { return d.Net.Bits() == 32 && d.Lo == d.Hi }
