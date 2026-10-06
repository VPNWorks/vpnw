// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package record

import (
	"encoding/binary"
	"net/netip"
	"strings"
	"testing"

	"vpnw.com/vpnw/internal/scope"
)

func packet(proto byte, ihl int, src, dst string, dport uint16, frag uint16) []byte {
	b := make([]byte, ihl+8)
	b[0] = 0x40 | byte(ihl/4)
	binary.BigEndian.PutUint16(b[6:], frag)
	b[9] = proto
	s, d := netip.MustParseAddr(src).As4(), netip.MustParseAddr(dst).As4()
	copy(b[12:], s[:])
	copy(b[16:], d[:])
	binary.BigEndian.PutUint16(b[ihl:], 51234)   // source port
	binary.BigEndian.PutUint16(b[ihl+2:], dport) // destination port
	return b
}

func TestParsePacket(t *testing.T) {
	f, ok := ParsePacket(packet(6, 20, "10.8.0.11", "10.0.1.20", 443, 0x4000))
	if !ok || f.Proto != scope.TCP || f.Src.String() != "10.8.0.11" || f.Dst.String() != "10.0.1.20" || f.Port != 443 {
		t.Fatalf("tcp: %v %+v", ok, f)
	}
	f, ok = ParsePacket(packet(17, 24, "10.8.0.12", "10.0.0.53", 53, 0))
	if !ok || f.Proto != scope.UDP || f.Port != 53 {
		t.Fatalf("udp with IP options: %v %+v", ok, f)
	}
	for name, b := range map[string][]byte{
		"icmp":            packet(1, 20, "10.8.0.11", "10.0.1.20", 0, 0),
		"later fragment":  packet(6, 20, "10.8.0.11", "10.0.1.20", 443, 0x0010),
		"short":           packet(6, 20, "10.8.0.11", "10.0.1.20", 443, 0)[:22],
		"ipv6":            append([]byte{0x60}, make([]byte, 40)...),
		"bad header size": func() []byte { b := packet(6, 20, "10.8.0.11", "10.0.1.20", 443, 0); b[0] = 0x44; return b }(),
		"empty":           nil,
	} {
		if _, ok := ParsePacket(b); ok {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestFindAttr(t *testing.T) {
	b := append(attr(1, []byte{1, 2, 3}), attr(9|0x8000, []byte("payload"))...)
	if got := string(findAttr(b, 9)); got != "payload" {
		t.Fatalf("got %q", got)
	}
	if findAttr(b, 4) != nil || findAttr([]byte{2, 0, 0, 0}, 9) != nil || findAttr([]byte{50, 0, 9, 0}, 9) != nil {
		t.Fatal("bad attributes should give nil")
	}
}

func TestRules(t *testing.T) {
	s := Rules(netip.MustParsePrefix("10.8.0.0/24"), 7)
	for _, want := range []string{"table inet vpnw_scope_record\ndelete table inet vpnw_scope_record\n", "priority -10", "ip saddr 10.8.0.0/24 ct state new meta l4proto { tcp, udp } log group 7"} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q in\n%s", want, s)
		}
	}
}

func FuzzParsePacket(f *testing.F) {
	f.Add(packet(6, 20, "10.8.0.11", "10.0.1.20", 443, 0))
	f.Add(packet(17, 60, "10.8.0.11", "10.0.1.20", 53, 0))
	f.Fuzz(func(t *testing.T, b []byte) {
		fl, ok := ParsePacket(b)
		if ok && (fl.Proto != scope.TCP && fl.Proto != scope.UDP || !fl.Src.Is4() || !fl.Dst.Is4()) {
			t.Fatalf("accepted %x as %+v", b, fl)
		}
	})
}
