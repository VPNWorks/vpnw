// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"net"
	"strings"
	"testing"

	"vpnw.com/vpnw/internal/config"
)

// FuzzParseRule makes sure no rule text crashes the compiler and that a
// compiled host rule never matches a bare address (host/address confusion is
// the class of bug that lets a policy be bypassed).
func FuzzParseRule(f *testing.F) {
	for _, s := range []string{"github.com", "*.example.com:443", "10.0.0.0/8", "[::1]:53", "2130706433", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, text string) {
		r, err := ParseRule(text)
		if err != nil {
			return
		}
		if (r.Kind == KindExact || r.Kind == KindWildcard) && r.Host != "" {
			for _, ip := range []string{"127.0.0.1", "169.254.169.254", "::1", "8.8.8.8"} {
				if r.matchAddr(net.ParseIP(ip), r.Port) {
					t.Fatalf("host rule %q matched address %s", text, ip)
				}
			}
		}
	})
}

// FuzzDecide feeds arbitrary policies and destinations through the engine and
// checks the one invariant that must always hold: an allowed request never
// resolves to a private address while deny_private is on.
func FuzzDecide(f *testing.F) {
	f.Add("github.com\n*.example.com", "evil.example", "api.example.com", "140.82.121.4", 443, true)
	f.Fuzz(func(t *testing.T, allowLines, denyLines, host, addr string, port int, denyPriv bool) {
		spec := &config.PolicySpec{DenyPrivate: denyPriv}
		for _, a := range strings.Split(allowLines, "\n") {
			if _, err := ParseRule(a); err == nil {
				spec.Allow = append(spec.Allow, a)
			}
		}
		for _, d := range strings.Split(denyLines, "\n") {
			if _, err := ParseRule(d); err == nil {
				spec.Deny = append(spec.Deny, d)
			}
		}
		p, err := New(spec, "fuzz")
		if err != nil {
			return
		}
		h, ip, err := NormalizeHost(host)
		if err != nil {
			return
		}
		tg := Target{Host: h, IP: ip, Port: port}
		var addrs []net.IP
		if a := net.ParseIP(addr); a != nil && h != "" {
			addrs = []net.IP{a}
		}
		d := p.Decide(tg, addrs)
		if d.Allow && denyPriv {
			for _, a := range addrs {
				if _, bad := PrivateReason(a); bad {
					t.Fatalf("allowed a request to a private address %s with deny_private on: %+v", a, d)
				}
			}
			if tg.Host == "" && tg.IP != nil {
				if _, bad := PrivateReason(tg.IP); bad {
					t.Fatalf("allowed a private literal %s with deny_private on: %+v", tg.IP, d)
				}
			}
		}
	})
}
