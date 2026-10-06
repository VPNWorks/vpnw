// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"net"
	"strings"
	"testing"

	"vpnw.com/vpnw/internal/config"
)

func mustPolicy(t *testing.T, spec config.PolicySpec) *Policy {
	t.Helper()
	p, err := New(&spec, "test")
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return p
}

func ips(list ...string) []net.IP {
	var out []net.IP
	for _, s := range list {
		ip := net.ParseIP(s)
		if ip == nil {
			panic(s)
		}
		out = append(out, ip)
	}
	return out
}

func TestNormalizeHost(t *testing.T) {
	cases := []struct {
		in, host, ip string
		bad          bool
	}{
		{in: "GitHub.COM", host: "github.com"},
		{in: "github.com.", host: "github.com"},
		{in: "a_b.example.com", host: "a_b.example.com"},
		{in: "xn--bcher-kva.example", host: "xn--bcher-kva.example"},
		{in: "127.0.0.1", ip: "127.0.0.1"},
		{in: "127.0.0.1.", ip: "127.0.0.1"},
		{in: "::1", ip: "::1"},
		{in: "::ffff:127.0.0.1", ip: "127.0.0.1"},
		{in: "2130706433", bad: true},
		{in: "0x7f000001", bad: true},
		{in: "0x7f.1", bad: true},
		{in: "127.1", bad: true},
		{in: "0177.0.0.1", bad: true},
		{in: "017.0.0.1", bad: true},
		{in: "1.2.3.04", bad: true},
		{in: "example.123", bad: true},
		{in: "bücher.example", bad: true},
		{in: "a..b", bad: true},
		{in: ".example.com", bad: true},
		{in: "example.com..", bad: true},
		{in: "", bad: true},
		{in: "exa mple.com", bad: true},
		{in: "evil.com%00.github.com", bad: true},
		{in: "fe80::1%eth0", bad: true},
		{in: strings.Repeat("a", 64) + ".com", bad: true},
		{in: strings.Repeat("a.", 127) + "com", bad: true},
		{in: "example.com:443", bad: true},
		{in: "[::1]", bad: true},
	}
	for _, c := range cases {
		h, ip, err := NormalizeHost(c.in)
		if c.bad {
			if err == nil {
				t.Errorf("%q: want error, got host=%q ip=%v", c.in, h, ip)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: unexpected error %v", c.in, err)
			continue
		}
		if c.ip != "" {
			if ip == nil || !ip.Equal(net.ParseIP(c.ip)) {
				t.Errorf("%q: want ip %s, got host=%q ip=%v", c.in, c.ip, h, ip)
			}
			continue
		}
		if h != c.host || ip != nil {
			t.Errorf("%q: want host %q, got %q (ip %v)", c.in, c.host, h, ip)
		}
	}
}

func TestParseRule(t *testing.T) {
	good := map[string]Kind{
		"github.com":              KindExact,
		"github.com:443":          KindExact,
		"*.githubusercontent.com": KindWildcard,
		"*.example.com:8443":      KindWildcard,
		"10.0.0.0/8":              KindCIDR,
		"10.1.2.3":                KindIP,
		"10.1.2.3:5432":           KindIP,
		"[::1]:443":               KindIP,
		"::1":                     KindIP,
		"fd00::/8":                KindCIDR,
		"[fd00::/8]:53":           KindCIDR,
	}
	for text, kind := range good {
		r, err := ParseRule(text)
		if err != nil {
			t.Errorf("%q: %v", text, err)
			continue
		}
		if r.Kind != kind {
			t.Errorf("%q: kind %v, want %v", text, r.Kind, kind)
		}
	}
	bad := []string{"", "*", "*example.com", "a.*.com", "*.10.0.0.1", "github.com:0", "github.com:65536",
		"github.com:http", "10.0.0.0/33", "[::1", "[::1]x", " github.com", "git hub.com", "2130706433", "*.com.:x"}
	for _, text := range bad {
		if _, err := ParseRule(text); err == nil {
			t.Errorf("%q: want error", text)
		}
	}
	r, _ := ParseRule("github.com:443")
	if r.Port != 443 || r.Host != "github.com" {
		t.Errorf("port parse: %+v", r)
	}
}

func TestDefaults(t *testing.T) {
	p := mustPolicy(t, config.PolicySpec{Allow: []string{"github.com"}})
	if p.Default != Deny || !strings.Contains(p.DefaultNote, "implied") {
		t.Errorf("allow list should imply default deny: %v %q", p.Default, p.DefaultNote)
	}
	p = mustPolicy(t, config.PolicySpec{Deny: []string{"evil.example"}})
	if p.Default != Allow {
		t.Errorf("deny-only policy should default to allow")
	}
	p = mustPolicy(t, config.PolicySpec{Allow: []string{"github.com"}, Default: "allow"})
	if p.Default != Allow || p.DefaultNote != "set in the policy" {
		t.Errorf("explicit default ignored")
	}
}

func TestDecide(t *testing.T) {
	p := mustPolicy(t, config.PolicySpec{
		Allow:       []string{"github.com", "*.githubusercontent.com", "api.example.com:443", "140.82.112.0/20", "[2001:db8:1::1]:443"},
		Deny:        []string{"gist.githubusercontent.com", "140.82.113.3", "*.bad.example"},
		DenyPrivate: true,
	})
	type tc struct {
		name  string
		t     Target
		addrs []net.IP
		allow bool
		rule  string
	}
	host := func(h string, port int) Target { return Target{Host: h, Port: port} }
	lit := func(ip string, port int) Target { return Target{IP: net.ParseIP(ip), Port: port} }
	cases := []tc{
		{"exact allow", host("github.com", 443), ips("140.82.121.4"), true, "allow[0]"},
		{"exact does not match subdomain", host("www.github.com", 443), ips("8.8.8.8"), false, "default"},
		{"wildcard matches subdomain", host("raw.githubusercontent.com", 443), ips("185.199.108.133"), true, "allow[1]"},
		{"wildcard matches deep subdomain", host("a.b.githubusercontent.com", 443), ips("185.199.108.133"), true, "allow[1]"},
		{"wildcard does not match apex", host("githubusercontent.com", 443), ips("185.199.108.133"), false, "default"},
		{"wildcard does not match a sibling", host("notgithubusercontent.com", 443), ips("185.199.108.133"), false, "default"},
		{"wildcard does not match a lookalike", host("evilgithubusercontent.com", 443), ips("8.8.8.8"), false, "default"},
		{"deny beats wildcard allow", host("gist.githubusercontent.com", 443), nil, false, "deny[0]"},
		{"port rule matches its port", host("api.example.com", 443), ips("93.184.216.34"), true, "allow[2]"},
		{"port rule ignores other ports", host("api.example.com", 80), ips("93.184.216.34"), false, "default"},
		{"allowed name resolving to loopback", host("github.com", 443), ips("127.0.0.1"), false, "deny_private"},
		{"allowed name with one private answer", host("github.com", 443), ips("140.82.121.4", "10.0.0.5"), false, "deny_private"},
		{"allowed name resolving to denied IP", host("github.com", 443), ips("140.82.113.3"), false, "deny[1]"},
		{"CIDR never allows a name", host("unlisted.example", 443), ips("140.82.114.9"), false, "default"},
		{"CIDR never allows a name, several answers", host("unlisted.example", 443), ips("140.82.114.9", "1.1.1.1"), false, "default"},
		{"address literal in CIDR", lit("140.82.112.1", 22), nil, true, "allow[3]"},
		{"denied address literal", lit("140.82.113.3", 443), nil, false, "deny[1]"},
		{"host rules never match literals", lit("20.201.28.151", 443), nil, false, "default"},
		{"metadata literal", lit("169.254.169.254", 80), nil, false, "deny_private"},
		{"loopback literal", lit("127.0.0.1", 8080), nil, false, "deny_private"},
		{"mapped loopback literal", lit("::ffff:127.0.0.1", 80), nil, false, "deny_private"},
		{"nat64 of private", lit("64:ff9b::a00:1", 80), nil, false, "deny_private"},
		{"6to4 of private", lit("2002:c0a8:0101::1", 80), nil, false, "deny_private"},
		{"ipv4-compatible", lit("::7f00:1", 80), nil, false, "deny_private"},
		{"ula", lit("fd12:3456::1", 443), nil, false, "deny_private"},
		{"v6 allow literal with port", lit("2001:db8:1::1", 443), nil, false, "deny_private"},
		{"wildcard deny", host("x.bad.example", 443), nil, false, "deny[2]"},
		{"unknown name", host("evil.example", 443), nil, false, "default"},
	}
	for _, c := range cases {
		d := p.Decide(c.t, c.addrs)
		if d.Allow != c.allow || d.Rule != c.rule {
			t.Errorf("%s: got allow=%v rule=%s (%s), want allow=%v rule=%s", c.name, d.Allow, d.Rule, d.Reason, c.allow, c.rule)
		}
		if d.Reason == "" {
			t.Errorf("%s: empty reason", c.name)
		}
	}
}

func TestNeedsAddresses(t *testing.T) {
	p := mustPolicy(t, config.PolicySpec{Allow: []string{"github.com"}, Deny: []string{"evil.example"}, DenyPrivate: true})
	if p.NeedsAddresses(Target{Host: "evil.example", Port: 443}) {
		t.Error("a denied name must never be resolved")
	}
	if !p.NeedsAddresses(Target{Host: "github.com", Port: 443}) {
		t.Error("an allowed name must be resolved to check deny_private")
	}
	if p.NeedsAddresses(Target{Host: "other.example", Port: 443}) {
		t.Error("default deny: an unlisted name must never be looked up")
	}
	c := mustPolicy(t, config.PolicySpec{Allow: []string{"10.0.0.0/8", "github.com"}})
	if c.NeedsAddresses(Target{Host: "data.evil.example", Port: 443}) {
		t.Error("address allow rules must not cause lookups of unlisted names (DNS exfiltration)")
	}
	if p.NeedsAddresses(Target{Host: "github.com", Port: 443, RemoteDNS: true}) {
		t.Error("remote DNS paths never resolve locally")
	}
	q := mustPolicy(t, config.PolicySpec{Default: "allow", DenyPrivate: true})
	if !q.NeedsAddresses(Target{Host: "anything.example", Port: 443}) {
		t.Error("default allow with deny_private must resolve")
	}
	if err := q.CheckRemoteDNS("office"); err == nil {
		t.Error("default allow + deny_private + remote DNS must be refused")
	}
	if err := p.CheckRemoteDNS("office"); err != nil {
		t.Errorf("allow-list policy is fine on remote DNS: %v", err)
	}
}

func TestRemoteDNSDecision(t *testing.T) {
	p := mustPolicy(t, config.PolicySpec{Allow: []string{"tracker.office.internal"}, DenyPrivate: true})
	d := p.Decide(Target{Host: "tracker.office.internal", Port: 443, RemoteDNS: true}, nil)
	if !d.Allow {
		t.Errorf("allowed internal name on a remote-DNS path: %+v", d)
	}
	d = p.Decide(Target{IP: net.ParseIP("10.1.2.3"), Port: 443, RemoteDNS: true}, nil)
	if d.Allow || d.Rule != "deny_private" {
		t.Errorf("private literal must still be denied on remote DNS: %+v", d)
	}
}

func TestPrivateRanges(t *testing.T) {
	private := []string{"0.0.0.0", "10.255.255.255", "100.64.0.1", "127.8.9.10", "169.254.169.254", "172.31.0.1",
		"192.168.1.1", "198.18.0.1", "224.0.0.1", "255.255.255.255", "::", "::1", "fe80::1", "fc00::1", "fd00:ec2::254",
		"ff02::1", "::ffff:10.0.0.1", "64:ff9b::7f00:1", "64:ff9b:1::1", "2002:7f00:1::", "2001:db8::1", "::10.0.0.1"}
	public := []string{"1.1.1.1", "8.8.8.8", "140.82.121.4", "172.32.0.1", "100.128.0.1", "2606:4700:4700::1111",
		"64:ff9b::808:808", "2002:808:808::1", "::ffff:8.8.8.8"}
	for _, s := range private {
		if _, bad := PrivateReason(net.ParseIP(s)); !bad {
			t.Errorf("%s should be private", s)
		}
	}
	for _, s := range public {
		if why, bad := PrivateReason(net.ParseIP(s)); bad {
			t.Errorf("%s should be public, got %s", s, why)
		}
	}
}

func BenchmarkDecideName(b *testing.B) {
	spec := config.PolicySpec{DenyPrivate: true}
	for i := 0; i < 40; i++ {
		spec.Allow = append(spec.Allow, "host"+string(rune('a'+i%26))+".example.com")
	}
	spec.Allow = append(spec.Allow, "*.githubusercontent.com", "github.com")
	p, _ := New(&spec, "bench")
	t := Target{Host: "raw.githubusercontent.com", Port: 443}
	a := ips("185.199.108.133")
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		p.Decide(t, a)
	}
}
