// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

// Package policy decides whether a workload may open a connection.
//
// A decision runs in a fixed order, the same for every request:
//
//  1. Deny rules on the name.
//  2. Deny rules on every address the name resolved to.
//  3. deny_private on every address: loopback, private ranges, link-local
//     (cloud metadata), and IPv6 forms that embed them.
//  4. Allow rules: host rules for names, address rules for addresses.
//  5. The default action.
//
// A name is looked up only when an address could change the answer: when
// the name is allowed and deny_private or an address deny rule has to be
// checked, or when the default is allow. A name that is denied, or simply
// not on an allow list, is never looked up, because a DNS query can carry
// data out too. For the same reason address rules in the allow list match
// connections to an address typed as a number, never a name that happens
// to resolve into the range.
//
// If a name resolves to several addresses, all of them must pass; one denied
// address denies the request. Rules never match more than they say:
// "example.com" matches that name only, "*.example.com" matches its
// subdomains at any depth but not example.com itself, and host rules never
// match an address typed as a number.
package policy

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/VPNWorks/vpnw/internal/config"
)

// Action is allow or deny.
type Action int

const (
	Deny Action = iota
	Allow
)

func (a Action) String() string {
	if a == Allow {
		return "allow"
	}
	return "deny"
}

// Kind is what a rule matches.
type Kind int

const (
	KindExact Kind = iota
	KindWildcard
	KindIP
	KindCIDR
)

// Rule is one compiled allow or deny entry.
type Rule struct {
	ID     string // "allow[2]", "deny[0]"
	Action Action
	Text   string // as written
	Kind   Kind
	Host   string // exact name, or ".suffix" for a wildcard
	IP     net.IP
	Net    *net.IPNet
	Port   int // 0 = any port
}

// Policy is a compiled policy.
type Policy struct {
	Name        string
	Default     Action
	DefaultNote string // "set in the policy", "implied by the allow list", ...
	DenyPrivate bool
	Deny        []Rule
	Allow       []Rule

	addrDeny bool
}

// Target is one connection request.
type Target struct {
	Host      string // normalized host name; empty when IP is a literal
	IP        net.IP // set when the request named an address
	Port      int
	RemoteDNS bool // the path resolves names at its exit
}

// Label is the target as people read it: "github.com:443", "[::1]:80".
func (t Target) Label() string {
	h := t.Host
	if h == "" {
		h = t.IP.String()
		if t.IP.To4() == nil {
			h = "[" + h + "]"
		}
	}
	return h + ":" + strconv.Itoa(t.Port)
}

// Decision is the outcome, with the rule that decided it.
type Decision struct {
	Allow  bool   `json:"allow"`
	Rule   string `json:"rule"`
	Text   string `json:"text,omitempty"`
	Reason string `json:"reason"`
}

// ErrInvalid marks a target that is not a valid host name or address.
var ErrInvalid = errors.New("invalid destination")

// New compiles a policy from its [policy] table.
func New(spec *config.PolicySpec, name string) (*Policy, error) {
	if spec == nil {
		return nil, errors.New("no [policy] table")
	}
	p := &Policy{Name: name, DenyPrivate: spec.DenyPrivate}
	for i, text := range spec.Deny {
		r, err := ParseRule(text)
		if err != nil {
			return nil, fmt.Errorf("deny entry %q: %v", text, err)
		}
		r.ID, r.Action = fmt.Sprintf("deny[%d]", i), Deny
		p.Deny = append(p.Deny, r)
	}
	for i, text := range spec.Allow {
		r, err := ParseRule(text)
		if err != nil {
			return nil, fmt.Errorf("allow entry %q: %v", text, err)
		}
		r.ID, r.Action = fmt.Sprintf("allow[%d]", i), Allow
		p.Allow = append(p.Allow, r)
	}
	switch spec.Default {
	case "allow":
		p.Default, p.DefaultNote = Allow, "set in the policy"
	case "deny":
		p.Default, p.DefaultNote = Deny, "set in the policy"
	default:
		// An allow list means "only these". A policy without one does not
		// pretend to isolate anything.
		if len(p.Allow) > 0 {
			p.Default, p.DefaultNote = Deny, "implied by the allow list"
		} else {
			p.Default, p.DefaultNote = Allow, "implied: the policy has no allow list"
		}
	}
	for _, r := range p.Deny {
		if r.Kind == KindIP || r.Kind == KindCIDR {
			p.addrDeny = true
		}
	}
	return p, nil
}

// ParseRule compiles one rule written as a host, *.domain, address or CIDR,
// with an optional :port.
func ParseRule(text string) (Rule, error) {
	r := Rule{Text: text}
	if text == "" {
		return r, errors.New("empty rule")
	}
	if strings.TrimSpace(text) != text || strings.ContainsAny(text, " \t") {
		return r, errors.New("rules cannot contain spaces")
	}
	if text == "*" {
		return r, errors.New(`use default = "deny" or default = "allow" instead of "*"`)
	}
	body, port, err := splitRulePort(text)
	if err != nil {
		return r, err
	}
	r.Port = port
	if strings.Contains(body, "/") {
		ip, n, err := net.ParseCIDR(body)
		if err != nil {
			return r, errors.New("not a valid CIDR range")
		}
		if v4 := ip.To4(); v4 != nil && strings.Contains(body, ".") {
			ones, _ := n.Mask.Size()
			n = &net.IPNet{IP: v4.Mask(net.CIDRMask(ones, 32)), Mask: net.CIDRMask(ones, 32)}
		}
		r.Kind, r.Net = KindCIDR, n
		return r, nil
	}
	if ip := net.ParseIP(body); ip != nil {
		r.Kind, r.IP = KindIP, ip
		return r, nil
	}
	if strings.HasPrefix(body, "*.") {
		h, ip, err := NormalizeHost(body[2:])
		if err != nil {
			return r, err
		}
		if ip != nil {
			return r, errors.New("a wildcard needs a domain name, not an address")
		}
		r.Kind, r.Host = KindWildcard, "."+h
		return r, nil
	}
	if strings.Contains(body, "*") {
		return r, errors.New("a wildcard goes only at the start, as in *.example.com")
	}
	h, ip, err := NormalizeHost(body)
	if err != nil {
		return r, err
	}
	if ip != nil {
		r.Kind, r.IP = KindIP, ip
		return r, nil
	}
	r.Kind, r.Host = KindExact, h
	return r, nil
}

func splitRulePort(text string) (string, int, error) {
	if strings.HasPrefix(text, "[") {
		end := strings.Index(text, "]")
		if end < 0 {
			return "", 0, errors.New("missing ] after an IPv6 address")
		}
		body, rest := text[1:end], text[end+1:]
		if rest == "" {
			return body, 0, nil
		}
		if !strings.HasPrefix(rest, ":") {
			return "", 0, errors.New("unexpected text after ]")
		}
		p, err := ParsePort(rest[1:])
		return body, p, err
	}
	if strings.Count(text, ":") == 1 {
		i := strings.LastIndex(text, ":")
		p, err := ParsePort(text[i+1:])
		return text[:i], p, err
	}
	return text, 0, nil // no port, or an IPv6 address without brackets
}

// ParsePort reads a port from 1 to 65535, digits only.
func ParsePort(s string) (int, error) {
	if s == "" || len(s) > 5 {
		return 0, errors.New("not a valid port")
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, errors.New("not a valid port")
		}
	}
	n, _ := strconv.Atoi(s)
	if n < 1 || n > 65535 {
		return 0, errors.New("port must be from 1 to 65535")
	}
	return n, nil
}

// NormalizeHost checks a destination as written and returns either a
// normalized host name (lowercase, no trailing dot) or an address.
// Names that a C library might read as an address in another notation
// ("2130706433", "0x7f.1", "127.1") are refused rather than guessed.
func NormalizeHost(raw string) (string, net.IP, error) {
	if raw == "" {
		return "", nil, fmt.Errorf("%w: empty host", ErrInvalid)
	}
	if len(raw) > 255 {
		return "", nil, fmt.Errorf("%w: host name is too long", ErrInvalid)
	}
	for i := 0; i < len(raw); i++ {
		if raw[i] >= 0x80 {
			return "", nil, fmt.Errorf("%w: non-ASCII host names must use their xn-- form", ErrInvalid)
		}
	}
	h := strings.TrimSuffix(raw, ".")
	if ip := net.ParseIP(h); ip != nil {
		return "", ip, nil
	}
	h = strings.ToLower(h)
	if len(h) > 253 {
		return "", nil, fmt.Errorf("%w: host name is too long", ErrInvalid)
	}
	labels := strings.Split(h, ".")
	for _, l := range labels {
		if l == "" {
			return "", nil, fmt.Errorf("%w: %q has an empty label", ErrInvalid, raw)
		}
		if len(l) > 63 {
			return "", nil, fmt.Errorf("%w: a label in %q is longer than 63 characters", ErrInvalid, raw)
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return "", nil, fmt.Errorf("%w: %q contains %q", ErrInvalid, raw, string(c))
			}
		}
	}
	if numericLabel(labels[len(labels)-1]) {
		return "", nil, fmt.Errorf("%w: %q ends in a number but is not a valid IP address", ErrInvalid, raw)
	}
	return h, nil, nil
}

// numericLabel reports labels that address parsers treat as numbers:
// decimal, octal with a leading 0, or hex with 0x.
func numericLabel(l string) bool {
	if l == "" {
		return false
	}
	if strings.HasPrefix(l, "0x") {
		for i := 2; i < len(l); i++ {
			c := l[i]
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
				return false
			}
		}
		return true
	}
	for i := 0; i < len(l); i++ {
		if l[i] < '0' || l[i] > '9' {
			return false
		}
	}
	return true
}

func (r *Rule) portOK(port int) bool { return r.Port == 0 || r.Port == port }

func (r *Rule) matchName(host string, port int) bool {
	if host == "" || !r.portOK(port) {
		return false
	}
	switch r.Kind {
	case KindExact:
		return host == r.Host
	case KindWildcard:
		return len(host) > len(r.Host) && strings.HasSuffix(host, r.Host)
	}
	return false
}

func (r *Rule) matchAddr(ip net.IP, port int) bool {
	if ip == nil || !r.portOK(port) {
		return false
	}
	switch r.Kind {
	case KindIP:
		return canon(ip).Equal(canon(r.IP))
	case KindCIDR:
		return r.Net.Contains(canon(ip))
	}
	return false
}

// canon returns the 4-byte form of IPv4 and IPv4-mapped addresses.
func canon(ip net.IP) net.IP {
	if v4 := ip.To4(); v4 != nil {
		return v4
	}
	return ip
}

// NeedsAddresses reports whether the decision for t can depend on the
// addresses its name resolves to. The broker resolves the name before
// deciding only when it can, and never resolves a name that is denied.
func (p *Policy) NeedsAddresses(t Target) bool {
	if t.Host == "" || t.RemoteDNS {
		return false
	}
	for i := range p.Deny {
		if p.Deny[i].matchName(t.Host, t.Port) {
			return false
		}
	}
	if p.Default == Allow {
		return p.DenyPrivate || p.addrDeny
	}
	for i := range p.Allow {
		if p.Allow[i].matchName(t.Host, t.Port) {
			return p.DenyPrivate || p.addrDeny
		}
	}
	return false
}

// Decide returns the decision for t. addrs are the addresses its name
// resolved to, or nil when the target is an address, when the path resolves
// names at its exit, or when NeedsAddresses said they cannot matter.
func (p *Policy) Decide(t Target, addrs []net.IP) Decision {
	if t.Host == "" {
		if t.IP == nil {
			return Decision{Allow: false, Rule: "invalid", Reason: "no destination"}
		}
		return p.decideAddrs([]net.IP{t.IP}, t, nil, false)
	}
	for i := range p.Deny {
		if r := &p.Deny[i]; r.matchName(t.Host, t.Port) {
			return Decision{Allow: false, Rule: r.ID, Text: r.Text, Reason: fmt.Sprintf("%s matches deny rule %q", t.Host, r.Text)}
		}
	}
	var nameAllow *Rule
	for i := range p.Allow {
		if r := &p.Allow[i]; r.matchName(t.Host, t.Port) {
			nameAllow = r
			break
		}
	}
	if len(addrs) == 0 {
		if nameAllow != nil {
			return Decision{Allow: true, Rule: nameAllow.ID, Text: nameAllow.Text, Reason: fmt.Sprintf("%s matches allow rule %q", t.Host, nameAllow.Text)}
		}
		return p.defaultDecision(t, t.RemoteDNS)
	}
	return p.decideAddrs(addrs, t, nameAllow, true)
}

func (p *Policy) decideAddrs(addrs []net.IP, t Target, nameAllow *Rule, resolved bool) Decision {
	subject := func(ip net.IP) string {
		if resolved {
			return fmt.Sprintf("%s resolved to %s", t.Host, ip)
		}
		return ip.String()
	}
	for _, ip := range addrs {
		for i := range p.Deny {
			if r := &p.Deny[i]; r.matchAddr(ip, t.Port) {
				return Decision{Allow: false, Rule: r.ID, Text: r.Text, Reason: fmt.Sprintf("%s, which matches deny rule %q", subject(ip), r.Text)}
			}
		}
		if p.DenyPrivate {
			if why, bad := PrivateReason(ip); bad {
				return Decision{Allow: false, Rule: "deny_private", Reason: fmt.Sprintf("%s: %s", subject(ip), why)}
			}
		}
	}
	if nameAllow != nil {
		return Decision{Allow: true, Rule: nameAllow.ID, Text: nameAllow.Text, Reason: fmt.Sprintf("%s matches allow rule %q", t.Host, nameAllow.Text)}
	}
	if !resolved {
		// An address typed as a number: address allow rules apply.
		for i := range p.Allow {
			if r := &p.Allow[i]; r.matchAddr(addrs[0], t.Port) {
				return Decision{Allow: true, Rule: r.ID, Text: r.Text, Reason: fmt.Sprintf("%s matches allow rule %q", addrs[0], r.Text)}
			}
		}
	}
	return p.defaultDecision(t, false)
}

func (p *Policy) defaultDecision(t Target, remote bool) Decision {
	d := Decision{Allow: p.Default == Allow, Rule: "default"}
	what := t.Label()
	if p.Default == Allow {
		d.Reason = fmt.Sprintf("no rule matches %s; default is allow (%s)", what, p.DefaultNote)
	} else {
		d.Reason = fmt.Sprintf("no allow rule matches %s; default is deny (%s)", what, p.DefaultNote)
	}
	if remote && p.Default == Allow {
		d.Reason += "; names resolve at the exit, so address rules cannot apply"
	}
	return d
}

// CheckRemoteDNS refuses combinations that would quietly weaken deny_private
// on a path that resolves names at its exit: with default allow, a name that
// resolves to a private address there could not be caught.
func (p *Policy) CheckRemoteDNS(pathName string) error {
	if p.DenyPrivate && p.Default == Allow {
		return fmt.Errorf("path %q resolves names at its exit, so deny_private cannot check where a name points; add an allow list (default deny) or use dns = \"local\"", pathName)
	}
	return nil
}

// Summary describes the policy for the run.start event.
func (p *Policy) Summary() map[string]any {
	return map[string]any{
		"name":         p.Name,
		"default":      p.Default.String(),
		"default_note": p.DefaultNote,
		"deny_private": p.DenyPrivate,
		"allow_rules":  len(p.Allow),
		"deny_rules":   len(p.Deny),
	}
}

// FromFlags builds a policy from command-line flags.
func FromFlags(allow, deny []string, denyPrivate bool, def string) (*Policy, error) {
	spec := &config.PolicySpec{Allow: allow, Deny: deny, DenyPrivate: denyPrivate, DenyPrivateSet: denyPrivate, Default: def}
	return New(spec, "command line")
}
