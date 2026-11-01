// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

// Package budget is the Budget plugin: a Guard that lets a program reach
// only the hosts on an allowlist, each with a budget of bytes sent, bytes
// received and connections. vpnw enforces the byte budgets itself (the
// plugin gives them, through the SDK's Budget, and vpnw counts and cuts);
// the plugin counts connections.
//
// Settings:
//
//	allow     entries separated by ";", each a host (api.github.com), a
//	          pattern for the names under a domain (*.npmjs.org, not
//	          npmjs.org itself), an IP address, or * for any host, followed
//	          by any of up=SIZE down=SIZE requests=N
//	up        bytes the program may send, for entries that don't say
//	down      bytes it may receive, likewise
//	requests  connections it may open, likewise
//
// SIZE is a number with B, KB, MB, GB, TB (powers of 1000) or KiB, MiB,
// GiB, TiB (powers of 1024), or 0 or "none" for no limit. A host on no
// entry is refused. The hosts a pattern covers share its budget, so a
// program can't get a fresh budget from each made-up subdomain; with *,
// each host has its own. At an exit every client has its own budgets.
package budget

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"net/netip"
	"sort"
	"strconv"
	"strings"

	"github.com/VPNWorks/vpnw/plugins/sdk"
)

// MaxCounters bounds the request counters the plugin keeps (one per budget
// key), for each client at an exit, the way vpnw bounds the byte budgets
// it keeps per Guard.
const MaxCounters = 100_000

const (
	kindHost = iota
	kindSuffix
	kindIP
	kindAny
)

// Entry is one entry of the allowlist.
type Entry struct {
	Pattern  string
	kind     int
	suffix   string // for *.x: ".x"
	ip       netip.Addr
	Up, Down int64 // 0: no limit
	Requests int64 // 0: no limit
}

// Rules are the plugin's settings, read, and its counts so far.
type Rules struct {
	hosts     map[string]*Entry
	suffixes  []*Entry // longest first
	ips       map[netip.Addr]*Entry
	anyHost   *Entry
	count     map[string]int64
	perClient map[string]int
}

var sizeUnits = map[string]float64{
	"": 1, "b": 1,
	"kb": 1e3, "mb": 1e6, "gb": 1e9, "tb": 1e12,
	"kib": 1 << 10, "mib": 1 << 20, "gib": 1 << 30, "tib": 1 << 40,
}

// ParseSize reads a byte count such as 10MB, 1.5GiB or 500; 0 and none
// mean no limit.
func ParseSize(s string) (int64, error) {
	t := strings.ToLower(strings.TrimSpace(s))
	if t == "none" {
		return 0, nil
	}
	i := 0
	for i < len(t) && (t[i] >= '0' && t[i] <= '9' || t[i] == '.') {
		i++
	}
	num, unit := t[:i], strings.TrimSpace(t[i:])
	mul, ok := sizeUnits[unit]
	if num == "" || !ok {
		return 0, fmt.Errorf("%q is not a size; write it as 10MB, 512KiB or 2GB", s)
	}
	f, err := strconv.ParseFloat(num, 64)
	if err != nil || f < 0 {
		return 0, fmt.Errorf("%q is not a size; write it as 10MB, 512KiB or 2GB", s)
	}
	v := f * mul
	if v >= math.MaxInt64/2 {
		return 0, fmt.Errorf("%q is too large", s)
	}
	if v > 0 && v < 1 {
		return 0, fmt.Errorf("%q is less than one byte", s)
	}
	return int64(v), nil
}

func parseCount(s string) (int64, error) {
	if strings.ToLower(s) == "none" {
		return 0, nil
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("%q is not a number of connections", s)
	}
	return n, nil
}

// validHost reports whether s is a host name as vpnw passes them on: lower
// case letters, digits, dashes and dots, labels of 1 to 63.
func validHost(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for _, l := range strings.Split(s, ".") {
		if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
	}
	return true
}

// Parse reads the plugin's settings.
func Parse(settings map[string]string) (*Rules, error) {
	for k := range settings {
		switch k {
		case "allow", "up", "down", "requests":
		default:
			return nil, fmt.Errorf("budget has no setting %q; it takes allow, up, down and requests", k)
		}
	}
	var def Entry
	var err error
	if v, ok := settings["up"]; ok {
		if def.Up, err = ParseSize(v); err != nil {
			return nil, fmt.Errorf("budget.up: %v", err)
		}
	}
	if v, ok := settings["down"]; ok {
		if def.Down, err = ParseSize(v); err != nil {
			return nil, fmt.Errorf("budget.down: %v", err)
		}
	}
	if v, ok := settings["requests"]; ok {
		if def.Requests, err = parseCount(v); err != nil {
			return nil, fmt.Errorf("budget.requests: %v", err)
		}
	}
	allow := strings.TrimSpace(settings["allow"])
	if allow == "" {
		return nil, fmt.Errorf("budget needs the hosts to allow: --set budget.allow='api.example.com up=10MB; *.example.org' (* allows any host)")
	}
	r := &Rules{hosts: map[string]*Entry{}, ips: map[netip.Addr]*Entry{}, count: map[string]int64{}, perClient: map[string]int{}}
	seen := map[string]bool{}
	for _, part := range strings.Split(allow, ";") {
		fields := strings.Fields(part)
		if len(fields) == 0 {
			continue
		}
		e := def
		e.Pattern = strings.ToLower(strings.TrimSuffix(fields[0], "."))
		if strings.Contains(e.Pattern, "=") {
			return nil, fmt.Errorf("budget.allow: an entry starts with %q; give the host first, then up=, down= or requests=", fields[0])
		}
		// An address is listed once however it is written (::1, [::1],
		// 0:0::1, ::ffff:10.0.0.1 for 10.0.0.1).
		canon := e.Pattern
		if a, err := netip.ParseAddr(strings.Trim(e.Pattern, "[]")); err == nil {
			canon = a.Unmap().String()
		}
		if seen[canon] {
			return nil, fmt.Errorf("budget.allow: %s is listed twice", e.Pattern)
		}
		seen[canon] = true
		for _, f := range fields[1:] {
			k, v, ok := strings.Cut(f, "=")
			if !ok {
				return nil, fmt.Errorf("budget.allow: %q after %s; write up=SIZE, down=SIZE or requests=N, and separate entries with ;", f, e.Pattern)
			}
			switch k {
			case "up":
				e.Up, err = ParseSize(v)
			case "down":
				e.Down, err = ParseSize(v)
			case "requests":
				e.Requests, err = parseCount(v)
			default:
				err = fmt.Errorf("%q is not up, down or requests", k)
			}
			if err != nil {
				return nil, fmt.Errorf("budget.allow, %s: %v", e.Pattern, err)
			}
		}
		ent := e
		switch {
		case e.Pattern == "*":
			ent.kind = kindAny
			r.anyHost = &ent
		case strings.HasPrefix(e.Pattern, "*."):
			if !validHost(e.Pattern[2:]) {
				return nil, fmt.Errorf("budget.allow: %q is not a domain pattern", e.Pattern)
			}
			ent.kind, ent.suffix = kindSuffix, e.Pattern[1:]
			r.suffixes = append(r.suffixes, &ent)
		default:
			if a, err := netip.ParseAddr(strings.Trim(e.Pattern, "[]")); err == nil {
				ent.kind, ent.ip = kindIP, a.Unmap()
				r.ips[ent.ip] = &ent
				continue
			}
			if !validHost(e.Pattern) {
				return nil, fmt.Errorf("budget.allow: %q is not a host, a *.domain pattern, an IP address or *", fields[0])
			}
			ent.kind = kindHost
			r.hosts[e.Pattern] = &ent
		}
	}
	if len(seen) == 0 {
		return nil, fmt.Errorf("budget.allow lists no hosts")
	}
	sort.SliceStable(r.suffixes, func(i, j int) bool { return len(r.suffixes[i].suffix) > len(r.suffixes[j].suffix) })
	return r, nil
}

// match finds the entry for a request: the host itself, then the longest
// pattern above it, then *; or an address's entry, then *.
func (r *Rules) match(q *sdk.Request) *Entry {
	if q.Host != "" {
		h := strings.ToLower(strings.TrimSuffix(q.Host, "."))
		if e := r.hosts[h]; e != nil {
			return e
		}
		for _, e := range r.suffixes {
			if strings.HasSuffix(h, e.suffix) && len(h) > len(e.suffix) {
				return e
			}
		}
		// A name that is an address ("10.0.0.1") meets the address entries.
		if a, err := netip.ParseAddr(strings.Trim(h, "[]")); err == nil {
			if e := r.ips[a.Unmap()]; e != nil {
				return e
			}
		}
		return r.anyHost
	}
	if a, err := netip.ParseAddr(q.IP); err == nil {
		if e := r.ips[a.Unmap()]; e != nil {
			return e
		}
	}
	return r.anyHost
}

// key names the budget a request counts against: the entry's, or under *
// the host's own; at an exit, the client's.
func key(e *Entry, q *sdk.Request) string {
	k := e.Pattern
	if e.kind == kindAny {
		k = "* " + target(q)
	}
	if q.Client != "" {
		k = q.Client + " " + k
	}
	if len(k) > 128 {
		sum := sha256.Sum256([]byte(k))
		k = k[:100] + "~" + hex.EncodeToString(sum[:8])
	}
	return k
}

func target(q *sdk.Request) string {
	if q.Host != "" {
		return strings.ToLower(strings.TrimSuffix(q.Host, "."))
	}
	return q.IP
}

// Decide answers one request.
func (r *Rules) Decide(q *sdk.Request) sdk.Decision {
	e := r.match(q)
	if e == nil {
		return sdk.Decision{Deny: true, Reason: target(q) + " is not on the budget allowlist"}
	}
	k := key(e, q)
	if q.Stage == "lookup" {
		// Asked before the name is looked up: refuse only, count nothing.
		if e.Requests > 0 && r.count[k] >= e.Requests {
			return sdk.Decision{Deny: true, Reason: fmt.Sprintf("request budget spent: %d connections (%s)", e.Requests, describe(e, q))}
		}
		return sdk.Decision{}
	}
	if e.Requests > 0 {
		n, ok := r.count[k]
		if !ok && r.perClient[q.Client] >= MaxCounters {
			return sdk.Decision{Deny: true, Reason: fmt.Sprintf("budget keeps request counts for %d hosts already, the most it may", MaxCounters)}
		}
		if n >= e.Requests {
			return sdk.Decision{Deny: true, Reason: fmt.Sprintf("request budget spent: %d connections (%s)", e.Requests, describe(e, q))}
		}
		if !ok {
			r.perClient[q.Client]++
		}
		r.count[k] = n + 1
	}
	if e.Up == 0 && e.Down == 0 {
		return sdk.Decision{}
	}
	return sdk.Decision{Budget: &sdk.Budget{Key: k, Up: e.Up, Down: e.Down, Reason: describe(e, q)}}
}

// describe says what a request's budget is, for the record.
func describe(e *Entry, q *sdk.Request) string {
	var parts []string
	if e.Up > 0 {
		parts = append(parts, FormatSize(e.Up)+" up")
	}
	if e.Down > 0 {
		parts = append(parts, FormatSize(e.Down)+" down")
	}
	if e.Requests > 0 {
		parts = append(parts, strconv.FormatInt(e.Requests, 10)+" connections")
	}
	who := e.Pattern
	if e.kind == kindAny {
		who = target(q)
	}
	if q.Client != "" {
		who = "client " + q.Client + ", " + who
	}
	return "budget for " + who + ": " + strings.Join(parts, ", ")
}

// FormatSize writes a byte count back the short way.
func FormatSize(n int64) string {
	for _, u := range []struct {
		s string
		v int64
	}{{"TiB", 1 << 40}, {"GiB", 1 << 30}, {"MiB", 1 << 20}, {"KiB", 1 << 10}, {"TB", 1e12}, {"GB", 1e9}, {"MB", 1e6}, {"KB", 1e3}} {
		if n >= u.v && n%u.v == 0 {
			return strconv.FormatInt(n/u.v, 10) + " " + u.s
		}
	}
	return strconv.FormatInt(n, 10) + " B"
}

// Plugin is the Budget plugin.
func Plugin() sdk.Plugin {
	var r *Rules
	return sdk.Plugin{
		Init: func(c *sdk.Config) error {
			var err error
			r, err = Parse(c.Settings)
			return err
		},
		Decide: func(q *sdk.Request) sdk.Decision {
			if r == nil {
				return sdk.Decision{Deny: true, Reason: "budget has no settings"}
			}
			return r.Decide(q)
		},
	}
}
