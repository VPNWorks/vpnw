// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

// Package learn turns traces into a starting policy: every destination a
// workload reached becomes an allow rule, everything else is denied.
//
// Learn allows what the workload did, including anything it should not have
// done, so its output is a draft to read before use. It helps the reader:
// destinations that were denied, raw IP addresses, and connections that sent
// much more than they received are marked in comments.
package learn

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/VPNWorks/vpnw/internal/events"
	"github.com/VPNWorks/vpnw/internal/policy"
	"github.com/VPNWorks/vpnw/internal/version"
)

// Options shape the output.
type Options struct {
	Name string
	// Ports writes host:port rules instead of host rules.
	Ports bool
	// Wildcards folds three or more subdomains of one domain into *.domain.
	Wildcards bool
	// Now stamps the header; zero means leave the date out.
	Now time.Time
}

type dest struct {
	key       string // host or IP as it will appear in the rule
	isIP      bool
	ports     map[int]bool
	opened    int
	denied    int
	failed    int
	up, down  int64
	denyWhy   string
	failWhy   string
	lastProto string
	private   string // a private address it was reached at, if any
}

// Result is the learned policy and what went into it.
type Result struct {
	TOML         string
	Allowed      []string
	Denied       []string
	Unreached    []string // tried, never opened and never denied
	Runs         []string
	Connections  int
	FlaggedIPs   []string
	FlaggedHeavy []string
	// Private lists allowed destinations reached at a private address.
	// The draft keeps deny_private on, which refuses them, and says so.
	Private []string
}

// FromEvents learns from one or more traces.
func FromEvents(evs []events.Event, opt Options) Result {
	type connInfo struct {
		key  string
		isIP bool
		port int
	}
	conns := map[string]*connInfo{} // run/conn -> destination
	dests := map[string]*dest{}
	runs := map[string]bool{}
	var runOrder []string
	get := func(k string, isIP bool) *dest {
		d, ok := dests[k]
		if !ok {
			d = &dest{key: k, isIP: isIP, ports: map[int]bool{}}
			dests[k] = d
		}
		return d
	}
	total := 0
	for i := range evs {
		e := &evs[i]
		if !runs[e.Run] {
			runs[e.Run] = true
			runOrder = append(runOrder, e.Run)
		}
		ck := e.Run + "/" + strconv.FormatUint(e.Conn, 10)
		switch e.Type {
		case events.ConnectionAttempt:
			if strings.HasPrefix(e.Str("proto"), "socks5-") {
				continue // BIND / UDP requests are never learned
			}
			host, isIP := e.Str("host"), false
			if host == "" {
				host, isIP = e.Str("ip"), true
			}
			if host == "" {
				continue
			}
			ci := &connInfo{key: host, isIP: isIP, port: int(e.Int("port"))}
			conns[ck] = ci
			total++
		case events.ConnectionOpen:
			if ci, ok := conns[ck]; ok {
				d := get(ci.key, ci.isIP)
				d.opened++
				d.ports[ci.port] = true
				at := e.Str("ip")
				if at == "" && ci.isIP {
					at = ci.key
				}
				if ip := net.ParseIP(at); ip != nil && d.private == "" {
					if _, bad := policy.PrivateReason(ip); bad {
						d.private = ip.String()
					}
				}
			}
		case events.PolicyDeny:
			if ci, ok := conns[ck]; ok {
				d := get(ci.key, ci.isIP)
				d.denied++
				if d.denyWhy == "" {
					d.denyWhy = e.Str("reason")
				}
				d.ports[ci.port] = true
			}
		case events.ConnectionError:
			if ci, ok := conns[ck]; ok {
				d := get(ci.key, ci.isIP)
				d.failed++
				if d.failWhy == "" {
					d.failWhy = e.Str("error")
				}
			}
		case events.ConnectionClose:
			if ci, ok := conns[ck]; ok {
				d := get(ci.key, ci.isIP)
				d.up += e.Int("bytes_up")
				d.down += e.Int("bytes_down")
			}
		}
	}

	var allowed, denied, unreached []*dest
	for _, d := range dests {
		switch {
		case d.opened > 0:
			allowed = append(allowed, d)
		case d.denied > 0:
			denied = append(denied, d)
		case d.failed > 0:
			unreached = append(unreached, d)
		}
	}
	sortDests(allowed)
	sortDests(denied)
	sortDests(unreached)

	res := Result{Runs: runOrder, Connections: total}
	var rules []string
	var notes []string
	folded := map[string]bool{}
	if opt.Wildcards {
		groups := map[string][]*dest{}
		for _, d := range allowed {
			if d.isIP {
				continue
			}
			if parent := parentDomain(d.key); parent != "" {
				groups[parent] = append(groups[parent], d)
			}
		}
		var parents []string
		for p, list := range groups {
			if len(list) >= 3 {
				parents = append(parents, p)
			}
		}
		sort.Strings(parents)
		for _, p := range parents {
			var n int
			for _, d := range groups[p] {
				folded[d.key] = true
				n += d.opened
			}
			rules = append(rules, ruleLine("*."+p, fmt.Sprintf("%d names, %d connections", len(groups[p]), n)))
		}
	}
	for _, d := range allowed {
		if folded[d.key] {
			continue
		}
		key := d.key
		if d.isIP && strings.Contains(key, ":") {
			key = "[" + key + "]"
		}
		ports := sortedPorts(d.ports)
		comment := fmt.Sprintf("%d connection%s, port %s", d.opened, plural(d.opened), joinInts(ports))
		if opt.Ports {
			for _, p := range ports {
				rules = append(rules, ruleLine(key+":"+strconv.Itoa(p), comment))
			}
		} else {
			rules = append(rules, ruleLine(key, comment))
		}
		if d.isIP {
			res.FlaggedIPs = append(res.FlaggedIPs, d.key)
			notes = append(notes, fmt.Sprintf("# check: %s is a raw IP address; a host name is easier to review", d.key))
		}
		if d.up > 16*1024 && d.up > 4*d.down {
			res.FlaggedHeavy = append(res.FlaggedHeavy, d.key)
			notes = append(notes, fmt.Sprintf("# check: the workload sent %s to %s and received only %s; make sure that upload was expected",
				events.HumanBytes(d.up), d.key, events.HumanBytes(d.down)))
		}
		if d.private != "" {
			res.Private = append(res.Private, d.key)
			at := ""
			if d.private != d.key {
				at = " at " + d.private
			}
			notes = append(notes, fmt.Sprintf("# check: %s was reached%s, a private address; deny_private refuses it, so its rule has no effect unless you set deny_private = false", d.key, at))
		}
		res.Allowed = append(res.Allowed, d.key)
	}
	for _, d := range denied {
		res.Denied = append(res.Denied, d.key)
	}
	for _, d := range unreached {
		res.Unreached = append(res.Unreached, d.key)
	}

	var b strings.Builder
	name := opt.Name
	if name == "" {
		name = "learned"
	}
	fmt.Fprintf(&b, "# Learned by vpnw %s from %d trace%s (%s), %d connection attempt%s", version.Version,
		len(runOrder), plural(len(runOrder)), strings.Join(runOrder, ", "), total, plural(total))
	if !opt.Now.IsZero() {
		fmt.Fprintf(&b, ", %s", opt.Now.Format("2006-01-02"))
	}
	b.WriteString(".\n")
	b.WriteString("# Learn allows what the workload did, including anything it should not have done.\n")
	b.WriteString("# Read it before you use it.\n")
	for _, n := range notes {
		b.WriteString(n + "\n")
	}
	b.WriteString("\nversion = 1\n")
	fmt.Fprintf(&b, "name = %q\n\n[policy]\ndefault = \"deny\"\ndeny_private = true\n", name)
	if len(rules) == 0 {
		b.WriteString("allow = []\n")
	} else {
		b.WriteString("allow = [\n")
		width := 0
		for _, r := range rules {
			if i := strings.Index(r, "\x00"); i > width {
				width = i
			}
		}
		for i, r := range rules {
			parts := strings.SplitN(r, "\x00", 2)
			comma := ","
			if i == len(rules)-1 {
				comma = ""
			}
			fmt.Fprintf(&b, "  %-*s # %s\n", width+3, parts[0]+comma, parts[1])
		}
		b.WriteString("]\n")
	}
	if len(denied) > 0 {
		b.WriteString("\n# Denied during the trace, left out. Add one only if the workload really needs it:\n")
		for _, d := range denied {
			fmt.Fprintf(&b, "#   %q  (%s)\n", d.key, oneLine(d.denyWhy))
		}
	}
	if len(unreached) > 0 {
		b.WriteString("\n# Tried but never reached, left out. The workload may need another path (--via) for these:\n")
		for _, d := range unreached {
			fmt.Fprintf(&b, "#   %q  (%s)\n", d.key, oneLine(d.failWhy))
		}
	}
	res.TOML = b.String()
	return res
}

func ruleLine(rule, comment string) string { return strconv.Quote(rule) + "\x00" + comment }

func oneLine(s string) string {
	if len(s) > 120 {
		return s[:117] + "..."
	}
	return s
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func sortedPorts(m map[int]bool) []int {
	out := make([]int, 0, len(m))
	for p := range m {
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}

func joinInts(v []int) string {
	s := make([]string, len(v))
	for i, n := range v {
		s[i] = strconv.Itoa(n)
	}
	return strings.Join(s, ", ")
}

func sortDests(d []*dest) {
	sort.Slice(d, func(i, j int) bool {
		if d[i].isIP != d[j].isIP {
			return !d[i].isIP
		}
		return reverseLabels(d[i].key) < reverseLabels(d[j].key)
	})
}

// reverseLabels sorts names by domain: api.github.com sorts as com.github.api.
func reverseLabels(h string) string {
	if net.ParseIP(h) != nil {
		return h
	}
	l := strings.Split(h, ".")
	for i, j := 0, len(l)-1; i < j; i, j = i+1, j-1 {
		l[i], l[j] = l[j], l[i]
	}
	return strings.Join(l, ".")
}

// parentDomain returns the name without its first label, if that still has
// at least two labels.
func parentDomain(h string) string {
	i := strings.IndexByte(h, '.')
	if i < 0 {
		return ""
	}
	p := h[i+1:]
	if !strings.Contains(p, ".") {
		return ""
	}
	return p
}
