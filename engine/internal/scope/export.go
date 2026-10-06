// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package scope

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// NftOptions tune the nftables export.
type NftOptions struct {
	Table    string // default "vpnw_scope"
	Drop     bool   // drop refused packets instead of rejecting them
	Watch    bool   // count and log what would be refused, but refuse nothing
	LogGroup int    // if above 0, log refused (or would-be refused) packets to this NFLOG group
	Source   string // file names for the header comment
}

type element struct{ d Dest }

func (e element) String() string {
	var b strings.Builder
	if e.d.Net.Bits() == 32 {
		b.WriteString(e.d.Net.Addr().String())
	} else {
		b.WriteString(e.d.Net.String())
	}
	b.WriteString(" . ")
	b.WriteString(strconv.Itoa(int(e.d.Lo)))
	if e.d.Hi != e.d.Lo {
		b.WriteString("-" + strconv.Itoa(int(e.d.Hi)))
	}
	return b.String()
}

func contains(a, b Dest) bool {
	return a.Proto == b.Proto && a.Net.Bits() <= b.Net.Bits() && a.Net.Contains(b.Net.Addr()) && a.Lo <= b.Lo && b.Hi <= a.Hi
}

func overlaps(a, b Dest) bool {
	return a.Proto == b.Proto && a.Net.Overlaps(b.Net) && a.Lo <= b.Hi && b.Lo <= a.Hi
}

// setElements removes duplicates and destinations that another destination
// in the same set already covers, because nftables refuses overlapping
// intervals in one set. Partial overlaps are an error for a person to fix.
func setElements(owner string, dests []Dest) ([]Dest, error) {
	singles := map[Dest]bool{}
	var ranges []Dest
	for _, d := range dests {
		if d.Single() {
			singles[d] = true
		} else {
			ranges = append(ranges, d)
		}
	}
	sort.Slice(ranges, func(i, j int) bool { return lessDest(ranges[i], ranges[j]) })
	// Ranges: drop duplicates and ranges inside others; refuse partial overlaps.
	var keep []Dest
	for i, a := range ranges {
		inside := false
		for j, b := range ranges {
			if i == j {
				continue
			}
			if a == b {
				if j < i {
					inside = true // keep the first copy only
				}
				continue
			}
			if contains(b, a) {
				inside = true
				continue
			}
			if overlaps(a, b) && !contains(a, b) {
				return nil, fmt.Errorf("%s: %s and %s overlap without one containing the other; merge them into one rule", owner, a, b)
			}
		}
		if !inside {
			keep = append(keep, a)
		}
	}
	out := append([]Dest(nil), keep...)
	for d := range singles {
		covered := false
		for _, r := range keep {
			if contains(r, d) {
				covered = true
				break
			}
		}
		if !covered {
			out = append(out, d)
		}
	}
	sort.Slice(out, func(i, j int) bool { return lessDest(out[i], out[j]) })
	return out, nil
}

// nftName turns a person or group name into an nftables identifier that
// has not been used yet.
func nftName(prefix, name string, used map[string]bool) string {
	base := prefix + strings.ReplaceAll(name, "-", "_")
	n := base
	for i := 2; used[n]; i++ {
		n = base + "_" + strconv.Itoa(i)
	}
	used[n] = true
	return n
}

func writeSet(b *strings.Builder, name, typ string, elems []string, interval bool) {
	fmt.Fprintf(b, "\tset %s {\n\t\ttype %s\n", name, typ)
	if interval {
		b.WriteString("\t\tflags interval\n")
	}
	b.WriteString("\t\telements = {")
	for i, e := range elems {
		if i%4 == 0 {
			b.WriteString("\n\t\t\t")
		} else {
			b.WriteString(" ")
		}
		b.WriteString(e)
		if i < len(elems)-1 {
			b.WriteString(",")
		}
	}
	b.WriteString("\n\t\t}\n\t}\n")
}

func addrList(addrs []netip.Addr) []string {
	var out []string
	for _, a := range addrs {
		out = append(out, a.String())
	}
	return out
}

// ExportNft writes the draft as an nftables script for the gateway. It
// replaces its own table and leaves every other table alone. The script is
// meant to be loaded with "nft -f FILE" and decides exactly as Decide does.
func ExportNft(d *Draft, p *People, opt NftOptions) (string, error) {
	if opt.Table == "" {
		opt.Table = "vpnw_scope"
	}
	var sets strings.Builder
	var rules []string
	used := map[string]bool{}
	split := func(owner string, rs []Rule) (tcp, udp []Dest, err error) {
		var all []Dest
		for _, r := range rs {
			all = append(all, r.Dest)
		}
		els, err := setElements(owner, all)
		if err != nil {
			return nil, nil, err
		}
		for _, d := range els {
			if d.Proto == TCP {
				tcp = append(tcp, d)
			} else {
				udp = append(udp, d)
			}
		}
		return tcp, udp, nil
	}
	emit := func(name, match string, tcp, udp []Dest) {
		for _, part := range []struct {
			proto string
			dests []Dest
		}{{"tcp", tcp}, {"udp", udp}} {
			if len(part.dests) == 0 {
				continue
			}
			setName := name + "_" + part.proto
			var elems []string
			for _, dd := range part.dests {
				elems = append(elems, element{dd}.String())
			}
			writeSet(&sets, setName, "ipv4_addr . inet_service", elems, true)
			rules = append(rules, fmt.Sprintf("%s ip daddr . %s dport @%s accept", match, part.proto, setName))
		}
	}
	for _, g := range d.GroupOrder {
		rs := d.Groups[g]
		if len(rs.Allow) == 0 {
			continue
		}
		var srcs []netip.Addr
		for _, per := range p.Groups[g] {
			srcs = append(srcs, per.Addrs...)
		}
		if len(srcs) == 0 {
			continue
		}
		tcp, udp, err := split("group "+g, rs.Allow)
		if err != nil {
			return "", err
		}
		name := nftName("g_", g, used)
		writeSet(&sets, name+"_src", "ipv4_addr", addrList(srcs), false)
		emit(name, "ip saddr @"+name+"_src", tcp, udp)
	}
	for _, id := range d.PeopleOrder {
		rs := d.People[id]
		per := p.Get(id)
		if per == nil || len(rs.Allow) == 0 || len(per.Addrs) == 0 {
			continue
		}
		tcp, udp, err := split("person "+id, rs.Allow)
		if err != nil {
			return "", err
		}
		name := nftName("p_", id, used)
		emit(name, "ip saddr { "+strings.Join(addrList(per.Addrs), ", ")+" }", tcp, udp)
	}

	var b strings.Builder
	b.WriteString("#!/usr/sbin/nft -f\n")
	fmt.Fprintf(&b, "# vpnw-scope %s: least-privilege rules for VPN clients in %s.\n", Version, p.VPNNet)
	if opt.Source != "" {
		fmt.Fprintf(&b, "# Made from %s.\n", opt.Source)
	}
	if opt.Watch {
		b.WriteString("# Watch mode: nothing is refused. What the rules would refuse is counted\n# (nft list table inet " + opt.Table + ")")
		if opt.LogGroup > 0 {
			fmt.Fprintf(&b, " and logged to NFLOG group %d", opt.LogGroup)
		}
		b.WriteString(".\n")
	} else {
		b.WriteString("# Traffic from the VPN range passes only where a rule below allows it.\n")
	}
	b.WriteString("# Traffic to the gateway itself, and from outside the VPN range, is not\n# touched. Loading this file replaces the table of the same name only.\n")
	fmt.Fprintf(&b, "table inet %[1]s\ndelete table inet %[1]s\ntable inet %[1]s {\n", opt.Table)
	b.WriteString(sets.String())
	fmt.Fprintf(&b, "\tchain forward {\n\t\ttype filter hook forward priority filter; policy accept;\n\t\tip saddr %s jump from_vpn\n\t}\n", p.VPNNet)
	b.WriteString("\tchain from_vpn {\n\t\tct state established,related accept\n")
	for _, r := range rules {
		b.WriteString("\t\t" + r + "\n")
	}
	if opt.LogGroup > 0 {
		prefix := "vpnw-scope refused"
		if opt.Watch {
			prefix = "vpnw-scope would refuse"
		}
		fmt.Fprintf(&b, "\t\tlog prefix %q group %d\n", prefix, opt.LogGroup)
	}
	switch {
	case opt.Watch:
		b.WriteString("\t\tcounter accept comment \"would be refused\"\n")
	case opt.Drop:
		b.WriteString("\t\tdrop\n")
	default:
		b.WriteString("\t\treject with icmpx type admin-prohibited\n")
	}
	b.WriteString("\t}\n}\n")
	return b.String(), nil
}

// ExportAllowedIPs writes, for each person, the AllowedIPs line for their
// WireGuard client: the addresses the draft lets them reach, so the client
// routes only those through the tunnel. It enforces nothing: a client can
// change its own AllowedIPs. The gateway rules enforce the draft.
func ExportAllowedIPs(d *Draft, p *People) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# vpnw-scope %s: AllowedIPs for each client's [Peer] section.\n", Version)
	b.WriteString("# These only tell each client what to send through the tunnel. They\n# enforce nothing; the gateway's nftables rules do.\n")
	for _, per := range p.List {
		var nets []netip.Prefix
		add := func(rs *RuleSet) {
			if rs == nil {
				return
			}
			for _, r := range rs.Allow {
				nets = append(nets, r.Dest.Net)
			}
		}
		add(d.People[per.ID])
		for _, g := range per.Groups {
			add(d.Groups[g])
		}
		nets = minimalPrefixes(nets)
		b.WriteString("\n# " + per.ID)
		if per.Name != "" {
			b.WriteString(" (" + per.Name + ")")
		}
		b.WriteString("\n")
		if len(nets) == 0 {
			b.WriteString("# nothing allowed: no AllowedIPs beyond the tunnel itself\n")
			continue
		}
		var parts []string
		for _, n := range nets {
			parts = append(parts, n.String())
		}
		b.WriteString("AllowedIPs = " + strings.Join(parts, ", ") + "\n")
	}
	return b.String()
}

// minimalPrefixes sorts prefixes and drops any that another one contains.
func minimalPrefixes(in []netip.Prefix) []netip.Prefix {
	sort.Slice(in, func(i, j int) bool {
		if in[i].Bits() != in[j].Bits() {
			return in[i].Bits() < in[j].Bits()
		}
		return in[i].Addr().Less(in[j].Addr())
	})
	var out []netip.Prefix
	for _, n := range in {
		covered := false
		for _, o := range out {
			if o.Contains(n.Addr()) && o.Bits() <= n.Bits() {
				covered = true
				break
			}
		}
		if !covered {
			out = append(out, n)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Addr() != out[j].Addr() {
			return out[i].Addr().Less(out[j].Addr())
		}
		return out[i].Bits() < out[j].Bits()
	})
	return out
}
