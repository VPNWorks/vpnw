// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package scope

import (
	"fmt"
	"net/netip"
	"sort"
)

// Policy is a draft compiled for deciding flows. It decides exactly as the
// nftables rules from ExportNft do: traffic from outside the VPN range is
// not Scope's business and passes; traffic from a VPN address that belongs
// to no one is refused; everything else passes only if a rule for the
// person, or for one of their groups, allows it.
type Policy struct {
	vpnNet netip.Prefix
	bySrc  map[netip.Addr]*compiled
}

type labeled struct {
	dest  Dest
	label string
}

type compiled struct {
	person *Person
	exact  map[Key]string
	ranges []labeled
}

func (c *compiled) add(d Dest, label string) {
	if d.Single() {
		k := Key{Dst: d.Net.Addr(), Port: d.Lo, Proto: d.Proto}
		if _, ok := c.exact[k]; !ok {
			c.exact[k] = label
		}
		return
	}
	c.ranges = append(c.ranges, labeled{d, label})
}

// Compile prepares a draft for Decide. Review entries are not allowed.
func Compile(d *Draft, p *People) *Policy {
	pol := &Policy{vpnNet: p.VPNNet, bySrc: map[netip.Addr]*compiled{}}
	for _, per := range p.List {
		c := &compiled{person: per, exact: map[Key]string{}}
		if rs := d.People[per.ID]; rs != nil {
			for _, r := range rs.Allow {
				c.add(r.Dest, "person "+per.ID)
			}
		}
		for _, g := range per.Groups {
			if rs := d.Groups[g]; rs != nil {
				for _, r := range rs.Allow {
					c.add(r.Dest, "group "+g)
				}
			}
		}
		for _, a := range per.Addrs {
			pol.bySrc[a] = c
		}
	}
	return pol
}

// Outcome is how a flow is decided.
type Outcome int

const (
	Allowed Outcome = iota
	Denied
	NotVPN // not from the VPN range: the rules do not apply
)

func (o Outcome) String() string {
	switch o {
	case Allowed:
		return "allowed"
	case Denied:
		return "denied"
	}
	return "not-vpn"
}

// Verdict is the decision for one flow and why.
type Verdict struct {
	Outcome Outcome
	Person  string // "" for unknown or non-VPN sources
	Rule    string // for allowed flows: "person alice" or "group finance"
	Reason  string // for denied flows
}

// Decide decides one flow.
func (pol *Policy) Decide(f Flow) Verdict {
	if !pol.vpnNet.Contains(f.Src) {
		return Verdict{Outcome: NotVPN, Reason: "not from the VPN range"}
	}
	c := pol.bySrc[f.Src]
	if c == nil {
		return Verdict{Outcome: Denied, Reason: fmt.Sprintf("%s is in the VPN range but belongs to no one in the people file", f.Src)}
	}
	if f.Proto != TCP && f.Proto != UDP {
		return Verdict{Outcome: Denied, Person: c.person.ID, Reason: "only tcp and udp can be allowed"}
	}
	k := f.Key()
	if label, ok := c.exact[k]; ok {
		return Verdict{Outcome: Allowed, Person: c.person.ID, Rule: label}
	}
	for _, r := range c.ranges {
		if r.dest.Match(f.Dst, f.Port, f.Proto) {
			return Verdict{Outcome: Allowed, Person: c.person.ID, Rule: r.label}
		}
	}
	return Verdict{Outcome: Denied, Person: c.person.ID, Reason: fmt.Sprintf("no rule allows %s for %s", k, c.person.ID)}
}

// PersonReplay counts one person's replayed flows.
type PersonReplay struct {
	Allowed, Denied int
}

// DeniedKey is one person's destination that the draft would block.
type DeniedKey struct {
	Person string // "" for an unknown VPN address
	Src    netip.Addr
	Key    Key
	Count  int
}

// Replay decides flows one by one and keeps the totals.
type Replay struct {
	pol     *Policy
	Flows   int
	Allowed int
	Denied  int
	NotVPN  int
	People  map[string]*PersonReplay
	denied  map[deniedID]int
	byRule  map[string]int
}

type deniedID struct {
	src netip.Addr
	key Key
}

// NewReplay returns an empty replay for a policy.
func NewReplay(pol *Policy) *Replay {
	return &Replay{pol: pol, People: map[string]*PersonReplay{}, denied: map[deniedID]int{}, byRule: map[string]int{}}
}

// Add decides one flow and counts it.
func (r *Replay) Add(f Flow) Verdict {
	v := r.pol.Decide(f)
	r.Flows++
	switch v.Outcome {
	case NotVPN:
		r.NotVPN++
		return v
	case Allowed:
		r.Allowed++
		r.byRule[v.Rule]++
	case Denied:
		r.Denied++
		r.denied[deniedID{f.Src, f.Key()}]++
	}
	if v.Person != "" {
		pr := r.People[v.Person]
		if pr == nil {
			pr = &PersonReplay{}
			r.People[v.Person] = pr
		}
		if v.Outcome == Allowed {
			pr.Allowed++
		} else {
			pr.Denied++
		}
	}
	return v
}

// DeniedKeys lists what would have been blocked, most frequent first.
func (r *Replay) DeniedKeys() []DeniedKey {
	var out []DeniedKey
	for id, n := range r.denied {
		dk := DeniedKey{Src: id.src, Key: id.key, Count: n}
		if c := r.pol.bySrc[id.src]; c != nil {
			dk.Person = c.person.ID
		}
		out = append(out, dk)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Count != b.Count {
			return a.Count > b.Count
		}
		if a.Src != b.Src {
			return a.Src.Less(b.Src)
		}
		if a.Key.Dst != b.Key.Dst {
			return a.Key.Dst.Less(b.Key.Dst)
		}
		if a.Key.Port != b.Key.Port {
			return a.Key.Port < b.Key.Port
		}
		return a.Key.Proto < b.Key.Proto
	})
	return out
}
