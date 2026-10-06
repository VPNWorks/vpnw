// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package scope

import (
	"fmt"
	"math"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"
)

// LearnOptions tune how a draft is learned.
type LearnOptions struct {
	// From and To bound the learning window: From is included, To is not.
	// Zero values leave that side open.
	From, To time.Time
	// MinDays is how many distinct days (UTC) a destination must have been
	// used on to be allowed. Less than that, it goes under review. Default 2.
	MinDays int
	// GroupShare is the share of a group's active members that must have
	// used a destination for it to become a group rule. The default, 1,
	// means every active member, so a group rule never gives an active
	// member something they did not use.
	GroupShare float64
}

func (o *LearnOptions) defaults() {
	if o.MinDays <= 0 {
		o.MinDays = 2
	}
	if o.GroupShare <= 0 || o.GroupShare > 1 {
		o.GroupShare = 1
	}
}

type evidence struct {
	conns int
	days  []int32 // distinct UTC day numbers, in the order first seen
}

func (e *evidence) addDay(d int32) {
	for i := len(e.days) - 1; i >= 0; i-- {
		if e.days[i] == d {
			return
		}
	}
	e.days = append(e.days, d)
}

// LearnStats counts what the learner saw.
type LearnStats struct {
	Flows       int // flows given to Add
	InWindow    int // of those, inside the window
	FromPeople  int // of those, from a known person's address
	OutsideVPN  int // in the window but not from the VPN range
	Unknown     map[netip.Addr]int
	First, Last time.Time // first and last flow in the window
}

// Learner builds a draft from flows added one at a time.
type Learner struct {
	people *People
	opt    LearnOptions
	per    map[*Person]map[Key]*evidence
	Stats  LearnStats
}

// NewLearner returns a learner for the people in p.
func NewLearner(p *People, opt LearnOptions) *Learner {
	opt.defaults()
	return &Learner{people: p, opt: opt, per: map[*Person]map[Key]*evidence{}, Stats: LearnStats{Unknown: map[netip.Addr]int{}}}
}

func dayOf(t time.Time) int32 { return int32(math.Floor(float64(t.Unix()) / 86400)) }

// Add takes one flow into account.
func (l *Learner) Add(f Flow) {
	l.Stats.Flows++
	if !l.opt.From.IsZero() && f.Time.Before(l.opt.From) {
		return
	}
	if !l.opt.To.IsZero() && !f.Time.Before(l.opt.To) {
		return
	}
	l.Stats.InWindow++
	if l.Stats.First.IsZero() || f.Time.Before(l.Stats.First) {
		l.Stats.First = f.Time
	}
	if f.Time.After(l.Stats.Last) {
		l.Stats.Last = f.Time
	}
	if !l.people.VPNNet.Contains(f.Src) {
		l.Stats.OutsideVPN++
		return
	}
	per := l.people.ByAddr(f.Src)
	if per == nil {
		l.Stats.Unknown[f.Src]++
		return
	}
	l.Stats.FromPeople++
	m := l.per[per]
	if m == nil {
		m = map[Key]*evidence{}
		l.per[per] = m
	}
	k := f.Key()
	e := m[k]
	if e == nil {
		e = &evidence{}
		m[k] = e
	}
	e.conns++
	e.addDay(dayOf(f.Time))
}

func sortedKeys(m map[Key]*evidence) []Key {
	keys := make([]Key, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		a, b := keys[i], keys[j]
		if a.Dst != b.Dst {
			return a.Dst.Less(b.Dst)
		}
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		return a.Proto < b.Proto
	})
	return keys
}

// Comma formats n with thousands separators, as in 20,232.
func Comma(n int) string {
	s := strconv.Itoa(n)
	neg := strings.HasPrefix(s, "-")
	if neg {
		s = s[1:]
	}
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	if neg {
		return "-" + s
	}
	return s
}

func plural(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return Comma(n) + " " + many
}

// Draft turns what was learned into a draft.
func (l *Learner) Draft() *Draft {
	d := NewDraft()
	solid := func(e *evidence) bool { return e != nil && len(e.days) >= l.opt.MinDays }

	// Group rules: a destination that enough active members used solidly.
	covered := map[*Person]map[Key]bool{}
	var inactive []string
	for _, per := range l.people.List {
		if len(l.per[per]) == 0 {
			inactive = append(inactive, per.ID)
		}
	}
	for _, g := range l.people.GroupOrder {
		var active []*Person
		for _, per := range l.people.Groups[g] {
			if len(l.per[per]) > 0 {
				active = append(active, per)
			}
		}
		rs := d.Group(g)
		if len(active) < 2 {
			continue // one active member: their rules stay personal
		}
		need := int(math.Ceil(l.opt.GroupShare * float64(len(active))))
		if need < 2 {
			need = 2
		}
		count := map[Key]int{}
		conns := map[Key]int{}
		days := map[Key]map[int32]bool{}
		for _, per := range active {
			for k, e := range l.per[per] {
				if !solid(e) {
					continue
				}
				count[k]++
				conns[k] += e.conns
				if days[k] == nil {
					days[k] = map[int32]bool{}
				}
				for _, dn := range e.days {
					days[k][dn] = true
				}
			}
		}
		agg := map[Key]*evidence{}
		for k, n := range count {
			if n >= need {
				agg[k] = &evidence{}
			}
		}
		for _, k := range sortedKeys(agg) {
			who := fmt.Sprintf("all %d active members", len(active))
			if len(active) == 2 {
				who = "both active members"
			}
			if count[k] < len(active) {
				who = fmt.Sprintf("%d of %d active members", count[k], len(active))
			}
			rs.Allow = append(rs.Allow, Rule{Dest: DestOf(k),
				Note: fmt.Sprintf("%s, %s, %s", who, plural(len(days[k]), "day", "days"), plural(conns[k], "connection", "connections"))})
			for _, per := range l.people.Groups[g] {
				if covered[per] == nil {
					covered[per] = map[Key]bool{}
				}
				covered[per][k] = true
			}
		}
	}

	// Personal rules: what each person used solidly and no group rule
	// covers. Destinations used on too few days go under review.
	for _, per := range l.people.List {
		m := l.per[per]
		if len(m) == 0 {
			continue
		}
		var rs *RuleSet
		for _, k := range sortedKeys(m) {
			if covered[per][k] {
				continue
			}
			e := m[k]
			if rs == nil {
				rs = d.Person(per.ID)
			}
			r := Rule{Dest: DestOf(k), Note: fmt.Sprintf("%s, %s", plural(len(e.days), "day", "days"), plural(e.conns, "connection", "connections"))}
			if solid(e) {
				rs.Allow = append(rs.Allow, r)
			} else {
				rs.Review = append(rs.Review, r)
			}
		}
	}

	d.Header = l.header(inactive)
	return d
}

func (l *Learner) header(inactive []string) []string {
	st := l.Stats
	var h []string
	span := "no flows in the window"
	if st.InWindow > 0 {
		span = fmt.Sprintf("between %s and %s (UTC)", st.First.UTC().Format("2006-01-02"), st.Last.UTC().Format("2006-01-02"))
	}
	h = append(h, fmt.Sprintf("vpnw-scope %s draft, learned from %s %s.", Version, plural(st.InWindow, "flow", "flows"), span))
	active := 0
	for _, per := range l.people.List {
		if len(l.per[per]) > 0 {
			active++
		}
	}
	h = append(h, fmt.Sprintf("%s in %s; %s with traffic in the window.",
		plural(len(l.people.List), "person", "people"), plural(len(l.people.GroupOrder), "group", "groups"), Comma(active)))
	if l.opt.GroupShare >= 1 {
		h = append(h, fmt.Sprintf("A group rule needs every active member of the group to have used the destination on %s or more.", plural(l.opt.MinDays, "day", "days")))
	} else {
		h = append(h, fmt.Sprintf("A group rule needs %.0f%% of the group's active members to have used the destination on %s or more.", l.opt.GroupShare*100, plural(l.opt.MinDays, "day", "days")))
	}
	h = append(h, fmt.Sprintf("A personal rule needs %s or more. Anything used less goes under review", plural(l.opt.MinDays, "day", "days")))
	h = append(h, "and stays blocked until a person moves it into allow.")
	if len(inactive) > 0 {
		h = append(h, "No traffic in the window, so they get their groups' rules only: "+strings.Join(inactive, ", ")+".")
	}
	if len(st.Unknown) > 0 {
		var addrs []netip.Addr
		for a := range st.Unknown {
			addrs = append(addrs, a)
		}
		sort.Slice(addrs, func(i, j int) bool { return addrs[i].Less(addrs[j]) })
		var parts []string
		for _, a := range addrs {
			parts = append(parts, fmt.Sprintf("%s (%s)", a, plural(st.Unknown[a], "flow", "flows")))
		}
		h = append(h, "VPN addresses not in the people file get no rules: "+strings.Join(parts, ", ")+".")
	}
	if st.OutsideVPN > 0 {
		h = append(h, fmt.Sprintf("%s came from outside the VPN range and were left out.", plural(st.OutsideVPN, "flow", "flows")))
	}
	return h
}
