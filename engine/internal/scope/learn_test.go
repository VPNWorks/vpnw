// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package scope_test

import (
	"math"
	"net/netip"
	"strings"
	"testing"
	"time"

	"vpnw.com/vpnw/internal/scope"
	"vpnw.com/vpnw/internal/scope/office"
)

// usage records, per person and destination, the distinct UTC days of use.
type usage map[string]map[scope.Key]map[int64]bool

func record(o *office.Office, p *scope.People, from, to int, seed uint64) (usage, []scope.Flow) {
	u := usage{}
	var flows []scope.Flow
	o.Flows(from, to, seed, func(f scope.Flow) {
		flows = append(flows, f)
		per := p.ByAddr(f.Src)
		if per == nil {
			return
		}
		if u[per.ID] == nil {
			u[per.ID] = map[scope.Key]map[int64]bool{}
		}
		if u[per.ID][f.Key()] == nil {
			u[per.ID][f.Key()] = map[int64]bool{}
		}
		u[per.ID][f.Key()][int64(math.Floor(float64(f.Time.Unix())/86400))] = true
	})
	return u, flows
}

func inReview(d *scope.Draft, id string, k scope.Key) bool {
	rs := d.People[id]
	if rs == nil {
		return false
	}
	for _, r := range rs.Review {
		if r.Dest == scope.DestOf(k) {
			return true
		}
	}
	return false
}

// checkDraft checks the learner's promises on one office.
func checkDraft(t *testing.T, o *office.Office, seed uint64, opt scope.LearnOptions) {
	t.Helper()
	p := o.People()
	u, flows := record(o, p, 0, 14, seed)
	l := scope.NewLearner(p, opt)
	for _, f := range flows {
		l.Add(f)
	}
	d := l.Draft()
	pol := scope.Compile(d, p)
	minDays := opt.MinDays
	if minDays == 0 {
		minDays = 2
	}
	share := opt.GroupShare
	if share == 0 {
		share = 1
	}

	// 1. Every flow in the window is allowed unless its destination is under
	// review for that person.
	for _, f := range flows {
		per := p.ByAddr(f.Src)
		v := pol.Decide(f)
		if v.Outcome == scope.Allowed {
			continue
		}
		if !inReview(d, per.ID, f.Key()) {
			t.Fatalf("seed %d: %s -> %s denied (%s) but not under review", seed, per.ID, f.Key(), v.Reason)
		}
	}

	// 2. Every rule is backed by use.
	active := func(g string) []*scope.Person {
		var out []*scope.Person
		for _, per := range p.Groups[g] {
			if len(u[per.ID]) > 0 {
				out = append(out, per)
			}
		}
		return out
	}
	for _, g := range d.GroupOrder {
		act := active(g)
		need := int(math.Ceil(share * float64(len(act))))
		if need < 2 {
			need = 2
		}
		for _, r := range d.Groups[g].Allow {
			k := scope.Key{Dst: r.Dest.Net.Addr(), Port: r.Dest.Lo, Proto: r.Dest.Proto}
			n := 0
			for _, per := range act {
				if len(u[per.ID][k]) >= minDays {
					n++
				}
			}
			if n < need {
				t.Fatalf("seed %d: group %s rule %s backed by %d active members, need %d", seed, g, r.Dest, n, need)
			}
		}
	}
	for _, id := range d.PeopleOrder {
		for _, r := range d.People[id].Allow {
			k := scope.Key{Dst: r.Dest.Net.Addr(), Port: r.Dest.Lo, Proto: r.Dest.Proto}
			if len(u[id][k]) < minDays {
				t.Fatalf("seed %d: %s personal rule %s used on %d days", seed, id, r.Dest, len(u[id][k]))
			}
		}
		for _, r := range d.People[id].Review {
			k := scope.Key{Dst: r.Dest.Net.Addr(), Port: r.Dest.Lo, Proto: r.Dest.Proto}
			if n := len(u[id][k]); n == 0 || n >= minDays {
				t.Fatalf("seed %d: %s review entry %s used on %d days", seed, id, r.Dest, n)
			}
		}
	}

	// 3. With the default share, nobody active is allowed anything they did
	// not use on enough days: try every person on every service.
	if share < 1 {
		return
	}
	for _, per := range p.List {
		if len(u[per.ID]) == 0 {
			continue
		}
		for _, s := range o.Systems {
			for _, sv := range s.Services {
				f := scope.Flow{Time: flows[0].Time, Proto: sv.Proto, Src: per.Addrs[0], Dst: s.Addr, Port: sv.Port}
				if pol.Decide(f).Outcome == scope.Allowed && len(u[per.ID][f.Key()]) < minDays {
					t.Fatalf("seed %d: %s is allowed %s, used on %d days", seed, per.ID, f.Key(), len(u[per.ID][f.Key()]))
				}
			}
		}
	}
}

func TestLearnPromisesDemo(t *testing.T) {
	checkDraft(t, office.Demo(), office.DemoSeed, scope.LearnOptions{})
}

func TestLearnPromisesRandomOffices(t *testing.T) {
	for seed := uint64(1); seed <= 12; seed++ {
		checkDraft(t, office.Large(150, seed), seed, scope.LearnOptions{})
	}
}

func TestLearnPromisesOptions(t *testing.T) {
	for seed := uint64(1); seed <= 4; seed++ {
		checkDraft(t, office.Large(150, seed), seed, scope.LearnOptions{MinDays: 1})
		checkDraft(t, office.Large(150, seed), seed, scope.LearnOptions{MinDays: 4})
		checkDraft(t, office.Large(150, seed), seed, scope.LearnOptions{GroupShare: 0.5})
	}
}

func TestLearnMinDaysOneHasNoReview(t *testing.T) {
	o := office.Demo()
	l := scope.NewLearner(o.People(), scope.LearnOptions{MinDays: 1})
	o.Flows(0, 14, office.DemoSeed, l.Add)
	if c := l.Draft().Count(); c.Review != 0 {
		t.Fatalf("%d review entries with --min-days 1", c.Review)
	}
}

func TestLearnWindowAndStats(t *testing.T) {
	src := `version = 1
vpn_net = "10.8.0.0/24"
[people.a]
addresses = ["10.8.0.11"]
groups = ["g"]
[people.b]
addresses = ["10.8.0.12"]
groups = ["g"]
[people.c]
addresses = ["10.8.0.13"]
groups = ["g"]
`
	p, err := scope.ParsePeople(src, "p.toml")
	if err != nil {
		t.Fatal(err)
	}
	from := time.Date(2026, 9, 7, 0, 0, 0, 0, time.UTC)
	to := from.AddDate(0, 0, 2)
	l := scope.NewLearner(p, scope.LearnOptions{From: from, To: to})
	add := func(src, dst string, port uint16, at time.Time) {
		l.Add(scope.Flow{Time: at, Proto: scope.TCP, Src: netip.MustParseAddr(src), Dst: netip.MustParseAddr(dst), Port: port})
	}
	day1, day2 := from.Add(9*time.Hour), from.Add(33*time.Hour)
	add("10.8.0.11", "10.0.1.20", 443, from) // the first instant is in
	add("10.8.0.11", "10.0.1.20", 443, day2)
	add("10.8.0.12", "10.0.1.20", 443, day1)
	add("10.8.0.12", "10.0.1.20", 443, day2)
	add("10.8.0.12", "10.0.1.21", 22, day1) // one day only: review
	add("10.8.0.11", "10.0.9.9", 22, to)    // the end instant is out
	add("10.8.0.11", "10.0.9.9", 22, from.Add(-time.Second))
	add("10.8.0.99", "10.0.1.20", 443, day1) // no one's address
	add("192.168.0.5", "10.0.1.20", 443, day1)
	d := l.Draft()
	st := l.Stats
	if st.Flows != 9 || st.InWindow != 7 || st.FromPeople != 5 || st.OutsideVPN != 1 || st.Unknown[netip.MustParseAddr("10.8.0.99")] != 1 {
		t.Fatalf("stats %+v", st)
	}
	// a and b are active, c is not: the group rule needs both active members.
	if g := d.Groups["g"]; len(g.Allow) != 1 || g.Allow[0].Dest.String() != "10.0.1.20:443/tcp" || !strings.Contains(g.Allow[0].Note, "both active members, 2 days, 4 connections") {
		t.Fatalf("group rules %+v", d.Groups["g"])
	}
	if b := d.People["b"]; b == nil || len(b.Allow) != 0 || len(b.Review) != 1 || b.Review[0].Note != "1 day, 1 connection" {
		t.Fatalf("b %+v", d.People["b"])
	}
	text := d.String()
	for _, want := range []string{
		"learned from 7 flows between 2026-09-07 and 2026-09-08 (UTC)",
		"3 people in 1 group; 2 with traffic in the window.",
		"they get their groups' rules only: c.",
		"10.8.0.99 (1 flow)",
		"1 flow came from outside the VPN range",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("draft header lacks %q:\n%s", want, text)
		}
	}
	// With a lower share, the header says so.
	l2 := scope.NewLearner(p, scope.LearnOptions{GroupShare: 0.5})
	if !strings.Contains(l2.Draft().String(), "needs 50% of the group's active members") || !strings.Contains(l2.Draft().String(), "no flows in the window") {
		t.Error("share header")
	}
}
