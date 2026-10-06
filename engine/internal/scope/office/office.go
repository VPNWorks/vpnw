// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

// Package office generates the traffic of a made-up office VPN: people in
// groups, internal systems with their services, and who uses what, day by
// day. The same seed gives the same flows on every machine, in Go and in the
// browser build, so the numbers in reports and demos can be reproduced.
//
// Everything here is generated. It stands in for a real gateway's records
// in tests, measurements and the demo.
package office

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"

	"vpnw.com/vpnw/internal/scope"
)

// Service is one port on a system.
type Service struct {
	Port  uint16
	Proto scope.Proto
	Name  string
}

// System is an internal server.
type System struct {
	Name     string
	Addr     netip.Addr
	Services []Service
}

// Use is how often someone uses one service: the chance of using it on a
// working day they are in, and how many connections that day brings.
type Use struct {
	System   string
	Port     uint16
	Proto    scope.Proto
	P        float64
	Min, Max int
}

// Member is one person on the VPN.
type Member struct {
	ID, Name string
	Groups   []string
	Addr     netip.Addr
	Uses     []Use // on top of their groups' uses
	StartDay int   // first day of work, counted from the office's start
	OnCall   []int // weekend days they work
}

// Event is a one-off: someone connects somewhere on one day.
type Event struct {
	Person string
	Day    int
	System string
	Port   uint16
	Proto  scope.Proto
	Conns  int
}

// Change is a use that starts on a given day.
type Change struct {
	Person  string
	FromDay int
	Use     Use
}

// Office is a made-up VPN with its people, systems and habits.
type Office struct {
	Name      string
	VPNNet    netip.Prefix
	Start     time.Time // a Monday, 00:00 UTC
	Systems   []System
	Groups    map[string][]Use
	GroupList []string
	Members   []Member
	Events    []Event
	Changes   []Change
	// PresentP is the chance a person works on a given working day.
	PresentP float64

	sys map[string]*System
}

func (o *Office) index() {
	o.sys = map[string]*System{}
	for i := range o.Systems {
		o.sys[o.Systems[i].Name] = &o.Systems[i]
	}
}

// System returns a system by name.
func (o *Office) System(name string) *System {
	if o.sys == nil {
		o.index()
	}
	return o.sys[name]
}

// Day returns the start of day n.
func (o *Office) Day(n int) time.Time { return o.Start.AddDate(0, 0, n) }

// PeopleFile returns the office's people file.
func (o *Office) PeopleFile() string {
	var b strings.Builder
	fmt.Fprintf(&b, "# People on the %s VPN (generated).\nversion = 1\nvpn_net = %q\n", o.Name, o.VPNNet.String())
	for _, m := range o.Members {
		fmt.Fprintf(&b, "\n[people.%s]\nname = %q\naddresses = [%q]\ngroups = [", m.ID, m.Name, m.Addr.String())
		for i, g := range m.Groups {
			if i > 0 {
				b.WriteString(", ")
			}
			fmt.Fprintf(&b, "%q", g)
		}
		b.WriteString("]\n")
	}
	return b.String()
}

// People parses PeopleFile.
func (o *Office) People() *scope.People {
	p, err := scope.ParsePeople(o.PeopleFile(), o.Name+"-people.toml")
	if err != nil {
		panic("office: generated people file does not parse: " + err.Error())
	}
	return p
}

// rng is SplitMix64: small, fast, and the same in every Go build.
type rng struct{ s uint64 }

func (r *rng) next() uint64 {
	r.s += 0x9e3779b97f4a7c15
	z := r.s
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	return z ^ (z >> 31)
}

func (r *rng) float() float64 { return float64(r.next()>>11) / (1 << 53) }

func (r *rng) intn(n int) int { return int(r.next() % uint64(n)) }

// Flows generates the flows of days [from, to), in time order, and calls fn
// for each. The seed picks one of many possible fortnights.
func (o *Office) Flows(from, to int, seed uint64, fn func(scope.Flow)) {
	if o.sys == nil {
		o.index()
	}
	r := &rng{s: seed}
	var day []scope.Flow
	emit := func(m *Member, u Use, n int, d int, work bool) {
		sys := o.sys[u.System]
		if sys == nil {
			panic("office: no system " + u.System)
		}
		start, span := 7*3600+1800, 11*3600 // 07:30 to 18:30
		if !work {
			start, span = 10*3600, 6*3600
		}
		for i := 0; i < n; i++ {
			t := o.Day(d).Add(time.Duration(start+r.intn(span))*time.Second + time.Duration(r.intn(1000))*time.Millisecond)
			day = append(day, scope.Flow{Time: t, Proto: u.Proto, Src: m.Addr, Dst: sys.Addr, Port: u.Port})
		}
	}
	for d := 0; d < to; d++ {
		day = day[:0]
		weekday := o.Day(d).Weekday()
		working := weekday != time.Saturday && weekday != time.Sunday
		for i := range o.Members {
			m := &o.Members[i]
			// Draw for every person every day, so one person's habits do not
			// change another's draws.
			present := r.float() < o.PresentP
			onCall := false
			for _, oc := range m.OnCall {
				if oc == d {
					onCall = true
				}
			}
			if d < m.StartDay || (working && !present) || (!working && !onCall) {
				continue
			}
			var uses []Use
			for _, g := range m.Groups {
				uses = append(uses, o.Groups[g]...)
			}
			uses = append(uses, m.Uses...)
			for _, c := range o.Changes {
				if c.Person == m.ID && d >= c.FromDay {
					uses = append(uses, c.Use)
				}
			}
			for _, u := range uses {
				if !working && u.P < 0.9 {
					continue // on call: only the daily essentials
				}
				if r.float() >= u.P {
					continue
				}
				n := u.Min
				if u.Max > u.Min {
					n += r.intn(u.Max - u.Min + 1)
				}
				emit(m, u, n, d, working)
			}
		}
		for _, e := range o.Events {
			if e.Day != d {
				continue
			}
			m := o.member(e.Person)
			emit(m, Use{System: e.System, Port: e.Port, Proto: e.Proto}, e.Conns, d, true)
		}
		if d < from {
			continue
		}
		sort.SliceStable(day, func(i, j int) bool { return day[i].Time.Before(day[j].Time) })
		for _, f := range day {
			fn(f)
		}
	}
}

func (o *Office) member(id string) *Member {
	for i := range o.Members {
		if o.Members[i].ID == id {
			return &o.Members[i]
		}
	}
	panic("office: no member " + id)
}

// ScanPorts are the ports a stolen login tries on every system.
var ScanPorts = []struct {
	Port  uint16
	Proto scope.Proto
}{
	{22, scope.TCP}, {53, scope.TCP}, {53, scope.UDP}, {80, scope.TCP}, {443, scope.TCP}, {445, scope.TCP},
	{587, scope.TCP}, {993, scope.TCP}, {3389, scope.TCP}, {5432, scope.TCP}, {8080, scope.TCP}, {8443, scope.TCP},
}

// StolenLogin returns the flows of someone using person's VPN login to try
// every system on the ports in ScanPorts, starting at t, one attempt every
// 50 ms.
func (o *Office) StolenLogin(person string, t time.Time) []scope.Flow {
	m := o.member(person)
	var out []scope.Flow
	for _, s := range o.Systems {
		for _, p := range ScanPorts {
			out = append(out, scope.Flow{Time: t, Proto: p.Proto, Src: m.Addr, Dst: s.Addr, Port: p.Port})
			t = t.Add(50 * time.Millisecond)
		}
	}
	return out
}

// Offers reports whether a system listens on port/proto.
func (s *System) Offers(port uint16, proto scope.Proto) bool {
	for _, sv := range s.Services {
		if sv.Port == port && sv.Proto == proto {
			return true
		}
	}
	return false
}

// SystemAt returns the system with address a, or nil.
func (o *Office) SystemAt(a netip.Addr) *System {
	for i := range o.Systems {
		if o.Systems[i].Addr == a {
			return &o.Systems[i]
		}
	}
	return nil
}
