// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

//go:build js && wasm

// Command scope-wasm runs Scope's own code in the browser demo: the office
// generator, the learner, the draft parser, the simulator and the exports.
// The page draws; every number it shows comes from these calls.
package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"syscall/js"

	"vpnw.com/vpnw/internal/scope"
	"vpnw.com/vpnw/internal/scope/office"
)

var (
	demo    = office.Demo()
	people  = demo.People()
	learnF  []scope.Flow
	replayF []scope.Flow
	perDay  = make([]int, office.DemoReplayTo)
)

func main() {
	demo.Flows(0, office.DemoReplayTo, office.DemoSeed, func(f scope.Flow) {
		day := int(f.Time.Sub(demo.Start).Hours() / 24)
		perDay[day]++
		if day < office.DemoLearnTo {
			learnF = append(learnF, f)
		} else {
			replayF = append(replayF, f)
		}
	})
	js.Global().Set("vpnwScope", js.ValueOf(map[string]any{
		"version": scope.Version,
		"office":  js.FuncOf(officeFn),
		"learn":   js.FuncOf(learnFn),
		"check":   js.FuncOf(checkFn),
		"replay":  js.FuncOf(replayFn),
		"stolen":  js.FuncOf(stolenFn),
		"export":  js.FuncOf(exportFn),
		"review":  js.FuncOf(reviewFn),
	}))
	select {}
}

func out(v any) any {
	b, err := json.Marshal(v)
	if err != nil {
		return `{"ok":false,"error":"` + err.Error() + `"}`
	}
	return string(b)
}

type failure struct {
	OK    bool   `json:"ok"`
	Error string `json:"error"`
}

func fail(err error) any { return out(failure{Error: err.Error()}) }

type service struct {
	Port  uint16 `json:"port"`
	Proto string `json:"proto"`
	Name  string `json:"name"`
}

type system struct {
	Name     string    `json:"name"`
	Addr     string    `json:"addr"`
	Services []service `json:"services"`
}

type person struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Groups   []string `json:"groups"`
	Addr     string   `json:"addr"`
	StartDay int      `json:"startDay"`
}

type group struct {
	Name    string   `json:"name"`
	Members []string `json:"members"`
}

// officeFn describes the demo office and its generated traffic.
func officeFn(js.Value, []js.Value) any {
	var o struct {
		Version     string   `json:"version"`
		Seed        uint64   `json:"seed"`
		Start       string   `json:"start"`
		LearnDays   int      `json:"learnDays"`
		ReplayDays  int      `json:"replayDays"`
		VPNNet      string   `json:"vpnNet"`
		Groups      []group  `json:"groups"`
		People      []person `json:"people"`
		Systems     []system `json:"systems"`
		PerDay      []int    `json:"perDay"`
		LearnFlows  int      `json:"learnFlows"`
		ReplayFlows int      `json:"replayFlows"`
		PeopleFile  string   `json:"peopleFile"`
		Stolen      string   `json:"stolen"`
		StolenAt    string   `json:"stolenAt"`
	}
	o.Version, o.Seed, o.Start = scope.Version, office.DemoSeed, demo.Start.Format("2006-01-02")
	o.LearnDays, o.ReplayDays = office.DemoLearnTo-office.DemoLearnFrom, office.DemoReplayTo-office.DemoReplayFrom
	o.VPNNet = demo.VPNNet.String()
	for _, g := range people.GroupOrder {
		gr := group{Name: g}
		for _, p := range people.Groups[g] {
			gr.Members = append(gr.Members, p.ID)
		}
		o.Groups = append(o.Groups, gr)
	}
	for _, m := range demo.Members {
		o.People = append(o.People, person{ID: m.ID, Name: m.Name, Groups: m.Groups, Addr: m.Addr.String(), StartDay: m.StartDay})
	}
	for _, s := range demo.Systems {
		sy := system{Name: s.Name, Addr: s.Addr.String()}
		for _, sv := range s.Services {
			sy.Services = append(sy.Services, service{sv.Port, sv.Proto.String(), sv.Name})
		}
		o.Systems = append(o.Systems, sy)
	}
	o.PerDay, o.LearnFlows, o.ReplayFlows = perDay, len(learnF), len(replayF)
	o.PeopleFile = demo.PeopleFile()
	o.Stolen, o.StolenAt = office.DemoStolenLogin, office.DemoStolenAt.Format("Monday 2 January, 15:04 UTC")
	return out(o)
}

type counts struct {
	GroupRules  int `json:"groupRules"`
	PersonRules int `json:"personRules"`
	Review      int `json:"review"`
	Groups      int `json:"groups"`
	People      int `json:"people"`
}

type cell struct {
	Kind     string   `json:"kind"` // "group", "person", "review" or ""
	Services []string `json:"services,omitempty"`
}

// matrix says, for every person and system, what the draft lets them reach.
func matrix(d *scope.Draft, pol *scope.Policy) [][]cell {
	var m [][]cell
	for _, per := range people.List {
		row := make([]cell, len(demo.Systems))
		review := map[scope.Dest]bool{}
		if rs := d.People[per.ID]; rs != nil {
			for _, r := range rs.Review {
				review[r.Dest] = true
			}
		}
		for i, s := range demo.Systems {
			c := &row[i]
			rank := 0
			for _, sv := range s.Services {
				f := scope.Flow{Time: demo.Start, Proto: sv.Proto, Src: per.Addrs[0], Dst: s.Addr, Port: sv.Port}
				v := pol.Decide(f)
				kind := ""
				switch {
				case v.Outcome == scope.Allowed && strings.HasPrefix(v.Rule, "person "):
					kind = "person"
				case v.Outcome == scope.Allowed:
					kind = "group"
				case review[scope.DestOf(f.Key())]:
					kind = "review"
				}
				if kind == "" {
					continue
				}
				c.Services = append(c.Services, fmt.Sprintf("%s (%d/%s)", sv.Name, sv.Port, sv.Proto))
				r := map[string]int{"review": 1, "group": 2, "person": 3}[kind]
				if r > rank {
					rank, c.Kind = r, kind
				}
			}
		}
		m = append(m, row)
	}
	return m
}

type reviewItem struct {
	Person  string `json:"person"`
	Name    string `json:"name"`
	System  string `json:"system"`
	Service string `json:"service"`
	Dest    string `json:"dest"`
	Note    string `json:"note"`
	Allowed bool   `json:"allowed"`
}

type draftInfo struct {
	OK     bool         `json:"ok"`
	Draft  string       `json:"draft,omitempty"`
	Counts counts       `json:"counts"`
	Matrix [][]cell     `json:"matrix"`
	Review []reviewItem `json:"review"`
	Flows  int          `json:"flows,omitempty"`
}

func describe(d *scope.Draft) draftInfo {
	c := d.Count()
	info := draftInfo{OK: true, Counts: counts{c.GroupRules, c.PersonRules, c.Review, c.Groups, c.People},
		Matrix: matrix(d, scope.Compile(d, people))}
	for _, id := range d.PeopleOrder {
		for _, r := range d.People[id].Review {
			sys, svc := serviceName(scope.Key{Dst: r.Dest.Net.Addr(), Port: r.Dest.Lo, Proto: r.Dest.Proto})
			info.Review = append(info.Review, reviewItem{id, people.Get(id).Name, sys, svc, r.Dest.String(), r.Note, false})
		}
	}
	return info
}

// reviewFn moves one destination of one person between review and allow,
// and returns the new draft with the same notes.
func reviewFn(_ js.Value, args []js.Value) any {
	d, err := parse(args)
	if err != nil {
		return fail(err)
	}
	if len(args) < 4 {
		return fail(fmt.Errorf("review needs the draft, a person, a destination and allow"))
	}
	dest, err := scope.ParseDest(args[2].String())
	if err != nil {
		return fail(err)
	}
	if !d.Move(args[1].String(), dest, args[3].Bool()) {
		return fail(fmt.Errorf("%s is not in the lists of %s", dest, args[1].String()))
	}
	info := describe(d)
	info.Draft = d.String()
	return out(info)
}

// learnFn learns a draft from the first two weeks.
func learnFn(js.Value, []js.Value) any {
	l := scope.NewLearner(people, scope.LearnOptions{From: demo.Day(office.DemoLearnFrom), To: demo.Day(office.DemoLearnTo)})
	for _, f := range learnF {
		l.Add(f)
	}
	d := l.Draft()
	info := describe(d)
	info.Draft = d.String()
	info.Flows = l.Stats.InWindow
	return out(info)
}

func parse(args []js.Value) (*scope.Draft, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("no draft given")
	}
	return scope.ParseDraft(args[0].String(), "draft.toml", people)
}

// checkFn parses an edited draft.
func checkFn(_ js.Value, args []js.Value) any {
	d, err := parse(args)
	if err != nil {
		return fail(err)
	}
	if _, err := scope.ExportNft(d, people, scope.NftOptions{}); err != nil {
		return fail(err)
	}
	return out(describe(d))
}

type blocked struct {
	Person  string `json:"person"`
	Name    string `json:"name"`
	System  string `json:"system"`
	Service string `json:"service"`
	Dest    string `json:"dest"`
	Count   int    `json:"count"`
	Why     string `json:"why"`
}

// why says why the draft blocks a person's destination.
func why(d *scope.Draft, person string, k scope.Key) string {
	if person == "" {
		return "no one in the people file has this address"
	}
	if rs := d.People[person]; rs != nil {
		for _, r := range rs.Review {
			if r.Dest == scope.DestOf(k) {
				return "under review in the draft"
			}
		}
	}
	return "not in the draft: not used in the two weeks it was learned from"
}

type personCount struct {
	ID      string `json:"id"`
	Allowed int    `json:"allowed"`
	Denied  int    `json:"denied"`
}

func serviceName(k scope.Key) (string, string) {
	s := demo.SystemAt(k.Dst)
	if s == nil {
		return k.Dst.String(), fmt.Sprintf("%d/%s", k.Port, k.Proto)
	}
	for _, sv := range s.Services {
		if sv.Port == k.Port && sv.Proto == k.Proto {
			return s.Name, sv.Name
		}
	}
	return s.Name, fmt.Sprintf("%d/%s, closed", k.Port, k.Proto)
}

// replayFn replays the week after the learning window under a draft.
func replayFn(_ js.Value, args []js.Value) any {
	d, err := parse(args)
	if err != nil {
		return fail(err)
	}
	r := scope.NewReplay(scope.Compile(d, people))
	for _, f := range replayF {
		r.Add(f)
	}
	var res struct {
		OK      bool          `json:"ok"`
		Flows   int           `json:"flows"`
		Allowed int           `json:"allowed"`
		Denied  int           `json:"denied"`
		Blocked []blocked     `json:"blocked"`
		People  []personCount `json:"people"`
	}
	res.OK, res.Flows, res.Allowed, res.Denied = true, r.Flows, r.Allowed, r.Denied
	for _, dk := range r.DeniedKeys() {
		sys, svc := serviceName(dk.Key)
		name := ""
		if p := people.Get(dk.Person); p != nil {
			name = p.Name
		}
		res.Blocked = append(res.Blocked, blocked{dk.Person, name, sys, svc, dk.Key.String(), dk.Count, why(d, dk.Person, dk.Key)})
	}
	for _, p := range people.List {
		pr := r.People[p.ID]
		if pr == nil {
			pr = &scope.PersonReplay{}
		}
		res.People = append(res.People, personCount{p.ID, pr.Allowed, pr.Denied})
	}
	return out(res)
}

type try struct {
	Port    uint16 `json:"port"`
	Proto   string `json:"proto"`
	Service string `json:"service"`
	Open    bool   `json:"open"`
	Allowed bool   `json:"allowed"`
}

type target struct {
	Name  string `json:"name"`
	Addr  string `json:"addr"`
	Tries []try  `json:"tries"`
}

// stolenFn replays the stolen login under a draft. On the flat VPN every
// attempt reaches its system, open port or closed.
func stolenFn(_ js.Value, args []js.Value) any {
	d, err := parse(args)
	if err != nil {
		return fail(err)
	}
	pol := scope.Compile(d, people)
	var res struct {
		OK       bool     `json:"ok"`
		Person   string   `json:"person"`
		Attempts int      `json:"attempts"`
		Reached  int      `json:"reached"`
		Systems  int      `json:"systems"`
		Targets  []target `json:"targets"`
	}
	res.OK, res.Person = true, office.DemoStolenLogin
	byAddr := map[string]*target{}
	for _, s := range demo.Systems {
		res.Targets = append(res.Targets, target{Name: s.Name, Addr: s.Addr.String()})
	}
	for i := range res.Targets {
		byAddr[res.Targets[i].Addr] = &res.Targets[i]
	}
	reachedSys := map[string]bool{}
	for _, f := range demo.StolenLogin(office.DemoStolenLogin, office.DemoStolenAt) {
		res.Attempts++
		t := byAddr[f.Dst.String()]
		s := demo.SystemAt(f.Dst)
		_, svc := serviceName(f.Key())
		allowed := pol.Decide(f).Outcome == scope.Allowed
		if allowed {
			res.Reached++
			reachedSys[t.Name] = true
		}
		t.Tries = append(t.Tries, try{f.Port, f.Proto.String(), svc, s.Offers(f.Port, f.Proto), allowed})
	}
	res.Systems = len(reachedSys)
	return out(res)
}

// exportFn writes a draft as nftables rules or AllowedIPs.
func exportFn(_ js.Value, args []js.Value) any {
	d, err := parse(args)
	if err != nil {
		return fail(err)
	}
	var res struct {
		OK   bool   `json:"ok"`
		Text string `json:"text"`
	}
	res.OK = true
	if len(args) > 1 && args[1].String() == "allowedips" {
		res.Text = scope.ExportAllowedIPs(d, people)
		return out(res)
	}
	watch := len(args) > 2 && args[2].Bool()
	res.Text, err = scope.ExportNft(d, people, scope.NftOptions{Watch: watch, Source: "draft.toml and people.toml"})
	if err != nil {
		return fail(err)
	}
	return out(res)
}
