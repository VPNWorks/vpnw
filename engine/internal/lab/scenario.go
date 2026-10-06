// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package lab

import (
	"fmt"
	"strings"
	"time"
)

// Scenario is a timetable of faults. Every scenario starts with the app
// connected and the probe running, waits Lead, turns its fault on, turns it
// off again after For (unless the fault lasts to the end), and stops after
// Tail. The seed moves the fault a little, so a run can be repeated exactly.
type Scenario struct {
	Name   string
	Title  string        // a short title for tables
	On     string        // what the bench does when the fault starts; empty for steady
	Off    string        // what it does when the fault ends; empty if it never does
	Lead   time.Duration // from start to the fault, before jitter
	For    time.Duration // how long the fault lasts; 0 when it lasts to the end
	Tail   time.Duration // from the end of the fault (or its start, if it lasts) to stop
	Jitter time.Duration // the seed moves the fault later by up to this
}

// Faults.
const (
	FaultServerSilent = "server-silent"
	FaultServerGone   = "server-gone"
	FaultAppKilled    = "app-killed"
	FaultLinkDrop     = "link-drop"
	FaultRoutePush    = "route-push"
	FaultDNSChange    = "dns-change"
)

// Scenarios are Lab's scenarios, with the timings the tests use. The demo
// and the command line can lengthen a fault with Timetable's override.
var Scenarios = []Scenario{
	{Name: "steady", Title: "Steady traffic",
		Lead: 3 * time.Second},
	{Name: FaultServerSilent, Title: "The server goes silent",
		On:   "the VPN server's address stops answering: every packet to it, and from it, is dropped",
		Off:  "the server answers again",
		Lead: 1500 * time.Millisecond, For: 3 * time.Second, Tail: 2500 * time.Millisecond, Jitter: 400 * time.Millisecond},
	{Name: FaultServerGone, Title: "The server is gone",
		On:   "the VPN server stops: its address answers every packet with a refusal, to the end of the run",
		Lead: 1500 * time.Millisecond, Tail: 3 * time.Second, Jitter: 400 * time.Millisecond},
	{Name: FaultAppKilled, Title: "The app is killed",
		On:   "the app under test is killed (SIGKILL), as in a crash",
		Off:  "the app is started again, as a service manager would",
		Lead: 1500 * time.Millisecond, For: 2 * time.Second, Tail: 2500 * time.Millisecond, Jitter: 400 * time.Millisecond},
	{Name: FaultLinkDrop, Title: "The link drops",
		On:   "the device's network link goes down",
		Off:  "the link comes back and the home network gives the device its default route again",
		Lead: 1500 * time.Millisecond, For: 2 * time.Second, Tail: 3 * time.Second, Jitter: 400 * time.Millisecond},
	{Name: FaultRoutePush, Title: "The network pushes a route",
		On:   "the home network pushes a route for the observers' range (198.51.100.0/24) through its router, as DHCP option 121 does",
		Off:  "the pushed route is withdrawn",
		Lead: 1500 * time.Millisecond, For: 2 * time.Second, Tail: 1500 * time.Millisecond, Jitter: 400 * time.Millisecond},
	{Name: FaultDNSChange, Title: "The network changes DNS",
		On:   "the home network hands out a new DNS server (192.168.1.53) and the device's network settings take it",
		Off:  "the network hands out its first DNS server again",
		Lead: 1500 * time.Millisecond, For: 2 * time.Second, Tail: 1500 * time.Millisecond, Jitter: 400 * time.Millisecond},
}

// FindScenario returns the scenario with the given name.
func FindScenario(name string) (Scenario, error) {
	for _, s := range Scenarios {
		if s.Name == name {
			return s, nil
		}
	}
	return Scenario{}, fmt.Errorf("unknown scenario %q; the scenarios are %s", name, strings.Join(ScenarioNames(), ", "))
}

// ScenarioNames lists the scenarios' names in order.
func ScenarioNames() []string {
	var out []string
	for _, s := range Scenarios {
		out = append(out, s.Name)
	}
	return out
}

// Step is one planned step of a timetable, at an offset from the start.
type Step struct {
	Name string
	At   time.Duration
}

// Timetable plans the scenario's steps for a seed. A positive faultFor
// replaces the scenario's own fault length, for faults that end.
func (s Scenario) Timetable(seed int64, faultFor time.Duration) []Step {
	steps := []Step{{StepStart, 0}}
	if s.On == "" {
		return append(steps, Step{StepStop, s.Lead})
	}
	r := splitmix(uint64(seed))
	on := s.Lead + jitter(&r, s.Jitter)
	steps = append(steps, Step{StepFaultOn, on})
	end := on
	if s.Off != "" {
		d := s.For
		if faultFor > 0 {
			d = faultFor
		}
		end = on + d + jitter(&r, s.Jitter/2)
		steps = append(steps, Step{StepFaultOff, end})
	}
	return append(steps, Step{StepStop, end + s.Tail})
}

// Duration is how long the timetable runs, from start to stop.
func Duration(steps []Step) time.Duration {
	if len(steps) == 0 {
		return 0
	}
	return steps[len(steps)-1].At
}

// splitmix is SplitMix64: a small generator that gives the same numbers
// everywhere, the browser included.
type splitmix uint64

func (r *splitmix) next() uint64 {
	*r += 0x9e3779b97f4a7c15
	z := uint64(*r)
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	return z ^ (z >> 31)
}

// jitter draws a whole number of milliseconds in [0, max).
func jitter(r *splitmix, max time.Duration) time.Duration {
	ms := uint64(max / time.Millisecond)
	if ms == 0 {
		return 0
	}
	return time.Duration(r.next()%ms) * time.Millisecond
}

// App is an app Lab can test.
type App struct {
	Name  string
	Title string
	What  string
	Agent bool // VPN Works Agent, which runs the probe as its workload
}

// Apps are the apps under test: four stand-in VPN clients built for the
// bench, one of them correct and three with a planted fault, and the VPN
// Works Agent in its two modes.
var Apps = []App{
	{Name: "correct", Title: "Correct client",
		What: "keeps a kill switch on the physical link, holds DNS inside the tunnel, and routes everything into the tunnel by its own routing table, so pushed routes are ignored"},
	{Name: "dns-leak", Title: "DNS leak",
		What: "while it reconnects it points DNS at the home router's resolver, its kill switch lets local traffic through, and it leaves a DNS setting the network changes alone"},
	{Name: "no-kill-switch", Title: "No kill switch",
		What: "when the tunnel is down its routes fall away, and nothing stops traffic going out the home network"},
	{Name: "follows-routes", Title: "Follows routes",
		What: "routes the tunnel through the main routing table, so a more specific route pushed by the local network wins over the tunnel"},
	{Name: "agent-sealed", Title: "Agent, sealed", Agent: true,
		What: "the probe runs under vpnw guard: its own network namespace, where the only way out is the Agent's proxy path"},
	{Name: "agent-env", Title: "Agent, proxy settings", Agent: true,
		What: "the probe runs under vpnw run --backend env: proxy settings only, so whatever ignores them goes direct"},
}

// FindApp returns the app with the given name.
func FindApp(name string) (App, error) {
	for _, a := range Apps {
		if a.Name == name {
			return a, nil
		}
	}
	return App{}, fmt.Errorf("unknown app %q; the apps are %s", name, strings.Join(AppNames(), ", "))
}

// AppNames lists the apps' names in order.
func AppNames() []string {
	var out []string
	for _, a := range Apps {
		out = append(out, a.Name)
	}
	return out
}
