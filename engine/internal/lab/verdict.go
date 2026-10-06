// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package lab

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Recording is one scenario run: its header and its events in time order.
type Recording struct {
	Header Event
	Events []Event
}

// ReadRecording reads a recording. Its first event must be the run header;
// the rest are put in time order, keeping the file's order for equal times.
func ReadRecording(r io.Reader, name string) (*Recording, error) {
	rec := &Recording{}
	first := true
	_, err := ReadEvents(r, name, func(e Event) error {
		if first {
			first = false
			if e.Ev != EvRun {
				return fmt.Errorf("%s: the first event must be the run header, not %q", name, e.Ev)
			}
			rec.Header = e
			return nil
		}
		if e.Ev == EvRun {
			return fmt.Errorf("%s: a second run header; one recording holds one run", name)
		}
		rec.Events = append(rec.Events, e)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if first {
		return nil, fmt.Errorf("%s: no events", name)
	}
	sort.SliceStable(rec.Events, func(i, j int) bool { return rec.Events[i].T.Before(rec.Events[j].T) })
	return rec, nil
}

// ParseRecording reads a recording from text.
func ParseRecording(text, name string) (*Recording, error) {
	return ReadRecording(strings.NewReader(text), name)
}

// WriteTo writes the recording as JSON Lines, the header first.
func (rec *Recording) WriteTo(w io.Writer) (int64, error) {
	cw := &countWriter{w: w}
	ew := NewEventWriter(cw)
	ew.Write(rec.Header)
	for _, e := range rec.Events {
		ew.Write(e)
	}
	err := ew.Flush()
	return cw.n, err
}

type countWriter struct {
	w io.Writer
	n int64
}

func (c *countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// Statuses of a verdict.
const (
	Pass      = "pass"       // nothing left outside the tunnel
	Leak      = "leak"       // at least one probe was seen outside the tunnel
	NoTraffic = "no traffic" // nothing came through the tunnel before the fault, so there was nothing to judge
)

// Path is where an arrival came from.
type Path int

const (
	Tunnel  Path = iota // through the tunnel: the VPN's exit address, or the VPN's resolver
	Outside             // outside the tunnel: the home network, or anywhere else
)

// Classify says whether an arrival came through the tunnel. Only the VPN's
// resolver and the VPN's exit address count as the tunnel; the home
// router's resolver, the home network's public address and any address the
// recording doesn't name count as outside.
func Classify(h Event, a Event) Path {
	switch {
	case a.At == AtHomeDNS:
		return Outside
	case a.At == AtVPNDNS, a.Src == h.Exit:
		return Tunnel
	}
	return Outside
}

// Outcome is what happened to one probe.
type Outcome int

const (
	Lost    Outcome = iota // seen nowhere: blocked, or dropped on the way
	Through                // seen only through the tunnel
	Leaked                 // seen outside the tunnel at least once
)

func (o Outcome) String() string {
	switch o {
	case Through:
		return "tunnel"
	case Leaked:
		return "leaked"
	}
	return "lost"
}

// ProbeKey names one probe of a run.
type ProbeKey struct {
	Kind, Via string
	Seq       int
}

// ProbeResult is one probe and what became of it.
type ProbeResult struct {
	ProbeKey
	Sent    time.Time
	Outcome Outcome
	First   time.Time // first arrival of any kind, zero if none
	Leak    time.Time // first arrival outside the tunnel, zero if none
	At      string    // where it first arrived outside the tunnel, or else where it first arrived
}

// KindCount counts one kind of probe, sent one way.
type KindCount struct {
	Kind   string `json:"kind"`
	Via    string `json:"via"`
	Sent   int    `json:"sent"`
	Tunnel int    `json:"tunnel"`
	Leaked int    `json:"leaked"`
	Lost   int    `json:"lost"`
}

// Window is a stretch of time in which probes leaked.
type Window struct {
	Start, End time.Time // the first and the last leaked arrival
	Probes     int
	Kinds      []string // the kinds that leaked, in the order dns, tcp, udp
	Open       bool     // still leaking when the run stopped
	// After is the last change the bench or the app recorded before the
	// window began, and AfterLag how long before the first leak it came.
	After    string
	AfterLag time.Duration
	// Before is the first change recorded after the window ended, and
	// BeforeLag how long after the last leak it came.
	Before    string
	BeforeLag time.Duration
}

// Verdict is what Lab decided about one run.
type Verdict struct {
	Run, App, Scenario string
	Seed               int64
	Interval           time.Duration
	Status             string

	Start, FaultOn, FaultOff, Stop time.Time // zero when the run has no such step
	Fault                          string

	Kinds       []KindCount
	Sent        int
	Tunnel      int // probes seen only through the tunnel
	Leaked      int // probes seen outside the tunnel at least once
	Lost        int // probes seen nowhere
	Unexplained int // arrivals outside the tunnel from an address the recording doesn't name
	Stray       int // arrivals of probes the run never sent
	Duplicates  int // probes sent twice under one name; the first is kept

	Windows []Window
	// Recovery is how long after the fault ended the first probe came
	// through the tunnel again; -1 when none did or the fault never ended.
	Recovery time.Duration
	Notes    []string
}

var kindOrder = []string{DNS, TCP, UDP}

// Analyze works out what became of every probe in a recording, in the order
// they were sent, and the verdict.
func Analyze(rec *Recording) ([]ProbeResult, *Verdict) {
	h := rec.Header
	v := &Verdict{Run: h.Run, App: h.App, Scenario: h.Scenario, Seed: h.Seed,
		Interval: time.Duration(h.IntervalMS) * time.Millisecond, Recovery: -1}
	var probes []ProbeResult
	index := map[ProbeKey]int{}
	type change struct {
		t    time.Time
		what string
	}
	var changes []change
	for _, e := range rec.Events {
		switch e.Ev {
		case EvStep:
			switch e.Step {
			case StepStart:
				v.Start = e.T
			case StepFaultOn:
				v.FaultOn, v.Fault = e.T, e.Fault
				changes = append(changes, change{e.T, "fault on (" + e.Fault + ")"})
			case StepFaultOff:
				v.FaultOff = e.T
				changes = append(changes, change{e.T, "fault off (" + e.Fault + ")"})
			case StepStop:
				v.Stop = e.T
				changes = append(changes, change{e.T, "stop"})
			}
		case EvClient, EvApp:
			what := e.Ev + " " + e.State
			if e.Note != "" {
				what += " " + e.Note
			}
			changes = append(changes, change{e.T, what})
		case EvSent:
			k := ProbeKey{e.Kind, e.Via, e.Seq}
			if _, dup := index[k]; dup {
				v.Duplicates++
				continue
			}
			index[k] = len(probes)
			probes = append(probes, ProbeResult{ProbeKey: k, Sent: e.T})
		case EvArrival:
			i, ok := index[ProbeKey{e.Kind, e.Via, e.Seq}]
			if !ok {
				v.Stray++
				continue
			}
			p := &probes[i]
			if p.First.IsZero() {
				p.First, p.At = e.T, e.At
			}
			if Classify(h, e) == Outside {
				if e.At != AtHomeDNS && e.Src != h.Home {
					v.Unexplained++
				}
				if p.Leak.IsZero() {
					p.Leak, p.At = e.T, e.At
				}
				p.Outcome = Leaked
			} else if p.Outcome == Lost {
				p.Outcome = Through
			}
		}
	}

	counts := map[[2]string]*KindCount{}
	tunnelBefore := false
	limit := v.FaultOn
	if limit.IsZero() {
		limit = v.Stop
	}
	for _, p := range probes {
		k := [2]string{p.Kind, p.Via}
		c := counts[k]
		if c == nil {
			c = &KindCount{Kind: p.Kind, Via: p.Via}
			counts[k] = c
		}
		c.Sent++
		v.Sent++
		switch p.Outcome {
		case Through:
			c.Tunnel++
			v.Tunnel++
			if limit.IsZero() || p.First.Before(limit) {
				tunnelBefore = true
			}
			if !v.FaultOff.IsZero() && !p.First.Before(v.FaultOff) {
				if d := p.First.Sub(v.FaultOff); v.Recovery < 0 || d < v.Recovery {
					v.Recovery = d
				}
			}
		case Leaked:
			c.Leaked++
			v.Leaked++
		default:
			c.Lost++
			v.Lost++
		}
	}
	for _, via := range []string{Direct, Proxy} {
		for _, kind := range kindOrder {
			if c := counts[[2]string{kind, via}]; c != nil {
				v.Kinds = append(v.Kinds, *c)
			}
		}
	}

	// Leak windows: leaked probes in the order they were first seen
	// outside, merged while the gaps stay under four probe intervals.
	var leaks []ProbeResult
	for _, p := range probes {
		if p.Outcome == Leaked {
			leaks = append(leaks, p)
		}
	}
	sort.SliceStable(leaks, func(i, j int) bool { return leaks[i].Leak.Before(leaks[j].Leak) })
	gap := 4 * v.Interval
	if gap < 100*time.Millisecond {
		gap = 100 * time.Millisecond
	}
	for _, p := range leaks {
		n := len(v.Windows)
		if n == 0 || p.Leak.Sub(v.Windows[n-1].End) > gap {
			v.Windows = append(v.Windows, Window{Start: p.Leak, End: p.Leak})
			n++
		}
		w := &v.Windows[n-1]
		w.End = p.Leak
		w.Probes++
		if !oneOf(p.Kind, w.Kinds...) {
			w.Kinds = append(w.Kinds, p.Kind)
		}
	}
	for i := range v.Windows {
		w := &v.Windows[i]
		sort.Slice(w.Kinds, func(a, b int) bool { return kindRank(w.Kinds[a]) < kindRank(w.Kinds[b]) })
		w.Open = v.Stop.IsZero() || v.Stop.Sub(w.End) <= gap
		for _, c := range changes {
			if !c.t.After(w.Start) {
				w.After, w.AfterLag = c.what, w.Start.Sub(c.t)
			}
		}
		for _, c := range changes {
			if !c.t.Before(w.End) {
				w.Before, w.BeforeLag = c.what, c.t.Sub(w.End)
				break
			}
		}
	}

	switch {
	case v.Leaked > 0:
		v.Status = Leak
	case v.Sent == 0:
		v.Status = NoTraffic
		v.Notes = append(v.Notes, "the probe sent nothing")
	case !tunnelBefore:
		v.Status = NoTraffic
		v.Notes = append(v.Notes, "nothing came through the tunnel before the fault, so the app never carried the probe's traffic")
	default:
		v.Status = Pass
	}
	if v.Unexplained > 0 {
		v.Notes = append(v.Notes, fmt.Sprintf("%d arrivals came from an address that is neither the VPN's exit nor the home network's; they count as leaks", v.Unexplained))
	}
	if v.Stray > 0 {
		v.Notes = append(v.Notes, fmt.Sprintf("%d arrivals belong to no probe of this run", v.Stray))
	}
	if v.Duplicates > 0 {
		v.Notes = append(v.Notes, fmt.Sprintf("%d probes were sent twice under one name", v.Duplicates))
	}
	return probes, v
}

// Decide returns the verdict for a recording.
func Decide(rec *Recording) *Verdict {
	_, v := Analyze(rec)
	return v
}

func kindRank(k string) int {
	for i, x := range kindOrder {
		if x == k {
			return i
		}
	}
	return len(kindOrder)
}

// LeakedKinds lists the kinds that leaked, in the order dns, tcp, udp, with
// the way they were sent when it was through the proxy: "dns", "tcp", or
// "tcp via proxy".
func (v *Verdict) LeakedKinds() []string {
	var out []string
	for _, c := range v.Kinds {
		if c.Leaked > 0 {
			k := c.Kind
			if c.Via == Proxy {
				k += " via proxy"
			}
			out = append(out, k)
		}
	}
	return out
}

// Summary is the verdict in one short line, the same for every run that
// should count as the same: the status and which kinds leaked.
func (v *Verdict) Summary() string {
	if v.Status != Leak {
		return v.Status
	}
	return v.Status + " (" + strings.Join(v.LeakedKinds(), ", ") + ")"
}

// Rel is a time as seconds after the run's start, such as "2.35 s".
func (v *Verdict) Rel(t time.Time) string {
	return Seconds(t.Sub(v.Start))
}

// Seconds formats a duration as seconds with two decimals.
func Seconds(d time.Duration) string {
	return strconv.FormatFloat(d.Seconds(), 'f', 2, 64) + " s"
}

// Millis formats a duration as whole milliseconds.
func Millis(d time.Duration) string {
	return strconv.FormatInt(d.Round(time.Millisecond).Milliseconds(), 10) + " ms"
}

// Text describes the verdict for people, in a few lines.
func (v *Verdict) Text() string {
	var b strings.Builder
	status := v.Status
	if status == Leak {
		status = "LEAK"
	}
	fmt.Fprintf(&b, "%s, %s (seed %d): %s\n", v.App, v.Scenario, v.Seed, status)
	fmt.Fprintf(&b, "  %s probes sent: %s through the tunnel, %s leaked, %s seen nowhere\n",
		Comma(v.Sent), Comma(v.Tunnel), Comma(v.Leaked), Comma(v.Lost))
	for _, c := range v.Kinds {
		name := c.Kind
		if c.Via == Proxy {
			name += " via proxy"
		}
		fmt.Fprintf(&b, "    %-14s %5s sent, %5s tunnel, %5s leaked, %5s nowhere\n", name, Comma(c.Sent), Comma(c.Tunnel), Comma(c.Leaked), Comma(c.Lost))
	}
	if !v.FaultOn.IsZero() && !v.Start.IsZero() {
		fmt.Fprintf(&b, "  fault %s: on at %s", v.Fault, v.Rel(v.FaultOn))
		if !v.FaultOff.IsZero() {
			fmt.Fprintf(&b, ", off at %s", v.Rel(v.FaultOff))
		} else {
			b.WriteString(", to the end")
		}
		if !v.Stop.IsZero() {
			fmt.Fprintf(&b, "; stop at %s", v.Rel(v.Stop))
		}
		b.WriteString("\n")
		if !v.FaultOff.IsZero() {
			if v.Recovery >= 0 {
				fmt.Fprintf(&b, "  the tunnel carried probes again %s after the fault ended\n", Millis(v.Recovery))
			} else {
				b.WriteString("  no probe came through the tunnel after the fault ended\n")
			}
		}
	}
	for i, w := range v.Windows {
		fmt.Fprintf(&b, "  leak %d: %s from %s to %s (%s)", i+1, plural(w.Probes, "probe"), v.Rel(w.Start), v.Rel(w.End), strings.Join(w.Kinds, ", "))
		if w.Open {
			b.WriteString(", still leaking at the end")
		}
		b.WriteString("\n")
		if w.After != "" {
			fmt.Fprintf(&b, "    first seen %s after: %s\n", Millis(w.AfterLag), w.After)
		}
		if w.Before != "" && !w.Open {
			fmt.Fprintf(&b, "    last seen %s before: %s\n", Millis(w.BeforeLag), w.Before)
		}
	}
	for _, n := range v.Notes {
		fmt.Fprintf(&b, "  note: %s\n", n)
	}
	return b.String()
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return Comma(n) + " " + word + "s"
}

// Comma formats n with thousands separators.
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
