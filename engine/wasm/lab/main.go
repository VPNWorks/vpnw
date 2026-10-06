// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

//go:build js && wasm

// Command lab-wasm runs Lab's verdict in the browser demo, on recordings of
// real runs in the test network that ship inside it. The page draws; every
// number it shows comes from these calls, which run the same Go code as the
// vpnw-lab command.
package main

import (
	"encoding/json"
	"strings"
	"syscall/js"
	"time"

	"vpnw.com/vpnw/internal/lab"
	"vpnw.com/vpnw/internal/lab/demo"
)

func main() {
	js.Global().Set("vpnwLab", js.ValueOf(map[string]any{
		"version":    lab.Version,
		"recordings": js.FuncOf(recordingsFn),
		"analyze":    js.FuncOf(analyzeFn),
		"probe":      js.FuncOf(probeFn),
		"decide":     js.FuncOf(decideFn),
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

type listed struct {
	Name     string `json:"name"`
	Title    string `json:"title"`
	App      string `json:"app"`
	Scenario string `json:"scenario"`
	Seed     int64  `json:"seed"`
	Lines    int    `json:"lines"`
}

// recordingsFn lists the recordings inside the engine.
func recordingsFn(js.Value, []js.Value) any {
	var list []listed
	for _, r := range demo.Recordings {
		text, err := demo.Text(r.Name)
		if err != nil {
			return fail(err)
		}
		rec, err := lab.ParseRecording(text, r.Name)
		if err != nil {
			return fail(err)
		}
		list = append(list, listed{r.Name, r.Title, rec.Header.App, rec.Header.Scenario, rec.Header.Seed, strings.Count(text, "\n")})
	}
	return out(list)
}

type mark struct {
	T     float64 `json:"t"` // seconds after the start
	What  string  `json:"what"`
	State string  `json:"state,omitempty"`
	Note  string  `json:"note,omitempty"`
}

type analysis struct {
	OK     bool       `json:"ok"`
	Report lab.Report `json:"report"`
	Header struct {
		Run, App, Scenario, Exit, Home string
		IntervalMS                     int `json:"intervalMS"`
	} `json:"header"`
	// Probes, one array each: kind (0 dns, 1 tcp, 2 udp), via (0 direct,
	// 1 proxy), sequence number, sent (ms after the start), outcome (0 seen
	// nowhere, 1 through the tunnel, 2 leaked), first arrival (ms, -1 for
	// none), first leaked arrival (ms, -1), where (an index into Observers).
	Probes    [][8]float64 `json:"probes"`
	Observers []string     `json:"observers"`
	Marks     []mark       `json:"marks"`
	Arrivals  int          `json:"arrivals"`
	Duration  float64      `json:"duration"`
}

var observers = []string{"", lab.AtHomeDNS, lab.AtVPNDNS, lab.AtZoneDNS, lab.AtTCP, lab.AtUDP}

func index(list []string, s string) float64 {
	for i, x := range list {
		if x == s {
			return float64(i)
		}
	}
	return 0
}

// analyze decides a recording and lays out every probe for the timeline.
func analyze(rec *lab.Recording) analysis {
	probes, v := lab.Analyze(rec)
	var a analysis
	a.OK = true
	a.Report = v.Report()
	a.Header.Run, a.Header.App, a.Header.Scenario = rec.Header.Run, rec.Header.App, rec.Header.Scenario
	a.Header.Exit, a.Header.Home, a.Header.IntervalMS = rec.Header.Exit.String(), rec.Header.Home.String(), rec.Header.IntervalMS
	a.Observers = observers
	start := v.Start
	if start.IsZero() {
		start = rec.Header.T
	}
	ms := func(t time.Time) float64 {
		if t.IsZero() {
			return -1
		}
		return float64(t.Sub(start).Microseconds()) / 1000
	}
	for _, p := range probes {
		a.Probes = append(a.Probes, [8]float64{index([]string{lab.DNS, lab.TCP, lab.UDP}, p.Kind), index([]string{lab.Direct, lab.Proxy}, p.Via),
			float64(p.Seq), ms(p.Sent), float64(p.Outcome), ms(p.First), ms(p.Leak), index(observers, p.At)})
	}
	for _, e := range rec.Events {
		switch e.Ev {
		case lab.EvStep:
			a.Marks = append(a.Marks, mark{T: ms(e.T) / 1000, What: "step", State: e.Step, Note: e.Fault})
		case lab.EvClient, lab.EvApp:
			a.Marks = append(a.Marks, mark{T: ms(e.T) / 1000, What: e.Ev, State: e.State, Note: e.Note})
		case lab.EvArrival:
			a.Arrivals++
		}
	}
	if !v.Stop.IsZero() {
		a.Duration = ms(v.Stop) / 1000
	}
	return a
}

// analyzeFn decides one of the recordings inside the engine.
func analyzeFn(_ js.Value, args []js.Value) any {
	if len(args) == 0 {
		return fail(errNoName)
	}
	rec, err := demo.Read(args[0].String())
	if err != nil {
		return fail(err)
	}
	return out(analyze(rec))
}

type arrival struct {
	T    float64 `json:"t"`
	At   string  `json:"at"`
	Src  string  `json:"src"`
	Path string  `json:"path"`
}

// probeFn follows one probe of a recording: when it was sent, everywhere it
// arrived, and how the verdict judged it.
func probeFn(_ js.Value, args []js.Value) any {
	if len(args) < 4 {
		return fail(labError("probe needs a recording, a kind, a way and a sequence number"))
	}
	rec, err := demo.Read(args[0].String())
	if err != nil {
		return fail(err)
	}
	key := lab.ProbeKey{Kind: args[1].String(), Via: args[2].String(), Seq: args[3].Int()}
	probes, v := lab.Analyze(rec)
	var res struct {
		OK       bool      `json:"ok"`
		Sent     float64   `json:"sent"`
		Outcome  string    `json:"outcome"`
		Arrivals []arrival `json:"arrivals"`
	}
	res.OK, res.Arrivals = true, []arrival{}
	found := false
	for _, p := range probes {
		if p.ProbeKey == key {
			res.Sent, res.Outcome, found = p.Sent.Sub(v.Start).Seconds(), p.Outcome.String(), true
		}
	}
	if !found {
		return fail(labError("no such probe in " + args[0].String()))
	}
	for _, e := range rec.Events {
		if e.Ev == lab.EvArrival && e.Kind == key.Kind && e.Via == key.Via && e.Seq == key.Seq {
			path := "outside"
			if lab.Classify(rec.Header, e) == lab.Tunnel {
				path = "tunnel"
			}
			res.Arrivals = append(res.Arrivals, arrival{e.T.Sub(v.Start).Seconds(), e.At, e.Src.String(), path})
		}
	}
	return out(res)
}

// decideFn decides a recording given as text, such as one pasted into the
// page.
func decideFn(_ js.Value, args []js.Value) any {
	if len(args) == 0 {
		return fail(errNoName)
	}
	rec, err := lab.ParseRecording(args[0].String(), "pasted.jsonl")
	if err != nil {
		return fail(err)
	}
	return out(analyze(rec))
}

type labError string

func (e labError) Error() string { return string(e) }

const errNoName = labError("no recording given")
