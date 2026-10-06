// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package lab

import (
	"math"
	"time"
)

// Report is a verdict as plain values, for JSON: the command line's --json
// and the browser demo print the same fields. Times are seconds after the
// run's start, and -1 when the run has no such moment.
type Report struct {
	Run         string         `json:"run"`
	App         string         `json:"app"`
	Scenario    string         `json:"scenario"`
	Seed        int64          `json:"seed"`
	IntervalMS  int            `json:"interval_ms"`
	Status      string         `json:"status"`
	Summary     string         `json:"summary"`
	Fault       string         `json:"fault,omitempty"`
	FaultOn     float64        `json:"fault_on"`
	FaultOff    float64        `json:"fault_off"`
	Stop        float64        `json:"stop"`
	Sent        int            `json:"sent"`
	Tunnel      int            `json:"tunnel"`
	Leaked      int            `json:"leaked"`
	Lost        int            `json:"lost"`
	Unexplained int            `json:"unexplained"`
	Stray       int            `json:"stray"`
	Kinds       []KindCount    `json:"kinds"`
	Windows     []WindowReport `json:"windows"`
	RecoveryMS  float64        `json:"recovery_ms"`
	Notes       []string       `json:"notes"`
}

// WindowReport is a leak window as plain values.
type WindowReport struct {
	Start    float64  `json:"start"`
	End      float64  `json:"end"`
	Probes   int      `json:"probes"`
	Kinds    []string `json:"kinds"`
	Open     bool     `json:"open"`
	After    string   `json:"after,omitempty"`
	AfterMS  float64  `json:"after_ms"`
	Before   string   `json:"before,omitempty"`
	BeforeMS float64  `json:"before_ms"`
}

func round(x float64, places int) float64 {
	p := math.Pow(10, float64(places))
	return math.Round(x*p) / p
}

// Report returns the verdict as plain values.
func (v *Verdict) Report() Report {
	rel := func(t time.Time) float64 {
		if t.IsZero() || v.Start.IsZero() {
			return -1
		}
		return round(t.Sub(v.Start).Seconds(), 3)
	}
	ms := func(d time.Duration) float64 { return round(float64(d)/float64(time.Millisecond), 1) }
	r := Report{Run: v.Run, App: v.App, Scenario: v.Scenario, Seed: v.Seed, IntervalMS: int(v.Interval / time.Millisecond),
		Status: v.Status, Summary: v.Summary(), Fault: v.Fault, FaultOn: rel(v.FaultOn), FaultOff: rel(v.FaultOff), Stop: rel(v.Stop),
		Sent: v.Sent, Tunnel: v.Tunnel, Leaked: v.Leaked, Lost: v.Lost, Unexplained: v.Unexplained, Stray: v.Stray,
		Kinds: append([]KindCount{}, v.Kinds...), Windows: []WindowReport{}, RecoveryMS: -1, Notes: append([]string{}, v.Notes...)}
	if v.Recovery >= 0 {
		r.RecoveryMS = ms(v.Recovery)
	}
	for _, w := range v.Windows {
		r.Windows = append(r.Windows, WindowReport{Start: rel(w.Start), End: rel(w.End), Probes: w.Probes, Kinds: w.Kinds, Open: w.Open,
			After: w.After, AfterMS: ms(w.AfterLag), Before: w.Before, BeforeMS: ms(w.BeforeLag)})
	}
	return r
}
