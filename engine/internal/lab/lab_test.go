// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package lab

import (
	"bytes"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"testing/iotest"
	"time"
)

var (
	t0      = time.Date(2026, 10, 5, 21, 0, 0, 0, time.UTC)
	exit    = netip.MustParseAddr("192.0.2.20")
	home    = netip.MustParseAddr("203.0.113.2")
	device  = netip.MustParseAddr("192.168.1.10")
	tunnelA = netip.MustParseAddr("10.66.0.2")
)

// builder makes recordings for the tests, with times in milliseconds after
// t0.
type builder struct{ rec *Recording }

func newBuilder(app, scenario string) *builder {
	return &builder{rec: &Recording{Header: Event{T: t0, Ev: EvRun, Lab: Version, Run: "r-test", App: app, Scenario: scenario,
		Seed: 7, IntervalMS: 50, Exit: exit, Home: home}}}
}

func ms(n int) time.Time { return t0.Add(time.Duration(n) * time.Millisecond) }

func (b *builder) add(e Event) *builder { b.rec.Events = append(b.rec.Events, e); return b }
func (b *builder) step(at int, step, fault string) *builder {
	return b.add(Event{T: ms(at), Ev: EvStep, Step: step, Fault: fault})
}
func (b *builder) sent(at int, kind, via string, seq int) *builder {
	return b.add(Event{T: ms(at), Ev: EvSent, Kind: kind, Via: via, Seq: seq})
}
func (b *builder) arrive(at int, kind, via string, seq int, where string, src netip.Addr) *builder {
	return b.add(Event{T: ms(at), Ev: EvArrival, Kind: kind, Via: via, Seq: seq, At: where, Src: src})
}
func (b *builder) client(at int, state, note string) *builder {
	return b.add(Event{T: ms(at), Ev: EvClient, State: state, Note: note})
}

// sorted returns the recording in time order, as ReadRecording would.
func (b *builder) sorted(t *testing.T) *Recording {
	t.Helper()
	var buf bytes.Buffer
	if _, err := b.rec.WriteTo(&buf); err != nil {
		t.Fatal(err)
	}
	rec, err := ReadRecording(&buf, "built.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

func TestEventRoundTrip(t *testing.T) {
	events := []Event{
		{T: t0, Ev: EvRun, Lab: "0.1.0", Run: "r-1", App: "correct", Scenario: "steady", Seed: 0, IntervalMS: 50, Exit: exit, Home: home},
		{T: t0.Add(time.Nanosecond), Ev: EvStep, Step: StepFaultOn, Fault: FaultServerSilent},
		{T: t0.Add(1500 * time.Microsecond), Ev: EvSent, Kind: DNS, Via: Direct, Seq: 0},
		{T: t0.Add(time.Second), Ev: EvArrival, Kind: TCP, Via: Proxy, Seq: 12345, At: AtTCP, Src: exit},
		{T: t0, Ev: EvClient, State: "dns", Note: "192.168.1.1"},
		{T: t0, Ev: EvApp, State: "killed", Note: "quote \" backslash \\ tab \t newline \n bell \x07 del \x7f é ✓"},
	}
	for _, e := range events {
		line := string(e.AppendJSON(nil))
		got, err := ParseEvent(line)
		if err != nil {
			t.Fatalf("%s: %v", line, err)
		}
		if !reflect.DeepEqual(got, e) {
			t.Fatalf("round trip of %s:\n got %+v\nwant %+v", line, got, e)
		}
	}
	want := `{"t":"2026-10-05T21:00:00.0015Z","ev":"sent","kind":"dns","via":"direct","seq":0}`
	if line := string(events[2].AppendJSON(nil)); line != want {
		t.Fatalf("got  %s\nwant %s", line, want)
	}
	// Any key order, spaces, escapes and unknown keys are fine.
	e, err := ParseEvent(` { "seq" : 7, "via":"proxy", "extra": -3, "kind":"udp", "note":"a\/b \u00e9", "ev":"sent", "t":"2026-10-05T21:00:00Z" } `)
	if err != nil || e.Seq != 7 || e.Kind != UDP || e.Via != Proxy || e.Note != "a/b é" {
		t.Fatalf("reordered: %v %+v", err, e)
	}
}

func TestEventErrors(t *testing.T) {
	good := `"t":"2026-10-05T21:00:00Z","ev":"sent","kind":"dns","via":"direct","seq":1`
	arrival := `"t":"2026-10-05T21:00:00Z","ev":"arrival","kind":"dns","via":"direct","seq":1,"at":"home-dns","src":"192.168.1.10"`
	run := `"t":"2026-10-05T21:00:00Z","ev":"run","run":"r","app":"a","scenario":"s","interval_ms":50,"exit":"192.0.2.20","home":"203.0.113.2"`
	for line, want := range map[string]string{
		``:                              "not a JSON object",
		`[1]`:                           "not a JSON object",
		`{` + good + `,}`:               "trailing comma",
		`{` + good + `,"seq":2}`:        "appears twice",
		`{` + good + ` "x":1}`:          "expected ,",
		`{"t" "x"}`:                     "expected :",
		`{"t":}`:                        "missing value",
		`{"t":true}`:                    "only strings and integers",
		`{"t":-}`:                       "only strings and integers",
		`{"seq":1.5}`:                   "expected ,",
		`{t:1}`:                         "expected a string",
		`{"t":"x`:                       "not a JSON object",
		`{"t":"x\`:                      "not a JSON object",
		`{"t":"a\qb"}`:                  "unknown escape",
		`{"t":"a\u12"}`:                 "short \\u escape",
		`{"t":"a\uzzzz"}`:               "bad \\u escape",
		"{\"t\":\"a\x01b\"}":            "control character",
		"{\"t\":\"a\xffb\"}":            "not valid UTF-8",
		`{"t":"\"}`:                     "unterminated string",
		`{"t":"yesterday","ev":"sent"}`: `not a time`,
		`{"t":5}`:                       `"t" must be a string`,
		`{"ev":"sent"}`:                 `missing "t"`,
		`{"t":"2026-10-05T21:00:00Z"}`:  `missing "ev"`,
		`{"t":"2026-10-05T21:00:00Z","ev":"party"}`:                                    `not one of run, step`,
		`{` + strings.Replace(good, `"dns"`, `"icmp"`, 1) + `}`:                        `"kind": "icmp" is not one of dns, tcp, udp`,
		`{` + strings.Replace(good, `"direct"`, `"vpn"`, 1) + `}`:                      `"via"`,
		`{` + strings.Replace(good, `"seq":1`, `"seq":-1`, 1) + `}`:                    "out of range",
		`{` + strings.Replace(good, `"seq":1`, `"seq":"1"`, 1) + `}`:                   "must be a number",
		`{` + strings.Replace(good, `"seq":1`, `"seq":99999999999`, 1) + `}`:           "out of range",
		`{` + strings.Replace(good, `,"kind":"dns"`, ``, 1) + `}`:                      `needs "kind"`,
		`{` + strings.Replace(arrival, `"home-dns"`, `"moon"`, 1) + `}`:                `"at"`,
		`{` + strings.Replace(arrival, `,"src":"192.168.1.10"`, ``, 1) + `}`:           `needs "src"`,
		`{` + strings.Replace(arrival, `"192.168.1.10"`, `"2001:db8::1"`, 1) + `}`:     "not an IPv4 address",
		`{` + strings.Replace(arrival, `"192.168.1.10"`, `10`, 1) + `}`:                `"src" must be a string`,
		`{` + strings.Replace(run, `"interval_ms":50`, `"interval_ms":0`, 1) + `}`:     "interval_ms",
		`{` + strings.Replace(run, `"interval_ms":50`, `"interval_ms":60001`, 1) + `}`: "out of range",
		`{` + strings.Replace(run, `,"home":"203.0.113.2"`, ``, 1) + `}`:               `"exit" and "home"`,
		`{` + strings.Replace(run, `"203.0.113.2"`, `"192.0.2.20"`, 1) + `}`:           "must differ",
		`{` + strings.Replace(run, `"app":"a",`, ``, 1) + `}`:                          `needs "app"`,
		`{"t":"2026-10-05T21:00:00Z","ev":"step","step":"pause"}`:                      `"step"`,
		`{"t":"2026-10-05T21:00:00Z","ev":"client"}`:                                   `needs "state"`,
	} {
		_, err := ParseEvent(line)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: error %v, want it to mention %q", line, err, want)
		}
	}
	if err := (Event{Ev: EvSent}).Check(); err == nil || !strings.Contains(err.Error(), "no time") {
		t.Errorf("an event without a time: %v", err)
	}
}

func TestReadEvents(t *testing.T) {
	good := `{"t":"2026-10-05T21:00:00Z","ev":"sent","kind":"dns","via":"direct","seq":1}`
	in := "# a comment\n\n" + good + "\n" + good + "\n"
	var n int
	st, err := ReadEvents(strings.NewReader(in), "rec.jsonl", func(Event) error { n++; return nil })
	if err != nil || n != 2 || st.Lines != 4 || st.Events != 2 || st.Skipped != 2 {
		t.Fatalf("%v %d %+v", err, n, st)
	}
	_, err = ReadEvents(strings.NewReader(good+"\n{\"t\":1}\n"), "rec.jsonl", func(Event) error { return nil })
	if err == nil || !strings.HasPrefix(err.Error(), "rec.jsonl:2: ") {
		t.Fatalf("bad line: %v", err)
	}
	long := `{"t":"2026-10-05T21:00:00Z","ev":"client","state":"x","note":"` + strings.Repeat("a", MaxLine) + `"}`
	_, err = ReadEvents(strings.NewReader(good+"\n"+long+"\n"), "rec.jsonl", func(Event) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "rec.jsonl:2: line longer than 4096 bytes") {
		t.Fatalf("long line: %v", err)
	}
	if _, err := ReadEvents(strings.NewReader(good+"\n"), "rec.jsonl", func(Event) error { return errStop }); err != errStop {
		t.Fatalf("fn's error should end the read: %v", err)
	}
	if _, err := ReadEvents(iotest.ErrReader(errors.New("disk on fire")), "rec.jsonl", nil); err == nil || !strings.Contains(err.Error(), "rec.jsonl: disk on fire") {
		t.Fatalf("read error: %v", err)
	}
}

var errStop = errors.New("stop")

func TestReadRecording(t *testing.T) {
	b := newBuilder("correct", "steady")
	b.sent(100, DNS, Direct, 2).sent(50, DNS, Direct, 1).client(50, "up", "")
	rec := b.sorted(t)
	if len(rec.Events) != 3 || rec.Events[0].Seq != 1 || rec.Events[1].Ev != EvClient || rec.Events[2].Seq != 2 {
		t.Fatalf("not in time order, or not stable: %+v", rec.Events)
	}
	if rec.Header.App != "correct" {
		t.Fatal("header lost")
	}
	sent := `{"t":"2026-10-05T21:00:00Z","ev":"sent","kind":"dns","via":"direct","seq":1}`
	head := string(b.rec.Header.AppendJSON(nil))
	for in, want := range map[string]string{
		"":                        "no events",
		"# only a comment\n":      "no events",
		sent + "\n":               "first event must be the run header",
		head + "\n" + head + "\n": "a second run header",
		head + "\nnot json\n":     "r.jsonl:2: not a JSON object",
	} {
		if _, err := ParseRecording(in, "r.jsonl"); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v, want %q", in, err, want)
		}
	}
	var w failWriter
	if _, err := rec.WriteTo(&w); err == nil {
		t.Fatal("a failed write should be reported")
	}
}

type failWriter struct{}

func (*failWriter) Write([]byte) (int, error) { return 0, errStop }

func TestTimetable(t *testing.T) {
	steady, err := FindScenario("steady")
	if err != nil {
		t.Fatal(err)
	}
	if got := steady.Timetable(1, 0); !reflect.DeepEqual(got, []Step{{StepStart, 0}, {StepStop, 3 * time.Second}}) {
		t.Fatalf("steady: %+v", got)
	}
	silent, _ := FindScenario(FaultServerSilent)
	a, b := silent.Timetable(7, 0), silent.Timetable(7, 0)
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("the same seed gave two timetables: %v %v", a, b)
	}
	if len(a) != 4 || a[1].Name != StepFaultOn || a[2].Name != StepFaultOff || a[3].Name != StepStop {
		t.Fatalf("steps: %+v", a)
	}
	on, off := a[1].At, a[2].At
	if on < silent.Lead || on >= silent.Lead+silent.Jitter || off-on < silent.For || off-on >= silent.For+silent.Jitter/2 {
		t.Fatalf("jitter out of bounds: %+v", a)
	}
	if a[3].At-off != silent.Tail || Duration(a) != a[3].At || Duration(nil) != 0 {
		t.Fatalf("tail: %+v", a)
	}
	differ := false
	for seed := int64(0); seed < 20; seed++ {
		if !reflect.DeepEqual(silent.Timetable(seed, 0), a) {
			differ = true
		}
	}
	if !differ {
		t.Fatal("twenty seeds gave one timetable")
	}
	five := silent.Timetable(7, 5*time.Second)
	if d := five[2].At - five[1].At; d < 5*time.Second || d >= 5*time.Second+silent.Jitter/2 {
		t.Fatalf("a 5 s fault lasted %v", d)
	}
	gone, _ := FindScenario(FaultServerGone)
	g := gone.Timetable(3, time.Hour)
	if len(g) != 3 || g[1].Name != StepFaultOn || g[2].At-g[1].At != gone.Tail {
		t.Fatalf("server-gone has no fault-off: %+v", g)
	}
	if r := splitmix(1); jitter(&r, 0) != 0 {
		t.Fatal("no jitter wanted")
	}
	if _, err := FindScenario("eclipse"); err == nil || !strings.Contains(err.Error(), "steady, server-silent, server-gone, app-killed, link-drop, route-push, dns-change") {
		t.Fatalf("unknown scenario: %v", err)
	}
	if _, err := FindApp("correct"); err != nil {
		t.Fatal(err)
	}
	if _, err := FindApp("toaster"); err == nil || !strings.Contains(err.Error(), "correct, dns-leak, no-kill-switch, follows-routes, agent-sealed, agent-env") {
		t.Fatalf("unknown app: %v", err)
	}
}

// leakyRun is a dns-leak client through a silent server: probes every 50 ms
// from 0 to 3000 ms; the fault is on from 1000 to 2200 ms; the client gives
// up on the server at 1600 ms and points DNS at the home router until it is
// back up at 2400 ms. TCP and UDP are held back while it is down.
func leakyRun() *builder {
	b := newBuilder("dns-leak", FaultServerSilent)
	b.step(0, StepStart, "").step(1000, StepFaultOn, FaultServerSilent).step(2200, StepFaultOff, FaultServerSilent).step(3000, StepStop, "")
	b.client(1600, "down", "no answer from the server for 600ms").client(1601, "dns", "192.168.1.1")
	b.client(2400, "up", "").client(2401, "dns", "10.66.0.1")
	for seq := 0; seq*50 < 3000; seq++ {
		at := seq * 50
		for _, k := range []string{DNS, TCP, UDP} {
			b.sent(at, k, Direct, seq)
		}
		switch {
		case at < 1000 || at > 2401:
			b.arrive(at+1, DNS, Direct, seq, AtVPNDNS, tunnelA)
			b.arrive(at+2, DNS, Direct, seq, AtZoneDNS, exit)
			b.arrive(at+1, TCP, Direct, seq, AtTCP, exit)
			b.arrive(at+1, UDP, Direct, seq, AtUDP, exit)
		case at > 1601:
			b.arrive(at+1, DNS, Direct, seq, AtHomeDNS, device)
			b.arrive(at+2, DNS, Direct, seq, AtZoneDNS, home)
		}
	}
	return b
}

func TestVerdictLeak(t *testing.T) {
	probes, v := Analyze(leakyRun().sorted(t))
	if v.Status != Leak || v.Summary() != "leak (dns)" {
		t.Fatalf("status %q %q", v.Status, v.Summary())
	}
	// DNS probes at 1650 ... 2400 ms leaked: 16 of them.
	if v.Sent != 180 || v.Leaked != 16 || v.Tunnel != 3*20+3*11 || v.Lost != 180-16-93 {
		t.Fatalf("counts: sent %d tunnel %d leaked %d lost %d", v.Sent, v.Tunnel, v.Leaked, v.Lost)
	}
	if len(v.Kinds) != 3 || v.Kinds[0] != (KindCount{DNS, Direct, 60, 31, 16, 13}) || v.Kinds[1].Leaked != 0 || v.Kinds[2].Kind != UDP {
		t.Fatalf("kinds: %+v", v.Kinds)
	}
	if len(v.Windows) != 1 {
		t.Fatalf("windows: %+v", v.Windows)
	}
	w := v.Windows[0]
	if !w.Start.Equal(ms(1651)) || !w.End.Equal(ms(2401)) || w.Probes != 16 || !reflect.DeepEqual(w.Kinds, []string{DNS}) || w.Open {
		t.Fatalf("window: %+v", w)
	}
	if w.After != "client dns 192.168.1.1" || w.AfterLag != 50*time.Millisecond || w.Before != "client dns 10.66.0.1" || w.BeforeLag != 0 {
		t.Fatalf("window edges: %+v", w)
	}
	if v.Recovery != 251*time.Millisecond {
		t.Fatalf("recovery %v", v.Recovery)
	}
	if !v.FaultOn.Equal(ms(1000)) || v.Fault != FaultServerSilent || v.Rel(v.FaultOff) != "2.20 s" {
		t.Fatalf("steps: %+v", v)
	}
	if len(probes) != 180 || probes[0].Outcome != Through || probes[0].At != AtVPNDNS {
		t.Fatalf("first probe: %+v", probes[0])
	}
	var leaked ProbeResult
	for _, p := range probes {
		if p.Outcome == Leaked {
			leaked = p
			break
		}
	}
	if leaked.Seq != 33 || leaked.At != AtHomeDNS || !leaked.Leak.Equal(ms(1651)) || leaked.Outcome.String() != "leaked" {
		t.Fatalf("first leaked probe: %+v", leaked)
	}
	text := v.Text()
	for _, want := range []string{
		"dns-leak, server-silent (seed 7): LEAK",
		"180 probes sent: 93 through the tunnel, 16 leaked, 71 seen nowhere",
		"dns               60 sent,    31 tunnel,    16 leaked,    13 nowhere",
		"fault server-silent: on at 1.00 s, off at 2.20 s; stop at 3.00 s",
		"the tunnel carried probes again 251 ms after the fault ended",
		"leak 1: 16 probes from 1.65 s to 2.40 s (dns)",
		"first seen 50 ms after: client dns 192.168.1.1",
		"last seen 0 ms before: client dns 10.66.0.1",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("missing %q in\n%s", want, text)
		}
	}
}

func TestVerdictPass(t *testing.T) {
	b := newBuilder("correct", FaultServerSilent)
	b.step(0, StepStart, "").step(500, StepFaultOn, FaultServerSilent).step(1000, StepFaultOff, FaultServerSilent).step(1500, StepStop, "")
	for seq := 0; seq < 30; seq++ {
		at := seq * 50
		b.sent(at, TCP, Direct, seq)
		b.sent(at, DNS, Proxy, seq)
		if at < 500 || at >= 1200 {
			b.arrive(at+3, TCP, Direct, seq, AtTCP, exit)
			b.arrive(at+3, DNS, Proxy, seq, AtZoneDNS, exit)
		}
	}
	v := Decide(b.sorted(t))
	if v.Status != Pass || v.Summary() != Pass || v.Leaked != 0 || len(v.Windows) != 0 || v.Lost != 28 {
		t.Fatalf("%+v", v)
	}
	if len(v.Kinds) != 2 || v.Kinds[0].Via != Direct || v.Kinds[1].Via != Proxy || v.Recovery != 203*time.Millisecond {
		t.Fatalf("kinds %+v recovery %v", v.Kinds, v.Recovery)
	}
	if !strings.Contains(v.Text(), "dns via proxy") || !strings.Contains(v.Text(), ": pass\n") {
		t.Fatalf("text:\n%s", v.Text())
	}
}

func TestVerdictOpenAndSeveralWindows(t *testing.T) {
	b := newBuilder("agent-env", FaultServerGone)
	b.step(0, StepStart, "").step(400, StepFaultOn, FaultServerGone).step(1000, StepStop, "")
	b.add(Event{T: ms(300), Ev: EvApp, State: "killed"})
	for seq := 0; seq < 20; seq++ {
		at := seq * 50
		b.sent(at, UDP, Direct, seq)
		b.sent(at, TCP, Proxy, seq)
		b.arrive(at+1, TCP, Proxy, seq, AtTCP, exit)
		// UDP leaks from 100 to 200 ms, then from 600 ms to the end.
		if (at >= 100 && at <= 200) || at >= 600 {
			b.arrive(at+1, UDP, Direct, seq, AtUDP, home)
		}
	}
	v := Decide(b.sorted(t))
	if v.Status != Leak || len(v.Windows) != 2 || v.Leaked != 3+8 {
		t.Fatalf("%s %+v", v.Status, v.Windows)
	}
	w0, w1 := v.Windows[0], v.Windows[1]
	if w0.Open || w0.After != "" || w0.Before != "app killed" || w0.BeforeLag != 99*time.Millisecond {
		t.Fatalf("first window: %+v", w0)
	}
	if !w1.Open || w1.After != "fault on (server-gone)" || w1.AfterLag != 201*time.Millisecond || w1.Before != "stop" {
		t.Fatalf("second window: %+v", w1)
	}
	if v.Recovery != -1 || !strings.Contains(v.Text(), "still leaking at the end") || !strings.Contains(v.Text(), ", to the end; stop at 1.00 s") {
		t.Fatalf("text:\n%s", v.Text())
	}
	if v.Summary() != "leak (udp)" {
		t.Fatalf("summary %q", v.Summary())
	}
}

func TestVerdictNoTraffic(t *testing.T) {
	b := newBuilder("correct", FaultAppKilled)
	b.step(0, StepStart, "").step(500, StepFaultOn, FaultAppKilled).step(800, StepFaultOff, FaultAppKilled).step(1000, StepStop, "")
	v := Decide(b.sorted(t))
	if v.Status != NoTraffic || len(v.Notes) != 1 || !strings.Contains(v.Notes[0], "sent nothing") {
		t.Fatalf("%+v", v)
	}
	// Probes that only get through after the fault don't count: the app
	// never carried traffic before it.
	for seq := 0; seq < 20; seq++ {
		b.sent(seq*50, DNS, Direct, seq)
		if seq*50 > 900 {
			b.arrive(seq*50+1, DNS, Direct, seq, AtVPNDNS, tunnelA)
		}
	}
	v = Decide(b.sorted(t))
	if v.Status != NoTraffic || !strings.Contains(v.Notes[0], "nothing came through the tunnel before the fault") || v.Recovery != 151*time.Millisecond {
		t.Fatalf("%+v", v)
	}
	if !strings.Contains(v.Text(), "no traffic") {
		t.Fatal(v.Text())
	}
	// A run with no steps at all still gets a verdict.
	b = newBuilder("correct", "steady")
	b.sent(0, DNS, Direct, 0).arrive(1, DNS, Direct, 0, AtVPNDNS, tunnelA)
	if v := Decide(b.sorted(t)); v.Status != Pass || !v.Start.IsZero() {
		t.Fatalf("no steps: %+v", v)
	}
}

func TestVerdictOddArrivals(t *testing.T) {
	b := newBuilder("correct", "steady")
	b.step(0, StepStart, "").step(1000, StepStop, "")
	b.sent(0, TCP, Direct, 1).arrive(1, TCP, Direct, 1, AtTCP, exit)
	b.sent(10, TCP, Direct, 1)                                             // the same probe again
	b.arrive(20, UDP, Direct, 99, AtUDP, home)                             // never sent
	b.sent(50, UDP, Direct, 2).arrive(51, UDP, Direct, 2, AtUDP, device)   // from an address the recording doesn't name
	b.sent(60, DNS, Direct, 3).arrive(61, DNS, Direct, 3, AtZoneDNS, exit) // through, then also outside
	b.arrive(62, DNS, Direct, 3, AtZoneDNS, home)
	b.sent(70, DNS, Direct, 4).arrive(71, DNS, Direct, 4, AtHomeDNS, device) // outside, then also through
	b.arrive(72, DNS, Direct, 4, AtVPNDNS, tunnelA)
	v := Decide(b.sorted(t))
	if v.Status != Leak || v.Duplicates != 1 || v.Stray != 1 || v.Unexplained != 1 || v.Leaked != 3 || v.Tunnel != 1 {
		t.Fatalf("%+v", v)
	}
	notes := strings.Join(v.Notes, "\n")
	for _, want := range []string{"neither the VPN's exit nor the home network's", "belong to no probe", "sent twice"} {
		if !strings.Contains(notes, want) {
			t.Errorf("notes lack %q:\n%s", want, notes)
		}
	}
	if Classify(b.rec.Header, Event{At: AtHomeDNS, Src: exit}) != Outside || Classify(b.rec.Header, Event{At: AtVPNDNS, Src: home}) != Tunnel {
		t.Fatal("classify")
	}
	if Lost.String() != "lost" || Through.String() != "tunnel" || kindRank("icmp") != 3 {
		t.Fatal("names")
	}
}

func TestFormatting(t *testing.T) {
	for n, want := range map[int]string{0: "0", 999: "999", 1000: "1,000", -1234567: "-1,234,567"} {
		if got := Comma(n); got != want {
			t.Errorf("Comma(%d) = %s", n, got)
		}
	}
	if Seconds(1234*time.Millisecond) != "1.23 s" || Millis(1500*time.Microsecond) != "2 ms" || plural(1, "probe") != "1 probe" {
		t.Fatal("formats")
	}
}
