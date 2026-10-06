// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

//go:build linux

// Package labtest runs Lab against the Linux kernel: every app through every
// scenario in a fresh test world of four network namespaces, with the
// stand-in clients, the probe and the Agent as real processes. It checks
// that each stand-in's planted fault is caught, that the correct client and
// the Agent's sealed mode pass every scenario, that the Agent's proxy
// settings alone leak, and that runs with the same seed give the same
// verdict.
package labtest

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"vpnw.com/vpnw/internal/lab"
	"vpnw.com/vpnw/internal/lab/bench"
	"vpnw.com/vpnw/internal/lab/world"
	"vpnw.com/vpnw/internal/testnet"
)

var (
	// binCover is where tools/measure-lab.sh wants the subprocesses'
	// coverage.
	binCover = os.Getenv("VPNW_LAB_BINCOVER")
	bins     string // where the built vpnw-lab and vpnw are
	buildErr error
)

func TestMain(m *testing.M) {
	// Runs mostly wait on timers, so more of them can share the machine
	// than it has CPUs: the runner's -parallel follows VPNW_LAB_PARALLEL
	// unless it is given.
	flag.Parse()
	given := false
	flag.Visit(func(f *flag.Flag) { given = given || f.Name == "test.parallel" })
	if !given {
		flag.Set("test.parallel", strconv.Itoa(cap(parallel)))
	}
	if err := testnet.Reexec(); err != nil {
		fmt.Println("lab kernel tests need user namespaces:", err)
		os.Exit(0)
	}
	if err := world.Check(); err != nil {
		fmt.Println("lab kernel tests skipped:", err)
		os.Exit(0)
	}
	dir, err := os.MkdirTemp("", "vpnw-lab-test-")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	bins = dir
	buildErr = build(dir)
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// build builds vpnw-lab, with coverage when the measurement asks for it,
// and the Agent's vpnw.
func build(dir string) error {
	args := []string{"build", "-o", filepath.Join(dir, "vpnw-lab")}
	if binCover != "" {
		args = append(args, "-cover", "-coverpkg=vpnw.com/vpnw/internal/lab/...,vpnw.com/vpnw/cmd/vpnw-lab")
	}
	for _, a := range [][]string{append(args, "vpnw.com/vpnw/cmd/vpnw-lab"), {"build", "-o", filepath.Join(dir, "vpnw"), "vpnw.com/vpnw/cmd/vpnw"}} {
		if out, err := exec.Command("go", a...).CombinedOutput(); err != nil {
			return fmt.Errorf("go %s: %v\n%s", strings.Join(a, " "), err, out)
		}
	}
	return nil
}

func needBins(t testing.TB) {
	t.Helper()
	if buildErr != nil {
		t.Fatal(buildErr)
	}
}

func env() []string {
	if binCover != "" {
		return []string{"GOCOVERDIR=" + binCover}
	}
	return nil
}

// runs is how many times each app goes through each scenario with the same
// seed: VPNW_LAB_RUNS, 1 by default; tools/measure-lab.sh uses 5.
func runs() int {
	if n, err := strconv.Atoi(os.Getenv("VPNW_LAB_RUNS")); err == nil && n > 0 {
		return n
	}
	return 1
}

// parallel is how many runs share the machine at once: VPNW_LAB_PARALLEL,
// 3 by default. Each has its own world, so they don't meet.
var parallel = func() chan struct{} {
	n := 3
	if v, err := strconv.Atoi(os.Getenv("VPNW_LAB_PARALLEL")); err == nil && v > 0 {
		n = v
	}
	return make(chan struct{}, n)
}()

// expected is the verdict each app should get in each scenario, by design.
var expected = map[string]map[string]string{
	"correct": {},
	"dns-leak": {lab.FaultServerSilent: "leak (dns)", lab.FaultServerGone: "leak (dns)",
		lab.FaultLinkDrop: "leak (dns)", lab.FaultDNSChange: "leak (dns)"},
	"no-kill-switch": {lab.FaultServerSilent: "leak (tcp, udp)", lab.FaultServerGone: "leak (tcp, udp)",
		lab.FaultAppKilled: "leak (tcp, udp)", lab.FaultLinkDrop: "leak (tcp, udp)"},
	"follows-routes": {lab.FaultRoutePush: "leak (tcp, udp)"},
	"agent-sealed":   {},
	"agent-env": {"steady": "leak (dns, tcp, udp)", lab.FaultServerSilent: "leak (dns, tcp, udp)",
		lab.FaultServerGone: "leak (dns, tcp, udp)", lab.FaultAppKilled: "leak (dns, tcp, udp)",
		lab.FaultLinkDrop: "leak (dns, tcp, udp)", lab.FaultRoutePush: "leak (dns, tcp, udp)", lab.FaultDNSChange: "leak (dns, tcp, udp)"},
}

// opens names the change that should open each designed leak, as the
// verdict describes it: the first leak window must open after one of these,
// and soon.
var opens = map[string]map[string][]string{
	"dns-leak": {
		lab.FaultServerSilent: {"client dns 192.168.1.1"},
		lab.FaultServerGone:   {"client dns 192.168.1.1"},
		lab.FaultLinkDrop:     {"fault off (link-drop)", "client link up"},
		lab.FaultDNSChange:    {"fault on (dns-change)"},
	},
	"no-kill-switch": {
		lab.FaultServerSilent: {"client routes removed"},
		lab.FaultServerGone:   {"client routes removed"},
		lab.FaultAppKilled:    {"fault on (app-killed)", "app killed"},
		lab.FaultLinkDrop:     {"fault off (link-drop)", "client link up"},
	},
	"follows-routes": {lab.FaultRoutePush: {"fault on (route-push)"}},
}

// closes names the change that should close each designed leak that ends
// before the run does.
var closes = map[string]map[string][]string{
	"dns-leak": {
		lab.FaultServerSilent: {"client up", "client routes installed"},
		lab.FaultLinkDrop:     {"client up", "client routes installed"},
	},
	"no-kill-switch": {
		lab.FaultServerSilent: {"client up", "client routes installed"},
		lab.FaultAppKilled:    {"client up", "client routes installed"},
		lab.FaultLinkDrop:     {"client up", "client routes installed"},
	},
	"follows-routes": {lab.FaultRoutePush: {"fault off (route-push)"}},
}

// wrongEdges says what is wrong with when a designed leak opened or closed,
// if anything: it must open after the change that causes it and close
// before the change that ends it, each within 250 ms. Leaks the design
// says last to the end must still be open when the run stops.
func wrongEdges(v *lab.Verdict) string {
	want, ok := opens[v.App][v.Scenario]
	if !ok || len(v.Windows) == 0 {
		return ""
	}
	first, last := v.Windows[0], v.Windows[len(v.Windows)-1]
	match := func(what string, lag time.Duration, list []string, side string) string {
		for _, p := range list {
			if strings.HasPrefix(what, p) {
				if lag > 250*time.Millisecond {
					return fmt.Sprintf("the leak was %s %s %q", side, lab.Millis(lag), what)
				}
				return ""
			}
		}
		return fmt.Sprintf("the leak was %s %q, not %s", side, what, strings.Join(list, " or "))
	}
	if why := match(first.After, first.AfterLag, want, "first seen after"); why != "" {
		return why
	}
	end, ends := closes[v.App][v.Scenario]
	switch {
	case !ends && !last.Open:
		return "the leak ended before the run did; by design it lasts to the end"
	case ends && last.Open:
		return "the leak was still open when the run stopped"
	case ends:
		return match(last.Before, last.BeforeLag, end, "last seen before")
	}
	return ""
}

func want(app, scenario string) string {
	if w, ok := expected[app][scenario]; ok {
		return w
	}
	return lab.Pass
}

func runOne(t *testing.T, app lab.App, sc lab.Scenario, seed int64, faultFor time.Duration) *bench.Result {
	t.Helper()
	parallel <- struct{}{}
	defer func() { <-parallel }()
	dir := t.TempDir()
	res, err := bench.Run(bench.Config{App: app, Scenario: sc, Seed: seed, FaultFor: faultFor,
		Self: filepath.Join(bins, "vpnw-lab"), VPNW: filepath.Join(bins, "vpnw"), Dir: dir, Env: env()})
	if err != nil {
		t.Fatalf("%s, %s: %v", app.Name, sc.Name, err)
	}
	return res
}

type outcome struct {
	app, scenario string
	run           int
	res           *bench.Result
}

var (
	mu       sync.Mutex
	outcomes []outcome
)

// TestMatrix runs every app through every scenario, runs() times each with
// seed 1, and checks every verdict against the design.
func TestMatrix(t *testing.T) {
	needBins(t)
	n := runs()
	t.Run("runs", func(t *testing.T) {
		for _, app := range lab.Apps {
			for _, sc := range lab.Scenarios {
				for i := 1; i <= n; i++ {
					app, sc, i := app, sc, i
					t.Run(fmt.Sprintf("%s/%s/%d", app.Name, sc.Name, i), func(t *testing.T) {
						t.Parallel()
						res := runOne(t, app, sc, 1, 0)
						v := res.Verdict
						mu.Lock()
						outcomes = append(outcomes, outcome{app.Name, sc.Name, i, res})
						mu.Unlock()
						defer func() {
							// A failed run's recording is kept for a look.
							if t.Failed() {
								var buf strings.Builder
								res.Recording.WriteTo(&buf)
								name := filepath.Join(os.TempDir(), fmt.Sprintf("vpnw-lab-failed-%s-%s-%d.jsonl", app.Name, sc.Name, i))
								os.WriteFile(name, []byte(buf.String()), 0o644)
								t.Logf("recording kept in %s", name)
							}
						}()
						if got, w := v.Summary(), want(app.Name, sc.Name); got != w {
							t.Errorf("%s, %s, run %d: %s, want %s\n%s", app.Name, sc.Name, i, got, w, v.Text())
						}
						if why := wrongEdges(v); why != "" {
							t.Errorf("%s, %s: %s", app.Name, sc.Name, why)
						}
						if v.Unexplained > 0 || v.Stray > 0 || v.Duplicates > 0 {
							t.Errorf("%s, %s: odd arrivals: %s", app.Name, sc.Name, strings.Join(v.Notes, "; "))
						}
						if n := throughDuringOutage(res.Recording, sc.Name); n > 0 {
							t.Errorf("%s, %s: %d probes arrived through the tunnel while the server was down", app.Name, sc.Name, n)
						}
						if sc.Off != "" {
							for _, k := range notRecovered(res.Recording, app.Name, sc.Name) {
								t.Errorf("%s, %s: no %s probe came through the tunnel after the fault ended", app.Name, sc.Name, k)
							}
						}
					})
				}
			}
		}
	})
	report(t, n)
}

// throughDuringOutage counts probes sent while the server was silent or
// gone that still came through the tunnel before the fault ended. A down
// server passes nothing. The fault counts from when the bench's action had
// finished, the step's time plus what its note says the action took, and
// 150 ms more for packets already on their way. Probes sent before that are
// left out: on a slow machine they may reach the far side late.
func throughDuringOutage(rec *lab.Recording, scenario string) int {
	if scenario != lab.FaultServerSilent && scenario != lab.FaultServerGone {
		return 0
	}
	probes, v := lab.Analyze(rec)
	from, to := v.FaultOn.Add(took(rec, lab.StepFaultOn)+150*time.Millisecond), v.FaultOff
	if to.IsZero() {
		to = v.Stop.Add(time.Second)
	}
	n := 0
	for _, p := range probes {
		if p.Outcome == lab.Through && !p.Sent.Before(from) && p.First.Before(to) {
			n++
		}
	}
	return n
}

// took reads how long the bench's action took for a step, from the step's
// note, such as "took 23 ms".
func took(rec *lab.Recording, step string) time.Duration {
	for _, e := range rec.Events {
		if e.Ev == lab.EvStep && e.Step == step {
			var ms int
			if _, err := fmt.Sscanf(e.Note, "took %d ms", &ms); err == nil {
				return time.Duration(ms) * time.Millisecond
			}
		}
	}
	return 0
}

// notRecovered lists the kinds of probe that never came through the tunnel
// again after the fault ended. Every app should recover every kind it
// carries, except the dns-leak client after a DNS change: it never puts its
// own resolver back, which is its fault.
func notRecovered(rec *lab.Recording, app, scenario string) []string {
	probes, v := lab.Analyze(rec)
	back := map[string]bool{}
	for _, p := range probes {
		if p.Outcome == lab.Through && !p.Sent.Before(v.FaultOff) {
			back[p.Kind+" "+p.Via] = true
		}
	}
	kinds := []string{"dns direct", "tcp direct", "udp direct"}
	if strings.HasPrefix(app, "agent-") {
		kinds = []string{"dns proxy", "tcp proxy"}
	}
	var out []string
	for _, k := range kinds {
		if !back[k] && !(app == "dns-leak" && scenario == lab.FaultDNSChange && k == "dns direct") {
			out = append(out, k)
		}
	}
	return out
}

func report(t *testing.T, n int) {
	mu.Lock()
	defer mu.Unlock()
	if len(outcomes) == 0 {
		return
	}
	sort.SliceStable(outcomes, func(i, j int) bool {
		a, b := outcomes[i], outcomes[j]
		if a.app != b.app {
			return appIndex(a.app) < appIndex(b.app)
		}
		if a.scenario != b.scenario {
			return scenarioIndex(a.scenario) < scenarioIndex(b.scenario)
		}
		return a.run < b.run
	})
	// One line per app and scenario: the verdict of every run.
	type key struct{ app, scenario string }
	verdicts := map[key][]string{}
	leaked := map[key][]int{}
	took := map[string][]time.Duration{}
	agree, total := 0, 0
	var startLag, endLag []time.Duration
	for _, o := range outcomes {
		k := key{o.app, o.scenario}
		v := o.res.Verdict
		verdicts[k] = append(verdicts[k], v.Summary())
		leaked[k] = append(leaked[k], v.Leaked)
		took[o.scenario] = append(took[o.scenario], o.res.Took)
		total++
		if v.Summary() == want(o.app, o.scenario) {
			agree++
		}
		for _, w := range v.Windows {
			// Leaks that began after a change made by the bench or the
			// app: the lag says how soon Lab saw the first leaked probe.
			if w.After != "" && !strings.HasPrefix(w.After, "app started") {
				startLag = append(startLag, w.AfterLag)
			}
			if !w.Open && w.Before != "" && w.Before != "stop" {
				endLag = append(endLag, w.BeforeLag)
			}
		}
	}
	for _, app := range lab.Apps {
		var cells []string
		for _, sc := range lab.Scenarios {
			k := key{app.Name, sc.Name}
			vs := verdicts[k]
			if len(vs) == 0 {
				continue
			}
			same := true
			for _, v := range vs {
				same = same && v == vs[0]
			}
			cell := fmt.Sprintf("%s %s", sc.Name, vs[0])
			if !same {
				cell = fmt.Sprintf("%s VARIES %v", sc.Name, vs)
			}
			if len(leaked[k]) > 0 && vs[0] != lab.Pass {
				lo, hi := minMax(leaked[k])
				if lo == hi {
					cell += fmt.Sprintf(" %d probes", lo)
				} else {
					cell += fmt.Sprintf(" %d-%d probes", lo, hi)
				}
			}
			cells = append(cells, cell)
		}
		t.Logf("RESULT matrix %s: %s", app.Name, strings.Join(cells, "; "))
	}
	t.Logf("RESULT matrix: %d runs (%d apps, %d scenarios, %d each with seed 1), %d with the verdict the design expects, %d without",
		total, len(lab.Apps), len(lab.Scenarios), n, agree, total-agree)
	if len(startLag) > 0 {
		t.Logf("RESULT timing: leaks first seen %s after the change that opened them (median of %d windows; at most %s); last seen %s before the change that closed them (median of %d; at most %s); probe interval 50 ms",
			lab.Millis(median(startLag)), len(startLag), lab.Millis(maxOf(startLag)), lab.Millis(median(endLag)), len(endLag), lab.Millis(maxOf(endLag)))
	}
	var durs []string
	for _, sc := range lab.Scenarios {
		if d := took[sc.Name]; len(d) > 0 {
			durs = append(durs, fmt.Sprintf("%s %s", sc.Name, lab.Seconds(median(d))))
		}
	}
	t.Logf("RESULT durations: median wall time of a run, building the world and starting the app included: %s", strings.Join(durs, ", "))
}

func appIndex(name string) int {
	for i, a := range lab.Apps {
		if a.Name == name {
			return i
		}
	}
	return len(lab.Apps)
}

func scenarioIndex(name string) int {
	for i, s := range lab.Scenarios {
		if s.Name == name {
			return i
		}
	}
	return len(lab.Scenarios)
}

func minMax(xs []int) (int, int) {
	lo, hi := xs[0], xs[0]
	for _, x := range xs {
		lo, hi = min(lo, x), max(hi, x)
	}
	return lo, hi
}

func median(ds []time.Duration) time.Duration {
	if len(ds) == 0 {
		return 0
	}
	s := append([]time.Duration(nil), ds...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	return s[len(s)/2]
}

func maxOf(ds []time.Duration) time.Duration {
	m := time.Duration(0)
	for _, d := range ds {
		m = max(m, d)
	}
	return m
}
