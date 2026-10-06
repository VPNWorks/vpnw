// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package scopetest

import (
	"fmt"
	"math/rand"
	"net/netip"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"testing"
	"time"

	"vpnw.com/vpnw/internal/scope"
	"vpnw.com/vpnw/internal/scope/office"
	"vpnw.com/vpnw/internal/scope/record"
)

// unknown is a VPN address that belongs to no one in the people file.
var unknown = netip.MustParseAddr("10.8.0.200")

func learnDemo(t testing.TB, o *office.Office) (*scope.People, *scope.Draft) {
	t.Helper()
	p := o.People()
	l := scope.NewLearner(p, scope.LearnOptions{From: o.Day(office.DemoLearnFrom), To: o.Day(office.DemoLearnTo)})
	o.Flows(office.DemoLearnFrom, office.DemoLearnTo, office.DemoSeed, l.Add)
	return p, l.Draft()
}

// grid is every source (each person, plus an unknown VPN address) against
// every system on every port a stolen login would try.
func grid(o *office.Office) []scope.Flow {
	srcs := []netip.Addr{unknown}
	for _, m := range o.Members {
		srcs = append(srcs, m.Addr)
	}
	var out []scope.Flow
	for _, src := range srcs {
		for _, s := range o.Systems {
			for _, p := range office.ScanPorts {
				out = append(out, scope.Flow{Time: office.DemoStolenAt, Proto: p.Proto, Src: src, Dst: s.Addr, Port: p.Port})
			}
		}
	}
	return out
}

type agreement struct {
	tuples, allowed, refused, mismatches int
	elapsed                              time.Duration
}

// compare makes a real connection for every flow and checks the kernel
// against the simulator.
func compare(t testing.TB, w *world, pol *scope.Policy, flows []scope.Flow) agreement {
	t.Helper()
	var a agreement
	start := time.Now()
	for _, f := range flows {
		v := pol.Decide(f)
		want := Refused
		if v.Outcome == scope.Allowed {
			want = Reached
		}
		got, err := w.probe(f)
		if err != nil {
			t.Fatal(err)
		}
		a.tuples++
		if want == Reached {
			a.allowed++
		} else {
			a.refused++
		}
		if got != want {
			a.mismatches++
			if a.mismatches <= 10 {
				t.Errorf("%s -> %s:%d/%s: simulator says %s (%s%s), kernel %s", f.Src, f.Dst, f.Port, f.Proto,
					v.Outcome, v.Rule, v.Reason, got)
			}
		}
	}
	a.elapsed = time.Since(start)
	return a
}

// TestKernelAgreesWithSimulator loads the draft learned from the demo
// office's first two weeks into the gateway and tries every person, and an
// unknown VPN address, against every system on every scanned port.
func TestKernelAgreesWithSimulator(t *testing.T) {
	o := office.Demo()
	w := build(t, o, unknown)
	p, d := learnDemo(t, o)
	script, err := scope.ExportNft(d, p, scope.NftOptions{})
	if err != nil {
		t.Fatal(err)
	}
	load(t, script)
	a := compare(t, w, scope.Compile(d, p), grid(o))
	t.Logf("RESULT kernel-demo: %d tuples, %d allowed and %d refused by the simulator, %d disagreements with the kernel, %s",
		a.tuples, a.allowed, a.refused, a.mismatches, a.elapsed.Round(time.Millisecond))
}

// TestKernelAgreesOnRanges uses a hand-written draft with address
// ranges, port ranges, udp, and rules that overlap across a person and
// their group.
func TestKernelAgreesOnRanges(t *testing.T) {
	o := office.Demo()
	w := build(t, o, unknown)
	p := o.People()
	src := `version = 1
default = "deny"

[groups.engineering]
allow = ["10.0.2.0/24:22-443/tcp", "10.0.0.53:53/udp", "10.0.0.53:53/tcp"]

[groups.it]
allow = ["10.0.0.0/16:8000-8443/tcp", "10.0.9.10:22/tcp", "10.0.0.53:1-65535/udp"]

[people.alice]
allow = ["10.0.1.20:443/tcp", "10.0.1.21:5432/tcp", "10.0.1.0/24:993/tcp"]
review = ["10.0.2.30:5432/tcp"]

[people.chen]
allow = ["10.0.2.30:5432/tcp", "10.0.2.10:443/tcp"]

[people.zoe]
allow = ["10.0.1.0/28:1-1024/tcp", "10.0.1.10:993/tcp"]
`
	d, err := scope.ParseDraft(src, "ranges.toml", p)
	if err != nil {
		t.Fatal(err)
	}
	script, err := scope.ExportNft(d, p, scope.NftOptions{})
	if err != nil {
		t.Fatal(err)
	}
	load(t, script)
	a := compare(t, w, scope.Compile(d, p), grid(o))
	t.Logf("RESULT kernel-ranges: %d tuples, %d allowed and %d refused by the simulator, %d disagreements with the kernel",
		a.tuples, a.allowed, a.refused, a.mismatches)
}

// TestStolenLogin replays a stolen login trying every system, first on a
// flat VPN, then under the learned draft.
func TestStolenLogin(t *testing.T) {
	o := office.Demo()
	w := build(t, o)
	p, d := learnDemo(t, o)
	attempts := o.StolenLogin(office.DemoStolenLogin, office.DemoStolenAt)
	count := func() (int, map[netip.Addr]bool) {
		reached, systems := 0, map[netip.Addr]bool{}
		for _, f := range attempts {
			r, err := w.probe(f)
			if err != nil {
				t.Fatal(err)
			}
			if r == Reached {
				reached++
				systems[f.Dst] = true
			}
		}
		return reached, systems
	}
	flat, flatSys := count()
	if flat != len(attempts) || len(flatSys) != len(o.Systems) {
		t.Fatalf("flat VPN: %d of %d attempts reached %d systems; want all", flat, len(attempts), len(flatSys))
	}
	script, err := scope.ExportNft(d, p, scope.NftOptions{})
	if err != nil {
		t.Fatal(err)
	}
	load(t, script)
	pol := scope.Compile(d, p)
	used := 0
	for _, f := range attempts {
		if pol.Decide(f).Outcome == scope.Allowed {
			used++
		}
	}
	drafted, draftSys := count()
	if drafted != used {
		t.Fatalf("under the draft %d attempts reached; the simulator allows %d", drafted, used)
	}
	t.Logf("RESULT stolen: flat VPN %d of %d attempts reached %d of %d systems; under the draft %d attempts reached %d systems",
		flat, len(attempts), len(flatSys), len(o.Systems), drafted, len(draftSys))
}

// TestWatchMode checks that watch mode refuses nothing and counts exactly
// what enforcement would refuse.
func TestWatchMode(t *testing.T) {
	o := office.Demo()
	w := build(t, o, unknown)
	p, d := learnDemo(t, o)
	script, err := scope.ExportNft(d, p, scope.NftOptions{Watch: true})
	if err != nil {
		t.Fatal(err)
	}
	load(t, script)
	pol := scope.Compile(d, p)
	flows := grid(o)
	wouldRefuse := 0
	for _, f := range flows {
		if pol.Decide(f).Outcome != scope.Allowed {
			wouldRefuse++
		}
		r, err := w.probe(f)
		if err != nil {
			t.Fatal(err)
		}
		if r != Reached {
			t.Fatalf("watch mode refused %s -> %s:%d/%s", f.Src, f.Dst, f.Port, f.Proto)
		}
	}
	out, err := exec.Command("nft", "list", "table", "inet", "vpnw_scope").CombinedOutput()
	if err != nil {
		t.Fatalf("nft list: %v: %s", err, out)
	}
	m := regexp.MustCompile(`counter packets (\d+) bytes \d+ accept comment "would be refused"`).FindSubmatch(out)
	if m == nil {
		t.Fatalf("no watch counter in:\n%s", out)
	}
	counted, _ := strconv.Atoi(string(m[1]))
	if counted != wouldRefuse {
		t.Fatalf("watch counter %d, simulator would refuse %d", counted, wouldRefuse)
	}
	t.Logf("RESULT watch: %d tuples all reached; counter %d equals the %d the simulator would refuse", len(flows), counted, wouldRefuse)
}

type tuple struct {
	src, dst netip.Addr
	port     uint16
	proto    scope.Proto
}

func tupleOf(f scope.Flow) tuple { return tuple{f.Src, f.Dst, f.Port, f.Proto} }

// TestRecorderSeesEveryConnection records at the gateway while enforcement
// is on, and checks the recorder against the attempts made, refused ones
// included.
func TestRecorderSeesEveryConnection(t *testing.T) {
	o := office.Demo()
	w := build(t, o, unknown)
	p, d := learnDemo(t, o)
	script, err := scope.ExportNft(d, p, scope.NftOptions{})
	if err != nil {
		t.Fatal(err)
	}
	load(t, script)
	const group = 7
	l, err := record.Listen(group)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if err := record.Install(p.VPNNet, group); err != nil {
		t.Fatal(err)
	}
	all := grid(o)
	rng := rand.New(rand.NewSource(1))
	rng.Shuffle(len(all), func(i, j int) { all[i], all[j] = all[j], all[i] })
	attempts := all[:600]
	want := map[tuple]int{}
	refused := 0
	for _, f := range attempts {
		r, err := w.probe(f)
		if err != nil {
			t.Fatal(err)
		}
		if r == Refused {
			refused++
		}
		want[tupleOf(f)]++
	}
	got := map[tuple]int{}
	n := 0
	quiet := time.Now().Add(time.Second)
	for time.Now().Before(quiet) {
		l.SetDeadline(time.Now().Add(100 * time.Millisecond))
		flows, err := l.Read()
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range flows {
			got[tupleOf(f)]++
			n++
			quiet = time.Now().Add(500 * time.Millisecond)
		}
	}
	var missing, extra []string
	for k, c := range want {
		if got[k] != c {
			missing = append(missing, fmt.Sprintf("%v x%d (recorded %d)", k, c, got[k]))
		}
	}
	for k, c := range got {
		if want[k] == 0 {
			extra = append(extra, fmt.Sprintf("%v x%d", k, c))
		}
	}
	sort.Strings(missing)
	sort.Strings(extra)
	if len(missing) > 0 || len(extra) > 0 {
		t.Fatalf("recorder differs from the attempts: %d missing or miscounted %v, %d extra %v", len(missing), missing, len(extra), extra)
	}
	t.Logf("RESULT recorder: %d attempts (%d refused by the gateway), %d recorded, every one matched; %d packets skipped",
		len(attempts), refused, n, l.Skipped)
}
