// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package scopetest

import (
	"math/rand"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"vpnw.com/vpnw/internal/scope"
	"vpnw.com/vpnw/internal/scope/office"
)

// TestKernelAgreesLargeOffice repeats the kernel check on a generated office
// of VPNW_SCOPE_LARGE people (tools/measure-scope.sh uses 2,000): every
// distinct connection of the week after the learning window, plus random
// people against random systems and ports.
func TestKernelAgreesLargeOffice(t *testing.T) {
	n, _ := strconv.Atoi(os.Getenv("VPNW_SCOPE_LARGE"))
	if n <= 0 {
		t.Skip("set VPNW_SCOPE_LARGE=N to run")
	}
	o := office.Large(n, 1)
	stranger := netip.MustParseAddr("10.8.250.250")
	w := build(t, o, stranger)
	p := o.People()
	l := scope.NewLearner(p, scope.LearnOptions{From: o.Day(0), To: o.Day(14)})
	o.Flows(0, 14, 1, l.Add)
	d := l.Draft()
	script, err := scope.ExportNft(d, p, scope.NftOptions{})
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	load(t, script)
	loadTime := time.Since(start)

	seen := map[tuple]bool{}
	var flows []scope.Flow
	add := func(f scope.Flow) {
		if !seen[tupleOf(f)] {
			seen[tupleOf(f)] = true
			flows = append(flows, f)
		}
	}
	o.Flows(14, 21, 1, add)
	week := len(flows)
	rng := rand.New(rand.NewSource(1))
	for i := 0; i < 10000; i++ {
		s := o.Systems[rng.Intn(len(o.Systems))]
		src := stranger
		if i%50 != 0 {
			src = o.Members[rng.Intn(len(o.Members))].Addr
		}
		port := office.ScanPorts[rng.Intn(len(office.ScanPorts))]
		if i%2 == 0 {
			sv := s.Services[rng.Intn(len(s.Services))]
			port.Port, port.Proto = sv.Port, sv.Proto
		}
		add(scope.Flow{Time: o.Day(20), Proto: port.Proto, Src: src, Dst: s.Addr, Port: port.Port})
	}
	a := compare(t, w, scope.Compile(d, p), flows)
	elements := strings.Count(script, " . ")
	t.Logf("RESULT kernel-large: %d people, %d systems; %s; nftables script %d bytes, %d set elements, loaded in %s; "+
		"%d distinct tuples (%d from the replayed week, %d random), %d allowed and %d refused by the simulator, %d disagreements with the kernel, %s",
		n, len(o.Systems), d.Describe(), len(script), elements, loadTime.Round(time.Millisecond),
		a.tuples, week, a.tuples-week, a.allowed, a.refused, a.mismatches, a.elapsed.Round(time.Millisecond))
}
