// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package office

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"testing"

	"vpnw.com/vpnw/internal/scope"
)

func digest(o *Office, from, to int, seed uint64) (string, int) {
	h := sha256.New()
	n := 0
	o.Flows(from, to, seed, func(f scope.Flow) {
		h.Write(f.AppendJSON(nil))
		n++
	})
	return fmt.Sprintf("%x", h.Sum(nil))[:16], n
}

func TestFlowsAreRepeatable(t *testing.T) {
	a, n := digest(Demo(), 0, 21, DemoSeed)
	b, m := digest(Demo(), 0, 21, DemoSeed)
	c, _ := digest(Demo(), 0, 21, DemoSeed+1)
	if a != b || n != m {
		t.Fatal("the same seed gave different flows")
	}
	if a == c {
		t.Fatal("a different seed gave the same flows")
	}
	// Starting later gives the same days, not a different draw.
	whole := map[string]bool{}
	Demo().Flows(0, 21, DemoSeed, func(f scope.Flow) {
		if !f.Time.Before(Demo().Day(14)) {
			whole[string(f.AppendJSON(nil))] = true
		}
	})
	k := 0
	Demo().Flows(14, 21, DemoSeed, func(f scope.Flow) {
		if !whole[string(f.AppendJSON(nil))] {
			t.Fatalf("flow %s differs when starting at day 14", f.AppendJSON(nil))
		}
		k++
	})
	if k != len(whole) {
		t.Fatalf("%d flows from day 14, %d in the full run", k, len(whole))
	}
}

// TestDemoNumbers pins the numbers the demo page and the Alpha report show.
// If the generator or the learner changes them, both must be redone.
func TestDemoNumbers(t *testing.T) {
	o := Demo()
	p := o.People()
	if len(o.Members) != 30 || len(o.Systems) != 12 || len(p.GroupOrder) != 5 {
		t.Fatalf("office shape: %d people, %d systems, %d groups", len(o.Members), len(o.Systems), len(p.GroupOrder))
	}
	l := scope.NewLearner(p, scope.LearnOptions{From: o.Day(DemoLearnFrom), To: o.Day(DemoLearnTo)})
	o.Flows(DemoLearnFrom, DemoLearnTo, DemoSeed, l.Add)
	d := l.Draft()
	c := d.Count()
	if l.Stats.InWindow != 20232 || c.GroupRules != 39 || c.PersonRules != 11 || c.Review != 3 {
		t.Fatalf("learned from %d flows: %s", l.Stats.InWindow, d.Describe())
	}
	pol := scope.Compile(d, p)
	r := scope.NewReplay(pol)
	o.Flows(DemoReplayFrom, DemoReplayTo, DemoSeed, func(f scope.Flow) { r.Add(f) })
	keys := r.DeniedKeys()
	if r.Flows != 10387 || r.Allowed != 10375 || r.Denied != 12 || len(keys) != 2 ||
		keys[0].Person != "farid" || keys[0].Count != 9 || keys[1].Person != "quinn" || keys[1].Count != 3 {
		t.Fatalf("replay: %d flows, %d allowed, %d denied, %+v", r.Flows, r.Allowed, r.Denied, keys)
	}
	if r.People["hana"] == nil || r.People["hana"].Allowed == 0 || r.People["hana"].Denied != 0 {
		t.Fatalf("the new hire: %+v", r.People["hana"])
	}
	allowed, systems := 0, map[string]bool{}
	attempts := o.StolenLogin(DemoStolenLogin, DemoStolenAt)
	for _, f := range attempts {
		if pol.Decide(f).Outcome == scope.Allowed {
			allowed++
			systems[o.SystemAt(f.Dst).Name] = true
		}
	}
	if len(attempts) != 144 || allowed != 8 || len(systems) != 6 {
		t.Fatalf("stolen login: %d attempts, %d allowed on %d systems", len(attempts), allowed, len(systems))
	}
}

func TestLargeOffice(t *testing.T) {
	o := Large(500, 7)
	p := o.People()
	if len(p.List) != 500 || len(o.Systems) != 3+500/7 || len(p.GroupOrder) < 2 {
		t.Fatalf("%d people, %d systems, %d groups", len(p.List), len(o.Systems), len(p.GroupOrder))
	}
	_, n := digest(o, 0, 14, 7)
	if n < 100000 {
		t.Fatalf("only %d flows for 500 people over two weeks", n)
	}
	if !strings.Contains(o.PeopleFile(), `vpn_net = "10.8.0.0/16"`) {
		t.Error("people file")
	}
	small := Large(10, 1)
	if len(small.Systems) != 13 {
		t.Errorf("a small office still gets 10 systems plus the 3 shared ones, got %d", len(small.Systems))
	}
}

func TestHelpers(t *testing.T) {
	o := Demo()
	if o.System("erp") == nil || o.System("nope") != nil || o.SystemAt(o.System("git").Addr).Name != "git" || o.SystemAt(o.VPNNet.Addr()) != nil {
		t.Fatal("system lookups")
	}
	if !o.System("dns").Offers(53, scope.UDP) || o.System("dns").Offers(80, scope.TCP) {
		t.Fatal("Offers")
	}
	defer func() {
		if recover() == nil {
			t.Error("no panic for an unknown member")
		}
	}()
	o.member("nobody")
}
