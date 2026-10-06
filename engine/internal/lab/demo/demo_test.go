// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package demo

import (
	"strings"
	"testing"

	"vpnw.com/vpnw/internal/lab"
)

// TestRecordings checks the demo's recordings still read and still give the
// verdicts the page explains.
func TestRecordings(t *testing.T) {
	want := map[string]string{
		"correct-server-silent.jsonl":     "pass",
		"dns-leak-server-silent.jsonl":    "leak (dns)",
		"no-kill-switch-app-killed.jsonl": "leak (tcp, udp)",
		"follows-routes-route-push.jsonl": "leak (tcp, udp)",
	}
	for _, r := range Recordings {
		rec, err := Read(r.Name)
		if err != nil {
			t.Fatal(err)
		}
		v := lab.Decide(rec)
		if v.Summary() != want[r.Name] {
			t.Errorf("%s: %s, want %s", r.Name, v.Summary(), want[r.Name])
		}
		if v.Unexplained+v.Stray+v.Duplicates != 0 || !strings.HasPrefix(r.Name, rec.Header.App+"-"+rec.Header.Scenario) {
			t.Errorf("%s: %+v", r.Name, v)
		}
	}
	silent, _ := Read("dns-leak-server-silent.jsonl")
	v := lab.Decide(silent)
	if d := v.FaultOff.Sub(v.FaultOn).Seconds(); d < 5 || d > 5.3 {
		t.Errorf("the demo's server is silent for %.2f s, not 5", d)
	}
	if _, err := Text("missing.jsonl"); err == nil {
		t.Fatal("a missing recording")
	}
	if _, err := Read("missing.jsonl"); err == nil {
		t.Fatal("a missing recording")
	}
}
