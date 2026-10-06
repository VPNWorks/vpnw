// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package exittest

import (
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"
)

// The clients of both exits in these tests: two agents and a CI job.
var (
	agent1 = client{name: "agent-1", token: "tok-agent-1-7Qp2vN", sources: map[string]string{"exit-de": "198.51.100.10", "exit-nl": "203.0.113.10"},
		policy: "default = \"deny\"\ndeny_private = true\nallow = [\"api.partner.test\", \"*.partner.test\"]\n"}
	agent2 = client{name: "agent-2", token: "tok-agent-2-Lm81xK", sources: map[string]string{"exit-de": "198.51.100.11", "exit-nl": "203.0.113.11"},
		policy: "default = \"deny\"\ndeny_private = true\nallow = [\"files.partner.test\", \"api.partner.test:80\"]\n"}
	ci = client{name: "ci", token: "tok-ci-0Hd3Rw", sources: map[string]string{},
		policy: "default = \"deny\"\nallow = [\"api.partner.test\"]\n"}
	clients = []client{agent1, agent2, ci}
)

// twoExits starts exit-de and exit-nl for every client.
func (w *world) twoExits() (de, nl *exitProc) {
	for _, c := range clients {
		w.tokenFile(c)
	}
	de = w.startExit("exit-de", w.exitConfig("exit-de", deListen, exitPort, "exit-de", clients))
	nl = w.startExit("exit-nl", w.exitConfig("exit-nl", nlListen, exitPort, "exit-nl", clients))
	return de, nl
}

func guard(c client) []string {
	return []string{"guard", "--backend", "sealed", "--policy", c.name + ".toml", "--via", "exits"}
}

// An allowed request leaves from the client's own fixed address at the exit
// in use, and a pool client keeps one address of its pool.
func TestFixedAddresses(t *testing.T) {
	w := build(t)
	w.twoExits()
	since := time.Now()
	out1, p1, _ := w.runAgent("agent-1", guard(agent1), fetch("http://api.partner.test/", "http://www.partner.test:8080/"))
	out2, p2, _ := w.runAgent("agent-2", guard(agent2), fetch("http://files.partner.test/", "http://api.partner.test/"))
	want := []string{
		"OK http://api.partner.test/ seen-from 198.51.100.10 at 51.15.0.10:80",
		"OK http://www.partner.test:8080/ seen-from 198.51.100.10 at 51.15.0.12:8080",
		"OK http://files.partner.test/ seen-from 198.51.100.11 at 51.15.0.11:80",
		"OK http://api.partner.test/ seen-from 198.51.100.11 at 51.15.0.10:80",
	}
	got := append(lines(out1, "OK"), lines(out2, "OK")...)
	if strings.Join(got, "\n") != strings.Join(want, "\n") || p1.code != 0 || p2.code != 0 {
		t.Fatalf("got\n%s\n%s\nagent-1 (exit %d):\n%s\nagent-2 (exit %d):\n%s", out1, out2, p1.code, p1.out.String(), p2.code, p2.out.String())
	}
	// The CI job has no Agent: it talks to the exit itself, ten times.
	seen := map[string]int{}
	for i := 0; i < 10; i++ {
		r := w.tamper(ci.token, "exit-de", "api.partner.test:80", "")
		if r.status != 200 {
			t.Fatalf("ci: %+v", r)
		}
		seen[r.body]++
	}
	if len(seen) != 1 {
		t.Errorf("the pool client changed address: %v", seen)
	}
	var ciAddr string
	for k := range seen {
		ciAddr = strings.Fields(k)[1]
	}
	// The partner's servers saw these addresses and no others.
	byAddr := map[string]int{}
	for _, h := range w.hitsSince(since) {
		byAddr[h.Src]++
	}
	if len(byAddr) != 3 || byAddr["198.51.100.10"] != 2 || byAddr["198.51.100.11"] != 2 || byAddr[ciAddr] != 10 {
		t.Errorf("the partner's servers saw %v", byAddr)
	}
	var saw []string
	for a, n := range byAddr {
		saw = append(saw, fmt.Sprintf("%s %d times", a, n))
	}
	sort.Strings(saw)
	t.Logf("RESULT fixed: agent-1 reached the partner from 198.51.100.10 and agent-2 from 198.51.100.11 through exit-de; a pool client kept %s for 10 of 10 connections; the partner's servers saw %s, and no other address",
		ciAddr, strings.Join(saw, ", "))
}
