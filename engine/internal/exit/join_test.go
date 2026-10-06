// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package exit

import (
	"bytes"
	"strings"
	"testing"

	"vpnw.com/vpnw/internal/events"
)

// records builds an Agent's record and two exits' records the way the
// engines write them.
type records struct {
	agent, de, nl *events.Bus
	ma, mx        *events.Memory
}

func newRecords() *records {
	r := &records{agent: events.NewBus("r-agent1", nil), de: events.NewBus("x-de0001", nil), nl: events.NewBus("x-nl0001", nil),
		ma: &events.Memory{}, mx: &events.Memory{}}
	r.agent.Add(r.ma)
	r.de.Add(r.mx)
	r.nl.Add(r.mx)
	r.agent.Emit(events.RunStart, 0, "exits", 0, map[string]any{"mode": "guard"})
	r.de.Emit(events.RunStart, 0, "exit-de", 0, map[string]any{"mode": "exit"})
	r.nl.Emit(events.RunStart, 0, "exit-nl", 0, map[string]any{"mode": "exit"})
	return r
}

func (r *records) attempt(conn uint64, host string, port int) {
	r.agent.Emit(events.ConnectionAttempt, 1, "exits", conn, map[string]any{"host": host, "port": port, "proto": "http-connect"})
	r.agent.Emit(events.PolicyAllow, 1, "exits", conn, map[string]any{"rule": "allow[0]"})
}

func (r *records) exitSaw(bus *events.Bus, name string, xconn uint64, run string, conn uint64, host string, port int, outcome string) {
	f := map[string]any{"host": host, "port": port, "proto": "http-connect", "client": "agent-1"}
	if run != "" {
		f["client_run"], f["client_conn"] = run, conn
	}
	bus.Emit(events.ConnectionAttempt, 0, name, xconn, f)
	switch outcome {
	case "open":
		bus.Emit(events.PolicyAllow, 0, name, xconn, map[string]any{"rule": "allow[0]"})
		bus.Emit(events.ConnectionOpen, 0, name, xconn, map[string]any{"source": "198.51.100.10"})
	case "denied":
		bus.Emit(events.PolicyDeny, 0, name, xconn, map[string]any{"rule": "deny_private", "reason": "private"})
	}
}

func TestJoin(t *testing.T) {
	r := newRecords()
	// 1: through exit-de. 2: denied at the Agent. 3: refused at exit-de.
	r.attempt(1, "api.partner.test", 443)
	r.exitSaw(r.de, "exit-de", 1, "r-agent1", 1, "api.partner.test", 443, "open")
	r.agent.Emit(events.ConnectionOpen, 1, "exits", 1, map[string]any{"exit": "198.51.100.2:8443"})
	r.agent.Emit(events.ConnectionAttempt, 1, "exits", 2, map[string]any{"host": "attacker.test", "port": 443})
	r.agent.Emit(events.PolicyDeny, 1, "exits", 2, map[string]any{"rule": "default"})
	r.attempt(3, "intranet.partner.test", 443)
	r.exitSaw(r.de, "exit-de", 2, "r-agent1", 3, "intranet.partner.test", 443, "denied")
	r.agent.Emit(events.ConnectionError, 1, "exits", 3, map[string]any{"error": "the exit refused it (deny_private): private", "exit": "198.51.100.2:8443"})
	// 4: exit-de took the request and died before answering; the Agent
	// moved to exit-nl.
	r.attempt(4, "api.partner.test", 443)
	r.exitSaw(r.de, "exit-de", 3, "r-agent1", 4, "api.partner.test", 443, "")
	r.agent.Emit(events.PathSwitch, 1, "exits", 4, map[string]any{"from": "198.51.100.2:8443", "to": "203.0.113.2:8443"})
	r.exitSaw(r.nl, "exit-nl", 1, "r-agent1", 4, "api.partner.test", 443, "open")
	r.agent.Emit(events.ConnectionOpen, 1, "exits", 4, map[string]any{"exit": "203.0.113.2:8443"})
	// A client without an Agent, straight to exit-nl.
	r.exitSaw(r.nl, "exit-nl", 2, "", 0, "169.254.169.254", 80, "denied")

	rep := Join(r.ma.Snapshot(), r.mx.Snapshot())
	if !rep.OK() || rep.AgentConns != 4 || rep.ViaExit != 3 || rep.Local != 1 || rep.Joined != 3 || rep.ExitConns != 5 || rep.Other != 1 {
		t.Fatalf("%+v", rep)
	}
	if strings.Join(rep.AgentRuns, ",") != "r-agent1" || strings.Join(rep.ExitRuns, ",") != "exit-de x-de0001,exit-nl x-nl0001" {
		t.Errorf("runs %v %v", rep.AgentRuns, rep.ExitRuns)
	}
	want := []string{
		"r-agent1/1 api.partner.test:443 exit-de open|open from 198.51.100.10",
		"r-agent1/3 intranet.partner.test:443 exit-de failed: the exit refused it (deny_private): private|refused: deny_private",
		"r-agent1/4 api.partner.test:443 exit-nl open|open from 198.51.100.10",
		"/0 169.254.169.254:80 exit-nl not in these records (no run ID)|refused: deny_private",
	}
	if len(rep.Rows) != len(want) {
		t.Fatalf("rows %+v", rep.Rows)
	}
	for i, row := range rep.Rows {
		got := row.Run + "/" + itoa(row.Conn) + " " + row.Target + " " + row.Exit + " " + row.Agent + "|" + row.AtExit
		if got != want[i] || !row.OK {
			t.Errorf("row %d: %s", i, got)
		}
	}
}

func itoa(n uint64) string {
	var b bytes.Buffer
	if n == 0 {
		return "0"
	}
	var d []byte
	for ; n > 0; n /= 10 {
		d = append([]byte{byte('0' + n%10)}, d...)
	}
	b.Write(d)
	return b.String()
}

func TestJoinProblems(t *testing.T) {
	cases := []struct {
		name  string
		build func(r *records)
		want  string
	}{
		{"no exit record", func(r *records) {
			r.attempt(1, "api.partner.test", 443)
			r.agent.Emit(events.ConnectionOpen, 1, "exits", 1, map[string]any{"exit": "198.51.100.2:8443"})
		}, "no exit record has it"},
		{"outcomes differ", func(r *records) {
			r.attempt(1, "api.partner.test", 443)
			r.exitSaw(r.de, "exit-de", 1, "r-agent1", 1, "api.partner.test", 443, "denied")
			r.agent.Emit(events.ConnectionOpen, 1, "exits", 1, map[string]any{"exit": "198.51.100.2:8443"})
		}, `the Agent recorded "open", the exit "refused: deny_private"`},
		{"targets differ", func(r *records) {
			r.attempt(1, "api.partner.test", 443)
			r.exitSaw(r.de, "exit-de", 1, "r-agent1", 1, "evil.test", 443, "open")
			r.agent.Emit(events.ConnectionOpen, 1, "exits", 1, map[string]any{"exit": "198.51.100.2:8443"})
		}, "the exit recorded evil.test:443"},
		{"ports differ", func(r *records) {
			r.attempt(1, "api.partner.test", 443)
			r.exitSaw(r.de, "exit-de", 1, "r-agent1", 1, "api.partner.test", 22, "open")
			r.agent.Emit(events.ConnectionOpen, 1, "exits", 1, map[string]any{"exit": "198.51.100.2:8443"})
		}, "the exit recorded api.partner.test:22"},
		{"an exit record the Agent does not have", func(r *records) {
			r.exitSaw(r.de, "exit-de", 1, "r-agent1", 9, "api.partner.test", 443, "open")
		}, "a connection the Agent's record does not have"},
		{"the exit answered a request the Agent says no exit answered", func(r *records) {
			r.attempt(1, "api.partner.test", 443)
			r.exitSaw(r.de, "exit-de", 1, "r-agent1", 1, "api.partner.test", 443, "open")
			r.agent.Emit(events.ConnectionError, 1, "exits", 1, map[string]any{"error": "no exit answered"})
		}, "the Agent says no exit answered"},
	}
	for _, c := range cases {
		r := newRecords()
		c.build(r)
		rep := Join(r.ma.Snapshot(), r.mx.Snapshot())
		if rep.OK() || len(rep.Problems) != 1 || !strings.Contains(rep.Problems[0], c.want) {
			t.Errorf("%s: %+v", c.name, rep.Problems)
		}
	}
	if rep := Join(nil, nil); !rep.OK() || rep.Problems == nil {
		t.Errorf("empty: %+v", rep)
	}
}
