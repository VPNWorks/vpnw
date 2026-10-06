// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package exit

import (
	"fmt"
	"strconv"

	"vpnw.com/vpnw/internal/events"
)

// JoinRow is one connection seen from both ends.
type JoinRow struct {
	Run    string `json:"run"`
	Conn   uint64 `json:"conn"`
	Target string `json:"target"`
	Client string `json:"client,omitempty"`
	Exit   string `json:"exit,omitempty"` // the exit's name, from its record
	Agent  string `json:"agent"`          // what the Agent recorded
	AtExit string `json:"at_exit"`        // what the exit recorded
	OK     bool   `json:"ok"`
	Note   string `json:"note,omitempty"`
}

// JoinReport is what Join found.
type JoinReport struct {
	AgentRuns []string `json:"agent_runs"`
	ExitRuns  []string `json:"exit_runs"`
	// AgentConns is every connection in the Agent records. Of those, ViaExit
	// reached an exit that answered, and Local were decided or failed before
	// any exit answered.
	AgentConns int `json:"agent_connections"`
	ViaExit    int `json:"via_exit"`
	Local      int `json:"decided_at_agent"`
	// ExitConns is every connection in the exit records. Of those, Other
	// came from runs whose records were not given, or with no run ID at all,
	// a client talking to the exit without an Agent among them.
	ExitConns int `json:"exit_connections"`
	Other     int `json:"other_runs"`
	// Joined counts the Agent's connections that met exactly the record the
	// exit kept, with the same destination and the same outcome.
	Joined   int       `json:"joined"`
	Problems []string  `json:"problems"`
	Rows     []JoinRow `json:"rows"`
}

// OK reports whether every connection joined.
func (r *JoinReport) OK() bool { return len(r.Problems) == 0 && r.Joined == r.ViaExit }

type agentConn struct {
	run            string
	conn           uint64
	host, ip       string
	port           int64
	denied         bool
	exit           string // the exit that answered
	opened, failed bool
	err            string
	switches       int
}

type exitConn struct {
	run, exit         string // the exit's run and name
	conn              uint64
	client, clientRun string
	clientConn        uint64
	host, ip          string
	port              int64
	outcome           string // "open", "denied", "failed", or "" if the exit stopped first
	rule, reason, src string
	err               string
	matched           bool
}

func key(run string, conn uint64) string { return run + "/" + strconv.FormatUint(conn, 10) }

func target(host, ip string, port int64) string {
	h := host
	if h == "" {
		h = ip
	}
	return h + ":" + strconv.FormatInt(port, 10)
}

// Join matches the connections in an Agent's record (one run or several)
// with those in one or more exits' records, on the run and connection IDs
// the Agent sent with each request.
func Join(agent, exits []events.Event) JoinReport {
	var r JoinReport
	conns := map[string]*agentConn{}
	var order []*agentConn
	runs := map[string]bool{}
	for i := range agent {
		e := &agent[i]
		k := key(e.Run, e.Conn)
		if e.Type == events.RunStart && !runs[e.Run] {
			runs[e.Run] = true
			r.AgentRuns = append(r.AgentRuns, e.Run)
		}
		if e.Conn == 0 {
			continue
		}
		if e.Type == events.ConnectionAttempt {
			if !runs[e.Run] {
				runs[e.Run] = true
				r.AgentRuns = append(r.AgentRuns, e.Run)
			}
			c := &agentConn{run: e.Run, conn: e.Conn, host: e.Str("host"), ip: e.Str("ip"), port: e.Int("port")}
			conns[k] = c
			order = append(order, c)
			continue
		}
		c := conns[k]
		if c == nil {
			continue
		}
		switch e.Type {
		case events.PolicyDeny:
			c.denied = true
		case events.PathSwitch:
			c.switches++
		case events.ConnectionOpen:
			c.opened, c.exit = true, e.Str("exit")
		case events.ConnectionError:
			c.failed, c.err, c.exit = true, e.Str("error"), e.Str("exit")
		}
	}
	xs := map[string]*exitConn{}
	var xorder []*exitConn
	xruns := map[string]bool{}
	for i := range exits {
		e := &exits[i]
		if !xruns[e.Run] {
			xruns[e.Run] = true
			r.ExitRuns = append(r.ExitRuns, e.Path+" "+e.Run)
		}
		if e.Conn == 0 {
			continue
		}
		k := key(e.Run, e.Conn)
		if e.Type == events.ConnectionAttempt {
			x := &exitConn{run: e.Run, exit: e.Path, conn: e.Conn, client: e.Str("client"), clientRun: e.Str("client_run"),
				clientConn: uint64(e.Int("client_conn")), host: e.Str("host"), ip: e.Str("ip"), port: e.Int("port")}
			xs[k] = x
			xorder = append(xorder, x)
			continue
		}
		x := xs[k]
		if x == nil {
			continue
		}
		switch e.Type {
		case events.PolicyDeny:
			x.outcome, x.rule, x.reason = "denied", e.Str("rule"), e.Str("reason")
		case events.ConnectionOpen:
			x.outcome, x.src = "open", e.Str("source")
		case events.ConnectionError:
			x.outcome, x.err = "failed", e.Str("error")
		}
	}
	byClient := map[string][]*exitConn{}
	for _, x := range xorder {
		if x.clientRun != "" {
			byClient[key(x.clientRun, x.clientConn)] = append(byClient[key(x.clientRun, x.clientConn)], x)
		}
	}
	r.AgentConns, r.ExitConns = len(order), len(xorder)
	problem := func(format string, a ...any) string {
		p := fmt.Sprintf(format, a...)
		r.Problems = append(r.Problems, p)
		return p
	}
	for _, c := range order {
		recs := byClient[key(c.run, c.conn)]
		for _, x := range recs {
			x.matched = true
		}
		row := JoinRow{Run: c.run, Conn: c.conn, Target: target(c.host, c.ip, c.port), Agent: agentOutcome(c)}
		if c.exit == "" {
			// Decided at the Agent, or no exit answered. An exit may still
			// hold the start of a request it never answered.
			r.Local++
			for _, x := range recs {
				if x.outcome != "" {
					row.Note = problem("%s: the Agent says no exit answered, but %s recorded it (%s)", key(c.run, c.conn), x.exit, x.outcome)
				}
			}
			if row.Note == "" {
				continue
			}
			r.Rows = append(r.Rows, row)
			continue
		}
		r.ViaExit++
		var final *exitConn
		for _, x := range recs {
			if x.outcome != "" {
				final = x
			}
		}
		switch {
		case final == nil:
			row.Note = problem("%s to %s: the Agent reached exit %s, but no exit record has it", key(c.run, c.conn), row.Target, c.exit)
		default:
			row.Client, row.Exit, row.AtExit = final.client, final.exit, exitOutcome(final)
			switch {
			case final.port != c.port || (final.host != "" && c.host != "" && final.host != c.host) || (final.ip != "" && c.ip != "" && final.ip != c.ip):
				row.Note = problem("%s: the Agent asked for %s, the exit recorded %s", key(c.run, c.conn), row.Target, target(final.host, final.ip, final.port))
			case c.opened != (final.outcome == "open"):
				row.Note = problem("%s to %s: the Agent recorded %q, the exit %q", key(c.run, c.conn), row.Target, row.Agent, row.AtExit)
			default:
				row.OK = true
				r.Joined++
			}
		}
		r.Rows = append(r.Rows, row)
	}
	for _, x := range xorder {
		switch {
		case x.matched:
		case x.clientRun != "" && runs[x.clientRun]:
			problem("%s recorded %s from %s/%d, a connection the Agent's record does not have", x.exit, target(x.host, x.ip, x.port), x.clientRun, x.clientConn)
		default:
			r.Other++
			who := x.clientRun
			if who == "" {
				who = "no run ID"
			}
			r.Rows = append(r.Rows, JoinRow{Run: x.clientRun, Conn: x.clientConn, Target: target(x.host, x.ip, x.port), Client: x.client,
				Exit: x.exit, Agent: "not in these records (" + who + ")", AtExit: exitOutcome(x), OK: true})
		}
	}
	if r.Problems == nil {
		r.Problems = []string{}
	}
	return r
}

func agentOutcome(c *agentConn) string {
	switch {
	case c.denied:
		return "denied at the Agent"
	case c.opened:
		return "open"
	case c.failed:
		return "failed: " + c.err
	}
	return "no outcome"
}

func exitOutcome(x *exitConn) string {
	switch x.outcome {
	case "open":
		return "open from " + x.src
	case "denied":
		return "refused: " + x.rule
	case "failed":
		return "failed: " + x.err
	}
	return "no outcome (the exit stopped first)"
}
