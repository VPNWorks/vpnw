// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package render

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/VPNWorks/vpnw/internal/events"
)

// Level says how much the text sink prints.
type Level int

const (
	// Quiet prints the run summary only.
	Quiet Level = iota
	// Decisions prints denials, errors and the summary (guard's default).
	Decisions
	// All prints every event (trace).
	All
)

// Text renders events for people, one line each, on a terminal or a log.
type Text struct {
	mu    sync.Mutex
	w     io.Writer
	Level Level
	Color bool
	// ShowAllows prints policy.allow lines at the Decisions level.
	ShowAllows bool
	// Zone, if set, prints clock times in that zone instead of UTC. A plugin
	// has no time zone database, so the host passes the offset.
	Zone *time.Location

	hosts map[uint64]string
}

// NewText writes to w at the given level.
func NewText(w io.Writer, level Level) *Text {
	return &Text{w: w, Level: level, hosts: map[uint64]string{}}
}

const (
	red   = "\x1b[31m"
	green = "\x1b[32m"
	dim   = "\x1b[2m"
	bold  = "\x1b[1m"
	reset = "\x1b[0m"
)

func (t *Text) c(code, s string) string {
	if !t.Color {
		return s
	}
	return code + s + reset
}

// HumanDuration prints milliseconds compactly.
func HumanDuration(ms int64) string {
	switch {
	case ms < 1000:
		return fmt.Sprintf("%d ms", ms)
	case ms < 60000:
		return fmt.Sprintf("%.1f s", float64(ms)/1000)
	}
	return fmt.Sprintf("%dm%02ds", ms/60000, (ms/1000)%60)
}

// Emit renders one event.
func (t *Text) Emit(e *events.Event) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if e.Type == events.ConnectionAttempt {
		t.hosts[e.Conn] = target(e)
		if c := e.Str("client"); c != "" {
			// At an exit, every line of a connection names the client.
			t.hosts[e.Conn] = c + " → " + target(e)
		}
	}
	line := t.render(e)
	switch e.Type {
	case events.ConnectionClose, events.ConnectionError, events.PolicyDeny:
		// A connection's last event: the console stops remembering it, so a
		// long run, or an exit, doesn't pile them up.
		delete(t.hosts, e.Conn)
	}
	if line == "" {
		return
	}
	ts := e.TS
	if t.Zone != nil {
		ts = ts.In(t.Zone)
	}
	// An event can take more than one line, each printed as its own.
	for _, l := range strings.Split(line, "\n") {
		fmt.Fprintf(t.w, "%s %s  %s\n", t.c(bold, "vpnw"), t.c(dim, ts.Format("15:04:05.000")), l)
	}
}

func target(e *events.Event) string {
	h := e.Str("host")
	if h == "" {
		h = e.Str("ip")
		if strings.Contains(h, ":") {
			h = "[" + h + "]"
		}
	}
	return fmt.Sprintf("%s:%d", h, e.Int("port"))
}

func (t *Text) render(e *events.Event) string {
	all := t.Level >= All
	dec := t.Level >= Decisions
	id := fmt.Sprintf("#%d", e.Conn)
	switch e.Type {
	case events.RunStart:
		if !dec {
			return ""
		}
		if e.Str("mode") == "exit" {
			n := e.Int("clients")
			noun := "clients"
			if n == 1 {
				noun = "client"
			}
			return fmt.Sprintf("exit %s  run %s  listening on %s  %d %s  certificate for %s until %s",
				e.Str("exit"), e.Run, e.Str("listen"), n, noun, e.Str("cert_for"), e.Str("cert_until"))
		}
		parts := []string{e.Str("mode"), "run " + e.Run, "path " + e.Path}
		tn, _ := e.Fields["tunnel"].(map[string]any)
		if tn != nil {
			x := fmt.Sprintf("tunnel %v from %v", tn["config"], tn["plugin"])
			if k := number(tn["keep"]); k > 0 {
				x += ", kept " + HumanDuration(k*1000)
			}
			parts = append(parts, x)
		}
		if b := e.Str("backend"); b != "" {
			parts = append(parts, "backend "+b)
		}
		if pol, ok := e.Fields["policy"].(map[string]any); ok {
			parts = append(parts, fmt.Sprintf("policy %v (default %v, %v allow rules, %v deny rules, deny_private %v)",
				pol["name"], pol["default"], pol["allow_rules"], pol["deny_rules"], pol["deny_private"]))
		}
		line := strings.Join(parts, "  ")
		// The configs the tunnel plugin handed over that weren't used.
		skipped, _ := tn["skipped"].([]any)
		for _, x := range skipped {
			if m, ok := x.(map[string]any); ok {
				line += fmt.Sprintf("\n%s  skipped %v: %v", t.c(bold, "tunnel"), m["config"], m["error"])
			}
		}
		return line
	case events.ProcessStart:
		if !all {
			return ""
		}
		return fmt.Sprintf("start  pid %d  %s", e.PID, e.Str("cmd"))
	case events.ProcessExit:
		if !dec {
			return ""
		}
		how := fmt.Sprintf("code %d", e.Int("code"))
		if s := e.Str("signal"); s != "" {
			how = "killed by " + s
		}
		return fmt.Sprintf("exit   pid %d  %s  after %s", e.PID, how, HumanDuration(e.Int("ms")))
	case events.DNSQuery:
		if !all {
			return ""
		}
		return fmt.Sprintf("%-4s   dns %s", id, e.Str("host"))
	case events.DNSResult:
		if !dec || (!all && e.Str("error") == "") {
			return ""
		}
		if err := e.Str("error"); err != "" {
			return fmt.Sprintf("%-4s   dns %s failed: %s", id, e.Str("host"), err)
		}
		ips, _ := e.Fields["ips"].([]any)
		var list []string
		for _, ip := range ips {
			list = append(list, fmt.Sprint(ip))
		}
		if l, ok := e.Fields["ips"].([]string); ok {
			list = l
		}
		return fmt.Sprintf("%-4s   dns %s = %s  (%d ms)", id, e.Str("host"), strings.Join(list, ", "), e.Int("ms"))
	case events.ConnectionAttempt:
		if !all {
			return ""
		}
		if c := e.Str("client"); c != "" {
			line := fmt.Sprintf("%-4s %s → %s  %s", id, c, target(e), t.c(dim, e.Str("proto")))
			if r := e.Str("client_run"); r != "" {
				line += t.c(dim, fmt.Sprintf("  its run %s #%d", r, e.Int("client_conn")))
			}
			return line
		}
		return fmt.Sprintf("%-4s → %s  %s", id, target(e), t.c(dim, e.Str("proto")))
	case events.PolicyAllow:
		if !all && !(dec && t.ShowAllows) {
			return ""
		}
		return fmt.Sprintf("%-4s   %s  %s  %s", id, t.c(green, "allow"), t.hosts[e.Conn], t.c(dim, ruleLabel(e)))
	case events.PolicyDeny:
		if !dec {
			return ""
		}
		return fmt.Sprintf("%-4s   %s  %s  %s", id, t.c(red+bold, "DENY "), t.hosts[e.Conn], e.Str("reason"))
	case events.ConnectionOpen:
		if !all {
			return ""
		}
		where := e.Str("ip")
		if where == "" {
			where = "exit resolves " + e.Str("host")
		}
		if src := e.Str("source"); src != "" {
			return fmt.Sprintf("%-4s   open  %s from %s  (%d ms)", id, where, src, e.Int("ms"))
		}
		via := e.Path
		var how []string
		if tn := e.Str("tunnel"); tn != "" {
			how = append(how, tn)
		}
		if x := e.Str("exit"); x != "" {
			how = append(how, "exit "+x)
		}
		if len(how) > 0 {
			via += " (" + strings.Join(how, ", ") + ")"
		}
		return fmt.Sprintf("%-4s   open  %s via %s  (%d ms)", id, where, via, e.Int("ms"))
	case events.ConnectionClose:
		if !all {
			return ""
		}
		return fmt.Sprintf("%-4s   close  sent %s  received %s  %s", id,
			events.HumanBytes(e.Int("bytes_up")), events.HumanBytes(e.Int("bytes_down")), HumanDuration(e.Int("ms")))
	case events.ConnectionError:
		if !dec {
			return ""
		}
		return fmt.Sprintf("%-4s   %s  %s: %s", id, t.c(red, "error"), t.hosts[e.Conn], e.Str("error"))
	case events.PathSwitch:
		if !dec {
			return ""
		}
		return fmt.Sprintf("%-4s   %s  exit %s stopped answering after %s (%s); moving to %s", id, t.c(bold, "switch"),
			e.Str("from"), HumanDuration(e.Int("ms")), e.Str("error"), e.Str("to"))
	case events.TunnelSwitch:
		if !dec {
			return ""
		}
		up := fmt.Sprintf("%s up in %s", e.Str("to"), HumanDuration(e.Int("ms")))
		if p := e.Str("peer"); p != "" {
			up += " (peer " + p + ")"
		}
		if e.Str("why") == "failed" {
			return fmt.Sprintf("%s  %s stopped answering (%s); moved to %s", t.c(bold, "tunnel"), e.Str("from"), e.Str("error"), up)
		}
		return fmt.Sprintf("%s  rotated from %s to %s", t.c(bold, "tunnel"), e.Str("from"), up)
	case events.TunnelError:
		if !dec {
			return ""
		}
		if c := e.Str("config"); c != "" {
			return fmt.Sprintf("%s  %s not used: %s", t.c(red, "tunnel"), c, e.Str("error"))
		}
		return fmt.Sprintf("%s  %s", t.c(red, "tunnel"), e.Str("error"))
	case events.TunnelClose:
		if !all {
			return ""
		}
		if n := e.Int("cut"); n > 0 {
			return fmt.Sprintf("%s  %s closed with %d connections still open: too many tunnels were winding down", t.c(bold, "tunnel"), e.Str("config"), n)
		}
		return fmt.Sprintf("%s  %s closed after its last connection", t.c(bold, "tunnel"), e.Str("config"))
	case events.AuthDeny:
		if !dec {
			return ""
		}
		line := fmt.Sprintf("%s  %s  %s  %s", t.c(red+bold, "REFUSED"), e.Str("peer"), e.Str("proto"), e.Str("reason"))
		if e.Str("host") != "" || e.Str("ip") != "" {
			line += "  (asked for " + target(e) + ")"
		}
		return line
	case events.PluginError:
		if !dec {
			return ""
		}
		return fmt.Sprintf("%s  %s plugin %s stopped: %s", t.c(red, "plugin"), e.Str("type"), e.Str("plugin"), e.Str("error"))
	case events.RunEnd:
		n := e.Int("connections")
		noun := "connections"
		if n == 1 {
			noun = "connection"
		}
		line := fmt.Sprintf("summary  %d %s: %d opened, %d denied, %d failed  sent %s  received %s",
			n, noun, e.Int("opened"), e.Int("denied"), e.Int("failed"),
			events.HumanBytes(e.Int("bytes_up")), events.HumanBytes(e.Int("bytes_down")))
		if a := e.Int("auth_denied"); a > 0 {
			noun := "requests"
			if a == 1 {
				noun = "request"
			}
			line += fmt.Sprintf("  %d %s without a valid token", a, noun)
		}
		return line
	}
	if strings.HasPrefix(e.Type, "plugin.") && all {
		var kv []string
		for _, k := range events.SortedKeys(e.Fields) {
			kv = append(kv, fmt.Sprintf("%s=%v", k, e.Fields[k]))
		}
		line := e.Type
		if e.Conn != 0 {
			line = fmt.Sprintf("%-4s   %s", id, line)
		}
		return strings.TrimSpace(line + "  " + strings.Join(kv, " "))
	}
	return ""
}

// number reads a number from a nested field, as JSON or Go left it.
func number(v any) int64 {
	switch x := v.(type) {
	case float64:
		return int64(x)
	case int64:
		return x
	case int:
		return int64(x)
	case interface{ Int64() (int64, error) }:
		n, _ := x.Int64()
		return n
	}
	return 0
}

func ruleLabel(e *events.Event) string {
	r := e.Str("rule")
	if txt := e.Str("text"); txt != "" {
		return fmt.Sprintf("%s %q", r, txt)
	}
	if r == "default" {
		return "default allow"
	}
	return r
}
