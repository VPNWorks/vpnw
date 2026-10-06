// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package events

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"time"
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
	// Local prints clock times in local time instead of UTC.
	Local bool

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

// HumanBytes prints 1234 as "1.2 KB".
func HumanBytes(n int64) string {
	switch {
	case n < 1000:
		return fmt.Sprintf("%d B", n)
	case n < 1000*1000:
		return fmt.Sprintf("%.1f KB", float64(n)/1000)
	case n < 1000*1000*1000:
		return fmt.Sprintf("%.1f MB", float64(n)/1e6)
	}
	return fmt.Sprintf("%.2f GB", float64(n)/1e9)
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
func (t *Text) Emit(e *Event) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if e.Type == ConnectionAttempt {
		t.hosts[e.Conn] = target(e)
	}
	line := t.render(e)
	if line == "" {
		return
	}
	ts := e.TS
	if t.Local {
		ts = ts.Local()
	}
	fmt.Fprintf(t.w, "%s %s  %s\n", t.c(bold, "vpnw"), t.c(dim, ts.Format("15:04:05.000")), line)
}

func target(e *Event) string {
	h := e.Str("host")
	if h == "" {
		h = e.Str("ip")
		if strings.Contains(h, ":") {
			h = "[" + h + "]"
		}
	}
	return fmt.Sprintf("%s:%d", h, e.Int("port"))
}

func (t *Text) render(e *Event) string {
	all := t.Level >= All
	dec := t.Level >= Decisions
	id := fmt.Sprintf("#%d", e.Conn)
	switch e.Type {
	case RunStart:
		if !dec {
			return ""
		}
		parts := []string{e.Str("mode"), "run " + e.Run, "path " + e.Path}
		if b := e.Str("backend"); b != "" {
			parts = append(parts, "backend "+b)
		}
		if pol, ok := e.Fields["policy"].(map[string]any); ok {
			parts = append(parts, fmt.Sprintf("policy %v (default %v, %v allow rules, %v deny rules, deny_private %v)",
				pol["name"], pol["default"], pol["allow_rules"], pol["deny_rules"], pol["deny_private"]))
		}
		return strings.Join(parts, "  ")
	case ProcessStart:
		if !all {
			return ""
		}
		return fmt.Sprintf("start  pid %d  %s", e.PID, e.Str("cmd"))
	case ProcessExit:
		if !dec {
			return ""
		}
		how := fmt.Sprintf("code %d", e.Int("code"))
		if s := e.Str("signal"); s != "" {
			how = "killed by " + s
		}
		return fmt.Sprintf("exit   pid %d  %s  after %s", e.PID, how, HumanDuration(e.Int("ms")))
	case DNSQuery:
		if !all {
			return ""
		}
		return fmt.Sprintf("%-4s   dns %s", id, e.Str("host"))
	case DNSResult:
		if !all && e.Str("error") == "" {
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
	case ConnectionAttempt:
		if !all {
			return ""
		}
		return fmt.Sprintf("%-4s → %s  %s", id, target(e), t.c(dim, e.Str("proto")))
	case PolicyAllow:
		if !all && !(dec && t.ShowAllows) {
			return ""
		}
		return fmt.Sprintf("%-4s   %s  %s  %s", id, t.c(green, "allow"), t.hosts[e.Conn], t.c(dim, ruleLabel(e)))
	case PolicyDeny:
		if !dec {
			return ""
		}
		return fmt.Sprintf("%-4s   %s  %s  %s", id, t.c(red+bold, "DENY "), t.hosts[e.Conn], e.Str("reason"))
	case ConnectionOpen:
		if !all {
			return ""
		}
		where := e.Str("ip")
		if where == "" {
			where = "exit resolves " + e.Str("host")
		}
		via := e.Path
		if x := e.Str("exit"); x != "" {
			via += " (exit " + x + ")"
		}
		return fmt.Sprintf("%-4s   open  %s via %s  (%d ms)", id, where, via, e.Int("ms"))
	case ConnectionClose:
		if !all {
			return ""
		}
		return fmt.Sprintf("%-4s   close  sent %s  received %s  %s", id,
			HumanBytes(e.Int("bytes_up")), HumanBytes(e.Int("bytes_down")), HumanDuration(e.Int("ms")))
	case ConnectionError:
		if !dec {
			return ""
		}
		return fmt.Sprintf("%-4s   %s  %s: %s", id, t.c(red, "error"), t.hosts[e.Conn], e.Str("error"))
	case PathSwitch:
		if !dec {
			return ""
		}
		return fmt.Sprintf("%-4s   %s  exit %s stopped answering after %s (%s); moving to %s", id, t.c(bold, "switch"),
			e.Str("from"), HumanDuration(e.Int("ms")), e.Str("error"), e.Str("to"))
	case RunEnd:
		n := e.Int("connections")
		noun := "connections"
		if n == 1 {
			noun = "connection"
		}
		return fmt.Sprintf("summary  %d %s: %d opened, %d denied, %d failed  sent %s  received %s",
			n, noun, e.Int("opened"), e.Int("denied"), e.Int("failed"),
			HumanBytes(e.Int("bytes_up")), HumanBytes(e.Int("bytes_down")))
	}
	return ""
}

func ruleLabel(e *Event) string {
	r := e.Str("rule")
	if txt := e.Str("text"); txt != "" {
		return fmt.Sprintf("%s %q", r, txt)
	}
	if r == "default" {
		return "default allow"
	}
	return r
}

// Since returns whole milliseconds since t.
func Since(t time.Time, now time.Time) int64 { return now.Sub(t).Milliseconds() }
