// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"fmt"
	"io"
	"strings"
	"sync"

	"vpnw.com/vpnw/internal/events"
	"vpnw.com/vpnw/internal/exit"
)

// Text renders an exit's record for people, one line per event, with the
// client's name and IDs on each connection.
type Text struct {
	mu    sync.Mutex
	w     io.Writer
	Level events.Level
	// Local prints clock times in local time instead of UTC.
	Local bool
	notes map[uint64]string
}

// NewText writes to w: events.Decisions shows refusals, errors, the start
// and the summary; events.All shows every step.
func NewText(w io.Writer, level events.Level) *Text {
	return &Text{w: w, Level: level, notes: map[uint64]string{}}
}

// Emit renders one event.
func (t *Text) Emit(e *events.Event) {
	t.mu.Lock()
	defer t.mu.Unlock()
	line := t.render(e)
	if line == "" {
		return
	}
	ts := e.TS
	if t.Local {
		ts = ts.Local()
	}
	fmt.Fprintf(t.w, "vpnw-exit %s  %s\n", ts.Format("15:04:05.000"), line)
}

func dest(e *events.Event) string {
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
	all := t.Level >= events.All
	dec := t.Level >= events.Decisions
	id := fmt.Sprintf("#%d", e.Conn)
	note := t.notes[e.Conn]
	switch e.Type {
	case events.RunStart:
		if !dec {
			return ""
		}
		return fmt.Sprintf("%s %s on %s  run %s  %d clients", e.Path, e.Str("version"), e.Str("listen"), e.Run, e.Int("clients"))
	case events.ConnectionAttempt:
		who := e.Str("client")
		if r := e.Str("client_run"); r != "" {
			who += fmt.Sprintf(" %s/%d", r, e.Int("client_conn"))
		}
		t.notes[e.Conn] = who + "  " + dest(e)
		if !all {
			return ""
		}
		return fmt.Sprintf("%-4s   %s  -> %s  %s", id, who, dest(e), e.Str("proto"))
	case events.PolicyAllow:
		if !all {
			return ""
		}
		return fmt.Sprintf("%-4s   allow  %s  %s", id, note, e.Str("rule"))
	case events.PolicyDeny:
		if !dec {
			return ""
		}
		return fmt.Sprintf("%-4s   DENY   %s  %s: %s", id, note, e.Str("rule"), e.Str("reason"))
	case events.DNSResult:
		if !all && e.Str("error") == "" {
			return ""
		}
		if err := e.Str("error"); err != "" {
			return fmt.Sprintf("%-4s   dns %s failed: %s", id, e.Str("host"), err)
		}
		return fmt.Sprintf("%-4s   dns %s = %v", id, e.Str("host"), e.Fields["ips"])
	case events.ConnectionOpen:
		if !all {
			return ""
		}
		return fmt.Sprintf("%-4s   open   %s from %s  (%d ms)", id, e.Str("ip"), e.Str("source"), e.Int("ms"))
	case events.ConnectionClose:
		delete(t.notes, e.Conn)
		if !all {
			return ""
		}
		return fmt.Sprintf("%-4s   close  sent %s  received %s  %s", id,
			events.HumanBytes(e.Int("bytes_up")), events.HumanBytes(e.Int("bytes_down")), events.HumanDuration(e.Int("ms")))
	case events.ConnectionError:
		if !dec {
			return ""
		}
		return fmt.Sprintf("%-4s   error  %s: %s", id, note, e.Str("error"))
	case exit.AuthDeny:
		if !dec {
			return ""
		}
		return fmt.Sprintf("refused a client at %s (%s): %s", e.Str("peer"), e.Str("proto"), e.Str("reason"))
	case events.RunEnd:
		return fmt.Sprintf("summary  %d connections: %d opened, %d denied, %d failed; %d refused for a missing or unknown token; sent %s, received %s",
			e.Int("connections"), e.Int("opened"), e.Int("denied"), e.Int("failed"), e.Int("auth_denied"),
			events.HumanBytes(e.Int("bytes_up")), events.HumanBytes(e.Int("bytes_down")))
	}
	return ""
}
