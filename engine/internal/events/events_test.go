// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package events

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func TestJSONLRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	b := NewBus("r-abc", func() time.Time { return time.Date(2026, 9, 29, 10, 0, 0, 5e6, time.UTC) })
	j := NewJSONL(&buf)
	b.Add(j)
	b.Emit(ConnectionAttempt, 42, "office", 7, map[string]any{"host": "tracker.office.internal", "port": 443, "proto": "socks5"})
	b.Emit(ConnectionClose, 42, "office", 7, map[string]any{"bytes_up": int64(1200), "bytes_down": int64(35000), "ms": int64(80)})
	j.Close()
	line := strings.SplitN(buf.String(), "\n", 2)[0]
	want := `{"v":1,"ts":"2026-09-29T10:00:00.005Z","type":"connection.attempt","run":"r-abc","pid":42,"path":"office","conn":7,"fields":{"host":"tracker.office.internal","port":443,"proto":"socks5"}}`
	if line != want {
		t.Errorf("line\n got %s\nwant %s", line, want)
	}
	evs, err := Read(&buf)
	if err != nil || len(evs) != 2 {
		t.Fatalf("read: %v %d", err, len(evs))
	}
	if evs[1].Int("bytes_down") != 35000 || evs[0].Str("host") != "tracker.office.internal" || evs[0].Int("port") != 443 {
		t.Errorf("fields: %+v", evs)
	}
	if b.Count(ConnectionAttempt) != 1 {
		t.Error("count")
	}
}

func TestReadErrors(t *testing.T) {
	for _, in := range []string{"{not json}\n", `{"v":2,"type":"x"}` + "\n", `{"v":1}` + "\n"} {
		if _, err := Read(strings.NewReader(in)); err == nil {
			t.Errorf("%q: want error", in)
		}
	}
	if evs, err := Read(strings.NewReader("\n\n")); err != nil || len(evs) != 0 {
		t.Errorf("blank lines: %v", err)
	}
}

func TestTextLevels(t *testing.T) {
	var all, dec bytes.Buffer
	b := NewBus("r-1", nil)
	b.Add(NewText(&all, All))
	b.Add(NewText(&dec, Decisions))
	b.Emit(ConnectionAttempt, 1, "direct", 1, map[string]any{"host": "a.example", "port": 443, "proto": "http-connect"})
	b.Emit(PolicyAllow, 1, "direct", 1, map[string]any{"rule": "allow[0]", "text": "a.example", "reason": "x"})
	b.Emit(ConnectionAttempt, 1, "direct", 2, map[string]any{"host": "b.example", "port": 443, "proto": "http-connect"})
	b.Emit(PolicyDeny, 1, "direct", 2, map[string]any{"rule": "default", "reason": "no allow rule matches b.example:443"})
	if strings.Count(all.String(), "\n") != 4 {
		t.Errorf("all:\n%s", all.String())
	}
	if strings.Count(dec.String(), "\n") != 1 || !strings.Contains(dec.String(), "DENY") || !strings.Contains(dec.String(), "b.example:443") {
		t.Errorf("decisions:\n%s", dec.String())
	}
}

// A switch between exits is a decision-level line; an open through an exit
// names it.
func TestTextExits(t *testing.T) {
	var all, dec bytes.Buffer
	b := NewBus("r-1", nil)
	b.Add(NewText(&all, All))
	b.Add(NewText(&dec, Decisions))
	b.Emit(ConnectionAttempt, 1, "exits", 4, map[string]any{"host": "api.partner.test", "port": 443, "proto": "http-connect"})
	b.Emit(PathSwitch, 1, "exits", 4, map[string]any{"from": "198.51.100.2:8443", "to": "203.0.113.2:8443", "error": "proxy 198.51.100.2:8443: connection refused", "ms": 1})
	b.Emit(ConnectionOpen, 1, "exits", 4, map[string]any{"host": "api.partner.test", "ms": 9, "exit": "203.0.113.2:8443"})
	want := "switch  exit 198.51.100.2:8443 stopped answering after 1 ms (proxy 198.51.100.2:8443: connection refused); moving to 203.0.113.2:8443"
	if !strings.Contains(dec.String(), want) || strings.Count(dec.String(), "\n") != 1 {
		t.Errorf("decisions:\n%s", dec.String())
	}
	if !strings.Contains(all.String(), "open  exit resolves api.partner.test via exits (exit 203.0.113.2:8443)  (9 ms)") {
		t.Errorf("all:\n%s", all.String())
	}
	found := false
	for _, typ := range Types {
		found = found || typ == PathSwitch
	}
	if !found {
		t.Error("path.switch is missing from Types")
	}
}

func TestHumanBytes(t *testing.T) {
	for n, want := range map[int64]string{0: "0 B", 999: "999 B", 1000: "1.0 KB", 1234567: "1.2 MB", 3e9: "3.00 GB"} {
		if got := HumanBytes(n); got != want {
			t.Errorf("%d: %s", n, got)
		}
	}
}
