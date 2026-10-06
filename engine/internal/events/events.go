// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

// Package events is VPNW's shared event model. Run, Trace, Guard and Learn
// all speak it: the engine produces events, sinks render or store them, and
// Learn reads them back.
//
// Events describe decisions, not payloads. They never carry application
// data, URL paths, headers, environment variables or proxy passwords.
package events

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"vpnw.com/vpnw/internal/version"
)

// Event types, schema version 1.
const (
	RunStart          = "run.start"
	RunEnd            = "run.end"
	ProcessStart      = "process.start"
	ProcessExit       = "process.exit"
	DNSQuery          = "dns.query"
	DNSResult         = "dns.result"
	ConnectionAttempt = "connection.attempt"
	ConnectionOpen    = "connection.open"
	ConnectionClose   = "connection.close"
	ConnectionError   = "connection.error"
	PolicyAllow       = "policy.allow"
	PolicyDeny        = "policy.deny"
	// PathSwitch: a list of exits gave up on the exit in use and moved to
	// the next one while opening a connection (Agent 0.2.0).
	PathSwitch = "path.switch"
)

// Types lists every event type in schema version 1.
var Types = []string{RunStart, ProcessStart, DNSQuery, DNSResult, ConnectionAttempt,
	PolicyAllow, PolicyDeny, PathSwitch, ConnectionOpen, ConnectionClose, ConnectionError, ProcessExit, RunEnd}

// Event is one line of a trace.
type Event struct {
	V      int            `json:"v"`
	TS     time.Time      `json:"ts"`
	Type   string         `json:"type"`
	Run    string         `json:"run"`
	PID    int            `json:"pid,omitempty"`
	Path   string         `json:"path,omitempty"`
	Conn   uint64         `json:"conn,omitempty"`
	Fields map[string]any `json:"fields,omitempty"`
}

// Sink receives events. Emit must not keep e after it returns.
type Sink interface {
	Emit(e *Event)
}

// Bus stamps events and hands them to every sink, one at a time and in order.
type Bus struct {
	mu     sync.Mutex
	run    string
	clock  func() time.Time
	sinks  []Sink
	counts map[string]int
}

// NewBus makes a bus for one run. clock may be nil for time.Now.
func NewBus(run string, clock func() time.Time) *Bus {
	if clock == nil {
		clock = time.Now
	}
	return &Bus{run: run, clock: clock, counts: map[string]int{}}
}

// Run is the run identifier stamped on every event.
func (b *Bus) Run() string { return b.run }

// Add attaches a sink.
func (b *Bus) Add(s Sink) {
	b.mu.Lock()
	b.sinks = append(b.sinks, s)
	b.mu.Unlock()
}

// Emit stamps and delivers one event.
func (b *Bus) Emit(typ string, pid int, path string, conn uint64, fields map[string]any) {
	if b == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	e := &Event{V: version.Schema, TS: b.clock().UTC(), Type: typ, Run: b.run, PID: pid, Path: path, Conn: conn, Fields: fields}
	b.counts[typ]++
	for _, s := range b.sinks {
		s.Emit(e)
	}
}

// Count returns how many events of a type were emitted.
func (b *Bus) Count(typ string) int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.counts[typ]
}

// Counts returns a copy of all counters.
func (b *Bus) Counts() map[string]int {
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make(map[string]int, len(b.counts))
	for k, v := range b.counts {
		out[k] = v
	}
	return out
}

// JSONL writes one JSON object per line.
type JSONL struct {
	mu  sync.Mutex
	w   *bufio.Writer
	c   io.Closer
	err error
}

// NewJSONL writes to w. If w is an io.Closer, Close closes it.
func NewJSONL(w io.Writer) *JSONL {
	j := &JSONL{w: bufio.NewWriterSize(w, 32<<10)}
	if c, ok := w.(io.Closer); ok && w != os.Stdout && w != os.Stderr {
		j.c = c
	}
	return j
}

// Emit writes the event and flushes it, so a crash never leaves half a line.
func (j *JSONL) Emit(e *Event) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.err != nil {
		return
	}
	b, err := json.Marshal(e)
	if err != nil {
		j.err = err
		return
	}
	b = append(b, '\n')
	if _, err := j.w.Write(b); err != nil {
		j.err = err
		return
	}
	j.err = j.w.Flush()
}

// Close flushes and closes the underlying file.
func (j *JSONL) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if err := j.w.Flush(); err != nil && j.err == nil {
		j.err = err
	}
	if j.c != nil {
		if err := j.c.Close(); err != nil && j.err == nil {
			j.err = err
		}
	}
	return j.err
}

// Memory keeps events in a slice, for tests and the browser build.
type Memory struct {
	mu     sync.Mutex
	Events []Event
}

// Emit stores a copy.
func (m *Memory) Emit(e *Event) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := *e
	if e.Fields != nil {
		c.Fields = make(map[string]any, len(e.Fields))
		for k, v := range e.Fields {
			c.Fields[k] = v
		}
	}
	m.Events = append(m.Events, c)
}

// Snapshot returns a copy of the stored events.
func (m *Memory) Snapshot() []Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]Event(nil), m.Events...)
}

// Filter passes only some event types to the next sink.
type Filter struct {
	Next  Sink
	Types map[string]bool
}

// Emit forwards the event if its type is wanted.
func (f *Filter) Emit(e *Event) {
	if f.Types[e.Type] {
		f.Next.Emit(e)
	}
}

// Read parses a JSONL trace. Blank lines are skipped; a line that is not a
// valid event is an error with its line number.
func Read(r io.Reader) ([]Event, error) {
	var out []Event
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	line := 0
	for sc.Scan() {
		line++
		t := strings.TrimSpace(sc.Text())
		if t == "" {
			continue
		}
		var e Event
		dec := json.NewDecoder(strings.NewReader(t))
		dec.UseNumber()
		if err := dec.Decode(&e); err != nil {
			return nil, fmt.Errorf("line %d: not a valid event: %v", line, err)
		}
		if e.V != version.Schema {
			return nil, fmt.Errorf("line %d: event schema v%d; this engine reads v%d", line, e.V, version.Schema)
		}
		if e.Type == "" {
			return nil, fmt.Errorf("line %d: event has no type", line)
		}
		out = append(out, e)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// Str reads a string field.
func (e *Event) Str(k string) string {
	if v, ok := e.Fields[k]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}

// Int reads a numeric field written by this engine or parsed from JSON.
func (e *Event) Int(k string) int64 {
	switch v := e.Fields[k].(type) {
	case int:
		return int64(v)
	case int64:
		return v
	case uint64:
		return int64(v)
	case float64:
		return int64(v)
	case json.Number:
		n, _ := v.Int64()
		return n
	}
	return 0
}

// Bool reads a boolean field.
func (e *Event) Bool(k string) bool {
	b, _ := e.Fields[k].(bool)
	return b
}

// SortedKeys returns field names in order, for stable text output.
func SortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
