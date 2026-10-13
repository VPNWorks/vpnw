// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package pluginhost

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/VPNWorks/vpnw/internal/events"
	"github.com/VPNWorks/vpnw/internal/version"
)

// QueueLen is how many events an Observer may fall behind by before events
// are dropped for it.
const QueueLen = 8192

// EventsLost is the type of the event a Sink hands its Observer where events
// were dropped because it fell behind; its field "count" says how many. It
// goes to that Observer only, never into the run's record.
const EventsLost = "events.lost"

// Sink feeds a run's events to an Observer plugin. It never blocks the
// event bus: events are queued and handed over by a goroutine of its own,
// in order, and dropped (and counted) if the plugin falls too far behind.
type Sink struct {
	in      *Instance
	own     string // the prefix of the plugin's own events
	onFail  func(name string, err error)
	ch      chan queued
	done    chan struct{}
	ctx     context.Context // cancelled to cut short a call in flight
	cancel  context.CancelFunc
	mu      sync.RWMutex
	closed  bool
	failed  atomic.Bool
	dropped atomic.Int64
	pending atomic.Int64 // drops not yet attached to a queued event
}

// queued is an event waiting for the plugin, with the number of events
// dropped just before it.
type queued struct {
	b    []byte
	lost int64
}

// NewSink starts handing events to in. onFail, if not nil, is called once,
// from the Sink's goroutine, if the plugin fails.
func NewSink(in *Instance, onFail func(name string, err error)) *Sink {
	s := &Sink{in: in, own: "plugin." + in.Name() + ".", onFail: onFail, ch: make(chan queued, QueueLen), done: make(chan struct{})}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	go s.loop()
	return s
}

// Name is the plugin's name.
func (s *Sink) Name() string { return s.in.Name() }

// Emit queues one event. It implements events.Sink. A plugin's own events
// are not handed back to it, so an Observer that emits for each event it
// gets cannot feed itself forever.
func (s *Sink) Emit(e *events.Event) {
	if s.failed.Load() || strings.HasPrefix(e.Type, s.own) {
		return
	}
	b, err := json.Marshal(e)
	if err != nil {
		return
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return
	}
	// Emit is called by the bus one event at a time, so the drops before
	// this event are exactly those pending now.
	lost := s.pending.Swap(0)
	select {
	case s.ch <- queued{b, lost}:
	default:
		s.pending.Add(lost + 1)
		s.dropped.Add(1)
	}
}

func (s *Sink) loop() {
	defer close(s.done)
	for q := range s.ch {
		if s.failed.Load() {
			continue
		}
		s.tellLost(q.lost)
		if s.failed.Load() {
			continue
		}
		if err := s.in.Event(s.ctx, q.b); err != nil {
			s.fail(err)
		}
	}
	// Drops after the last event that was queued.
	if !s.failed.Load() {
		s.tellLost(s.pending.Swap(0))
	}
}

// tellLost hands the plugin an EventsLost event for n events dropped, in
// the place where they were dropped: after the event it had last, before
// the one it gets next.
func (s *Sink) tellLost(n int64) {
	if n <= 0 {
		return
	}
	b, _ := json.Marshal(events.Event{V: version.Schema, TS: time.Now().UTC(), Type: EventsLost, Run: s.in.opt.Run,
		Fields: map[string]any{"count": n}})
	if err := s.in.Event(s.ctx, b); err != nil {
		s.fail(err)
	}
}

func (s *Sink) fail(err error) {
	if s.failed.CompareAndSwap(false, true) && s.onFail != nil {
		s.onFail(s.in.Name(), err)
	}
}

// Close waits up to grace for the queued events to be handed over, calls
// the plugin's Finish, and stops it. It returns how many events the plugin
// lost and the plugin's failure, if any.
func (s *Sink) Close(grace time.Duration) (dropped int64, err error) {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return s.dropped.Load(), s.in.Err()
	}
	s.closed = true
	close(s.ch)
	s.mu.Unlock()
	select {
	case <-s.done:
		if !s.failed.Load() {
			if err := s.in.Finish(context.Background()); err != nil {
				s.fail(err)
			}
		}
	case <-time.After(grace):
		s.fail(errBehind)
		s.in.stop(errBehind)
		// Cut short the call in flight and wait for the loop to leave the
		// plugin before closing it: closing a module while a call is still
		// running in it is a data race.
		s.cancel()
		<-s.done
	}
	s.cancel()
	s.in.Close()
	return s.dropped.Load(), s.in.Err()
}

var errBehind = errorString("was still working through the run's events when it ended")

type errorString string

func (e errorString) Error() string { return string(e) }
