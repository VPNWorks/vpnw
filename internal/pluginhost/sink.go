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
)

// QueueLen is how many events an Observer may fall behind by before events
// are dropped for it.
const QueueLen = 8192

// Sink feeds a run's events to an Observer plugin. It never blocks the
// event bus: events are queued and handed over by a goroutine of its own,
// in order, and dropped (and counted) if the plugin falls too far behind.
type Sink struct {
	in      *Instance
	own     string // the prefix of the plugin's own events
	onFail  func(name string, err error)
	ch      chan []byte
	done    chan struct{}
	mu      sync.RWMutex
	closed  bool
	failed  atomic.Bool
	dropped atomic.Int64
}

// NewSink starts handing events to in. onFail, if not nil, is called once,
// from the Sink's goroutine, if the plugin fails.
func NewSink(in *Instance, onFail func(name string, err error)) *Sink {
	s := &Sink{in: in, own: "plugin." + in.Name() + ".", onFail: onFail, ch: make(chan []byte, QueueLen), done: make(chan struct{})}
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
	select {
	case s.ch <- b:
	default:
		s.dropped.Add(1)
	}
}

func (s *Sink) loop() {
	defer close(s.done)
	for b := range s.ch {
		if s.failed.Load() {
			continue
		}
		if err := s.in.Event(context.Background(), b); err != nil {
			s.fail(err)
		}
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
	if !s.closed {
		s.closed = true
		close(s.ch)
	}
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
	}
	s.in.Close()
	return s.dropped.Load(), s.in.Err()
}

var errBehind = errorString("was still working through the run's events when it ended")

type errorString string

func (e errorString) Error() string { return string(e) }
