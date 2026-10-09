// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package path

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// ExitLimit is how long one exit in a list may take to accept a connection
// and finish TLS before the list moves on to the next exit.
const ExitLimit = 3 * time.Second

// Exits is a path through a list of exits, used in order. The health check
// before a run starts picks the first exit that answers. When the exit in
// use stops answering, the connection being opened moves to the next exit,
// and so does every connection after it. An exit that answers, even with a
// refusal, is still in use. The list does not move back on its own; the
// next run starts again from the top.
type Exits struct {
	Name string
	List []*Proxy
	// Limit, if set, replaces ExitLimit.
	Limit time.Duration

	mu      sync.Mutex
	cur     int
	skipped []string // why exits before the one in use failed the health check
}

func (e *Exits) ID() string      { return e.Name }
func (e *Exits) Kind() string    { return "exits" }
func (e *Exits) RemoteDNS() bool { return e.List[0].Remote }

func (e *Exits) limit() time.Duration {
	if e.Limit > 0 {
		return e.Limit
	}
	return ExitLimit
}

// Current returns the exit in use, as host:port.
func (e *Exits) Current() string {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.List[e.cur].Addr
}

// Describe lists the exits in order, without credentials, and says which is
// in use.
func (e *Exits) Describe() string {
	e.mu.Lock()
	cur, skipped := e.cur, e.skipped
	e.mu.Unlock()
	parts := make([]string, len(e.List))
	for i, px := range e.List {
		s := px.Kind() + "://" + px.Addr
		switch {
		case i == cur:
			s += " (in use)"
		case i < len(skipped) && skipped[i] != "":
			s += " (no answer at start: " + skipped[i] + ")"
		}
		parts[i] = s
	}
	dns := "local DNS"
	if e.RemoteDNS() {
		dns = "DNS at the exit"
	}
	return fmt.Sprintf("exits in order: %s; %s", strings.Join(parts, ", "), dns)
}

// Health checks every exit at once and puts the first in list order that
// answers in use. It returns as soon as that exit is known.
func (e *Exits) Health(ctx context.Context) error {
	results := make([]chan error, len(e.List))
	for i, px := range e.List {
		results[i] = make(chan error, 1)
		go func(px *Proxy, out chan<- error) {
			hctx, cancel := context.WithTimeout(ctx, e.limit())
			defer cancel()
			out <- px.Health(hctx)
		}(px, results[i])
	}
	var why []string
	for i := range e.List {
		err := <-results[i]
		if err == nil {
			e.mu.Lock()
			e.cur, e.skipped = i, why
			e.mu.Unlock()
			return nil
		}
		why = append(why, err.Error())
	}
	return fmt.Errorf("no exit answered: %s", strings.Join(why, "; "))
}

// Dial opens a connection through the exit in use, moving down the list,
// and round to its top, past exits that do not answer. Each exit is tried at
// most once per connection.
func (e *Exits) Dial(ctx context.Context, host string, ip net.IP, port int) (net.Conn, error) {
	info := ConnOf(ctx)
	e.mu.Lock()
	i := e.cur
	e.mu.Unlock()
	var why []string
	for n := 0; n < len(e.List); n++ {
		px := e.List[i]
		t0 := time.Now()
		c, err := px.dial(ctx, host, ip, port, e.limit())
		if err == nil || !isDown(err) || ctx.Err() != nil {
			if info != nil && (err == nil || !isDown(err)) {
				info.Exit = px.Addr
			}
			return c, err
		}
		next := (i + 1) % len(e.List)
		e.mu.Lock()
		if e.cur == i {
			e.cur = next
		}
		e.mu.Unlock()
		if info != nil && info.Switched != nil && len(e.List) > 1 {
			info.Switched(px.Addr, e.List[next].Addr, err.Error(), time.Since(t0).Milliseconds())
		}
		why = append(why, err.Error())
		i = next
	}
	return nil, errors.New("no exit answered: " + strings.Join(why, "; "))
}
