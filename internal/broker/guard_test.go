// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package broker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/VPNWorks/vpnw/internal/config"
	"github.com/VPNWorks/vpnw/internal/events"
)

type stubGuard struct {
	name  string
	deny  map[string]string
	err   error
	mu    sync.Mutex
	asked []GuardRequest
}

func (g *stubGuard) Name() string { return g.name }

func (g *stubGuard) Check(_ context.Context, r GuardRequest) (bool, string, error) {
	g.mu.Lock()
	g.asked = append(g.asked, r)
	g.mu.Unlock()
	if g.err != nil {
		return true, "", g.err
	}
	why, ok := g.deny[r.Host]
	return ok, why, nil
}

func lastDeny(r *rig) *events.Event {
	evs := r.mem.Snapshot()
	for i := len(evs) - 1; i >= 0; i-- {
		if evs[i].Type == events.PolicyDeny {
			return &evs[i]
		}
	}
	return nil
}

// A Guard sees only what the policy allowed, can refuse it with its own
// reason, and lets the rest through untouched.
func TestGuardRefuses(t *testing.T) {
	port, _ := echoServer(t)
	g := &stubGuard{name: "geo", deny: map[string]string{"echo.test": "echo.test is outside the fence"}}
	r := newRig(t, pol(t, config.PolicySpec{Allow: []string{"echo.test", "allowed.test"}}), g)

	_, status := connect(t, r.addr, fmt.Sprintf("echo.test:%d", port), "")
	if !strings.HasPrefix(status, "HTTP/1.1 403") {
		t.Fatalf("status %q", status)
	}
	waitEvents(r, events.PolicyDeny, 1)
	d := lastDeny(r)
	if d == nil || d.Str("rule") != "plugin:geo" || d.Str("reason") != "echo.test is outside the fence" {
		t.Fatalf("deny event %+v", d)
	}
	if got := strings.Join(r.types(), ","); got != "connection.attempt,policy.allow,policy.deny" {
		t.Errorf("events %s", got)
	}

	c, status := connect(t, r.addr, fmt.Sprintf("allowed.test:%d", port), "")
	if status != "HTTP/1.1 200 Connection established" {
		t.Fatalf("allowed.test: %q", status)
	}
	io.WriteString(c, "ping\n")
	io.ReadAll(c)
	c.Close()

	// The policy refused this one; the Guard is never asked.
	connect(t, r.addr, fmt.Sprintf("evil.test:%d", port), "")
	waitEvents(r, events.PolicyDeny, 2)

	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.asked) != 2 || g.asked[0].Host != "echo.test" || g.asked[0].Port != port || g.asked[0].Run != "r-test" || g.asked[1].Host != "allowed.test" {
		t.Errorf("asked %+v", g.asked)
	}
	st := r.b.Stats()
	if st.Denied != 2 || st.Allowed != 1 {
		t.Errorf("stats %+v", st)
	}
}

// A Guard that fails refuses the connection, and says so.
func TestGuardFailureRefuses(t *testing.T) {
	port, _ := echoServer(t)
	g := &stubGuard{name: "broken", err: errors.New("ran past its 250ms time budget")}
	r := newRig(t, nil, g)
	_, status := connect(t, r.addr, fmt.Sprintf("echo.test:%d", port), "")
	if !strings.HasPrefix(status, "HTTP/1.1 403") {
		t.Fatalf("status %q", status)
	}
	waitEvents(r, events.PolicyDeny, 1)
	d := lastDeny(r)
	if d == nil || d.Str("rule") != "plugin:broken" || !strings.Contains(d.Str("reason"), "guard plugin failed, so the connection is refused: ran past") {
		t.Fatalf("deny event %+v", d)
	}
}

// With no policy, Guards still stand in front of every connection; an
// address asked for directly reaches the Guard as IP, not Host.
func TestGuardWithoutPolicy(t *testing.T) {
	port, _ := echoServer(t)
	g := &stubGuard{name: "g", deny: map[string]string{"": "no raw addresses"}}
	r := newRig(t, nil, g)
	_, status := connect(t, r.addr, fmt.Sprintf("127.0.0.1:%d", port), "")
	if !strings.HasPrefix(status, "HTTP/1.1 403") {
		t.Fatalf("status %q", status)
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.asked) != 1 || g.asked[0].IP != "127.0.0.1" || g.asked[0].Host != "" {
		t.Errorf("asked %+v", g.asked)
	}
}
