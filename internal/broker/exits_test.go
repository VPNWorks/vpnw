// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package broker

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/VPNWorks/vpnw/internal/config"
	"github.com/VPNWorks/vpnw/internal/events"
	"github.com/VPNWorks/vpnw/internal/path"
)

// listPath stands in for a list of exits: it records what the broker put in
// each dial's context, reports a switch, names the exit that answered, and
// refuses one destination as an exit would.
type listPath struct {
	port int
	mu   sync.Mutex
	got  []path.Conn
}

func (*listPath) ID() string       { return "exits" }
func (*listPath) Kind() string     { return "exits" }
func (*listPath) RemoteDNS() bool  { return true }
func (*listPath) Describe() string { return "test exits" }
func (l *listPath) Dial(ctx context.Context, host string, ip net.IP, port int) (net.Conn, error) {
	ci := path.ConnOf(ctx)
	if ci == nil {
		return nil, errors.New("no connection in the context")
	}
	l.mu.Lock()
	l.got = append(l.got, *ci)
	l.mu.Unlock()
	ci.Switched("exit-a:8443", "exit-b:8443", "proxy exit-a:8443: connection refused", 2)
	ci.Exit = "exit-b:8443"
	if host == "refused.test" {
		return nil, errors.New("the exit refused it (default): no allow rule matches refused.test:80")
	}
	var d net.Dialer
	return d.DialContext(ctx, "tcp", "127.0.0.1:"+strconv.Itoa(l.port))
}
func (*listPath) Health(context.Context) error { return nil }

func TestBrokerSendsIDsAndRecordsExit(t *testing.T) {
	port, _ := echoServer(t)
	lp := &listPath{port: port}
	mem := &events.Memory{}
	bus := events.NewBus("r-ids", nil)
	bus.Add(mem)
	b := &Broker{Path: lp, Resolver: &fakeDNS{}, Bus: bus, DialTimeout: 3 * time.Second}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go b.Serve(l)
	t.Cleanup(func() { l.Close(); b.Shutdown(time.Second) })

	c, status := connect(t, l.Addr().String(), fmt.Sprintf("api.partner.test:%d", port), "")
	if status != "HTTP/1.1 200 Connection established" {
		t.Fatalf("status %q", status)
	}
	c.Close()
	_, status = connect(t, l.Addr().String(), "refused.test:80", "")
	if !strings.HasPrefix(status, "HTTP/1.1 502") {
		t.Fatalf("refused at the exit: %q", status)
	}
	r := &rig{b: b, mem: mem}
	waitEvents(r, events.ConnectionError, 1)
	waitEvents(r, events.ConnectionClose, 1)

	lp.mu.Lock()
	got := append([]path.Conn(nil), lp.got...)
	lp.mu.Unlock()
	if len(got) != 2 || got[0].Run != "r-ids" || got[0].ID != 1 || got[1].ID != 2 {
		t.Fatalf("the path was given %+v", got)
	}
	var switches, opens, errs int
	for _, e := range mem.Snapshot() {
		switch e.Type {
		case events.PathSwitch:
			switches++
			if e.Str("from") != "exit-a:8443" || e.Str("to") != "exit-b:8443" || e.Int("ms") != 2 || e.Path != "exits" || e.Conn == 0 {
				t.Errorf("switch event %+v", e)
			}
		case events.ConnectionOpen:
			opens++
			if e.Str("exit") != "exit-b:8443" || e.Conn != 1 {
				t.Errorf("open event %+v", e)
			}
		case events.ConnectionError:
			errs++
			if e.Str("exit") != "exit-b:8443" || !strings.Contains(e.Str("error"), "the exit refused it") || e.Conn != 2 {
				t.Errorf("error event %+v", e)
			}
		}
	}
	if switches != 2 || opens != 1 || errs != 1 {
		t.Errorf("%d switches, %d opens, %d errors", switches, opens, errs)
	}
}

// A path that is not an exit leaves the events exactly as before: no exit
// field on open, error or anywhere else.
func TestDirectEventsUnchanged(t *testing.T) {
	port, _ := echoServer(t)
	r := newRig(t, pol(t, config.PolicySpec{Allow: []string{"echo.test", "missing.test"}}))
	c, _ := connect(t, r.addr, fmt.Sprintf("echo.test:%d", port), "")
	c.Close()
	c, _ = connect(t, r.addr, "missing.test:80", "")
	c.Close()
	waitEvents(r, events.ConnectionClose, 1)
	waitEvents(r, events.ConnectionError, 1)
	for _, e := range r.mem.Snapshot() {
		if _, ok := e.Fields["exit"]; ok || e.Type == events.PathSwitch {
			t.Errorf("event %+v", e)
		}
	}
}
