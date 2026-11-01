// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package broker

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/VPNWorks/vpnw/internal/events"
)

// sinkServer counts every byte it receives, over all connections, and
// sends send bytes on each connection.
func sinkServer(t *testing.T, send int) (port int, got *atomic.Int64) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	got = &atomic.Int64{}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				if send > 0 {
					c.Write(bytes.Repeat([]byte("d"), send))
				}
				n, _ := io.Copy(io.Discard, c)
				got.Add(n)
			}(c)
		}
	}()
	return l.Addr().(*net.TCPAddr).Port, got
}

func eventsOf(r *rig, typ string) []events.Event {
	var out []events.Event
	for _, e := range r.mem.Snapshot() {
		if e.Type == typ {
			out = append(out, e)
		}
	}
	return out
}

func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	for i := 0; i < 400; i++ {
		if ok() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func budget(key string, up, down int64) func(GuardRequest) *Meter {
	return func(GuardRequest) *Meter {
		return &Meter{Key: key, Up: up, Down: down, Reason: "budget for " + key}
	}
}

// A connection sends exactly up to its budget, is cut with a record of
// why, and the next connection on the spent budget is refused.
func TestMeterCutsUpload(t *testing.T) {
	port, got := sinkServer(t, 0)
	g := &stubGuard{name: "budget", meter: budget("echo.test", 3000, 0)}
	r := newRig(t, nil, g)
	c, status := connect(t, r.addr, fmt.Sprintf("echo.test:%d", port), "")
	if status != "HTTP/1.1 200 Connection established" {
		t.Fatalf("status %q", status)
	}
	// More than the budget, in pieces.
	for i := 0; i < 10; i++ {
		if _, err := c.Write(bytes.Repeat([]byte("u"), 1000)); err != nil {
			break
		}
	}
	io.Copy(io.Discard, c) // the broker closes it
	c.Close()
	waitEvents(r, events.ConnectionClose, 1)
	waitFor(t, "the sink to finish", func() bool { return got.Load() == 3000 })
	cuts := eventsOf(r, events.ConnectionCut)
	if len(cuts) != 1 {
		t.Fatalf("cuts %+v", cuts)
	}
	cut := cuts[0]
	if cut.Str("rule") != "plugin:budget" || cut.Str("limit") != "up" || cut.Str("key") != "echo.test" || cut.Str("reason") != "budget for echo.test" || cut.Int("bytes") != 3000 {
		t.Errorf("cut %+v", cut)
	}
	cl := eventsOf(r, events.ConnectionClose)[0]
	if cl.Int("bytes_up") != 3000 || cl.Conn != cut.Conn {
		t.Errorf("close %+v", cl)
	}
	if st := r.b.Stats(); st.BytesUp != 3000 {
		t.Errorf("stats %+v", st)
	}

	_, status = connect(t, r.addr, fmt.Sprintf("echo.test:%d", port), "")
	if !strings.HasPrefix(status, "HTTP/1.1 403") {
		t.Fatalf("after the budget: %q", status)
	}
	d := lastDeny(r)
	if d == nil || d.Str("rule") != "plugin:budget" || d.Str("reason") != "byte budget spent: 3 KB sent (budget for echo.test)" {
		t.Fatalf("deny %+v", d)
	}
	// Another key has its own budget.
	g.meter = budget("other", 3000, 0)
	c, status = connect(t, r.addr, fmt.Sprintf("echo.test:%d", port), "")
	if status != "HTTP/1.1 200 Connection established" {
		t.Fatalf("other key: %q", status)
	}
	c.Write([]byte("ok"))
	c.Close()
}

// The download side is cut the same way: the program gets the budget and
// no more.
func TestMeterCutsDownload(t *testing.T) {
	port, _ := sinkServer(t, 10000)
	g := &stubGuard{name: "budget", meter: budget("k", 0, 2500)}
	r := newRig(t, nil, g)
	c, status := connect(t, r.addr, fmt.Sprintf("echo.test:%d", port), "")
	if status != "HTTP/1.1 200 Connection established" {
		t.Fatalf("status %q", status)
	}
	b, _ := io.ReadAll(c)
	c.Close()
	if len(b) != 2500 {
		t.Fatalf("received %d bytes", len(b))
	}
	waitEvents(r, events.ConnectionClose, 1)
	cuts := eventsOf(r, events.ConnectionCut)
	if len(cuts) != 1 || cuts[0].Str("limit") != "down" {
		t.Fatalf("cuts %+v", cuts)
	}
	if cl := eventsOf(r, events.ConnectionClose)[0]; cl.Int("bytes_down") != 2500 {
		t.Errorf("close %+v", cl)
	}
}

// Connections sharing a budget at the same time never get past it
// together.
func TestMeterSharedAcrossConnections(t *testing.T) {
	port, got := sinkServer(t, 0)
	g := &stubGuard{name: "budget", meter: budget("shared", 8000, 0)}
	r := newRig(t, nil, g)
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, status := connect(t, r.addr, fmt.Sprintf("echo.test:%d", port), "")
			if !strings.HasPrefix(status, "HTTP/1.1 200") {
				return // refused: the budget was spent before it asked
			}
			for j := 0; j < 20; j++ {
				if _, err := c.Write(bytes.Repeat([]byte("x"), 250)); err != nil {
					break
				}
			}
			c.Close()
		}()
	}
	wg.Wait()
	waitFor(t, "every connection to close", func() bool {
		return len(eventsOf(r, events.ConnectionClose))+len(eventsOf(r, events.PolicyDeny)) == 6
	})
	time.Sleep(50 * time.Millisecond)
	if n := got.Load(); n != 8000 {
		t.Fatalf("the destination got %d bytes, want exactly the budget, 8000", n)
	}
	var up int64
	for _, e := range eventsOf(r, events.ConnectionClose) {
		up += int64(e.Int("bytes_up"))
	}
	if up != 8000 {
		t.Errorf("recorded %d bytes up", up)
	}
}

// A plain HTTP request whose head alone is over the budget never leaves.
func TestMeterPlainHTTPHead(t *testing.T) {
	port, heads := httpOrigin(t)
	g := &stubGuard{name: "budget", meter: budget("k", 20, 0)}
	r := newRig(t, nil, g)
	c, err := net.Dial("tcp", r.addr)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(c, "GET http://echo.test:%d/a-long-path-to-pass-twenty-bytes HTTP/1.1\r\nHost: echo.test\r\n\r\n", port)
	io.ReadAll(c)
	c.Close()
	waitEvents(r, events.ConnectionClose, 1)
	select {
	case h := <-heads:
		if len(h) > 20 {
			t.Fatalf("the origin got a %d-byte head: %q", len(h), h)
		}
	case <-time.After(100 * time.Millisecond):
	}
	if len(eventsOf(r, events.ConnectionCut)) != 1 {
		t.Errorf("events %v", r.types())
	}
}

// A Guard can't make vpnw keep budgets without bound.
func TestMeterLimitPerGuard(t *testing.T) {
	old := MaxMeters
	MaxMeters = 2
	defer func() { MaxMeters = old }()
	port, _ := sinkServer(t, 0)
	var n atomic.Int64
	g := &stubGuard{name: "budget", meter: func(GuardRequest) *Meter {
		return &Meter{Key: fmt.Sprint(n.Add(1)), Up: 100}
	}}
	r := newRig(t, nil, g)
	for i := 0; i < 2; i++ {
		c, status := connect(t, r.addr, fmt.Sprintf("echo.test:%d", port), "")
		if !strings.HasPrefix(status, "HTTP/1.1 200") {
			t.Fatalf("%d: %q", i, status)
		}
		c.Close()
	}
	_, status := connect(t, r.addr, fmt.Sprintf("echo.test:%d", port), "")
	if !strings.HasPrefix(status, "HTTP/1.1 403") {
		t.Fatalf("third key: %q", status)
	}
	if d := lastDeny(r); d == nil || !strings.Contains(d.Str("reason"), "keeps 2 byte budgets already") {
		t.Fatalf("deny %+v", d)
	}
}
