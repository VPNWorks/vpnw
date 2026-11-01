// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

// Review of 0.9.0: reproductions of defects found by the independent review.

package exit

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/VPNWorks/vpnw/internal/broker"
)

// A connection opened by a client before any reload is tracked under the
// broker.Client it logged in as. A later reload that doesn't touch that
// client still makes a new broker.Client for it, and when the client is
// taken out after that, only the newest one is revoked: the old login's
// connections stay open.
func TestReview090RevokeMissesEarlierGeneration(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "exit.toml")
	write(t, file, exitFile(client("a", "tok-a", `default = "allow"`)))
	cfg, err := LoadConfig(file)
	if err != nil {
		t.Fatal(err)
	}
	clients := cfg.BrokerClients()
	live := NewLive(clients)
	var revoked []*broker.Client
	r := NewReloader(cfg, clients, live, func(cls ...*broker.Client) int {
		revoked = append(revoked, cls...)
		return len(cls)
	})
	first := live.Login("tok-a") // a's open connection is tracked under this
	write(t, file, exitFile(client("a", "tok-a", `default = "allow"`)+client("b", "tok-b", `default = "allow"`)))
	if ch := r.Check(); ch == nil || ch.Err != nil {
		t.Fatalf("add b: %+v", ch)
	}
	write(t, file, exitFile(client("b", "tok-b", `default = "allow"`)))
	if ch := r.Check(); ch == nil || ch.Err != nil || len(ch.Removed) != 1 {
		t.Fatalf("remove a: %+v", ch)
	}
	for _, c := range revoked {
		if c == first {
			return
		}
	}
	t.Errorf("a was taken out, but the client it logged in as before the first reload was never revoked (revoked %d other objects)", len(revoked))
}

// Check hashes the files again after loading them. A change written while
// a reload is being taken in (between LoadConfig and the second hash) is
// counted as seen and never loaded: here, a client taken out stays in.
func TestReview090ReloadLosesChangeDuringLoad(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "exit.toml")
	with := exitFile(client("a", "tok-a", `default = "allow"`) + client("b", "tok-b", `default = "allow"`))
	without := exitFile(client("b", "tok-b", `default = "allow"`))
	write(t, file, without)
	cfg, err := LoadConfig(file)
	if err != nil {
		t.Fatal(err)
	}
	clients := cfg.BrokerClients()
	live := NewLive(clients)
	r := NewReloader(cfg, clients, live, func(cls ...*broker.Client) int { return 0 })
	for i := 0; i < 4000; i++ {
		write(t, file, with)
		done := make(chan struct{})
		go func() { r.Check(); close(done) }()
		for t0 := time.Now(); time.Since(t0) < time.Duration(i%300)*5*time.Microsecond; {
		}
		write(t, file, without) // a taken out again, while the reload runs
		<-done
		r.Check() // the watcher's next look
		if live.Login("tok-a") != nil {
			t.Fatalf("round %d: the file no longer has client a, the watcher sees nothing changed, and a can still log in", i)
		}
	}
}
