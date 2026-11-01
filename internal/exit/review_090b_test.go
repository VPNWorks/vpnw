// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

// Second review round of 0.9.0.

package exit

import (
	"path/filepath"
	"testing"

	"github.com/VPNWorks/vpnw/internal/broker"
)

// The exit's file is changed to name a policy file that isn't there yet:
// the reload is refused, as it should be. Then the policy file is written.
// Only the old set of files is watched, so the reload is never tried again
// and the new client never gets in until the exit's file is saved again.
func TestReview090bPolicyFileWrittenAfterTheExitFile(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "exit.toml")
	write(t, file, exitFile(client("a", "tok-a", `default = "allow"`)))
	cfg, err := LoadConfig(file)
	if err != nil {
		t.Fatal(err)
	}
	clients := cfg.BrokerClients()
	live := NewLive(clients)
	r := NewReloader(cfg, clients, live, func(cls ...*broker.Client) int { return 0 })
	write(t, file, exitFile(client("a", "tok-a", `default = "allow"`)+client("c", "tok-c", `policy = "c.toml"`)))
	if ch := r.Check(); ch == nil || ch.Err == nil {
		t.Fatalf("missing c.toml: %+v", ch)
	}
	write(t, filepath.Join(dir, "c.toml"), "version = 1\n[policy]\ndefault = \"allow\"\n")
	for i := 0; i < 3; i++ {
		r.Check()
	}
	if live.Login("tok-c") == nil {
		t.Errorf("c.toml now exists and the exit's file names it, but client c is still not taken in (the refused file's policy files are not watched)")
	}
}
