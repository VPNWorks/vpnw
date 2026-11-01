// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package exit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/VPNWorks/vpnw/internal/broker"
)

func exitFile(clients string) string {
	return `version = 1
name = "exit-t"
listen = "127.0.0.1:0"
cert = "t.crt"
key = "t.key"

[pools.local]
addresses = ["127.0.0.1"]
` + clients
}

func client(name, token, extra string) string {
	return "\n[clients." + name + "]\ntoken_sha256 = \"" + HashHex(token) + "\"\npool = \"local\"\n" + extra + "\n"
}

func write(t *testing.T, name, s string) {
	t.Helper()
	if err := os.WriteFile(name, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
}

// A client added to the file can log in without a restart; one taken out,
// or given a new token, can't, and its connections are closed; a broken
// file leaves the clients as they were.
func TestReload(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "exit.toml")
	pol := filepath.Join(dir, "a.toml")
	write(t, pol, "version = 1\n[policy]\ndefault = \"deny\"\nallow = [\"a.test\"]\n")
	write(t, file, exitFile(client("a", "tok-a", `policy = "a.toml"`)+client("b", "tok-b", `default = "allow"`)))
	cfg, err := LoadConfig(file)
	if err != nil {
		t.Fatal(err)
	}
	clients := cfg.BrokerClients()
	live := NewLive(clients)
	var revoked []string
	r := NewReloader(cfg, clients, live, func(cls ...*broker.Client) int {
		for _, c := range cls {
			revoked = append(revoked, c.Name)
		}
		return len(cls)
	})
	if ch := r.Check(); ch != nil {
		t.Fatalf("nothing changed, got %+v", ch)
	}
	if live.Login("tok-c") != nil {
		t.Fatal("c before it was added")
	}

	// Add c, take b out, give a a new policy in its file.
	write(t, file, exitFile(client("a", "tok-a", `policy = "a.toml"`)+client("c", "tok-c", `default = "allow"`)))
	write(t, pol, "version = 1\n[policy]\ndefault = \"deny\"\nallow = [\"a.test\", \"b.test\"]\n")
	ch := r.Check()
	if ch == nil || ch.Err != nil || strings.Join(ch.Added, ",") != "c" || strings.Join(ch.Removed, ",") != "b" || strings.Join(ch.Changed, ",") != "a" || ch.Closed != 1 {
		t.Fatalf("change %+v", ch)
	}
	if strings.Join(revoked, ",") != "b" {
		t.Fatalf("revoked %v", revoked)
	}
	if live.Login("tok-c") == nil || live.Login("tok-b") != nil || live.Login("tok-a") == nil {
		t.Fatal("logins after the reload")
	}
	if a := live.Login("tok-a"); len(a.Policy.Allow) != 2 {
		t.Fatalf("a's policy %+v", a.Policy.Allow)
	}
	f := ch.Fields()
	if _, ok := f["error"]; ok || f["closed"] != 1 {
		t.Errorf("fields %v", f)
	}

	// A new token for c: the old one stops working at once.
	revoked = nil
	write(t, file, exitFile(client("a", "tok-a", `policy = "a.toml"`)+client("c", "tok-c2", `default = "allow"`)))
	ch = r.Check()
	if ch == nil || strings.Join(ch.Changed, ",") != "c" || strings.Join(revoked, ",") != "c" || live.Login("tok-c") != nil || live.Login("tok-c2") == nil {
		t.Fatalf("token change %+v %v", ch, revoked)
	}

	// A broken file: the clients stay.
	write(t, file, exitFile(client("a", "tok-a", `policy = "a.toml"`)+"\n[clients.z]\nwhat = 1\n"))
	ch = r.Check()
	if ch == nil || ch.Err == nil || live.Login("tok-c2") == nil {
		t.Fatalf("broken %+v", ch)
	}
	if f := ch.Fields(); f["error"] == nil {
		t.Errorf("fields %v", f)
	}
	// Reported once, not every look.
	if ch := r.Check(); ch != nil {
		t.Fatalf("again %+v", ch)
	}

	// Fixed, with the listen address changed too: clients come in, the
	// address waits for a restart.
	write(t, file, strings.Replace(exitFile(client("a", "tok-a", `policy = "a.toml"`)), "127.0.0.1:0", "127.0.0.1:9", 1))
	ch = r.Check()
	if ch == nil || ch.Err != nil || strings.Join(ch.Restart, ",") != "listen" || strings.Join(ch.Removed, ",") != "c" {
		t.Fatalf("fixed %+v", ch)
	}

	// A source address the machine doesn't have is refused.
	write(t, file, strings.Replace(exitFile(client("a", "tok-a", `policy = "a.toml"`)), `["127.0.0.1"]`, `["192.0.2.55"]`, 1))
	ch = r.Check()
	if ch == nil || ch.Err == nil || !strings.Contains(ch.Err.Error(), "192.0.2.55") || live.Login("tok-a") == nil {
		t.Fatalf("missing source %+v", ch)
	}

	// The file gone: an error, and the clients stay.
	os.Remove(file)
	if ch := r.Check(); ch == nil || ch.Err == nil || live.Login("tok-a") == nil {
		t.Fatalf("gone %+v", ch)
	}
}
