// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package exit

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"vpnw.com/vpnw/internal/config"
	"vpnw.com/vpnw/internal/events"
)

// FuzzParseConfig feeds arbitrary files to the exit's configuration reader.
// It must not crash, and a file it accepts must hold what an exit needs:
// clients with a token hash, an address and a policy, and no address shared
// between two owners.
func FuzzParseConfig(f *testing.F) {
	_, good := demo(f)
	f.Add(strings.Replace(good, `policy = "agent-1.toml"`, `default = "deny"`, 1))
	f.Add("version = 1\nlisten = \"h:1\"\ncert = \"c\"\nkey = \"k\"\n[clients.a]\ntoken_sha256 = \"" + HashHex("t") + "\"\nsource = \"10.0.0.1\"\nallow = [\"x.test\"]\n")
	f.Add("version = 1\n[pools.p]\naddresses = [\"::1\"]\n")
	f.Add("[[clients]]\n")
	noFiles := func(string) (*config.File, error) { return nil, errors.New("no files") }
	f.Fuzz(func(t *testing.T, src string) {
		c, err := ParseConfig(src, "fuzz.toml", noFiles)
		if err != nil {
			return
		}
		if len(c.Clients) == 0 || c.Listen == "" {
			t.Fatalf("accepted a file without clients or a listener")
		}
		owners := map[string]int{}
		for _, cl := range c.Clients {
			if cl.Policy == nil || (!cl.Source.IsValid() && cl.Pool == nil) {
				t.Fatalf("client %s lacks a policy or an address", cl.Name)
			}
			if cl.Source.IsValid() {
				owners[cl.Source.String()]++
			}
			if c.Lookup("") == cl {
				t.Fatal("an empty token matched a client")
			}
		}
		for _, p := range c.Pools {
			for _, a := range p.Addrs {
				owners[a.String()]++
			}
		}
		for a, n := range owners {
			if n > 1 {
				t.Fatalf("address %s has %d owners", a, n)
			}
		}
	})
}

// FuzzParseIDs feeds arbitrary SOCKS5 user names and header values to the ID
// readers. What they accept must be safe to record and to write back.
func FuzzParseIDs(f *testing.F) {
	for _, s := range []string{"r-3f9a1c/17", "r/1/198.51.100.21", "vpnw", "a/b/c/d", "r/0", "\x00/1", "r/1/::1"} {
		f.Add(s, "1", "")
	}
	f.Fuzz(func(t *testing.T, user, conn, source string) {
		check := func(ids IDs) {
			if _, err := ParseRun(ids.Run); ids.Run != "" && err != nil {
				t.Fatalf("accepted run %q", ids.Run)
			}
			for _, r := range ids.Run + ids.Source {
				if r <= ' ' || r >= 0x7f {
					t.Fatalf("unsafe character in %+v", ids)
				}
			}
		}
		if ids, err := ParseSOCKSUser(user); err == nil {
			check(ids)
			if ids.Run != "" {
				back, err := ParseSOCKSUser(ids.SOCKSUser())
				if err != nil || back != ids {
					t.Fatalf("%q read back as %+v, %v", ids.SOCKSUser(), back, err)
				}
			}
		}
		if ids, err := FromHeaders(user, conn, source); err == nil {
			check(ids)
		}
	})
}

// FuzzJoin feeds arbitrary JSON Lines to the record reader and the join.
func FuzzJoin(f *testing.F) {
	r := newRecords()
	r.attempt(1, "api.partner.test", 443)
	r.exitSaw(r.de, "exit-de", 1, "r-agent1", 1, "api.partner.test", 443, "open")
	r.agent.Emit(events.ConnectionOpen, 1, "exits", 1, map[string]any{"exit": "198.51.100.2:8443"})
	var a, x bytes.Buffer
	ja, jx := events.NewJSONL(&a), events.NewJSONL(&x)
	for _, e := range r.ma.Snapshot() {
		ja.Emit(&e)
	}
	for _, e := range r.mx.Snapshot() {
		jx.Emit(&e)
	}
	ja.Close()
	jx.Close()
	f.Add(a.Bytes(), x.Bytes())
	f.Add([]byte(`{"v":1,"type":"connection.attempt","run":"r","conn":1,"fields":{"port":1e30}}`), []byte(`{"v":1,"type":"connection.open","run":"x","conn":1}`))
	f.Fuzz(func(t *testing.T, agentLines, exitLines []byte) {
		ae, err1 := events.Read(bytes.NewReader(agentLines))
		xe, err2 := events.Read(bytes.NewReader(exitLines))
		if err1 != nil || err2 != nil {
			return
		}
		rep := Join(ae, xe)
		if rep.Joined > rep.ViaExit || rep.ViaExit+rep.Local != rep.AgentConns || rep.Other > rep.ExitConns {
			t.Fatalf("counts do not add up: %+v", rep)
		}
	})
}
