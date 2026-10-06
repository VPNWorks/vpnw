// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package world

import (
	"fmt"
	"net/netip"
	"os"
	"strings"

	"vpnw.com/vpnw/internal/lab"
)

// WriteResolv writes a resolver setting in resolv.conf form, by a rename so
// a reader never sees half a file.
func WriteResolv(path string, a netip.Addr) error {
	tmp := fmt.Sprintf("%s.%d.tmp", path, os.Getpid())
	if err := os.WriteFile(tmp, []byte("nameserver "+a.String()+"\n"), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// ReadResolv reads the first nameserver of a resolver setting.
func ReadResolv(path string) (netip.Addr, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return netip.Addr{}, err
	}
	return ParseResolv(string(b), path)
}

// ParseResolv reads the first nameserver line of a resolver setting in
// resolv.conf form. Errors name the file and the line.
func ParseResolv(text, name string) (netip.Addr, error) {
	for i, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "nameserver" {
			a, err := netip.ParseAddr(f[1])
			if err != nil || !a.Is4() {
				return netip.Addr{}, fmt.Errorf("%s:%d: %q is not an IPv4 address", name, i+1, f[1])
			}
			return a, nil
		}
	}
	return netip.Addr{}, fmt.Errorf("%s: no nameserver line", name)
}

// Header returns a recording header filled in with this world's addresses.
func Header(run, app, scenario string, seed int64, intervalMS int) lab.Event {
	return lab.Event{Ev: lab.EvRun, Lab: lab.Version, Run: run, App: app, Scenario: scenario, Seed: seed,
		IntervalMS: intervalMS, Exit: ExitAddr, Home: HomePublic}
}
