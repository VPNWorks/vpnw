// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

package builtin

import (
	"testing"

	"github.com/VPNWorks/vpnw/internal/version"
)

// The built-in plugins ship with vpnw and carry its version. A mismatch
// means plugins/builtin holds modules built from older source: run
// tools/build-plugins.sh.
func TestBuiltinsMatchRelease(t *testing.T) {
	pkgs, err := Packages()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range pkgs {
		if p.Manifest.Version != version.Version {
			t.Errorf("built-in %s is version %s; vpnw is %s", p.Manifest.Name, p.Manifest.Version, version.Version)
		}
		if p.Wasm != nil {
			t.Errorf("built-in %s was unpacked before anything asked for it", p.Manifest.Name)
		}
		w, err := p.Module()
		if err != nil || len(w) < 1<<20 || string(w[:4]) != "\x00asm" {
			t.Errorf("built-in %s is not a WebAssembly module (%d bytes, %v)", p.Manifest.Name, len(w), err)
		}
	}
}
