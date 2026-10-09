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
		if len(p.Wasm) < 1<<20 || string(p.Wasm[:4]) != "\x00asm" {
			t.Errorf("built-in %s is not a WebAssembly module (%d bytes)", p.Manifest.Name, len(p.Wasm))
		}
	}
}
