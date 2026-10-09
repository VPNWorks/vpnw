// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

// Package builtin embeds the first-party plugins, Trace and Learn, in vpnw.
//
// They run through the same plugin host and interface as any other plugin;
// being built in only means they ship inside the binary and are trusted
// without a signature. The .wasm files are built from ../trace and ../learn
// by tools/build-plugins.sh, which CI runs before every build.
package builtin

import (
	_ "embed"
	"fmt"

	"github.com/VPNWorks/vpnw/internal/pluginhost"
)

//go:generate sh ../../tools/build-plugins.sh

var (
	//go:embed trace.toml
	traceToml []byte
	//go:embed trace.wasm
	traceWasm []byte
	//go:embed learn.toml
	learnToml []byte
	//go:embed learn.wasm
	learnWasm []byte
)

// Packages returns the built-in plugins.
func Packages() ([]*pluginhost.Package, error) {
	var out []*pluginhost.Package
	for _, p := range []struct{ toml, wasm []byte }{{traceToml, traceWasm}, {learnToml, learnWasm}} {
		m, err := pluginhost.ParseManifest(string(p.toml))
		if err != nil {
			return nil, fmt.Errorf("built-in plugin: %v", err)
		}
		out = append(out, &pluginhost.Package{Manifest: m, ManifestSrc: p.toml, Wasm: p.wasm, Source: pluginhost.BuiltinSource, Builtin: true})
	}
	return out, nil
}
