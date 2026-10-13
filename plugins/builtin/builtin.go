// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

// Package builtin embeds the first-party plugins in vpnw: Trace, Learn,
// Ledger and ledger-verify.
//
// They run through the same plugin host and interface as any other plugin;
// being built in only means they ship inside the binary and are trusted
// without a signature. The modules are built from ../trace, ../learn,
// ../ledger and ../ledgerverify by tools/build-plugins.sh, which CI runs
// before every build, and kept gzipped: a command unpacks only the plugins
// it uses.
package builtin

import (
	"bytes"
	"compress/gzip"
	"embed"
	"fmt"
	"io"

	"github.com/VPNWorks/vpnw/internal/pluginhost"
)

//go:generate sh ../../tools/build-plugins.sh

//go:embed *.toml *.wasm.gz
var files embed.FS

// Names lists the built-in plugins.
var Names = []string{"trace", "learn", "ledger", "ledger-verify"}

// Packages returns the built-in plugins.
func Packages() ([]*pluginhost.Package, error) {
	var out []*pluginhost.Package
	for _, name := range Names {
		toml, err := files.ReadFile(name + ".toml")
		if err != nil {
			return nil, fmt.Errorf("built-in plugin %s: %v", name, err)
		}
		m, err := pluginhost.ParseManifest(string(toml))
		if err != nil {
			return nil, fmt.Errorf("built-in plugin: %v", err)
		}
		gz, err := files.ReadFile(name + ".wasm.gz")
		if err != nil {
			return nil, fmt.Errorf("built-in plugin %s: %v", name, err)
		}
		out = append(out, &pluginhost.Package{Manifest: m, ManifestSrc: toml, Source: pluginhost.BuiltinSource, Builtin: true,
			Unpack: func() ([]byte, error) { return gunzip(gz) }})
	}
	return out, nil
}

func gunzip(b []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("unpacking a built-in plugin: %v", err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("unpacking a built-in plugin: %v", err)
	}
	return out, nil
}
