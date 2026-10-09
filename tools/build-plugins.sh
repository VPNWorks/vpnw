#!/bin/sh
# Builds the first-party plugins to WebAssembly and puts them, with their
# manifests, where vpnw embeds them (plugins/builtin). Run from anywhere;
# CI runs it before every build so release binaries embed plugins built from
# the same commit. Needs only the Go toolchain.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
out="$root/plugins/builtin"
for p in trace learn; do
	GOOS=wasip1 GOARCH=wasm CGO_ENABLED=0 go build -C "$root" -buildmode=c-shared -trimpath -buildvcs=false -ldflags="-s -w -buildid=" \
		-o "$out/$p.wasm" "./plugins/$p"
	cp "$root/plugins/$p/plugin.toml" "$out/$p.toml"
done
