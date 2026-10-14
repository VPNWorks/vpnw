#!/bin/sh
# Builds the first-party plugins to WebAssembly and puts them, with their
# manifests, where vpnw embeds them (plugins/builtin). They stay
# uncompressed: unpacking one would cost every run tens of milliseconds. Run from anywhere;
# CI runs it before every build so release binaries embed plugins built from
# the same commit. Needs only the Go toolchain.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
out="$root/plugins/builtin"
# directory:name
for p in trace:trace learn:learn ledger:ledger ledgerverify:ledger-verify rotate:rotate; do
	dir=${p%%:*} name=${p#*:}
	GOOS=wasip1 GOARCH=wasm CGO_ENABLED=0 go build -C "$root" -buildmode=c-shared -trimpath -buildvcs=false -ldflags="-s -w -buildid=" \
		-o "$out/$name.wasm" "./plugins/$dir"
	cp "$root/plugins/$dir/plugin.toml" "$out/$name.toml"
done
