#!/bin/sh
# Builds the first-party plugins to WebAssembly and puts them, gzipped, with
# their manifests, where vpnw embeds them (plugins/builtin). vpnw unpacks
# only the one a command uses. Run from anywhere;
# CI runs it before every build so release binaries embed plugins built from
# the same commit. Needs only the Go toolchain.
set -eu
root=$(cd "$(dirname "$0")/.." && pwd)
out="$root/plugins/builtin"
# directory:name
for p in trace:trace learn:learn ledger:ledger ledgerverify:ledger-verify; do
	dir=${p%%:*} name=${p#*:}
	GOOS=wasip1 GOARCH=wasm CGO_ENABLED=0 go build -C "$root" -buildmode=c-shared -trimpath -buildvcs=false -ldflags="-s -w -buildid=" \
		-o "$out/$name.wasm" "./plugins/$dir"
	gzip -9 -n -f "$out/$name.wasm"
	cp "$root/plugins/$dir/plugin.toml" "$out/$name.toml"
done
