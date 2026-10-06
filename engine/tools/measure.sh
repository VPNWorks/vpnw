#!/usr/bin/env bash
# Copyright VPNW.com 2026
# SPDX-License-Identifier: Apache-2.0

# Reproduce every figure quoted for the Agent in its documents and on
# vpnw.com. Writes results/agent-0.2.0/*.txt; results/alpha/ keeps the run of
# September 29, 2026, for Agent 0.1.0. Needs Linux, Go 1.24, python3, and
# TinyGo for the browser build (optional). Takes about ten minutes.
#
#   tools/measure.sh                everything
#   FUZZTIME=10s tools/measure.sh   shorter fuzzing
#   OUT=results/x tools/measure.sh  another folder
set -eu
cd "$(dirname "$0")/.."
OUT=${OUT:-results/agent-0.2.0}
FUZZTIME=${FUZZTIME:-60s}
mkdir -p "$OUT" bin
# The Agent's own packages. The other engines share the module and have
# scripts of their own: Scope (internal/scope, internal/testnet,
# cmd/vpnw-scope, cmd/scope-office, wasm/scope, test/scope), and Ledger, Lab
# and Exit (internal/E, cmd/vpnw-E, wasm/E, test/E).
OTHERS='scope|testnet|/(ledger|lab|exit)(/|$)|vpnw-(ledger|lab|exit)'
AGENT_PKGS=$(go list ./... | grep -v -E "$OTHERS")
AGENT_INTERNAL=$(go list ./internal/... | grep -v -E "$OTHERS")
AGENT_COVERPKG=$(echo $AGENT_PKGS | tr ' ' ',')
export NO_COLOR=1
say() { printf '\n== %s\n' "$*"; }

say "environment"
{
  echo "date: $(date -u +%Y-%m-%d)"
  echo "kernel: $(uname -sr), $(uname -m), $(nproc) CPUs"
  go version
  command -v tinygo >/dev/null && tinygo version || echo "tinygo: not installed"
  python3 --version
} | tee "$OUT/environment.txt"

say "builds and sizes"
{
  for arch in amd64 arm64; do
    GOOS=linux GOARCH=$arch CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "bin/vpnw-linux-$arch" ./cmd/vpnw
    printf 'linux/%s binary: %s bytes; gzip -9: %s bytes\n' "$arch" \
      "$(stat -c %s "bin/vpnw-linux-$arch")" "$(gzip -9 -c "bin/vpnw-linux-$arch" | wc -c)"
  done
  for os_arch in darwin/amd64 darwin/arm64; do
    GOOS=${os_arch%/*} GOARCH=${os_arch#*/} CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /dev/null ./cmd/vpnw \
      && echo "$os_arch: compiles (env backend only; sealed runs need Linux in the Alpha)"
  done
  if command -v tinygo >/dev/null; then
    tinygo build -target=wasm -no-debug -opt=z -o bin/engine.wasm ./wasm
    printf 'browser engine (TinyGo, WebAssembly): %s bytes; gzip -9: %s bytes\n' \
      "$(stat -c %s bin/engine.wasm)" "$(gzip -9 -c bin/engine.wasm | wc -c)"
  fi
  GOOS=js GOARCH=wasm go build -trimpath -ldflags="-s -w" -o bin/engine-go.wasm ./wasm
  printf 'browser engine (standard Go, WebAssembly): %s bytes; gzip -9: %s bytes\n' \
    "$(stat -c %s bin/engine-go.wasm)" "$(gzip -9 -c bin/engine-go.wasm | wc -c)"
  echo "third-party modules: $(go list -m all | tail -n +2 | wc -l)"
} | tee "$OUT/size.txt"

say "source lines"
{
  skip=(! -path '*scope*' ! -path '*testnet*')
  for e in ledger lab exit; do skip+=(! -path "*/$e/*" ! -path "*/vpnw-$e/*"); done
  code=$(find cmd internal wasm -name '*.go' ! -name '*_test.go' "${skip[@]}" | xargs cat | wc -l)
  files=$(find cmd internal wasm -name '*.go' ! -name '*_test.go' "${skip[@]}" | wc -l)
  tests=$(find . -name '*_test.go' "${skip[@]}" | xargs cat | wc -l)
  echo "engine: $code lines of Go in $files files (tests not counted)"
  echo "tests: $tests lines of Go"
  for d in cmd/vpnw $(ls -d internal/* | grep -v -E "$OTHERS") wasm; do
    printf '  %-20s %5s lines\n' "$d" "$(find "$d" -name '*.go' ! -name '*_test.go' "${skip[@]}" | xargs cat | wc -l)"
  done
} | tee "$OUT/source.txt"

say "tests"
go test -count=1 -json $AGENT_PKGS >"$OUT/tests.json" 2>&1 || true
python3 - "$OUT/tests.json" <<'PY' | tee "$OUT/tests.txt"
import json, sys, collections
res = collections.Counter(); top = collections.Counter(); failed = []
for line in open(sys.argv[1]):
    try: e = json.loads(line)
    except ValueError: continue
    if e.get("Test") and e.get("Action") in ("pass", "fail", "skip"):
        res[e["Action"]] += 1
        if "/" not in e["Test"]: top[e["Action"]] += 1
        if e["Action"] == "fail": failed.append(e["Package"] + " " + e["Test"])
print(f"test functions: {sum(top.values())} ({top['pass']} passed, {top['fail']} failed, {top['skip']} skipped)")
print(f"with subtests: {sum(res.values())} ({res['pass']} passed, {res['fail']} failed, {res['skip']} skipped)")
for f in failed: print("FAILED:", f)
PY

say "race detector"
go test -count=1 -race $AGENT_PKGS 2>&1 | tee "$OUT/race.txt" | tail -12

say "coverage (unit tests plus the real binary under the integration tests)"
COV=$(mktemp -d)
mkdir -p "$COV/unit" "$COV/it"
go test -count=1 -cover -coverpkg="$AGENT_COVERPKG" $AGENT_INTERNAL -args -test.gocoverdir="$COV/unit" >/dev/null
GOCOVERDIR="$COV/it" go test -count=1 ./test/integration/ >/dev/null
{
  go tool covdata percent -i="$COV/unit,$COV/it" | sed 's/\t/  /g' | grep -v 'internal/version'
  go tool covdata textfmt -i="$COV/unit,$COV/it" -o "$COV/all.txt"
  go tool cover -func="$COV/all.txt" | tail -1 | sed 's/(statements)\s*/statements: /; s/\t\+/ /g'
} | tee "$OUT/coverage.txt"
rm -rf "$COV"

say "fuzzing ($FUZZTIME per target)"
: >"$OUT/fuzz.txt"
for target in internal/config:FuzzParse internal/policy:FuzzParseRule internal/policy:FuzzDecide internal/broker:FuzzHandle \
              internal/path:FuzzFromURL internal/path:FuzzExitAnswer; do
  pkg=./${target%%:*}; fn=${target##*:}
  log=$(go test -run '^$' -fuzz "^$fn\$" -fuzztime "$FUZZTIME" "$pkg" 2>&1 || true)
  execs=$(printf '%s\n' "$log" | grep -o 'execs: [0-9]*' | tail -1 | tr -dc 0-9)
  status=$(printf '%s\n' "$log" | tail -1)
  printf '%-10s %-14s %10s executions  %s\n' "${target%%:*}" "$fn" "$execs" "$status" | tee -a "$OUT/fuzz.txt"
done

say "bypass matrix"
VPNW_MATRIX_OUT="$PWD/$OUT/bypass-matrix.md" go test -count=1 -run 'TestBypassMatrix|TestKnownGap' -v ./test/integration/ 2>&1 \
  | grep -E '^(---|    ---|ok|FAIL)' | tee "$OUT/bypass.txt"
cat "$OUT/bypass-matrix.md"

say "planted bugs"
python3 tools/planted_bugs.py 2>&1 | tee "$OUT/planted-bugs.txt"

say "performance"
python3 tools/perf.py "bin/vpnw-linux-$(go env GOARCH)" 2>&1 | tee "$OUT/perf.txt"

say "done: $OUT"
