#!/usr/bin/env bash
# Copyright VPNW.com 2026
# SPDX-License-Identifier: Apache-2.0

# Records every figure quoted for VPN Works on vpnw.com and in the README,
# into test/results/. Needs Linux (for the sealed tests), Go and python3.
# Takes about fifteen minutes.
#
#   tools/record-results.sh                 everything
#   FUZZTIME=10s tools/record-results.sh    shorter fuzzing
set -eu
cd "$(dirname "$0")/.."
OUT=test/results
FUZZTIME=${FUZZTIME:-60s}
mkdir -p "$OUT" bin
export NO_COLOR=1
say() { printf '\n== %s\n' "$*"; }

say "built-in plugins, from this source"
sh tools/build-plugins.sh

say "environment"
{
  echo "date: $(date -u +%Y-%m-%d)"
  echo "commit: $(git rev-parse --short HEAD 2>/dev/null || echo unknown)"
  echo "kernel: $(uname -sr), $(uname -m), $(nproc) CPUs"
  go version
  python3 --version
} | tee "$OUT/environment.txt"

say "sizes"
{
  for arch in amd64 arm64; do
    GOOS=linux GOARCH=$arch CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "bin/vpnw-linux-$arch" ./cmd/vpnw
    printf 'vpnw, linux/%s: %s bytes; gzip -9: %s bytes\n' "$arch" \
      "$(stat -c %s "bin/vpnw-linux-$arch")" "$(gzip -9 -c "bin/vpnw-linux-$arch" | wc -c)"
  done
  for os_arch in darwin/amd64 darwin/arm64; do
    GOOS=${os_arch%/*} GOARCH=${os_arch#*/} CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /dev/null ./cmd/vpnw \
      && echo "vpnw, $os_arch: compiles (env backend; sealed runs need Linux)"
  done
  for p in trace learn; do
    printf 'built-in plugin %s: %s bytes of WebAssembly; gzip -9: %s bytes\n' "$p" \
      "$(stat -c %s "plugins/builtin/$p.wasm")" "$(gzip -9 -c "plugins/builtin/$p.wasm" | wc -c)"
  done
  echo "third-party modules: $(go list -m all | tail -n +2 | wc -l) ($(go list -m all | tail -n +2 | tr '\n' ' '))"
} | tee "$OUT/size.txt"

say "source lines"
{
  count() { find "$@" -name '*.go' ! -name '*_test.go' ! -path '*/testdata/*' | xargs cat | wc -l; }
  echo "core: $(count cmd internal) lines of Go (tests not counted)"
  echo "plugins and SDK: $(count plugins) lines of Go"
  echo "tests: $(find . -name '*_test.go' -o -path '*/testdata/plugins/*.go' | xargs cat | wc -l) lines of Go, test plugins included"
  for d in cmd/vpnw internal/* plugins/sdk plugins/trace plugins/learn; do
    printf '  %-22s %5s lines\n' "$d" "$(count "$d")"
  done
} | tee "$OUT/source.txt"

say "tests"
go test -count=1 -timeout 30m -json ./... >"$OUT/tests.json" 2>&1 || true
python3 - "$OUT/tests.json" <<'PY' | tee "$OUT/tests.txt"
import json, sys, collections
res = collections.Counter(); top = collections.Counter(); failed = []; pkgs = collections.Counter()
for line in open(sys.argv[1]):
    try: e = json.loads(line)
    except ValueError: continue
    if e.get("Test") and e.get("Action") in ("pass", "fail", "skip"):
        res[e["Action"]] += 1
        if "/" not in e["Test"]:
            top[e["Action"]] += 1
            if e["Action"] == "pass": pkgs[e["Package"].replace("github.com/VPNWorks/vpnw/", "")] += 1
        if e["Action"] == "fail": failed.append(e["Package"] + " " + e["Test"])
print(f"test functions: {sum(top.values())} ({top['pass']} passed, {top['fail']} failed, {top['skip']} skipped)")
print(f"with subtests: {sum(res.values())} ({res['pass']} passed, {res['fail']} failed, {res['skip']} skipped)")
for p, n in sorted(pkgs.items()): print(f"  {p:28s} {n:3d} passed")
for f in failed: print("FAILED:", f)
PY
rm -f "$OUT/tests.json"

say "race detector"
go test -count=1 -race -timeout 30m ./... 2>&1 | tee "$OUT/race.txt" | tail -16

say "coverage (unit tests plus the real binary under the integration tests)"
COV=$(mktemp -d)
mkdir -p "$COV/unit" "$COV/it"
PKGS=$(go list ./cmd/... ./internal/... ./plugins/... | tr '\n' ',' | sed 's/,$//')
go test -count=1 -cover -coverpkg="$PKGS" ./internal/... ./plugins/... -args -test.gocoverdir="$COV/unit" >/dev/null
GOCOVERDIR="$COV/it" go test -count=1 ./test/integration/ >/dev/null
{
  go tool covdata percent -i="$COV/unit,$COV/it" | sed 's/\t/  /g' | grep -v -E 'internal/version|plugins/builtin'
  go tool covdata textfmt -i="$COV/unit,$COV/it" -o "$COV/all.txt"
  go tool cover -func="$COV/all.txt" | tail -1 | sed 's/(statements)\s*/statements: /; s/\t\+/ /g'
  echo "(the Trace and Learn plugin programs run as WebAssembly, where Go records no coverage; their logic is covered through plugins/trace/render and plugins/learn/learn)"
} | tee "$OUT/coverage.txt"
rm -rf "$COV"

say "fuzzing ($FUZZTIME per target)"
: >"$OUT/fuzz.txt"
for target in internal/config:FuzzParse internal/policy:FuzzParseRule internal/policy:FuzzDecide internal/broker:FuzzHandle \
              internal/path:FuzzFromURL internal/path:FuzzExitAnswer internal/pluginhost:FuzzParseManifest internal/pluginhost:FuzzVerify; do
  pkg=./${target%%:*}; fn=${target##*:}
  log=$(go test -run '^$' -fuzz "^$fn\$" -fuzztime "$FUZZTIME" "$pkg" 2>&1 || true)
  execs=$(printf '%s\n' "$log" | grep -o 'execs: [0-9]*' | tail -1 | tr -dc 0-9)
  status=$(printf '%s\n' "$log" | tail -1)
  printf '%-20s %-18s %10s executions  %s\n' "${target%%:*}" "$fn" "$execs" "$status" | tee -a "$OUT/fuzz.txt"
done

say "plugin costs"
go test -run '^$' -bench . -benchtime 3s -count 3 ./internal/pluginhost 2>&1 | grep -E '^Benchmark' | python3 -c '
import sys, collections
runs = collections.defaultdict(list)
for line in sys.stdin:
    f = line.split()
    runs[f[0].split("-")[0]].append(float(f[2]))
label = {"BenchmarkGuardDecide": "a Guard decision (test guard, policy already passed)",
         "BenchmarkObserverEvent": "one event through the Trace plugin, rendered",
         "BenchmarkLoadWarm": "starting the Trace plugin, compiled code from the cache"}
for k, v in runs.items():
    v.sort(); m = v[len(v)//2]
    unit, div = ("ms", 1e6) if m >= 1e6 else ("µs", 1e3)
    print(f"{label.get(k, k)}: {m/div:.1f} {unit} (median of {len(v)} runs)")
' | tee "$OUT/plugins.txt"

say "bypass matrix"
VPNW_MATRIX_OUT="$PWD/$OUT/bypass-matrix.md" go test -count=1 -run 'TestBypassMatrix' -v ./test/integration/ 2>&1 \
  | grep -E '^(---|    ---|ok|FAIL)' | tee "$OUT/bypass.txt"
cat "$OUT/bypass-matrix.md"
