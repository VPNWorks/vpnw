#!/usr/bin/env bash
# Copyright VPNW.com 2026
# SPDX-License-Identifier: Apache-2.0

# Reproduce every figure quoted for VPN Works Lab in its Alpha report.
# Writes results/lab-alpha/*.txt. Needs Linux with unprivileged user and
# network namespaces, nftables (nft), the TUN driver, Go 1.24 and python3;
# TinyGo, Node and Playwright for the browser demo (optional). Takes about
# 36 minutes with one minute of fuzzing per target.
#
#   tools/measure-lab.sh               everything
#   FUZZTIME=10s tools/measure-lab.sh  shorter fuzzing
#   RUNS=2 tools/measure-lab.sh        fewer runs of each app and scenario (default 5)
#   PARALLEL=2 tools/measure-lab.sh    fewer test worlds at once (default 4)
set -eu
cd "$(dirname "$0")/.."
OUT=results/lab-alpha
FUZZTIME=${FUZZTIME:-60s}
RUNS=${RUNS:-5}
export VPNW_LAB_PARALLEL=${PARALLEL:-4}
mkdir -p "$OUT" bin
export NO_COLOR=1
[ -d /tmp/tinygo/bin ] && export PATH="$PATH:/tmp/tinygo/bin"
UNIT="./internal/lab/... ./cmd/vpnw-lab/"
IT=./test/lab/
COVPKG=vpnw.com/vpnw/internal/lab/...,vpnw.com/vpnw/cmd/vpnw-lab
say() { printf '\n== %s\n' "$*"; }

say "environment"
{
  echo "date: $(date -u +%Y-%m-%d)"
  echo "kernel: $(uname -sr), $(uname -m), $(nproc) CPUs"
  go version
  command -v tinygo >/dev/null && tinygo version || echo "tinygo: not installed"
  python3 --version
  nft --version
  command -v node >/dev/null && echo "node $(node --version)" || echo "node: not installed"
  echo "test worlds at once: $VPNW_LAB_PARALLEL; runs of each app and scenario: $RUNS"
} | tee "$OUT/environment.txt"

say "builds and sizes"
{
  for arch in amd64 arm64; do
    GOOS=linux GOARCH=$arch CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "bin/vpnw-lab-linux-$arch" ./cmd/vpnw-lab
    printf 'vpnw-lab linux/%s: %s bytes; gzip -9: %s bytes\n' "$arch" \
      "$(stat -c %s "bin/vpnw-lab-linux-$arch")" "$(gzip -9 -c "bin/vpnw-lab-linux-$arch" | wc -c)"
  done
  for os_arch in darwin/amd64 darwin/arm64 windows/amd64; do
    GOOS=${os_arch%/*} GOARCH=${os_arch#*/} CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /dev/null ./cmd/vpnw-lab \
      && echo "vpnw-lab $os_arch: compiles (verdict, list and probe; run and the stand-in clients need Linux)"
  done
  if command -v tinygo >/dev/null && [ -d wasm/lab ]; then
    tinygo build -target=wasm -no-debug -opt=z -o bin/lab.wasm ./wasm/lab
    printf 'browser engine (TinyGo, WebAssembly, with the demo recordings inside): %s bytes; gzip -9: %s bytes\n' \
      "$(stat -c %s bin/lab.wasm)" "$(gzip -9 -c bin/lab.wasm | wc -c)"
  fi
  echo "third-party modules: $(go list -m all | tail -n +2 | wc -l)"
  echo "packages of the engine the command uses: $(go list -deps ./cmd/vpnw-lab | grep '^vpnw.com' | tr '\n' ' ')"
} | tee "$OUT/size.txt"
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/vpnw-lab ./cmd/vpnw-lab
go build -o bin/vpnw ./cmd/vpnw

say "source lines"
{
  lines() { find "$@" -name '*.go' ! -name '*_test.go' 2>/dev/null | xargs cat | wc -l; }
  files() { find "$@" -name '*.go' ! -name '*_test.go' 2>/dev/null | wc -l; }
  own="cmd/vpnw-lab internal/lab"
  [ -d wasm/lab ] && own="$own wasm/lab"
  echo "Lab: $(lines $own) lines of Go in $(files $own) files (tests not counted)"
  printf '  %-26s %5s lines\n' "internal/lab (root)" "$(find internal/lab -maxdepth 1 -name '*.go' ! -name '*_test.go' | xargs cat | wc -l)"
  for d in internal/lab/*/ cmd/vpnw-lab wasm/lab; do
    [ -d "$d" ] || continue
    printf '  %-26s %5s lines\n' "${d%/}" "$(lines "$d")"
  done
  echo "recordings for the demo: $(ls internal/lab/demo/*.jsonl 2>/dev/null | wc -l) files, $(cat internal/lab/demo/*.jsonl 2>/dev/null | wc -l) lines"
  echo "tests: $(find internal/lab cmd/vpnw-lab test/lab -name '*_test.go' | xargs cat | wc -l) lines of Go"
  echo "shared test network used as it is: internal/testnet, $(lines internal/testnet) lines"
} | tee "$OUT/source.txt"

say "tests"
go test -count=1 -json $UNIT $IT >"$OUT/tests.json" 2>&1 || true
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
            pkgs[e["Package"]] += 1
        if e["Action"] == "fail": failed.append(e["Package"] + " " + e["Test"])
print(f"test functions: {sum(top.values())} ({top['pass']} passed, {top['fail']} failed, {top['skip']} skipped)")
print(f"with subtests: {sum(res.values())} ({res['pass']} passed, {res['fail']} failed, {res['skip']} skipped)")
for p, n in sorted(pkgs.items()): print(f"  {p}: {n}")
for f in failed: print("FAILED:", f)
PY

say "race detector (two test worlds at once: it slows the bench's own servers)"
VPNW_LAB_PARALLEL=2 go test -count=1 -race $UNIT $IT 2>&1 | tee "$OUT/race.txt" | tail -12

say "coverage (unit tests, plus the kernel tests and the commands they run)"
COV=$(mktemp -d)
mkdir -p "$COV/unit" "$COV/it" "$COV/bin"
go test -count=1 -cover -coverpkg=$COVPKG $UNIT -args -test.gocoverdir="$COV/unit" >/dev/null
VPNW_LAB_BINCOVER="$COV/bin" go test -count=1 -cover -coverpkg=vpnw.com/vpnw/internal/lab/... $IT -args -test.gocoverdir="$COV/it" >/dev/null
{
  go tool covdata percent -i="$COV/unit,$COV/it,$COV/bin" -pkg=$COVPKG | sed 's/\t/  /g'
  go tool covdata textfmt -i="$COV/unit,$COV/it,$COV/bin" -pkg=$COVPKG -o "$COV/all.txt"
  go tool cover -func="$COV/all.txt" | tail -1 | sed 's/(statements)\s*/statements: /; s/\t\+/ /g'
} | tee "$OUT/coverage.txt"
rm -rf "$COV"

say "fuzzing ($FUZZTIME per target)"
: >"$OUT/fuzz.txt"
for target in internal/lab:FuzzParseEvent internal/lab:FuzzRecording \
              internal/lab/wire:FuzzParseQuery internal/lab/wire:FuzzParseAnswer internal/lab/wire:FuzzParseName \
              internal/lab/wire:FuzzParseTag internal/lab/wire:FuzzParseFrame \
              internal/lab/world:FuzzParseResolv internal/lab/probe:FuzzParseProxy; do
  pkg=./${target%%:*}; fn=${target##*:}
  log=$(go test -run '^$' -fuzz "^$fn\$" -fuzztime "$FUZZTIME" "$pkg" 2>&1 || true)
  execs=$(printf '%s\n' "$log" | grep -o 'execs: [0-9]*' | tail -1 | tr -dc 0-9)
  status=$(printf '%s\n' "$log" | tail -1)
  printf '%-20s %-18s %10s executions  %s\n' "${target%%:*}" "$fn" "$execs" "$status" | tee -a "$OUT/fuzz.txt"
done

say "every app through every scenario, $RUNS runs each"
VPNW_LAB_RUNS=$RUNS go test -count=1 -v -timeout 60m $IT 2>&1 | tee "$OUT/kernel.log" | grep -o 'RESULT .*' | sed 's/^RESULT //' | tee "$OUT/kernel.txt"
grep -E '^(--- FAIL|FAIL|ok )' "$OUT/kernel.log" | tail -3
rm -f "$OUT/kernel.log"

say "planted bugs"
python3 tools/planted_bugs_lab.py 2>&1 | tee "$OUT/planted-bugs.txt"

say "performance"
python3 tools/lab_perf.py bin 2>&1 | tee "$OUT/perf.txt"

say "the demo's recordings"
{
  echo "The recordings the browser demo replays, decided again by the command line:"
  echo
  for f in internal/lab/demo/*.jsonl; do
    echo "$ vpnw-lab verdict $(basename "$f")"
    bin/vpnw-lab verdict "$f" || true
    echo
  done
} | tee "$OUT/demo.txt"
bin/vpnw-lab verdict --json internal/lab/demo/*.jsonl >"$OUT/demo-verdicts.json" || true

say "the browser demo"
if command -v tinygo >/dev/null && command -v node >/dev/null && [ -f bin/lab.wasm ]; then
  python3 ../web/tools/build_lab_js.py ../web/tools/wasm_exec_tinygo.js bin/lab.wasm ../web/lab/engine.lab.v1.js "$(sed -n 's/^const Version = "\(.*\)"/\1/p' internal/lab/lab.go)"
  node ../web/tools/lab_battery.js ../web/tools/wasm_exec_tinygo.js bin/lab.wasm "$OUT/demo-verdicts.json" 2>&1 | tee "$OUT/demo-browser.txt"
  SHOTS=$(mktemp -d)
  NODE_PATH=$(npm root -g) node ../web/tools/check_lab_demo.js "file://$(cd ../web/lab && pwd)/index.html" "$SHOTS" "$OUT/demo-verdicts.json" 2>&1 | tee "$OUT/demo-check.txt"
  rm -rf "$SHOTS"
else
  echo "skipped: needs TinyGo, Node and Playwright" | tee "$OUT/demo-check.txt"
fi

say "done: $OUT"
