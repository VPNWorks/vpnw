#!/usr/bin/env bash
# Copyright VPNW.com 2026
# SPDX-License-Identifier: Apache-2.0

# Reproduce every figure quoted for VPN Works Scope in its Alpha report and on
# vpnw.com. Writes results/scope-alpha/*.txt. Needs Linux with unprivileged
# user namespaces, nftables (nft), Go 1.24 and python3; TinyGo for the browser
# build (optional). Takes about twelve minutes.
#
#   tools/measure-scope.sh               everything
#   FUZZTIME=10s tools/measure-scope.sh  shorter fuzzing
#   LARGE=500 tools/measure-scope.sh     a smaller generated office
set -eu
cd "$(dirname "$0")/.."
OUT=results/scope-alpha
FUZZTIME=${FUZZTIME:-60s}
LARGE=${LARGE:-2000}
mkdir -p "$OUT" bin
export NO_COLOR=1
UNIT="./internal/scope/... ./cmd/vpnw-scope/ ./internal/testnet/"
IT=./test/scope/
COVPKG=vpnw.com/vpnw/internal/scope/...,vpnw.com/vpnw/cmd/vpnw-scope
say() { printf '\n== %s\n' "$*"; }

say "environment"
{
  echo "date: $(date -u +%Y-%m-%d)"
  echo "kernel: $(uname -sr), $(uname -m), $(nproc) CPUs"
  go version
  command -v tinygo >/dev/null && tinygo version || echo "tinygo: not installed"
  python3 --version
  nft --version
} | tee "$OUT/environment.txt"

say "builds and sizes"
{
  for arch in amd64 arm64; do
    GOOS=linux GOARCH=$arch CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "bin/vpnw-scope-linux-$arch" ./cmd/vpnw-scope
    printf 'vpnw-scope linux/%s: %s bytes; gzip -9: %s bytes\n' "$arch" \
      "$(stat -c %s "bin/vpnw-scope-linux-$arch")" "$(gzip -9 -c "bin/vpnw-scope-linux-$arch" | wc -c)"
  done
  for os_arch in darwin/amd64 darwin/arm64 windows/amd64; do
    GOOS=${os_arch%/*} GOARCH=${os_arch#*/} CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /dev/null ./cmd/vpnw-scope \
      && echo "vpnw-scope $os_arch: compiles (learn, replay, export and check; record needs Linux)"
  done
  if command -v tinygo >/dev/null && [ -d wasm/scope ]; then
    tinygo build -target=wasm -no-debug -opt=z -o bin/scope.wasm ./wasm/scope
    printf 'browser engine (TinyGo, WebAssembly): %s bytes; gzip -9: %s bytes\n' \
      "$(stat -c %s bin/scope.wasm)" "$(gzip -9 -c bin/scope.wasm | wc -c)"
  fi
  echo "third-party modules: $(go list -m all | tail -n +2 | wc -l)"
  echo "packages of the engine the command uses: $(go list -deps ./cmd/vpnw-scope | grep '^vpnw.com' | tr '\n' ' ')"
} | tee "$OUT/size.txt"
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/vpnw-scope ./cmd/vpnw-scope
go build -o bin/scope-office ./cmd/scope-office

say "source lines"
{
  lines() { find "$@" -name '*.go' ! -name '*_test.go' 2>/dev/null | xargs cat | wc -l; }
  files() { find "$@" -name '*.go' ! -name '*_test.go' 2>/dev/null | wc -l; }
  own="cmd/vpnw-scope internal/scope"
  [ -d wasm/scope ] && own="$own wasm/scope"
  echo "Scope: $(lines $own) lines of Go in $(files $own) files (tests not counted)"
  for d in cmd/vpnw-scope internal/scope/*.go internal/scope/office internal/scope/record wasm/scope; do
    [ -e "$d" ] || continue
    case "$d" in *.go) continue ;; esac
    printf '  %-22s %5s lines\n' "$d" "$(lines "$d")"
  done
  printf '  %-22s %5s lines\n' "internal/scope (root)" "$(find internal/scope -maxdepth 1 -name '*.go' ! -name '*_test.go' | xargs cat | wc -l)"
  echo "test tools: internal/testnet $(lines internal/testnet) lines, cmd/scope-office $(lines cmd/scope-office) lines"
  echo "tests: $(find internal/scope cmd/vpnw-scope internal/testnet test/scope -name '*_test.go' | xargs cat | wc -l) lines of Go"
} | tee "$OUT/source.txt"

say "tests"
VPNW_SCOPE_LARGE=$LARGE go test -count=1 -json $UNIT $IT >"$OUT/tests.json" 2>&1 || true
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

say "race detector"
go test -count=1 -race $UNIT $IT 2>&1 | tee "$OUT/race.txt" | tail -8

say "coverage (unit tests, plus the kernel tests and the command they build)"
COV=$(mktemp -d)
mkdir -p "$COV/unit" "$COV/it" "$COV/bin"
go test -count=1 -cover -coverpkg=$COVPKG $UNIT -args -test.gocoverdir="$COV/unit" >/dev/null
VPNW_SCOPE_BINCOVER="$COV/bin" go test -count=1 -cover -coverpkg=vpnw.com/vpnw/internal/scope/... $IT -args -test.gocoverdir="$COV/it" >/dev/null
{
  go tool covdata percent -i="$COV/unit,$COV/it,$COV/bin" -pkg=vpnw.com/vpnw/internal/scope/...,vpnw.com/vpnw/cmd/vpnw-scope | sed 's/\t/  /g'
  go tool covdata textfmt -i="$COV/unit,$COV/it,$COV/bin" -pkg=vpnw.com/vpnw/internal/scope/...,vpnw.com/vpnw/cmd/vpnw-scope -o "$COV/all.txt"
  go tool cover -func="$COV/all.txt" | tail -1 | sed 's/(statements)\s*/statements: /; s/\t\+/ /g'
} | tee "$OUT/coverage.txt"
rm -rf "$COV"

say "fuzzing ($FUZZTIME per target)"
: >"$OUT/fuzz.txt"
for target in internal/scope:FuzzParseFlowJSON internal/scope:FuzzParseConntrackLine internal/scope:FuzzParseDest \
              internal/scope:FuzzParsePeople internal/scope:FuzzParseDraft internal/scope/record:FuzzParsePacket; do
  pkg=./${target%%:*}; fn=${target##*:}
  log=$(go test -run '^$' -fuzz "^$fn\$" -fuzztime "$FUZZTIME" "$pkg" 2>&1 || true)
  execs=$(printf '%s\n' "$log" | grep -o 'execs: [0-9]*' | tail -1 | tr -dc 0-9)
  status=$(printf '%s\n' "$log" | tail -1)
  printf '%-22s %-24s %10s executions  %s\n' "${target%%:*}" "$fn" "$execs" "$status" | tee -a "$OUT/fuzz.txt"
done

say "the kernel against the simulator"
VPNW_SCOPE_LARGE=$LARGE go test -count=1 -v $IT 2>&1 | grep -o 'RESULT .*' | sed 's/^RESULT //' | tee "$OUT/kernel.txt"

say "planted bugs"
python3 tools/planted_bugs_scope.py 2>&1 | tee "$OUT/planted-bugs.txt"

say "performance"
WORK=$(mktemp -d)
python3 tools/scope_perf.py bin "$LARGE" "$WORK" 2>&1 | tee "$OUT/perf.txt"
rm -rf "$WORK"

say "the demo office"
DEMO=$(mktemp -d)
{
  bin/scope-office "$DEMO"
  bin/vpnw-scope learn --people "$DEMO/people.toml" --flows "$DEMO/learn.jsonl" -o "$OUT/demo-draft.toml" 2>&1
  echo
  echo "The week after, replayed under the draft:"
  bin/vpnw-scope replay --people "$DEMO/people.toml" --draft "$OUT/demo-draft.toml" --flows "$DEMO/replay.jsonl"
  echo
  echo "A stolen login (alice) trying every system on 12 ports, under the draft:"
  bin/vpnw-scope replay --people "$DEMO/people.toml" --draft "$OUT/demo-draft.toml" --flows "$DEMO/stolen.jsonl" --top 0 | head -1
  grep '^stolen:' "$OUT/kernel.txt"
} | tee "$OUT/demo.txt"
cp "$DEMO/people.toml" "$OUT/demo-people.toml"
bin/vpnw-scope export --people "$DEMO/people.toml" --draft "$OUT/demo-draft.toml" -o "$OUT/demo-rules.nft"
rm -rf "$DEMO"

say "the browser demo"
if command -v tinygo >/dev/null && command -v node >/dev/null && [ -f bin/scope.wasm ]; then
  python3 ../web/tools/build_scope_js.py ../web/tools/wasm_exec_tinygo.js bin/scope.wasm ../web/scope/engine.scope.v1.js "$(sed -n 's/^const Version = "\(.*\)"/\1/p' internal/scope/flow.go)"
  node ../web/tools/scope_battery.js ../web/tools/wasm_exec_tinygo.js bin/scope.wasm 2>&1 | tee "$OUT/demo-browser.txt"
  SHOTS=$(mktemp -d)
  NODE_PATH=$(npm root -g) node ../web/tools/check_scope_demo.js "file://$(cd ../web/scope && pwd)/index.html" "$SHOTS" 2>&1 | tee "$OUT/demo-check.txt"
  rm -rf "$SHOTS"
else
  echo "skipped: needs TinyGo, Node and Playwright" | tee "$OUT/demo-check.txt"
fi

say "done: $OUT"
