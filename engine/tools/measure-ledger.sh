#!/usr/bin/env bash
# Copyright VPNW.com 2026
# SPDX-License-Identifier: Apache-2.0

# Reproduce every figure quoted for VPN Works Ledger in its Alpha report.
# Writes results/ledger-alpha/*.txt. Needs Linux with unprivileged user
# namespaces, nftables (nft), Go 1.24 and python3; TinyGo, Node and
# Playwright for the browser demo (optional). Takes about 13 minutes, most
# of it fuzzing and the planted bugs.
#
#   tools/measure-ledger.sh                  everything
#   FUZZTIME=10s tools/measure-ledger.sh     shorter fuzzing
#   RECORDS=100000 tools/measure-ledger.sh   smaller files for the speed figures
set -eu
cd "$(dirname "$0")/.."
OUT=results/ledger-alpha
FUZZTIME=${FUZZTIME:-60s}
RECORDS=${RECORDS:-1000000}
mkdir -p "$OUT" bin
export NO_COLOR=1
UNIT="./internal/ledger/... ./cmd/vpnw-ledger/"
IT=./test/ledger/
COVPKG=vpnw.com/vpnw/internal/ledger/...,vpnw.com/vpnw/cmd/vpnw-ledger
TRACE=../recordings/1-trace-1.jsonl
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
} | tee "$OUT/environment.txt"

say "builds and sizes"
{
  for arch in amd64 arm64; do
    GOOS=linux GOARCH=$arch CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "bin/vpnw-ledger-linux-$arch" ./cmd/vpnw-ledger
    printf 'vpnw-ledger linux/%s: %s bytes; gzip -9: %s bytes\n' "$arch" \
      "$(stat -c %s "bin/vpnw-ledger-linux-$arch")" "$(gzip -9 -c "bin/vpnw-ledger-linux-$arch" | wc -c)"
  done
  for os_arch in darwin/amd64 darwin/arm64 windows/amd64; do
    GOOS=${os_arch%/*} GOARCH=${os_arch#*/} CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /dev/null ./cmd/vpnw-ledger \
      && echo "vpnw-ledger $os_arch: compiles (every command; the lock that keeps two seals off one ledger is Unix only)"
  done
  if command -v tinygo >/dev/null && [ -d wasm/ledger ]; then
    tinygo build -target=wasm -no-debug -opt=z -o bin/ledger.wasm ./wasm/ledger
    printf 'browser engine (TinyGo, WebAssembly): %s bytes; gzip -9: %s bytes\n' \
      "$(stat -c %s bin/ledger.wasm)" "$(gzip -9 -c bin/ledger.wasm | wc -c)"
  fi
  echo "third-party modules: $(go list -m all | tail -n +2 | wc -l)"
  echo "packages of the engine the command uses: $(go list -deps ./cmd/vpnw-ledger | grep '^vpnw.com' | tr '\n' ' ')"
} | tee "$OUT/size.txt"
CGO_ENABLED=0 go build -trimpath -o bin/vpnw-ledger ./cmd/vpnw-ledger
go build -o bin/scope-office ./cmd/scope-office

say "source lines"
{
  lines() { find "$@" -name '*.go' ! -name '*_test.go' 2>/dev/null | xargs cat | wc -l; }
  files() { find "$@" -name '*.go' ! -name '*_test.go' 2>/dev/null | wc -l; }
  own="cmd/vpnw-ledger internal/ledger"
  [ -d wasm/ledger ] && own="$own wasm/ledger"
  echo "Ledger: $(lines $own) lines of Go in $(files $own) files (tests not counted)"
  for d in cmd/vpnw-ledger internal/ledger/tamper wasm/ledger; do
    [ -e "$d" ] && printf '  %-26s %5s lines\n' "$d" "$(lines "$d")"
  done
  printf '  %-26s %5s lines\n' "internal/ledger (root)" "$(find internal/ledger -maxdepth 1 -name '*.go' ! -name '*_test.go' | xargs cat | wc -l)"
  for f in hash.go key.go checkpoint.go file.go verify.go proof.go seal.go; do
    printf '    %-24s %5s lines\n' "$f" "$(wc -l < "internal/ledger/$f")"
  done
  v=$(cat internal/ledger/{hash,key,checkpoint,file,verify,proof}.go | wc -l)
  echo "  what verify and check-proof run, with the file formats and the parts seal shares (all of internal/ledger but seal.go): $v lines"
  echo "tests: $(find internal/ledger cmd/vpnw-ledger test/ledger -name '*_test.go' | xargs cat | wc -l) lines of Go"
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

say "race detector"
go test -count=1 -race $UNIT $IT 2>&1 | tee "$OUT/race.txt" | tail -8

say "coverage (unit tests, plus the live tests and the command they run)"
COV=$(mktemp -d)
mkdir -p "$COV/unit" "$COV/it" "$COV/bin"
go test -count=1 -cover -coverpkg=$COVPKG $UNIT -args -test.gocoverdir="$COV/unit" >/dev/null
VPNW_LEDGER_BINCOVER="$COV/bin" go test -count=1 -cover -coverpkg=$COVPKG $IT -args -test.gocoverdir="$COV/it" >/dev/null
{
  go tool covdata percent -i="$COV/unit,$COV/it,$COV/bin" -pkg=$COVPKG | sed 's/\t/  /g'
  go tool covdata textfmt -i="$COV/unit,$COV/it,$COV/bin" -pkg=$COVPKG -o "$COV/all.txt"
  go tool cover -func="$COV/all.txt" | tail -1 | sed 's/(statements)\s*/statements: /; s/\t\+/ /g'
} | tee "$OUT/coverage.txt"
rm -rf "$COV"

say "fuzzing ($FUZZTIME per target)"
: >"$OUT/fuzz.txt"
for fn in FuzzParseKey FuzzParseCheckpoint FuzzReadLedger FuzzReadWitness FuzzSealVerify FuzzVerify FuzzProof; do
  # The inputs are whole files, and Go's default of a minute to shrink each
  # new input would take the whole budget: cap it at 100 runs an input.
  log=$(go test -run '^$' -fuzz "^$fn\$" -fuzztime "$FUZZTIME" -fuzzminimizetime 100x ./internal/ledger/ 2>&1 || true)
  execs=$(printf '%s\n' "$log" | grep -o 'execs: [0-9]*' | tail -1 | tr -dc 0-9)
  status=$(printf '%s\n' "$log" | tail -1)
  printf '%-16s %-20s %10s executions  %s\n' "internal/ledger" "$fn" "$execs" "$status" | tee -a "$OUT/fuzz.txt"
done

say "the tamper matrix"
go test -count=1 -v -run '^TestTamperMatrix$' ./cmd/vpnw-ledger/ 2>&1 | grep -o 'RESULT tamper | .*' | python3 -c "$(cat <<'PY'
import sys
rows = [l.rstrip("\n").split(" | ")[1:] for l in sys.stdin]
caught = sum(1 for r in rows if r[2] == "yes")
print("The Agent's recorded run (recordings/1-trace-1.jsonl, 28 events) sealed with a checkpoint every 8 records,")
print("then changed around line 25, its connection to evil.example, one case at a time. Each case was checked")
print("with vpnw-ledger verify; the wrong-key case with another public key, the last case with a witness file")
print("holding the untouched ledger's last checkpoint.")
print()
print("| Case | What vpnw-ledger verify said | Caught |")
print("|---|---|---|")
for case, said, yes in rows:
    print(f"| {case} | {said} | {yes} |")
print()
print(f"{caught} of {len(rows)} cases caught, each at the line the test expects")
PY
)" | tee "$OUT/tamper.txt"

say "live: real vpnw and vpnw-scope output, sealed as it is written"
go test -count=1 -v $IT 2>&1 | grep -o 'RESULT .*' | sed 's/^RESULT //' | tee "$OUT/live.txt"

say "planted bugs"
python3 tools/planted_bugs_ledger.py 2>&1 | tee "$OUT/planted-bugs.txt"

say "performance"
WORK=$(mktemp -d)
python3 tools/ledger_perf.py bin "$WORK" "$RECORDS" 2>&1 | tee "$OUT/perf.txt"
rm -rf "$WORK"

say "the demo trace"
DEMO=$(mktemp -d)
B=$PWD/bin/vpnw-ledger
cp "$TRACE" "$DEMO/"
(
  cd "$DEMO"
  echo "The Agent's recorded run, recordings/1-trace-1.jsonl: $(wc -l <1-trace-1.jsonl) events, $(wc -c <1-trace-1.jsonl) bytes."
  "$B" keygen -o agent >/dev/null
  echo
  echo "\$ vpnw-ledger seal --key agent.key --every 8 1-trace-1.jsonl"
  "$B" seal --key agent.key --every 8 1-trace-1.jsonl 2>&1 >/dev/null | sed 's/ in [0-9.]*m\?s\././'
  python3 - <<'PY'
import json
for line in open("1-trace-1.jsonl.ledger"):
    if line.startswith('{"cp":'):
        c = json.loads(line)
        print(f"  checkpoint {c['cp']}: records 1 to {c['size']}, root {c['root']}, chain {c['chain']}")
PY
  echo "Ledger file: $(wc -l <1-trace-1.jsonl.ledger) lines, $(wc -c <1-trace-1.jsonl.ledger) bytes."
  echo
  echo "\$ vpnw-ledger verify --pub agent.pub 1-trace-1.jsonl"
  "$B" verify --pub agent.pub 1-trace-1.jsonl
  echo
  echo "\$ vpnw-ledger prove --line 25 -o proof.json 1-trace-1.jsonl"
  "$B" prove --line 25 -o proof.json 1-trace-1.jsonl 2>&1
  python3 -c 'import json; p = json.load(open("proof.json")); print("  leaf", p["leaf"]); [print("  path", h) for h in p["path"]]'
  echo
  echo "\$ vpnw-ledger check-proof --pub agent.pub proof.json"
  "$B" check-proof --pub agent.pub proof.json
) | tee "$OUT/demo.txt"
rm -rf "$DEMO"

say "the browser demo"
if command -v tinygo >/dev/null && command -v node >/dev/null && [ -f bin/ledger.wasm ]; then
  python3 ../web/tools/build_ledger_js.py ../web/tools/wasm_exec_tinygo.js bin/ledger.wasm "$TRACE" ../web/ledger/engine.ledger.v1.js "$(sed -n 's/^const Version = "\(.*\)"/\1/p' internal/ledger/hash.go)"
  node ../web/tools/ledger_battery.js ../web/tools/wasm_exec_tinygo.js bin/ledger.wasm "$TRACE" 2>&1 | tee "$OUT/demo-browser.txt"
  SHOTS=$(mktemp -d)
  NODE_PATH=$(npm root -g) node ../web/tools/check_ledger_demo.js "file://$(cd ../web/ledger && pwd)/index.html" "$SHOTS" 2>&1 | tee "$OUT/demo-check.txt"
  rm -rf "$SHOTS"
else
  echo "skipped: needs TinyGo, Node and Playwright" | tee "$OUT/demo-check.txt"
fi

say "done: $OUT"
