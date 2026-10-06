#!/usr/bin/env bash
# Copyright VPNW.com 2026
# SPDX-License-Identifier: Apache-2.0

# Reproduce every figure quoted for VPN Works Exit in its Alpha report and on
# vpnw.com. Writes results/exit-alpha/*.txt. Needs Linux with unprivileged
# user namespaces, nftables (nft), Go 1.24, python3 and openssl; TinyGo, Node
# and Playwright for the browser demo (optional). Takes about nine minutes
# with a minute of fuzzing per target, on a machine with two CPUs.
#
#   tools/measure-exit.sh               everything
#   FUZZTIME=10s tools/measure-exit.sh  shorter fuzzing
set -eu
cd "$(dirname "$0")/.."
OUT=results/exit-alpha
FUZZTIME=${FUZZTIME:-60s}
mkdir -p "$OUT" bin
export NO_COLOR=1
UNIT="./internal/exit/... ./cmd/vpnw-exit/"
IT=./test/exit/
COVPKG=vpnw.com/vpnw/internal/exit/...,vpnw.com/vpnw/cmd/vpnw-exit
REC=../web/exit/recording
say() { printf '\n== %s\n' "$*"; }

say "environment"
{
  echo "date: $(date -u +%Y-%m-%d)"
  echo "kernel: $(uname -sr), $(uname -m), $(nproc) CPUs"
  go version
  command -v tinygo >/dev/null && tinygo version || echo "tinygo: not installed"
  python3 --version
  nft --version
  openssl version
} | tee "$OUT/environment.txt"

say "builds and sizes"
{
  for arch in amd64 arm64; do
    GOOS=linux GOARCH=$arch CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o "bin/vpnw-exit-linux-$arch" ./cmd/vpnw-exit
    printf 'vpnw-exit linux/%s: %s bytes; gzip -9: %s bytes\n' "$arch" \
      "$(stat -c %s "bin/vpnw-exit-linux-$arch")" "$(gzip -9 -c "bin/vpnw-exit-linux-$arch" | wc -c)"
  done
  for os_arch in darwin/amd64 darwin/arm64 windows/amd64; do
    GOOS=${os_arch%/*} GOARCH=${os_arch#*/} CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /dev/null ./cmd/vpnw-exit \
      && echo "vpnw-exit $os_arch: compiles (not run)"
  done
  if command -v tinygo >/dev/null && [ -d wasm/exit ]; then
    tinygo build -target=wasm -no-debug -opt=z -o bin/exit.wasm ./wasm/exit
    printf 'browser engine (TinyGo, WebAssembly): %s bytes; gzip -9: %s bytes\n' \
      "$(stat -c %s bin/exit.wasm)" "$(gzip -9 -c bin/exit.wasm | wc -c)"
  fi
  echo "third-party modules: $(go list -m all | tail -n +2 | wc -l)"
  echo "packages of the engine the command uses: $(go list -deps ./cmd/vpnw-exit | grep '^vpnw.com' | tr '\n' ' ')"
} | tee "$OUT/size.txt"
CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/vpnw-exit ./cmd/vpnw-exit

say "source lines"
{
  lines() { find "$@" -name '*.go' ! -name '*_test.go' 2>/dev/null | xargs cat | wc -l; }
  files() { find "$@" -name '*.go' ! -name '*_test.go' 2>/dev/null | wc -l; }
  own="cmd/vpnw-exit internal/exit"
  [ -d wasm/exit ] && own="$own wasm/exit"
  echo "Exit: $(lines $own) lines of Go in $(files $own) files (tests not counted)"
  printf '  %-22s %5s lines\n' "internal/exit (root)" "$(find internal/exit -maxdepth 1 -name '*.go' ! -name '*_test.go' | xargs cat | wc -l)"
  for d in internal/exit/server cmd/vpnw-exit wasm/exit; do
    [ -e "$d" ] && printf '  %-22s %5s lines\n' "$d" "$(lines "$d")"
  done
  echo "tests: $(find internal/exit cmd/vpnw-exit test/exit -name '*_test.go' | xargs cat | wc -l) lines of Go"
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
go test -count=1 -race $UNIT $IT 2>&1 | tee "$OUT/race.txt" | tail -6

say "coverage (unit tests, plus the vpnw-exit binary under the network tests)"
COV=$(mktemp -d)
mkdir -p "$COV/unit" "$COV/bin"
go test -count=1 -cover -coverpkg=$COVPKG $UNIT -args -test.gocoverdir="$COV/unit" >/dev/null
VPNW_EXIT_BINCOVER="$COV/bin" go test -count=1 $IT >/dev/null
{
  go tool covdata percent -i="$COV/unit,$COV/bin" -pkg=$COVPKG | sed 's/\t/  /g'
  go tool covdata textfmt -i="$COV/unit,$COV/bin" -pkg=$COVPKG -o "$COV/all.txt"
  go tool cover -func="$COV/all.txt" | tail -1 | sed 's/(statements)\s*/statements: /; s/\t\+/ /g'
} | tee "$OUT/coverage.txt"
rm -rf "$COV"

say "fuzzing ($FUZZTIME per target)"
# Each new input the fuzzer keeps is shrunk with at most 100 runs, so the time
# goes to new inputs: with Go's default of a minute of shrinking per input,
# FuzzJoin, whose inputs are whole records, spent most of its time shrinking.
: >"$OUT/fuzz.txt"
for target in internal/exit:FuzzParseConfig internal/exit:FuzzParseIDs internal/exit:FuzzJoin \
              internal/exit/server:FuzzHTTPFront internal/exit/server:FuzzSOCKSFront; do
  pkg=./${target%%:*}; fn=${target##*:}
  log=$(go test -run '^$' -fuzz "^$fn\$" -fuzztime "$FUZZTIME" -fuzzminimizetime 100x "$pkg" 2>&1 || true)
  execs=$(printf '%s\n' "$log" | grep -o 'execs: [0-9]*' | tail -1 | tr -dc 0-9)
  status=$(printf '%s\n' "$log" | tail -1)
  printf '%-22s %-18s %10s executions  %s\n' "${target%%:*}" "$fn" "$execs" "$status" | tee -a "$OUT/fuzz.txt"
done

say "the private test network (RESULT lines of the network tests)"
go test -count=1 -v $IT ./internal/exit/server/ 2>&1 | grep -o 'RESULT .*' | sed 's/^RESULT //' | tee "$OUT/network.txt"

say "planted bugs"
python3 tools/planted_bugs_exit.py 2>&1 | tee "$OUT/planted-bugs.txt"

say "performance"
python3 tools/exit_perf.py bin/vpnw-exit 2>&1 | tee "$OUT/perf.txt"

say "the demo's recorded run"
ASK="169.254.169.254:80 attacker.test:443 intranet.partner.test:80 files.partner.test:80 api.partner.test:443 api.partner.test:80"
{
  echo "Recorded in the private test network by: VPNW_EXIT_RECORD=web/exit/recording go test -run TestDemoScenario ./test/exit/"
  echo "Recorded on $(python3 -c "import json;print(json.load(open('$REC/marks.json'))['start'][:10])"); these figures are vpnw-exit's own reading of that recording."
  python3 - "$REC" <<'PY'
import datetime, json, os, sys
rec = sys.argv[1]
def ts(s):
    s = s.rstrip("Z")
    head, frac = s.split(".") if "." in s else (s, "0")
    return datetime.datetime.fromisoformat(head + "." + frac[:6].ljust(6, "0") + "+00:00")
m = json.load(open(os.path.join(rec, "marks.json")))
print(f"The run took {round((ts(m['end']) - ts(m['start'])).total_seconds() * 1000)} ms; exit-de was killed "
      f"{round((ts(m['killed']) - ts(m['start'])).total_seconds() * 1000)} ms after the start.")
n = 0
for name in ("exit-de", "exit-nl"):
    for line in open(os.path.join(rec, name + ".jsonl")):
        n += json.loads(line)["type"] in ("policy.allow", "policy.deny")
print(f"Decisions in the exits' records: {n} (policy.allow and policy.deny events)")
PY
  echo
  bin/vpnw-exit join --agent $REC/agent-1.jsonl --agent $REC/agent-2.jsonl --exit $REC/exit-de.jsonl --exit $REC/exit-nl.jsonl || true
  echo
  echo "What exit-de decides for agent-2 (the tampered client holds its token), with the recording's DNS answers:"
  bin/vpnw-exit decide --config $REC/exit-de.toml --client agent-2 --dns $REC/dns.json $ASK || true
  echo
  echo "Switches between exits in the Agents' records:"
  python3 - $REC/agent-1.jsonl $REC/agent-2.jsonl <<'PY'
import json, sys
for fn in sys.argv[1:]:
    evs = [json.loads(line) for line in open(fn)]
    for e in evs:
        if e["type"] == "path.switch":
            f = e["fields"]
            opened = [x["fields"]["ms"] for x in evs if x["type"] == "connection.open" and x["conn"] == e["conn"]]
            print(f"  {fn.split('/')[-1][:-6]} connection #{e['conn']}: gave up on {f['from']} after {f['ms']} ms ({f['error']}); "
                  f"moved to {f['to']}; open {opened[0] if opened else '?'} ms after its dial began")
PY
} 2>&1 | tee "$OUT/demo.txt"
bin/vpnw-exit join --json --agent $REC/agent-1.jsonl --agent $REC/agent-2.jsonl --exit $REC/exit-de.jsonl --exit $REC/exit-nl.jsonl >"$OUT/demo-join.json" || true
bin/vpnw-exit decide --json --config $REC/exit-de.toml --client agent-2 --dns $REC/dns.json $ASK >"$OUT/demo-decide.json" || true

say "the browser demo"
if command -v tinygo >/dev/null && command -v node >/dev/null && [ -f bin/exit.wasm ]; then
  python3 ../web/tools/build_exit_js.py ../web/tools/wasm_exec_tinygo.js bin/exit.wasm ../web/exit/engine.exit.v1.js "$(sed -n 's/^const Version = "\(.*\)"/\1/p' internal/exit/exit.go)"
  python3 ../web/tools/build_exit_data.py $REC ../web/exit/data.exit.v1.js
  node ../web/tools/exit_battery.js ../web/tools/wasm_exec_tinygo.js bin/exit.wasm $REC 2>&1 | tee "$OUT/demo-browser.txt"
  SHOTS=$(mktemp -d)
  NODE_PATH=$(npm root -g) node ../web/tools/check_exit_demo.js "file://$(cd ../web/exit && pwd)/index.html" "$SHOTS" "$OUT" 2>&1 | tee "$OUT/demo-check.txt"
  rm -rf "$SHOTS"
else
  echo "skipped: needs TinyGo, Node and Playwright" | tee "$OUT/demo-check.txt"
fi

say "done: $OUT"
