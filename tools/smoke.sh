#!/bin/sh
# Copyright VPNW.com 2026
# SPDX-License-Identifier: Apache-2.0
#
# smoke.sh DIR: checks the vpnw binary in DIR before it goes public. It must
# report its version, list its built-in plugins, start the plugin host, and
# run the Learn plugin end to end on a small trace. On Linux it also traces
# and guards a real program in the sealed backend when the machine allows
# it. The release workflow runs it on Linux and macOS.
set -eu

bin=$(cd "${1:?usage: smoke.sh DIR}" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"
export XDG_DATA_HOME="$work/data" XDG_CONFIG_HOME="$work/config" XDG_STATE_HOME="$work/state" XDG_CACHE_HOME="$work/cache" NO_COLOR=1

fail() { echo "smoke: $*" >&2; exit 1; }

out=$("$bin/vpnw" version) || fail "vpnw version failed"
case "$out" in
  "vpnw "[0-9]*.[0-9]*.[0-9]*" ("*) echo "$out" ;;
  *) fail "vpnw version printed: $out" ;;
esac

list=$("$bin/vpnw" plugin list) || fail "vpnw plugin list failed"
for p in trace learn; do
  echo "$list" | grep -q "^$p .*built-in" || fail "built-in plugin $p is missing:
$list"
done
echo "plugins: trace and learn built in"

doctor=$("$bin/vpnw" doctor) || true
echo "$doctor" | grep -q "plugins          ok" || fail "the plugin host did not start:
$doctor"
echo "doctor: plugin host up"

# Learn, through the advisor path, from a trace written by hand.
cat > trace.jsonl <<'TRACE'
{"v":1,"ts":"2026-10-09T10:00:00Z","type":"run.start","run":"r-smoke","fields":{"mode":"trace"}}
{"v":1,"ts":"2026-10-09T10:00:00Z","type":"connection.attempt","run":"r-smoke","conn":1,"fields":{"host":"api.github.com","port":443,"proto":"http-connect"}}
{"v":1,"ts":"2026-10-09T10:00:00Z","type":"connection.open","run":"r-smoke","conn":1,"fields":{"ip":"140.82.121.6","host":"api.github.com","ms":12}}
{"v":1,"ts":"2026-10-09T10:00:01Z","type":"connection.attempt","run":"r-smoke","conn":2,"fields":{"host":"evil.example","port":443,"proto":"http-connect"}}
{"v":1,"ts":"2026-10-09T10:00:01Z","type":"policy.deny","run":"r-smoke","conn":2,"fields":{"rule":"default","reason":"no allow rule matches"}}
TRACE
"$bin/vpnw" learn --from trace.jsonl --name smoke -o draft.toml 2> learn.log || fail "vpnw learn failed: $(cat learn.log)"
grep -q '"api.github.com"' draft.toml || fail "the draft does not allow api.github.com"
grep -q '#   "evil.example"' draft.toml || fail "the draft does not list the denied evil.example"
echo "learn: drafted a policy from a trace"

# A real program, where the sealed backend works here.
if [ "$(uname -s)" = Linux ] && "$bin/vpnw" doctor > /dev/null 2>&1; then
  "$bin/vpnw" trace -q -- sh -c 'exit 0' || fail "vpnw trace failed"
  code=0
  "$bin/vpnw" guard --allow example.invalid -- sh -c 'exit 7' || code=$?
  [ "$code" = 7 ] || fail "vpnw guard did not keep the program's exit code ($code)"
  echo "sealed: traced and guarded a program"
fi

echo "smoke: all checks passed"
