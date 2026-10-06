#!/usr/bin/env bash
# Copyright VPNW.com 2026
# SPDX-License-Identifier: Apache-2.0

# VPN Works Alpha: the demo, offline, in about a minute.
#
#   ./run-demo.sh               play it, pausing between steps
#   ./run-demo.sh --no-pause    play it straight through
#   ./run-demo.sh --record=DIR  also save each step's output and trace in DIR
#
# Everything runs inside a private network namespace with stand-in servers,
# so the demo never touches your network, your files or your settings.
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
VPNW="${VPNW:-$(cd "$HERE/.." && pwd)/vpnw}"
PAUSE=1
RECORD=""
for a in "$@"; do
  case "$a" in
    --no-pause) PAUSE=0 ;;
    --record=*) RECORD="${a#--record=}"; PAUSE=0 ;;
    -h|--help) sed -n '2,10p' "$0"; exit 0 ;;
    *) echo "unknown option: $a (see --help)"; exit 2 ;;
  esac
done

# ---------------------------------------------------------------------------
# Outside the demo world: check what is needed, then step inside.
# ---------------------------------------------------------------------------
if [ -z "${VPNW_DEMO_WORLD:-}" ]; then
  [ "$(uname -s)" = Linux ] || { echo "The Alpha demo needs Linux. On another computer, use the browser demo at https://vpnw.com/demo/."; exit 1; }
  [ -x "$VPNW" ] || { echo "Cannot find the vpnw binary at $VPNW."; exit 1; }
  command -v python3 >/dev/null || { echo "The demo's stand-in agent and servers need python3."; exit 1; }
  command -v unshare >/dev/null || { echo "The demo needs unshare (from util-linux) to build its private network."; exit 1; }
  if ! "$VPNW" doctor >/tmp/vpnw-doctor.$$ 2>&1; then
    cat /tmp/vpnw-doctor.$$; rm -f /tmp/vpnw-doctor.$$
    echo
    echo "vpnw cannot seal a program on this machine as this user."
    echo "On Ubuntu 23.10 and later, AppArmor limits user namespaces. For a quick look, run the demo with sudo;"
    echo "it still stays inside its own private network. The Beta ships an AppArmor profile instead."
    exit 1
  fi
  rm -f /tmp/vpnw-doctor.$$
  if [ -n "$RECORD" ]; then mkdir -p "$RECORD" && RECORD="$(cd "$RECORD" && pwd)"; fi
  export VPNW_DEMO_WORLD=1 VPNW RECORD PAUSE
  exec unshare --user --map-root-user --net --mount --propagation private bash "$0" "$@"
fi

# ---------------------------------------------------------------------------
# Inside the demo world.
# ---------------------------------------------------------------------------
cd "$HERE"
rm -rf .world && mkdir -p .world/state
python3 world.py setup || { echo "Could not build the demo's private network."; exit 1; }
python3 world.py serve >.world/world.log 2>&1 &
WORLD=$!
trap 'kill $WORLD 2>/dev/null' EXIT
for _ in $(seq 50); do [ -f .world/ready ] && break; sleep 0.1; done
[ -f .world/ready ] || { echo "The stand-in servers did not start:"; cat .world/world.log; exit 1; }

export SSL_CERT_FILE="$HERE/certs/ca.pem" CURL_CA_BUNDLE="$HERE/certs/ca.pem"
export DEPLOY_TOKEN="ghp_demo_0000_not_a_real_token_0000"
export DEMO_SOCKET="$HERE/.world/docker.sock"   # the stand-in local service
export XDG_STATE_HOME="$HERE/.world/state"   # vpnw's "last trace" stays in the demo folder
unset XDG_RUNTIME_DIR HTTP_PROXY HTTPS_PROXY ALL_PROXY NO_PROXY http_proxy https_proxy all_proxy no_proxy
PATH="$(dirname "$VPNW"):$PATH"

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then B=$'\e[1m'; D=$'\e[2m'; C=$'\e[36m'; R=$'\e[0m'; else B=; D=; C=; R=; fi
N=0
K=0
STEP=""
say()   { printf '%s\n' "$*" | fold -s -w 78; }
title() { N=$((N+1)); K=0; STEP="$N-$1"; shift; printf '\n%s%s%s\n' "$B" "$N. $*" "$R"; }
note()  { printf '%s' "$D"; say "$*"; printf '%s' "$R"; }
pause() { if [ "$PAUSE" = 1 ]; then printf '\n%s[Enter] next step%s ' "$D" "$R"; read -r _; fi; }
# run CMD... : print the command, run it, keep its output for --record.
run() {
  printf '\n%s$ %s%s\n' "$C" "$*" "$R"
  local code
  touch .world/mark
  if [ -n "$RECORD" ]; then
    { printf '$ %s\n' "$*"; "$@" 2>&1; echo "[exit $?]"; } >>"$RECORD/$STEP.txt.tmp"
    code=$(tail -n 1 "$RECORD/$STEP.txt.tmp" | tr -dc 0-9)
    sed '1d;$d' "$RECORD/$STEP.txt.tmp"
    cat "$RECORD/$STEP.txt.tmp" >>"$RECORD/$STEP.txt"; rm -f "$RECORD/$STEP.txt.tmp"
  else
    "$@"; code=$?
  fi
  if [ "$code" != 0 ]; then printf '%s(exit %s)%s\n' "$D" "$code" "$R"; fi
  # vpnw keeps each run's trace as "last"; with --record, keep a copy per command.
  if [ -n "$RECORD" ] && [ .world/state/vpnw/last.jsonl -nt .world/mark ]; then
    K=$((K+1)); cp .world/state/vpnw/last.jsonl "$RECORD/$STEP-$K.jsonl"
  fi
}

printf '%sVPN Works Alpha demo%s: one agent, its own network path, a policy and a record.\n' "$B" "$R"
note "Everything below runs in a private network built for this demo. The servers are stand-ins; vpnw is the real Alpha."
pause

title trace "See what the agent does"
note "A coding agent runs a task. Its task file hides an instruction to send a deploy token to evil.example. First, run it under vpnw trace. Nothing is blocked yet, but every connection is recorded."
run vpnw trace -- python3 agent.py
note "Five connections. The ticket failed: tracker.office.internal is an internal name, unknown on the public internet. And the token went to evil.example. Nothing stopped it, but now there is a record."
pause

title learn "Learn a policy from the trace"
run vpnw learn --name agent
note "Learn turns the trace into a draft: what the agent reached is allowed, everything else is denied. The draft allows evil.example too, because the agent went there, which is why a person reads it. It also notes the tracker, which the agent tried but could not reach on this path. The reviewed policy, agent.toml, drops evil.example and adds the tracker:"
run grep -v '^#' agent.toml
pause

title guard "Guard: enforce the policy"
run vpnw guard --policy agent.toml -- python3 agent.py
note "The token is blocked and the attempt is logged. The rest of the agent's work goes through, except the ticket, which still fails because the tracker lives inside the office network. vpnw exits with 120 when it denied a connection, so a script or CI job notices."
pause

title route "Route: this agent, through the office"
note "vpnw run sends one program through the path you choose. Only this command goes through the office exit, not the whole machine."
run vpnw run --config office.toml --via office -- curl -s https://tracker.office.internal/api/tickets
note "Now the agent again, with route, policy and record in one command:"
run vpnw guard --config office.toml --via office --policy agent.toml -- python3 agent.py
note "Every allowed step works, the ticket included. The token still goes nowhere: the policy is checked before the path is used."
pause

title seal "Sealed: an agent that ignores proxy settings"
note "Proxy settings are only a request. A program can skip them and connect directly. Without vpnw, that works:"
run python3 sneaky.py
note "Inside vpnw, the program has no network of its own, and it cannot open a Unix socket to ask a local service such as Docker to connect for it. Its only way out is vpnw:"
run vpnw guard --policy agent.toml -- python3 sneaky.py
pause

title metadata "Private addresses: the cloud metadata service"
note "An agent tricked into reading a cloud metadata service can leak the machine's credentials. deny_private refuses loopback, private networks and the link-local range where those services live, even when the default is allow."
run vpnw guard --deny-private --default allow -- curl -s http://169.254.169.254/latest/meta-data/iam/
echo
say "That is the Alpha: run, trace, guard and learn, in one binary with no dependencies."
if [ -n "$RECORD" ]; then say "Saved each step's output and trace to $RECORD."; fi
