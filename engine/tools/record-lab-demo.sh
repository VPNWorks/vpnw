#!/usr/bin/env bash
# Copyright VPNW.com 2026
# SPDX-License-Identifier: Apache-2.0

# Record the runs the browser demo replays, in the test network, with the
# vpnw-lab command: the correct client and the dns-leak client through the
# VPN server going silent for 5 s, the no-kill-switch client killed for 2 s,
# and the follows-routes client with a route pushed for 2 s. Every recording
# is kept as it came out, in internal/lab/demo/, and the browser engine is
# built with them inside. Needs what tools/measure-lab.sh needs.
#
#   tools/record-lab-demo.sh
set -eu
cd "$(dirname "$0")/.."
mkdir -p bin internal/lab/demo
go build -o bin/vpnw-lab ./cmd/vpnw-lab
rec() {
  app=$1 scenario=$2
  shift 2
  out=internal/lab/demo/$app-$scenario.jsonl
  code=0
  bin/vpnw-lab run --app "$app" --scenario "$scenario" --seed 7 "$@" -o "$out" || code=$?
  if [ "$code" != 0 ] && [ "$code" != 120 ]; then
    echo "recording $app through $scenario failed: exit $code" >&2
    exit 1
  fi
}
rec correct server-silent --fault-for 5s
rec dns-leak server-silent --fault-for 5s
rec no-kill-switch app-killed
rec follows-routes route-push
wc -l internal/lab/demo/*.jsonl
