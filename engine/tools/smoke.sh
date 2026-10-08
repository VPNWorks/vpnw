#!/bin/sh
# Copyright VPNW.com 2026
# SPDX-License-Identifier: Apache-2.0
#
# smoke.sh DIR: checks the release binaries in DIR before they go public.
# Every command must report its version, and the parts that run on any
# system must work end to end: Scope learns, replays and exports from the
# demo office, and Ledger seals a log, verifies it, proves a line and catches
# a changed record. The release workflow runs it on Linux and macOS.
set -eu

bin=$(cd "${1:?usage: smoke.sh DIR}" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"

fail() { echo "smoke: $*" >&2; exit 1; }

for cmd in vpnw vpnw-scope vpnw-lab vpnw-ledger vpnw-exit; do
  out=$("$bin/$cmd" version) || fail "$cmd version failed"
  case "$out" in
    "$cmd "[0-9]*.[0-9]*.[0-9]*" ("*) echo "$out" ;;
    *) fail "$cmd version printed: $out" ;;
  esac
done

# Scope, offline: the demo office, a draft learned from it, a replay that
# blocks the stolen logins, and the gateway's rules.
"$bin/scope-office" office > /dev/null
"$bin/vpnw-scope" learn --people office/people.toml --flows office/learn.jsonl -o draft.toml > /dev/null 2>&1 \
  || fail "vpnw-scope learn failed"
"$bin/vpnw-scope" replay --people office/people.toml --draft draft.toml --flows office/replay.jsonl > /dev/null \
  || fail "vpnw-scope replay failed"
"$bin/vpnw-scope" export --people office/people.toml --draft draft.toml -o rules.nft \
  || fail "vpnw-scope export failed"
grep -q 'table' rules.nft || fail "vpnw-scope export wrote no nftables table"
echo "scope: learned, replayed and exported"

# Ledger: seal, verify, prove one line, then change a record and expect it caught.
head -n 200 office/learn.jsonl > records.jsonl
"$bin/vpnw-ledger" keygen -o k > /dev/null
"$bin/vpnw-ledger" seal --key k.key --every 50 records.jsonl > /dev/null
"$bin/vpnw-ledger" verify --pub k.pub records.jsonl > /dev/null || fail "vpnw-ledger verify failed on a good log"
"$bin/vpnw-ledger" prove --line 7 -o p.json records.jsonl > /dev/null
"$bin/vpnw-ledger" check-proof --pub k.pub p.json > /dev/null || fail "vpnw-ledger check-proof failed"
sed '42s/[0-9]/9/' records.jsonl > changed.jsonl && mv changed.jsonl records.jsonl
if "$bin/vpnw-ledger" verify --pub k.pub records.jsonl > /dev/null 2>&1; then
  fail "vpnw-ledger verify passed a changed log"
fi
echo "ledger: sealed, verified, proved, and caught a change"

echo "smoke: all checks passed"
