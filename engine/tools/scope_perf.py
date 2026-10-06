#!/usr/bin/env python3
# Copyright VPNW.com 2026
# SPDX-License-Identifier: Apache-2.0

"""Performance figures for Scope on a generated office: how fast it learns,
replays and exports, how much memory learning takes, how big the draft and
the nftables script are, and how long the kernel takes to load the script.
Everything runs on this machine against generated flows.

    python3 tools/scope_perf.py BIN_DIR PEOPLE WORK_DIR > results/scope-alpha/perf.txt

BIN_DIR holds vpnw-scope and scope-office. WORK_DIR receives the generated
office (about 100 MB of flows per 1,000 people).
"""
import os
import re
import statistics
import subprocess
import sys
import time

BIN, PEOPLE, WORK = sys.argv[1], int(sys.argv[2]), sys.argv[3]
SCOPE = os.path.join(BIN, "vpnw-scope")
OFFICE = os.path.join(BIN, "scope-office")
RUNS = 3


def timed(args):
    """Run a command; return seconds, peak memory in MB, and its stderr."""
    start = time.perf_counter()
    p = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    _, status, usage = os.wait4(p.pid, 0)
    secs = time.perf_counter() - start
    err = p.stderr.read()
    p.stderr.close()
    if os.waitstatus_to_exitcode(status) != 0:
        sys.exit(f"failed: {' '.join(args)}\n{err}")
    return secs, usage.ru_maxrss / 1024, err


def median_of(args):
    runs = [timed(args) for _ in range(RUNS)]
    secs = statistics.median(r[0] for r in runs)
    mem = max(r[1] for r in runs)
    return secs, mem, runs[-1][2]


def count_lines(path):
    with open(path, "rb") as f:
        return sum(1 for _ in f)


def main():
    os.makedirs(WORK, exist_ok=True)
    gen = subprocess.run([OFFICE, "--large", str(PEOPLE), "--seed", "1", WORK], capture_output=True, text=True, check=True)
    people = os.path.join(WORK, "people.toml")
    learn = os.path.join(WORK, "learn.jsonl")
    replay = os.path.join(WORK, "replay.jsonl")
    draft = os.path.join(WORK, "draft.toml")
    rules = os.path.join(WORK, "rules.nft")
    n_learn, n_replay = count_lines(learn), count_lines(replay)
    print(f"Office: {gen.stdout.strip()} (generated, seed 1)")
    print(f"Flow files: {os.path.getsize(learn):,} bytes to learn from, {os.path.getsize(replay):,} bytes to replay")
    print(f"Each figure is the median of {RUNS} runs of the vpnw-scope command, reading and writing files.")
    print()

    secs, mem, err = median_of([SCOPE, "learn", "--people", people, "--flows", learn, "-o", draft])
    summary = re.search(r"in [0-9.]+m?s: (.*)\.", err).group(1)
    print(f"learn:   {n_learn:,} flows in {secs:.2f} s, {n_learn / secs:,.0f} flows per second, peak memory {mem:.0f} MB")
    print(f"         draft: {summary}; {os.path.getsize(draft):,} bytes")

    secs, mem, _ = median_of([SCOPE, "replay", "--people", people, "--draft", draft, "--flows", replay])
    out = subprocess.run([SCOPE, "replay", "--people", people, "--draft", draft, "--flows", replay], capture_output=True, text=True).stdout
    first = out.splitlines()[0]
    print(f"replay:  {n_replay:,} flows in {secs:.2f} s, {n_replay / secs:,.0f} flows per second, peak memory {mem:.0f} MB")
    print(f"         {first}")

    secs, mem, _ = median_of([SCOPE, "export", "--people", people, "--draft", draft, "-o", rules])
    script = open(rules).read()
    elements = script.count(" . ")
    print(f"export:  {secs * 1000:.0f} ms for {os.path.getsize(rules):,} bytes of nftables script, {elements:,} set elements")

    base = [timed(["unshare", "--user", "--map-root-user", "--net", "true"])[0] for _ in range(RUNS)]
    load = [timed(["unshare", "--user", "--map-root-user", "--net", "nft", "-f", rules])[0] for _ in range(RUNS)]
    b, l = statistics.median(base), statistics.median(load)
    print(f"load:    nft -f into an empty network namespace: {l * 1000:.0f} ms, of which about {b * 1000:.0f} ms is starting the namespace")


if __name__ == "__main__":
    main()
