#!/usr/bin/env python3
# Copyright VPNW.com 2026
# SPDX-License-Identifier: Apache-2.0

"""Performance figures for Ledger: how fast it seals and verifies a million
records, and how much memory that takes, for Agent events and for Scope
flows; what a checkpoint costs; and how big a proof is at 1,000 and at
1,000,000 records. Everything runs on this machine against generated files.

    python3 tools/ledger_perf.py BIN_DIR WORK_DIR [RECORDS] > results/ledger-alpha/perf.txt

BIN_DIR holds vpnw-ledger and scope-office. WORK_DIR receives the generated
files and their ledgers, about 460 MB for a million records of each kind. Run from the engine
directory: it reads ../recordings/1-trace-1.jsonl and runs a Go benchmark.
"""
import json
import os
import re
import statistics
import subprocess
import sys
import time

BIN, WORK = sys.argv[1], sys.argv[2]
N = int(sys.argv[3]) if len(sys.argv) > 3 else 1_000_000
LEDGER = os.path.join(BIN, "vpnw-ledger")
OFFICE = os.path.join(BIN, "scope-office")
TRACE = "../recordings/1-trace-1.jsonl"
RUNS = 3


def measured(args, before=None):
    """Median time and highest peak memory of RUNS runs."""
    times, mems, out = [], [], ""
    for _ in range(RUNS):
        if before:
            before()
        start = time.perf_counter()
        p = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
        _, status, usage = os.wait4(p.pid, 0)
        times.append(time.perf_counter() - start)
        out = p.stderr.read()
        p.stderr.close()
        if os.waitstatus_to_exitcode(status) != 0:
            sys.exit(f"failed: {' '.join(args)}\n{out}")
        mems.append(usage.ru_maxrss / 1024)
    return statistics.median(times), max(mems), out


def agent_events(path, n):
    """The recorded Agent run, repeated as new runs (new run ID, process ID,
    times and connection numbers) until there are n lines."""
    lines = open(TRACE).read().splitlines()
    t0 = 1759312800  # 2025-10-01T10:00:00Z
    with open(path, "w") as f:
        written, run = 0, 0
        while written < n:
            for line in lines:
                if written == n:
                    break
                e = json.loads(line)
                e["run"] = "r-%06x" % run
                e["ts"] = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(t0 + run)) + e["ts"][19:]
                if "pid" in e:
                    e["pid"] = 10000 + run % 50000
                if "conn" in e:
                    e["conn"] = run * 5 + e["conn"]
                f.write(json.dumps(e, separators=(",", ":")) + "\n")
                written += 1
            run += 1


def scope_flows(path, n):
    """Flows of the generated 2,000-person office, the first n of them."""
    office = os.path.join(WORK, "office")
    os.makedirs(office, exist_ok=True)
    subprocess.run([OFFICE, "--large", "2000", "--seed", "1", office], check=True, capture_output=True)
    with open(os.path.join(office, "learn.jsonl")) as src, open(path, "w") as dst:
        for i, line in enumerate(src):
            if i == n:
                break
            dst.write(line)
    for name in os.listdir(office):
        os.remove(os.path.join(office, name))
    os.rmdir(office)


def benchmark():
    """Median ns per checkpoint, from the Go benchmark at a million records."""
    out = subprocess.run(["go", "test", "-run", "^$", "-bench", "^BenchmarkCheckpoint$", "-count", str(RUNS), "./internal/ledger/"],
                         capture_output=True, text=True, check=True).stdout
    return statistics.median(float(x) for x in re.findall(r"BenchmarkCheckpoint\S*\s+\d+\s+([\d.]+) ns/op", out))


def main():
    os.makedirs(WORK, exist_ok=True)
    key = os.path.join(WORK, "k")
    subprocess.run([LEDGER, "keygen", "-o", key], check=True, capture_output=True)
    sets = [("Agent events", os.path.join(WORK, "agent.jsonl"), agent_events),
            ("Scope flows", os.path.join(WORK, "flows.jsonl"), scope_flows)]
    for name, path, make in sets:
        make(path, N)
    print(f"Agent events: {N:,} records, {os.path.getsize(sets[0][1]):,} bytes: recordings/1-trace-1.jsonl, a real run of the Agent, "
          "repeated as new runs with new run IDs, times and connection numbers (generated)")
    print(f"Scope flows: {N:,} records, {os.path.getsize(sets[1][1]):,} bytes: the first {N:,} flows of the generated "
          "2,000-person office, from scope-office --large 2000 --seed 1 (generated)")
    print(f"Each time is the median of {RUNS} runs of the vpnw-ledger command, reading and writing files; memory is the highest of the {RUNS}.")
    print("seal signs a checkpoint every 1,000 records, the default.")
    print()
    for name, path, _ in sets:
        led = path + ".ledger"

        def fresh():
            if os.path.exists(led):
                os.remove(led)
        secs, mem, _ = measured([LEDGER, "seal", "--key", key + ".key", path], before=fresh)
        cps = sum(1 for l in open(led) if l.startswith('{"cp":'))
        print(f"seal    {name}: {N:,} records in {secs:.2f} s, {N / secs:,.0f} records per second, peak memory {mem:.0f} MB; "
              f"ledger {os.path.getsize(led):,} bytes ({os.path.getsize(led) / os.path.getsize(path) * 100:.0f}% of the records), {cps:,} checkpoints")
        secs, mem, _ = measured([LEDGER, "verify", "--pub", key + ".pub", path])
        print(f"verify  {name}: {N:,} records in {secs:.2f} s, {N / secs:,.0f} records per second, peak memory {mem:.0f} MB")
    print()

    cp_lines = [l for l in open(sets[0][1] + ".ledger") if l.startswith('{"cp":')]
    ns = benchmark()
    print(f"checkpoint: {ns / 1000:.0f} µs each at 1,000,000 records (Go benchmark, median of {RUNS}: the root from the tree's "
          f"{bin(1_000_000).count('1')} complete subtrees, the signed text, the Ed25519 signature and the JSON line); "
          f"{statistics.mean(len(l) for l in cp_lines):.0f} bytes per checkpoint line in the ledger")
    for size in (1000, N):
        path = sets[0][1]
        if size != N:
            path = os.path.join(WORK, "small.jsonl")
            with open(sets[0][1]) as src, open(path, "w") as dst:
                for i, line in enumerate(src):
                    if i == size:
                        break
                    dst.write(line)
            subprocess.run([LEDGER, "seal", "--key", key + ".key", path], check=True, capture_output=True)
        line = size // 2
        proof = os.path.join(WORK, f"proof-{size}.json")
        psecs, pmem, _ = measured([LEDGER, "prove", "--line", str(line), "-o", proof, path])
        csecs, _, _ = measured([LEDGER, "check-proof", "--pub", key + ".pub", proof])
        p = json.load(open(proof))
        rec = len(p["record"].encode())
        print(f"proof at {size:,} records (line {line:,}): {len(p['path'])} hashes in the path; the proof file is {os.path.getsize(proof):,} bytes, "
              f"with the {rec:,}-byte record in it; made in {psecs * 1000:.0f} ms (peak memory {pmem:.0f} MB), checked in {csecs * 1000:.0f} ms")


if __name__ == "__main__":
    main()
