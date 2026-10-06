#!/usr/bin/env python3
# Copyright VPNW.com 2026
# SPDX-License-Identifier: Apache-2.0

"""Performance figures for Lab: how long each scenario takes end to end,
how long the test world takes to build, how much memory a run takes, how big
its recording is, and how fast the verdict reads a long recording.

    python3 tools/lab_perf.py BIN_DIR > results/lab-alpha/perf.txt

BIN_DIR holds vpnw-lab. Times are the median of three runs, memory the
highest of three. Memory is the peak resident size of the largest single
process of the run: the bench, which holds the world's servers and
observers, or one of the processes it starts.
"""
import json
import os
import re
import statistics
import subprocess
import sys
import tempfile
import time

BIN = sys.argv[1]
LAB = os.path.join(BIN, "vpnw-lab")
RUNS = 3
SCENARIOS = ["steady", "server-silent", "server-gone", "app-killed", "link-drop", "route-push", "dns-change"]

# Runs a command in a fresh Python, so the peak memory it reports belongs to
# that command's processes alone.
MEASURE = r"""
import resource, subprocess, sys, time
t = time.perf_counter()
p = subprocess.run(sys.argv[1:], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
secs = time.perf_counter() - t
print(f"{secs} {resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss} {p.returncode}")
sys.stdout.write(p.stdout)
sys.stderr.write(p.stderr)
"""


def measure(args, ok=(0,)):
    p = subprocess.run([sys.executable, "-c", MEASURE] + args, capture_output=True, text=True)
    first, _, out = p.stdout.partition("\n")
    secs, rss, code = first.split()
    if int(code) not in ok:
        sys.exit(f"failed ({code}): {' '.join(args)}\n{out}\n{p.stderr}")
    return float(secs), int(rss) / 1024, out, p.stderr


def synthetic(path, seconds):
    """Write a recording of a long steady run: probes of three kinds every
    50 ms, each arriving twice for DNS and once for TCP and UDP, with a
    leak in the middle. It is generated, not recorded."""
    t0 = 1_791_000_000_000_000  # microseconds

    def ts(us):
        return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(us // 1_000_000)) + f".{us % 1_000_000:06d}Z"
    n = 0
    with open(path, "w") as f:
        f.write(json.dumps({"t": ts(t0), "ev": "run", "lab": "0.1.0", "run": "r-perf", "app": "synthetic",
                            "scenario": "steady", "seed": 1, "interval_ms": 50,
                            "exit": "192.0.2.20", "home": "203.0.113.2"}, separators=(",", ":")) + "\n")
        f.write(json.dumps({"t": ts(t0), "ev": "step", "step": "start"}, separators=(",", ":")) + "\n")
        ticks = int(seconds * 20)
        for k in range(ticks):
            t = t0 + k * 50_000
            leak = ticks // 2 <= k < ticks // 2 + 40
            for kind in ("dns", "tcp", "udp"):
                f.write(f'{{"t":"{ts(t)}","ev":"sent","kind":"{kind}","via":"direct","seq":{k}}}\n')
                src = "203.0.113.2" if leak else "192.0.2.20"
                if kind == "dns":
                    at = "home-dns" if leak else "vpn-dns"
                    f.write(f'{{"t":"{ts(t + 500)}","ev":"arrival","kind":"dns","via":"direct","seq":{k},"at":"{at}","src":"192.168.1.10"}}\n')
                    f.write(f'{{"t":"{ts(t + 1000)}","ev":"arrival","kind":"dns","via":"direct","seq":{k},"at":"zone-dns","src":"{src}"}}\n')
                    n += 3
                else:
                    f.write(f'{{"t":"{ts(t + 1000)}","ev":"arrival","kind":"{kind}","via":"direct","seq":{k},"at":"{kind}","src":"{src}"}}\n')
                    n += 2
        f.write(json.dumps({"t": ts(t0 + seconds * 1_000_000), "ev": "step", "step": "stop"}, separators=(",", ":")) + "\n")
    return n + 3


def main():
    print(f"Each time is the median of {RUNS} runs, each memory figure the highest of {RUNS}, on this machine.")
    print("Memory is the peak resident size of the largest process of a run.")
    print()
    print("Scenario runs: vpnw-lab run --app correct --scenario NAME, from the command to the verdict,")
    print("building the test world, starting the client and tearing everything down included.")
    with tempfile.TemporaryDirectory() as work:
        for sc in SCENARIOS:
            walls, mems, builds, sizes = [], [], [], []
            planned = None
            for i in range(RUNS):
                rec = os.path.join(work, f"{sc}-{i}.jsonl")
                secs, mem, out, err = measure([LAB, "run", "--app", "correct", "--scenario", sc, "-v", "-o", rec])
                walls.append(secs)
                mems.append(mem)
                m = re.search(r"world built in ([0-9.]+)(ms|s)", err)
                if m:
                    builds.append(float(m.group(1)) * (1 if m.group(2) == "ms" else 1000))
                m = re.search(r"ran ([0-9.]+) s", out)
                planned = float(m.group(1)) if m else None
                sizes.append(os.path.getsize(rec))
            print(f"  {sc:14} planned {planned:.2f} s; run {statistics.median(walls):.2f} s; world built in "
                  f"{statistics.median(builds):.0f} ms; peak memory {max(mems):.0f} MB; recording {statistics.median(sizes) / 1000:.0f} kB")
        print()
        for app in ["dns-leak", "agent-sealed"]:
            walls, mems = [], []
            for i in range(RUNS):
                args = [LAB, "run", "--app", app, "--scenario", "server-silent"]
                if app.startswith("agent"):
                    args += ["--vpnw", os.path.join(BIN, "vpnw")]
                secs, mem, _, _ = measure(args, ok=(0, 120))
                walls.append(secs)
                mems.append(mem)
            print(f"  server-silent with {app}: run {statistics.median(walls):.2f} s; peak memory {max(mems):.0f} MB")
        print()
        big = os.path.join(work, "long.jsonl")
        seconds = 3600
        events = synthetic(big, seconds)
        times, mems = [], []
        for _ in range(RUNS):
            secs, mem, out, _ = measure([LAB, "verdict", big], ok=(120,))
            times.append(secs)
            mems.append(mem)
        t = statistics.median(times)
        print(f"Deciding a long recording: vpnw-lab verdict on a generated recording of one hour of probes,")
        print(f"  {events:,} events, {os.path.getsize(big) / 1e6:.0f} MB: {t:.2f} s, {events / t:,.0f} events a second, peak memory {max(mems):.0f} MB")
        print(f"  verdict: {out.splitlines()[0]}")


if __name__ == "__main__":
    main()
