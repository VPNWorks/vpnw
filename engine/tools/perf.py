#!/usr/bin/env python3
# Copyright VPNW.com 2026
# SPDX-License-Identifier: Apache-2.0

"""Performance figures for the Alpha: start-up cost, added time per new
connection, bulk throughput, many clients at once, and memory. Everything
runs against local servers on this machine, so the numbers describe vpnw's
own cost, not a network's.

    python3 tools/perf.py path/to/vpnw > results/alpha/perf.txt
"""
import http.server
import json
import os
import socketserver
import statistics
import subprocess
import sys
import tempfile
import threading
import time

VPNW = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "vpnw")
ENV = dict(os.environ, NO_COLOR="1")
for k in list(ENV):
    if k.lower() in ("http_proxy", "https_proxy", "all_proxy", "no_proxy"):
        del ENV[k]
BIG = 100 * 1024 * 1024


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        n = int(self.path.strip("/") or "64")
        self.send_response(200)
        self.send_header("Content-Length", str(n))
        self.send_header("Connection", "close")
        self.end_headers()
        chunk = b"v" * 65536
        left = n
        while left > 0:
            k = min(left, len(chunk))
            self.wfile.write(chunk[:k])
            left -= k

    def log_message(self, *a):
        pass


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 256


def start_server():
    s = Server(("127.0.0.1", 0), Handler)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    return s.server_address[1]


def timed(cmd, n):
    out = []
    for _ in range(n):
        t = time.perf_counter()
        subprocess.run(cmd, env=ENV, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        out.append((time.perf_counter() - t) * 1000)
    return statistics.median(out)


# The client runs as a workload. It prints JSON with its own timings, so
# vpnw's start-up does not count against the per-connection figures.
CLIENT = r'''
import json, os, sys, time, urllib.request, threading
mode, url, n = sys.argv[1], sys.argv[2], int(sys.argv[3])
op = urllib.request.build_opener(urllib.request.ProxyHandler() if os.environ.get("HTTP_PROXY") else urllib.request.ProxyHandler({}))
if mode == "seq":
    t = time.perf_counter()
    for _ in range(n):
        op.open(url, timeout=10).read()
    print(json.dumps({"ms": (time.perf_counter() - t) * 1000}))
elif mode == "bulk":
    t = time.perf_counter()
    got = 0
    with op.open(url, timeout=60) as r:
        while True:
            b = r.read(1 << 20)
            if not b:
                break
            got += len(b)
    print(json.dumps({"ms": (time.perf_counter() - t) * 1000, "bytes": got}))
elif mode == "par":
    size = int(url.rsplit("/", 1)[1])
    ok = [0]; bad = [0]; lock = threading.Lock(); per = n // 64
    def worker():
        for _ in range(per):
            try:
                b = op.open(url, timeout=30).read()
                with lock:
                    if len(b) == size: ok[0] += 1
                    else: bad[0] += 1
            except Exception:
                with lock: bad[0] += 1
    t = time.perf_counter()
    ths = [threading.Thread(target=worker) for _ in range(64)]
    [x.start() for x in ths]; [x.join() for x in ths]
    print(json.dumps({"ms": (time.perf_counter() - t) * 1000, "ok": ok[0], "bad": bad[0]}))
elif mode == "sleep":
    time.sleep(float(n))
'''


def client(backend, mode, url, n):
    f = tempfile.NamedTemporaryFile("w", suffix=".py", delete=False)
    f.write(CLIENT)
    f.close()
    if backend == "bare":
        cmd = [sys.executable, f.name, mode, url, str(n)]
    else:
        cmd = [VPNW, "run", "--backend", backend, "--no-save", "--", sys.executable, f.name, mode, url, str(n)]
    r = subprocess.run(cmd, env=ENV, capture_output=True, text=True)
    os.unlink(f.name)
    lines = [l for l in r.stdout.splitlines() if l.startswith("{")]
    if not lines:
        raise SystemExit("client failed (%s %s):\n%s\n%s" % (backend, mode, r.stdout, r.stderr))
    return json.loads(lines[-1])


def rss_kb(pid):
    try:
        for line in open("/proc/%d/status" % pid):
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    except OSError:
        return 0
    return 0


def main():
    port = start_server()
    base = "http://127.0.0.1:%d" % port
    print("vpnw:", subprocess.run([VPNW, "version"], capture_output=True, text=True).stdout.strip())
    print("host:", os.uname().release, os.uname().machine, "cpus:", os.cpu_count())
    print()

    # 1. Start-up and tear-down, median of 60 runs each.
    bare = timed(["/bin/true"], 60)
    sealed = timed([VPNW, "run", "--backend", "sealed", "--no-save", "--", "/bin/true"], 60)
    env = timed([VPNW, "run", "--backend", "env", "--no-save", "--", "/bin/true"], 60)
    print("start-up, median of 60 runs of /bin/true")
    print("  bare                 %6.2f ms" % bare)
    print("  vpnw, sealed         %6.2f ms   (+%.2f ms)" % (sealed, sealed - bare))
    print("  vpnw, env            %6.2f ms   (+%.2f ms)" % (env, env - bare))
    print()

    # 2. Added time per new connection: 1,000 sequential requests, each on a
    #    new connection, with and without vpnw. Best of three.
    n = 1000
    res = {}
    for be in ("bare", "env", "sealed"):
        res[be] = min(client(be, "seq", base + "/64", n)["ms"] for _ in range(3))
    print("per connection, %d sequential requests on new connections, best of 3" % n)
    for be in ("bare", "env", "sealed"):
        extra = "" if be == "bare" else "   (+%.3f ms per connection)" % ((res[be] - res["bare"]) / n)
        print("  %-8s %8.1f ms total, %.3f ms each%s" % (be, res[be], res[be] / n, extra))
    print()

    # 3. Bulk: one 100 MB download.
    print("bulk, one 100 MB download, best of 3")
    for be in ("bare", "sealed"):
        runs = [client(be, "bulk", base + "/%d" % BIG, 1) for _ in range(3)]
        best = min(runs, key=lambda r: r["ms"])
        assert best["bytes"] == BIG, best
        print("  %-8s %7.0f MB/s  (%d bytes intact)" % (be, BIG / 1e6 / (best["ms"] / 1000), best["bytes"]))
    print()

    # 4. Many clients: 3,008 requests from 64 threads at once, 16 KB each.
    print("parallel, 64 threads, 3,008 requests of 16 KB")
    for be in ("bare", "sealed"):
        r = client(be, "par", base + "/16384", 3008)
        print("  %-8s %6.0f requests/s  %d intact, %d failed" % (be, 3008 / (r["ms"] / 1000), r["ok"], r["bad"]))
    print()

    # 5. Memory while a workload runs (sealed): vpnw itself and its helper.
    f = tempfile.NamedTemporaryFile("w", suffix=".py", delete=False)
    f.write(CLIENT)
    f.close()
    p = subprocess.Popen([VPNW, "run", "--backend", "sealed", "--no-save", "--", sys.executable, f.name, "sleep", "x", "2"],
                         env=ENV, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.0)
    helper = 0
    for d in os.listdir("/proc"):
        if d.isdigit():
            try:
                cmd = open("/proc/%s/cmdline" % d, "rb").read().split(b"\0")
            except OSError:
                continue
            if len(cmd) > 1 and cmd[1] == b"__vpnw_sandbox__":
                helper = int(d)
    print("memory while a workload runs (resident set)")
    print("  vpnw           %5.1f MB" % (rss_kb(p.pid) / 1024))
    print("  sandbox helper %5.1f MB" % (rss_kb(helper) / 1024))
    p.wait()
    os.unlink(f.name)


if __name__ == "__main__":
    main()
