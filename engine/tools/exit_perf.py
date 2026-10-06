#!/usr/bin/env python3
# Copyright VPNW.com 2026
# SPDX-License-Identifier: Apache-2.0

"""Performance figures for VPN Works Exit: the time an exit adds to each new
connection (a full TLS handshake each time, and with a resumed TLS session),
the throughput of one 100 MB transfer, and the memory each connected client
takes. Everything runs against local servers on this machine, so the
figures describe the exit's own cost, not a network's. Times are the median
of three runs; memory is the highest of three.

    python3 tools/exit_perf.py path/to/vpnw-exit > results/exit-alpha/perf.txt
"""
import http.server
import os
import re
import socket
import socketserver
import ssl
import statistics
import subprocess
import sys
import tempfile
import threading
import time

EXIT = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "vpnw-exit")
RUNS = 3
N = 1000
BIG = 100 * 1024 * 1024
CLIENTS = 200
TOKEN = "perf-token-4c1e9a"


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
    request_queue_size = 512


class Hold(socketserver.BaseRequestHandler):
    """Keeps a connection open until the other side closes it."""

    def handle(self):
        try:
            while self.request.recv(4096):
                pass
        except OSError:
            pass


def start(server_cls, handler):
    s = server_cls(("127.0.0.1", 0), handler)
    threading.Thread(target=s.serve_forever, daemon=True).start()
    return s, s.server_address[1]


def sha256_hex(s):
    import hashlib
    return hashlib.sha256(s.encode()).hexdigest()


def exit_files(work):
    cert, key = os.path.join(work, "exit.crt"), os.path.join(work, "exit.key")
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                    "-keyout", key, "-out", cert, "-days", "2", "-nodes", "-subj", "/CN=exit-perf",
                    "-addext", "subjectAltName=IP:127.0.0.1"], check=True, capture_output=True)
    cfg = os.path.join(work, "exit.toml")
    with open(cfg, "w") as f:
        f.write('version = 1\nname = "exit-perf"\nlisten = "127.0.0.1:0"\ncert = "exit.crt"\nkey = "exit.key"\n\n'
                '[clients.perf]\ntoken_sha256 = "%s"\nsource = "127.0.0.1"\ndefault = "deny"\nallow = ["127.0.0.1"]\n'
                % sha256_hex(TOKEN))
    return cfg, cert


def start_exit(cfg):
    p = subprocess.Popen([EXIT, "serve", "--config", cfg, "-q"], stderr=subprocess.PIPE, text=True)
    line = p.stderr.readline()
    m = re.search(r"listening on (127\.0\.0\.1):(\d+)", line)
    if not m:
        p.kill()
        sys.exit("the exit did not start: " + line + p.stderr.read())
    threading.Thread(target=p.stderr.read, daemon=True).start()
    return p, int(m.group(2))


AUTH = "Basic " + __import__("base64").b64encode(("perf:" + TOKEN).encode()).decode()


def read_head(f):
    status = f.readline()
    while True:
        line = f.readline()
        if line in (b"\r\n", b"\n", b""):
            break
    return status


def dial(port):
    """A TCP connection with Nagle's algorithm off, as Go clients, the
    Agent among them, have by default. Without it a small write after the
    TLS handshake waits for a delayed acknowledgement, about 40 ms."""
    s = socket.create_connection(("127.0.0.1", port))
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return s


def bare_once(port, size=64):
    s = dial(port)
    s.sendall(b"GET /%d HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n" % size)
    n = 0
    while True:
        b = s.recv(65536)
        if not b:
            break
        n += len(b)
    s.close()
    return n


def exit_once(ctx, exit_port, port, size=64, session=None):
    s = ctx.wrap_socket(dial(exit_port), server_hostname="127.0.0.1", session=session)
    s.sendall(("CONNECT 127.0.0.1:%d HTTP/1.1\r\nProxy-Authorization: %s\r\n\r\n" % (port, AUTH)).encode())
    f = s.makefile("rb")
    status = read_head(f)
    if b" 200 " not in status:
        raise RuntimeError("the exit answered " + status.decode().strip())
    s.sendall(b"GET /%d HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n" % size)
    n = 0
    while True:
        b = f.read(65536)
        if not b:
            break
        n += len(b)
    reused, sess, version = s.session_reused, s.session, s.version()
    f.close()
    s.close()
    return n, sess, reused, version


def per_connection(fn):
    times = []
    for _ in range(RUNS):
        t0 = time.perf_counter()
        for _ in range(N):
            fn()
        times.append((time.perf_counter() - t0) * 1000)
    return statistics.median(times)


def rss_kb(pid):
    with open("/proc/%d/status" % pid) as f:
        for line in f:
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    return 0


def main():
    work = tempfile.mkdtemp(prefix="exit-perf-")
    cfg, cert = exit_files(work)
    web, port = start(Server, Handler)
    hold, hold_port = start(Server, Hold)
    p, exit_port = start_exit(cfg)
    ctx = ssl.create_default_context(cafile=cert)
    try:
        version = subprocess.run([EXIT, "version"], capture_output=True, text=True).stdout.strip()
        print("exit: " + version)
        print("host: %s %s cpus: %d" % (os.uname().release, os.uname().machine, os.cpu_count()))
        print("client: Python %s with %s" % (sys.version.split()[0], ssl.OPENSSL_VERSION))
        print()

        bare = per_connection(lambda: bare_once(port))
        full = per_connection(lambda: exit_once(ctx, exit_port, port))
        state = {"session": None, "reused": 0, "total": 0}

        def resumed():
            n, sess, reused, _ = exit_once(ctx, exit_port, port, session=state["session"])
            state["session"] = sess
            state["total"] += 1
            state["reused"] += 1 if reused else 0

        res = per_connection(resumed)
        _, _, _, tls_version = exit_once(ctx, exit_port, port)
        print("per connection, %d sequential requests on new connections, median of %d runs" % (N, RUNS))
        print("  bare                                %7.1f ms total, %.3f ms each" % (bare, bare / N))
        print("  through the exit, full TLS          %7.1f ms total, %.3f ms each   (+%.3f ms per connection)" % (full, full / N, (full - bare) / N))
        print("  through the exit, resumed session   %7.1f ms total, %.3f ms each   (+%.3f ms per connection; %d of %d sessions resumed)"
              % (res, res / N, (res - bare) / N, state["reused"], state["total"]))
        print("  TLS version: %s; each request: TCP, TLS, CONNECT with the token, the exit's decision and its dial from" % tls_version)
        print("  the client's source address, then one small HTTP request through the tunnel")
        print()

        def bulk(through):
            t0 = time.perf_counter()
            n = exit_once(ctx, exit_port, port, size=BIG)[0] if through else bare_once(port, size=BIG)
            return time.perf_counter() - t0, n

        print("bulk, one 100 MB download, median of %d runs" % RUNS)
        for name, through in (("bare", False), ("through the exit", True)):
            runs = [bulk(through) for _ in range(RUNS)]
            secs = statistics.median(r[0] for r in runs)
            intact = all(r[1] >= BIG for r in runs)
            print("  %-18s %6.0f MB/s  (%d bytes each run, %s)" % (name, BIG / secs / 1e6, runs[0][1], "intact" if intact else "SHORT"))
        print()

        per = []
        for _ in range(RUNS):
            time.sleep(0.5)
            before = rss_kb(p.pid)
            socks = []
            for _ in range(CLIENTS):
                s = ctx.wrap_socket(dial(exit_port), server_hostname="127.0.0.1")
                s.sendall(("CONNECT 127.0.0.1:%d HTTP/1.1\r\nProxy-Authorization: %s\r\n\r\n" % (hold_port, AUTH)).encode())
                f = s.makefile("rb")
                if b" 200 " not in read_head(f):
                    raise RuntimeError("tunnel refused")
                socks.append((s, f))
            time.sleep(0.5)
            after = rss_kb(p.pid)
            per.append((before, after))
            for s, f in socks:
                f.close()
                s.close()
        worst = max(per, key=lambda x: x[1] - x[0])
        print("memory, %d clients connected at once, each with an open tunnel (TLS, CONNECT, a held connection), highest of %d runs" % (CLIENTS, RUNS))
        print("  exit, idle          %6.1f MB" % (worst[0] / 1024))
        print("  exit, %d clients   %6.1f MB" % (CLIENTS, worst[1] / 1024))
        print("  per connected client  %5.1f KB" % ((worst[1] - worst[0]) / CLIENTS))
    finally:
        p.terminate()
        p.wait()
        web.shutdown()
        hold.shutdown()


if __name__ == "__main__":
    main()
