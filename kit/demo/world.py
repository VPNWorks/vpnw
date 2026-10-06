#!/usr/bin/env python3
# Copyright VPNW.com 2026
# SPDX-License-Identifier: Apache-2.0

"""The demo's private little internet.

run-demo.sh starts this inside its own user, network and mount namespaces,
so nothing here can reach your real network and nothing on your machine is
changed. Inside, it builds a small world:

  a DNS server       127.0.0.53    knows the public names below
  api.github.com     140.82.112.6  HTTPS, the code host
  files.pythonhosted.org  151.101.0.223  HTTPS, a package download
  telemetry.example.com   93.184.215.14  HTTPS, a telemetry endpoint
  evil.example       45.77.10.10   HTTPS, the attacker's collector
  office exit        10.8.0.1:1080 SOCKS5, the way into the office network
  tracker.office.internal  10.20.30.40  HTTPS, only known inside the office
  a local service    .world/docker.sock  a Unix socket, standing in for Docker

Every server is a stand-in written in a few lines of Python. The addresses
look public so that vpnw's deny_private rule treats them as the real thing;
they exist only inside this namespace.

Usage (from run-demo.sh, inside the namespaces):
  world.py setup    bring the network up and mount the demo's hosts/resolv.conf
  world.py serve    run every server until killed; writes ./.world-ready
"""
import fcntl
import http.server
import json
import os
import selectors
import socket
import socketserver
import ssl
import struct
import subprocess
import sys
import threading

HERE = os.path.dirname(os.path.abspath(__file__))

PUBLIC = {
    "api.github.com": "140.82.112.6",
    "files.pythonhosted.org": "151.101.0.223",
    "telemetry.example.com": "93.184.215.14",
    "evil.example": "45.77.10.10",
}
OFFICE_ONLY = {"tracker.office.internal": "10.20.30.40"}
OFFICE_EXIT = ("10.8.0.1", 1080)
DNS_ADDR = ("127.0.0.53", 53)

BODIES = {
    "api.github.com": b'{"repo":"acme/widget","default_branch":"main","build":"failing"}\n',
    "files.pythonhosted.org": b"PK\x03\x04 widget-1.0-py3-none-any.whl " + b"." * 40000,
    "telemetry.example.com": b'{"ok":true}\n',
    "evil.example": b"thanks\n",
    "tracker.office.internal": b'{"ticket":"OPS-3411","status":"open"}\n',
}

SIOCSIFADDR = 0x8916
SIOCSIFNETMASK = 0x891C
SIOCGIFFLAGS = 0x8913
SIOCSIFFLAGS = 0x8914
IFF_UP = 0x1
IFF_RUNNING = 0x40


# ---- network setup ---------------------------------------------------------

def _ifreq_addr(name, addr):
    sin = struct.pack("HH4s8x", socket.AF_INET, 0, socket.inet_aton(addr))
    return struct.pack("16s", name.encode()) + sin


def setup():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Loopback up.
    ifr = struct.pack("16sH14x", b"lo", 0)
    flags = struct.unpack("16sH14x", fcntl.ioctl(s, SIOCGIFFLAGS, ifr))[1]
    fcntl.ioctl(s, SIOCSIFFLAGS, struct.pack("16sH14x", b"lo", flags | IFF_UP | IFF_RUNNING))
    # One loopback alias per stand-in host. Any address on any interface is
    # local, so the kernel delivers to our servers.
    addrs = list(PUBLIC.values()) + list(OFFICE_ONLY.values()) + [OFFICE_EXIT[0], DNS_ADDR[0]]
    for i, a in enumerate(addrs, start=1):
        name = "lo:%d" % i
        fcntl.ioctl(s, SIOCSIFADDR, _ifreq_addr(name, a))
        fcntl.ioctl(s, SIOCSIFNETMASK, _ifreq_addr(name, "255.255.255.255"))
    # The demo's own hosts and resolv.conf, visible only in this namespace.
    state = os.path.join(HERE, ".world")
    os.makedirs(state, exist_ok=True)
    hosts = os.path.join(state, "hosts")
    resolv = os.path.join(state, "resolv.conf")
    with open(hosts, "w") as f:
        f.write("127.0.0.1 localhost\n::1 localhost\n")
    with open(resolv, "w") as f:
        f.write("nameserver %s\noptions timeout:1 attempts:1\n" % DNS_ADDR[0])
    for src, dst in ((hosts, "/etc/hosts"), (resolv, "/etc/resolv.conf")):
        subprocess.run(["mount", "--bind", src, dst], check=True)


# ---- DNS -------------------------------------------------------------------

def _qname(pkt, off):
    labels = []
    while True:
        n = pkt[off]
        off += 1
        if n == 0:
            break
        labels.append(pkt[off:off + n].decode("ascii", "replace"))
        off += n
    return ".".join(labels).lower(), off


def dns_server():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(DNS_ADDR)
    while True:
        pkt, peer = sock.recvfrom(1500)
        try:
            qid, flags, qd = struct.unpack(">HHH", pkt[:6])
            name, off = _qname(pkt, 12)
            qtype, qclass = struct.unpack(">HH", pkt[off:off + 4])
            question = pkt[12:off + 4]
            known = name in PUBLIC
            rcode = 0 if known else 3  # NXDOMAIN for names the public DNS does not know
            answers = b""
            an = 0
            if known and qtype == 1:
                answers = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 60, 4) + socket.inet_aton(PUBLIC[name])
                an = 1
            rflags = 0x8000 | 0x0400 | (flags & 0x0100) | 0x0080 | rcode
            resp = struct.pack(">HHHHHH", qid, rflags, 1, an, 0, 0) + question + answers
            sock.sendto(resp, peer)
        except Exception:
            continue


# ---- HTTPS stand-ins -------------------------------------------------------

LOG = []
LOG_LOCK = threading.Lock()


def make_handler(host):
    body = BODIES[host]

    class H(http.server.BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def _reply(self):
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            self._note("GET", 0)
            self._reply()

        def do_POST(self):
            n = int(self.headers.get("Content-Length", 0) or 0)
            data = self.rfile.read(n)
            self._note("POST", len(data), data)
            self._reply()

        def _note(self, method, n, data=b""):
            with LOG_LOCK:
                LOG.append({"host": host, "method": method, "path": self.path, "bytes": n,
                            "token": b"ghp_" in data})
            if host == "evil.example" and b"ghp_" in data:
                with open(os.path.join(HERE, ".world", "stolen.txt"), "ab") as f:
                    f.write(data + b"\n")

        def log_message(self, *a):
            pass

    return H


class TLSServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

    def __init__(self, addr, handler, ctx):
        self.ctx = ctx
        super().__init__(addr, handler)

    def get_request(self):
        c, a = self.socket.accept()
        c.settimeout(10)
        try:
            return self.ctx.wrap_socket(c, server_side=True), a
        except (ssl.SSLError, OSError):
            c.close()
            raise


def https_servers():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(os.path.join(HERE, "certs", "server.pem"), os.path.join(HERE, "certs", "server.key"))
    for host, addr in list(PUBLIC.items()) + list(OFFICE_ONLY.items()):
        srv = TLSServer((addr, 443), make_handler(host), ctx)
        threading.Thread(target=srv.serve_forever, daemon=True).start()


# ---- office exit (SOCKS5, names resolved at the exit) ----------------------

def _pipe(a, b):
    sel = selectors.DefaultSelector()
    for x, y in ((a, b), (b, a)):
        x.setblocking(False)
        sel.register(x, selectors.EVENT_READ, y)
    open_ends = 2
    try:
        while open_ends:
            for key, _ in sel.select(timeout=30):
                src, dst = key.fileobj, key.data
                try:
                    data = src.recv(65536)
                except OSError:
                    data = b""
                if not data:
                    sel.unregister(src)
                    try:
                        dst.shutdown(socket.SHUT_WR)
                    except OSError:
                        pass
                    open_ends -= 1
                    continue
                try:
                    dst.setblocking(True)
                    dst.sendall(data)
                    dst.setblocking(False)
                except OSError:
                    open_ends = 0
    finally:
        a.close()
        b.close()


def _office_resolve(host):
    if host in OFFICE_ONLY:
        return OFFICE_ONLY[host]
    try:
        return socket.gethostbyname(host)  # the office can reach the internet too
    except OSError:
        return None


def _socks_client(c):
    try:
        c.settimeout(10)
        ver, n = c.recv(2)
        c.recv(n)
        c.sendall(b"\x05\x00")
        hdr = c.recv(4)
        if len(hdr) < 4 or hdr[1] != 1:
            c.sendall(b"\x05\x07\x00\x01" + b"\x00" * 6)
            return
        if hdr[3] == 3:
            ln = c.recv(1)[0]
            host = c.recv(ln).decode()
        elif hdr[3] == 1:
            host = socket.inet_ntoa(c.recv(4))
        else:
            c.recv(16)
            c.sendall(b"\x05\x08\x00\x01" + b"\x00" * 6)
            return
        port = struct.unpack(">H", c.recv(2))[0]
        ip = _office_resolve(host)
        if not ip:
            c.sendall(b"\x05\x04\x00\x01" + b"\x00" * 6)
            return
        try:
            up = socket.create_connection((ip, port), timeout=5)
        except OSError:
            c.sendall(b"\x05\x05\x00\x01" + b"\x00" * 6)
            return
        c.sendall(b"\x05\x00\x00\x01" + b"\x00" * 6)
        c.settimeout(None)
        _pipe(c, up)
    except Exception:
        pass
    finally:
        try:
            c.close()
        except OSError:
            pass


def office_exit():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(OFFICE_EXIT)
    s.listen(64)
    while True:
        c, _ = s.accept()
        threading.Thread(target=_socks_client, args=(c,), daemon=True).start()


# ---- a local service on a Unix socket --------------------------------------
# A stand-in for the Docker socket: a service on this machine that could make
# connections on a program's behalf. It keeps whatever it is sent.

def local_service():
    path = os.path.join(HERE, ".world", "docker.sock")
    try:
        os.unlink(path)
    except OSError:
        pass
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(path)
    s.listen(8)
    while True:
        c, _ = s.accept()
        try:
            data = c.recv(65536)
            with open(os.path.join(HERE, ".world", "stolen.txt"), "ab") as f:
                f.write(b"via the local service: " + data + b"\n")
            c.sendall(b"ok\n")
        except OSError:
            pass
        finally:
            c.close()


def serve():
    threading.Thread(target=dns_server, daemon=True).start()
    threading.Thread(target=local_service, daemon=True).start()
    https_servers()
    threading.Thread(target=office_exit, daemon=True).start()
    with open(os.path.join(HERE, ".world", "ready"), "w") as f:
        f.write(str(os.getpid()))
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else ""
    if cmd == "setup":
        setup()
    elif cmd == "serve":
        serve()
    else:
        print(__doc__)
        sys.exit(2)
