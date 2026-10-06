#!/usr/bin/env python3
# Copyright VPNW.com 2026
# SPDX-License-Identifier: Apache-2.0

"""Wrap the browser build of VPN Works Exit (TinyGo, WebAssembly) into one
script the Exit demo page loads: TinyGo's loader, then the WebAssembly as
text, so the page also works when opened straight from a folder on disk.

    python3 build_exit_js.py wasm_exec.js exit.wasm OUT.js VERSION
"""
import base64
import sys

exec_js, wasm, out, version = sys.argv[1:5]
loader = open(exec_js).read()
b64 = base64.b64encode(open(wasm, "rb").read()).decode()

js = """/* VPN Works Exit engine for the demo page, version %(version)s: Exit's own Go code
 * (the configuration reader, a client's policy through the Agent's request plan,
 * source addresses, and the join of an Agent's record with an exit's), compiled to
 * WebAssembly with TinyGo. Loaded from the text below, so the page also works when
 * opened straight from a folder on disk. Nothing here talks to a server.
 *
 * The loader that follows is TinyGo's wasm_exec.js, under the Go authors' BSD license. */
%(loader)s
(function (global) {
  'use strict';
  var WASM = '%(b64)s';

  function bytes(b64) {
    var bin = atob(b64), n = bin.length, out = new Uint8Array(n);
    for (var i = 0; i < n; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function load() {
    var go = new global.Go();
    return WebAssembly.instantiate(bytes(WASM), go.importObject).then(function (res) {
      go.run(res.instance);
      var e = global.vpnwExit;
      if (!e) throw new Error('the engine did not start');
      function j(s) { return JSON.parse(String(s)); }
      function s(v) { return JSON.stringify(v || {}); }
      return {
        version: e.version,
        agentVersion: e.agentVersion,
        /* Read an exit's configuration file, name, from files: an object of
           file names and their text that stands for the exit's folder. */
        parse: function (name, files) { return j(e.parse(String(name), s(files))); },
        /* What the exit does with one request from a client, before it dials:
           {ok, outcome: allow|denied|failed, rule, text, reason, error, addrs, source}. */
        decide: function (name, files, client, target, dns) {
          return j(e.decide(String(name), s(files), String(client), String(target), s(dns)));
        },
        /* Join Agent records with exit records (JSON Lines, end to end). */
        join: function (agent, exits) { return j(e.join(String(agent), String(exits))); }
      };
    });
  }

  global.VPNWExit = { load: load };
})(typeof window !== 'undefined' ? window : globalThis);
""" % {"version": version, "loader": loader, "b64": b64}
open(out, "w").write(js)
print("wrote %s: %d bytes (engine %d bytes)" % (out, len(js), len(open(wasm, "rb").read())))
