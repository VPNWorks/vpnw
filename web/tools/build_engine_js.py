#!/usr/bin/env python3
# Copyright VPNW.com 2026
# SPDX-License-Identifier: Apache-2.0

"""Wrap the browser build of the engine (TinyGo, WebAssembly) into one
script the demo page loads: the loader TinyGo ships, then the WebAssembly as
text, so the page also works when opened straight from a folder on disk.

    python3 build_engine_js.py wasm_exec.js engine.wasm OUT.js VERSION
"""
import base64
import sys

exec_js, wasm, out, version = sys.argv[1:5]
loader = open(exec_js).read()
b64 = base64.b64encode(open(wasm, "rb").read()).decode()

js = """/* VPN Works Alpha engine for the demo page, version %(version)s: the engine's own Go code
 * (policy engine, request plan, event model and learn), compiled to WebAssembly with TinyGo.
 * Loaded from the text below, so the page also works when opened straight from a folder on
 * disk. Nothing here talks to a server.
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
      var e = global.vpnwEngine;
      if (!e) throw new Error('the engine did not start');
      function plain(o) { return JSON.parse(JSON.stringify(o)); }
      return {
        version: e.version,
        schema: e.schema,
        /* Check a policy file; returns {ok, summary} or {ok:false, error}. */
        compile: function (toml) {
          var r = plain(e.compile(String(toml)));
          if (r.ok) r.summary = JSON.parse(r.summary);
          return r;
        },
        /* What the broker would do with one request. dns maps names to addresses. */
        plan: function (policyToml, host, port, remoteDNS, dns) {
          var r = plain(e.plan(String(policyToml || ''), String(host), port | 0, !!remoteDNS, JSON.stringify(dns || {})));
          if (r.ok) r.plan = JSON.parse(r.plan);
          return r;
        },
        /* vpnw learn, from a trace in JSON Lines. */
        learn: function (jsonl, name, wildcards) {
          return plain(e.learn(String(jsonl), String(name || ''), !!wildcards));
        },
        parseRule: function (text) { return plain(e.parseRule(String(text))); }
      };
    });
  }

  global.VPNWEngine = { load: load };
})(typeof window !== 'undefined' ? window : globalThis);
""" % {"version": version, "loader": loader, "b64": b64}
open(out, "w").write(js)
print("wrote %s: %d bytes (engine %d bytes)" % (out, len(js), len(open(wasm, "rb").read())))
