#!/usr/bin/env python3
# Copyright VPNW.com 2026
# SPDX-License-Identifier: Apache-2.0

"""Wrap the browser build of VPN Works Scope (TinyGo, WebAssembly) into one
script the Scope demo page loads: TinyGo's loader, then the WebAssembly as
text, so the page also works when opened straight from a folder on disk.

    python3 build_scope_js.py wasm_exec.js scope.wasm OUT.js VERSION
"""
import base64
import sys

exec_js, wasm, out, version = sys.argv[1:5]
loader = open(exec_js).read()
b64 = base64.b64encode(open(wasm, "rb").read()).decode()

js = """/* VPN Works Scope engine for the demo page, version %(version)s: Scope's own Go code
 * (the office generator, the learner, the draft parser, the simulator and the
 * exports), compiled to WebAssembly with TinyGo. Loaded from the text below, so the
 * page also works when opened straight from a folder on disk. Nothing here talks to
 * a server.
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
      var e = global.vpnwScope;
      if (!e) throw new Error('the engine did not start');
      function j(s) { return JSON.parse(String(s)); }
      return {
        version: e.version,
        /* The demo office: people, groups, systems and the generated traffic per day. */
        office: function () { return j(e.office()); },
        /* Learn a draft from the two weeks: {draft, counts, matrix, review, flows}. */
        learn: function () { return j(e.learn()); },
        /* Parse an edited draft: {ok, counts, matrix, review} or {ok:false, error}. */
        check: function (text) { return j(e.check(String(text))); },
        /* Move one entry between review and allow: {ok, draft, ...}. */
        review: function (text, person, dest, allow) { return j(e.review(String(text), String(person), String(dest), !!allow)); },
        /* Replay the week after under a draft. */
        replay: function (text) { return j(e.replay(String(text))); },
        /* A stolen login trying every system, under a draft. */
        stolen: function (text) { return j(e.stolen(String(text))); },
        /* The draft as nftables rules ("nft", watch or not) or WireGuard AllowedIPs. */
        exportRules: function (text, format, watch) { return j(e.export(String(text), String(format || 'nft'), !!watch)); }
      };
    });
  }

  global.VPNWScope = { load: load };
})(typeof window !== 'undefined' ? window : globalThis);
""" % {"version": version, "loader": loader, "b64": b64}
open(out, "w").write(js)
print("wrote %s: %d bytes (engine %d bytes)" % (out, len(js), len(open(wasm, "rb").read())))
