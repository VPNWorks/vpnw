#!/usr/bin/env python3
# Copyright VPNW.com 2026
# SPDX-License-Identifier: Apache-2.0

"""Wrap the browser build of VPN Works Lab (TinyGo, WebAssembly) into one
script the Lab demo page loads: TinyGo's loader, then the WebAssembly as
text, so the page also works when opened straight from a folder on disk.
The demo's recordings are inside the WebAssembly.

    python3 build_lab_js.py wasm_exec.js lab.wasm OUT.js VERSION
"""
import base64
import sys

exec_js, wasm, out, version = sys.argv[1:5]
loader = open(exec_js).read()
b64 = base64.b64encode(open(wasm, "rb").read()).decode()

js = """/* VPN Works Lab engine for the demo page, version %(version)s: Lab's own Go code
 * (the recording reader and the verdict), compiled to WebAssembly with TinyGo, with the
 * demo's recordings of real runs inside. Loaded from the text below, so the page also
 * works when opened straight from a folder on disk. Nothing here talks to a server.
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
      var e = global.vpnwLab;
      if (!e) throw new Error('the engine did not start');
      function j(s) { return JSON.parse(String(s)); }
      return {
        version: e.version,
        /* The recordings inside the engine: [{name, title, app, scenario, seed, lines}]. */
        recordings: function () { return j(e.recordings()); },
        /* Decide one: {ok, report, header, probes, observers, marks, arrivals, duration}. */
        analyze: function (name) { return j(e.analyze(String(name))); },
        /* Follow one probe: {ok, sent, outcome, arrivals: [{t, at, src, path}]}. */
        probe: function (name, kind, via, seq) { return j(e.probe(String(name), String(kind), String(via), Number(seq))); },
        /* Decide a recording given as text. */
        decide: function (text) { return j(e.decide(String(text))); }
      };
    });
  }

  global.VPNWLab = { load: load };
})(typeof window !== 'undefined' ? window : globalThis);
""" % {"version": version, "loader": loader, "b64": b64}
open(out, "w").write(js)
print("wrote %s: %d bytes (engine %d bytes)" % (out, len(js), len(open(wasm, "rb").read())))
