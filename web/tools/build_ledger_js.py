#!/usr/bin/env python3
# Copyright VPNW.com 2026
# SPDX-License-Identifier: Apache-2.0

"""Wrap the browser build of VPN Works Ledger (TinyGo, WebAssembly) and the
recorded Agent trace it seals into one script the Ledger demo page loads:
TinyGo's loader, then the WebAssembly as text, then the trace, so the page
also works when opened straight from a folder on disk.

    python3 build_ledger_js.py wasm_exec.js ledger.wasm TRACE.jsonl OUT.js VERSION
"""
import base64
import json
import sys

exec_js, wasm, trace, out, version = sys.argv[1:6]
loader = open(exec_js).read()
b64 = base64.b64encode(open(wasm, "rb").read()).decode()
trace_text = open(trace, encoding="utf-8").read()

js = """/* VPN Works Ledger engine for the demo page, version %(version)s: Ledger's own Go code
 * (keys, sealing, verifying, proofs and the tamper matrix), compiled to WebAssembly
 * with TinyGo, and the Agent's recorded trace it seals (recordings/1-trace-1.jsonl).
 * Loaded from the text below, so the page also works when opened straight from a
 * folder on disk. Nothing here talks to a server.
 *
 * The loader that follows is TinyGo's wasm_exec.js, under the Go authors' BSD license. */
%(loader)s
(function (global) {
  'use strict';
  var WASM = '%(b64)s';
  var TRACE = %(trace)s;

  function bytes(b64) {
    var bin = atob(b64), n = bin.length, out = new Uint8Array(n);
    for (var i = 0; i < n; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  function load() {
    var go = new global.Go();
    return WebAssembly.instantiate(bytes(WASM), go.importObject).then(function (res) {
      go.run(res.instance);
      var e = global.vpnwLedger;
      if (!e) throw new Error('the engine did not start');
      function j(s) { return JSON.parse(String(s)); }
      return {
        version: e.version,
        /* The Agent's recorded trace, as recorded. */
        trace: TRACE,
        /* Make the key in a slot ("main" seals, "other" is any other key): {ok, id, pub}. */
        keygen: function (slot) { return j(e.keygen(String(slot || 'main'))); },
        /* Seal records with the main key, a checkpoint every n: {ok, ledger, records, checkpoints, ms}. */
        seal: function (records, every) { return j(e.seal(String(records), every | 0)); },
        /* Verify with a key slot's public half, and checkpoint lines kept elsewhere: {ok, intact, problem, ...}. */
        verify: function (records, ledger, slot, witness) { return j(e.verify(String(records), String(ledger), String(slot || 'main'), String(witness || ''))); },
        /* A proof for one line: {ok, proof, line, leaf, path, bytes, checkpoint}. */
        prove: function (records, ledger, line) { return j(e.prove(String(records), String(ledger), line | 0)); },
        /* Check a proof with a key slot's public half alone: {ok, holds, msg, line, record}. */
        checkProof: function (proof, slot) { return j(e.checkProof(String(proof), String(slot || 'main'))); },
        /* The tamper matrix around one line: {ok, rows}. */
        matrix: function (records, ledger, target) { return j(e.matrix(String(records), String(ledger), target | 0)); }
      };
    });
  }

  global.VPNWLedger = { load: load };
})(typeof window !== 'undefined' ? window : globalThis);
""" % {"version": version, "loader": loader, "b64": b64, "trace": json.dumps(trace_text)}
open(out, "w").write(js)
print("wrote %s: %d bytes (engine %d bytes, trace %d bytes)" % (out, len(js), len(open(wasm, "rb").read()), len(trace_text)))
