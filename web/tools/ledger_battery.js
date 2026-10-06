// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

// Runs Ledger's browser engine in Node on the Agent's recorded trace and
// prints the demo's numbers, so they can be compared with the command line's
// in results/ledger-alpha/demo.txt and tamper.txt. The hashes, lines and
// verdicts match; the key, and so the key ID and signatures, are new each run.
// Usage: node ledger_battery.js wasm_exec.js ledger.wasm TRACE.jsonl
const fs = require('fs');
const [, , execJs, wasmFile, traceFile] = process.argv;
require(require('path').resolve(execJs));
const go = new globalThis.Go();
WebAssembly.instantiate(fs.readFileSync(wasmFile), go.importObject).then((res) => {
  go.run(res.instance);
  const e = globalThis.vpnwLedger;
  const j = (s) => JSON.parse(s);
  const trace = fs.readFileSync(traceFile, 'utf8');
  j(e.keygen('main'));
  j(e.keygen('other'));
  const t0 = Date.now();
  const sealed = j(e.seal(trace, 8));
  const ms = Date.now() - t0;
  const v = j(e.verify(trace, sealed.ledger, 'main', ''));
  const proof = j(e.prove(trace, sealed.ledger, 25));
  const check = j(e.checkProof(proof.proof, 'main'));
  const m = j(e.matrix(trace, sealed.ledger, 25));
  const out = {
    version: e.version,
    records: sealed.records,
    ledgerLines: sealed.ledger.split('\n').length - 1,
    ledgerBytes: Buffer.byteLength(sealed.ledger),
    checkpoints: sealed.checkpoints.map((c) => `checkpoint ${c.cp}: records 1 to ${c.size}, root ${c.root}, chain ${c.chain}`),
    verify: v.intact ? `intact: ${v.records} records, ${v.checked} checkpoints` : v.problem.said,
    proof: { line: proof.line, leaf: proof.leaf, path: proof.path, bytes: proof.bytes, holds: check.holds },
    matrix: m.rows.map((r) => `${r.name} | ${r.problem ? r.problem.said : 'nothing found'} | ${r.caught ? 'yes' : 'no'}`),
  };
  console.log(JSON.stringify(out, null, 1));
  console.error(`sealed in ${ms} ms`);
  process.exit(0);
});
