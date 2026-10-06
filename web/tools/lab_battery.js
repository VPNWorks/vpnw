// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

// Runs Lab's browser engine in Node on the demo's recordings, prints what it
// decided, and checks it against the command line's verdicts on the same
// files (vpnw-lab verdict --json). Exits 1 on any difference.
// Usage: node lab_battery.js wasm_exec.js lab.wasm demo-verdicts.json
const fs = require('fs');
const [, , execJs, wasmFile, cliFile] = process.argv;
require(require('path').resolve(execJs));
const cli = {};
fs.readFileSync(cliFile, 'utf8').trim().split('\n').forEach((l) => { const r = JSON.parse(l); cli[r.app + ' ' + r.scenario] = r; });
const go = new globalThis.Go();
WebAssembly.instantiate(fs.readFileSync(wasmFile), go.importObject).then((res) => {
  go.run(res.instance);
  const L = globalThis.vpnwLab;
  const t0 = Date.now();
  const list = JSON.parse(L.recordings());
  const fields = ['status', 'summary', 'sent', 'tunnel', 'leaked', 'lost', 'fault_on', 'fault_off', 'stop', 'recovery_ms'];
  let failures = 0;
  const out = { version: L.version, recordings: [] };
  for (const r of list) {
    const a = JSON.parse(L.analyze(r.name));
    const rep = a.report;
    const c = cli[rep.app + ' ' + rep.scenario];
    const row = { name: r.name, lines: r.lines, arrivals: a.arrivals };
    fields.forEach((f) => { row[f] = rep[f]; });
    row.windows = rep.windows.map((w) => `${w.probes} probes ${w.kinds.join('+')} ${w.start}-${w.end} s, ${w.after_ms} ms after ${w.after}`);
    out.recordings.push(row);
    if (!c) { console.error(`${r.name}: no command-line verdict`); failures++; continue; }
    for (const f of fields) {
      if (JSON.stringify(rep[f]) !== JSON.stringify(c[f])) { console.error(`${r.name}: ${f} ${rep[f]} in the browser, ${c[f]} on the command line`); failures++; }
    }
    if (JSON.stringify(rep.windows) !== JSON.stringify(c.windows) || JSON.stringify(rep.kinds) !== JSON.stringify(c.kinds)) {
      console.error(`${r.name}: windows or kinds differ`); failures++;
    }
  }
  // A recording given as text decides the same as the one inside.
  const pasted = JSON.parse(L.decide(fs.readFileSync(require('path').join(__dirname, '../../engine/internal/lab/demo/', list[1].name), 'utf8')));
  if (pasted.report.summary !== out.recordings[1].summary) { console.error('decide on text differs'); failures++; }
  const bad = JSON.parse(L.decide('{"t":"2026-10-05T21:00:00Z","ev":"sent"}'));
  out.badRecording = bad.error;
  console.log(JSON.stringify(out, null, 1));
  console.error(`decided ${list.length} recordings in ${Date.now() - t0} ms; ${failures ? failures + ' differences from the command line' : 'the same as the command line'}`);
  process.exit(failures ? 1 : 0);
});
