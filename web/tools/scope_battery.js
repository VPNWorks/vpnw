// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

// Runs Scope's browser engine in Node and prints the demo's numbers, so they
// can be compared with the command-line run in results/scope-alpha/demo.txt.
// Usage: node scope_battery.js wasm_exec.js scope.wasm
const fs = require('fs');
const [,, execJs, wasmFile] = process.argv;
require(require('path').resolve(execJs));
const go = new globalThis.Go();
WebAssembly.instantiate(fs.readFileSync(wasmFile), go.importObject).then((res) => {
  go.run(res.instance);
  const s = globalThis.vpnwScope;
  const office = JSON.parse(s.office());
  const t0 = Date.now();
  const learned = JSON.parse(s.learn());
  const ms = Date.now() - t0;
  const replay = JSON.parse(s.replay(learned.draft));
  const stolen = JSON.parse(s.stolen(learned.draft));
  const nft = JSON.parse(s.export(learned.draft, 'nft', false));
  const check = JSON.parse(s.check(learned.draft + '\n[people.nobody]\n'));
  const out = {
    version: s.version,
    people: office.people.length, systems: office.systems.length, groups: office.groups.length,
    learnFlows: office.learnFlows, replayFlows: office.replayFlows,
    learned: learned.flows, counts: learned.counts,
    replay: { flows: replay.flows, allowed: replay.allowed, denied: replay.denied,
      blocked: replay.blocked.map((b) => `${b.person} ${b.system} ${b.service} ${b.count}`) },
    stolen: { attempts: stolen.attempts, reached: stolen.reached, systems: stolen.systems },
    nftBytes: nft.text.length, badDraft: check.error,
  };
  console.log(JSON.stringify(out, null, 1));
  console.error(`learned in ${ms} ms`);
  process.exit(0);
});
