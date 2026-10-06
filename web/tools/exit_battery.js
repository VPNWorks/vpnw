// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

// Runs Exit's browser engine in Node on the demo's recorded run and prints
// what the page will show, so it can be compared with the command line's
// reading of the same recording in results/exit-alpha/demo.txt.
// Usage: node exit_battery.js wasm_exec.js exit.wasm RECORDING_DIR
const fs = require('fs');
const path = require('path');
const [, , execJs, wasmFile, rec] = process.argv;
require(path.resolve(execJs));
const read = (n) => fs.readFileSync(path.join(rec, n), 'utf8');
const records = (n) => read(n).split('\n').filter((l) => l.trim()).map((l) => JSON.parse(l));
const go = new globalThis.Go();
WebAssembly.instantiate(fs.readFileSync(wasmFile), go.importObject).then((res) => {
  go.run(res.instance);
  const x = globalThis.vpnwExit;
  const files = {};
  for (const n of ['exit-de.toml', 'exit-nl.toml', 'agent-1.toml', 'agent-2.toml', 'ci.toml']) files[n] = read(n);
  const dns = read('dns.json');
  const exits = {};
  for (const name of ['exit-de', 'exit-nl']) {
    const p = JSON.parse(x.parse(name + '.toml', JSON.stringify(files)));
    if (!p.ok) throw new Error(name + ': ' + p.error);
    exits[name] = { listen: p.listen, clients: p.clients.map((c) => c.describe) };
  }

  // What exit-de decides for agent-2, as the page's step 4 asks it.
  const targets = ['169.254.169.254:80', 'attacker.test:443', 'intranet.partner.test:80', 'files.partner.test:80', 'api.partner.test:443', 'api.partner.test:80'];
  const decide = targets.map((t) => {
    const d = JSON.parse(x.decide('exit-de.toml', JSON.stringify(files), 'agent-2', t, dns));
    return [t, d.outcome, d.rule || '', d.reason || d.error || '', d.source || ''].join(' | ');
  });

  // Every decision in the exits' records, made again.
  let same = 0, total = 0;
  for (const name of ['exit-de', 'exit-nl']) {
    const att = {};
    for (const e of records(name + '.jsonl')) {
      if (e.type === 'connection.attempt') att[e.conn] = e.fields;
      if ((e.type === 'policy.allow' || e.type === 'policy.deny') && att[e.conn]) {
        const a = att[e.conn];
        const d = JSON.parse(x.decide(name + '.toml', JSON.stringify(files), a.client, `${a.host || a.ip}:${a.port}`, dns));
        const want = e.type === 'policy.allow' ? 'allow' : 'denied';
        total++;
        if (d.ok && d.rule === e.fields.rule && (d.outcome === want || (want === 'allow' && d.outcome === 'failed'))) same++;
      }
    }
  }

  const t0 = Date.now();
  const j = JSON.parse(x.join(read('agent-1.jsonl') + read('agent-2.jsonl'), read('exit-de.jsonl') + read('exit-nl.jsonl')));
  const ms = Date.now() - t0;
  console.log(JSON.stringify({
    exit: x.version, agent: x.agentVersion, exits,
    decide,
    redecided: `${same} of ${total}`,
    join: {
      agent_connections: j.agent_connections, via_exit: j.via_exit, decided_at_agent: j.decided_at_agent,
      exit_connections: j.exit_connections, other_runs: j.other_runs, joined: j.joined, complete: j.complete, problems: j.problems,
      rows: j.rows.map((r) => `${r.run || 'no run ID'} #${r.conn} ${r.target}: ${r.agent} | ${r.exit || ''} ${r.at_exit}`),
    },
  }, null, 1));
  console.error(`joined in ${ms} ms`);
  process.exit(0);
});
