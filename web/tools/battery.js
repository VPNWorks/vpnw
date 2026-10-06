// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

// Runs the same calls through one build of the browser engine and prints
// one JSON line per answer. Usage: node battery.js wasm_exec.js engine.wasm trace.jsonl
const fs = require('fs');
const [,, execJs, wasmFile, traceFile] = process.argv;
require(require('path').resolve(execJs));
const go = new globalThis.Go();
const agent = `version = 1
name = "agent"
[policy]
default = "deny"
deny_private = true
allow = ["api.github.com", "files.pythonhosted.org", "telemetry.example.com", "tracker.office.internal"]
`;
const office = `version = 1
name = "office"
[paths.office]
type = "proxy"
url = "socks5h://10.8.0.1:1080"
`;
const openAllow = `version = 1
[policy]
default = "allow"
deny_private = true
deny = ["evil.example", "*.ads.example", "203.0.113.0/24"]
`;
const bad = [
  'version = 2\n[policy]\nallow=["a.com"]\n', 'version = 1\n[policy]\nallow = ["*"]\n', 'version = 1\n[policy]\nallow = [\n',
  'version = 1\n[policy]\ncolour = "red"\n', 'version = 1\n[policy]\nallow = ["github.com:99999"]\n', '[policy]\nallow=["x.com"]\n',
  'version = 1\n[policy]\nallow = ["*.*"]\n', 'version = 1\n[policy]\ndefault = "maybe"\n', 'version = 1\nname = "x"\n',
];
const dns = JSON.stringify({
  "api.github.com": ["140.82.112.6"], "files.pythonhosted.org": ["151.101.0.223"],
  "telemetry.example.com": ["93.184.215.14"], "evil.example": ["45.77.10.10"],
  "rebind.example": ["93.184.215.14", "10.0.0.7"], "localhost.example": ["127.0.0.1"],
});
const hosts = ["api.github.com", "evil.example", "tracker.office.internal", "169.254.169.254", "2130706433", "::ffff:127.0.0.1",
  "64:ff9b::a9fe:a9fe", "bad..name", "EXAMPLE.com.", "sub.api.github.com", "rebind.example", "localhost.example", "10.0.0.5",
  "2606:4700:4700::1111", "0x7f.1", "xn--bcher-kva.example", "b\u00fccher.example", "a".repeat(64) + ".com"];
const ports = [443, 80, 0, 70000];
const rules = ["github.com", "*.github.com", "10.0.0.0/8", "[::1]:443", "github.com:443", "*", "*.", "a b", "1.2.3.4:0", "::1", "*.10.0.0.1", "x*.com"];
const out = [];
WebAssembly.instantiate(fs.readFileSync(wasmFile), go.importObject).then((r) => {
  go.run(r.instance);
  const e = globalThis.vpnwEngine;
  out.push(["version", e.version, e.schema]);
  for (const p of [agent, office, openAllow, ...bad]) out.push(["compile", JSON.stringify(e.compile(p))]);
  for (const p of [agent, office, ...bad]) out.push(["parseConfig", JSON.stringify(e.parseConfig(p))]);
  for (const r of rules) out.push(["parseRule", r, JSON.stringify(e.parseRule(r))]);
  for (const p of [agent, openAllow, ""]) for (const h of hosts) for (const port of ports) for (const remote of [false, true])
    out.push(["plan", h, port, remote, JSON.stringify(e.plan(p, h, port, remote, dns))]);
  const trace = fs.readFileSync(traceFile, 'utf8');
  for (const w of [false, true]) {
    const r = e.learn(trace, "agent", w);
    r.toml = r.toml.replace(/, \d{4}-\d{2}-\d{2}\./, ", DATE.");
    out.push(["learn", w, JSON.stringify(r)]);
  }
  out.push(["learn-bad", JSON.stringify(e.learn('{"v":9,"type":"x"}\n', "a", false))]);
  for (const l of out) console.log(JSON.stringify(l));
  process.exit(0);
});
