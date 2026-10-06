// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

// Plays the Exit demo in headless Chromium and checks it: the engine loads,
// every step shows what the command line read from the same recording
// (vpnw-exit join and decide, in results/exit-alpha/), the policy editor runs
// the exit's code, nothing overflows a phone screen, the page asks for nothing
// over the network, and nothing logs an error. Screenshots of every step go
// to OUT.
//   NODE_PATH=$(npm root -g) node check_exit_demo.js URL OUT RESULTS_DIR
// RESULTS_DIR holds demo-join.json, demo-decide.json, demo.txt and
// network.txt, as tools/measure-exit.sh writes them.
const { chromium } = require('playwright');
const fs = require('fs');
const path = require('path');
const [, , url, out, res] = process.argv;
if (!url || !out || !res) {
  console.error('usage: node check_exit_demo.js URL OUT RESULTS_DIR');
  process.exit(1);
}
fs.mkdirSync(out, { recursive: true });

let failures = 0;
function check(name, got, want) {
  const ok = got === want;
  if (!ok) failures++;
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${name}: ${got}${ok ? '' : ` (want ${want})`}`);
}
function need(name, v) {
  if (v == null) {
    console.log(`FAIL ${name}: not found in ${res}`);
    failures++;
  }
  return v;
}

// What the command line read from the recording.
const join = JSON.parse(fs.readFileSync(path.join(res, 'demo-join.json'), 'utf8'));
const decide = fs.readFileSync(path.join(res, 'demo-decide.json'), 'utf8').split('\n').filter((l) => l.trim()).map((l) => JSON.parse(l));
const demoTxt = fs.readFileSync(path.join(res, 'demo.txt'), 'utf8');
const network = fs.readFileSync(path.join(res, 'network.txt'), 'utf8');
const switches = [...demoTxt.matchAll(/^\s+(agent-\d) connection #(\d+): gave up on (\S+) after (\d+) ms .*; moved to (\S+); open (\d+) ms after its dial began$/gm)]
  .map((m) => ({ agent: m[1], from: m[3], ms: m[4], to: m[5], open: m[6] }));
const decisions = need('decisions in the exits\' records', (demoTxt.match(/^Decisions in the exits' records: (\d+)/m) || [])[1]);
const runMs = need('length of the run', (demoTxt.match(/^The run took (\d+) ms/m) || [])[1]);
const recorded = need('date of the run', (demoTxt.match(/^Recorded on (\d{4}-\d\d-\d\d)/m) || [])[1]);
const diff = need('differential line', network.match(/^differential: (\d+) requests under (\d+) policies.*: (\d+) of (\d+) agree/m));

const rows = join.rows;
// Rows of connections the Agents' records have, and rows of clients with no
// Agent record (the tampered client's), as vpnw-exit join tells them apart.
const noAgent = rows.filter((r) => r.agent.startsWith('not in these records'));
const viaAgent = rows.filter((r) => !noAgent.includes(r));
function source(client, exit) {
  const s = new Set(viaAgent.filter((r) => r.client === client && r.exit === exit && r.at_exit.startsWith('open from '))
    .map((r) => r.at_exit.slice('open from '.length)));
  return s.size === 1 ? [...s][0] : `${s.size} addresses`;
}

(async () => {
  const browser = await chromium.launch();
  const errors = [];
  const remote = [];
  async function open(viewport) {
    const ctx = await browser.newContext({ viewport });
    const p = await ctx.newPage();
    p.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()); });
    p.on('pageerror', (e) => errors.push(String(e)));
    p.on('request', (r) => { if (!/^(file|data|blob):/.test(r.url())) remote.push(r.url()); });
    await p.goto(url);
    await p.waitForSelector('html[data-ready="1"]', { timeout: 30000 });
    return p;
  }
  const n = async (p, id) => (await p.textContent(`#${id} .n`)).trim();
  const go = async (p, k) => { await p.click(`#steps button[data-step="${k}"]`); await p.waitForTimeout(150); };
  const all = async (p, k) => {
    await p.click(`#scene-${k} button[data-skip="${k}"]`);
    await p.waitForSelector(`#log-${k}[data-done="1"]`, { timeout: 5000 });
    await p.waitForTimeout(700); // let the entries fade in before a screenshot
  };

  const p = await open({ width: 1280, height: 900 });
  const status = (await p.textContent('#status')).trim();
  console.log('status:', status);
  check('status names the join', status.includes(`${join.joined} of ${join.via_exit} connections`) ? 'yes' : 'no', 'yes');
  const links = await p.$$eval('header a', (as) => as.map((a) => a.href));
  check('header links', [...new Set(links)].join(' '), 'https://vpnw.com/');

  // Step 1: the setup, read by the exit's code from the recorded files.
  await go(p, 1);
  check('exits', await n(p, 't1-exits'), '2');
  check('clients at each exit', await n(p, 't1-clients'), '3');
  check('fixed addresses for the agents', await n(p, 't1-addrs'), '4');
  check('setup rows', String(await p.locator('#setup-body tr').count()), '3');
  check('exit-de listens where the Agents gave up', (await p.textContent('#addr-de')).trim(), switches.length ? switches[0].from : 'a switch');
  check('exit-nl listens where the Agents moved', (await p.textContent('#addr-nl')).trim(), switches.length ? switches[0].to : 'a switch');
  for (const client of ['agent-1', 'agent-2']) {
    const cells = await p.locator('#setup-body tr', { hasText: client }).first().locator('td').allTextContents();
    check(`${client} at exit-de`, cells[2], source(client, 'exit-de'));
    check(`${client} at exit-nl`, cells[3], source(client, 'exit-nl'));
  }
  await p.screenshot({ path: `${out}/1-setup.png`, fullPage: true });

  // Step 2: fixed addresses.
  await go(p, 2);
  await all(p, 2);
  const deOpen = viaAgent.filter((r) => r.exit === 'exit-de' && r.at_exit.startsWith('open from ')).length;
  check('reached the partner through exit-de', await n(p, 't2-reached'), String(deOpen));
  check('step 2 entries', String(await p.locator('#log-2 .entry').count()), String(deOpen));
  check('agent-1\'s address', await n(p, 't2-a1'), source('agent-1', 'exit-de'));
  check('agent-2\'s address', await n(p, 't2-a2'), source('agent-2', 'exit-de'));
  await p.screenshot({ path: `${out}/2-fixed.png`, fullPage: true });

  // Step 3: checked at both ends.
  await go(p, 3);
  await all(p, 3);
  check('refused at the Agent', await n(p, 't3-agent'), String(join.decided_at_agent));
  check('refused at the exit', await n(p, 't3-exit'), String(viaAgent.filter((r) => r.at_exit.startsWith('refused: ')).length));
  const pair = await p.locator('#pair-3 pre').allTextContents();
  check('both records of the refused connection', pair.length === 2 && pair.every((t) => t.includes('deny_private')) ? 'yes' : 'no', 'yes');
  const outro3 = await p.textContent('#scene-3 .scene-outro');
  check('differential in the text', outro3.includes(`${diff[1]} requests under ${diff[2]} policies`) ? 'yes' : 'no', 'yes');
  check('differential: all agree', `${diff[3]} of ${diff[4]}`, `${diff[1]} of ${diff[1]}`);
  await p.screenshot({ path: `${out}/3-both-ends.png`, fullPage: true });

  // Step 4: the tampered client, and the exit's code deciding in the page.
  await go(p, 4);
  await all(p, 4);
  check('tampered requests', await n(p, 't4-requests'), String(noAgent.length));
  check('tampered requests are the join\'s other runs', String(noAgent.length), String(join.other_runs));
  check('refused by exit-de', await n(p, 't4-refused'), String(noAgent.filter((r) => r.at_exit.startsWith('refused: ')).length));
  check('reached a server', await n(p, 't4-servers'), String(noAgent.filter((r) => r.at_exit.startsWith('open from ')).length));
  check('decisions asked of the command line', String(decide.length), String(await p.locator('#ask-chips button').count()));
  for (const d of decide) {
    await p.click(`#ask-chips button:text-is("${d.target}")`);
    const v = p.locator('#verdict');
    const got = `${await v.getAttribute('data-outcome')} ${await v.getAttribute('data-rule')}`;
    check(`decide ${d.target}`, got, `${d.outcome} ${d.rule || ''}`);
    if (d.outcome === 'allow') check(`${d.target} leaves from`, (await v.textContent()).includes(`Allowed, from ${d.source}`) ? d.source : 'another address', d.source);
  }
  await p.screenshot({ path: `${out}/4-tampered.png`, fullPage: true });
  const policy = await p.inputValue('#policy-text');
  await p.fill('#ask-target', 'attacker.test:443');
  await p.fill('#policy-text', policy.replace('default = "deny"', 'default = "allow"'));
  await p.click('#ask-btn');
  check('edited policy: attacker.test allowed by default', `${await p.getAttribute('#verdict', 'data-outcome')} ${await p.getAttribute('#verdict', 'data-rule')}`, 'allow default');
  await p.fill('#ask-target', '169.254.169.254:80');
  await p.click('#ask-btn');
  check('edited policy: metadata still refused', `${await p.getAttribute('#verdict', 'data-outcome')} ${await p.getAttribute('#verdict', 'data-rule')}`, 'denied deny_private');
  await p.fill('#policy-text', policy + '\nport = 22\n');
  await p.click('#ask-btn');
  const bad = (await p.textContent('#policy-check')).trim();
  console.log('a broken file:', bad);
  check('a broken file is refused with its name', bad.includes('agent-2.toml') && (await p.getAttribute('#policy-check', 'class')).includes('bad') ? 'yes' : 'no', 'yes');
  await p.click('#policy-reset');
  check('back to the recorded file', (await p.inputValue('#policy-text')) === policy ? 'yes' : 'no', 'yes');

  // Step 5: exit-de fails.
  await go(p, 5);
  await all(p, 5);
  check('agents that moved', await n(p, 't5-moved'), String(switches.length));
  check('failed requests', await n(p, 't5-failed'),
    String(viaAgent.filter((r) => r.agent.startsWith('failed') && !r.at_exit.startsWith('refused: ')).length));
  for (const s of switches) {
    const t = p.locator(`#t5-${s.agent}`);
    check(`${s.agent} gave up on exit-de after (ms)`, await t.getAttribute('data-switch-ms'), s.ms);
    check(`${s.agent} open through exit-nl after (ms)`, await t.getAttribute('data-open-ms'), s.open);
  }
  const outro5 = await p.textContent('#outro-5');
  check('addresses at exit-nl', outro5.includes(`from ${source('agent-1', 'exit-nl')} and agent-2 from ${source('agent-2', 'exit-nl')}`) ? 'yes' : 'no', 'yes');
  await p.screenshot({ path: `${out}/5-failover.png`, fullPage: true });

  // Step 6: the joined record.
  await go(p, 6);
  check('joined', await n(p, 't6-joined'), `${join.joined} of ${join.via_exit}`);
  check('stopped at the Agent', await n(p, 't6-local'), String(join.decided_at_agent));
  check('from a client with no Agent', await n(p, 't6-other'), String(join.other_runs));
  check('recorded decisions made again', await n(p, 't6-redecided'), `${decisions} of ${decisions}`);
  const trs = await p.$$eval('#join-body tr', (rs) => rs.map((r) => [...r.querySelectorAll('td')].map((td) => td.textContent).join(' | ')));
  const want = rows.map((r) => [r.run ? `${r.run} #${r.conn}` : 'no run ID', r.target, r.agent, (r.exit ? r.exit + ': ' : '') + r.at_exit].join(' | '));
  check('join rows', String(trs.length), String(want.length));
  check('join rows match vpnw-exit join', trs.every((t, i) => t === want[i]) ? 'yes' : 'no', 'yes');
  await p.click('#join-body tr.pick');
  const pair6 = await p.locator('#pair-6 pre').allTextContents();
  check('a row shows both records', pair6.length === 2 && pair6.every((t) => t.includes('connection.open') || t.includes('policy.')) ? 'yes' : 'no', 'yes');
  await p.screenshot({ path: `${out}/6-join.png`, fullPage: true });

  check('length of the run', (await p.textContent('#run-secs')).trim(), (Number(runMs) / 1000).toFixed(1));
  check('date of the run', (await p.textContent('#recorded-on')).trim(),
    new Date(recorded + 'T00:00:00Z').toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric', timeZone: 'UTC' }));

  // A phone: every step fits the width.
  const m = await open({ width: 390, height: 844 });
  for (let k = 1; k <= 6; k++) {
    await go(m, k);
    if (k >= 2 && k <= 5) await all(m, k);
    const over = await m.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
    check(`phone step ${k} horizontal overflow px`, String(over), '0');
    await m.screenshot({ path: `${out}/phone-${k}.png`, fullPage: true });
  }
  check('requests over the network', remote.length ? remote.join(' ') : 'none', 'none');
  check('console errors', errors.length ? errors.join(' | ') : 'none', 'none');
  await browser.close();
  console.log(failures ? `${failures} check(s) failed` : 'all checks passed');
  process.exit(failures ? 1 : 0);
})().catch((err) => {
  console.log('FAIL', err && err.stack ? err.stack : err);
  process.exit(1);
});
