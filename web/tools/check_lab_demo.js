// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

// Plays the Lab demo in headless Chromium and checks it: the engine loads,
// every step shows the numbers the command line gives for the same
// recordings (vpnw-lab verdict --json), picking a probe explains it, nothing
// overflows a phone screen, and nothing logs an error. Screenshots of every
// step go to OUT.
//   NODE_PATH=... node check_lab_demo.js URL OUT demo-verdicts.json
const { chromium } = require('playwright');
const fs = require('fs');
const [, , url, out, cliFile] = process.argv;
fs.mkdirSync(out, { recursive: true });

const cli = {};
fs.readFileSync(cliFile, 'utf8').trim().split('\n').forEach((l) => { const r = JSON.parse(l); cli[r.app] = r; });
const fmt = (n) => Number(n).toLocaleString('en-US');
const sec = (s) => (Math.round(s * 100) / 100).toFixed(2) + ' s';

let failures = 0;
function check(name, got, want) {
  const ok = got === want;
  if (!ok) failures++;
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${name}: ${got}${ok ? '' : ` (want ${want})`}`);
}

(async () => {
  const browser = await chromium.launch();
  const errors = [];
  const requests = [];
  async function open(viewport) {
    const ctx = await browser.newContext({ viewport });
    const p = await ctx.newPage();
    p.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()); });
    p.on('pageerror', (e) => errors.push(String(e)));
    p.on('request', (r) => { if (!r.url().startsWith('file:') && !r.url().startsWith('data:')) requests.push(r.url()); });
    await p.goto(url);
    await p.waitForSelector('html[data-ready="1"]', { timeout: 30000 });
    return p;
  }
  const n = async (p, id) => (await p.textContent(`#${id} .n`)).trim();
  const go = async (p, k) => { await p.click(`#steps button[data-step="${k}"]`); await p.waitForTimeout(200); };
  async function tiles(p, prefix, r, label) {
    check(`${label}: sent`, await n(p, `${prefix}-sent`), fmt(r.sent));
    check(`${label}: through the tunnel`, await n(p, `${prefix}-tunnel`), fmt(r.tunnel));
    check(`${label}: leaked`, await n(p, `${prefix}-leaked`), fmt(r.leaked));
    check(`${label}: held back`, await n(p, `${prefix}-lost`), fmt(r.lost));
    check(`${label}: verdict`, (await p.textContent(`#${prefix}-verdict`)).trim(), `Lab's verdict: ${r.summary}`);
  }

  const p = await open({ width: 1280, height: 900 });
  console.log('status:', (await p.textContent('#status')).trim());
  check('namespaces drawn', String(await p.locator('.bench .ns').count()), '4');
  check('exit address', (await p.textContent('#b-exit')).trim(), '192.0.2.20');
  check('home address', (await p.textContent('#b-home')).trim(), '203.0.113.2');
  await p.screenshot({ path: `${out}/1-bench.png`, fullPage: true });

  await go(p, 2);
  const leak = cli['dns-leak'], correct = cli['correct'];
  const ticks = await p.locator('#plan .tick').allTextContents();
  check('timetable: fault on', ticks[1], sec(leak.fault_on));
  check('timetable: fault off', ticks[2], sec(leak.fault_off));
  check('timetable: stop', ticks[3], sec(leak.stop));
  check('the dns-leak client points DNS at the home router', (await p.textContent('#log-leak')).includes('DNS set to 192.168.1.1') ? 'yes' : 'no', 'yes');
  check('the correct client never does', (await p.textContent('#log-correct')).includes('192.168.1.1') ? 'yes' : 'no', 'no');
  await p.screenshot({ path: `${out}/2-fault.png`, fullPage: true });

  await go(p, 3);
  await tiles(p, 'c', correct, 'correct');
  check('correct: probes drawn', String(await p.locator('#tl-correct rect.p-tunnel, #tl-correct rect.p-lost, #tl-correct rect.p-leak').count()), String(correct.sent));
  check('correct: no leak drawn', String(await p.locator('#tl-correct rect.p-leak').count()), '0');
  console.log('correct:', (await p.textContent('#outro-correct')).trim());
  await p.screenshot({ path: `${out}/3-correct.png`, fullPage: true });

  await go(p, 4);
  await tiles(p, 'l', leak, 'dns-leak');
  check('dns-leak: leaks drawn', String(await p.locator('#tl-leak rect.p-leak').count()), String(leak.leaked));
  const w = leak.windows[0];
  const outro = (await p.textContent('#outro-leak')).trim();
  check('dns-leak: the window', outro.startsWith(`${fmt(w.probes)} DNS queries reached the home router's resolver between ${sec(w.start)} and ${sec(w.end)}`) ? 'yes' : 'no', 'yes');
  check('dns-leak: first seen', outro.includes(`first ${Math.round(w.after_ms)} ms after`) ? 'yes' : 'no', 'yes');
  check('dns-leak: last seen', outro.includes(`last ${Math.round(w.before_ms)} ms before`) ? 'yes' : 'no', 'yes');
  console.log('dns-leak:', outro);
  await p.screenshot({ path: `${out}/4-leak.png`, fullPage: true });

  await go(p, 5);
  check('a leaked probe is picked', (await p.textContent('#inspect-why')).includes('leaked') ? 'yes' : 'no', 'yes');
  console.log('picked:', (await p.textContent('#inspect-title')).trim());
  check('it reached the home router', (await p.textContent('#inspect')).includes('the home router\'s resolver, from 192.168.1.10') ? 'yes' : 'no', 'yes');
  const first = await p.locator('#zoom-correct rect.p-tunnel').first().boundingBox();
  await p.mouse.click(first.x + first.width / 2, first.y + first.height / 2);
  await p.waitForTimeout(200);
  check('a correct probe before the fault went through', (await p.textContent('#inspect-why')).includes('through the tunnel') ? 'yes' : 'no', 'yes');
  await p.screenshot({ path: `${out}/5-probe.png`, fullPage: true });

  await go(p, 6);
  await tiles(p, 'o', cli['no-kill-switch'], 'no-kill-switch');
  await p.click('#scene-6 .seg button[data-rec="follows-routes-route-push.jsonl"]');
  await p.waitForTimeout(150);
  await tiles(p, 'o', cli['follows-routes'], 'follows-routes');
  check('matrix cells', String(await p.locator('#matrix tbody td').count()), '48');
  await p.screenshot({ path: `${out}/6-other.png`, fullPage: true });

  // A phone: every step fits the width.
  const m = await open({ width: 390, height: 844 });
  for (let k = 1; k <= 6; k++) {
    await go(m, k);
    const over = await m.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
    check(`phone step ${k} horizontal overflow px`, String(over), '0');
    await m.screenshot({ path: `${out}/phone-${k}.png`, fullPage: true });
  }
  check('network requests', requests.length ? requests.join(' ') : 'none', 'none');
  check('console errors', errors.length ? errors.join(' | ') : 'none', 'none');
  await browser.close();
  console.log(failures ? `${failures} check(s) failed` : 'all checks passed');
  process.exit(failures ? 1 : 0);
})();
