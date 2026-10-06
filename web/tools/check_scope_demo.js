// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

// Plays the Scope demo in headless Chromium and checks it: the engine loads,
// every step shows the numbers of the Alpha report, the review changes the
// draft, nothing overflows a phone screen, and nothing logs an error.
// Screenshots of every step go to OUT.
//   NODE_PATH=... node check_scope_demo.js URL OUT
const { chromium } = require('playwright');
const fs = require('fs');
const [, , url, out] = process.argv;
fs.mkdirSync(out, { recursive: true });

const expect = {
  't-flows': '20,232', 't-group': '39', 't-person': '11', 't-review': '3',
  'r-flows': '10,387', 'r-allowed': '10,375', 'r-denied': '12',
  's-attempts': '144', 's-reached': '8', 's-systems': '6 of 12', 's-refused': '136',
};
let failures = 0;
function check(name, got, want) {
  const ok = got === want;
  if (!ok) failures++;
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${name}: ${got}${ok ? '' : ` (want ${want})`}`);
}

(async () => {
  const browser = await chromium.launch();
  const errors = [];
  async function open(viewport) {
    const ctx = await browser.newContext({ viewport });
    const p = await ctx.newPage();
    p.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()); });
    p.on('pageerror', (e) => errors.push(String(e)));
    await p.goto(url);
    await p.waitForSelector('html[data-ready="1"]', { timeout: 30000 });
    return p;
  }
  const n = async (p, id) => (await p.textContent(`#${id} .n`)).trim();
  const go = async (p, k) => { await p.click(`#steps button[data-step="${k}"]`); await p.waitForTimeout(150); };

  const p = await open({ width: 1280, height: 900 });
  console.log('status:', (await p.textContent('#status')).trim());
  check('teams', String(await p.locator('#teams .team').count()), '5');
  check('systems', String(await p.locator('#systems .sys').count()), '12');
  check('days of traffic', String(await p.locator('#bars i').count()), '21');
  await p.screenshot({ path: `${out}/1-office.png`, fullPage: true });

  await go(p, 2);
  for (const id of ['t-flows', 't-group', 't-person', 't-review']) check(id, await n(p, id), expect[id]);
  check('matrix cells', String(await p.locator('#matrix td').count()), '360');
  const allowed = await p.getAttribute('#matrix-note', 'data-allowed');
  console.log('pairs of person and system allowed by the draft:', allowed);
  await p.screenshot({ path: `${out}/2-learn.png`, fullPage: true });
  await p.click('#scene-2 .seg button[data-view="flat"]');
  check('flat view', String(await p.locator('#matrix td.flat').count()), '360');
  await p.click('#scene-2 .seg button[data-view="draft"]');

  await go(p, 3);
  check('review cards', String(await p.locator('#review-list .rv-card').count()), '3');
  await p.screenshot({ path: `${out}/3-review.png`, fullPage: true });
  const quinn = p.locator('#review-list .rv-card', { hasText: 'Quinn' });
  await quinn.locator('button', { hasText: 'Allow' }).click();
  check('after allowing Quinn', (await p.textContent('#draft-check')).includes('2 under review') ? 'yes' : 'no', 'yes');
  await go(p, 4);
  check('blocked after allowing Quinn', await n(p, 'r-denied'), '9');
  await go(p, 3);
  await p.locator('#review-list .rv-card', { hasText: 'Quinn' }).locator('button', { hasText: 'Keep blocked' }).click();
  const learned = await p.inputValue('#draft-text');
  await p.fill('#draft-text', learned + '\n[people.nobody]\n');
  await p.waitForTimeout(400);
  check('a broken draft is refused', (await p.textContent('#draft-check')).includes('"nobody" is not in the people file') ? 'yes' : 'no', 'yes');
  await go(p, 4);
  check('steps wait for a good draft', (await p.textContent('#replay-tiles')).includes('Fix it there first') ? 'yes' : 'no', 'yes');
  await go(p, 3);
  await p.click('#btn-reset');
  check('reset gives the learned draft', (await p.inputValue('#draft-text')) === learned ? 'yes' : 'no', 'yes');

  await go(p, 4);
  for (const id of ['r-flows', 'r-allowed', 'r-denied']) check(id, await n(p, id), expect[id]);
  check('blocked rows', String(await p.locator('#replay-body tr').count()), '2');
  console.log('new hire:', (await p.textContent('#newhire')).trim());
  await p.screenshot({ path: `${out}/4-replay.png`, fullPage: true });

  await go(p, 5);
  for (const id of ['s-attempts', 's-reached', 's-systems', 's-refused']) check(id, await n(p, id), expect[id]);
  await p.screenshot({ path: `${out}/5-stolen-draft.png`, fullPage: true });
  await p.click('#scene-5 .seg button[data-mode="flat"]');
  check('flat: reached', await n(p, 's-reached'), '144');
  check('flat: systems', await n(p, 's-systems'), '12 of 12');
  await p.screenshot({ path: `${out}/5-stolen-flat.png`, fullPage: true });
  await p.click('#scene-5 .seg button[data-mode="draft"]');

  await go(p, 6);
  const nft = await p.textContent('#export-out');
  check('nftables script', nft.includes('table inet vpnw_scope {') && nft.includes('reject with icmpx type admin-prohibited') ? 'yes' : 'no', 'yes');
  await p.screenshot({ path: `${out}/6-rules.png`, fullPage: true });
  await p.click('#scene-6 .seg button[data-format="watch"]');
  check('watch mode', (await p.textContent('#export-out')).includes('would be refused') ? 'yes' : 'no', 'yes');
  await p.click('#scene-6 .seg button[data-format="allowedips"]');
  check('AllowedIPs', (await p.textContent('#export-out')).includes('AllowedIPs = ') ? 'yes' : 'no', 'yes');

  // A phone: every step fits the width.
  const m = await open({ width: 390, height: 844 });
  for (let k = 1; k <= 6; k++) {
    await go(m, k);
    const over = await m.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
    check(`phone step ${k} horizontal overflow px`, String(over), '0');
    await m.screenshot({ path: `${out}/phone-${k}.png`, fullPage: true });
  }
  check('console errors', errors.length ? errors.join(' | ') : 'none', 'none');
  await browser.close();
  console.log(failures ? `${failures} check(s) failed` : 'all checks passed');
  process.exit(failures ? 1 : 0);
})();
