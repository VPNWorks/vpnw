// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

// Plays the Ledger demo in headless Chromium and checks it: the engine loads,
// the page seals the trace to the same roots and chains as the command line
// (results/ledger-alpha/demo.txt), every change in step 3 is named at the
// line the command line names, the twelve cases of step 4 are caught at the
// lines of tamper.txt, the proof holds and its forgeries don't, the witness
// catches the cut, nothing overflows a phone screen, and nothing logs an
// error. Screenshots of every step go to OUT.
//   NODE_PATH=... node check_ledger_demo.js URL OUT
const { chromium } = require('playwright');
const fs = require('fs');
const [, , url, out] = process.argv;
fs.mkdirSync(out, { recursive: true });

// What vpnw-ledger gives for recordings/1-trace-1.jsonl sealed with
// --every 8: these hashes depend on the records alone, not on the key.
const roots = [
  '3190285b489233c6176fdcfd5410f325bce542f840967f8c8ba0c2d2b7d7c990',
  '51bfe759947d270359b04342ccc94c7efbebba6f157515d79dd1d0039488e700',
  '23b61e7521ee56edecb6ad5ff5f25df9b1bdedfd8b683ce36c5221159e8e17c6',
  '022a83034e598c35315df8fd2b8206c5f11e7b7ee330b6f93a084db29e5c841c',
];
const chains = [
  '80511d1bc442ee24f2caa4dfc497dfff44e770e415d6a84c4f10daae916abe53',
  '96e3d706450a277e8d563b6bfd79d499e7a0b111bbe873d19242a30558f39a89',
  'dbcd44777ca0df848922701b36cab5a291d857c86cd2375ba330315a08bc7339',
  'f43fef60081d109389f0186a8e17f9856286c406ef2bef1db4137f959ba454f9',
];
const changes = {
  edit: ['records', '25', 'changed'], delete: ['records', '25', 'missing'], swap: ['records', '25', 'swapped'],
  conn: ['records', '22', 'missing'], cut: ['records', '22', 'cut'],
};
const matrix = [['records', 25], ['records', 25], ['records', 25], ['records', 25], ['records', 25], ['ledger', 33],
  ['ledger', 10], ['ledger', 33], ['ledger', 29], ['ledger', 33], ['records', 29], ['records', 25]];

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
  const go = async (p, k) => { await p.click(`#steps button[data-step="${k}"]`); await p.waitForTimeout(150); };
  const attr = async (p, sel, a) => p.getAttribute(sel, a);

  const p = await open({ width: 1280, height: 900 });
  console.log('status:', (await p.textContent('#status')).trim());
  check('trace lines', String(await p.locator('#trace-list .ln').count()), '28');
  check('lines of the connection to evil.example', String(await p.locator('#trace-list .ln.evil').count()), '5');
  check('t-events', await n(p, 't-events'), '28');
  check('t-conns', await n(p, 't-conns'), '5');
  check('t-evil', await n(p, 't-evil'), '865 B');
  await p.screenshot({ path: `${out}/1-record.png`, fullPage: true });

  await go(p, 2);
  check('s-records', await n(p, 's-records'), '28');
  check('s-cps', await n(p, 's-cps'), '4');
  check('ledger lines', String(await p.locator('#ledger-view .ln').count()), '33');
  check('checkpoint lines', String(await p.locator('#ledger-view .ln.cp').count()), '4');
  const ledger = await p.textContent('#ledger-view');
  roots.forEach((r, i) => check(`checkpoint ${i + 1} root and chain as on the command line`, ledger.includes(r) && ledger.includes(chains[i]) ? 'yes' : 'no', 'yes'));
  check('the signed text', (await p.textContent('#signed-text')).startsWith('vpnw-ledger checkpoint v1\nlog 1-trace-1.jsonl\ncp 4\nsize 28\nroot ' + roots[3]) ? 'yes' : 'no', 'yes');
  await p.screenshot({ path: `${out}/2-seal.png`, fullPage: true });

  await go(p, 3);
  check('the untouched record', await attr(p, '#verdict', 'data-intact'), 'yes');
  for (const [act, [file, line, kind]] of Object.entries(changes)) {
    await p.click(`#tamper-actions button[data-act="${act}"]`);
    const got = [await attr(p, '#verdict', 'data-file'), await attr(p, '#verdict', 'data-line'), await attr(p, '#verdict', 'data-kind')].join(' ');
    check(`change "${act}" named`, got, `${file} ${line} ${kind}`);
    check(`change "${act}" highlighted line`, (await p.textContent('#edit-list .ln.hit .no')).trim(), line);
    if (act === 'edit') await p.screenshot({ path: `${out}/3-change.png`, fullPage: true });
  }
  await p.click('#tamper-actions button[data-act="undo"]');
  check('undo', await attr(p, '#verdict', 'data-intact'), 'yes');
  await p.click('.edit-own summary');
  const text = await p.inputValue('#trace-text');
  await p.fill('#trace-text', text.split('\n').filter((_, i) => i !== 2).join('\n'));
  await p.waitForTimeout(600);
  check('your own edit: line 3 deleted', [await attr(p, '#verdict', 'data-line'), await attr(p, '#verdict', 'data-kind')].join(' '), '3 missing');

  await go(p, 4);
  check('m-cases', await n(p, 'm-cases'), '12');
  check('m-caught', await n(p, 'm-caught'), '12');
  const rows = await p.locator('#matrix-body tr').evaluateAll((trs) => trs.map((tr) => [tr.dataset.file, Number(tr.dataset.line), tr.dataset.caught]));
  matrix.forEach(([file, line], i) => check(`case ${i + 1} named`, rows[i] ? `${rows[i][0]} ${rows[i][1]} ${rows[i][2]}` : 'none', `${file} ${line} yes`));
  await p.screenshot({ path: `${out}/4-matrix.png`, fullPage: true });

  await go(p, 5);
  check('p-path', await n(p, 'p-path'), '4');
  check('p-bytes', await n(p, 'p-bytes'), '1,087');
  check('p-others', await n(p, 'p-others'), '27');
  check('the proof holds', await attr(p, '#proof-verdict', 'data-holds'), 'yes');
  check('the proof is of line 25, evil.example', (await p.textContent('#proof-text')).includes('"line": 25,') && (await p.textContent('#proof-text')).includes('evil.example') ? 'yes' : 'no', 'yes');
  await p.screenshot({ path: `${out}/5-proof.png`, fullPage: true });
  await p.click('#btn-forge-proof');
  check('a changed record in the proof', await attr(p, '#proof-verdict', 'data-holds'), 'no');
  check('what the check said', (await p.textContent('#proof-verdict')).includes("the record doesn't match the proof's hash") ? 'yes' : 'no', 'yes');
  await p.click('#btn-other-key');
  check('another key', await attr(p, '#proof-verdict', 'data-holds'), 'no');
  await p.selectOption('#prove-line', '6');
  check('a proof for line 6 holds', await attr(p, '#proof-verdict', 'data-holds'), 'yes');

  await go(p, 6);
  await p.click('#btn-cut');
  check('c-records', await n(p, 'c-records'), '24');
  await p.click('#btn-alone');
  check('the two files alone', await attr(p, '#cut-verdict', 'data-intact'), 'yes');
  await p.screenshot({ path: `${out}/6-cut-alone.png`, fullPage: true });
  await p.click('#btn-witness');
  check('with the witness', [await attr(p, '#cut-verdict', 'data-file'), await attr(p, '#cut-verdict', 'data-line'), await attr(p, '#cut-verdict', 'data-kind')].join(' '), 'records 25 cut');
  await p.screenshot({ path: `${out}/6-cut-witness.png`, fullPage: true });

  // A phone: every step fits the width.
  const m = await open({ width: 390, height: 844 });
  for (let k = 1; k <= 6; k++) {
    await go(m, k);
    if (k === 3) await m.click('#tamper-actions button[data-act="edit"]');
    if (k === 6) { await m.click('#btn-cut'); await m.click('#btn-witness'); }
    const over = await m.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
    check(`phone step ${k} horizontal overflow px`, String(over), '0');
    const clipped = await m.evaluate(() => [...document.querySelectorAll('.stage-foot .btn, .actions .btn')].filter((b) => {
      if (!b.offsetParent) return false;
      const r = document.createRange();
      r.selectNodeContents(b);
      return r.getBoundingClientRect().width > b.clientWidth + 0.5;
    }).map((b) => b.textContent));
    check(`phone step ${k} buttons whose label doesn't fit`, clipped.length ? clipped.join(', ') : 'none', 'none');
    await m.screenshot({ path: `${out}/phone-${k}.png`, fullPage: true });
  }
  check('network requests', requests.length ? requests.join(' ') : 'none', 'none');
  check('console errors', errors.length ? errors.join(' | ') : 'none', 'none');
  await browser.close();
  console.log(failures ? `${failures} check(s) failed` : 'all checks passed');
  process.exit(failures ? 1 : 0);
})();
