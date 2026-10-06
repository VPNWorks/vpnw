// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

// Plays the demo in headless Chromium and checks it: engine loads, every step
// replays, the labs answer, no console errors. Screenshots go to OUT.
//   NODE_PATH=... node check_demo.js URL OUT [--quick]
const { chromium } = require('playwright');
const [, , url, out, quick] = process.argv;
const fs = require('fs');
fs.mkdirSync(out, { recursive: true });

(async () => {
  const browser = await chromium.launch();
  const errors = [];
  async function page(viewport) {
    const ctx = await browser.newContext({ viewport });
    const p = await ctx.newPage();
    p.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()); });
    p.on('pageerror', (e) => errors.push(String(e)));
    return p;
  }
  const p = await page({ width: 1280, height: 900 });
  await p.goto(url);
  await p.waitForFunction(() => !document.getElementById('btn-run').disabled, null, { timeout: 20000 });
  console.log('engine loaded:', await p.textContent('#engine-version'));
  await p.screenshot({ path: out + '/0-start.png', fullPage: false });

  // Play through, screenshotting each step when its conclusion shows.
  await p.click('#btn-play');
  for (let i = 0; i < 6; i++) {
    await p.waitForFunction((n) => document.getElementById('scene-no').textContent.startsWith('Step ' + n) &&
      !document.getElementById('scene-outro').hidden, i + 1, { timeout: 60000 });
    const title = await p.textContent('#scene-title');
    const lines = await p.$$eval('#term .l', (ls) => ls.length);
    const rows = await p.$$eval('#rec-body tr', (rs) => rs.length);
    console.log(`step ${i + 1}: ${title} | terminal lines ${lines} | table rows ${rows}`);
    await p.screenshot({ path: `${out}/step-${i + 1}.png`, fullPage: false });
    if (quick && i === 1) break;
  }
  await p.waitForTimeout(3500);
  console.log('after the end:', await p.textContent('#progress-text'), '/', await p.textContent('#play-label'));

  // The draft computed in the page.
  await p.click('#steps button:nth-child(2)');
  await p.waitForTimeout(300);
  await p.click('#btn-play'); // pause
  await p.click('#btn-learn-here');
  console.log('learn here:', (await p.textContent('#learn-here-note')).slice(0, 140));

  // Lab 1: the reviewed policy, direct and via the office.
  await p.click('#btn-run');
  console.log('lab direct:', await p.textContent('#run-verdict'));
  await p.check('input[name="path"][value="office"]', { force: true });
  await p.click('#btn-run');
  console.log('lab office:', await p.textContent('#run-verdict'));
  await p.locator('#lab-policy').screenshot({ path: out + '/lab-policy.png' });
  // The learned draft allows the token out.
  await p.click('#pol-presets .preset:nth-child(2)');
  await p.check('input[name="path"][value="direct"]', { force: true });
  await p.click('#btn-run');
  console.log('lab draft:', await p.textContent('#run-verdict'));
  // A broken policy.
  await p.fill('#pol-text', 'version = 1\n[policy]\nallow = ["*"]\n');
  await p.click('#btn-run');
  console.log('lab broken:', await p.textContent('#run-verdict'), '|', await p.textContent('#pol-check'));
  // Deny list + office path: refused (remote DNS weakens deny_private with default allow).
  await p.click('#pol-presets .preset:nth-child(3)');
  await p.check('input[name="path"][value="office"]', { force: true });
  await p.click('#btn-run');
  console.log('lab deny list via office:', await p.textContent('#run-verdict'));

  // Lab 2: every preset.
  await p.click('#pol-presets .preset:nth-child(1)');
  const n = await p.$$eval('#dest-presets .preset', (b) => b.length);
  for (let i = 1; i <= n; i++) {
    await p.click(`#dest-presets .preset:nth-child(${i})`);
    const big = await p.textContent('#dest-out .big');
    const why = await p.$eval('#dest-out', (e) => e.innerText.replace(/\s+/g, ' ').slice(0, 170));
    console.log(`dest ${i}: ${big} | ${why}`);
  }
  await p.locator('#lab-dest').screenshot({ path: out + '/lab-dest.png' });
  await p.screenshot({ path: out + '/full.png', fullPage: true });

  // Phone size.
  const m = await page({ width: 390, height: 844 });
  await m.goto(url);
  await m.waitForFunction(() => !document.getElementById('btn-run').disabled, null, { timeout: 20000 });
  await m.click('#steps button:nth-child(4)');
  await m.waitForTimeout(9000);
  await m.screenshot({ path: out + '/phone.png', fullPage: false });
  const overflow = await m.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  console.log('phone horizontal overflow px:', overflow);

  console.log('console errors:', errors.length ? errors : 'none');
  await browser.close();
})().catch((e) => { console.error('CHECK FAILED:', e); process.exit(1); });
