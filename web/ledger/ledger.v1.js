// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

/* VPN Works Ledger live demo. Every hash, line number and verdict on the page
 * comes from Ledger's own Go code in engine.ledger.v1.js; this file only
 * draws, and makes the changes a visitor asks for. */
(function () {
  'use strict';

  var E = null;        // the engine
  var TRACE = '';      // the recorded trace, as recorded
  var LINES = [];      // its lines
  var EVENTS = [];     // its lines, parsed for display
  var KEY = null;      // the main key's public half
  var SEALED = null;   // the ledger and its checkpoints, as the engine returned them
  var sealMs = 0;
  var edited = '';     // step 3: the record as it stands after the visitor's changes
  var proofText = '';  // step 5: the proof as made
  var cut = null;      // step 6: both files cut back to checkpoint 3
  var step = 1;
  var seen = {};

  var NEXT = ['', 'seal it', 'change it', 'every kind of change', 'prove one connection', 'cut at a checkpoint', 'start again'];
  var RECORDS = '1-trace-1.jsonl';
  var LEDGER = '1-trace-1.jsonl.ledger';

  function $(id) { return document.getElementById(id); }
  function fmt(n) { return Number(n).toLocaleString('en-US'); }
  function h(tag, attrs, kids) {
    var e = document.createElement(tag);
    if (attrs) {
      Object.keys(attrs).forEach(function (k) {
        if (attrs[k] == null) return;
        if (k === 'class') e.className = attrs[k];
        else if (k === 'text') e.textContent = attrs[k];
        else e.setAttribute(k, attrs[k]);
      });
    }
    (kids || []).forEach(function (c) {
      if (c == null) return;
      e.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
    });
    return e;
  }
  function clear(e) { while (e.firstChild) e.removeChild(e.firstChild); return e; }
  function tile(n, label, cls, id) {
    return h('div', { 'class': 'tile' + (cls ? ' ' + cls : ''), id: id || null }, [
      h('div', { 'class': 'n', text: n }), h('div', { 'class': 'l', text: label })]);
  }
  function setStatus(text, bad) {
    var s = $('status');
    s.textContent = text;
    s.className = 'status' + (bad ? ' bad' : '');
  }
  function split(text) {
    var l = text.split('\n');
    if (l.length && l[l.length - 1] === '') l.pop();
    return l;
  }
  function join(lines) { return lines.join('\n') + '\n'; }

  /* What a line of the trace says, in words. */
  function summary(e) {
    var f = e.fields || {}, c = e.conn ? '#' + e.conn + ' ' : '';
    switch (e.type) {
      case 'run.start': return ['run starts', f.mode + ', ' + f.path + ', backend ' + f.backend];
      case 'process.start': return ['process starts', f.cmd + ', pid ' + e.pid];
      case 'connection.attempt': return [c + 'tries ' + f.host + ':' + f.port, f.proto];
      case 'dns.query': return [c + 'asks DNS', f.host];
      case 'dns.result': return [c + 'DNS answers', f.error ? f.host + ': ' + f.error : f.host + ' = ' + (f.ips || []).join(', ')];
      case 'connection.open': return [c + 'opens', f.host + ' at ' + f.ip];
      case 'connection.close': return [c + 'closes', 'sent ' + fmt(f.bytes_up) + ' B, received ' + fmt(f.bytes_down) + ' B'];
      case 'connection.error': return [c + 'fails', f.error];
      case 'process.exit': return ['process exits', 'code ' + f.code + ' after ' + f.ms + ' ms'];
      case 'run.end': return ['run ends', f.connections + ' connections, sent ' + fmt(f.bytes_up) + ' B, received ' + fmt(f.bytes_down) + ' B'];
    }
    return [e.type || '?', ''];
  }
  function evil(e) { return e && e.conn === 5; }

  function lineRow(no, kids, cls) {
    return h('div', { 'class': 'ln' + (cls ? ' ' + cls : ''), 'data-line': String(no) }, [h('span', { 'class': 'no', text: String(no) })].concat(kids));
  }
  function scrollTo(list, row) {
    if (row) list.scrollTop = Math.max(0, row.offsetTop - list.offsetTop - 60);
  }

  /* A verdict box: the engine's own words. */
  function verdict(box, r, okText) {
    box.removeAttribute('data-file');
    box.removeAttribute('data-line');
    box.removeAttribute('data-kind');
    clear(box);
    if (!r.ok) {
      box.className = 'verdict bad';
      box.appendChild(h('b', { text: 'Refused' }));
      box.appendChild(document.createTextNode(r.error));
      return;
    }
    if (r.intact) {
      box.className = 'verdict good';
      box.setAttribute('data-intact', 'yes');
      box.appendChild(h('b', { text: 'Intact' }));
      box.appendChild(document.createTextNode(okText));
      return;
    }
    var p = r.problem;
    box.className = 'verdict bad';
    box.setAttribute('data-intact', 'no');
    box.setAttribute('data-file', p.file);
    box.setAttribute('data-line', String(p.line));
    box.setAttribute('data-kind', p.kind);
    box.appendChild(h('b', { text: 'Not intact' }));
    box.appendChild(h('code', { text: (p.file === 'ledger' ? LEDGER : RECORDS) + ':' + p.line + ': ' + p.msg }));
  }

  /* ---- step 1: the record ---- */
  function renderRecord() {
    var tiles = clear($('record-tiles'));
    var conns = 0, sent = 0;
    EVENTS.forEach(function (e) {
      if (e.type === 'connection.attempt') conns++;
      if (evil(e) && e.type === 'connection.close') sent = e.fields.bytes_up;
    });
    tiles.appendChild(tile(fmt(EVENTS.length), 'events, one JSON line each', '', 't-events'));
    tiles.appendChild(tile(fmt(conns), 'connections the agent tried', '', 't-conns'));
    tiles.appendChild(tile(fmt(sent) + ' B', 'sent to evil.example, lines 22 to 26', 'warn', 't-evil'));
    var list = clear($('trace-list'));
    EVENTS.forEach(function (e, i) {
      var s = summary(e);
      list.appendChild(lineRow(i + 1, [h('span', { 'class': 'tx sum', title: LINES[i] }, [
        h('span', { 'class': 't', text: (e.ts || '').slice(11, 23) }), h('b', { text: s[0] }), ' ' + s[1]])], evil(e) ? 'evil' : ''));
    });
  }

  /* ---- step 2: seal it ---- */
  function renderSeal() {
    var tiles = clear($('seal-tiles'));
    var cps = SEALED.checkpoints;
    tiles.appendChild(tile(fmt(SEALED.records), 'records sealed', 'good', 's-records'));
    tiles.appendChild(tile(fmt(cps.length), 'checkpoints, every 8 records', '', 's-cps'));
    tiles.appendChild(tile(KEY.id, 'the key, made in this page', '', 's-key'));
    tiles.appendChild(tile(fmt(Math.max(1, Math.round(sealMs))) + ' ms', 'to seal, in this page', '', 's-ms'));
    var list = clear($('ledger-view'));
    split(SEALED.ledger).forEach(function (l, i) {
      list.appendChild(lineRow(i + 1, [h('span', { 'class': 'tx', text: l })], l.indexOf('{"cp":') === 0 ? 'cp' : ''));
    });
    var last = cps[cps.length - 1];
    $('signed-title').textContent = 'What checkpoint ' + last.cp + ' signs';
    $('signed-text').textContent = last.text;
  }

  /* ---- step 3: change the record ---- */
  function change(act) {
    var l = LINES.slice();
    switch (act) {
      case 'edit': l[24] = l[24].replace('evil.example', 'cdn.example'); break;
      case 'delete': l.splice(24, 1); break;
      case 'swap': var t = l[24]; l[24] = l[25]; l[25] = t; break;
      case 'conn': l.splice(21, 5); break;
      case 'cut': l = l.slice(0, 21); break;
    }
    edited = join(l);
    $('trace-text').value = edited;
    document.querySelectorAll('#tamper-actions button').forEach(function (b) { b.classList.toggle('on', b.getAttribute('data-act') === act && act !== 'undo'); });
    checkEdited();
  }

  function checkEdited() {
    var r = E.verify(edited, SEALED.ledger, 'main', '');
    verdict($('verdict'), r, RECORDS + ': ' + (r.records || 0) + ' records, all sealed and signed by key ' + KEY.id + '.');
    var list = clear($('edit-list'));
    var lines = split(edited);
    var hit = r.ok && r.problem && r.problem.file === 'records' ? r.problem.line : 0;
    var hitRow = null;
    lines.forEach(function (l, i) {
      var row = lineRow(i + 1, [h('span', { 'class': 'tx', text: l })], i + 1 === hit ? 'hit' : '');
      if (i + 1 === hit) hitRow = row;
      list.appendChild(row);
    });
    if (hit > lines.length) {
      hitRow = lineRow(hit, [h('span', { 'class': 'tx', text: 'missing: the file ends before this line' })], 'hit gone');
      list.appendChild(hitRow);
    }
    scrollTo(list, hitRow);
    var o = $('change-outro');
    if (!r.ok) o.textContent = 'The engine refused to read the files.';
    else if (r.intact) o.textContent = 'The record is as it was sealed. Pick a change above, or edit the text yourself.';
    else o.textContent = 'The check names line ' + r.problem.line + '. To hide the change, the ledger would have to change as well, and its checkpoints are signed with a key that only this page holds. Step 4 tries that too.';
  }

  var typing = 0;
  function onEdit() {
    clearTimeout(typing);
    typing = setTimeout(function () {
      edited = $('trace-text').value;
      document.querySelectorAll('#tamper-actions button').forEach(function (b) { b.classList.remove('on'); });
      checkEdited();
    }, 250);
  }

  /* ---- step 4: every kind of change ---- */
  function renderMatrix() {
    var m = E.matrix(TRACE, SEALED.ledger, 25);
    var tiles = clear($('matrix-tiles'));
    var body = clear($('matrix-body'));
    if (!m.ok) {
      body.appendChild(h('tr', {}, [h('td', { colspan: '4', 'class': 'empty', text: m.error })]));
      return;
    }
    var caught = m.rows.filter(function (r) { return r.caught; }).length;
    tiles.appendChild(tile(fmt(m.rows.length), 'changes tried', '', 'm-cases'));
    tiles.appendChild(tile(fmt(caught), 'caught, at the line expected', caught === m.rows.length ? 'good' : 'bad', 'm-caught'));
    m.rows.forEach(function (r) {
      var p = r.problem;
      var where = (r.file === 'ledger' ? 'ledger' : 'record') + ', line ' + r.line;
      body.appendChild(h('tr', { 'data-file': p ? p.file : '', 'data-line': p ? String(p.line) : '', 'data-caught': r.caught ? 'yes' : 'no' }, [
        h('td', { text: r.name }),
        h('td', { 'class': 'num', text: where }),
        h('td', { 'class': 'mono', text: p ? (p.file === 'ledger' ? LEDGER : RECORDS) + ':' + p.line + ': ' + p.msg : 'nothing found' }),
        h('td', { 'class': r.caught ? 'caught' : 'missed', text: r.caught ? 'yes' : 'no' })]));
    });
  }

  /* ---- step 5: prove one connection ---- */
  function fillLines() {
    var sel = $('prove-line');
    if (sel.options.length) return;
    EVENTS.forEach(function (e, i) {
      var s = summary(e);
      sel.appendChild(h('option', { value: String(i + 1), text: 'line ' + (i + 1) + ': ' + s[0] + ', ' + s[1] }));
    });
    sel.value = '25';
  }

  function renderProof() {
    fillLines();
    var line = Number($('prove-line').value);
    var p = E.prove(TRACE, SEALED.ledger, line);
    var tiles = clear($('proof-tiles'));
    if (!p.ok) {
      verdict($('proof-verdict'), p, '');
      return;
    }
    proofText = p.proof;
    tiles.appendChild(tile(fmt(p.path.length), 'hashes link it to the root of checkpoint ' + p.checkpoint.cp, '', 'p-path'));
    tiles.appendChild(tile(fmt(p.bytes), 'bytes in the proof', '', 'p-bytes'));
    tiles.appendChild(tile(fmt(SEALED.records - 1), 'other records, none of them in it', 'good', 'p-others'));
    $('proof-text').textContent = proofText;
    checkProof(proofText, 'main');
  }

  function checkProof(text, slot) {
    var r = E.checkProof(text, slot);
    var box = $('proof-verdict');
    clear(box);
    box.className = 'verdict ' + (r.holds ? 'good' : 'bad');
    box.setAttribute('data-holds', r.holds ? 'yes' : 'no');
    box.appendChild(h('b', { text: r.holds ? 'The proof holds' : 'The proof doesn\'t hold' }));
    box.appendChild(document.createTextNode(r.holds ? 'This is ' + r.msg + ', checked with the public key alone.' : r.msg + '.'));
  }

  function forgeProof() {
    var lines = proofText.split('\n');
    for (var i = 0; i < lines.length; i++) {
      if (lines[i].indexOf('  "record": ') !== 0) continue;
      var l = lines[i];
      if (l.indexOf('evil.example') >= 0) l = l.replace('evil.example', 'cdn.example');
      else {
        var k = l.search(/\d(?=\D*$)/);
        l = k >= 0 ? l.slice(0, k) + String((Number(l[k]) + 1) % 10) + l.slice(k + 1) : l;
      }
      lines[i] = l;
    }
    var forged = lines.join('\n');
    $('proof-text').textContent = forged;
    checkProof(forged, 'main');
  }

  /* ---- step 6: cut back to a checkpoint ---- */
  function cutFiles() {
    var cp3 = SEALED.checkpoints[2];
    var led = split(SEALED.ledger);
    cut = { records: join(LINES.slice(0, cp3.size)), ledger: join(led.slice(0, cp3.line)) };
    var tiles = clear($('cut-tiles'));
    tiles.appendChild(tile(fmt(cp3.size), 'records left, lines 25 to 28 gone', 'warn', 'c-records'));
    tiles.appendChild(tile(fmt(3), 'checkpoints left in the ledger', 'warn', 'c-cps'));
    var box = $('cut-verdict');
    clear(box);
    box.className = 'verdict';
  }

  function checkCut(withWitness) {
    if (!cut) cutFiles();
    var led = split(SEALED.ledger);
    var witness = withWitness ? led[SEALED.checkpoints[3].line - 1] : '';
    var r = E.verify(cut.records, cut.ledger, 'main', witness);
    verdict($('cut-verdict'), r, 'as far as the two files go: ' + (r.records || 0) + ' records, all sealed and signed, ' + (r.checked || 0) + ' checkpoints. The connection to evil.example is gone, with no trace of the cut.');
  }

  function renderCut() {
    $('witness-text').textContent = split(SEALED.ledger)[SEALED.checkpoints[3].line - 1];
  }

  /* ---- navigation ---- */
  var render = { 1: renderRecord, 2: renderSeal, 3: function () { if (!$('verdict').className.match(/good|bad/)) checkEdited(); }, 4: renderMatrix, 5: renderProof, 6: renderCut };

  function show(n, scroll) {
    n = Math.max(1, Math.min(6, n | 0));
    step = n;
    seen[n] = true;
    document.querySelectorAll('.scene').forEach(function (s) { s.hidden = Number(s.getAttribute('data-step')) !== n; });
    document.querySelectorAll('#steps button').forEach(function (b) {
      var k = Number(b.getAttribute('data-step'));
      b.classList.toggle('on', k === n);
      b.classList.toggle('done', !!seen[k] && k !== n);
      if (k === n) b.setAttribute('aria-current', 'step'); else b.removeAttribute('aria-current');
    });
    $('btn-back').disabled = n === 1;
    $('btn-next').textContent = 'Next: ' + NEXT[n];
    if (E) render[n]();
    if (history.replaceState) history.replaceState(null, '', '#step-' + n);
    if (scroll) {
      var top = $('steps').getBoundingClientRect().top;
      if (top < 0) $('steps').scrollIntoView({ block: 'start' });
    }
  }

  function seal() {
    KEY = E.keygen('main');
    E.keygen('other');
    var t0 = performance.now();
    SEALED = E.seal(TRACE, 8);
    sealMs = performance.now() - t0;
    if (!SEALED.ok) throw new Error(SEALED.error);
    cut = null;
  }

  function wire() {
    document.querySelectorAll('#steps button').forEach(function (b) {
      b.addEventListener('click', function () { show(Number(b.getAttribute('data-step')), false); });
    });
    $('btn-back').addEventListener('click', function () { show(step - 1, true); });
    $('btn-next').addEventListener('click', function () { show(step === 6 ? 1 : step + 1, true); });
    document.querySelectorAll('#tamper-actions button').forEach(function (b) {
      b.addEventListener('click', function () { change(b.getAttribute('data-act')); });
    });
    $('trace-text').addEventListener('input', onEdit);
    $('btn-reseal').addEventListener('click', function () { seal(); renderSeal(); checkEdited(); });
    $('prove-line').addEventListener('change', renderProof);
    $('btn-check-proof').addEventListener('click', function () { $('proof-text').textContent = proofText; checkProof(proofText, 'main'); });
    $('btn-forge-proof').addEventListener('click', forgeProof);
    $('btn-other-key').addEventListener('click', function () { $('proof-text').textContent = proofText; checkProof(proofText, 'other'); });
    $('btn-cut').addEventListener('click', cutFiles);
    $('btn-alone').addEventListener('click', function () { checkCut(false); });
    $('btn-witness').addEventListener('click', function () { checkCut(true); });
  }

  function start() {
    wire();
    var m = /^#step-([1-6])$/.exec(location.hash);
    show(m ? Number(m[1]) : 1, false);
    if (!window.VPNWLedger || !window.WebAssembly) {
      setStatus('This browser cannot run the engine: it needs WebAssembly.', true);
      return;
    }
    window.VPNWLedger.load().then(function (engine) {
      E = engine;
      $('engine-version').textContent = E.version;
      TRACE = E.trace;
      LINES = split(TRACE);
      EVENTS = LINES.map(function (l) { try { return JSON.parse(l); } catch (e) { return {}; } });
      seal();
      edited = TRACE;
      $('trace-text').value = edited;
      setStatus('Ledger ' + E.version + ' is running in this page. It made a key, ' + KEY.id + ', and sealed the ' + fmt(SEALED.records) +
        ' records in ' + fmt(Math.max(1, Math.round(sealMs))) + ' ms.');
      document.documentElement.setAttribute('data-ready', '1');
      show(step, false);
    }).catch(function (err) {
      setStatus('The engine could not start: ' + (err && err.message ? err.message : err), true);
    });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start);
  else start();
})();
