// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

/* VPN Works Scope live demo. Every number on the page comes from Scope's own
 * Go code in engine.scope.v1.js; this file only draws. */
(function () {
  'use strict';

  var E = null;        // the engine
  var OFFICE = null;   // the demo office, from the engine
  var LEARNED = null;  // the learned draft, as the engine returned it
  var draftText = '';  // the draft as it stands after the review
  var current = null;  // the engine's reading of draftText, or null if it has an error
  var step = 1;
  var seen = {};
  var matrixView = 'draft';
  var stolenMode = 'draft';
  var exportFormat = 'nft';
  var learnMs = 0;

  var NEXT = ['', 'learn', 'review', 'the week after', 'a stolen login', 'gateway rules', 'start again'];
  var DAY = 86400000;

  function $(id) { return document.getElementById(id); }
  function fmt(n) { return Number(n).toLocaleString('en-US'); }
  function h(tag, attrs, kids) {
    var e = document.createElement(tag);
    if (attrs) {
      Object.keys(attrs).forEach(function (k) {
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
  function person(id) {
    for (var i = 0; i < OFFICE.people.length; i++) if (OFFICE.people[i].id === id) return OFFICE.people[i];
    return null;
  }
  function firstName(id) { var p = person(id); return p ? p.name.split(' ')[0] : id; }
  function words(n) { return ['no', 'one', 'two', 'three', 'four', 'five', 'six', 'seven', 'eight', 'nine'][n] || fmt(n); }
  function setStatus(text, bad) {
    var s = $('status');
    s.textContent = text;
    s.className = 'status' + (bad ? ' bad' : '');
  }

  /* ---- step 1: the office ---- */
  function renderOffice() {
    var teams = clear($('teams'));
    OFFICE.groups.forEach(function (g) {
      var chips = h('div', { 'class': 'chips' });
      g.members.forEach(function (id) {
        var p = person(id);
        var late = p.startDay > 0;
        chips.appendChild(h('span', { 'class': 'chip' + (late ? ' new' : '') },
          [p.name, late ? h('small', { text: ' joins in the third week' }) : null]));
      });
      teams.appendChild(h('div', { 'class': 'team' }, [
        h('h4', {}, [g.name, h('small', { text: ' ' + g.members.length + ' people' })]), chips]));
    });
    var sys = clear($('systems'));
    OFFICE.systems.forEach(function (s) {
      var svcs = s.services.map(function (v) { return v.name + ' ' + v.port + '/' + v.proto; }).join(', ');
      sys.appendChild(h('div', { 'class': 'sys' }, [
        h('b', { text: s.name }), h('span', { 'class': 'addr', text: s.addr }), h('div', { 'class': 'svcs', text: svcs })]));
    });
    var bars = clear($('bars')), axis = clear($('bars-axis'));
    var max = Math.max.apply(null, OFFICE.perDay);
    var start = Date.parse(OFFICE.start + 'T00:00:00Z');
    OFFICE.perDay.forEach(function (n, i) {
      var d = new Date(start + i * DAY);
      var wd = d.getUTCDay();
      var label = d.toLocaleDateString('en-GB', { weekday: 'short', day: 'numeric', month: 'short', timeZone: 'UTC' });
      bars.appendChild(h('i', {
        'class': (i < OFFICE.learnDays ? 'learn' : 'replay') + (wd === 0 || wd === 6 ? ' weekend' : ''),
        style: 'height:' + Math.max(2, Math.round(n / max * 100)) + '%',
        title: label + ': ' + fmt(n) + ' connections'
      }));
      axis.appendChild(h('span', { text: i % 7 === 0 ? d.toLocaleDateString('en-GB', { day: 'numeric', month: 'short', timeZone: 'UTC' }) : '' }));
    });
    $('traffic-note').textContent = fmt(OFFICE.learnFlows) + ' connections in the two weeks Scope learns from and ' +
      fmt(OFFICE.replayFlows) + ' in the week after, generated in this page from seed ' + OFFICE.seed +
      ' by the same code the tests and the report use. Weekends are quiet: one engineer is on call on each of the first two.';
    $('seed').textContent = OFFICE.seed;
  }

  /* ---- step 2: learn ---- */
  function renderLearn() {
    var c = LEARNED.counts;
    var tiles = clear($('learn-tiles'));
    tiles.appendChild(tile(fmt(LEARNED.flows), 'connections read', '', 't-flows'));
    tiles.appendChild(tile(fmt(c.groupRules), 'team rules, for ' + c.groups + ' teams', 'good', 't-group'));
    tiles.appendChild(tile(fmt(c.personRules), 'personal rules, for ' + c.people + ' people', '', 't-person'));
    tiles.appendChild(tile(fmt(c.review), 'under review', 'warn', 't-review'));
    tiles.appendChild(tile(learnMs + ' ms', 'to learn, in this page', '', 't-ms'));
    renderMatrix();
  }

  function renderMatrix() {
    var t = clear($('matrix'));
    t.className = 'matrix' + (matrixView === 'flat' ? ' flat' : '');
    var head = h('tr', {}, [h('th', {})]);
    OFFICE.systems.forEach(function (s) { head.appendChild(h('th', { scope: 'col' }, [h('span', { text: s.name })])); });
    t.appendChild(h('thead', {}, [head]));
    var body = h('tbody');
    var index = {};
    OFFICE.people.forEach(function (p, i) { index[p.id] = i; });
    var allowed = 0, total = 0;
    OFFICE.groups.forEach(function (g) {
      body.appendChild(h('tr', { 'class': 'team' }, [h('th', { colspan: String(OFFICE.systems.length + 1), text: g.name })]));
      g.members.forEach(function (id) {
        var row = LEARNED.matrix[index[id]];
        var tr = h('tr', {}, [h('th', { 'class': 'who', scope: 'row', text: person(id).name })]);
        row.forEach(function (cell, j) {
          var kind = matrixView === 'flat' ? 'flat' : cell.kind;
          total++;
          if (cell.kind === 'group' || cell.kind === 'person') allowed++;
          var what = {
            flat: 'reachable on the flat VPN: every port',
            group: 'team rule: ', person: 'personal rule: ', review: 'under review, blocked: ', '': 'not allowed'
          }[kind];
          var title = person(id).name + ' to ' + OFFICE.systems[j].name + ': ' + what +
            ((kind === 'group' || kind === 'person' || kind === 'review') ? cell.services.join(', ') : '');
          tr.appendChild(h('td', { 'class': kind, title: title }));
        });
        body.appendChild(tr);
      });
    });
    t.appendChild(body);
    $('matrix-note').textContent = matrixView === 'flat'
      ? 'On the flat VPN, all ' + fmt(total) + ' pairs of person and system are reachable, on every port.'
      : 'The draft lets people reach ' + fmt(allowed) + ' of the ' + fmt(total) +
        ' pairs of person and system, and only on the ports they used. The flat VPN allows all ' + fmt(total) + '.';
    $('matrix-note').setAttribute('data-allowed', allowed);
  }

  /* ---- step 3: review ---- */
  function renderReview() {
    var list = clear($('review-list'));
    var under = {};
    (current ? current.review : []).forEach(function (r) { under[r.person + ' ' + r.dest] = true; });
    LEARNED.review.forEach(function (r) {
      var isAllowed = current && !under[r.person + ' ' + r.dest];
      var team = person(r.person).groups[0];
      var keep = h('button', { type: 'button', 'class': isAllowed ? '' : 'on', 'aria-pressed': String(!isAllowed), text: 'Keep blocked' });
      var allow = h('button', { type: 'button', 'class': isAllowed ? 'on' : '', 'aria-pressed': String(!!isAllowed), text: 'Allow' });
      keep.addEventListener('click', function () { decide(r, false); });
      allow.addEventListener('click', function () { decide(r, true); });
      list.appendChild(h('div', { 'class': 'rv-card' + (isAllowed ? ' allowed' : '') }, [
        h('div', { 'class': 'who', text: r.name + ' (' + team + ')' }),
        h('div', { 'class': 'what' }, [r.system + ', ' + r.service + ' ', h('code', { text: r.dest })]),
        h('div', { 'class': 'ev', text: 'Seen on ' + r.note }),
        h('div', { 'class': 'choice', role: 'group', 'aria-label': 'Decision for ' + r.name }, [keep, allow])
      ]));
    });
  }

  function decide(r, allow) {
    if (!current) {
      checkDraft();
      if (!current) return;
    }
    var res = E.review(draftText, r.person, r.dest, allow);
    if (!res.ok) return; // already in that list
    draftText = res.draft;
    $('draft-text').value = draftText;
    current = res;
    showCheck();
    renderReview();
  }

  function checkDraft() {
    var res = E.check(draftText);
    current = res.ok ? res : null;
    showCheck(res.ok ? null : res.error);
  }

  function showCheck(error) {
    var c = $('draft-check');
    if (error) {
      c.className = 'pol-check bad';
      c.textContent = error;
      return;
    }
    var n = current.counts;
    c.className = 'pol-check good';
    c.textContent = 'The draft reads cleanly: ' + fmt(n.groupRules) + ' team rules, ' + fmt(n.personRules) +
      ' personal rules, ' + fmt(n.review) + ' under review.';
  }

  var typing = 0;
  function onEdit() {
    clearTimeout(typing);
    typing = setTimeout(function () {
      draftText = $('draft-text').value;
      checkDraft();
      renderReview();
    }, 250);
  }

  /* ---- steps 4 to 6 need a draft that reads ---- */
  function needDraft(container) {
    if (current) return true;
    clear(container).appendChild(h('p', { 'class': 'pol-check bad', text: 'The draft in step 3 has an error. Fix it there first.' }));
    return false;
  }

  /* ---- step 4: the week after ---- */
  function renderReplay() {
    var tiles = clear($('replay-tiles'));
    var body = clear($('replay-body'));
    $('newhire').textContent = '';
    $('replay-outro').textContent = '';
    if (!needDraft(tiles)) return;
    var r = E.replay(draftText);
    tiles.appendChild(tile(fmt(r.flows), 'connections in the week after', '', 'r-flows'));
    tiles.appendChild(tile(fmt(r.allowed), 'allowed', 'good', 'r-allowed'));
    tiles.appendChild(tile(fmt(r.denied), 'would have been blocked', r.denied ? 'bad' : 'good', 'r-denied'));
    if (!r.blocked || !r.blocked.length) {
      body.appendChild(h('tr', {}, [h('td', { colspan: '5', 'class': 'empty', text: 'Nothing would have been blocked.' })]));
    } else {
      r.blocked.forEach(function (b) {
        body.appendChild(h('tr', {}, [
          h('td', { text: b.name || b.person }), h('td', { text: b.system }), h('td', { text: b.service }),
          h('td', { 'class': 'num', text: fmt(b.count) }), h('td', { text: b.why })]));
      });
    }
    var late = OFFICE.people.filter(function (p) { return p.startDay > 0; });
    late.forEach(function (p) {
      var c = null;
      r.people.forEach(function (x) { if (x.id === p.id) c = x; });
      if (!c) return;
      $('newhire').textContent = p.name + ' joined the ' + p.groups[0] + ' team at the start of this week, so the two weeks held nothing of hers to learn from. Her team\'s rules covered her first week: ' +
        fmt(c.allowed) + ' connections allowed, ' + fmt(c.denied) + ' blocked.';
    });
    var parts = (r.blocked || []).map(function (b) {
      return b.why.indexOf('review') >= 0
        ? 'decide on ' + firstName(b.person) + '\'s ' + b.system + ' entry, still under review'
        : 'give ' + firstName(b.person) + ' the ' + b.system + ' if it is now part of the job';
    });
    $('replay-outro').textContent = parts.length
      ? 'Before anything is enforced, the reviewer has ' + words(parts.length) + (parts.length === 1 ? ' decision' : ' decisions') + ' to make: ' + parts.join('; ') + '.'
      : 'Under this draft, the whole week would have gone through.';
  }

  /* ---- step 5: the stolen login ---- */
  function renderStolen() {
    var tiles = clear($('stolen-tiles'));
    var grid = clear($('targets'));
    if (!needDraft(tiles)) return;
    var s = E.stolen(draftText);
    var flat = stolenMode === 'flat';
    var reached = flat ? s.attempts : s.reached;
    var systems = flat ? s.targets.length : s.systems;
    tiles.appendChild(tile(fmt(s.attempts), 'attempts', '', 's-attempts'));
    tiles.appendChild(tile(fmt(reached), 'reached a system', flat ? 'bad' : 'warn', 's-reached'));
    tiles.appendChild(tile(systems + ' of ' + s.targets.length, 'systems reached', flat ? 'bad' : 'warn', 's-systems'));
    tiles.appendChild(tile(fmt(s.attempts - reached), 'refused at the gateway', 'good', 's-refused'));
    s.targets.forEach(function (t) {
      var any = false;
      var ports = h('div', { 'class': 'ports' });
      t.tries.forEach(function (x) {
        var ok = flat || x.allowed;
        if (ok) any = true;
        var cls = !ok ? 'refused' : (x.open ? 'open' : 'closed');
        var what = !ok ? 'refused at the gateway' : (x.open ? 'reached ' + x.service : 'reached the system; nothing listens on that port');
        ports.appendChild(h('span', { 'class': 'pm ' + cls, title: x.port + '/' + x.proto + ': ' + what, text: String(x.port) + (x.proto === 'udp' ? 'u' : '') }));
      });
      grid.appendChild(h('div', { 'class': 'target ' + (any ? 'reached' : 'refused') }, [
        h('div', { 'class': 't-head' }, [h('b', { text: t.name }), h('span', { 'class': 't-state', text: any ? 'reached' : 'refused' })]),
        h('div', { 'class': 't-addr', text: t.addr }), ports]));
    });
    var who = firstName(s.person);
    $('stolen-outro').textContent = flat
      ? 'On the flat VPN the stolen login reaches all ' + s.targets.length + ' systems. Every port answers, open or closed, so whoever holds the login learns what runs where.'
      : 'Under the draft, the stolen login reaches the ' + s.systems + ' systems ' + who + ' uses for her work, on the ports she uses. The other ' +
        fmt(s.attempts - s.reached) + ' attempts stop at the gateway.';
  }

  /* ---- step 6: the rules ---- */
  function renderExport() {
    var pre = $('export-out');
    clear(pre);
    $('export-note').textContent = '';
    if (!needDraft(pre)) return;
    var res = exportFormat === 'allowedips' ? E.exportRules(draftText, 'allowedips', false) : E.exportRules(draftText, 'nft', exportFormat === 'watch');
    if (!res.ok) {
      pre.appendChild(document.createTextNode(res.error));
      return;
    }
    res.text.split('\n').forEach(function (line, i, all) {
      var span = h('span', { 'class': /^\s*#/.test(line) ? 'c' : (/^\s*(table|set|chain|type|flags|elements|ip|ct|reject|counter|log|delete)\b/.test(line) ? 'k' : '') }, [line]);
      pre.appendChild(span);
      if (i < all.length - 1) pre.appendChild(document.createTextNode('\n'));
    });
    var lines = res.text.split('\n').length - 1;
    $('export-note').textContent = exportFormat === 'allowedips'
      ? 'One AllowedIPs line per person, for their WireGuard client. They only tell each client what to send through the tunnel and enforce nothing; the gateway rules do.'
      : fmt(lines) + ' lines, ' + fmt(res.text.length) + ' bytes. On the gateway: nft -f scope.nft, as root.';
  }

  /* ---- navigation ---- */
  var render = { 1: function () {}, 2: renderLearn, 3: renderReview, 4: renderReplay, 5: renderStolen, 6: renderExport };

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

  function seg(container, attr, set) {
    container.querySelectorAll('button').forEach(function (b) {
      b.addEventListener('click', function () {
        container.querySelectorAll('button').forEach(function (x) {
          var on = x === b;
          x.classList.toggle('on', on);
          x.setAttribute('aria-pressed', String(on));
        });
        set(b.getAttribute(attr));
      });
    });
  }

  function wire() {
    document.querySelectorAll('#steps button').forEach(function (b) {
      b.addEventListener('click', function () { show(Number(b.getAttribute('data-step')), false); });
    });
    $('btn-back').addEventListener('click', function () { show(step - 1, true); });
    $('btn-next').addEventListener('click', function () { show(step === 6 ? 1 : step + 1, true); });
    seg(document.querySelector('#scene-2 .seg'), 'data-view', function (v) { matrixView = v; renderMatrix(); });
    seg(document.querySelector('#scene-5 .seg'), 'data-mode', function (v) { stolenMode = v; renderStolen(); });
    seg(document.querySelector('#scene-6 .seg'), 'data-format', function (v) { exportFormat = v; renderExport(); });
    $('draft-text').addEventListener('input', onEdit);
    $('btn-reset').addEventListener('click', function () {
      draftText = LEARNED.draft;
      $('draft-text').value = draftText;
      checkDraft();
      renderReview();
    });
  }

  function start() {
    wire();
    var m = /^#step-([1-6])$/.exec(location.hash);
    show(m ? Number(m[1]) : 1, false);
    if (!window.VPNWScope || !window.WebAssembly) {
      setStatus('This browser cannot run the engine: it needs WebAssembly.', true);
      return;
    }
    window.VPNWScope.load().then(function (engine) {
      E = engine;
      $('engine-version').textContent = E.version;
      OFFICE = E.office();
      var t0 = performance.now();
      LEARNED = E.learn();
      learnMs = Math.max(1, Math.round(performance.now() - t0));
      draftText = LEARNED.draft;
      $('draft-text').value = draftText;
      checkDraft();
      $('stolen-intro').textContent = 'On ' + OFFICE.stolenAt.replace(', ', ' at ') + ', someone uses ' + firstName(OFFICE.stolen) +
        '\'s VPN login to try every system on 12 common ports: ' + (OFFICE.systems.length * 12) + ' attempts.';
      renderOffice();
      setStatus('Scope ' + E.version + ' is running in this page. It learned the draft from ' + fmt(LEARNED.flows) + ' connections in ' + learnMs + ' ms.');
      document.documentElement.setAttribute('data-ready', '1');
      show(step, false);
    }).catch(function (err) {
      setStatus('The engine could not start: ' + (err && err.message ? err.message : err), true);
    });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start);
  else start();
})();
