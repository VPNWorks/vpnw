// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

/* VPN Works Alpha live demo (for vpnw.com/demo/): the page. Plain JavaScript, no libraries.
 * recordings.v1.js holds the recorded Linux runs; engine.v1.js holds the engine's decision
 * code. This file replays the runs step by step and lets you ask the engine yourself. */
(function () {
  'use strict';

  var D = window.VPNW_DEMO;
  var E = null;                 /* the engine, once loaded */
  var OUTRO_MS = 3200;          /* pause on each step's conclusion while playing */

  /* ---- the demo network, as run-demo.sh builds it ------------------------------------- */
  var PUBLIC = {
    'api.github.com': '140.82.112.6',
    'files.pythonhosted.org': '151.101.0.223',
    'telemetry.example.com': '93.184.215.14',
    'evil.example': '45.77.10.10'
  };
  var OFFICE_ONLY = { 'tracker.office.internal': '10.20.30.40' };
  var AGENT_STEPS = [
    { label: 'Read the repository', host: 'api.github.com' },
    { label: 'Download a dependency', host: 'files.pythonhosted.org' },
    { label: 'File a ticket on the office tracker', host: 'tracker.office.internal' },
    { label: 'Post telemetry', host: 'telemetry.example.com' },
    { label: 'Follow the task file: send the deploy token', host: 'evil.example', evil: true }
  ];

  /* ---- helpers ------------------------------------------------------------------------ */
  function $(id) { return document.getElementById(id); }
  function esc(s) {
    return String(s).replace(/[&<>"]/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]; });
  }
  function human(n) {
    if (n < 1000) return n + ' B';
    if (n < 1000 * 1000) return (n / 1024).toFixed(1) + ' KB';
    return (n / 1048576).toFixed(1) + ' MB';
  }
  function mmss(ms) { var s = Math.round(ms / 1000); return Math.floor(s / 60) + ':' + ('0' + (s % 60)).slice(-2); }
  var SVGNS = 'http://www.w3.org/2000/svg';
  function svg(tag, attrs, parent) {
    var e = document.createElementNS(SVGNS, tag);
    for (var k in attrs) if (Object.prototype.hasOwnProperty.call(attrs, k)) e.setAttribute(k, attrs[k]);
    if (parent) parent.appendChild(e);
    return e;
  }
  function text(parent, x, y, cls, s, anchor) {
    var t = svg('text', { x: x, y: y, 'class': cls }, parent);
    if (anchor) t.setAttribute('text-anchor', anchor);
    t.textContent = s;
    return t;
  }

  /* ---- the diagram -------------------------------------------------------------------- */
  var net = $('net');
  var G = {};            /* named groups and nodes */
  var HOSTS = {};        /* host key -> {g, box, badge, cy} */
  var conns = {};        /* connection id -> {host, ip, path, segs[], bridge} */
  var COUNT = {};        /* live counters for this command */

  var HOST_Y = { 'api.github.com': 36, 'files.pythonhosted.org': 86, 'telemetry.example.com': 136, 'evil.example': 186 };
  var BRIDGE = 'M190,180 L232,180';
  var DIRECT_STUB = 'M332,180 L352,180';
  var OFFICE_PATH = 'M332,192 L362,192 L362,314 L384,314';
  var EXIT_TRACKER = 'M500,314 L512,314';
  var METADATA_PATH = 'M282,206 L282,347 L194,347';
  function directPath(cy) { return 'M332,180 L352,180 L352,' + cy + ' L384,' + cy; }

  function hostBox(parent, name, sub, x, y, w, h, key, badgeY) {
    var g = svg('g', { 'class': 'host' }, parent);
    var box = svg('rect', { x: x, y: y, width: w, height: h, rx: 9, 'class': 'box' }, g);
    text(g, x + 12, y + 19, 'name', name);
    text(g, x + 12, y + 36, 'sub mono', sub);
    var badge = text(g, badgeY ? x + w : x + w - 10, badgeY || y + 36, 'tagtext', '', 'end');
    HOSTS[key] = { g: g, box: box, badge: badge, cy: y + h / 2 };
    return g;
  }

  function drawNet() {
    net.textContent = '';
    svg('rect', { x: 372, y: 4, width: 324, height: 236, rx: 12, 'class': 'region' }, net);
    text(net, 384, 23, 'region-label', 'Public internet');
    svg('rect', { x: 372, y: 254, width: 324, height: 142, rx: 12, 'class': 'region' }, net);
    text(net, 384, 273, 'region-label', 'Office network');
    svg('rect', { x: 4, y: 292, width: 200, height: 104, rx: 12, 'class': 'region' }, net);
    text(net, 16, 311, 'region-label', 'This machine’s network');

    G.trunks = svg('g', {}, net);
    svg('path', { d: 'M332,180 L352,180 M352,58 L352,208', 'class': 'trunk' }, G.trunks);
    Object.keys(HOST_Y).forEach(function (h) {
      svg('path', { d: 'M352,' + (HOST_Y[h] + 22) + ' L384,' + (HOST_Y[h] + 22), 'class': 'trunk' }, G.trunks);
    });
    svg('path', { d: OFFICE_PATH, 'class': 'trunk' }, G.trunks);
    svg('path', { d: EXIT_TRACKER, 'class': 'trunk' }, G.trunks);
    svg('path', { d: METADATA_PATH, 'class': 'trunk' }, G.trunks);
    G.segs = svg('g', {}, net);

    Object.keys(HOST_Y).forEach(function (h) {
      hostBox(net, h === 'evil.example' ? 'evil.example (the attacker)' : h, PUBLIC[h], 384, HOST_Y[h], 300, 44, h);
    });
    hostBox(net, 'office exit', '10.8.0.1:1080', 384, 290, 116, 48, 'office-exit', 355);
    hostBox(net, 'tracker.office.internal', '10.20.30.40', 512, 290, 178, 48, 'tracker.office.internal', 355);
    HOSTS['office-exit'].badge.setAttribute('text-anchor', 'start');
    HOSTS['office-exit'].badge.setAttribute('x', 386);
    hostBox(net, '169.254.169.254', 'cloud metadata', 14, 324, 180, 46, '169.254.169.254', 386);
    HOSTS['169.254.169.254'].badge.setAttribute('text-anchor', 'start');
    HOSTS['169.254.169.254'].badge.setAttribute('x', 16);

    G.sandbox = svg('rect', { x: 8, y: 92, width: 196, height: 180, rx: 14, 'class': 'sandbox' }, net);
    G.sandboxLabel = text(net, 20, 113, 'sandbox-label', 'Sealed sandbox');
    G.sandboxSub = text(net, 20, 130, 'sub', 'no network of its own');
    G.agent = svg('g', { 'class': 'host' }, net);
    G.agentBox = svg('rect', { x: 22, y: 150, width: 168, height: 60, rx: 10, 'class': 'box' }, G.agent);
    G.agentName = text(G.agent, 34, 175, 'name mono', 'agent.py');
    G.agentSub = text(G.agent, 34, 195, 'sub', 'the coding agent');
    G.door = svg('rect', { x: 200, y: 172, width: 8, height: 16, rx: 3, 'class': 'door' }, net);

    G.vpnw = svg('g', {}, net);
    G.vpnwBox = svg('rect', { x: 232, y: 154, width: 100, height: 52, rx: 12, 'class': 'vpnw' }, G.vpnw);
    text(G.vpnw, 282, 186, 'vpnw-name', 'vpnw', 'middle');
    G.vpnwSub = text(net, 282, 226, 'vpnw-status', '', 'middle');
    G.bypass = svg('g', {}, net);
  }

  function resetNet(cmd) {
    G.segs.textContent = '';
    G.bypass.textContent = '';
    conns = {};
    COUNT = { connections: 0, opened: 0, denied: 0, failed: 0 };
    Object.keys(HOSTS).forEach(function (k) {
      var h = HOSTS[k];
      h.g.setAttribute('class', 'host');
      h.badge.textContent = '';
      h.badge.setAttribute('class', 'tagtext');
    });
    var sealed = !cmd || cmd.sealed;
    [G.sandbox, G.sandboxLabel, G.sandboxSub, G.door].forEach(function (e) { e.style.opacity = sealed ? 1 : 0; });
    G.vpnw.style.opacity = sealed ? 1 : 0.25;
    var w = (cmd && cmd.workload) || 'agent.py';
    G.agentName.textContent = w;
    G.agentSub.textContent = w === 'sneaky.py' ? 'skips proxy settings' : w === 'curl' ? (cmd.path === 'office' ? 'asks the tracker' : 'asks for credentials') : 'the coding agent';
    G.vpnwSub.textContent = cmd && !cmd.vpnw ? 'not in use' : '';
    var uses = {};
    (cmd && cmd.items || []).forEach(function (it) {
      if (it.k === 'ev' && it.e.type === 'connection.attempt') uses[it.e.host || it.e.ip] = true;
    });
    if (cmd && cmd.path === 'office') uses['office-exit'] = true;
    if (cmd && cmd.workload === 'sneaky.py') uses['evil.example'] = true;
    Object.keys(HOSTS).forEach(function (k) {
      if (cmd && !uses[k]) HOSTS[k].g.setAttribute('class', 'host dim');
    });
    token(cmd && (cmd.workload === 'agent.py' || cmd.workload === 'sneaky.py') ? 'wait' : 'none');
    counters();
  }

  function counters() {
    ['connections', 'opened', 'denied', 'failed'].forEach(function (k) { $('n-' + k).textContent = COUNT[k] || 0; });
  }
  function token(state) {
    var t = $('token'), v = $('token-v');
    t.className = 'counter token ' + state;
    v.textContent = { none: 'not in this run', wait: 'not sent yet', sent: 'sent to evil.example', blocked: 'blocked by vpnw', sealed: 'no way out' }[state];
  }

  function seg(d, cls) { return svg('path', { d: d, 'class': 'seg ' + cls }, G.segs); }
  function setCls(list, cls) { list.forEach(function (p) { if (p) p.setAttribute('class', 'seg ' + cls); }); }
  function mark(key, cls, badge, badgeCls) {
    var h = HOSTS[key];
    if (!h) return;
    h.g.setAttribute('class', 'host ' + cls);
    if (badge !== undefined) {
      h.badge.textContent = badge;
      h.badge.setAttribute('class', 'tagtext ' + (badgeCls || ''));
    }
  }
  function flashVpnw() {
    G.vpnwBox.classList.remove('flash');
    void G.vpnwBox.getBBox();
    G.vpnwBox.classList.add('flash');
  }

  function pathsTo(c) {
    var key = c.host || c.ip;
    if (key === '169.254.169.254') return [METADATA_PATH];
    if (c.path === 'office') return key === 'tracker.office.internal' ? [OFFICE_PATH, EXIT_TRACKER] : [OFFICE_PATH];
    if (HOST_Y[key] !== undefined) return [directPath(HOST_Y[key] + 22)];
    return [DIRECT_STUB];
  }

  function onEvent(e) {
    var c = conns[e.conn];
    switch (e.type) {
      case 'run.start':
        G.vpnwSub.textContent = e.mode + (e.policy ? ' · policy ' + e.policy : '') + (e.path === 'office' ? ' · via office' : '');
        break;
      case 'connection.attempt':
        c = conns[e.conn] = { host: e.host, ip: e.ip, port: e.port, path: e.path, segs: [], bridge: seg(BRIDGE, 'pend') };
        COUNT.connections++;
        break;
      case 'dns.result':
        if (c && e.error) {
          c.segs.push(seg(DIRECT_STUB, 'fail'));
          setCls([c.bridge], 'fail');
          mark(c.host, 'fail', 'not found on this path', 'tag-fail');
        }
        break;
      case 'policy.allow':
        if (c) setCls([c.bridge], 'ok');
        break;
      case 'policy.deny':
        if (!c) break;
        COUNT.denied++;
        setCls([c.bridge], 'deny');
        flashVpnw();
        if ((c.host || c.ip) === '169.254.169.254') c.segs.push(seg(METADATA_PATH, 'deny'));
        mark(c.host || c.ip, 'deny', 'DENY: ' + (e.rule === 'default' ? 'not on the list' : e.rule), 'tag-deny');
        if (c.host === 'evil.example') token('blocked');
        break;
      case 'connection.open':
        if (!c) break;
        COUNT.opened++;
        setCls([c.bridge], 'ok');
        pathsTo(c).forEach(function (d) { c.segs.push(seg(d, 'ok')); });
        if (c.path === 'office') mark('office-exit', 'ok', 'relaying', 'tag-ok');
        mark(c.host || c.ip, 'ok', c.path === 'office' && PUBLIC[c.host] ? 'open, via the office' : 'open', 'tag-ok');
        if (c.host === 'evil.example') token('sent');
        break;
      case 'connection.close':
        if (!c) break;
        setCls([c.bridge].concat(c.segs), 'done');
        mark(c.host || c.ip, 'ok', (c.path === 'office' && PUBLIC[c.host] ? 'via office  ' : '') + '↑' + human(e.bytes_up || 0) + '  ↓' + human(e.bytes_down || 0), 'tag-ok');
        break;
      case 'connection.error':
        if (!c) break;
        COUNT.failed++;
        if (!c.segs.length) c.segs.push(seg(DIRECT_STUB, 'fail'));
        setCls([c.bridge], 'fail');
        mark(c.host || c.ip, 'fail', e.error && e.error.indexOf('dns') === 0 ? 'not found on this path' : 'unreachable', 'tag-fail');
        break;
      case 'run.end':
        if (!e.connections) recClear('No connections reached vpnw: the program never used it.');
        G.vpnwSub.textContent = e.connections + (e.connections === 1 ? ' connection' : ' connections') + ' · ' + e.denied + ' denied';
        break;
    }
    counters();
  }

  /* The sneaky program's own lines carry what vpnw never sees. */
  function onLine(line, cmd) {
    var s = line.trim();
    if (cmd.workload !== 'sneaky.py') return;
    if (s.indexOf('sneaky: token sent') === 0) {
      svg('path', { d: 'M190,196 L214,196 L214,248 L352,248 L352,208 L384,208', 'class': 'seg bad' }, G.bypass);
      mark('evil.example', 'leak', 'TOKEN RECEIVED', 'tag-deny');
      token('sent');
    } else if (s.indexOf('by name:') > 0 || s.indexOf('by address:') > 0) {
      var byName = s.indexOf('by name:') > 0, y = byName ? 158 : 202;
      svg('path', { d: 'M190,' + y + ' L197,' + y, 'class': 'seg bad' }, G.bypass);
      svg('path', { d: 'M198,' + (y - 6) + ' L210,' + (y + 6) + ' M210,' + (y - 6) + ' L198,' + (y + 6), 'class': 'wall-x' }, G.bypass);
      text(G.bypass, 20, byName ? 228 : 245, 'tagtext tag-deny', byName ? '✕ by name: no DNS' : '✕ by address: no route');
      token('sealed');
    } else if (s.indexOf('local service') > 0 && s.indexOf('not permitted') > 0) {
      svg('path', { d: 'M178,210 L178,264', 'class': 'seg bad' }, G.bypass);
      svg('path', { d: 'M172,266 L184,278 M184,266 L172,278', 'class': 'wall-x' }, G.bypass);
      text(G.bypass, 20, 262, 'tagtext tag-deny', '✕ local socket: refused');
      token('sealed');
    }
  }

  /* ---- the terminal ------------------------------------------------------------------- */
  var term = $('term');
  function termClear() { term.textContent = ''; }
  function termLine(s, cls) {
    var d = document.createElement('span');
    d.className = 'l ' + cls;
    d.textContent = s;
    term.appendChild(d);
    term.scrollTop = term.scrollHeight;
  }
  function lineClass(it) {
    if (it.c !== 'vpnw') return it.c;
    if (it.text.indexOf('  DENY ') > 0) return 'deny';
    if (it.text.indexOf('  error ') > 0 || it.text.indexOf(' failed: ') > 0) return 'err';
    return 'vpnw';
  }

  /* ---- the recorded table ------------------------------------------------------------- */
  var rows = {};
  function recClear(note) {
    rows = {};
    $('rec-body').innerHTML = '<tr><td colspan="6" class="empty">' + esc(note) + '</td></tr>';
    $('rec-note').textContent = '';
  }
  function recRow(id) {
    if (rows[id]) return rows[id];
    var body = $('rec-body');
    if (body.querySelector('.empty')) body.textContent = '';
    var tr = document.createElement('tr');
    tr.innerHTML = '<td class="num"></td><td class="mono"></td><td></td><td></td><td></td><td class="num"></td>';
    body.appendChild(tr);
    rows[id] = { tr: tr, td: tr.children };
    rows[id].td[0].textContent = '#' + id;
    return rows[id];
  }
  function recEvent(e) {
    if (e.type === 'run.start') {
      $('rec-note').textContent = '(' + e.mode + ', path ' + e.path + (e.policy ? ', policy ' + e.policy : ', no policy') + ')';
      return;
    }
    if (!e.conn) return;
    var r = recRow(e.conn);
    switch (e.type) {
      case 'connection.attempt':
        r.td[1].textContent = (e.host || e.ip) + ':' + e.port;
        r.td[2].textContent = e.path;
        r.td[3].innerHTML = '<span class="why">no policy</span>';
        r.td[4].innerHTML = '<span class="st pend">deciding</span>';
        break;
      case 'policy.allow':
        r.td[3].innerHTML = '<span class="st ok">allow</span><span class="why">' + esc(e.rule) + '</span>';
        break;
      case 'policy.deny':
        r.td[3].innerHTML = '<span class="st deny">deny</span><span class="why">' + esc(e.reason || e.rule) + '</span>';
        r.td[4].innerHTML = '<span class="st deny">denied</span>';
        break;
      case 'connection.open':
        r.td[4].innerHTML = '<span class="st ok">opened</span><span class="why">' + esc(e.ip ? e.ip : 'the exit resolves the name') + '</span>';
        break;
      case 'connection.error':
        r.td[4].innerHTML = '<span class="st fail">failed</span><span class="why">' + esc(e.error) + '</span>';
        break;
      case 'connection.close':
        r.td[5].textContent = human(e.bytes_up || 0) + ' / ' + human(e.bytes_down || 0);
        break;
    }
  }

  /* ---- the policy panel (step 2) ------------------------------------------------------ */
  function learnLines(scene) {
    var draft = [], fin = [];
    scene.commands[0].items.forEach(function (it) { if (it.k === 'line') draft.push(it.text); });
    if (scene.commands[1]) scene.commands[1].items.forEach(function (it) { if (it.k === 'line') fin.push(it.text); });
    return { draft: draft, fin: fin };
  }
  function parseLists(L) {
    var draft = [], unreached = [], fin = [], m;
    L.draft.forEach(function (l) {
      if ((m = /^\s+"([^"]+)",?\s+# (.*)$/.exec(l))) draft.push({ host: m[1], note: m[2] });
      else if ((m = /^#\s+"([^"]+)"\s+\((.*)\)$/.exec(l))) unreached.push({ host: m[1], note: m[2] });
    });
    L.fin.forEach(function (l) { if ((m = /^\s+"([^"]+)",?\s*$/.exec(l))) fin.push(m[1]); });
    return { draft: draft, unreached: unreached, fin: fin };
  }
  function showPolicy(scene, stage) {
    var P = parseLists(learnLines(scene));
    var hosts = [];
    P.draft.forEach(function (d) { hosts.push(d.host); });
    P.unreached.forEach(function (d) { if (hosts.indexOf(d.host) < 0) hosts.push(d.host); });
    var body = $('review-body');
    body.textContent = '';
    if (stage < 1) {
      body.innerHTML = '<tr><td colspan="3" class="empty">Waiting for vpnw learn.</td></tr>';
      return;
    }
    hosts.forEach(function (h) {
      var inDraft = P.draft.filter(function (d) { return d.host === h; })[0];
      var out = P.unreached.filter(function (d) { return d.host === h; })[0];
      var kept = P.fin.indexOf(h) >= 0;
      var tr = document.createElement('tr');
      var draftCell = inDraft ? '<span class="rv keep">allowed</span><span class="why">' + esc(inDraft.note) + '</span>'
        : '<span class="rv out">left out</span><span class="why">tried, not reached: ' + esc(out.note) + '</span>';
      var finCell = '<span class="why">…</span>';
      if (stage >= 2) {
        if (inDraft && kept) finCell = '<span class="rv keep">kept</span>';
        else if (inDraft && !kept) { finCell = '<span class="rv rm">removed</span><span class="why">reached only because of the hidden instruction</span>'; tr.className = 'rm'; }
        else if (kept) finCell = '<span class="rv add">added</span><span class="why">the ticket step needs it, through the office exit</span>';
        else finCell = '<span class="rv out">still out</span>';
      }
      tr.innerHTML = '<td>' + esc(h) + '</td><td>' + draftCell + '</td><td>' + finCell + '</td>';
      body.appendChild(tr);
    });
  }

  /* ---- playback ------------------------------------------------------------------------ */
  var S = { scene: 0, cmd: 0, item: 0, t0: 0, playing: false, pausedAt: 0, phase: 'idle', outroT: 0, started: false };
  var done = {};
  var totalMs = 0;
  D.scenes.forEach(function (s) { s.ms = s.commands.reduce(function (a, c) { return a + c.ms; }, 0); totalMs += s.ms; });

  function sceneOffset(i) { var t = 0; for (var k = 0; k < i; k++) t += D.scenes[k].ms; return t; }

  function buildSteps() {
    var nav = $('steps');
    D.scenes.forEach(function (s, i) {
      var b = document.createElement('button');
      b.type = 'button';
      b.innerHTML = '<b>Step ' + s.no + '</b><span>' + esc(s.title) + '</span>';
      b.addEventListener('click', function () { goScene(i, true); });
      nav.appendChild(b);
    });
  }
  function markSteps() {
    var bs = $('steps').children;
    for (var i = 0; i < bs.length; i++) {
      bs[i].className = (i === S.scene ? 'on' : '') + (done[i] ? ' done' : '');
    }
  }

  function enterScene(i) {
    var s = D.scenes[i];
    S.scene = i; S.cmd = 0; S.item = 0; S.phase = 'cmd';
    $('scene-no').textContent = 'Step ' + s.no + ' of ' + D.scenes.length;
    $('scene-title').textContent = s.title;
    $('scene-intro').textContent = s.intro;
    $('scene-outro').hidden = true;
    $('scene-outro').textContent = s.outro;
    $('panel-net').hidden = s.panel !== 'net';
    $('panel-policy').hidden = s.panel !== 'policy';
    termClear();
    if (s.panel === 'policy') {
      showPolicy(s, 0);
      recClear('vpnw learn reads a trace; it makes no connections.');
    } else {
      recClear('Nothing yet.');
    }
    startCmd();
    markSteps();
  }

  function startCmd() {
    var s = D.scenes[S.scene], c = s.commands[S.cmd];
    S.item = 0;
    S.t0 = performance.now();
    if (s.panel === 'net') {
      resetNet(c);
      if (c.vpnw) recClear(c.sealed ? 'Starting.' : 'Nothing yet.');
      else recClear('This command runs without vpnw, so vpnw records nothing.');
    }
  }

  function finishCmd() {
    var s = D.scenes[S.scene], c = s.commands[S.cmd];
    if (c.exit) termLine('(exit ' + c.exit + ')', 'exit');
    if (s.panel === 'policy') showPolicy(s, S.cmd + 1);
    if (S.cmd + 1 < s.commands.length) {
      S.cmd++;
      startCmd();
      return;
    }
    S.phase = 'outro';
    S.outroT = performance.now();
    $('scene-outro').hidden = false;
    done[S.scene] = true;
    markSteps();
  }

  function applyItem(it, c) {
    if (it.k === 'cmd') termLine(it.text, 'cmd');
    else if (it.k === 'line') { termLine(it.text, lineClass(it)); if (D.scenes[S.scene].panel === 'net') onLine(it.text, c); }
    else if (it.k === 'ev') { onEvent(it.e); recEvent(it.e); }
  }

  function renderSceneInstantly(i) {
    enterScene(i);
    var s = D.scenes[i];
    for (var k = 0; k < s.commands.length; k++) {
      var c = s.commands[k];
      if (k > 0 && s.panel === 'net') { /* keep the last command on the diagram */ }
      for (; S.item < c.items.length; S.item++) applyItem(c.items[S.item], c);
      finishCmd();
    }
  }

  function elapsed() {
    var now = S.playing ? performance.now() : S.pausedAt;
    return now - S.t0;
  }

  function tick() {
    if (!S.playing) return;
    var s = D.scenes[S.scene];
    if (S.phase === 'cmd') {
      var c = s.commands[S.cmd], t = elapsed();
      while (S.item < c.items.length && c.items[S.item].t <= t) { applyItem(c.items[S.item], c); S.item++; }
      if (t >= c.ms) finishCmd();
    } else if (S.phase === 'outro') {
      if (performance.now() - S.outroT >= OUTRO_MS) {
        if (S.scene + 1 < D.scenes.length) enterScene(S.scene + 1);
        else { stop(true); return; }
      }
    }
    progress();
    requestAnimationFrame(tick);
  }

  function progress() {
    var s = D.scenes[S.scene];
    var inScene = 0;
    for (var k = 0; k < S.cmd; k++) inScene += s.commands[k].ms;
    if (S.phase === 'cmd') inScene += Math.min(elapsed(), s.commands[S.cmd].ms);
    else inScene = s.ms;
    var t = sceneOffset(S.scene) + inScene;
    $('progress-bar').style.width = Math.min(100, t / totalMs * 100).toFixed(1) + '%';
    $('progress-text').textContent = 'Step ' + s.no + ' of ' + D.scenes.length + ', ' + mmss(t) + ' / ' + mmss(totalMs);
  }

  function setPlayButton() {
    $('play-icon').setAttribute('d', S.playing ? 'M7 5h3.5v14H7zM13.5 5H17v14h-3.5z' : 'M7 4.5v15l13-7.5z');
    $('play-label').textContent = S.playing ? 'Pause' : (S.started ? (S.phase === 'end' ? 'Replay' : 'Resume') : 'Play');
  }

  function play() {
    if (S.phase === 'end') { S.started = false; goScene(0, true); return; }
    if (!S.started) { S.started = true; enterScene(S.scene); }
    else if (S.phase === 'cmd') S.t0 += performance.now() - S.pausedAt;
    else if (S.phase === 'outro') S.outroT += performance.now() - S.pausedAt;
    S.playing = true;
    setPlayButton();
    requestAnimationFrame(tick);
  }
  function pause() {
    S.playing = false;
    S.pausedAt = performance.now();
    setPlayButton();
  }
  function stop(end) {
    S.playing = false;
    S.pausedAt = performance.now();
    if (end) {
      S.phase = 'end';
      $('progress-bar').style.width = '100%';
      $('progress-text').textContent = 'Done: all ' + D.scenes.length + ' steps';
    }
    setPlayButton();
  }
  function goScene(i, autoplay) {
    S.started = true;
    if (autoplay) {
      enterScene(i);
      S.playing = true;
      setPlayButton();
      requestAnimationFrame(tick);
    } else {
      S.playing = false;
      renderSceneInstantly(i);
      S.pausedAt = performance.now();
      setPlayButton();
      progress();
    }
  }

  $('btn-play').addEventListener('click', function () { if (S.playing) pause(); else play(); });
  $('btn-next').addEventListener('click', function () { goScene(Math.min(S.scene + 1, D.scenes.length - 1), S.playing || !S.started); });
  $('btn-prev').addEventListener('click', function () { goScene(Math.max(S.scene - 1, 0), S.playing); });
  $('btn-restart').addEventListener('click', function () { done = {}; goScene(0, true); });

  /* ---- learn, in this page ------------------------------------------------------------ */
  function normalizeDraft(s) {
    return s.split('\n').filter(function (l) { return l.indexOf('$ ') !== 0 && l.indexOf('[exit') !== 0; })
      .join('\n').replace(/, \d{4}-\d{2}-\d{2}\./, ', DATE.').trim();
  }
  $('btn-learn-here').addEventListener('click', function () {
    if (!E) return;
    var r = E.learn(D.trace1, 'agent', $('learn-wild').checked);
    if (!r.ok) { $('learn-here-note').textContent = 'The engine refused the trace: ' + r.error; return; }
    $('pol-here-out').hidden = false;
    $('pol-here-out').textContent = r.toml;
    var rec = learnLines(D.scenes[1]).draft.join('\n');
    var same = normalizeDraft(r.toml) === normalizeDraft(rec);
    $('learn-here-note').innerHTML = same
      ? '<b>Computed in this page:</b> the same draft as the recorded run, line for line (only the date differs). '
        + r.allowed + ' destinations allowed, ' + r.unreached + ' tried but not reached.'
      : ($('learn-wild').checked
        ? '<b>Computed in this page, with folding on.</b> No domain here had three or more subdomains, so the result only differs from the recording in its header.'
        : '<b>Computed in this page.</b> It differs from the recording; please tell the project.');
  });

  /* ---- lab: the agent under your own policy ------------------------------------------ */
  var PRESETS = [
    ['The reviewed policy', 'agent.toml', function () { return D.policy; }],
    ['The draft from learn', 'with evil.example', function () {
      return learnLines(D.scenes[1]).draft.filter(function (l) { return l.indexOf('$ ') !== 0; }).join('\n') + '\n';
    }],
    ['A deny list', 'default allow', function () {
      return 'version = 1\nname = "deny-list"\n\n[policy]\ndefault = "allow"\ndeny_private = true\ndeny = ["evil.example"]\n';
    }],
    ['Wildcards', '*.github.com', function () {
      return 'version = 1\nname = "wildcards"\n\n[policy]\ndefault = "deny"\ndeny_private = true\nallow = [\n  "*.github.com",\n  "*.pythonhosted.org",\n  "*.example.com",\n  "tracker.office.internal",\n]\n';
    }],
    ['Nothing allowed', 'default deny', function () {
      return 'version = 1\nname = "closed"\n\n[policy]\ndefault = "deny"\n';
    }]
  ];

  function pathValue() {
    var r = document.querySelector('input[name="path"]:checked');
    return r ? r.value : 'direct';
  }
  function checkPolicy() {
    var p = $('pol-check');
    if (!E) return null;
    var r = E.compile($('pol-text').value);
    if (!r.ok) { p.className = 'pol-check bad'; p.textContent = r.error; return null; }
    var s = r.summary;
    p.className = 'pol-check good';
    p.textContent = 'The engine accepts it: default ' + s['default'] + ' (' + s.default_note + '), ' + s.allow_rules + ' allow and ' + s.deny_rules + ' deny rules, deny_private ' + (s.deny_private ? 'on' : 'off') + '.';
    return s;
  }
  function runCommand() {
    var name = 'policy.toml';
    var m = /^name\s*=\s*"([^"]*)"/m.exec($('pol-text').value);
    if (m && m[1]) name = m[1] + '.toml';
    $('run-cmd').textContent = 'vpnw guard ' + (pathValue() === 'office' ? '--config office.toml --via office ' : '') + '--policy ' + name + ' -- python3 agent.py';
  }

  function publicDNS() {
    var dns = {};
    Object.keys(PUBLIC).forEach(function (k) { dns[k] = [PUBLIC[k]]; });
    return dns;
  }

  function outcomeFor(step, remote) {
    var dns = remote ? {} : publicDNS();
    var r = E.plan($('pol-text').value, step.host, 443, remote, dns);
    if (!r.ok) return { error: r.error };
    var p = r.plan, o = { plan: p };
    if (p.outcome === 'denied') { o.cls = 'deny'; o.saw = 'blocked (vpnw answered 403)'; }
    else if (p.outcome === 'failed') { o.cls = 'fail'; o.saw = 'could not reach it (' + p.error + ')'; }
    else {
      var reachable = remote ? (PUBLIC[step.host] || OFFICE_ONLY[step.host]) : PUBLIC[step.host];
      if (reachable) { o.cls = 'ok'; o.saw = step.evil ? 'done: the token left' : 'done'; }
      else { o.cls = 'fail'; o.saw = 'could not reach it'; }
    }
    return o;
  }

  $('btn-run').addEventListener('click', function () {
    if (!E) return;
    runCommand();
    var body = $('run-body'), v = $('run-verdict');
    body.textContent = '';
    if (!checkPolicy()) {
      $('run-table').hidden = true;
      v.hidden = false; v.className = 'verdict bad';
      v.textContent = 'vpnw would stop here with exit code 121: the policy does not load, so nothing runs.';
      return;
    }
    var remote = pathValue() === 'office';
    var denied = 0, worked = 0, leaked = false, refused = null;
    AGENT_STEPS.forEach(function (step) {
      var o = outcomeFor(step, remote);
      if (o.error) { refused = o.error; return; }
      var p = o.plan;
      var tr = document.createElement('tr');
      var decided = p.outcome === 'denied'
        ? '<span class="st deny">deny</span><span class="why">' + esc(p.reason) + '</span>'
        : p.rule ? '<span class="st ok">allow</span><span class="why">' + esc(p.reason) + '</span>'
        : '<span class="why">' + esc(p.error || 'no decision needed') + '</span>';
      tr.innerHTML = '<td>' + esc(step.label) + '</td><td class="mono">' + esc(step.host) + ':443</td><td>' + decided +
        '</td><td><span class="st ' + o.cls + '">' + esc(o.saw) + '</span></td>';
      body.appendChild(tr);
      if (p.outcome === 'denied') denied++;
      if (o.cls === 'ok' && !step.evil) worked++;
      if (o.cls === 'ok' && step.evil) leaked = true;
    });
    if (refused) {
      $('run-table').hidden = true;
      v.hidden = false; v.className = 'verdict bad';
      v.textContent = 'vpnw refuses to start with this policy on this path (exit code 121): ' + refused;
      return;
    }
    $('run-table').hidden = false;
    v.hidden = false;
    var code = denied ? 'vpnw exits with 120, because it denied ' + denied + (denied === 1 ? ' connection.' : ' connections.') : 'vpnw exits with the agent’s own code, 0.';
    if (leaked) { v.className = 'verdict bad'; v.textContent = 'The token reached evil.example. ' + worked + ' of the agent’s 4 real steps worked. ' + code; }
    else if (worked === 4) { v.className = 'verdict ok'; v.textContent = 'All 4 real steps worked and the token went nowhere. ' + code; }
    else { v.className = 'verdict warn'; v.textContent = 'The token went nowhere, and ' + worked + ' of the agent’s 4 real steps worked. ' + code; }
  });

  function buildPolicyLab() {
    var pr = $('pol-presets');
    PRESETS.forEach(function (p) {
      var b = document.createElement('button');
      b.type = 'button'; b.className = 'preset';
      b.innerHTML = esc(p[0]) + ' <small>' + esc(p[1]) + '</small>';
      b.addEventListener('click', function () { $('pol-text').value = p[2](); checkPolicy(); runCommand(); });
      pr.appendChild(b);
    });
    $('pol-text').value = D.policy;
    $('pol-text').addEventListener('input', function () { checkPolicy(); runCommand(); });
    Array.prototype.forEach.call(document.querySelectorAll('input[name="path"]'), function (r) {
      r.addEventListener('change', runCommand);
    });
    runCommand();
  }

  /* ---- lab: one destination ------------------------------------------------------------ */
  var DEST = [
    ['evil.example', '443', '', 'direct', 'the attacker’s collector'],
    ['api.github.com', '443', '', 'direct', 'on the list'],
    ['169.254.169.254', '80', '', 'direct', 'cloud metadata'],
    ['2130706433', '80', '', 'direct', '127.0.0.1 written as a number'],
    ['64:ff9b::a9fe:a9fe', '80', '', 'direct', 'metadata in NAT64 form'],
    ['api.github.com', '443', '10.0.0.7', 'direct', 'a DNS answer that points inside'],
    ['::ffff:127.0.0.1', '22', '', 'direct', 'loopback, IPv4-mapped'],
    ['gist.github.com', '443', '140.82.112.4', 'direct', 'a name not on the list'],
    ['tracker.office.internal', '443', '', 'office', 'through the office exit']
  ];
  function buildDestLab() {
    var pr = $('dest-presets');
    DEST.forEach(function (d) {
      var b = document.createElement('button');
      b.type = 'button'; b.className = 'preset';
      b.innerHTML = esc(d[0].indexOf(':') >= 0 ? '[' + d[0] + ']:' + d[1] : d[0] + ':' + d[1]) + ' <small>' + esc(d[4]) + '</small>';
      b.addEventListener('click', function () {
        $('d-host').value = d[0]; $('d-port').value = d[1]; $('d-addrs').value = d[2]; $('d-path').value = d[3];
        askDest();
      });
      pr.appendChild(b);
    });
    $('btn-dest').addEventListener('click', askDest);
    ['d-host', 'd-port', 'd-addrs'].forEach(function (id) {
      $(id).addEventListener('keydown', function (ev) { if (ev.key === 'Enter') askDest(); });
    });
  }
  function askDest() {
    if (!E) return;
    var out = $('dest-out');
    var host = $('d-host').value.trim().replace(/^\[(.*)\]$/, '$1');
    var port = parseInt($('d-port').value, 10) || 0;
    var remote = $('d-path').value === 'office';
    var addrs = $('d-addrs').value.trim();
    var dns = publicDNS();
    if (addrs) dns[host.toLowerCase().replace(/\.$/, '')] = addrs.split(/[\s,]+/).filter(Boolean);
    var r = E.plan($('pol-text').value, host, port, remote, dns);
    if (!r.ok) {
      out.innerHTML = '<div class="answer deny"><p class="big">vpnw refuses to start</p><p>' + esc(r.error) + '</p></div>';
      return;
    }
    var p = r.plan, cls, big;
    if (p.outcome === 'denied') { cls = 'deny'; big = 'Denied'; }
    else if (p.outcome === 'failed') { cls = 'fail'; big = 'Stops before connecting'; }
    else { cls = 'ok'; big = remote ? 'Allowed: handed to the office exit' : 'Allowed: vpnw connects'; }
    var lookup = p.looked_up
      ? 'yes: ' + (p.addrs ? p.addrs.join(', ') : 'no answer')
      : (p.exit_resolves ? 'no: the office exit resolves names itself'
        : p.ip ? 'no: an address, not a name'
        : 'no: the answer could not change the decision, and a lookup can carry data out too');
    out.innerHTML = '<div class="answer ' + cls + '"><p class="big">' + esc(big) + '</p><dl>' +
      '<dt>Destination</dt><dd class="mono">' + esc((p.host || p.ip || host) + ':' + port) + '</dd>' +
      (p.rule ? '<dt>Rule</dt><dd class="mono">' + esc(p.rule + (p.text ? ' "' + p.text + '"' : '')) + '</dd>' : '') +
      (p.reason ? '<dt>Why</dt><dd>' + esc(p.reason) + '</dd>' : '') +
      (p.error ? '<dt>Stopped by</dt><dd>' + esc(p.error) + '</dd>' : '') +
      '<dt>DNS lookup</dt><dd>' + esc(lookup) + '</dd>' +
      '<dt>Path</dt><dd>' + (remote ? 'office exit' : 'direct') + '</dd></dl></div>';
  }

  /* ---- start ----------------------------------------------------------------------------- */
  Array.prototype.forEach.call(document.querySelectorAll('[data-recorded]'), function (e) {
    e.textContent = new Date(D.recorded + 'T12:00:00Z').toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
  });
  drawNet();
  buildSteps();
  buildPolicyLab();
  buildDestLab();
  enterScene(0);
  S.started = false;
  S.phase = 'cmd';
  resetNet(D.scenes[0].commands[0]);
  termLine('Press Play to replay the recorded runs, or pick a step.', 'exit');
  $('progress-text').textContent = 'Ready: 6 steps, ' + mmss(totalMs);
  setPlayButton();

  window.VPNWEngine.load().then(function (api) {
    E = api;
    $('engine-version').textContent = api.version;
    ['btn-run', 'btn-dest', 'btn-learn-here'].forEach(function (id) { $(id).disabled = false; });
    checkPolicy();
    askDest();
  }).catch(function (err) {
    var msg = 'The engine could not start in this browser (' + (err && err.message || err) + '). The replay above still works; the two panels need WebAssembly.';
    ['lab-policy', 'lab-dest'].forEach(function (id) {
      var p = document.createElement('p');
      p.className = 'fatal';
      p.textContent = msg;
      $(id).appendChild(p);
    });
  });
})();
