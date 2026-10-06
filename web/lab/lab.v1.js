// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

/* VPN Works Lab live demo. Every number on the page comes from Lab's own Go
 * code in engine.lab.v1.js, run on recordings of real runs; this file only
 * draws. */
(function () {
  'use strict';

  var E = null;          // the engine
  var RUNS = {};         // analyses by recording name
  var CORRECT = 'correct-server-silent.jsonl';
  var LEAK = 'dns-leak-server-silent.jsonl';
  var other = 'no-kill-switch-app-killed.jsonl';
  var step = 1;
  var seen = {};
  var picked = null;     // {name, kind, via, seq}

  var NEXT = ['', 'the fault', 'the correct client', 'the leaky client', 'one probe at a time', 'other faults', 'start again'];
  var KINDS = ['dns', 'tcp', 'udp'];
  var KIND_LABEL = { dns: 'DNS', tcp: 'TCP', udp: 'UDP' };
  var AT = {
    'home-dns': 'the home router\'s resolver',
    'vpn-dns': 'the VPN\'s resolver, inside the tunnel',
    'zone-dns': 'the name server for the probe\'s names',
    'tcp': 'the TCP observer',
    'udp': 'the UDP observer'
  };
  var SVGNS = 'http://www.w3.org/2000/svg';
  var ON = {
    'server-silent': 'the server fell silent', 'server-gone': 'the server went away', 'app-killed': 'the bench killed the client',
    'link-drop': 'the link dropped', 'route-push': 'the home network pushed its route', 'dns-change': 'the home network changed its DNS server'
  };
  var OFF = {
    'server-silent': 'the server answered again', 'app-killed': 'the client was started again', 'link-drop': 'the link came back',
    'route-push': 'the pushed route was withdrawn', 'dns-change': 'the network handed out its first DNS server again'
  };

  function $(id) { return document.getElementById(id); }
  function fmt(n) { return Number(n).toLocaleString('en-US'); }
  function sec(s) { return (Math.round(s * 100) / 100).toFixed(2) + ' s'; }
  function ms(x) { return Math.round(x) + ' ms'; }
  function h(tag, attrs, kids) {
    var e = document.createElement(tag);
    if (attrs) {
      Object.keys(attrs).forEach(function (k) {
        if (k === 'class') e.className = attrs[k];
        else if (k === 'text') e.textContent = attrs[k];
        else if (attrs[k] != null) e.setAttribute(k, attrs[k]);
      });
    }
    (kids || []).forEach(function (c) {
      if (c == null) return;
      e.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
    });
    return e;
  }
  function s(tag, attrs, text) {
    var e = document.createElementNS(SVGNS, tag);
    Object.keys(attrs || {}).forEach(function (k) { e.setAttribute(k, attrs[k]); });
    if (text != null) e.textContent = text;
    return e;
  }
  function clear(e) { while (e.firstChild) e.removeChild(e.firstChild); return e; }
  function tile(n, label, cls, id) {
    return h('div', { 'class': 'tile' + (cls ? ' ' + cls : ''), id: id || null }, [
      h('div', { 'class': 'n', text: n }), h('div', { 'class': 'l', text: label })]);
  }
  // said turns a change the verdict names into words.
  function said(change) {
    var m;
    if ((m = /^fault on \((.*)\)$/.exec(change))) return ON[m[1]] || 'the fault began';
    if ((m = /^fault off \((.*)\)$/.exec(change))) return OFF[m[1]] || 'the fault ended';
    if ((m = /^client dns (\S+) \(while reconnecting\)$/.exec(change))) return 'the client pointed DNS at ' + m[1];
    if ((m = /^client dns (\S+)/.exec(change))) return 'the client set DNS to ' + m[1];
    if (change === 'client routes removed') return 'the client removed its routes';
    if (change === 'client routes installed') return 'the client put its routes back';
    if (change === 'client up') return 'the client\'s tunnel came up';
    if (/^client down/.test(change)) return 'the client gave up on its tunnel';
    if (change === 'client link up') return 'the client saw its link come back';
    if (/^app killed/.test(change)) return 'the bench killed the app';
    if (/^app started/.test(change)) return 'the bench started the app';
    if (change === 'stop') return 'the run stopped';
    return change;
  }
  function kinds(list) { return list.map(function (k) { return KIND_LABEL[k] || k; }).join(' and '); }

  function setStatus(text, bad) {
    var st = $('status');
    st.textContent = text;
    st.className = 'status' + (bad ? ' bad' : '');
  }

  /* ---- reading an analysis ---- */
  function steps(a) {
    var out = {};
    a.marks.forEach(function (m) { if (m.what === 'step') out[m.state] = m.t; });
    return out;
  }
  function faultSpan(a) {
    var st = steps(a);
    var off = st['fault-off'] != null ? st['fault-off'] : (st.stop != null ? st.stop : a.duration);
    return st['fault-on'] != null ? [st['fault-on'], off] : null;
  }
  // The client's tunnel, up or down, from its own log: spans of [from, to, up].
  function bands(a) {
    var out = [], up = true, from = 0;
    a.marks.forEach(function (m) {
      var change = null;
      if (m.what === 'client' && m.state === 'up') change = true;
      if (m.what === 'client' && m.state === 'down') change = false;
      if (m.what === 'app' && m.state === 'killed') change = false;
      if (change === null || change === up) return;
      out.push([from, m.t, up]);
      from = m.t;
      up = change;
    });
    out.push([from, a.duration, up]);
    return out;
  }
  function tunnelDown(a) {
    var down = bands(a).filter(function (b) { return !b[2] && b[1] > b[0]; });
    return down.length ? down[0] : null;
  }
  function count(a, f) {
    var n = 0;
    a.probes.forEach(function (p) { if (f(p)) n++; });
    return n;
  }

  /* ---- timelines ---- */
  function timeline(svg, name, from, to, opts) {
    var a = RUNS[name];
    opts = opts || {};
    var W = Math.max(300, Math.round(svg.parentNode.clientWidth - 20));
    var L = 40, R = 6, top = 4, band = 8, rowH = 20, gap = 6, axis = opts.marks ? 42 : 18;
    var H = top + band + 6 + KINDS.length * (rowH + gap) + axis;
    clear(svg);
    svg.setAttribute('viewBox', '0 0 ' + W + ' ' + H);
    svg.setAttribute('width', W);
    svg.setAttribute('height', H);
    var span = to - from;
    var x = function (t) { return L + (t - from) / span * (W - L - R); };
    var rowY = function (i) { return top + band + 6 + i * (rowH + gap); };
    var f = faultSpan(a);
    if (f) {
      var fx0 = Math.max(L, x(f[0])), fx1 = Math.min(W - R, x(f[1]));
      if (fx1 > fx0) {
        svg.appendChild(s('rect', { 'class': 'fault', x: fx0, y: top, width: fx1 - fx0, height: H - top - axis }));
        svg.appendChild(s('line', { 'class': 'fault-edge', x1: fx0, x2: fx0, y1: top, y2: H - axis }));
        svg.appendChild(s('line', { 'class': 'fault-edge', x1: fx1, x2: fx1, y1: top, y2: H - axis }));
      }
    }
    bands(a).forEach(function (b) {
      var b0 = Math.max(from, b[0]), b1 = Math.min(to, b[1]);
      if (b1 <= b0) return;
      svg.appendChild(s('rect', { 'class': b[2] ? 'band-up' : 'band-down', x: x(b0), y: top, width: x(b1) - x(b0), height: band, rx: 2 }));
    });
    var step = span > 6 ? 1 : 0.5;
    for (var t = Math.ceil(from / step) * step; t <= to + 1e-9; t += step) {
      var tx = x(t);
      svg.appendChild(s('line', { 'class': 'grid', x1: tx, x2: tx, y1: top + band + 2, y2: H - axis }));
      var lbl = (step < 1 ? t.toFixed(1) : String(Math.round(t))) + ' s';
      if (W < 500 && step < 1 && Math.round(t * 2) % 2 === 1) continue;
      svg.appendChild(s('text', { 'class': 'axis', x: tx, y: H - axis + 13, 'text-anchor': 'middle' }, lbl));
    }
    KINDS.forEach(function (k, i) {
      svg.appendChild(s('text', { 'class': 'row-label', x: 2, y: rowY(i) + rowH / 2 + 4 }, KIND_LABEL[k]));
    });
    var interval = a.header.intervalMS / 1000;
    var pw = Math.max(1.2, interval / span * (W - L - R) * 0.72);
    var rows = KINDS.map(function () { return []; });
    a.probes.forEach(function (p) {
      if (p[1] !== 0) return; // direct probes only: the stand-ins' probe sends nothing else
      var t = p[3] / 1000;
      if (t < from || t > to) return;
      var cls = p[4] === 2 ? 'p-leak' : (p[4] === 1 ? 'p-tunnel' : 'p-lost');
      var r = s('rect', { 'class': cls, x: x(t) - pw / 2, y: rowY(p[0]), width: pw, height: rowH, rx: 1 });
      svg.appendChild(r);
      rows[p[0]].push(p);
    });
    (a.report.windows || []).forEach(function (w) {
      var w0 = Math.max(from, w.start), w1 = Math.min(to, w.end);
      if (w1 < w0) return;
      svg.appendChild(s('rect', { 'class': 'window', x: x(w0) - pw, y: top + band + 2, width: x(w1) - x(w0) + 2 * pw, height: KINDS.length * (rowH + gap) + 2, rx: 3 }));
    });
    if (opts.marks) {
      // The client's changes, grouped when they come within 150 ms of each
      // other, so "down", "routes removed" and a DNS change read as one.
      var groups = [];
      a.marks.forEach(function (m) {
        if (m.what !== 'client' || m.t < from || m.t > to) return;
        var word = m.state === 'down' ? 'tunnel down' : m.state === 'up' ? 'tunnel up' :
          m.state === 'dns' ? 'DNS to ' + m.note.split(' ')[0] : null;
        if (!word) return;
        var g = groups[groups.length - 1];
        if (g && m.t - g.t < 0.15) { if (g.words.indexOf(word) < 0) g.words.push(word); return; }
        groups.push({ t: m.t, words: [word] });
      });
      var lastX = -1000, lane = 0;
      groups.forEach(function (g) {
        var mx = x(g.t);
        svg.appendChild(s('line', { 'class': 'mark', x1: mx, x2: mx, y1: top, y2: H - axis + 18 }));
        lane = mx - lastX < 120 ? 1 - lane : 0;
        lastX = mx;
        var anchor = mx < L + 60 ? 'start' : mx > W - 90 ? 'end' : 'middle';
        svg.appendChild(s('text', { 'class': 'mark-text', x: mx + (anchor === 'start' ? 2 : anchor === 'end' ? -2 : 0), y: H - 3 - lane * 11, 'text-anchor': anchor }, g.words.join(', ')));
      });
    }
    if (opts.pick) {
      svg.onclick = function (ev) {
        var box = svg.getBoundingClientRect();
        var px = (ev.clientX - box.left) / box.width * W, py = (ev.clientY - box.top) / box.height * H;
        var row = -1;
        KINDS.forEach(function (k, i) { if (py >= rowY(i) - gap / 2 && py <= rowY(i) + rowH + gap / 2) row = i; });
        if (row < 0) return;
        var t = from + (px - L) / (W - L - R) * span, best = null;
        rows[row].forEach(function (p) {
          if (!best || Math.abs(p[3] / 1000 - t) < Math.abs(best[3] / 1000 - t)) best = p;
        });
        if (best) pick(name, best);
      };
      if (picked && picked.name === name) {
        var pp = null;
        rows.forEach(function (r) { r.forEach(function (p) { if (KINDS[p[0]] === picked.kind && p[2] === picked.seq) pp = p; }); });
        if (pp) svg.appendChild(s('rect', { 'class': 'sel', x: x(pp[3] / 1000) - pw / 2 - 2, y: rowY(pp[0]) - 2, width: pw + 4, height: rowH + 4, rx: 2 }));
      }
    }
  }

  /* ---- step 2: the timetable and the logs ---- */
  function renderPlan() {
    var a = RUNS[LEAK];
    var st = steps(a), plan = clear($('plan'));
    var total = st.stop;
    var pct = function (t) { return (t / total * 100) + '%'; };
    plan.appendChild(h('div', { 'class': 'bar' }));
    plan.appendChild(h('div', { 'class': 'fault', style: 'left:' + pct(st['fault-on']) + ';width:' + pct(st['fault-off'] - st['fault-on']) }));
    [['start', 0, 'start'], ['fault-on', st['fault-on'], ''], ['fault-off', st['fault-off'], ''], ['stop', total, 'end']].forEach(function (k) {
      plan.appendChild(h('span', { 'class': 'tick ' + k[2], style: 'left:' + pct(k[1]), text: sec(k[1]) }));
    });
    plan.appendChild(h('span', { 'class': 'lbl', style: 'left:' + pct((st['fault-on'] + st['fault-off']) / 2), text: 'server silent, ' + sec(st['fault-off'] - st['fault-on']) }));
    $('t-seed').textContent = a.report.seed;
    renderLog($('log-correct'), RUNS[CORRECT]);
    renderLog($('log-leak'), a);
  }

  function renderLog(ul, a) {
    clear(ul);
    var st = steps(a);
    a.marks.forEach(function (m) {
      if (m.t < st['fault-on'] - 0.01 || m.t > st.stop) return;
      var text = null, cls = '';
      if (m.what === 'step' && (m.state === 'fault-on' || m.state === 'fault-off')) {
        text = m.state === 'fault-on' ? 'the server falls silent (the bench)' : 'the server answers again (the bench)';
        cls = 'step';
      } else if (m.what === 'client') {
        if (m.state === 'down') text = 'tunnel down: ' + m.note;
        else if (m.state === 'up') text = 'tunnel up again';
        else if (m.state === 'routes') text = 'routes ' + m.note;
        else if (m.state === 'dns') { text = 'DNS set to ' + m.note; if (m.note.indexOf('192.168.') === 0) cls = 'warn'; }
      }
      if (text) ul.appendChild(h('li', { 'class': cls }, [h('span', { 'class': 't', text: sec(m.t) }), h('span', { 'class': 'w', text: text })]));
    });
  }

  /* ---- steps 3, 4 and 6: one run ---- */
  function renderRun(name, prefix, ids) {
    var a = RUNS[name], r = a.report;
    var v = clear($(ids.verdict));
    v.appendChild(h('span', { 'class': 'verdict ' + (r.status === 'pass' ? 'pass' : 'leak'), id: prefix + '-verdict',
      text: 'Lab\'s verdict: ' + r.summary }));
    var tiles = clear($(ids.tiles));
    tiles.appendChild(tile(fmt(r.sent), 'probes sent', '', prefix + '-sent'));
    tiles.appendChild(tile(fmt(r.tunnel), 'through the tunnel', 'good', prefix + '-tunnel'));
    tiles.appendChild(tile(fmt(r.leaked), 'leaked', r.leaked ? 'bad' : 'good', prefix + '-leaked'));
    tiles.appendChild(tile(fmt(r.lost), 'held back, seen nowhere', 'warn', prefix + '-lost'));
    timeline($(ids.svg), name, 0, a.duration, {});
  }

  function renderCorrect() {
    renderRun(CORRECT, 'c', { verdict: 'verdict-correct', tiles: 'tiles-correct', svg: 'tl-correct' });
    var a = RUNS[CORRECT], r = a.report, d = tunnelDown(a);
    var held = count(a, function (p) { return p[4] === 0; });
    var text = fmt(held) + ' probes went nowhere. ';
    if (d) {
      var inside = count(a, function (p) { return p[4] === 0 && p[3] / 1000 >= d[0] && p[3] / 1000 <= d[1]; });
      var before = count(a, function (p) { return p[4] === 0 && p[3] / 1000 < d[0]; });
      text = 'By its own log the tunnel was down from ' + sec(d[0]) + ' to ' + sec(d[1]) + '. ' +
        fmt(inside) + ' probes went nowhere in that time: the kill switch held them, and DNS stayed pointed into the tunnel. ' +
        (before ? fmt(before) + ' more were lost before the client noticed the silence: they went into the tunnel, and the silent server dropped them. ' : '');
    }
    $('outro-correct').textContent = text + 'Not one left outside. ' +
      (r.recovery_ms >= 0 ? 'Probes came through the tunnel again ' + ms(r.recovery_ms) + ' after the server answered.' : '');
  }

  function renderLeak() {
    renderRun(LEAK, 'l', { verdict: 'verdict-leak', tiles: 'tiles-leak', svg: 'tl-leak' });
    var r = RUNS[LEAK].report, w = r.windows[0];
    if (!w) return;
    $('outro-leak').textContent = fmt(w.probes) + ' DNS queries reached the home router\'s resolver between ' + sec(w.start) + ' and ' + sec(w.end) +
      ', each with its name in the clear. Lab saw the first ' + ms(w.after_ms) + ' after ' + said(w.after) +
      ', and the last ' + ms(w.before_ms) + ' before ' + said(w.before) + '. Its TCP and UDP probes were held back, as the correct client\'s were.';
  }

  function renderOther() {
    renderRun(other, 'o', { verdict: 'verdict-other', tiles: 'tiles-other', svg: 'tl-other' });
    var r = RUNS[other].report, w = r.windows[0];
    var text = '';
    if (w) {
      text = fmt(w.probes) + ' probes (' + kinds(w.kinds) + ') left outside the tunnel between ' + sec(w.start) + ' and ' + sec(w.end) +
        '. Lab saw the first ' + ms(w.after_ms) + ' after ' + said(w.after) + (w.open ? '.' : ', and the last ' + ms(w.before_ms) + ' before ' + said(w.before) + '.');
      if (other.indexOf('route-push') >= 0) text += ' DNS went to the VPN\'s resolver through the tunnel throughout: the pushed route only covered the observers\' range.';
      if (other.indexOf('app-killed') >= 0) text += ' With no kill switch, nothing held the traffic back once the client was gone; the restarted client closed the leak when its tunnel came up.';
    }
    $('note-other').textContent = text;
  }

  /* ---- step 5: zoom and inspect ---- */
  function zoomSpan() {
    var st = steps(RUNS[LEAK]);
    var down = tunnelDown(RUNS[LEAK]);
    var to = Math.max(st['fault-off'], down ? down[1] : 0) + 0.6;
    return [Math.max(0, st['fault-on'] - 0.5), Math.min(RUNS[LEAK].duration, to)];
  }

  function renderZoom() {
    var z = zoomSpan();
    timeline($('zoom-correct'), CORRECT, z[0], z[1], { marks: true, pick: true });
    timeline($('zoom-leak'), LEAK, z[0], z[1], { marks: true, pick: true });
    if (!picked) {
      var first = null;
      RUNS[LEAK].probes.forEach(function (p) { if (!first && p[4] === 2) first = p; });
      if (first) pick(LEAK, first);
    }
  }

  function pick(name, p) {
    picked = { name: name, kind: KINDS[p[0]], via: p[1] === 0 ? 'direct' : 'proxy', seq: p[2] };
    var d = E.probe(name, picked.kind, picked.via, picked.seq);
    var box = clear($('inspect'));
    var who = name === CORRECT ? 'the correct client' : 'the dns-leak client';
    box.appendChild(h('h4', { id: 'inspect-title', text: KIND_LABEL[picked.kind] + ' probe ' + picked.seq + ' of ' + who + ', sent at ' + sec(d.sent) }));
    var ol = h('ol');
    if (!d.arrivals.length) ol.appendChild(h('li', { text: 'It arrived nowhere.' }));
    d.arrivals.forEach(function (x) {
      ol.appendChild(h('li', { text: 'At ' + sec(x.t) + ' it reached ' + (AT[x.at] || x.at) + ', from ' + x.src +
        (x.path === 'tunnel' ? ': through the tunnel.' : ': outside the tunnel.') }));
    });
    box.appendChild(ol);
    var o = d.outcome;
    box.appendChild(h('p', { id: 'inspect-why', 'class': 'why ' + (o === 'leaked' ? 'out' : o === 'tunnel' ? 'in' : 'none'),
      text: o === 'leaked' ? 'Lab counts it as leaked: it was seen outside the tunnel.' :
        o === 'tunnel' ? 'Lab counts it as through the tunnel: every arrival came from the VPN\'s side.' :
          'Lab counts it as held back: nothing saw it arrive.' }));
    if (step === 5) {
      var z = zoomSpan();
      timeline($('zoom-correct'), CORRECT, z[0], z[1], { marks: true, pick: true });
      timeline($('zoom-leak'), LEAK, z[0], z[1], { marks: true, pick: true });
    }
  }

  function renderBench() {
    var a = RUNS[LEAK];
    $('b-interval').textContent = a.header.intervalMS;
    $('b-home').textContent = $('b-home2').textContent = a.header.Home;
    $('b-exit').textContent = $('b-exit2').textContent = a.header.Exit;
  }

  /* ---- navigation ---- */
  var render = { 1: renderBench, 2: renderPlan, 3: renderCorrect, 4: renderLeak, 5: renderZoom, 6: renderOther };

  function show(n, scroll) {
    n = Math.max(1, Math.min(6, n | 0));
    step = n;
    seen[n] = true;
    document.querySelectorAll('.scene').forEach(function (sc) { sc.hidden = Number(sc.getAttribute('data-step')) !== n; });
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

  function wire() {
    document.querySelectorAll('#steps button').forEach(function (b) {
      b.addEventListener('click', function () { show(Number(b.getAttribute('data-step')), false); });
    });
    $('btn-back').addEventListener('click', function () { show(step - 1, true); });
    $('btn-next').addEventListener('click', function () { show(step === 6 ? 1 : step + 1, true); });
    var seg = document.querySelector('#scene-6 .seg');
    seg.querySelectorAll('button').forEach(function (b) {
      b.addEventListener('click', function () {
        seg.querySelectorAll('button').forEach(function (x) {
          x.classList.toggle('on', x === b);
          x.setAttribute('aria-pressed', String(x === b));
        });
        other = b.getAttribute('data-rec');
        renderOther();
      });
    });
    var resize = 0;
    window.addEventListener('resize', function () {
      clearTimeout(resize);
      resize = setTimeout(function () { if (E) render[step](); }, 150);
    });
  }

  function start() {
    wire();
    var m = /^#step-([1-6])$/.exec(location.hash);
    show(m ? Number(m[1]) : 1, false);
    if (!window.VPNWLab || !window.WebAssembly) {
      setStatus('This browser cannot run the engine: it needs WebAssembly.', true);
      return;
    }
    window.VPNWLab.load().then(function (engine) {
      E = engine;
      $('engine-version').textContent = E.version;
      var t0 = performance.now(), probes = 0, n = 0;
      E.recordings().forEach(function (r) {
        var a = E.analyze(r.name);
        if (!a.ok) throw new Error(a.error);
        RUNS[r.name] = a;
        probes += a.report.sent;
        n++;
      });
      var took = Math.max(1, Math.round(performance.now() - t0));
      setStatus('Lab ' + E.version + ' is running in this page. It decided ' + n + ' recorded runs, ' + fmt(probes) + ' probes, in ' + took + ' ms.');
      document.documentElement.setAttribute('data-ready', '1');
      show(step, false);
    }).catch(function (err) {
      setStatus('The engine could not start: ' + (err && err.message ? err.message : err), true);
    });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start);
  else start();
})();
