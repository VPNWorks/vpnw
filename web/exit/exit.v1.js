// Copyright VPNW.com 2026
// SPDX-License-Identifier: Apache-2.0

/* VPN Works Exit live demo. The run it replays is in data.exit.v1.js, copied
 * from the records the real binaries wrote; every decision and count that is
 * not a recording comes from Exit's own Go code in engine.exit.v1.js. This
 * file only draws. */
(function () {
  'use strict';

  var D = window.VPNW_EXIT_DATA;   // the recorded run
  var E = null;                    // the engine
  var step = 1;
  var seen = {};
  var timers = [];
  var files = {};                  // the exits' folder: their configuration and the clients' policy files
  var NEXT = ['', 'fixed addresses', 'checked at both ends', 'a tampered client', 'an exit fails', 'one joined record', 'start again'];
  var EXITS = { '198.51.100.2:8443': 'exit-de', '203.0.113.2:8443': 'exit-nl' };
  var CHIPS = ['169.254.169.254:80', 'attacker.test:443', 'intranet.partner.test:80', 'files.partner.test:80', 'api.partner.test:443', 'api.partner.test:80'];

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
  function when(ms) { return '+' + (ms / 1000).toFixed(1) + ' s'; }
  function setStatus(text, bad) {
    var s = $('status');
    s.textContent = text;
    s.className = 'status' + (bad ? ' bad' : '');
  }
  function records(name) {
    return D.records[name].split('\n').filter(function (l) { return l.trim(); }).map(function (l) { return JSON.parse(l); });
  }

  /* ---- the timeline ---- */
  function items(n) {
    var kill = 0;
    D.timeline.forEach(function (it, i) { if (it.kind === 'killed') kill = i; });
    return D.timeline.filter(function (it, i) {
      var agent = it.actor === 'agent-1' || it.actor === 'agent-2';
      switch (n) {
        case 2: return agent && i < kill && it.outcome === 'reached';
        case 3: return it.actor === 'agent-1' && it.outcome.indexOf('refused') === 0;
        case 4: return it.actor === 'tampered';
        case 5: return i >= kill;
      }
      return false;
    });
  }

  function rule(r, text) { return text ? r + ' "' + text + '"' : r; }

  function entry(it) {
    var lines = [], badge, cls = 'reached', dest = it.target;
    var a = it.agent, x = it.exit;
    if (it.kind === 'killed') {
      return h('div', { 'class': 'entry kill' }, [
        h('div', { 'class': 'head' }, [h('span', { 'class': 'who' }, [h('span', { 'class': 'when', text: when(it.t) }), 'exit-de']),
          h('span', { 'class': 'badge event', text: 'stopped' })]),
        h('ul', {}, [h('li', { text: 'Its process is killed (SIGKILL): no goodbye, no summary in its record. exit-nl carries on.' })])]);
    }
    if (a) {
      if (a.decision === 'deny') {
        lines.push(h('li', {}, ['at the Agent: refused, ', h('code', { text: a.rule }), ': ' + a.reason + '. Nothing left the machine.']));
      } else {
        lines.push(h('li', {}, ['at the Agent: allowed by ', h('code', { text: rule(a.rule, a.text) }),
          '; names resolve at the exit, so it is sent there by name']));
      }
      if (a.switch) {
        lines.push(h('li', { 'class': 'switch' }, ['switch: the Agent gave up on ' + a.switch.from + ' after ' + a.switch.ms + ' ms (' +
          a.switch.error + ') and moved to ' + a.switch.to + '; open ' + a.ms + ' ms after the dial began']));
      }
    }
    if (x) {
      var at = 'at ' + x.exit + (it.actor !== 'tampered' ? ', run ' + x.clientRun + ' #' + x.clientConn :
        ' (' + x.proto + (x.clientRun ? ', with a run ID it made up: ' + x.clientRun + ' #' + x.clientConn : ', no run ID: there is no Agent') + ')');
      var dns = Array.isArray(x.dns) ? '; ' + x.host + ' = ' + x.dns.join(', ') : '';
      if (x.outcome === 'refused') {
        cls = 'refused';
        lines.push(h('li', {}, [at + ': refused, ', h('code', { text: x.rule }), ': ' + x.reason]));
      } else if (x.outcome === 'open') {
        lines.push(h('li', {}, [at + ': allowed by ', h('code', { text: rule(x.rule, x.text) }), dns + '; left from ', h('code', { text: x.source })]));
      }
    }
    if (it.server) {
      lines.push(h('li', {}, ['the partner saw ', h('code', { text: it.server.src }), ' at ' + it.server.dst + ':' + it.server.port]));
    } else if (it.outcome.indexOf('refused') === 0) {
      cls = 'refused';
      lines.push(h('li', { text: 'no server saw anything' }));
    }
    badge = it.outcome;
    return h('div', { 'class': 'entry', 'data-outcome': it.outcome, 'data-rule': x ? (x.rule || '') : (a ? a.rule : '') }, [
      h('div', { 'class': 'head' }, [
        h('span', {}, [h('span', { 'class': 'when', text: when(it.t) }), h('span', { 'class': 'who', text: it.actor }), ' asks for ', h('span', { 'class': 'dest', text: dest })]),
        h('span', { 'class': 'badge ' + cls, text: badge })]),
      h('ul', {}, lines)]);
  }

  function light(it) {
    document.querySelectorAll('#net .node').forEach(function (n) { n.classList.remove('on'); });
    if (!it) return;
    var on = [it.actor];
    if (it.kind === 'killed') on = ['exit-de'];
    if (it.exit) on.push(it.exit.exit);
    if (it.server) on.push('partner');
    else if (it.outcome.indexOf('refused') === 0) on.push('forbidden');
    on.forEach(function (k) {
      var n = document.querySelector('#net .node[data-node="' + k + '"]');
      if (n) n.classList.add('on');
    });
  }

  function exitDown(down) {
    document.querySelector('#net .node[data-node="exit-de"]').classList.toggle('down', !!down);
  }

  function stop() {
    timers.forEach(clearTimeout);
    timers = [];
  }

  function play(n, instant) {
    stop();
    var log = $('log-' + n);
    if (!log) return;
    clear(log);
    log.removeAttribute('data-done');
    var list = items(n);
    exitDown(n > 5);
    function show(i) {
      var it = list[i];
      log.appendChild(entry(it));
      light(it);
      if (it.kind === 'killed') exitDown(true);
      if (i === list.length - 1) {
        log.setAttribute('data-done', '1');
        timers.push(setTimeout(function () { light(null); }, instant ? 0 : 1600));
      }
    }
    if (instant) {
      list.forEach(function (_, i) { show(i); });
      light(null);
      return;
    }
    list.forEach(function (_, i) { timers.push(setTimeout(function () { show(i); }, 350 + i * 900)); });
  }

  /* ---- step 1 ---- */
  function renderSetup() {
    var de = E.parse('exit-de.toml', files), nl = E.parse('exit-nl.toml', files);
    if (!de.ok || !nl.ok) {
      $('setup-note').textContent = (de.error || nl.error);
      return;
    }
    $('addr-de').textContent = de.listen;
    $('addr-nl').textContent = nl.listen;
    var allowed = 0, body = clear($('setup-body'));
    de.clients.forEach(function (c, i) {
      var c2 = nl.clients[i];
      if (c.name !== 'ci') allowed += 2;
      var pol = 'default ' + c.default + ', ' + c.allow + ' allow rules' + (c.denyPrivate ? ', deny_private' : '');
      var from = function (x) { return x.pool ? x.source + ' (pool ' + x.pool + ')' : x.source; };
      body.appendChild(h('tr', {}, [h('td', { text: c.name }), h('td', { 'data-label': 'Policy', text: pol }),
        h('td', { 'class': 'mono', 'data-label': 'From exit-de', text: from(c) }), h('td', { 'class': 'mono', 'data-label': 'From exit-nl', text: from(c2) })]));
    });
    var tiles = clear($('setup-tiles'));
    tiles.appendChild(tile('2', 'exits, in two countries', '', 't1-exits'));
    tiles.appendChild(tile(String(de.clients.length), 'clients at each exit', '', 't1-clients'));
    tiles.appendChild(tile(String(allowed), 'fixed addresses the partner allows', 'good', 't1-addrs'));
    $('setup-note').textContent = 'Read from exit-de.toml and exit-nl.toml by the exit\'s code in this page. ci is a CI job that talks to the exits without an Agent; it shares a pool of two addresses at each exit.';
  }

  /* ---- steps 2 to 5: tiles ---- */
  function renderTiles(n) {
    var list = items(n), t = clear($('t' + n + '-tiles'));
    if (n === 2) {
      var by = {};
      list.forEach(function (it) { if (it.server) by[it.actor] = it.server.src; });
      t.appendChild(tile(String(list.length), 'requests reached the partner', 'good', 't2-reached'));
      t.appendChild(tile(by['agent-1'] || '', 'agent-1\'s address, every time', '', 't2-a1'));
      t.appendChild(tile(by['agent-2'] || '', 'agent-2\'s address, every time', '', 't2-a2'));
    } else if (n === 3) {
      var atAgent = list.filter(function (it) { return it.outcome === 'refused at the Agent'; }).length;
      t.appendChild(tile(String(atAgent), 'refused by the Agent, before anything left', 'good', 't3-agent'));
      t.appendChild(tile(String(list.length - atAgent), 'refused by the exit, once it saw the address', 'good', 't3-exit'));
      renderPair3(list);
    } else if (n === 4) {
      var refused = list.filter(function (it) { return it.outcome === 'refused at the exit'; }).length;
      var reached = list.filter(function (it) { return it.server; }).length;
      t.appendChild(tile(String(list.length), 'requests with a stolen token', '', 't4-requests'));
      t.appendChild(tile(String(refused), 'refused by exit-de', 'good', 't4-refused'));
      t.appendChild(tile(String(reached), 'reached a server', reached ? 'bad' : 'good', 't4-servers'));
    } else if (n === 5) {
      var moved = list.filter(function (it) { return it.agent && it.agent.switch; });
      var failed = list.filter(function (it) { return it.outcome === 'failed'; }).length;
      t.appendChild(tile(String(moved.length), 'agents moved to exit-nl', 'good', 't5-moved'));
      t.appendChild(tile(String(failed), 'requests failed', failed ? 'bad' : 'good', 't5-failed'));
      moved.forEach(function (it) {
        var s = tile(it.agent.ms + ' ms', it.actor + ': from the start of its dial to a connection through exit-nl (it gave up on exit-de after ' +
          it.agent.switch.ms + ' ms)', '', 't5-' + it.actor);
        s.setAttribute('data-open-ms', String(it.agent.ms));
        s.setAttribute('data-switch-ms', String(it.agent.switch.ms));
        t.appendChild(s);
      });
      var nl = {};
      list.forEach(function (it) { if (it.server) nl[it.actor] = it.server.src; });
      $('outro-5').textContent = 'agent-1 now reaches the partner from ' + nl['agent-1'] + ' and agent-2 from ' + nl['agent-2'] +
        ', their addresses at exit-nl. ' + (failed ? failed + ' of the requests failed' : 'No request failed') +
        ', and the Agent\'s record says when and why it moved.';
    }
  }

  /* Both records of one connection, side by side. */
  function pairOf(container, run, conn) {
    clear(container);
    var agent = null, ex = null, exitName = '';
    ['agent-1.jsonl', 'agent-2.jsonl'].forEach(function (f) {
      var r = records(f).filter(function (e) { return e.run === run && e.conn === conn; });
      if (r.length) agent = r;
    });
    ['exit-de.jsonl', 'exit-nl.jsonl'].forEach(function (f) {
      var all = records(f), id = null;
      all.forEach(function (e) {
        if (e.type === 'connection.attempt' && e.fields && e.fields.client_run === run && e.fields.client_conn === conn) id = e.conn;
      });
      if (id != null) {
        var r = all.filter(function (e) { return e.conn === id; });
        if (r.some(function (e) { return e.type !== 'connection.attempt'; })) { ex = r; exitName = f.replace('.jsonl', ''); }
      }
    });
    function show(title, list) {
      return h('div', {}, [h('h4', { text: title }), h('pre', { tabindex: '0', text: (list || []).map(function (e) { return JSON.stringify(e); }).join('\n') || 'no record' })]);
    }
    container.appendChild(show('The Agent\'s record, run ' + run + ', connection ' + conn, agent));
    container.appendChild(show(exitName ? exitName + '\'s record of the same connection' : 'No exit record', ex));
  }

  function renderPair3(list) {
    var it = list.filter(function (x) { return x.outcome === 'refused at the exit'; })[0];
    if (it) pairOf($('pair-3'), it.agent.run, it.agent.conn);
  }

  /* ---- step 4: ask the exit ---- */
  function policyFiles() {
    var f = {};
    Object.keys(files).forEach(function (k) { f[k] = files[k]; });
    f['agent-2.toml'] = $('policy-text').value;
    return f;
  }

  function checkPolicy() {
    var res = E.parse('exit-de.toml', policyFiles());
    var c = $('policy-check');
    if (!res.ok) {
      c.className = 'pol-check bad';
      c.textContent = res.error;
      return false;
    }
    var a2 = res.clients.filter(function (x) { return x.name === 'agent-2'; })[0];
    c.className = 'pol-check good';
    c.textContent = 'exit-de reads it: default ' + a2.default + ', ' + a2.allow + ' allow rules, ' + a2.deny + ' deny rules, deny_private ' + a2.denyPrivate + '.';
    return true;
  }

  function ask() {
    var v = $('verdict');
    clear(v);
    v.className = 'verdict';
    if (!checkPolicy()) {
      v.textContent = 'The file has an error; exit-de would not start with it.';
      return;
    }
    var target = $('ask-target').value.trim();
    var d = E.decide('exit-de.toml', policyFiles(), 'agent-2', target, D.dns);
    v.setAttribute('data-target', target);
    if (!d.ok) {
      v.textContent = d.error;
      v.setAttribute('data-outcome', 'error');
      return;
    }
    v.setAttribute('data-outcome', d.outcome);
    v.setAttribute('data-rule', d.rule || '');
    if (d.outcome === 'allow') {
      v.className = 'verdict allow';
      v.appendChild(h('b', { text: 'Allowed, from ' + d.source }));
      v.appendChild(document.createTextNode('Rule ' + rule(d.rule, d.text) + ': ' + d.reason + (d.addrs ? '. DNS at the exit: ' + d.addrs.join(', ') : '') + '.'));
    } else if (d.outcome === 'denied') {
      v.className = 'verdict deny';
      v.appendChild(h('b', { text: 'Refused before any dial' }));
      v.appendChild(document.createTextNode('Rule ' + d.rule + ': ' + d.reason + '.'));
    } else {
      v.appendChild(h('b', { text: 'No connection' }));
      v.appendChild(document.createTextNode(d.error + (d.rule ? ' (the policy allowed it: ' + d.rule + ')' : '') + '.'));
    }
  }

  /* ---- step 6: the join ---- */
  var joined = null;
  function renderJoin() {
    var agent = D.records['agent-1.jsonl'] + D.records['agent-2.jsonl'];
    var exits = D.records['exit-de.jsonl'] + D.records['exit-nl.jsonl'];
    joined = E.join(agent, exits);
    var t = clear($('t6-tiles'));
    if (!joined.ok) {
      t.appendChild(h('p', { 'class': 'pol-check bad', text: joined.error }));
      return;
    }
    // Decide every recorded exit request again, with the code in this page.
    var same = 0, total = 0;
    ['exit-de', 'exit-nl'].forEach(function (name) {
      var all = records(name + '.jsonl'), att = {};
      all.forEach(function (e) {
        if (e.type === 'connection.attempt') att[e.conn] = e;
        if ((e.type === 'policy.allow' || e.type === 'policy.deny') && att[e.conn]) {
          var a = att[e.conn].fields, target = (a.host || a.ip) + ':' + a.port;
          var d = E.decide(name + '.toml', files, a.client, target, D.dns);
          total++;
          var outcome = e.type === 'policy.allow' ? 'allow' : 'denied';
          if (d.ok && d.rule === e.fields.rule && (d.outcome === outcome || (outcome === 'allow' && d.outcome === 'failed'))) same++;
        }
      });
    });
    t.appendChild(tile(joined.joined + ' of ' + joined.via_exit, 'connections that reached an exit, found in the exit\'s record', joined.complete ? 'good' : 'bad', 't6-joined'));
    t.appendChild(tile(String(joined.decided_at_agent), 'stopped at the Agent: nothing for an exit to record', '', 't6-local'));
    t.appendChild(tile(String(joined.other_runs), 'exit records from a client with no Agent', 'warn', 't6-other'));
    t.appendChild(tile(same + ' of ' + total, 'recorded exit decisions made again in this page, with the same rule', same === total ? 'good' : 'bad', 't6-redecided'));
    var body = clear($('join-body'));
    joined.rows.forEach(function (r, i) {
      var tr = h('tr', { 'class': r.run ? 'pick' : '', tabindex: r.run ? '0' : null, 'data-row': String(i) }, [
        h('td', { 'class': 'mono', text: r.run ? r.run + ' #' + r.conn : 'no run ID' }),
        h('td', { 'class': 'mono', 'data-label': 'To', text: r.target }),
        h('td', { 'data-label': 'At the Agent', text: r.agent }),
        h('td', { 'data-label': 'At the exit', text: (r.exit ? r.exit + ': ' : '') + r.at_exit })]);
      if (r.run) {
        var pick = function () {
          document.querySelectorAll('#join-body tr').forEach(function (x) { x.classList.remove('sel'); });
          tr.classList.add('sel');
          pairOf($('pair-6'), r.run, r.conn);
        };
        tr.addEventListener('click', pick);
        tr.addEventListener('keydown', function (ev) { if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); pick(); } });
      }
      body.appendChild(tr);
    });
    $('outro-6').textContent = 'The Agent sent its run ID and each connection\'s number with every request, and the exits wrote them into their own records. So ' +
      joined.joined + ' of ' + joined.via_exit + ' connections join up, across the failover. The tampered client\'s requests are in exit-de\'s record too, with no Agent run to join.';
  }

  /* ---- navigation ---- */
  var render = {
    1: renderSetup,
    2: function () { renderTiles(2); play(2); },
    3: function () { renderTiles(3); play(3); },
    4: function () { renderTiles(4); play(4); ask(); },
    5: function () { renderTiles(5); play(5); },
    6: function () { exitDown(true); renderJoin(); }
  };

  function show(n, scroll) {
    n = Math.max(1, Math.min(6, n | 0));
    step = n;
    seen[n] = true;
    stop();
    light(null);
    exitDown(n === 6);
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

  function wire() {
    document.querySelectorAll('#steps button').forEach(function (b) {
      b.addEventListener('click', function () { show(Number(b.getAttribute('data-step')), false); });
    });
    $('btn-back').addEventListener('click', function () { show(step - 1, true); });
    $('btn-next').addEventListener('click', function () { show(step === 6 ? 1 : step + 1, true); });
    document.querySelectorAll('[data-replay]').forEach(function (b) {
      b.addEventListener('click', function () { play(Number(b.getAttribute('data-replay'))); });
    });
    document.querySelectorAll('[data-skip]').forEach(function (b) {
      b.addEventListener('click', function () { play(Number(b.getAttribute('data-skip')), true); });
    });
    var chips = $('ask-chips');
    CHIPS.forEach(function (c) {
      var b = h('button', { type: 'button', text: c });
      b.addEventListener('click', function () { $('ask-target').value = c; ask(); });
      chips.appendChild(b);
    });
    $('ask-btn').addEventListener('click', ask);
    $('ask-target').addEventListener('keydown', function (ev) { if (ev.key === 'Enter') ask(); });
    var typing = 0;
    $('policy-text').addEventListener('input', function () {
      clearTimeout(typing);
      typing = setTimeout(ask, 250);
    });
    $('policy-reset').addEventListener('click', function () {
      $('policy-text').value = D.files['agent-2.toml'];
      ask();
    });
  }

  function start() {
    wire();
    var m = /^#step-([1-6])$/.exec(location.hash);
    show(m ? Number(m[1]) : 1, false);
    if (!D) {
      setStatus('The recorded run is missing: data.exit.v1.js did not load.', true);
      return;
    }
    Object.keys(D.files).forEach(function (k) { files[k] = D.files[k]; });
    $('policy-text').value = D.files['agent-2.toml'];
    $('recorded-on').textContent = new Date(D.startUTC).toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric', timeZone: 'UTC' });
    $('run-secs').textContent = (D.end / 1000).toFixed(1);
    if (!window.VPNWExit || !window.WebAssembly) {
      setStatus('This browser cannot run the engine: it needs WebAssembly.', true);
      return;
    }
    window.VPNWExit.load().then(function (engine) {
      E = engine;
      $('engine-version').textContent = E.version;
      document.querySelectorAll('.v-exit').forEach(function (x) { x.textContent = E.version; });
      document.querySelectorAll('.v-agent').forEach(function (x) { x.textContent = E.agentVersion; });
      var j = E.join(D.records['agent-1.jsonl'] + D.records['agent-2.jsonl'], D.records['exit-de.jsonl'] + D.records['exit-nl.jsonl']);
      setStatus('Exit ' + E.version + ' is running in this page. It read both exits\' configuration and joined the recorded records: ' +
        j.joined + ' of ' + j.via_exit + ' connections that reached an exit.');
      document.documentElement.setAttribute('data-ready', '1');
      show(step, false);
    }).catch(function (err) {
      setStatus('The engine could not start: ' + (err && err.message ? err.message : err), true);
    });
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start);
  else start();
})();
