// app.js: rendering only. Takes the analyze() result and writes the page.
// No parsing logic lives here; every value comes from the result object,
// and every value with a src can light its raw lines.
(function () {
  'use strict';
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s === null || s === undefined ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const fmtDur = HA.received.fmtDur;

  // Delay bands, upper bounds in seconds. The colors are the --delay-*
  // tokens in page.html. Tune both against real mail.
  const DELAY_BANDS = [[2, 'neutral'], [60, 'info'], [600, 'warn'], [Infinity, 'fail']];
  const band = (sec) => DELAY_BANDS.find(b => sec < b[0])[1];
  // Bars run on a log scale so a 2 second hop still shows next to a 2 hour one.
  const barPct = (sec, max) => sec > 0 && max > 0 ? Math.max(2, Math.round(Math.log1p(sec) / Math.log1p(max) * 100)) : 0;
  const bar = (sec, max) => '<div class="bar" aria-hidden="true"><i class="d-' + band(Math.max(0, sec)) + '" style="width:' + barPct(sec, max) + '%"></i></div>';

  const STATES = { pass: ['✓', 'Pass'], caveat: ['!', 'Caveat'], fail: ['✕', 'Fail'], unknown: ['?', 'Unknown'], info: ['i', 'Info'] };
  // Filter items carry a level; each maps to a chip class and its word.
  const LEVELS = { pass: ['pass', 'Pass'], info: ['info', 'Info'], warn: ['caveat', 'Warn'], fail: ['fail', 'Fail'] };
  const STATUS_WORD = { pass: 'Passed', fail: 'Failed', forwarded: 'Broken by a forward', none: 'No DMARC policy', error: 'DMARC error', unknown: 'Cannot judge' };
  const FORMATS = { 'gmail-original': 'a Gmail Show original copy', 'outlook-headers': 'Outlook Internet headers', eml: 'a full message (.eml)', bare: 'a header block' };

  let R = null;
  let sample = '';
  // Plain first: the headline has to make sense to the person who owns the
  // domain. The technical line sits under it either way. Nothing is stored.
  let voice = 'plain';

  // State chip: symbol and word carry the state, color repeats it.
  function chip(state, label) {
    const s = STATES[state] || STATES.unknown;
    const word = label || s[1];
    const sr = label && label !== s[1] ? '<span class="sr-only">' + s[1] + ': </span>' : '';
    return '<span class="st ' + state + '"><span class="sym" aria-hidden="true">' + s[0] + '</span>' + sr + esc(word) + '</span>';
  }

  function linesOf(src) {
    const ls = [];
    for (const i of src || []) { const f = R.fields[i]; if (f) ls.push(f.lines[0] + 1, f.lines[1] + 1); }
    if (!ls.length) return '';
    const lo = Math.min.apply(null, ls), hi = Math.max.apply(null, ls);
    return lo === hi ? 'L' + lo : 'L' + lo + ' to ' + hi;
  }
  function srcAttr(src) { return ' data-src="' + esc((src || []).join(',')) + '"'; }
  function srcBtn(src) {
    if (!src || !src.length) return '';
    const names = Array.from(new Set(src.map(i => R.fields[i] && R.fields[i].name))).join(', ');
    return '<button type="button" class="src"' + srcAttr(src) + ' aria-label="Show source lines: ' + esc(names) + ', ' + linesOf(src) + '">' + linesOf(src) + '</button>';
  }
  function prov(src, html) {
    if (!src || !src.length) return html;
    return '<button type="button" class="prov"' + srcAttr(src) + ' title="Show the raw lines this came from">' + html + '</button>';
  }

  function says(list) {
    if (!list || !list.length) return '';
    return '<ul class="says">' + list.map(s => '<li class="say">' + chip(s.state) + '<span class="txt">' + esc(s[voice]) + srcBtn(s.src) + '</span></li>').join('') + '</ul>';
  }

  function fmtUtc(ms) {
    if (ms === null || ms === undefined) return '';
    return new Date(ms).toISOString().replace('T', ' ').replace(/\.\d{3}Z$/, ' UTC');
  }

  const cap = (x) => x ? x.charAt(0).toUpperCase() + x.slice(1) : '';
  const RANK = { pass: 0, caveat: 1, fail: 2, unknown: 3 };

  // The four checks at a glance. Each tile reads values already in the
  // result; none of them decides anything the finding does not.
  function tiles() {
    const rows = R.alignment.rows;
    const plain = voice === 'plain';
    const idWord = (x) => !x || x.absent ? 'Not recorded' : x.state === 'pass' ? (plain ? 'Passed' : 'Pass, aligned') : x.state === 'caveat' ? (plain ? 'Passed for another domain' : 'Pass, not aligned') : x.result ? cap(x.result) : 'Not reported';
    const idState = (x) => !x || x.absent ? 'unknown' : x.state;
    const spf = rows.find(x => x.kind === 'spf');
    const dkims = rows.filter(x => x.kind === 'dkim' && !x.absent).sort((a, b) => RANK[a.state] - RANK[b.state]);
    const dk = dkims[0];
    const out = [];
    out.push({ k: 'SPF', q: 'Was the sending server allowed?', state: idState(spf), v: idWord(spf), d: spf && !spf.absent ? (plain ? 'checked ' : '') + spf.domain : '', jump: 'alignment' });
    out.push({ k: 'DKIM', q: 'Was it signed by the sender?', state: idState(dk), v: dk ? idWord(dk) : 'No signature', d: dk ? (plain ? 'signed by ' : 'd=') + dk.domain + (dkims.length > 1 ? ' and ' + (dkims.length - 1) + ' more' : '') : '', jump: 'alignment' });
    const d = R.auth.dmarc, c = R.auth.computed;
    if (d.reported) {
      const pol = d.policy.p ? (plain ? 'policy: ' : 'p=') + d.policy.p : d.policy.action ? (plain ? 'Microsoft action: ' : 'action=') + d.policy.action : '';
      const mismatch = c.result !== 'none' && c.result !== d.result ? 'computed here: ' + c.result : '';
      out.push({ k: 'DMARC', q: 'Does it pass as the From domain?', state: mismatch && d.state === 'pass' ? 'caveat' : d.state, v: plain ? ({ pass: 'Passed', fail: 'Failed', none: 'No DMARC setting' }[d.result] || cap(d.result)) : cap(d.result), d: [pol, mismatch].filter(Boolean).join(', '), jump: 'auth' });
    } else if (c.result === 'none') out.push({ k: 'DMARC', q: 'Does it pass as the From domain?', state: 'unknown', v: 'Not reported', d: '', jump: 'auth' });
    else out.push({ k: 'DMARC', q: 'Does it pass as the From domain?', state: c.result === 'pass' ? 'pass' : 'fail', v: cap(c.result), d: 'computed here; the receiver reported none', jump: 'auth' });
    // A forward the finding already blamed: say what passed before it, from
    // the first ARC set's results, so the tiles agree with the headline.
    if (R.finding.status === 'forwarded') {
      const first = (R.auth.arc.instances || []).find(x => x.i === 1);
      const before = first ? first.preForward : [];
      for (const t of out) {
        const m = t.k.toLowerCase();
        if (t.state !== 'pass' && before.some(x => x.method === m && x.state === 'pass')) {
          t.state = 'caveat';
          t.v = t.v + ' after the forward';
          t.d = 'passed before it' + (t.d ? '; ' + t.d : '');
        }
      }
    }
    const ch = R.chain;
    if (ch.totalSec !== null && ch.totalSec >= 0) {
      const b = band(ch.totalSec);
      out.push({ k: 'Delivery', q: 'How long did it take?', state: b === 'fail' ? 'fail' : b === 'warn' ? 'caveat' : 'pass', v: fmtDur(ch.totalSec), d: ch.count + ' hop' + (ch.count === 1 ? '' : 's') + (ch.trust.operator ? ', received by ' + ch.trust.operator : ''), jump: 'path' });
    } else out.push({ k: 'Delivery', q: 'How long did it take?', state: 'unknown', v: 'Unknown', d: ch.count + ' hop' + (ch.count === 1 ? '' : 's'), jump: 'path' });
    return out;
  }
  function tileHtml(t) {
    return '<button type="button" class="tile ' + t.state + '" data-jump="' + t.jump + '"><span class="tk">' + t.k + '</span><span class="tq">' + esc(t.q) + '</span>' +
      '<span class="tv"><span class="sym" aria-hidden="true">' + (STATES[t.state] || STATES.unknown)[0] + '</span>' + esc(t.v) + '</span>' + (t.d ? '<span class="td">' + esc(t.d) + '</span>' : '') + '</button>';
  }

  // The finding: the one sentence, the four checks, why and what the policy
  // did, what to do. The evidence and the limits fold away under it.
  function renderFinding() {
    const f = R.finding;
    const para = (s) => s ? '<p class="fpara">' + esc(s[voice]) + srcBtn(s.src) + '</p>' : '';
    $('finding').className = 'card finding s-' + f.state;
    let h = '<h2 id="h-finding">Finding</h2><div class="fhead">' + chip(f.state, STATUS_WORD[f.status]) +
      '<p class="headline">' + esc(f.headline[voice]) + srcBtn(f.headline.src) + '</p>' +
      '</div>';
    h += '<div class="tiles">' + tiles().map(tileHtml).join('') + '</div>';
    h += para(f.cause) + para(f.consequence);
    if (f.fixes.length) h += '<h3>What to do</h3><ol class="steps">' + f.fixes.map(x => '<li><span class="txt">' + esc(x[voice]) + srcBtn(x.src) + '</span></li>').join('') + '</ol>';
    if (f.flags.length) h += '<h3>Also worth knowing</h3>' + says(f.flags);
    const n = f.details.length + f.limits.length;
    if (n) {
      h += '<details class="more" id="finding-more"><summary>Evidence behind this finding <span class="count">' + n + ' item' + (n === 1 ? '' : 's') + '</span></summary>';
      if (f.details.length) h += '<h3>Details</h3>' + says(f.details);
      if (f.limits.length) h += '<h3>What these headers cannot show</h3>' + says(f.limits);
      h += '</details>';
    }
    $('finding').innerHTML = h;
  }

  // A plain text report for a ticket or an email to a client.
  function reportText() {
    const f = R.finding, m = R.message, L = ['Email Header Decoder report (beta)'];
    if (m.subject) L.push('Subject: ' + (m.subject.value || '(empty)'));
    if (m.from) L.push('From: ' + m.from.address);
    if (m.date) L.push('Date: ' + m.date.text);
    L.push('', STATUS_WORD[f.status] + ': ' + f.headline[voice]);
    if (voice === 'plain' && f.headline.technical !== f.headline.plain) L.push('Technical: ' + f.headline.technical);
    for (const s of [f.cause, f.consequence]) if (s) L.push(s[voice]);
    L.push('');
    for (const t of tiles()) L.push(t.k + ': ' + t.v + (t.d ? ' (' + t.d + ')' : ''));
    if (f.fixes.length) { L.push('', 'What to do:'); f.fixes.forEach(x => L.push('- ' + x[voice])); }
    if (f.limits.length) { L.push('', 'What these headers cannot show:'); f.limits.forEach(x => L.push('- ' + x[voice])); }
    L.push('', 'Decoded in the browser at headers.dns-audit.com. The headers were not sent anywhere.');
    return L.join('\n');
  }
  function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) return navigator.clipboard.writeText(text);
    const ta = document.createElement('textarea');
    ta.value = text; ta.setAttribute('readonly', ''); ta.style.position = 'fixed'; ta.style.opacity = '0';
    document.body.appendChild(ta); ta.select();
    const ok = document.execCommand('copy');
    ta.remove();
    return ok ? Promise.resolve() : Promise.reject(new Error('copy blocked'));
  }

  function itemRow(it) {
    const lv = LEVELS[it.level] || LEVELS.info;
    return '<li class="it"><div class="kv"><span class="k">' + esc(it.key) + '</span><span class="raw">' + esc(it.raw) + '</span></div>' +
      '<div class="txt">' + chip(lv[0], lv[1]) + '<span>' + esc(it[voice]) + '</span>' + srcBtn(it.src) + '</div></li>';
  }
  const items = (list) => '<ul class="items">' + list.map(itemRow).join('') + '</ul>';

  // Filter headers, then the sending platform, then list and sending headers.
  function renderFilters() {
    const d = R.decoded;
    let h = '<h2 id="h-filters">Filter headers <span class="count">' + d.filters.length + ' filter' + (d.filters.length === 1 ? '' : 's') + ' found</span></h2>';
    for (const g of d.filters) {
      h += '<div class="fgroup"><div class="arh"><span class="who">' + esc(g.name) + '</span>' +
        (g.side === 'before-custody' ? chip('caveat', 'Before custody') : g.side === 'receiver' ? chip('pass', 'Receiver') : '') + srcBtn(g.src) + '</div>';
      if (g.items.length) h += items(g.items);
      if (g.note) h += says([g.note]);
      h += '</div>';
    }
    h += says(d.notes);
    const p = d.platform;
    h += '<h3>Sending platform' + (p.name ? ' <span class="count">' + esc(p.confidence) + ' confidence</span>' : '') + '</h3>' + says([p.statement]);
    if (p.mailer) h += '<p class="raw-line"><span class="lbl">' + esc(p.mailer.name) + ':</span> <span class="mono">' + prov(p.mailer.src, esc(p.mailer.value)) + '</span> <span class="absent">the sender\'s own software label, not verified</span></p>';
    h += '<h3>List and sending headers</h3>' + (d.list.length ? items(d.list) : '<p class="absent">No unsubscribe, list, Reply-To, Sender, Precedence, Auto-Submitted or Feedback-ID fields that say something here.</p>');
    $('filters').innerHTML = h;
  }

  function renderMessage() {
    const m = R.message;
    const row = (label, html) => '<dt>' + esc(label) + '</dt><dd>' + html + '</dd>';
    const absent = (what) => chip('unknown', 'Absent') + ' <span class="absent">' + esc(what) + '</span>';
    let rows = '';
    if (m.from) {
      const who = m.from.display ? esc(m.from.display) + ' <span class="sub mono">&lt;' + esc(m.from.address) + '&gt;</span>' : '<span class="mono">' + esc(m.from.address) + '</span>';
      rows += row('From', prov(m.from.src, who) + (m.fromCount > 1 ? ' ' + chip('fail', m.fromCount + ' From fields') : ''));
    } else rows += row('From', absent('No From field in these headers.'));
    const addrList = (x) => esc(x.addresses.map(a => a.display ? a.display + ' <' + a.address + '>' : a.address).join(', ') || x.text);
    if (m.replyTo) rows += row('Reply-To', prov(m.replyTo.src, addrList(m.replyTo)));
    rows += row('To', m.to ? prov(m.to.src, esc(m.to.addresses.map(a => a.display ? a.display + ' <' + a.address + '>' : a.address).join(', ') || m.to.text)) : absent('No To field in these headers.'));
    rows += row('Subject', m.subject ? prov(m.subject.src, esc(m.subject.value || '(empty)')) : absent('No Subject field in these headers.'));
    if (m.date) {
      const utc = m.date.time !== null ? '<span class="sub mono">' + esc(fmtUtc(m.date.time)) + '</span>' : '';
      rows += row('Date', prov(m.date.src, esc(m.date.text)) + utc + (m.date.time === null ? ' ' + chip('unknown', 'Unreadable') : !m.date.tzKnown ? ' ' + chip('caveat', 'Zone unknown') : ''));
    } else rows += row('Date', absent('No Date field in these headers.'));
    rows += row('Message-ID', m.messageId ? prov(m.messageId.src, '<span class="mono">' + esc(m.messageId.value) + '</span>') : absent('No Message-ID field in these headers.'));
    if (m.returnPath) rows += row('Return-Path domain', prov(m.returnPath.src, m.returnPath.empty ? '<span class="mono">&lt;&gt;</span> <span class="sub">empty, the null sender that bounces use</span>' : '<span class="mono">' + esc(m.returnPath.domain || m.returnPath.address) + '</span>'));
    else rows += row('Return-Path domain', absent('No Return-Path field. The receiving server adds it at delivery, so a sent copy has none.'));
    $('message').innerHTML = '<h2 id="h-message">Message</h2><dl class="meta">' + rows + '</dl>' + says(m.notes);
  }

  // Alignment picture: the From domain in the middle, DKIM d= on one
  // side, the SPF domain on the other, each connector styled by state.
  function alignNode(x) {
    let inner = '<span class="k">' + (x.kind === 'dkim' ? 'DKIM signing domain' : 'SPF domain') + '</span>';
    if (x.absent) inner += '<span class="d absent">' + (x.kind === 'dkim' ? 'No DKIM signature' : 'No SPF domain') + '</span>';
    else {
      inner += '<span class="d mono">' + esc(x.domain) + '</span>';
      const sub = [];
      if (x.kind === 'dkim' && x.selector) sub.push('s=' + esc(x.selector));
      if (x.kind === 'spf' && x.identity) sub.push('from ' + esc(x.identity));
      if (sub.length) inner += '<span class="sub mono">' + sub.join(' · ') + '</span>';
      inner += '<span class="res">' + chip(HA.auth.resultState(x.result), x.result ? x.kind + '=' + x.result : 'Not reported') + '</span>';
    }
    return '<div class="anode">' + prov(x.src, inner) + '</div>';
  }
  function connector(x) {
    const state = x.absent ? 'unknown' : x.state;
    const word = x.absent ? 'Absent' : x.word;
    return '<div class="conn ' + state + '"><span class="wire" aria-hidden="true"></span>' + chip(state, word) + '</div>';
  }
  function renderAlignment() {
    const a = R.alignment;
    const f = a.from;
    const dkim = a.rows.filter(x => x.kind === 'dkim');
    const spf = a.rows.find(x => x.kind === 'spf');
    const st = (x) => x.absent ? 'unknown' : x.state;
    const left = (dkim.length ? dkim : [{ kind: 'dkim', absent: true, src: [] }]).map(x => '<div class="arow ' + st(x) + '">' + alignNode(x) + connector(x) + '</div>').join('');
    const right = '<div class="arow ' + st(spf) + '">' + connector(spf) + alignNode(spf) + '</div>';
    const showOrg = f.domain && a.rows.some(x => x.state === 'pass' && x.relaxedOnly);
    let center = '<span class="k">From domain</span>';
    if (f.domain) {
      center += '<span class="d mono">' + esc(f.domain) + '</span>';
      if (showOrg) center += '<span class="org">organizational domain <span class="mono">' + esc(f.org) + '</span>' + (f.approximate ? ' ' + chip('caveat', 'Approximate') : '') + '</span>';
      else if (f.approximate) center += '<span class="org">' + chip('caveat', 'Approximate') + ' organizational domain</span>';
    } else center += '<span class="d absent">No From domain</span>';
    let h = '<h2 id="h-alignment">Alignment <span class="count">recomputed from the identifiers, not copied from the receiver</span></h2>';
    h += '<div class="apic' + (dkim.length > 1 ? ' multi' : '') + '"><div class="aside left">' + left + '</div><div class="acenter"><div class="anode from">' + prov(f.src, center) + '</div></div><div class="aside right">' + right + '</div></div>';
    h += '<p class="legend"><span class="lg pass">aligned</span><span class="lg caveat">passed, not aligned</span><span class="lg fail">failed</span><span class="lg unknown">absent or not reported</span></p>';
    h += says(a.notes);
    $('alignment').innerHTML = h;
  }

  const TRUST = { receiver: ['pass', 'Receiver'], 'sender-side': ['unknown', 'Before custody'], unverified: ['unknown', 'Unverified'] };
  const MATCHED = { host: 'named as a Received by host', operator: 'same operator as a receiving hop', position: 'no authserv-id; tied by position' };
  function idText(e) {
    return Object.keys(e.ids).map(k => k + '=' + e.ids[k]).join(' ');
  }
  function arBlock(rec) {
    const t = TRUST[rec.trust];
    let h = '<div class="arf' + (rec.primary ? ' primary' : '') + (rec.trust === 'unverified' ? ' unverified' : '') + '"><div class="arh">' +
      '<span class="who mono">' + esc(rec.writer || '(no host named)') + '</span>' +
      (rec.primary ? '<span class="badge">Primary</span>' : '') + chip(t[0], t[1]) +
      '<span class="how">' + esc(rec.matchedBy ? MATCHED[rec.matchedBy] + (rec.hopIdx >= 0 ? ', hop ' + (rec.hopIdx + 1) : '') : 'no Received by host matches') + '</span>' + srcBtn(rec.src) + '</div>';
    if (!rec.entries.length) h += '<p class="absent">' + (rec.none ? 'Reports none: no methods were checked.' : 'No method results could be read.') + '</p>';
    else h += '<div class="ents">' + rec.entries.map(e => '<div class="ent"><span class="m">' + esc(e.method) + '</span>' + chip(e.state, e.result) +
      '<span class="id mono">' + esc(idText(e) || 'no identifiers') + '</span>' + (e.reason ? '<span class="why">reason ' + esc(e.reason) + '</span>' : '') + '</div>').join('') + '</div>';
    return h + '</div>';
  }
  function cvState(set) { return (set.i === 1 && set.cv === 'none') || (set.i > 1 && set.cv === 'pass') ? 'pass' : set.cv ? 'fail' : 'unknown'; }
  function renderAuth() {
    const a = R.auth;
    let h = '<h2 id="h-auth">Authentication</h2>';
    // Authentication-Results, the primary first, the rest in header order.
    h += '<h3>Authentication-Results <span class="count">' + a.all.length + ' field' + (a.all.length === 1 ? '' : 's') + '</span></h3>';
    if (a.all.length) {
      const order = a.all.filter(r => r.primary).concat(a.all.filter(r => !r.primary));
      h += order.map(arBlock).join('');
    } else h += '<p class="absent">' + chip('unknown', 'Absent') + ' No Authentication-Results field in these headers.</p>';
    if (a.receivedSpf.length) {
      h += '<div class="arf"><div class="arh"><span class="who">Received-SPF</span>' + srcBtn(a.receivedSpf.flatMap(x => x.src)) + '</div><div class="ents">' +
        a.receivedSpf.map(x => '<div class="ent"><span class="m">spf</span>' + chip(HA.auth.resultState(x.result), x.result || 'unreadable') + '<span class="id mono">' +
          esc(['client-ip', 'envelope-from', 'helo', 'receiver'].filter(k => x.props[k]).map(k => k + '=' + x.props[k]).join(' ') || 'no details') + '</span></div>').join('') + '</div></div>';
    }
    // ARC chain, one row per instance.
    const arc = a.arc;
    h += '<h3>ARC chain <span class="count">' + (arc.present ? arc.instances.length + ' set' + (arc.instances.length === 1 ? '' : 's') : 'none') + '</span></h3>';
    if (arc.present) {
      h += '<ol class="arc">' + arc.instances.map(set => '<li><span class="i mono">i=' + set.i + '</span><div class="body"><div class="arh">' +
        '<span class="who mono">' + esc(set.sealer.domain || '(no d=)') + '</span>' + (set.sealer.host ? '<span class="how">at ' + esc(set.sealer.host) + (set.hopIdx >= 0 ? ', hop ' + (set.hopIdx + 1) : ', not in the Received chain') + '</span>' : '') +
        chip(cvState(set), 'cv=' + (set.cv || 'missing')) + srcBtn(set.src) + '</div>' +
        '<div class="pre"><span class="lbl">Before this hop:</span>' + (set.preForward.length ? set.preForward.map(x => chip(x.state, x.method + '=' + x.result)).join('') : '<span class="absent">no ARC-Authentication-Results</span>') + '</div></div></li>').join('') + '</ol>';
      h += '<p class="arc-sum">' + chip(arc.state === 'pass' ? 'pass' : 'fail', arc.state === 'pass' ? 'Chain intact' : 'Chain broken') +
        (a.arcResult ? ' <span>receiver reported</span> ' + chip(HA.auth.resultState(a.arcResult.result), 'arc=' + a.arcResult.result) + srcBtn(a.arcResult.src) : ' <span class="absent">the receiver reported no arc= result</span>') + '</p>';
    } else if (a.arcResult) {
      h += '<p class="arc-sum"><span>No ARC set; receiver reported</span> ' + chip(HA.auth.resultState(a.arcResult.result), 'arc=' + a.arcResult.result) + srcBtn(a.arcResult.src) + '</p>';
    } else h += '<p class="absent">No ARC headers. The message carries no record of being forwarded.</p>';
    // Reported DMARC beside computed DMARC.
    const d = a.dmarc, c = a.computed;
    h += '<h3>DMARC</h3><div class="dm">';
    let rep = '<span class="k">Reported by the receiver</span>';
    if (d.reported) {
      const pol = [d.policy.p && 'p=' + d.policy.p, d.policy.sp && 'sp=' + d.policy.sp, d.policy.dis && 'dis=' + d.policy.dis, d.policy.action && 'action=' + d.policy.action].filter(Boolean).join(' ');
      rep += chip(d.state, 'dmarc=' + d.result) + (d.headerFrom ? '<span class="sub mono">header.from=' + esc(d.headerFrom) + '</span>' : '') + (pol ? '<span class="sub mono">' + esc(pol) + '</span>' : '') + srcBtn(d.src);
    } else rep += chip('unknown', 'Not reported') + '<span class="sub">No dmarc= result in the receiver\'s Authentication-Results.</span>';
    let cmp = '<span class="k">Computed here</span>';
    const NONE_WHY = { 'no-from': 'There is no From domain to align with.', 'two-from': 'There is more than one From field, so there is no single domain to align with.', 'multi-domain': 'The From field names addresses in more than one domain, so there is no single domain to align with.', 'no-trusted-results': 'No Authentication-Results field here was written by the receiver.' };
    if (c.result === 'none') cmp += chip('unknown', 'Cannot compute') + '<span class="sub">' + (NONE_WHY[c.why] || 'The receiver reported no SPF or DKIM results to combine.') + '</span>';
    else if (c.differ) cmp += '<span class="modes">' + chip('pass', 'relaxed: pass') + chip('fail', 'strict: fail') + '</span><span class="sub">The DMARC record decides: ' + esc(c.tags.join(' and ')) + ' (relaxed when absent).</span>' + srcBtn(c.src);
    else cmp += chip(c.result, 'dmarc=' + c.result) + '<span class="sub">' + (c.result === 'pass' ? 'Aligned pass from ' + esc((c.by.strict.length ? c.by.strict : c.by.relaxed).join(', ')) + '.' : 'No method that passed aligns with the From domain.') + '</span>' + srcBtn(c.src);
    h += '<div class="dmt">' + rep + '</div><div class="dmt">' + cmp + '</div></div>';
    if (d.disagreement) h += says([d.disagreement]);
    if (a.compauth) h += '<p class="raw-line"><span class="lbl">Microsoft compauth, raw:</span> <span class="mono">' + prov(a.compauth.src, esc(a.compauth.raw)) + '</span> <span class="absent">The reason code is decoded under Filter headers.</span></p>';
    const shown = (n) => (d.disagreement && n.technical === d.disagreement.technical) || /^Microsoft composite authentication/.test(n.technical);
    h += says(a.notes.filter(n => !shown(n)));
    $('auth').innerHTML = h;
  }

  // The protocol chip carries the TLS version when the stamp records one.
  // With no evidence it says so; the page does not claim the hop was plain.
  function tlsChip(h) {
    const proto = h.protocol ? h.protocol + ' ' : '';
    if (h.tls.state === 'pass' || h.tls.state === 'caveat') return chip(h.tls.state, proto + h.tls.label);
    if (h.tls.state === 'fail') return chip('fail', proto + 'plain');
    return chip('unknown', h.tls.label === 'No connection' ? 'No connection' : 'TLS not recorded');
  }

  function hopRow(h, maxDelay, numberLabel) {
    const from = h.from ? esc(h.fromHost || '(unnamed)') + (h.fromIp && h.fromHost.indexOf(h.fromIp) === -1 ? ' <span class="ip">' + esc(h.fromIp) + '</span>' : '') +
      (h.fromIp && HA.received.isPrivateIp(h.fromIp) ? ' <span class="tag">private</span>' : '') : '<span class="ip">(handoff inside the server)</span>';
    const route = from + '<span class="arrow" aria-label="to">→</span>' + esc(h.byHost || '(unnamed)');
    const facts = [];
    facts.push(tlsChip(h));
    if (h.authenticated) facts.push(chip('pass', 'Authenticated'));
    // The stated HELO name, when it says something the route line does not.
    const norm = (x) => (x || '').toLowerCase().replace(/\.$/, '');
    if (h.helo && norm(h.helo) !== norm(h.fromHost) || h.helo && h.rdns && norm(h.helo) !== norm(h.rdns)) {
      facts.push('<span>said HELO <span class="mono">' + esc(h.helo) + '</span>' + (h.rdns && norm(h.rdns) !== norm(h.helo) ? ', reverse DNS <span class="mono">' + esc(h.rdns) + '</span>' : '') + '</span>');
    }
    if (h.internal) facts.push('<span title="' + esc(h.internalReason) + '">internal</span>');
    if (h.time !== null) facts.push('<span class="time">' + esc(fmtUtc(h.time)) + (h.tzKnown ? '' : ' (zone unknown)') + '</span>');
    else facts.push(chip('unknown', 'No readable date'));
    facts.push(srcBtn(h.src));
    let delay = '';
    if (h.delaySec !== null) {
      // Clock skew shows as 0s with a chip, never as a negative bar.
      delay = '<div class="delay">' + bar(h.skew ? 0 : h.delaySec, maxDelay) + '<span class="val">' + esc(fmtDur(h.skew ? 0 : h.delaySec)) + '</span></div>';
      if (h.skew) delay += '<div class="facts">' + chip('caveat', 'Clock skew') + '<span>stamped ' + esc(fmtDur(-h.delaySec)) + ' earlier than the hop before it</span></div>';
    } else if (h.index === 0) delay = '<div class="facts"><span class="absent">First stamp, so no delay to measure.</span></div>';
    const forgeable = R.chain.trust.boundaryIdx > h.index;
    return '<li class="hop' + (h.slowest ? ' slowest' : '') + (forgeable ? ' sender-side' : '') + '"><span class="n">' + numberLabel + '</span><div class="body">' +
      '<div class="route">' + prov(h.src, route) + (h.slowest ? ' <span class="slow-word">slowest</span>' : '') + '</div>' +
      '<div class="facts">' + facts.join('') + '</div>' + delay + '</div></li>';
  }

  // The trust line: where the receiver took custody. Hops above it were
  // written by the sender's side.
  function trustRow(c) {
    const t = c.trust;
    const origin = t.originPrivate
      ? '<span>inside ' + esc(t.operator) + '\'s own network' + (t.originIp ? ', from private address <span class="mono">' + esc(t.originIp) + '</span>' : '') + '</span>'
      : '<span>' + esc(t.operator) + ' took it from <span class="mono ip-o">' + esc(t.originIp || 'an unrecorded address') + '</span>' + (t.originHelo ? ' <span class="sub">which called itself <span class="mono">' + esc(t.originHelo) + '</span></span>' : '') + '</span>';
    const above = t.boundaryIdx ? '<span class="sub">Above this line: ' + t.boundaryIdx + ' hop' + (t.boundaryIdx === 1 ? '' : 's') + ' written by the sender\'s side, which can be forged.</span>' : '';
    return '<li class="trust" aria-label="Trust line"><span class="tl" aria-hidden="true"></span><div class="tt"><strong>Receiver took custody here</strong>' + origin + srcBtn(t.src) + above + '</div></li>';
  }

  function renderPath() {
    const c = R.chain;
    const slow = c.slowestIdx >= 0 ? ', slowest is hop ' + (c.slowestIdx + 1) + ' at ' + fmtDur(c.hops[c.slowestIdx].delaySec) : '';
    const total = c.totalSec !== null && c.totalSec >= 0 ? ', ' + fmtDur(c.totalSec) + ' end to end' : '';
    let h = '<h2 id="h-path">Path <span class="count">' + c.count + ' hop' + (c.count === 1 ? '' : 's') + ' oldest first' + total + slow + '</span></h2>';
    if (!c.count) { $('path').innerHTML = h + says(c.notes); return; }
    const maxDelay = Math.max.apply(null, [0].concat(c.hops.map(x => x.delaySec || 0), c.groups.map(g => g.delaySec || 0)));
    h += '<div class="summary"><span class="big">' + (c.totalSec !== null && c.totalSec >= 0 ? esc(fmtDur(c.totalSec)) : 'Unknown') + '</span><span class="lbl">end to end, ' + c.count + ' hop' + (c.count === 1 ? '' : 's') + '</span>' +
      (c.clockSkew ? chip('caveat', 'Clock skew') : '') + (c.trust.boundaryIdx >= 0 && !c.trust.originPrivate && c.originIp ? '<span class="lbl">origin <span class="mono">' + esc(c.originIp) + '</span></span>' : '') + '</div>';
    h += '<ol class="hops">';
    const t = c.trust;
    for (const g of c.groups) {
      if (t.boundaryIdx >= 0 && g.hops.includes(t.boundaryIdx)) h += trustRow(c);
      if (g.kind === 'hop') { h += hopRow(c.hops[g.hops[0]], maxDelay, String(g.hops[0] + 1)); continue; }
      const hs = g.hops.map(i => c.hops[i]);
      const states = hs.map(x => x.tls.state);
      const worst = ['fail', 'caveat', 'unknown', 'pass'].find(s => states.includes(s));
      const slow = hs.some(x => x.slowest);
      h += '<li class="hop group' + (slow ? ' slowest' : '') + '"><span class="n">' + (g.hops[0] + 1) + ' to ' + (g.hops[g.hops.length - 1] + 1) + '</span><div class="body"><details data-group="' + g.hops[0] + '"><summary>' +
        '<span class="grp-title">' + hs.length + ' internal hops inside ' + esc(g.operator) + (slow ? ' <span class="slow-word">slowest</span>' : '') + ' <span class="chev"><span class="closed">Show hops</span><span class="open">Hide hops</span></span></span>' +
        '<span class="facts">' + chip(worst, worst === 'pass' ? 'TLS on every hop' : worst === 'unknown' ? 'TLS not recorded on every hop' : worst === 'caveat' ? 'TLS with caveats' : 'Plain on a hop') + srcBtn(g.src) + '</span>' +
        (g.delaySec !== null ? '<span class="delay">' + bar(g.delaySec, maxDelay).replace(/div/g, 'span') + '<span class="val">' + esc(fmtDur(Math.max(0, g.delaySec))) + '</span></span>' : '') +
        '</summary><ol class="inner">' + hs.map(x => hopRow(x, maxDelay, String(x.index + 1))).join('') + '</ol></details></div></li>';
    }
    h += '</ol>';
    h += says(c.notes);
    if (t.boundaryIdx > 0) h = h.replace('<ol class="hops">', '<ol class="hops has-trust">');
    h += '<p class="note-line">A delay is the time between the previous stamp and this one. Hops inside one operator (mapi, private addresses, two hosts of one company) are grouped; open a group to see each hop.</p>';
    $('path').innerHTML = h;
  }

  function renderRaw() {
    const fields = R.fields;
    const b = R.input.block;
    let h = '<details class="raw" id="raw-details"><summary>Raw headers <span class="count">' + fields.length + ' field' + (fields.length === 1 ? '' : 's') + (b ? ', lines ' + (b[0] + 1) + ' to ' + (b[1] + 1) + ' of the paste' : '') + '</span></summary>' +
      '<div class="raw-tools"><label class="sr-only" for="raw-filter">Search the headers</label><input id="raw-filter" type="search" placeholder="Search names and values" autocomplete="off"><button class="btn" type="button" id="raw-clear-hl">Clear highlight</button><span class="status" id="raw-status"></span></div>' +
      '<div class="rawbox" id="rawbox"></div></details>';
    if (R.input.bodyPresent) h += '<p class="note-line">A message body followed the headers. It was not read.</p>';
    $('raw').innerHTML = h;
    drawRaw('');
    $('raw-filter').addEventListener('input', (e) => drawRaw(e.target.value));
    $('raw-clear-hl').addEventListener('click', () => highlight([]));
  }

  let lit = [];
  function drawRaw(q) {
    q = (q || '').trim().toLowerCase();
    const mark = (t) => { if (!q) return esc(t); const i = t.toLowerCase().indexOf(q); return i < 0 ? esc(t) : esc(t.slice(0, i)) + '<mark>' + esc(t.slice(i, i + q.length)) + '</mark>' + esc(t.slice(i + q.length)); };
    const shown = R.fields.filter(f => !q || f.raw.toLowerCase().includes(q));
    $('rawbox').innerHTML = shown.map(f => '<div class="f' + (lit.includes(f.index) ? ' hl' : '') + '" data-field="' + f.index + '">' + f.raw.split('\n').map((t, k) => {
      const body = k === 0 ? '<span class="nm">' + mark(t.slice(0, f.name.length + 1)) + '</span>' + mark(t.slice(f.name.length + 1)) : mark(t);
      return '<div class="l"><span class="ln">' + (f.lines[0] + k + 1) + '</span><span class="tx">' + body + '</span></div>';
    }).join('') + '</div>').join('') || '<p class="empty-raw">No header matches that search.</p>';
    $('raw-status').textContent = q ? shown.length + ' of ' + R.fields.length + ' fields match' : '';
  }

  function highlight(src) {
    lit = src.slice();
    document.querySelectorAll('.prov.on, .src.on').forEach(el => el.classList.remove('on'));
    document.querySelectorAll('#rawbox .f').forEach(el => el.classList.toggle('hl', lit.includes(+el.dataset.field)));
    if (!lit.length) { $('live').textContent = 'Highlight cleared.'; return; }
    $('analysis').open = true;
    const det = $('raw-details');
    det.open = true;
    const filter = $('raw-filter');
    if (filter.value && !lit.every(i => document.querySelector('#rawbox .f[data-field="' + i + '"]'))) { filter.value = ''; drawRaw(''); }
    const firstEl = document.querySelector('#rawbox .f[data-field="' + Math.min.apply(null, lit) + '"]');
    if (firstEl) firstEl.scrollIntoView({ behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth', block: 'center' });
    const names = lit.map(i => R.fields[i].name + ' (' + linesOf([i]) + ')');
    $('live').textContent = 'Highlighted ' + names.join(', ') + ' in the raw headers.';
  }

  document.addEventListener('click', (e) => {
    const jump = e.target.closest('[data-jump]');
    if (jump && R) { if ($('analysis').contains($(jump.dataset.jump))) $('analysis').open = true; $(jump.dataset.jump).scrollIntoView({ behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth', block: 'start' }); return; }
    const el = e.target.closest('[data-src]');
    if (!el || !R) return;
    if (el.closest('summary')) e.preventDefault(); // a source button inside a group row should not also toggle it
    const src = el.dataset.src.split(',').filter(Boolean).map(Number);
    highlight(src);
    el.classList.add('on');
  });

  function setVoice(v) {
    voice = v;
    document.body.dataset.voice = v;
    document.querySelectorAll('[data-voice]').forEach(b => b.setAttribute('aria-pressed', String(b.dataset.voice === v)));
    if (R) renderAll();
  }

  function renderAll() {
    const open = $('raw-details') && $('raw-details').open;
    const moreOpen = $('finding-more') && $('finding-more').open;
    const openGroups = Array.from(document.querySelectorAll('#path details[open]')).map(d => d.dataset.group);
    // One line above the cards: what the paste was read as.
    const c = R.chain;
    const parts = [R.fields.length + ' field' + (R.fields.length === 1 ? '' : 's'), c.count + ' hop' + (c.count === 1 ? '' : 's')];
    if (c.totalSec !== null && c.totalSec >= 0) parts.push('transit ' + fmtDur(c.totalSec));
    if (c.originIp && !c.trust.originPrivate) parts.push('origin ' + c.originIp);
    if (voice === 'plain') $('read-as').textContent = (sample ? 'Sample: ' + sample + '. ' : '') + 'Read ' + R.fields.length + ' header' + (R.fields.length === 1 ? '' : 's') + ' and ' + c.count + ' hop' + (c.count === 1 ? '' : 's') + '.';
    else $('read-as').textContent = (sample ? 'Sample: ' + sample + '. ' : '') + 'Read as ' + (FORMATS[R.input.format] || 'a header block') + ': ' + parts.join(', ') + '.' + (R.input.repairedLines ? ' ' + R.input.repairedLines + (R.input.repairedLines === 1 ? ' line had lost its indentation and was rejoined.' : ' lines had lost their indentation and were rejoined.') : '');
    renderFinding();
    renderFilters();
    renderMessage();
    renderAlignment();
    renderAuth();
    renderPath();
    renderRaw();
    if (R.input.notes.length) $('raw').insertAdjacentHTML('beforeend', says(R.input.notes));
    if (open) $('raw-details').open = true;
    if (moreOpen && $('finding-more')) $('finding-more').open = true;
    openGroups.forEach(g => { const d = document.querySelector('#path details[data-group="' + g + '"]'); if (d) d.open = true; });
    if (lit.length) highlight(lit);
  }

  function run(scroll) {
    const text = $('headers').value;
    if (!text.trim()) { $('results').hidden = true; R = null; return; }
    lit = [];
    try { R = HA.analyze(text); } catch (e) {
      // Never leave the previous result on screen for a paste that failed.
      R = null;
      $('results').hidden = false;
      $('read-as').textContent = '';
      $('finding').innerHTML = '<h2 id="h-finding">Could not read these headers</h2><p>Something in this paste stopped the page from reading it. Nothing was sent anywhere.</p>';
      ['filters', 'message', 'alignment', 'auth', 'path', 'raw'].forEach(id => { $(id).innerHTML = ''; $(id).hidden = true; });
      return;
    }
    $('results').hidden = false;
    if (!R.input.blockFound) {
      $('read-as').textContent = '';
      $('finding').innerHTML = '<h2 id="h-finding">Nothing to read</h2>' + says(R.input.notes);
      ['filters', 'message', 'alignment', 'auth', 'path', 'raw'].forEach(id => { $(id).innerHTML = ''; $(id).hidden = true; });
      return;
    }
    ['filters', 'message', 'alignment', 'auth', 'path', 'raw'].forEach(id => { $(id).hidden = false; });
    renderAll();
    if (scroll) $('results').scrollIntoView({ behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth', block: 'start' });
  }

  $('go').addEventListener('click', () => run(true));
  $('copy-report').addEventListener('click', () => {
    if (!R || !R.input.blockFound) return;
    const b = $('copy-report');
    copyText(reportText()).then(() => { b.textContent = 'Copied'; b.classList.add('done'); $('live').textContent = 'Report copied.'; },
      () => { b.textContent = 'Copy blocked'; $('live').textContent = 'The browser blocked the copy.'; });
    setTimeout(() => { b.textContent = 'Copy report'; b.classList.remove('done'); }, 2000);
  });
  $('clear').addEventListener('click', () => { $('headers').value = ''; sample = ''; run(false); $('headers').focus(); });
  const loadSample = (key, scroll) => {
    const b = document.querySelector('[data-sample="' + key + '"]');
    $('headers').value = window.SAMPLES[key];
    sample = b ? b.textContent : key;
    run(scroll);
  };
  document.querySelectorAll('[data-sample]').forEach(b => b.addEventListener('click', () => loadSample(b.dataset.sample, true)));
  $('headers').addEventListener('input', () => { sample = ''; });
  document.querySelectorAll('[data-voice]').forEach(b => b.addEventListener('click', () => setVoice(b.dataset.voice)));
  $('headers').addEventListener('paste', () => { sample = ''; setTimeout(() => run(true), 0); });
  $('headers').addEventListener('keydown', (e) => { if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') run(true); });

  const panel = $('input-panel');
  panel.addEventListener('dragover', (e) => { e.preventDefault(); panel.classList.add('drop'); });
  panel.addEventListener('dragleave', () => panel.classList.remove('drop'));
  panel.addEventListener('drop', (e) => {
    e.preventDefault(); panel.classList.remove('drop');
    const f = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
    if (!f) return;
    const reader = new FileReader();
    reader.onload = () => { $('headers').value = String(reader.result || ''); sample = ''; run(true); };
    reader.readAsText(f);
  });

  setVoice(voice);
  // A browser restoring form state can refill the box; read it if so.
  run(false);
})();
