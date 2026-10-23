// app.js: rendering only. Takes the analyze() result and writes the page.
// No parsing logic lives here; every value comes from the result object,
// and every value with a src can light its raw lines.
(function () {
  'use strict';
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s === null || s === undefined ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const fmtDur = HA.received.fmtDur;

  const STATES = { pass: ['✓', 'Pass'], caveat: ['!', 'Caveat'], fail: ['✕', 'Fail'], unknown: ['?', 'Unknown'] };
  const FORMATS = { 'gmail-original': 'a Gmail Show original copy', 'outlook-headers': 'Outlook Internet headers', eml: 'a full message (.eml)', bare: 'a header block' };
  const STEP_FILLS = {
    verdict: [3, 'Step 3 writes the verdict here: what failed and why in one sentence, with the fix, in technical and plain wording.'],
    filters: [3, 'Step 3 fills this: Microsoft, Google, Proofpoint and Mimecast filter verdicts decoded in one place.'],
  };
  const TITLES = { verdict: 'Verdict', alignment: 'Alignment', auth: 'Authentication', filters: 'Filter headers' };

  let R = null;
  let voice = 'technical';
  try { if (localStorage.getItem('hv-voice') === 'plain') voice = 'plain'; } catch (e) { /* storage blocked */ }

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
    return lo === hi ? 'L' + lo : 'L' + lo + '–' + hi;
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
    return '<ul class="says">' + list.map(s => '<li class="say">' + chip(s.state) + '<span class="txt">' + esc(s[voice]) + '</span>' + srcBtn(s.src) + '</li>').join('') + '</ul>';
  }

  function fmtUtc(ms) {
    if (ms === null || ms === undefined) return '';
    return new Date(ms).toISOString().replace('T', ' ').replace(/\.\d{3}Z$/, ' UTC');
  }

  function later(key) {
    const [step, text] = STEP_FILLS[key];
    return '<h2 id="h-' + key + '">' + TITLES[key] + '</h2><p class="later">' + chip('unknown', 'Step ' + step) + '<span>' + esc(text) + '</span></p>';
  }

  function renderVerdict() {
    let h = later('verdict');
    const fails = [].concat(R.message.notes, R.alignment.notes, R.auth.notes, R.chain.notes).filter(s => s.state === 'fail');
    if (fails.length) h += '<p class="note-line">Until then, these findings are marked as failures:</p>' + says(fails);
    $('verdict').innerHTML = h;
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
      '<span class="id mono">' + esc(idText(e) || '–') + '</span>' + (e.reason ? '<span class="why">reason ' + esc(e.reason) + '</span>' : '') + '</div>').join('') + '</div>';
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
          esc(['client-ip', 'envelope-from', 'helo', 'receiver'].filter(k => x.props[k]).map(k => k + '=' + x.props[k]).join(' ') || '–') + '</span></div>').join('') + '</div></div>';
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
    if (c.result === 'unknown') cmp += chip('unknown', 'Cannot compute') + '<span class="sub">' + (c.why === 'no-from' ? 'There is no From domain to align with.' : 'The receiver reported no SPF or DKIM results to combine.') + '</span>';
    else if (c.result === 'depends') cmp += '<span class="modes">' + chip('pass', 'relaxed: pass') + chip('fail', 'strict: fail') + '</span><span class="sub">The DMARC record decides: ' + esc(c.tags.join(' and ')) + ' (relaxed when absent).</span>' + srcBtn(c.src);
    else cmp += chip(c.result, 'dmarc=' + c.result) + '<span class="sub">' + (c.result === 'pass' ? 'Aligned pass from ' + esc((c.by.strict.length ? c.by.strict : c.by.relaxed).join(', ')) + '.' : 'No method that passed aligns with the From domain.') + '</span>' + srcBtn(c.src);
    h += '<div class="dmt">' + rep + '</div><div class="dmt">' + cmp + '</div></div>';
    if (d.disagreement) h += says([d.disagreement]);
    if (a.compauth) h += '<p class="raw-line"><span class="lbl">Microsoft compauth, raw:</span> <span class="mono">' + prov(a.compauth.src, esc(a.compauth.raw)) + '</span> <span class="absent">Step 3 decodes the reason code.</span></p>';
    const shown = (n) => (d.disagreement && n.technical === d.disagreement.technical) || /^Microsoft composite authentication/.test(n.technical);
    h += says(a.notes.filter(n => !shown(n)));
    $('auth').innerHTML = h;
  }

  function tlsChip(h) { return chip(h.tls.state, h.tls.state === 'pass' || h.tls.state === 'caveat' ? h.tls.label : h.tls.state === 'fail' ? 'Plain' : h.tls.label); }

  function hopRow(h, maxDelay, numberLabel) {
    const from = h.from ? esc(h.fromHost || '(unnamed)') + (h.fromIp && h.fromHost.indexOf(h.fromIp) === -1 ? ' <span class="ip">' + esc(h.fromIp) + '</span>' : '') : '<span class="ip">(handoff inside the server)</span>';
    const route = from + '<span class="arrow" aria-label="to">→</span>' + esc(h.byHost || '(unnamed)');
    const facts = [];
    facts.push(tlsChip(h));
    if (h.protocol) facts.push('<span>with ' + esc(h.protocol) + (h.authenticated ? ', authenticated' : '') + '</span>');
    if (h.internal) facts.push('<span title="' + esc(h.internalReason) + '">internal</span>');
    if (h.time !== null) facts.push('<span class="time">' + esc(fmtUtc(h.time)) + (h.tzKnown ? '' : ' (zone unknown)') + '</span>');
    else facts.push(chip('unknown', 'No readable date'));
    facts.push(srcBtn(h.src));
    let delay = '';
    if (h.delaySec !== null) {
      const pct = h.delaySec > 0 && maxDelay > 0 ? Math.max(1, Math.round(h.delaySec / maxDelay * 100)) : 0;
      delay = '<div class="delay"><div class="bar" aria-hidden="true">' + (h.skew ? '' : '<i style="width:' + pct + '%"></i>') + '</div><span class="val">' + esc(fmtDur(h.delaySec)) + '</span></div>';
      if (h.skew) delay += '<div class="facts">' + chip('caveat', 'Clock skew') + '<span>stamped earlier than the hop before it</span></div>';
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
    let h = '<h2 id="h-path">Path <span class="count">' + c.count + ' hop' + (c.count === 1 ? '' : 's') + ', oldest first</span></h2>';
    if (!c.count) { $('path').innerHTML = h + says(c.notes); return; }
    const maxDelay = Math.max.apply(null, [0].concat(c.hops.map(x => x.delaySec || 0), c.groups.map(g => g.delaySec || 0)));
    h += '<div class="summary"><span class="big">' + (c.totalSec !== null && c.totalSec >= 0 ? esc(fmtDur(c.totalSec)) : '–') + '</span><span class="lbl">end to end</span>' +
      (c.clockSkew ? chip('caveat', 'Clock skew') : '') + (c.trust.boundaryIdx >= 0 && !c.trust.originPrivate && c.originIp ? '<span class="lbl">origin <span class="mono">' + esc(c.originIp) + '</span></span>' : '') + '</div>';
    h += '<ol class="hops">';
    const t = c.trust;
    for (const g of c.groups) {
      if (t.boundaryIdx >= 0 && g.hops.includes(t.boundaryIdx)) h += trustRow(c);
      if (g.kind === 'hop') { h += hopRow(c.hops[g.hops[0]], maxDelay, String(g.hops[0] + 1)); continue; }
      const hs = g.hops.map(i => c.hops[i]);
      const states = hs.map(x => x.tls.state);
      const worst = ['fail', 'caveat', 'unknown', 'pass'].find(s => states.includes(s));
      const pct = g.delaySec > 0 && maxDelay > 0 ? Math.max(1, Math.round(g.delaySec / maxDelay * 100)) : 0;
      const slow = hs.some(x => x.slowest);
      h += '<li class="hop group' + (slow ? ' slowest' : '') + '"><span class="n">' + (g.hops[0] + 1) + '–' + (g.hops[g.hops.length - 1] + 1) + '</span><div class="body"><details data-group="' + g.hops[0] + '"><summary>' +
        '<span class="grp-title">' + hs.length + ' internal hops inside ' + esc(g.operator) + (slow ? ' <span class="slow-word">slowest</span>' : '') + ' <span class="chev"><span class="closed">Show hops</span><span class="open">Hide hops</span></span></span>' +
        '<span class="facts">' + chip(worst, worst === 'pass' ? 'TLS on every hop' : worst === 'unknown' ? 'TLS not recorded on every hop' : worst === 'caveat' ? 'TLS with caveats' : 'Plain on a hop') + srcBtn(g.src) + '</span>' +
        (g.delaySec !== null ? '<span class="delay"><span class="bar" aria-hidden="true"><i style="width:' + pct + '%"></i></span><span class="val">' + esc(fmtDur(g.delaySec)) + '</span></span>' : '') +
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
    let h = '<details class="raw" id="raw-details"><summary>Raw headers <span class="count">' + fields.length + ' field' + (fields.length === 1 ? '' : 's') + (b ? ', lines ' + (b[0] + 1) + '–' + (b[1] + 1) + ' of the paste' : '') + '</span></summary>' +
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
    const el = e.target.closest('[data-src]');
    if (!el || !R) return;
    if (el.closest('summary')) e.preventDefault(); // a source button inside a group row should not also toggle it
    const src = el.dataset.src.split(',').filter(Boolean).map(Number);
    highlight(src);
    el.classList.add('on');
  });

  function setVoice(v) {
    voice = v;
    document.querySelectorAll('[data-voice]').forEach(b => b.setAttribute('aria-pressed', String(b.dataset.voice === v)));
    try { localStorage.setItem('hv-voice', v); } catch (e) { /* storage blocked */ }
    if (R) renderAll();
  }

  function renderAll() {
    const open = $('raw-details') && $('raw-details').open;
    const openGroups = Array.from(document.querySelectorAll('#path details[open]')).map(d => d.dataset.group);
    $('read-as').textContent = 'Read as ' + (FORMATS[R.input.format] || 'a header block') + ': ' + R.fields.length + ' fields, ' + R.chain.count + ' Received.';
    renderVerdict(); renderMessage();
    renderAlignment();
    renderAuth();
    renderPath();
    $('filters').innerHTML = later('filters');
    renderRaw();
    if (R.input.notes.length) $('raw').insertAdjacentHTML('beforeend', says(R.input.notes));
    if (open) $('raw-details').open = true;
    openGroups.forEach(g => { const d = document.querySelector('#path details[data-group="' + g + '"]'); if (d) d.open = true; });
    if (lit.length) highlight(lit);
  }

  function run(scroll) {
    const text = $('headers').value;
    if (!text.trim()) { $('results').hidden = true; R = null; return; }
    lit = [];
    R = HA.analyze(text);
    $('results').hidden = false;
    if (!R.input.blockFound) {
      $('read-as').textContent = '';
      $('verdict').innerHTML = '<h2 id="h-verdict">Nothing to read</h2>' + says(R.input.notes);
      ['message', 'alignment', 'auth', 'path', 'filters', 'raw'].forEach(id => { $(id).innerHTML = ''; $(id).hidden = true; });
      return;
    }
    ['message', 'alignment', 'auth', 'path', 'filters', 'raw'].forEach(id => { $(id).hidden = false; });
    renderAll();
    if (scroll) $('results').scrollIntoView({ behavior: matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth', block: 'start' });
  }

  $('go').addEventListener('click', () => run(true));
  $('clear').addEventListener('click', () => { $('headers').value = ''; run(false); $('headers').focus(); });
  document.querySelectorAll('[data-sample]').forEach(b => b.addEventListener('click', () => { $('headers').value = window.SAMPLES[b.dataset.sample]; run(true); }));
  document.querySelectorAll('[data-voice]').forEach(b => b.addEventListener('click', () => setVoice(b.dataset.voice)));
  $('headers').addEventListener('keydown', (e) => { if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') run(true); });

  const panel = $('input-panel');
  panel.addEventListener('dragover', (e) => { e.preventDefault(); panel.classList.add('drop'); });
  panel.addEventListener('dragleave', () => panel.classList.remove('drop'));
  panel.addEventListener('drop', (e) => {
    e.preventDefault(); panel.classList.remove('drop');
    const f = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
    if (!f) return;
    const reader = new FileReader();
    reader.onload = () => { $('headers').value = String(reader.result || ''); run(true); };
    reader.readAsText(f);
  });

  setVoice(voice);
  // Open on a sample so the page shows what it does before anyone pastes.
  if (!$('headers').value.trim()) { $('headers').value = window.SAMPLES.gmail; run(false); }
})();
