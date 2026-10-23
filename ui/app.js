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
    alignment: [2, 'Step 2 fills this: the From domain against the Return-Path and every DKIM d=, each marked aligned or not.'],
    auth: [2, 'Step 2 fills this: Authentication-Results per method with the host that wrote them, and the ARC chain with cv=.'],
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
    const fails = [].concat(R.message.notes, R.chain.notes).filter(s => s.state === 'fail');
    if (fails.length) h += '<p class="note-line">Until then, these step 1 findings are marked as failures:</p>' + says(fails);
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
    return '<li class="hop' + (h.slowest ? ' slowest' : '') + '"><span class="n">' + numberLabel + '</span><div class="body">' +
      '<div class="route">' + prov(h.src, route) + (h.slowest ? ' <span class="slow-word">slowest</span>' : '') + '</div>' +
      '<div class="facts">' + facts.join('') + '</div>' + delay + '</div></li>';
  }

  function renderPath() {
    const c = R.chain;
    let h = '<h2 id="h-path">Path <span class="count">' + c.count + ' hop' + (c.count === 1 ? '' : 's') + ', oldest first</span></h2>';
    if (!c.count) { $('path').innerHTML = h + says(c.notes); return; }
    const maxDelay = Math.max.apply(null, [0].concat(c.hops.map(x => x.delaySec || 0), c.groups.map(g => g.delaySec || 0)));
    h += '<div class="summary"><span class="big">' + (c.totalSec !== null && c.totalSec >= 0 ? esc(fmtDur(c.totalSec)) : '–') + '</span><span class="lbl">end to end</span>' +
      (c.clockSkew ? chip('caveat', 'Clock skew') : '') + (c.originIp ? '<span class="lbl">first public address <span class="mono">' + esc(c.originIp) + '</span></span>' : '') + '</div>';
    h += '<ol class="hops">';
    for (const g of c.groups) {
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
    $('alignment').innerHTML = later('alignment');
    $('auth').innerHTML = later('auth');
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
