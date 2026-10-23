// app.js: rendering only. Takes the analyze() result and writes the page.
(function () {
  'use strict';
  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s === null || s === undefined ? '' : s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const fmtDur = HA.verdict.fmtDur;
  const lvlPill = (lvl, text) => '<span class="pill ' + esc(lvl) + '">' + esc(text) + '</span>';
  const resultLevel = (r) => r === 'pass' ? 'ok' : (r === 'fail' || r === 'permerror' || r === 'softfail') ? 'bad' : (r === 'none' || r === 'neutral' || r === 'temperror' || r === 'policy') ? 'warn' : 'info';

  function fmtDate(d) {
    if (!d) return '';
    try { return d.toISOString().replace('T', ' ').replace(/\.\d{3}Z$/, ' UTC'); } catch (e) { return ''; }
  }

  function renderVerdict(r) {
    const v = r.verdict;
    const pillFor = { pass: ['ok', 'Pass'], fail: ['bad', 'Fail'], none: ['warn', 'No policy'], unknown: ['info', 'Not determined'] }[v.status] || ['info', v.status];
    let h = '<div class="head">' + lvlPill(pillFor[0], pillFor[1]) + '<h3>' + esc(v.headline) + '</h3>' + (v.forwarded ? lvlPill('info', 'Forwarded') : '') + '</div>';
    h += '<p class="cause">' + esc(v.cause) + '</p>';
    if (v.policyText) h += '<p class="policy">' + esc(v.policyText) + '</p>';
    if (v.detail.length) h += '<ul class="detail">' + v.detail.map(d => '<li>' + esc(d) + '</li>').join('') + '</ul>';
    if (v.fixes.length) h += '<div class="fixes"><h4>' + (v.status === 'pass' ? 'Worth knowing' : 'What to change') + '</h4><ol>' + v.fixes.map(f => '<li>' + esc(f) + '</li>').join('') + '</ol></div>';
    if (v.flags.length) h += '<div class="flags">' + v.flags.map(f => '<div class="flag">' + lvlPill(f.level, f.level === 'bad' ? 'Problem' : f.level === 'warn' ? 'Watch' : 'Note') + '<span>' + esc(f.text) + '</span></div>').join('') + '</div>';
    if (v.forwardEvidence.length) h += '<p class="note">Forwarding evidence: ' + esc(v.forwardEvidence.join('; ')) + '.</p>';
    const el = $('verdict');
    el.className = 'panel verdict ' + v.status;
    el.innerHTML = h;
  }

  function renderMessage(r) {
    const m = r.message;
    const from = m.from ? (m.from.display ? m.from.display + ' <' + m.from.address + '>' : m.from.address) : '(none)';
    const rows = [
      ['From', from],
      ['To', m.to.map(a => a.address).join(', ') || ''],
      ['Subject', m.subject],
      ['Date', m.date && m.date.date ? fmtDate(m.date.date) + (m.date.tzKnown ? '' : ' (zone unknown)') : (m.date ? m.date.text : '')],
      ['Message-ID', m.messageId],
      ['Delivered to', m.deliveredTo],
      ['Received by', r.auth.primary ? (r.auth.primary.authserv || (r.auth.compauth ? 'Microsoft 365 (no authserv-id written)' : 'unnamed')) : ''],
      ['Sent through', r.decoded.platform.name ? r.decoded.platform.name + (r.decoded.platform.confident ? '' : ' (weak evidence)') + ' (' + r.decoded.platform.evidence.map(e => e.what).join(', ') + ')' : (r.decoded.platform.xmailer ? r.decoded.platform.xmailer : 'not identified')],
      ['Origin', r.chain.originIp ? r.chain.originIp + (r.chain.originHost ? ' (' + r.chain.originHost + ')' : '') : ''],
    ].filter(x => x[1]);
    $('message').innerHTML = '<h2>Message</h2><dl class="meta">' + rows.map(x => '<dt>' + esc(x[0]) + '</dt><dd' + (/Message-ID|Origin/.test(x[0]) ? ' class="mono"' : '') + '>' + esc(x[1]) + '</dd>').join('') + '</dl>';
  }

  function renderAlignment(r) {
    const a = r.alignment;
    if (!a.fromDomain) { $('alignment').innerHTML = '<h2>Alignment</h2><p class="note">No From domain to align against.</p>'; return; }
    let h = '<h2>Alignment with ' + esc(a.fromDomain) + '</h2><div class="tbl"><table><thead><tr><th>Identifier</th><th>Domain</th><th>Result</th><th>Aligned</th><th>Note</th></tr></thead><tbody>';
    for (const row of a.rows) {
      const aligned = row.aligned === null ? '' : row.aligned ? lvlPill('ok', row.strict ? 'Yes, strict' : 'Yes, relaxed') : lvlPill('bad', 'No');
      h += '<tr><td>' + esc(row.id) + (row.selector ? ' <span class="mono">s=' + esc(row.selector) + '</span>' : '') + (row.identity === 'helo' ? ' (HELO)' : '') + '</td><td class="mono">' + esc(row.domain || '(none)') + '</td><td>' + (row.result ? lvlPill(resultLevel(row.result), row.result) : '') + '</td><td>' + aligned + '</td><td>' + esc(row.note || '') + '</td></tr>';
    }
    h += '</tbody></table></div>';
    const p = a.policy;
    const bits = [];
    if (p.p) bits.push('p=' + p.p); if (p.sp) bits.push('sp=' + p.sp); if (p.action) bits.push('action=' + p.action); if (p.dis) bits.push('disposition ' + p.dis);
    bits.push('adkim=' + p.adkim + ' aspf=' + p.aspf + (p.source === 'reported' ? '' : ' (assumed relaxed; not in the headers)'));
    h += '<p class="note">Receiver reported DMARC ' + esc(a.reported || 'nothing') + '. Policy as seen: ' + esc(bits.join(', ')) + '. Computed from identifiers: ' + (a.computed.pass ? 'pass' : 'fail') + (a.computed.byDkim ? ' via DKIM' : '') + (a.computed.bySpf ? (a.computed.byDkim ? ' and SPF' : ' via SPF') : '') + '.</p>';
    $('alignment').innerHTML = h;
  }

  function renderAuth(r) {
    const A = r.auth;
    let h = '<h2>Authentication results</h2>';
    if (!A.all.length) h += '<p class="note">No Authentication-Results header present.</p>';
    A.all.forEach((ar, i) => {
      h += '<div class="card" style="margin-bottom:10px"><h4>' + (i === 0 ? 'Final receiver' : 'Earlier hop') + ': <span class="mono">' + esc(ar.authserv || '(no authserv-id)') + '</span></h4><div class="chips">';
      if (ar.none) h += '<span class="chip">none</span>';
      for (const x of ar.results) {
        const who = x.props['header.d'] || x.props['header.i'] || x.props['header.from'] || x.props['smtp.mailfrom'] || x.props['smtp.helo'] || '';
        h += '<span class="chip ' + resultLevel(x.result) + '" title="' + esc(x.comments.join(' ') + (x.reason ? ' reason=' + x.reason : '')) + '">' + esc(x.method + '=' + x.result + (who ? ' ' + who : '') + (x.reason ? ' (' + x.reason + ')' : '')) + '</span>';
      }
      h += '</div></div>';
    });
    if (A.receivedSpf.length) h += '<p class="note">Received-SPF: ' + esc(A.receivedSpf[0].result) + (A.receivedSpf[0].props['envelope-from'] ? ' for ' + esc(A.receivedSpf[0].props['envelope-from']) : '') + (A.receivedSpf[0].props['client-ip'] ? ' from ' + esc(A.receivedSpf[0].props['client-ip']) : '') + '.</p>';
    if (A.dkimSignatures.length) {
      h += '<h2 style="margin-top:14px">DKIM signatures present</h2><div class="tbl"><table><thead><tr><th class="tag">d=</th><th class="tag">s=</th><th class="tag">a=</th><th class="tag">c=</th><th>Signed headers</th><th>Result</th></tr></thead><tbody>';
      for (const s of A.dkimSignatures) {
        const res = A.dkim.find(k => k.signature === s);
        h += '<tr><td class="mono">' + esc(s.d) + '</td><td class="mono">' + esc(s.s) + '</td><td class="mono">' + esc(s.a) + '</td><td class="mono">' + esc(s.c) + '</td><td class="mono" style="font-size:12px">' + esc(s.signedHeaders.join(' ')) + '</td><td>' + (res && res.result ? lvlPill(resultLevel(res.result), res.result) : lvlPill('info', 'no result')) + '</td></tr>';
      }
      h += '</tbody></table></div>';
    }
    if (A.arc.present) {
      h += '<h2 style="margin-top:14px">ARC chain</h2><div class="tbl"><table><thead><tr><th class="tag">i=</th><th>Sealer</th><th class="tag">cv=</th><th>Results at that hop</th></tr></thead><tbody>';
      for (const set of A.arc.chain) {
        const res = set.aar ? set.aar.results.map(x => x.method + '=' + x.result).join(', ') : '(no ARC-Authentication-Results)';
        h += '<tr><td class="num">' + set.i + '</td><td class="mono">' + esc((set.seal && set.seal.d) || (set.ams && set.ams.d) || '') + '</td><td>' + (set.seal ? lvlPill(set.seal.cv === 'fail' ? 'bad' : set.seal.cv === 'pass' || set.seal.cv === 'none' ? 'ok' : 'warn', set.seal.cv || '?') : '') + '</td><td class="mono" style="font-size:12.5px">' + esc(res) + '</td></tr>';
      }
      h += '</tbody></table></div>';
      if (A.arcResult) h += '<p class="note">Final receiver: arc=' + esc(A.arcResult.result) + '.</p>';
    }
    $('auth').innerHTML = h;
  }

  function renderHops(r) {
    const c = r.chain;
    let h = '<h2>Path (' + c.count + ' hop' + (c.count === 1 ? '' : 's') + (c.totalSec !== null ? ', ' + fmtDur(c.totalSec) + ' end to end' : '') + ')</h2>';
    if (!c.count) { $('hops').innerHTML = h + '<p class="note">No Received headers. This copy never passed through a receiving server.</p>'; return; }
    h += '<div class="tbl"><table><thead><tr><th class="num">#</th><th>From</th><th>By</th><th>Protocol</th><th>Time (UTC)</th><th class="num">Delay</th></tr></thead><tbody>';
    c.hops.forEach((hop, i) => {
      const cls = ['hop', hop.internal ? 'internal' : '', i === c.slowestIdx && c.slowestSec >= 60 ? 'slow' : '', hop.delaySec !== null && hop.delaySec < 0 ? 'skew' : ''].join(' ');
      const tls = hop.tls === true ? (hop.tlsVersion || 'TLS') : hop.tls === false ? 'no TLS' : '';
      h += '<tr class="' + cls + '"><td class="num">' + hop.index + '</td><td class="mono">' + esc(hop.fromHost || '(unnamed)') + (hop.fromIp ? '<br><span style="color:var(--muted)">' + esc(hop.fromIp) + '</span>' : '') + '</td><td class="mono">' + esc(hop.byHost || '') + '</td><td>' + esc(hop.protocol || '') + (tls ? '<br><span style="color:var(--muted);font-size:12.5px">' + esc(tls) + (hop.authenticated ? ', authenticated' : '') + '</span>' : (hop.authenticated ? '<br><span style="color:var(--muted);font-size:12.5px">authenticated</span>' : '')) + '</td><td class="mono" style="font-size:12.5px">' + esc(hop.date ? fmtDate(hop.date) : (hop.dateText || '')) + (hop.date && !hop.tzKnown ? '<br><span style="color:var(--muted)">zone unknown</span>' : '') + '</td><td class="num delay">' + (hop.delaySec === null ? '' : esc(fmtDur(hop.delaySec))) + '</td></tr>';
    });
    h += '</tbody></table></div>';
    const notes = [];
    if (c.slowestSec >= 60) notes.push('Longest wait is at hop ' + (c.slowestIdx + 1) + ' (' + fmtDur(c.slowestSec) + '). The delay on a row is the time between the previous server\'s stamp and this one\'s.');
    if (c.hops.some(x => x.internal)) notes.push('Greyed rows are relays inside one operator.');
    if (c.clockSkew) notes.push('A negative delay means two servers disagree about the time.');
    if (notes.length) h += '<p class="note">' + esc(notes.join(' ')) + '</p>';
    $('hops').innerHTML = h;
  }

  function renderProviders(r) {
    const d = r.decoded;
    let h = '<h2>Filter and platform headers</h2>';
    if (!d.providers.length && !d.misc.length) { $('providers').innerHTML = h + '<p class="note">No filter verdict headers from Microsoft, Proofpoint, Mimecast, Cisco, Barracuda, or SpamAssassin, and no list headers.</p>'; return; }
    h += '<div class="cards">';
    for (const p of d.providers) {
      h += '<div class="card"><h4>' + esc(p.name) + '</h4><div class="kv">' + p.items.map(it => '<span class="k">' + esc(it.key) + '</span><span class="v lvl-' + esc(it.level) + '"><b>' + esc(it.value) + '</b> ' + esc(it.meaning) + '</span>').join('') + '</div>' + (p.note ? '<p class="note">' + esc(p.note) + '</p>' : '') + '</div>';
    }
    if (d.misc.length) h += '<div class="card"><h4>Sending and list headers</h4><div class="kv">' + d.misc.map(it => '<span class="k">' + esc(it.key) + '</span><span class="v lvl-' + esc(it.level) + '"><b>' + esc(it.value) + '</b> ' + esc(it.meaning) + '</span>').join('') + '</div></div>';
    h += '</div>';
    $('providers').innerHTML = h;
  }

  function renderRaw(r) {
    const fields = r.fields;
    let h = '<details><summary>All ' + fields.length + ' headers</summary><div class="raw"><label for="filter" class="hidden">Filter headers</label><input id="filter" type="search" placeholder="Filter by name or value"><div class="rawlist" id="rawlist"></div></div></details>';
    if (r.input.notes.length) h += '<p class="note">' + esc(r.input.notes.join(' ')) + '</p>';
    if (r.input.bodyPresent) h += '<p class="note">A message body was included after the headers and was ignored.</p>';
    $('raw').innerHTML = h;
    const list = $('rawlist');
    const draw = (q) => {
      q = (q || '').toLowerCase();
      list.innerHTML = fields.filter(f => !q || f.lower.includes(q) || f.value.toLowerCase().includes(q)).map(f => '<div><span class="n">' + esc(f.name) + '</span><span class="v">' + esc(f.value) + '</span></div>').join('') || '<p class="note">No header matches.</p>';
    };
    draw('');
    $('filter').addEventListener('input', (e) => draw(e.target.value));
  }

  function run() {
    const text = $('headers').value;
    if (!text.trim()) { $('results').hidden = true; return; }
    let r;
    try { r = HA.analyze(text); }
    catch (e) {
      $('results').hidden = false;
      $('verdict').className = 'panel verdict';
      $('verdict').innerHTML = '<div class="head">' + lvlPill('bad', 'Error') + '<h3>Could not read these headers</h3></div><p class="cause">' + esc(String(e && e.message || e)) + '</p>';
      ['message', 'alignment', 'auth', 'hops', 'providers', 'raw'].forEach(id => { $(id).innerHTML = ''; });
      return;
    }
    if (!r.input.blockFound) {
      $('results').hidden = false;
      $('verdict').className = 'panel verdict';
      $('verdict').innerHTML = '<div class="head">' + lvlPill('info', 'Nothing to read') + '<h3>No header lines found</h3></div><p class="cause">Nothing in the paste looks like a header (a name, a colon, a value). Copy the raw source of the message, not the rendered view.</p>';
      ['message', 'alignment', 'auth', 'hops', 'providers', 'raw'].forEach(id => { $(id).innerHTML = ''; });
      return;
    }
    renderVerdict(r); renderMessage(r); renderAlignment(r); renderAuth(r); renderHops(r); renderProviders(r); renderRaw(r);
    $('results').hidden = false;
    $('verdict').scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  $('go').addEventListener('click', run);
  $('clear').addEventListener('click', () => { $('headers').value = ''; $('results').hidden = true; $('headers').focus(); });
  $('sample1').addEventListener('click', () => { $('headers').value = window.SAMPLES.unaligned; run(); });
  $('sample2').addEventListener('click', () => { $('headers').value = window.SAMPLES.forwarded; run(); });
  $('headers').addEventListener('keydown', (e) => { if ((e.metaKey || e.ctrlKey) && e.key === 'Enter') run(); });

  const panel = $('input-panel');
  panel.addEventListener('dragover', (e) => { e.preventDefault(); panel.classList.add('drop'); });
  panel.addEventListener('dragleave', () => panel.classList.remove('drop'));
  panel.addEventListener('drop', (e) => {
    e.preventDefault(); panel.classList.remove('drop');
    const f = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0];
    if (!f) return;
    const reader = new FileReader();
    reader.onload = () => { $('headers').value = String(reader.result || ''); run(); };
    reader.readAsText(f);
  });

  // Open on a sample so the page shows what it does before anyone pastes.
  if (!$('headers').value.trim()) { $('headers').value = window.SAMPLES.unaligned; run(); window.scrollTo(0, 0); }
})();
