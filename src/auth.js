// auth.js: Authentication-Results (RFC 8601), Received-SPF, DKIM-Signature,
// the ARC set (RFC 8617), and DMARC identifier alignment (RFC 7489 3.1).
// Nothing here verifies a signature or queries DNS. It reads what the
// receiving systems reported and recomputes alignment from the
// identifiers, so the page can show its own DMARC result beside theirs.
(function (root) {
  'use strict';
  const HA = (root.HA = root.HA || {});
  const P = HA.parse;
  const say = P.sentence;

  // Split on a separator outside comments and quoted strings.
  function splitOutside(value, sep) {
    const parts = [];
    let depth = 0, inQuote = false, buf = '';
    for (let i = 0; i < value.length; i++) {
      const c = value[i];
      if (inQuote) { buf += c; if (c === '\\') { buf += value[++i] || ''; continue; } if (c === '"') inQuote = false; continue; }
      if (c === '"' && depth === 0) { inQuote = true; buf += c; continue; }
      if (c === '(') depth++;
      else if (c === ')') depth = Math.max(0, depth - 1);
      if (c === sep && depth === 0) { parts.push(buf); buf = ''; continue; }
      buf += c;
    }
    parts.push(buf);
    return parts;
  }

  const PROP_RE = /([A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)?)\s*=\s*("(?:[^"\\]|\\.)*"|[^\s;]+)/g;
  // The identifiers the page shows for every method (RFC 8601 2.7).
  const IDS = ['header.d', 'header.i', 'header.s', 'header.b', 'smtp.mailfrom', 'smtp.helo', 'header.from'];

  function parseAuthResults(value) {
    const out = { raw: value, authserv: '', version: '', instance: null, results: [], none: false };
    const parts = splitOutside(value, ';').map(s => s.trim()).filter(s => s !== '');
    if (!parts.length) return out;
    let head = parts.shift();
    const m = /^i\s*=\s*(\d+)$/i.exec(P.stripComments(head));
    if (m) { out.instance = parseInt(m[1], 10); head = parts.shift() || ''; }
    const headStripped = P.stripComments(head);
    if (/^[A-Za-z0-9-]+\s*=\s*[A-Za-z0-9_-]+/.test(headStripped)) {
      // Exchange Online writes no authserv-id: the value starts with spf=.
      parts.unshift(head);
    } else {
      const headTokens = headStripped.split(/\s+/).filter(Boolean);
      // authserv-id, optional version, and sometimes "none" or the first
      // method when the writer skipped the semicolon.
      out.authserv = (headTokens[0] || '').toLowerCase();
      if (headTokens[1] && /^\d+$/.test(headTokens[1])) out.version = headTokens[1];
      const rest = headTokens.slice(out.version ? 2 : 1).join(' ');
      if (rest) parts.unshift(rest);
    }
    for (const part of parts) {
      const stripped = P.stripComments(part);
      if (!stripped) continue;
      if (/^none$/i.test(stripped)) { out.none = true; continue; }
      const mm = /^([A-Za-z0-9-]+)\s*=\s*([A-Za-z0-9_-]+)/.exec(stripped);
      if (!mm) continue;
      const r = { method: mm[1].toLowerCase(), result: mm[2].toLowerCase(), props: {}, ids: {}, comments: P.extractComments(part), reason: '', text: stripped };
      let pm;
      const tail = stripped.slice(mm[0].length);
      PROP_RE.lastIndex = 0;
      while ((pm = PROP_RE.exec(tail))) {
        const key = pm[1].toLowerCase();
        const val = pm[2].replace(/^"|"$/g, '');
        if (key === 'reason') r.reason = val; else r.props[key] = val;
      }
      for (const k of IDS) if (r.props[k]) r.ids[k] = r.props[k];
      // policy.* properties (RFC 8601 2.7.7), keyed by what follows the dot.
      r.policy = {};
      for (const k of Object.keys(r.props)) if (k.startsWith('policy.')) r.policy[k.slice(7)] = r.props[k];
      out.results.push(r);
    }
    return out;
  }

  // Received-SPF: result (comment) key=value; key=value
  function parseReceivedSpf(value) {
    const r = { raw: value, result: '', comments: P.extractComments(value), props: {} };
    const stripped = P.stripComments(value);
    const m = /^([A-Za-z]+)/.exec(stripped);
    if (m) r.result = m[1].toLowerCase();
    let pm; PROP_RE.lastIndex = 0;
    while ((pm = PROP_RE.exec(stripped))) r.props[pm[1].toLowerCase()] = pm[2].replace(/^"|"$/g, '');
    return r;
  }

  // The state a reported result shows. RFC 8601 2.7 result words.
  function resultState(result) {
    if (result === 'pass') return 'pass';
    if (['fail', 'hardfail', 'permerror'].includes(result)) return 'fail';
    if (['softfail', 'temperror', 'neutral', 'policy', 'bestguesspass'].includes(result)) return 'caveat';
    return 'unknown';
  }

  const int = (v) => { const n = parseInt(v, 10); return isNaN(n) ? null : n; };

  function parseDkimSignature(value) {
    const { tags } = P.parseTagList(value);
    const sig = { v: tags.v || '', d: (tags.d || '').toLowerCase(), s: tags.s || '', i: tags.i || '', a: tags.a || '', c: tags.c || 'simple/simple', bh: tags.bh || '', h: (tags.h || '').toLowerCase(), t: int(tags.t), x: int(tags.x), l: int(tags.l), b: tags.b || '', bPrefix: (tags.b || '').slice(0, 8) };
    sig.signedHeaders = sig.h.split(':').map(s => s.trim()).filter(Boolean);
    sig.partialBody = sig.l !== null;
    // expired is set against the arrival time in buildAuth; null means unknown.
    sig.expired = sig.x === null ? false : sig.t !== null && sig.x < sig.t ? true : null;
    sig.notes = [];
    if (!sig.signedHeaders.includes('from')) sig.notes.push('h= does not list From, which RFC 6376 5.4 requires.');
    if (sig.l !== null) sig.notes.push('l= body length limit present; the signature covers only the first ' + sig.l + ' bytes of the body, and content appended after that is unsigned.');
    if (sig.x !== null && sig.t !== null && sig.x < sig.t) sig.notes.push('x= expiry is earlier than t= timestamp.');
    if (/sha1/i.test(sig.a)) sig.notes.push('rsa-sha1 is historic (RFC 8301); receivers may ignore it.');
    return sig;
  }

  const sameHost = (a, b) => !!a && !!b && a.toLowerCase().replace(/\.$/, '') === b.toLowerCase().replace(/\.$/, '');

  // Which hop wrote a header that names a host: a by host with that exact
  // name, else a hop whose receiving side belongs to the same operator.
  // Returns the latest such hop, since results are stamped on arrival.
  function hopForHost(host, chain) {
    if (!host || !chain.count) return { hopIdx: -1, matchedBy: '' };
    for (let i = chain.count - 1; i >= 0; i--) if (sameHost(chain.hops[i].byHost, host)) return { hopIdx: i, matchedBy: 'host' };
    const op = HA.received.operatorOf(host);
    if (op) for (let i = chain.count - 1; i >= 0; i--) if (chain.trust.sides[i] === op) return { hopIdx: i, matchedBy: 'operator' };
    return { hopIdx: -1, matchedBy: '' };
  }

  // One record per Authentication-Results field, with the host that
  // wrote it and whether the Received chain backs that up. RFC 8601 5
  // has receivers delete fields that carry their own authserv-id, so a
  // field whose host the chain never names could have come from anyone.
  function readArField(f, chain, exo) {
    const ar = parseAuthResults(f.value);
    const rec = { index: f.index, src: [f.index], authserv: ar.authserv, version: ar.version, none: ar.none, writer: ar.authserv, writerNamed: !!ar.authserv, hopIdx: -1, matchedBy: '', trust: 'unverified', primary: false, entries: [] };
    if (ar.authserv) Object.assign(rec, hopForHost(ar.authserv, chain));
    else if (exo) {
      // Exchange Online names no authserv-id. The field usually sits just
      // above the Received field of the hop that wrote it, sometimes just
      // below. Only Microsoft writes this form, so the Received directly
      // above counts only when its receiving side is Microsoft.
      const below = chain.hops.filter(h => h.src[0] > f.index).sort((a, b) => a.src[0] - b.src[0])[0];
      const above = chain.hops.filter(h => h.src[0] < f.index).sort((a, b) => b.src[0] - a.src[0])[0];
      const onReceiver = (h) => h && chain.trust.boundaryIdx >= 0 && h.index >= chain.trust.boundaryIdx;
      const pick = onReceiver(below) ? below : (above && chain.trust.sides[above.index] === 'Microsoft' && onReceiver(above)) ? above : below;
      if (pick) { rec.hopIdx = pick.index; rec.matchedBy = 'position'; rec.writer = pick.byHost; }
    }
    if (rec.hopIdx >= 0) rec.trust = chain.trust.boundaryIdx >= 0 && rec.hopIdx >= chain.trust.boundaryIdx ? 'receiver' : 'sender-side';
    // RFC 8601 5 has a receiver strip only fields that carry its own
    // authserv-id, so anything not written by the final receiver could
    // have come from the sender or a hop before.
    rec.untrusted = rec.trust !== 'receiver';
    rec.entries = ar.results.map(r => ({ method: r.method, result: r.result, state: resultState(r.result), reason: r.reason, ids: r.ids, props: r.props, policy: r.policy, comments: r.comments, text: r.text, field: f.index, src: [f.index] }));
    return rec;
  }

  function buildArc(fields, chain) {
    const sets = {};
    const problems = [];
    const put = (i, key, val, idx) => {
      sets[i] = sets[i] || { i, src: [] };
      if (sets[i][key]) problems.push({ i, text: 'ARC set i=' + i + ' carries more than one ' + { seal: 'ARC-Seal', ams: 'ARC-Message-Signature', aar: 'ARC-Authentication-Results' }[key] + '.', src: [sets[i][key].field, idx] });
      else { sets[i][key] = Object.assign(val, { field: idx }); sets[i].src.push(idx); }
    };
    for (const f of fields) {
      if (f.lower === 'arc-seal' || f.lower === 'arc-message-signature') {
        const { tags } = P.parseTagList(f.value);
        const i = int(tags.i);
        if (!i) { problems.push({ i: 0, text: f.name + ' has no usable i= instance.', src: [f.index] }); continue; }
        if (f.lower === 'arc-seal') put(i, 'seal', { cv: (tags.cv || '').toLowerCase(), d: (tags.d || '').toLowerCase(), s: tags.s || '', t: int(tags.t), a: tags.a || '' }, f.index);
        else put(i, 'ams', { d: (tags.d || '').toLowerCase(), s: tags.s || '', h: (tags.h || '').toLowerCase(), c: tags.c || '' }, f.index);
      } else if (f.lower === 'arc-authentication-results') {
        const ar = parseAuthResults(f.value);
        if (!ar.instance) { problems.push({ i: 0, text: 'ARC-Authentication-Results has no usable i= instance.', src: [f.index] }); continue; }
        put(ar.instance, 'aar', { authserv: ar.authserv, results: ar.results.map(r => ({ method: r.method, result: r.result, state: resultState(r.result), ids: r.ids, reason: r.reason })) }, f.index);
      }
    }
    const instances = Object.keys(sets).map(Number).sort((a, b) => a - b).map(i => sets[i]);
    instances.forEach((set, idx) => {
      set.src.sort((a, b) => a - b);
      if (set.i !== idx + 1) problems.push({ i: set.i, text: 'ARC instances are not contiguous: i=' + set.i + ' follows ' + (idx ? 'i=' + instances[idx - 1].i : 'nothing') + '.', src: set.src });
      const missing = ['seal', 'ams', 'aar'].filter(k => !set[k]).map(k => ({ seal: 'ARC-Seal', ams: 'ARC-Message-Signature', aar: 'ARC-Authentication-Results' }[k]));
      if (missing.length) problems.push({ i: set.i, text: 'ARC set i=' + set.i + ' is incomplete: no ' + missing.join(' or ') + '.', src: set.src });
      if (set.seal) {
        const cv = set.seal.cv || 'missing';
        if (set.i === 1 && cv !== 'none') problems.push({ i: 1, text: 'ARC-Seal i=1 carries cv=' + cv + '; the first seal must carry cv=none.', src: [set.seal.field] });
        if (set.i > 1 && cv !== 'pass') problems.push({ i: set.i, text: 'ARC-Seal i=' + set.i + ' carries cv=' + cv + (cv === 'fail' ? ': this sealer found the chain already broken.' : '; every seal after the first must carry cv=pass.'), src: [set.seal.field] });
      }
      // The sealer: the ARC-Seal d= domain, and the host named in its
      // ARC-Authentication-Results, tied to a hop when the chain shows one.
      set.sealer = { domain: (set.seal && set.seal.d) || (set.ams && set.ams.d) || '', host: (set.aar && set.aar.authserv) || '' };
      const at = hopForHost(set.sealer.host, chain);
      set.hopIdx = at.hopIdx;
      set.cv = set.seal ? set.seal.cv : '';
      set.preForward = set.aar ? set.aar.results : [];
    });
    const state = !instances.length ? 'none' : problems.length ? 'fail' : 'pass';
    // ARC-Authentication-Results i=1 is written by the first forwarder.
    const firstForwarder = instances[0] && instances[0].i === 1 && instances[0].aar ? instances[0].aar.authserv : '';
    return { present: instances.length > 0, instances, problems, state, sealers: instances.map(s => s.sealer.domain), firstForwarder };
  }

  // Alignment of one authenticated identifier with the From domain,
  // under both modes, plus the state its connector shows.
  function alignRow(kind, domain, result, from) {
    const L = HA.psl.lookup(domain);
    const strict = !!from.domain && !!L.domain && L.domain === from.domain;
    const relaxed = strict || (!!from.org && !!L.org && L.org === from.org);
    const passed = result === 'pass';
    let state, word;
    if (!from.defined) {
      return { kind, domain: L.domain, org: L.org, approximate: L.approximate, result, passed, strict: false, relaxed: false, relaxedOnly: false, modes: { relaxed: false, strict: false }, aligned: null, mode: '', state: 'unknown', word: 'No single From domain' };
    }
    if (!result || result === 'none') { state = 'unknown'; word = result === 'none' ? 'None' : 'Not reported'; }
    else if (!passed) { state = 'fail'; word = 'Failed'; }
    else if (strict) { state = 'pass'; word = 'Aligned'; }
    else if (relaxed) { state = 'pass'; word = 'Aligned, relaxed'; }
    else { state = 'caveat'; word = 'Passed, not aligned'; }
    return { kind, domain: L.domain, org: L.org, approximate: L.approximate, result, passed, strict, relaxed, relaxedOnly: passed && relaxed && !strict, modes: { relaxed: passed && relaxed, strict: passed && strict }, aligned: relaxed, mode: strict ? 's' : relaxed ? 'r' : '', state, word };
  }

  // DMARC policy as the receiver reported it. Google writes
  // (p=REJECT sp=REJECT dis=NONE); Microsoft writes action=none.
  function readPolicy(e) {
    const policy = { p: '', sp: '', dis: '', action: '' };
    if (!e) return policy;
    const text = e.comments.join(' ');
    const grab = (k) => { const m = new RegExp('\\b' + k + '=([A-Za-z0-9]+)', 'i').exec(text); return m ? m[1].toLowerCase() : ''; };
    policy.p = grab('p'); policy.sp = grab('sp'); policy.dis = grab('dis');
    if (e.props['policy.dmarc']) policy.p = e.props['policy.dmarc'].toLowerCase();
    if (e.props.action) policy.action = e.props.action.toLowerCase();
    return policy;
  }

  // The disposition the receiver applied. Google writes dis=; Microsoft
  // writes action=. Microsoft's own pages disagree on what oreject and
  // pct.* did to the message, so for those value stays empty and the
  // raw word, the policy it names, and the sampling are kept.
  const MS_ACTION = { oreject: ['', 'reject', false], 'pct.quarantine': ['', 'quarantine', true], 'pct.reject': ['', 'reject', true] };
  function readDisposition(e, policy) {
    const out = { value: '', source: '', raw: '', policy: policy.p || '', sampled: false, src: e ? e.src.slice() : [] };
    if (!e) return out;
    const word = (w) => ['none', 'quarantine', 'reject'].includes(w) ? w : '';
    if (policy.dis) {
      const m = /\bdis=([A-Za-z0-9]+)/i.exec(e.comments.join(' '));
      Object.assign(out, { value: word(policy.dis), source: 'dis', raw: m ? m[0] : 'dis=' + policy.dis });
    } else if (policy.action) {
      Object.assign(out, { value: word(policy.action), source: 'action', raw: 'action=' + e.props.action });
      const ms = MS_ACTION[policy.action];
      if (ms) Object.assign(out, { value: ms[0], policy: ms[1], sampled: ms[2] });
    }
    return out;
  }

  // The From domain DMARC evaluates: one From field whose addresses share
  // one domain. Two From fields, or addresses in two domains, leave it
  // undefined, and nothing is computed from any of them.
  function fromOf(message) {
    const src = message.from ? message.from.src.slice() : [];
    const none = (why) => ({ domain: '', org: '', approximate: false, defined: false, why, src });
    if (message.fromCount > 1) return none('two-from');
    if (!message.from || !message.from.domain) return none('no-from');
    const domains = message.from.domains || [message.from.domain];
    if (domains.length > 1) return none('multi-domain');
    const L = HA.psl.lookup(message.from.domain);
    return { domain: L.domain, org: L.org, approximate: L.approximate, defined: true, why: '', src };
  }

  function buildAuth(fields, chain, message) {
    const from = fromOf(message);
    const notes = [];
    const exo = fields.some(f => f.lower.startsWith('x-ms-exchange-organization-'));

    const all = fields.filter(f => f.lower === 'authentication-results').map(f => readArField(f, chain, exo));
    // The primary field is the final receiver's: the topmost one whose
    // authserv-id shares an operator with the last hop's by host, or, at
    // Exchange Online, the topmost one with no authserv-id. Never one the
    // sender could have written.
    const primary = all.find(r => !r.untrusted) || null;
    if (primary) primary.primary = true;
    const primaryRule = !primary ? '' : primary.authserv ? 'operator' : 'exchange-online';
    // The receiver's own fields. iCloud writes one field per method, so
    // results are gathered from all of them, the first per method winning.
    const reportSet = all.filter(r => !r.untrusted);
    const reported = (method) => { for (const r of reportSet) { const es = r.entries.filter(e => e.method === method); if (es.length) return es; } return []; };

    // Received-SPF counts when the receiver wrote it: above the Received
    // field of the last hop before the receiver took custody.
    const b = chain.trust.boundaryIdx;
    const senderTop = b > 0 ? chain.hops[b - 1].src[0] : Infinity;
    const rspfFields = fields.filter(f => f.lower === 'received-spf');
    const receivedSpf = rspfFields.map(f => Object.assign(parseReceivedSpf(f.value), { src: [f.index], trusted: b >= 0 && f.index < senderTop }));
    const dkimFields = fields.filter(f => f.lower === 'dkim-signature');
    const signatures = dkimFields.map(f => Object.assign(parseDkimSignature(f.value), { src: [f.index] }));
    const arc = buildArc(fields, chain);

    // x= against the time the receiver stamped, else the Date field.
    const lastHop = chain.count ? chain.hops[chain.count - 1] : null;
    const arrival = lastHop && lastHop.time !== null ? lastHop.time : message.date && message.date.time !== null ? message.date.time : null;
    for (const sig of signatures) {
      if (sig.x !== null && arrival !== null) sig.expired = sig.x * 1000 < arrival;
      if (sig.expired && !(sig.t !== null && sig.x < sig.t)) sig.notes.push('x= expiry ' + new Date(sig.x * 1000).toISOString().replace('.000Z', 'Z') + ' expired before the message arrived.');
    }

    // SPF: the primary A-R's spf, else a Received-SPF the receiver wrote.
    // The identifier is smtp.mailfrom, else the envelope-from (or helo)
    // Received-SPF names, else the Return-Path. A null reverse path means
    // SPF checked the HELO domain (RFC 7208 2.4).
    const spfE = reported('spf')[0] || null;
    const rspf = receivedSpf.find(x => x.trusted) || null;
    const rpF = fields.find(f => f.lower === 'return-path');
    const rp = rpF ? (P.parseAddresses(rpF.value)[0] || null) : null;
    const isNull = (v) => !v || /^<?\s*>?$/.test(v);
    let spfDomain = '', spfFrom = '', spfSrc = [], nullPath = false;
    const rspfId = rspf ? (rspf.props.identity || '').toLowerCase() : '';
    if (spfE && !isNull(spfE.ids['smtp.mailfrom'])) { spfDomain = P.domainOf(spfE.ids['smtp.mailfrom']); spfFrom = 'smtp.mailfrom'; spfSrc = spfE.src.slice(); }
    else if (!spfE && rspf && rspfId === 'helo' && rspf.props.helo) { spfDomain = P.domainOf(rspf.props.helo); spfFrom = 'Received-SPF helo'; spfSrc = rspf.src.slice(); }
    else if (rspf && !isNull(rspf.props['envelope-from'])) { spfDomain = P.domainOf(rspf.props['envelope-from']); spfFrom = 'Received-SPF envelope-from'; spfSrc = rspf.src.slice(); }
    else if (rp && rp.domain) { spfDomain = rp.domain; spfFrom = 'Return-Path'; spfSrc = [rpF.index]; }
    else if (rp && rp.empty) {
      nullPath = true;
      const recvHop = b >= 0 ? chain.hops[b] : null;
      if (spfE && spfE.ids['smtp.helo']) { spfDomain = P.domainOf(spfE.ids['smtp.helo']); spfFrom = 'smtp.helo'; spfSrc = spfE.src.slice(); }
      else if (rspf && rspf.props.helo) { spfDomain = P.domainOf(rspf.props.helo); spfFrom = 'Received-SPF helo'; spfSrc = rspf.src.slice(); }
      else if (recvHop && recvHop.fromHost && !HA.received.isIpLiteral(recvHop.fromHost)) { spfDomain = P.domainOf(recvHop.fromHost); spfFrom = 'Received HELO'; spfSrc = recvHop.src.slice(); }
      spfSrc = spfSrc.concat([rpF.index]);
    }
    const spfR = spfE || rspf;
    const spfResult = spfR ? spfR.result : '';
    const spfResultSrc = spfR ? spfR.src : [];
    const spf = Object.assign(alignRow('spf', spfDomain, spfResult, from), {
      identity: spfFrom, helo: spfE ? P.domainOf(spfE.ids['smtp.helo'] || '') : rspf ? P.domainOf(rspf.props.helo || '') : '', ip: (spfE && (spfE.props['smtp.remote-ip'] || spfE.props['client-ip'])) || (rspf && rspf.props['client-ip']) || '',
      reason: spfE ? spfE.reason : '', comments: spfE ? spfE.comments : rspf ? rspf.comments : [], reportedBy: spfE ? 'Authentication-Results' : rspf ? 'Received-SPF' : '',
      src: Array.from(new Set(spfSrc.concat(spfResultSrc))).sort((a, b) => a - b), absent: !spfDomain, nullPath });

    // DKIM: every result the receiver reported, matched to a signature by
    // header.d, and by header.s or header.b when two signatures share d=.
    // Two candidates and neither tag is ambiguous, and the page says so
    // instead of picking one. Signatures it reported nothing for follow.
    const used = new Set();
    const dkim = reported('dkim').map(e => {
      let d = P.domainOf(e.ids['header.d'] || e.ids['header.i'] || '');
      if (d === 'none') d = '';
      const s = e.ids['header.s'] || '';
      const bTag = (e.ids['header.b'] || '').replace(/\s+/g, '');
      const free = signatures.filter(x => !used.has(x));
      const sameD = d ? free.filter(x => x.d === d) : free;
      let sig = null, matchedBy = '', candidates = [];
      if (bTag && (sig = sameD.find(x => x.b.startsWith(bTag)) || null)) matchedBy = 'header.b';
      else if (s && (sig = sameD.find(x => x.s === s) || null)) matchedBy = 'header.s';
      else if (d && sameD.length === 1) { sig = sameD[0]; matchedBy = 'header.d'; }
      else if (d && sameD.length > 1) candidates = sameD;
      if (sig) used.add(sig);
      for (const c of candidates) used.add(c);
      if (!d && sig) d = sig.d;
      const ambiguous = candidates.length > 1;
      return Object.assign(alignRow('dkim', d, e.result, from), { selector: s || (sig ? sig.s : ''), reason: e.reason, comments: e.comments, signature: sig ? signatures.indexOf(sig) : -1, matchedBy, ambiguous, candidates: candidates.map(c => signatures.indexOf(c)),
        src: (sig ? [sig.src[0]] : candidates.map(c => c.src[0])).concat(e.src).sort((a, b) => a - b), absent: !d });
    }).filter(r => !(r.absent && r.result === 'none'));
    for (const sig of signatures) {
      if (used.has(sig)) continue;
      dkim.push(Object.assign(alignRow('dkim', sig.d, '', from), { selector: sig.s, reason: '', comments: [], signature: signatures.indexOf(sig), matchedBy: '', ambiguous: false, candidates: [], src: sig.src.slice(), absent: false }));
    }

    // Reported DMARC, with the policy and disposition the receiver quoted.
    const dmarcE = reported('dmarc')[0] || null;
    const policy = readPolicy(dmarcE);
    const dmarc = { result: dmarcE ? dmarcE.result : '', state: resultState(dmarcE ? dmarcE.result : ''), headerFrom: dmarcE ? P.domainOf(dmarcE.ids['header.from'] || '') : '', policy, disposition: readDisposition(dmarcE, policy), reason: dmarcE ? dmarcE.reason : '', comments: dmarcE ? dmarcE.comments : [], reported: !!dmarcE, src: dmarcE ? dmarcE.src.slice() : [] };

    // The receiver's own arc= result, kept beside the chain check.
    const arcE = reported('arc')[0] || null;
    const arcResult = arcE ? { result: arcE.result, props: arcE.props, comments: arcE.comments, text: arcE.text, src: arcE.src.slice() } : null;
    const caE = reported('compauth')[0] || null;
    const compauth = caE ? { result: caE.result, reason: caE.reason || caE.props.reason || '', raw: caE.text, src: caE.src.slice() } : null;

    const rows = dkim.concat(spf.absent ? [] : [spf]);
    const computed = computeDmarc(from, rows, dkim, spf, all, primary);
    dmarc.disagreement = compare(dmarc, computed, from, rows, arc, arcResult);

    const auth = { all, primary: primary ? all.indexOf(primary) : -1, primaryRule, exchangeOnline: exo, spf, dkim, signatures, receivedSpf, dmarc, computed, arc, arcResult, compauth, notes };
    authNotes(auth);
    return { auth, alignment: alignmentOf(from, dkim, spf, computed) };
  }

  // The page's own DMARC result: pass when SPF passed on an aligned
  // identifier or any DKIM passed on an aligned d=, otherwise fail, and
  // none when there is no trusted A-R or no single From domain. adkim and
  // aspf live in the DMARC record, which needs DNS, so relaxed (the
  // default) decides the result and strict is computed beside it.
  function computeDmarc(from, rows, dkim, spf, all, primary) {
    const c = { result: 'none', mode: 'relaxed', relaxed: null, strict: null, differ: false, by: { relaxed: [], strict: [] }, tags: [], src: [] };
    if (!from.defined) { c.why = from.why; c.src = from.src.slice(); return c; }
    if (!primary) { c.why = all.length ? 'no-trusted-results' : 'no-results'; return c; }
    const name = (r) => (r.kind === 'dkim' ? 'DKIM ' : 'SPF ') + r.domain;
    c.by.relaxed = rows.filter(r => r.modes.relaxed).map(name);
    c.by.strict = rows.filter(r => r.modes.strict).map(name);
    c.relaxed = c.by.relaxed.length > 0;
    c.strict = c.by.strict.length > 0;
    c.differ = c.relaxed !== c.strict;
    c.result = c.relaxed ? 'pass' : 'fail';
    // The tags that decide it when the modes differ.
    if (c.differ) {
      if (dkim.some(r => r.relaxedOnly)) c.tags.push('adkim');
      if (spf.relaxedOnly) c.tags.push('aspf');
    }
    c.src = Array.from(new Set(rows.filter(r => r.result).flatMap(r => r.src).concat(from.src))).sort((a, b) => a - b);
    c.why = '';
    return c;
  }

  // When the receiver's DMARC result and the computed one disagree, name
  // the likely reason instead of hiding it.
  function compare(dmarc, computed, from, rows, arc, arcResult) {
    const rep = dmarc.result;
    if (!['pass', 'fail'].includes(rep) || computed.result === 'none') return null;
    const src = Array.from(new Set(dmarc.src.concat(computed.src))).sort((a, b) => a - b);
    if (rep === computed.result) return null;
    if (rep === 'fail' && computed.differ) {
      return { reason: 'strict-mode', state: 'caveat', technical: 'The receiver reported dmarc=fail and the identifiers align only in relaxed mode, so the record most likely sets ' + computed.tags.map(t => t + '=s').join(' and ') + '. The DMARC record decides; this page cannot read it without DNS.', plain: 'The sending domain\'s DMARC record probably demands an exact domain match, and this message only matches the wider organization.', src };
    }
    const approx = rows.some(r => r.approximate) || from.approximate;
    const otherFrom = dmarc.headerFrom && dmarc.headerFrom !== from.domain;
    if (rep === 'fail') {
      // computed pass
      if (otherFrom) return { reason: 'org-domain', state: 'caveat', technical: 'The receiver evaluated header.from=' + dmarc.headerFrom + ', not ' + from.domain + ', so it checked a different author domain.', plain: 'The receiving system checked a different sender domain than the one shown here.', src };
      if (approx || rows.some(r => r.relaxedOnly)) return { reason: 'org-domain', state: 'caveat', technical: 'The pass here rests on relaxed alignment through the organizational domain ' + from.org + '. The receiver found a different organizational domain' + (approx ? ' (this page\'s suffix list does not cover this name, so its answer is an approximation)' : '') + '.', plain: 'The receiving system drew the line around the sender\'s organization differently from this page.', src };
      return { reason: 'local-policy', state: 'caveat', technical: 'The identifiers align and the receiver reported them as passing, yet it reported dmarc=fail. A local policy, or a result it did not write into these headers, is the likely reason.', plain: 'The checks line up, but the receiving system marked the message as failing anyway, probably because of its own rules.', src };
    }
    // reported pass, computed fail
    const preForward = arc.present && arc.instances[0] && arc.instances[0].preForward.some(x => x.method === 'dmarc' && x.result === 'pass');
    if ((arcResult && arcResult.result === 'pass') || (arc.state === 'pass' && preForward)) return { reason: 'arc-override', state: 'caveat', technical: 'Nothing aligned and passed at this receiver, but it trusted the ARC chain' + (arcResult ? ' (arc=' + arcResult.result + ')' : '') + ', whose earlier results show dmarc=pass before the forward. That is an ARC override.', plain: 'The message was forwarded, which broke its checks, and the receiver accepted the forwarder\'s word that they passed earlier.', src };
    if (otherFrom || approx) return { reason: 'org-domain', state: 'caveat', technical: 'The receiver ' + (otherFrom ? 'evaluated header.from=' + dmarc.headerFrom + ', not ' + from.domain : 'used a different organizational domain; this page\'s suffix list does not cover this name') + '.', plain: 'The receiving system drew the line around the sender\'s organization differently from this page.', src };
    return { reason: 'local-policy', state: 'caveat', technical: 'No reported pass aligns with ' + from.domain + ', yet the receiver reported dmarc=pass. A local policy, or a result it did not write into these headers, is the likely reason.', plain: 'The checks do not line up, but the receiving system passed the message anyway, probably because of its own rules.', src };
  }

  function alignmentOf(from, dkim, spf, computed) {
    const rows = dkim.concat([spf]);
    const notes = [];
    if (from.domain && rows.some(r => r.state === 'pass' && r.relaxedOnly)) {
      const r = rows.filter(x => x.state === 'pass' && x.relaxedOnly);
      notes.push(say('caveat', r.map(x => (x.kind === 'dkim' ? 'DKIM d=' : 'SPF ') + x.domain).join(' and ') + ' align' + (r.length === 1 ? 's' : '') + ' with ' + from.domain + ' only in relaxed mode, through the organizational domain ' + from.org + '. Under ' + (r.some(x => x.kind === 'dkim') ? 'adkim=s' : '') + (r.some(x => x.kind === 'dkim') && r.some(x => x.kind === 'spf') ? ' or ' : '') + (r.some(x => x.kind === 'spf') ? 'aspf=s' : '') + ' it would not count. The DMARC record decides.',
        'The signature belongs to the same organization as the sender but not to the exact same domain. That counts unless the domain\'s policy demands an exact match.', r.flatMap(x => x.src).concat(from.src)));
    }
    const approx = [from].concat(rows).filter(x => x.approximate && x.domain);
    if (approx.length) {
      notes.push(say('caveat', 'The organizational domain of ' + Array.from(new Set(approx.map(x => x.domain))).join(', ') + ' is an approximation without DNS: its suffix is outside this page\'s list, so a longer public suffix could apply and relaxed alignment could come out differently.', 'This page is not sure where the sender\'s organization begins for this kind of domain, so the relaxed match is a best guess.', from.src));
    }
    // Always beside the result: the page cannot see the alignment mode.
    const modeNote = computed.result === 'none' ? null : say('unknown', 'Alignment is computed in relaxed mode, the DMARC default, with strict mode beside it. adkim and aspf are set in the DMARC record, which is not in the headers.',
      'This page assumes the usual, looser domain match. The sender\'s policy can demand an exact match, and that setting is not in the headers.', computed.src);
    return { from, rows, notes, modeNote };
  }

  function authNotes(auth) {
    const n = auth.notes;
    const why = auth.computed.why;
    if (why === 'two-from' || why === 'multi-domain') {
      n.push(say('fail', why === 'two-from' ? 'With more than one From field there is no single author domain, so alignment is undefined and DMARC is not computed from either address.' : 'The From field holds addresses in more than one domain, so alignment is undefined and DMARC is not computed from any of them.',
        'The message does not name one clear sender, so this page cannot check whether the sender is genuine.', auth.computed.src));
    }
    if (auth.all.length && auth.primary < 0) {
      n.push(say('unknown', 'No Authentication-Results field here was written by the final receiver, so there are no reported results to recompute from.', 'None of the check results in these headers can be tied to the system that delivered the message.', auth.all.flatMap(r => r.src)));
    }
    if (!auth.all.length) {
      n.push(say('unknown', 'No Authentication-Results field. The receiver reported no SPF, DKIM or DMARC results here, so there is nothing to recompute; the alignment shows identifiers only.', 'The receiving mail system did not record any authentication checks in these headers.', []));
    }
    for (const r of auth.all) {
      if (r.trust === 'unverified') {
        n.push(say('unknown', r.authserv
          ? 'Authentication-Results from ' + r.authserv + ' is unverified: no Received by host in the chain matches it, so the sender could have added it. A hint, not a verdict.'
          : auth.exchangeOnline ? 'An Authentication-Results field with no authserv-id has no Received field below it to tie it to a host, so it is unverified.'
            : 'An Authentication-Results field with no authserv-id is unverified: that form is Exchange Online\'s, and these headers carry no X-MS-Exchange-Organization fields to show Exchange Online received the message.',
          'One set of check results cannot be tied to any server the message passed through. The sender could have written it.', r.src));
      } else if (r.trust === 'sender-side') {
        n.push(say('unknown', 'Authentication-Results from ' + (r.writer || 'an unnamed host') + ' was written at hop ' + (r.hopIdx + 1) + ', before the receiver took custody, so the receiver does not vouch for it.', 'One set of check results was written before the message reached the receiving mail system.', r.src));
      }
      if (r.matchedBy === 'position' && r.trust === 'receiver') {
        n.push(say('pass', 'Authentication-Results without an authserv-id (the Exchange Online form) sits beside the Received field of hop ' + (r.hopIdx + 1) + ', so ' + r.writer + ' wrote it. Microsoft names no host in this form, so the tie is by position.', 'Microsoft wrote these check results when the message arrived.', r.src));
      }
    }
    const arc = auth.arc;
    for (const p of arc.problems) n.push(say('fail', p.text, 'The forwarding record on this message is broken or incomplete, so the results it carries cannot be relied on.', p.src));
    if (arc.state === 'pass') {
      n.push(say('pass', 'ARC chain of ' + arc.instances.length + ' set' + (arc.instances.length === 1 ? '' : 's') + ' is intact: instances 1 to ' + arc.instances.length + ', cv=none at i=1' + (arc.instances.length > 1 ? ', cv=pass after' : '') + '. Sealed by ' + arc.instances.map(s => s.sealer.domain || '(unnamed)').join(', then ') + '. Seals are not verified here.',
        'The message carries a complete forwarding record from ' + arc.instances.map(s => s.sealer.domain || 'an unnamed system').join(' and ') + '.', arc.instances.flatMap(s => s.src)));
    }
    for (const sig of auth.signatures) for (const t of sig.notes) n.push(say('caveat', 'DKIM-Signature d=' + sig.d + ': ' + t, 'One of the message\'s signatures is set up in a weak or unusual way.', sig.src));
    const c = auth.computed;
    if (c.differ) {
      n.push(say('caveat', 'Computed DMARC passes in relaxed mode (' + c.by.relaxed.join(', ') + ') and fails in strict mode. The record\'s ' + c.tags.join(' and ') + ' decide' + (c.tags.length === 1 ? 's' : '') + '; relaxed is the default when the tag is absent.', 'Whether this passes depends on a setting in the sender\'s DMARC record that this page cannot see.', c.src));
    }
    if (auth.dmarc.disagreement) { const d = auth.dmarc.disagreement; n.push(say(d.state, d.technical, d.plain, d.src)); }
    if (auth.compauth) n.push(say('unknown', 'Microsoft composite authentication: compauth=' + auth.compauth.result + (auth.compauth.reason ? ' reason=' + auth.compauth.reason : '') + '. Shown raw; step 3 decodes the reason code.', 'Microsoft recorded its own combined check result. The next step explains it.', auth.compauth.src));
  }

  HA.auth = { resultState, parseAuthResults, parseReceivedSpf, parseDkimSignature, buildArc, buildAuth, alignRow, splitOutside };
  // Node: require() returns this layer; the browser reads HA instead.
  if (typeof module !== 'undefined' && module.exports) module.exports = HA.auth;
})(typeof globalThis !== 'undefined' ? globalThis : this);
