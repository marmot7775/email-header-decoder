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
  const IDS = ['header.d', 'header.i', 'header.s', 'smtp.mailfrom', 'smtp.helo', 'header.from'];

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
    const sig = { d: (tags.d || '').toLowerCase(), s: tags.s || '', i: tags.i || '', a: tags.a || '', c: tags.c || 'simple/simple', bh: tags.bh || '', h: (tags.h || '').toLowerCase(), t: int(tags.t), x: int(tags.x), l: int(tags.l), bPrefix: (tags.b || '').slice(0, 8) };
    sig.signedHeaders = sig.h.split(':').map(s => s.trim()).filter(Boolean);
    sig.notes = [];
    if (!sig.signedHeaders.includes('from')) sig.notes.push('h= does not list From, which RFC 6376 5.4 requires.');
    if (sig.l !== null) sig.notes.push('l= body length limit present; content appended after ' + sig.l + ' bytes is unsigned.');
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
  function readArField(f, chain) {
    const ar = parseAuthResults(f.value);
    const rec = { index: f.index, src: [f.index], authserv: ar.authserv, version: ar.version, none: ar.none, writer: ar.authserv, writerNamed: !!ar.authserv, hopIdx: -1, matchedBy: '', trust: 'unverified', primary: false, entries: [] };
    if (ar.authserv) Object.assign(rec, hopForHost(ar.authserv, chain));
    else {
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
    rec.entries = ar.results.map(r => ({ method: r.method, result: r.result, state: resultState(r.result), reason: r.reason, ids: r.ids, props: r.props, comments: r.comments, text: r.text, field: f.index, src: [f.index] }));
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
    return { present: instances.length > 0, instances, problems, state, sealers: instances.map(s => s.sealer.domain) };
  }

  // Alignment of one authenticated identifier with the From domain,
  // under both modes, plus the state its connector shows.
  function alignRow(kind, domain, result, from) {
    const L = HA.psl.lookup(domain);
    const strict = !!from.domain && !!L.domain && L.domain === from.domain;
    const relaxed = strict || (!!from.org && !!L.org && L.org === from.org);
    const passed = result === 'pass';
    let state, word;
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

  function buildAuth(fields, chain, message) {
    const fromInfo = message.from && message.from.domain ? HA.psl.lookup(message.from.domain) : { domain: '', org: '', approximate: false };
    const from = { domain: fromInfo.domain, org: fromInfo.org, approximate: fromInfo.approximate, src: message.from ? message.from.src.slice() : [] };
    const notes = [];

    const all = fields.filter(f => f.lower === 'authentication-results').map(f => readArField(f, chain));
    let primary = all.find(r => r.trust === 'receiver') || all[0] || null;
    if (primary) primary.primary = true;
    // The receiver's own fields. iCloud writes one field per method, so
    // results are gathered from all of them, the first per method winning.
    const receiverSet = all.filter(r => r.trust === 'receiver');
    const reportSet = receiverSet.length ? receiverSet : (primary ? [primary] : []);
    const reported = (method) => { for (const r of reportSet) { const es = r.entries.filter(e => e.method === method); if (es.length) return es; } return []; };

    const rspfFields = fields.filter(f => f.lower === 'received-spf');
    const receivedSpf = rspfFields.map(f => Object.assign(parseReceivedSpf(f.value), { src: [f.index] }));
    const dkimFields = fields.filter(f => f.lower === 'dkim-signature');
    const signatures = dkimFields.map(f => Object.assign(parseDkimSignature(f.value), { src: [f.index] }));
    const arc = buildArc(fields, chain);

    // SPF: the domain checked is smtp.mailfrom, else the envelope-from in
    // Received-SPF (the same identity), else the Return-Path.
    const spfE = reported('spf')[0] || null;
    const rspf = receivedSpf[0] || null;
    const rpF = fields.find(f => f.lower === 'return-path');
    const rp = rpF ? (P.parseAddresses(rpF.value)[0] || null) : null;
    let spfDomain = '', spfFrom = '', spfSrc = [];
    if (spfE && spfE.ids['smtp.mailfrom']) { spfDomain = P.domainOf(spfE.ids['smtp.mailfrom']); spfFrom = 'smtp.mailfrom'; spfSrc = spfE.src.slice(); }
    else if (rspf && rspf.props['envelope-from']) { spfDomain = P.domainOf(rspf.props['envelope-from']); spfFrom = 'Received-SPF envelope-from'; spfSrc = rspf.src.slice(); }
    else if (rp && rp.domain) { spfDomain = rp.domain; spfFrom = 'Return-Path'; spfSrc = [rpF.index]; }
    const spfResult = spfE ? spfE.result : rspf ? rspf.result : '';
    const spfResultSrc = spfE ? spfE.src : rspf ? rspf.src : [];
    const spf = Object.assign(alignRow('spf', spfDomain, spfResult, from), {
      identity: spfFrom, helo: spfE ? P.domainOf(spfE.ids['smtp.helo'] || '') : '', ip: (spfE && (spfE.props['smtp.remote-ip'] || spfE.props['client-ip'])) || (rspf && rspf.props['client-ip']) || '',
      reason: spfE ? spfE.reason : '', comments: spfE ? spfE.comments : rspf ? rspf.comments : [], reportedBy: spfE ? 'Authentication-Results' : rspf ? 'Received-SPF' : '',
      src: Array.from(new Set(spfSrc.concat(spfResultSrc))).sort((a, b) => a - b), absent: !spfDomain });

    // DKIM: every result the receiver reported, matched to a signature by
    // header.b, else by d= and s=. Signatures it reported nothing for follow.
    const used = new Set();
    const dkim = reported('dkim').map(e => {
      let d = P.domainOf(e.ids['header.d'] || e.ids['header.i'] || '');
      if (d === 'none') d = '';
      const s = e.ids['header.s'] || '';
      const b = (e.props['header.b'] || '').slice(0, 8);
      const sig = signatures.find(x => !used.has(x) && b && x.bPrefix === b) || signatures.find(x => !used.has(x) && x.d === d && (!s || x.s === s)) || null;
      if (sig) used.add(sig);
      if (!d && sig) d = sig.d;
      return Object.assign(alignRow('dkim', d, e.result, from), { selector: s || (sig ? sig.s : ''), reason: e.reason, comments: e.comments, signature: sig ? signatures.indexOf(sig) : -1, src: (sig ? [sig.src[0]] : []).concat(e.src).sort((a, b) => a - b), absent: !d });
    }).filter(r => !(r.absent && r.result === 'none'));
    for (const sig of signatures) {
      if (used.has(sig)) continue;
      dkim.push(Object.assign(alignRow('dkim', sig.d, '', from), { selector: sig.s, reason: '', comments: [], signature: signatures.indexOf(sig), src: sig.src.slice(), absent: false }));
    }

    // Reported DMARC, with the policy the receiver quoted.
    const dmarcE = reported('dmarc')[0] || null;
    const dmarc = { result: dmarcE ? dmarcE.result : '', state: resultState(dmarcE ? dmarcE.result : ''), headerFrom: dmarcE ? P.domainOf(dmarcE.ids['header.from'] || '') : '', policy: readPolicy(dmarcE), reason: dmarcE ? dmarcE.reason : '', comments: dmarcE ? dmarcE.comments : [], reported: !!dmarcE, src: dmarcE ? dmarcE.src.slice() : [] };

    const arcE = reported('arc')[0] || null;
    const arcResult = arcE ? { result: arcE.result, props: arcE.props, comments: arcE.comments, text: arcE.text, src: arcE.src.slice() } : null;
    const caE = reported('compauth')[0] || null;
    const compauth = caE ? { result: caE.result, reason: caE.reason || caE.props.reason || '', raw: caE.text, src: caE.src.slice() } : null;

    const rows = dkim.concat(spf.absent ? [] : [spf]);
    const computed = computeDmarc(from, rows, dkim, spf);
    dmarc.disagreement = compare(dmarc, computed, from, rows, arc, arcResult);

    const auth = { all, primary: primary ? all.indexOf(primary) : -1, spf, dkim, signatures, receivedSpf, dmarc, computed, arc, arcResult, compauth, notes };
    authNotes(auth);
    return { auth, alignment: alignmentOf(from, dkim, spf, computed) };
  }

  // The page's own DMARC result: pass when any method the receiver
  // reported as pass also aligns. adkim and aspf live in the DMARC record,
  // which needs DNS, so the result is worked out under both modes.
  function computeDmarc(from, rows, dkim, spf) {
    const c = { result: 'unknown', relaxed: null, strict: null, differ: false, by: { relaxed: [], strict: [] }, tags: [], src: [] };
    const reportedAny = rows.some(r => r.result);
    if (!from.domain || !reportedAny) { c.why = !from.domain ? 'no-from' : 'no-results'; return c; }
    const name = (r) => (r.kind === 'dkim' ? 'DKIM ' : 'SPF ') + r.domain;
    c.by.relaxed = rows.filter(r => r.modes.relaxed).map(name);
    c.by.strict = rows.filter(r => r.modes.strict).map(name);
    c.relaxed = c.by.relaxed.length > 0;
    c.strict = c.by.strict.length > 0;
    c.differ = c.relaxed !== c.strict;
    c.result = c.relaxed && c.strict ? 'pass' : !c.relaxed ? 'fail' : 'depends';
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
    if (!['pass', 'fail'].includes(rep) || computed.result === 'unknown') return null;
    const src = Array.from(new Set(dmarc.src.concat(computed.src))).sort((a, b) => a - b);
    if (rep === 'pass' && computed.result !== 'fail') return null;
    if (rep === 'fail' && computed.result === 'fail') return null;
    if (rep === 'fail' && computed.result === 'depends') {
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
    return { from, rows, notes };
  }

  function authNotes(auth) {
    const n = auth.notes;
    if (!auth.all.length) {
      n.push(say('unknown', 'No Authentication-Results field. The receiver reported no SPF, DKIM or DMARC results here, so there is nothing to recompute; the alignment shows identifiers only.', 'The receiving mail system did not record any authentication checks in these headers.', []));
    }
    for (const r of auth.all) {
      if (r.trust === 'unverified') {
        n.push(say('unknown', r.authserv
          ? 'Authentication-Results from ' + r.authserv + ' is unverified: no Received by host in the chain matches it, so the sender could have added it. A hint, not a verdict.'
          : 'An Authentication-Results field with no authserv-id has no Received field below it to tie it to a host, so it is unverified.',
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
    if (c.result === 'depends') {
      n.push(say('caveat', 'Computed DMARC passes in relaxed mode (' + c.by.relaxed.join(', ') + ') and fails in strict mode. The record\'s ' + c.tags.join(' and ') + ' decide' + (c.tags.length === 1 ? 's' : '') + '; relaxed is the default when the tag is absent.', 'Whether this passes depends on a setting in the sender\'s DMARC record that this page cannot see.', c.src));
    }
    if (auth.dmarc.disagreement) { const d = auth.dmarc.disagreement; n.push(say(d.state, d.technical, d.plain, d.src)); }
    if (auth.compauth) n.push(say('unknown', 'Microsoft composite authentication: compauth=' + auth.compauth.result + (auth.compauth.reason ? ' reason=' + auth.compauth.reason : '') + '. Shown raw; step 3 decodes the reason code.', 'Microsoft recorded its own combined check result. The next step explains it.', auth.compauth.src));
  }

  HA.auth = { resultState, parseAuthResults, parseReceivedSpf, parseDkimSignature, buildArc, buildAuth, alignRow, splitOutside };
  // Node: require() returns this layer; the browser reads HA instead.
  if (typeof module !== 'undefined' && module.exports) module.exports = HA.auth;
})(typeof globalThis !== 'undefined' ? globalThis : this);
