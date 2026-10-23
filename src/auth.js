// auth.js: Authentication-Results (RFC 8601), Received-SPF, DKIM-Signature,
// the ARC set (RFC 8617), and DMARC identifier alignment (RFC 7489 3.1).
// Nothing here verifies a signature or queries DNS. It reads what the
// receiving systems wrote and works out alignment from the identifiers.
(function (root) {
  'use strict';
  const HA = (root.HA = root.HA || {});
  const P = HA.parse;

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

  function parseAuthResults(value) {
    const out = { raw: value, authserv: '', version: '', instance: null, results: [], none: false };
    const parts = splitOutside(value, ';').map(s => s.trim()).filter(s => s !== '');
    if (!parts.length) return out;
    let head = parts.shift();
    let m = /^i\s*=\s*(\d+)$/i.exec(P.stripComments(head));
    if (m) { out.instance = parseInt(m[1], 10); head = parts.shift() || ''; }
    const headStripped = P.stripComments(head);
    if (/^[A-Za-z0-9-]+\s*=\s*[A-Za-z0-9_-]+/.test(headStripped)) {
      // Exchange Online writes no authserv-id: the value starts with spf=.
      out.authserv = '';
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
      const r = { method: mm[1].toLowerCase(), result: mm[2].toLowerCase(), props: {}, comments: P.extractComments(part), reason: '' };
      let pm;
      const tail = stripped.slice(mm[0].length);
      PROP_RE.lastIndex = 0;
      while ((pm = PROP_RE.exec(tail))) {
        const key = pm[1].toLowerCase();
        const val = pm[2].replace(/^"|"$/g, '');
        if (key === 'reason') r.reason = val; else r.props[key] = val;
      }
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

  function parseDkimSignature(value) {
    const { tags } = P.parseTagList(value);
    const sig = { raw: value, tags, d: (tags.d || '').toLowerCase(), s: tags.s || '', a: tags.a || '', c: tags.c || 'simple/simple', h: (tags.h || '').toLowerCase(), i: tags.i || '', t: tags.t ? parseInt(tags.t, 10) : null, x: tags.x ? parseInt(tags.x, 10) : null, l: tags.l ? parseInt(tags.l, 10) : null, bPrefix: (tags.b || '').slice(0, 8), signedHeaders: (tags.h || '').toLowerCase().split(':').filter(Boolean) };
    sig.notes = [];
    if (!sig.signedHeaders.includes('from')) sig.notes.push('h= does not list From, which RFC 6376 5.4 requires.');
    if (sig.l !== null) sig.notes.push('l= body length limit present; content appended after ' + sig.l + ' bytes is unsigned.');
    if (sig.x && sig.t && sig.x < sig.t) sig.notes.push('x= expiry is earlier than t= timestamp.');
    if (/sha1/i.test(sig.a)) sig.notes.push('rsa-sha1 is historic (RFC 8301); receivers may ignore it.');
    return sig;
  }

  function buildArc(fields) {
    const sets = {};
    for (const f of fields) {
      if (f.lower === 'arc-seal' || f.lower === 'arc-message-signature') {
        const { tags } = P.parseTagList(f.value);
        const i = parseInt(tags.i, 10);
        if (!i) continue;
        sets[i] = sets[i] || { i };
        if (f.lower === 'arc-seal') sets[i].seal = { cv: (tags.cv || '').toLowerCase(), d: (tags.d || '').toLowerCase(), s: tags.s || '', t: tags.t ? parseInt(tags.t, 10) : null, a: tags.a || '' };
        else sets[i].ams = { d: (tags.d || '').toLowerCase(), s: tags.s || '', h: (tags.h || '').toLowerCase() };
      } else if (f.lower === 'arc-authentication-results') {
        const ar = parseAuthResults(f.value);
        const i = ar.instance;
        if (!i) continue;
        sets[i] = sets[i] || { i };
        sets[i].aar = ar;
      }
    }
    const chain = Object.keys(sets).map(Number).sort((a, b) => a - b).map(i => sets[i]);
    const problems = [];
    chain.forEach((set, idx) => {
      if (set.i !== idx + 1) problems.push('ARC instances are not contiguous at i=' + set.i + '.');
      if (!set.seal || !set.ams || !set.aar) problems.push('ARC set i=' + set.i + ' is incomplete (needs Seal, Message-Signature and Authentication-Results).');
      if (set.seal) {
        if (set.i === 1 && set.seal.cv !== 'none') problems.push('ARC-Seal i=1 should carry cv=none, found cv=' + (set.seal.cv || 'missing') + '.');
        if (set.i > 1 && set.seal.cv !== 'pass') problems.push('ARC-Seal i=' + set.i + ' carries cv=' + (set.seal.cv || 'missing') + '; the chain was already broken when this sealer saw it.');
      }
    });
    return { chain, problems, present: chain.length > 0, sealers: chain.map(s => (s.seal && s.seal.d) || (s.ams && s.ams.d) || '') };
  }

  // Alignment between the From domain and the authenticated identifiers.
  function alignment(fromDomain, identDomain, mode) {
    if (!fromDomain || !identDomain) return { aligned: false, strict: false, relaxed: false, mode };
    const strict = fromDomain === identDomain;
    const relaxed = strict || HA.psl.orgDomain(fromDomain) === HA.psl.orgDomain(identDomain);
    const aligned = mode === 's' ? strict : relaxed;
    return { aligned, strict, relaxed, mode };
  }

  function domainFromProp(props, keys) {
    for (const k of keys) if (props[k]) return P.domainOf(props[k]);
    return '';
  }

  // Pick the receiving system's Authentication-Results. The first one
  // in header order was written last, by the system closest to the
  // mailbox. RFC 8601 7.1 warns that lower ones can be forged by a
  // sender, so the top one is primary and the rest are shown as history.
  function buildAuth(fields, fromDomain) {
    const arFields = fields.filter(f => f.lower === 'authentication-results');
    const all = arFields.map(f => parseAuthResults(f.value));
    const primary = all[0] || null;
    const spfHeaders = fields.filter(f => f.lower === 'received-spf').map(f => parseReceivedSpf(f.value));
    const dkimSigs = fields.filter(f => f.lower === 'dkim-signature').map(f => parseDkimSignature(f.value));
    const arc = buildArc(fields);

    const get = (method) => primary ? primary.results.filter(r => r.method === method) : [];
    const spfR = get('spf')[0] || null;
    const dkimR = get('dkim');
    const dmarcR = get('dmarc')[0] || null;
    const arcR = get('arc')[0] || null;
    const compauth = get('compauth')[0] || null;
    const iprev = get('iprev')[0] || null;

    // DMARC policy as the receiver reported it. Google writes
    // (p=REJECT sp=REJECT dis=NONE); Microsoft writes action=none.
    const policy = { p: '', sp: '', adkim: 'r', aspf: 'r', dis: '', action: '', source: '' };
    if (dmarcR) {
      const text = dmarcR.comments.join(' ');
      const grab = (k) => { const m = new RegExp('\\b' + k + '=([A-Za-z0-9]+)', 'i').exec(text); return m ? m[1].toLowerCase() : ''; };
      policy.p = grab('p'); policy.sp = grab('sp'); policy.dis = grab('dis');
      if (grab('adkim')) policy.adkim = grab('adkim')[0];
      if (grab('aspf')) policy.aspf = grab('aspf')[0];
      if (dmarcR.props['policy.dmarc']) policy.p = dmarcR.props['policy.dmarc'].toLowerCase();
      if (dmarcR.props['policy.adkim']) policy.adkim = dmarcR.props['policy.adkim'][0].toLowerCase();
      if (dmarcR.props['policy.aspf']) policy.aspf = dmarcR.props['policy.aspf'][0].toLowerCase();
      if (dmarcR.props.action) policy.action = dmarcR.props.action.toLowerCase();
      policy.source = policy.p ? 'reported' : (policy.action ? 'action' : 'unknown');
    }

    // SPF identifier: smtp.mailfrom, else Received-SPF envelope-from, else Return-Path.
    const returnPath = fields.find(f => f.lower === 'return-path');
    const rpAddr = returnPath ? (P.parseAddresses(returnPath.value)[0] || null) : null;
    let spfDomain = spfR ? domainFromProp(spfR.props, ['smtp.mailfrom', 'smtp.helo']) : '';
    let spfIdentity = spfR && spfR.props['smtp.mailfrom'] ? 'mailfrom' : (spfR && spfR.props['smtp.helo'] ? 'helo' : '');
    if (!spfDomain && spfHeaders[0]) { spfDomain = P.domainOf(spfHeaders[0].props['envelope-from'] || ''); spfIdentity = spfDomain ? 'mailfrom' : ''; }
    if (!spfDomain && rpAddr && rpAddr.domain) { spfDomain = rpAddr.domain; spfIdentity = 'return-path'; }
    const spfResult = spfR ? spfR.result : (spfHeaders[0] ? spfHeaders[0].result : '');
    const spf = { result: spfResult, domain: spfDomain, identity: spfIdentity, align: alignment(fromDomain, spfDomain, policy.aspf), ip: (spfR && (spfR.props['smtp.remote-ip'] || spfR.props['client-ip'])) || (spfHeaders[0] && spfHeaders[0].props['client-ip']) || '', comments: spfR ? spfR.comments : (spfHeaders[0] ? spfHeaders[0].comments : []), reported: !!spfR || !!spfHeaders[0] };

    // DKIM: every result the receiver wrote, matched to a signature when possible.
    const dkim = dkimR.map(r => {
      const d = domainFromProp(r.props, ['header.d', 'header.i']);
      const s = r.props['header.s'] || '';
      const b = (r.props['header.b'] || '').slice(0, 8);
      const sig = dkimSigs.find(x => (b && x.bPrefix === b) || (x.d === d && (!s || x.s === s))) || null;
      return { result: r.result, domain: d, selector: s || (sig ? sig.s : ''), align: alignment(fromDomain, d, policy.adkim), comments: r.comments, reason: r.reason, signature: sig, matched: !!sig };
    });
    // Signatures with no result from the receiver.
    const unreported = dkimSigs.filter(sig => !dkim.some(x => x.signature === sig)).map(sig => ({ result: '', domain: sig.d, selector: sig.s, align: alignment(fromDomain, sig.d, policy.adkim), comments: [], reason: '', signature: sig, matched: true, unreported: true }));

    const dmarc = { result: dmarcR ? dmarcR.result : '', fromDomain: dmarcR ? domainFromProp(dmarcR.props, ['header.from']) : '', policy, reported: !!dmarcR, comments: dmarcR ? dmarcR.comments : [], reason: dmarcR ? dmarcR.reason : '' };

    // What DMARC should be from the identifiers, independent of what was reported.
    const spfPassAligned = spf.result === 'pass' && spf.align.aligned;
    const dkimPassAligned = dkim.filter(x => x.result === 'pass' && x.align.aligned);
    const computed = { pass: spfPassAligned || dkimPassAligned.length > 0, bySpf: spfPassAligned, byDkim: dkimPassAligned.length > 0, dkimDomains: dkimPassAligned.map(x => x.domain) };

    return { all, primary, spf, dkim: dkim.concat(unreported), dkimSignatures: dkimSigs, dmarc, computed, arc, arcResult: arcR ? { result: arcR.result, props: arcR.props, comments: arcR.comments } : null, compauth: compauth ? { result: compauth.result, reason: compauth.reason || compauth.props.reason || '', comments: compauth.comments } : null, iprev: iprev ? { result: iprev.result, props: iprev.props, comments: iprev.comments } : null, returnPath: rpAddr, receivedSpf: spfHeaders };
  }

  HA.auth = { parseAuthResults, parseReceivedSpf, parseDkimSignature, buildArc, buildAuth, alignment, splitOutside };
})(typeof globalThis !== 'undefined' ? globalThis : this);
