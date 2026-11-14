// dkimkey.js: the DKIM key check the reader starts with a button. Looks up
// selector._domainkey.domain over DNS over HTTPS, reads the key record
// (RFC 6376 3.6.1), and verifies each signature again with dkimverify.js.
// fetch and WebCrypto are passed in, so the tests make no network calls.
// Nothing here runs on paste, on page load, or for a built-in sample; the
// page calls checkAll only when the button is pressed. The query carries
// the name and type=TXT, nothing else.
(function (root) {
  'use strict';
  const HA = (root.HA = root.HA || {});
  const P = HA.parse;
  const V = HA.dkimverify;

  const DOH = 'https://cloudflare-dns.com/dns-query';
  const TIMEOUT_MS = 6000;
  // A name this page will query: DNS labels only, nothing a paste could
  // smuggle into the request.
  const NAME_OK = /^(?=.{1,253}$)([A-Za-z0-9_](?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?\.)+[A-Za-z0-9-]{1,63}$/;

  // TXT data as DNS over HTTPS JSON writes it: one or more quoted strings.
  // RFC 6376 3.6.2.2: the strings join with nothing between them.
  function txtJoin(data) {
    const s = String(data || '');
    const parts = [];
    const re = /"((?:[^"\\]|\\.)*)"/g;
    let m;
    while ((m = re.exec(s))) parts.push(m[1].replace(/\\(\d{3})/g, (x, d) => String.fromCharCode(+d)).replace(/\\(.)/g, '$1'));
    return parts.length ? parts.join('') : s;
  }

  // One TXT lookup. Resolves to { status, records, cname, target, rcode }:
  // status is ok, nxdomain, nodata, servfail, timeout or error. cname lists
  // the names the answer passed through, and target is the last of them.
  async function lookup(name, fetchFn, opts) {
    const timeoutMs = (opts && opts.timeoutMs) || TIMEOUT_MS;
    const base = { name, records: [], cname: [], target: '', rcode: null };
    if (!NAME_OK.test(name)) return Object.assign(base, { status: 'error', why: 'not a DNS name' });
    let timer;
    const ctl = typeof AbortController !== 'undefined' ? new AbortController() : null;
    const timeout = new Promise(resolve => { timer = setTimeout(() => { if (ctl) ctl.abort(); resolve('timeout'); }, timeoutMs); });
    try {
      const req = fetchFn(DOH + '?name=' + encodeURIComponent(name) + '&type=TXT', { headers: { accept: 'application/dns-json' }, signal: ctl ? ctl.signal : undefined, credentials: 'omit', referrerPolicy: 'no-referrer' })
        .then(r => r.ok ? r.json() : { httpStatus: r.status });
      const res = await Promise.race([req, timeout]);
      if (res === 'timeout') return Object.assign(base, { status: 'timeout' });
      if (res.httpStatus) return Object.assign(base, { status: 'error', why: 'HTTP ' + res.httpStatus });
      base.rcode = res.Status;
      // A CNAME chain is in the answer even when its end does not exist.
      const answers = Array.isArray(res.Answer) ? res.Answer : [];
      for (const a of answers) if (a.type === 5) base.cname.push(String(a.data || '').replace(/\.$/, '').toLowerCase());
      base.target = base.cname.length ? base.cname[base.cname.length - 1] : '';
      if (res.Status === 3) return Object.assign(base, { status: 'nxdomain' });
      if (res.Status !== 0) return Object.assign(base, { status: 'servfail', why: 'RCODE ' + res.Status });
      base.records = answers.filter(a => a.type === 16).map(a => txtJoin(a.data));
      return Object.assign(base, { status: base.records.length ? 'ok' : 'nodata' });
    } catch (e) {
      return Object.assign(base, { status: ctl && ctl.signal.aborted ? 'timeout' : 'error', why: 'no response' });
    } finally {
      clearTimeout(timer);
    }
  }

  // A key record per RFC 6376 3.6.1 (and RFC 8463 4 for k=ed25519).
  // Returns { ok, revoked, error, v, k, h, s, t, testing, strict, bits, rsa, ed }.
  function parseKey(txt) {
    const { tags, order } = P.parseTagList(txt);
    const key = { raw: txt, v: tags.v, k: (tags.k || 'rsa').toLowerCase(), h: tags.h ? tags.h.toLowerCase().split(':').filter(Boolean) : null, s: tags.s ? tags.s.toLowerCase().split(':').filter(Boolean) : null, t: tags.t ? tags.t.toLowerCase().split(':').filter(Boolean) : [], ok: false, revoked: false, error: '', bits: null, rsa: null, ed: null };
    key.testing = key.t.includes('y');
    key.strict = key.t.includes('s');
    const bad = (error) => Object.assign(key, { error });
    if (tags.v !== undefined && tags.v !== 'DKIM1') return bad('v=' + tags.v + ' is not DKIM1');
    if (tags.v !== undefined && order[0] !== 'v') return bad('v= is not the first tag');
    if (!('p' in tags)) return bad('there is no p= tag');
    if (tags.p === '') return Object.assign(key, { revoked: true });
    const bytes = V.b64decode(tags.p);
    if (!bytes || !bytes.length) return bad('p= is not base64');
    if (key.k === 'rsa') {
      const r = V.rsaKey(bytes);
      if (!r) return bad('p= is not an RSA public key in DER form');
      if (r.notRsa) return bad('p= holds a key that is not RSA, though k=rsa');
      return Object.assign(key, { ok: true, rsa: r, bits: r.bits });
    }
    if (key.k === 'ed25519') {
      if (bytes.length !== 32) return bad('p= is ' + bytes.length + ' bytes, and an Ed25519 key is 32');
      return Object.assign(key, { ok: true, ed: bytes, bits: 256 });
    }
    return bad('k=' + key.k + ' is not a key type this page knows');
  }

  // The message as DKIM reads it: the fields byte for byte as they were
  // given, joined with CRLF, and the body when there is one.
  function exactMessage(text, opts) {
    const parsed = P.parseHeaders(text);
    const lines = P.exactLines(text);
    const fields = parsed.fields.map(f => ({ index: f.index, lower: f.lower, exact: lines.slice(f.lines[0], f.lines[1] + 1).join('\r\n') }));
    // A paste that ends after the headers has no body to hash; an empty
    // line at its end is not one.
    const bodyPresent = parsed.bodyStart >= 0 && !!parsed.bodyPresent;
    const body = bodyPresent && !(opts && opts.truncated) ? lines.slice(parsed.bodyStart).join('\r\n') : null;
    return { fields, body, bodyPresent, encoding: (opts && opts.encoding) || 'utf8', parsed };
  }

  const ALGS = { 'rsa-sha256': 'rsa', 'ed25519-sha256': 'ed25519' };

  // One signature against one key record. Resolves to an outcome:
  // too-short, malformed, pass, no-body, body-mismatch, header-changed,
  // key-mismatch, ed25519-fail or unsupported, with the facts behind it.
  async function verifyWith(msg, sig, key, subtle) {
    const kind = ALGS[sig.a];
    if (!key.ok) return { outcome: 'malformed', why: key.error };
    if (key.k !== kind) return { outcome: 'malformed', why: 'k=' + key.k + ' cannot check a=' + sig.a, permfail: 'inappropriate key algorithm' };
    if (key.h && !key.h.includes('sha256')) return { outcome: 'malformed', why: 'h=' + key.h.join(':') + ' does not allow sha256', permfail: 'inappropriate hash algorithm' };
    if (key.s && !key.s.includes('*') && !key.s.includes('email')) return { outcome: 'malformed', why: 's=' + key.s.join(':') + ' does not allow email' };
    if (key.strict && sig.i && P.domainOf(sig.i) !== sig.d) return { outcome: 'malformed', why: 't=s requires the i= domain to equal d=, and i=' + sig.i + ' does not' };
    if (kind === 'rsa' && key.bits < 1024) return { outcome: 'too-short' };
    const h = V.hashes(msg, sig);
    const sigBytes = V.b64decode(sig.b);
    const facts = { body: h.body, signedCount: h.signedCount, listed: h.listed, c: h.hmode + '/' + h.bmode };
    let headerOk;
    if (kind === 'rsa') {
      const r = V.rsaCheck(key.rsa, sigBytes, h.headerHash);
      if (r === 'bad-padding') return Object.assign(facts, { outcome: 'key-mismatch' });
      if (r === 'other-hash') return Object.assign(facts, { outcome: 'header-changed' });
      headerOk = true;
    } else {
      if (!subtle) return Object.assign(facts, { outcome: 'unsupported' });
      const r = sigBytes && sigBytes.length === 64 ? await V.ed25519Check(subtle, key.ed, sigBytes, h.headerHash) : false;
      if (r === null) return Object.assign(facts, { outcome: 'unsupported' });
      if (!r) return Object.assign(facts, { outcome: 'ed25519-fail' });
      headerOk = true;
    }
    if (headerOk && !h.body) return Object.assign(facts, { outcome: 'no-body' });
    if (!h.body.matches) return Object.assign(facts, { outcome: 'body-mismatch' });
    return Object.assign(facts, { outcome: 'pass' });
  }

  const MONTHS = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'];
  // The reader's own date, as the page writes it: November 13, 2026.
  function dayOf(ms) { const d = new Date(ms); return MONTHS[d.getMonth()] + ' ' + d.getDate() + ', ' + d.getFullYear(); }

  // Check every DKIM-Signature in the text. opts: { source: file | paste,
  // encoding, truncated, now, day, subtle, timeoutMs }. The signatures are
  // read here the way auth.js reads them, so result i is auth.signatures[i].
  async function checkAll(text, fetchFn, opts) {
    opts = opts || {};
    const msg = exactMessage(text, opts);
    const sigs = msg.parsed.fields.filter(f => f.lower === 'dkim-signature').map(f => Object.assign(HA.auth.parseDkimSignature(f.value), { src: [f.index] }));
    const exactOf = (sig) => { const f = msg.fields.find(x => x.index === sig.src[0]); return f ? f.exact : ''; };
    const cache = new Map();
    const results = await Promise.all(sigs.map(async (sig, index) => {
      const alg = String(sig.a || '').toLowerCase();
      const base = { signature: index, d: sig.d, s: sig.s, a: alg, l: sig.l, name: sig.s && sig.d ? sig.s + '._domainkey.' + sig.d : '' };
      if (/sha1/.test(alg)) return Object.assign(base, { outcome: 'sha1' });
      if (!ALGS[alg]) return Object.assign(base, { outcome: 'unknown-alg' });
      if (!sig.d || !sig.s || !sig.b || !sig.bh || !sig.h || !NAME_OK.test(base.name)) return Object.assign(base, { outcome: 'incomplete' });
      if (!cache.has(base.name)) cache.set(base.name, lookup(base.name, fetchFn, opts));
      const dns = await cache.get(base.name);
      Object.assign(base, { dns: { status: dns.status, cname: dns.cname, target: dns.target, why: dns.why || '', records: dns.records.length } });
      if (dns.status === 'nxdomain' || dns.status === 'nodata') return Object.assign(base, { outcome: 'no-key' });
      if (dns.status !== 'ok') return Object.assign(base, { outcome: 'dns-failed' });
      // A wildcard or a stray TXT at the name is not a key, and a verifier
      // ignores malformed key records (RFC 6376 6.1.2).
      const keys = dns.records.map(parseKey);
      const usable = keys.filter(k => k.ok || k.revoked);
      if (!usable.length) return Object.assign(base, { outcome: 'malformed', why: keys[0].error });
      if (usable.every(k => k.revoked)) return Object.assign(base, { outcome: 'revoked' });
      // Several records: RFC 6376 6.1.2 step 4 lets a verifier try each.
      let first = null;
      for (const key of usable.filter(k => !k.revoked)) {
        const r = Object.assign(await verifyWith(msg, Object.assign({}, sig, { a: alg, exact: exactOf(sig) }), key, opts.subtle), { k: key.k, bits: key.bits, testing: key.testing });
        if (!first) first = r;
        if (r.outcome === 'pass' || r.outcome === 'no-body') return Object.assign(base, r);
      }
      return Object.assign(base, first);
    }));
    const at = opts.now !== undefined ? opts.now : Date.now();
    return { at, day: opts.day || dayOf(at), source: opts.source === 'file' ? 'file' : 'paste', truncated: !!opts.truncated, bodyPresent: msg.bodyPresent, results };
  }

  HA.dkimkey = { DOH, lookup, txtJoin, parseKey, exactMessage, verifyWith, checkAll, dayOf, NAME_OK };
  // Node: require() returns this layer; the browser reads HA instead.
  if (typeof module !== 'undefined' && module.exports) module.exports = HA.dkimkey;
})(typeof globalThis !== 'undefined' ? globalThis : this);
