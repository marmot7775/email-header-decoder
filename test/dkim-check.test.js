'use strict';
// The signature check: key lookup (src/dkimkey.js), verification
// (src/dkimverify.js), and what the finding says about it. Keys are made
// here and every message is synthetic. fetch is a stand-in, so no test
// touches the network.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { HA, fixture } = require('./load.js');
const K = HA.dkimkey, V = HA.dkimverify;

const rsa = (bits) => crypto.generateKeyPairSync('rsa', { modulusLength: bits });
const RSA = rsa(2048), RSA2 = rsa(2048), RSA1024 = rsa(1024), RSA512 = rsa(512), ED = crypto.generateKeyPairSync('ed25519');
const rsaP = (k) => k.publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
const edP = (k) => Buffer.from(k.publicKey.export({ format: 'jwk' }).x, 'base64url').toString('base64');
const rec = (k) => 'v=DKIM1; k=rsa; p=' + rsaP(k);

// A signer written apart from the code under test (RFC 6376 3.4 and 3.7).
const relaxH = (f) => { const i = f.indexOf(':'); return f.slice(0, i).trim().toLowerCase() + ':' + f.slice(i + 1).replace(/\r\n/g, '').replace(/[ \t]+/g, ' ').trim(); };
function canonB(body, mode) {
  let b = body;
  if (mode === 'relaxed') b = b.split('\r\n').map(l => l.replace(/[ \t]+/g, ' ').replace(/ $/, '')).join('\r\n');
  b = b.replace(/(\r\n)+$/, '');
  return mode === 'relaxed' && b === '' ? '' : b + '\r\n';
}
function sign(headers, body, o) {
  o = Object.assign({ d: 'shop.example', s: 's1', c: 'relaxed/relaxed', h: ['from', 'to', 'subject', 'date', 'message-id'], key: RSA, alg: 'rsa-sha256' }, o);
  const [hc, bc] = o.c.split('/');
  let cb = Buffer.from(canonB(body, bc || 'simple'), 'latin1');
  if (o.l !== undefined) cb = cb.subarray(0, o.l);
  const bh = crypto.createHash('sha256').update(cb).digest('base64');
  const stub = 'DKIM-Signature: v=1; a=' + o.alg + '; c=' + o.c + '; d=' + o.d + ';\r\n s=' + o.s + '; h=' + o.h.join(' : ') + ';' + (o.l !== undefined ? ' l=' + o.l + ';' : '') + '\r\n bh=' + bh + ';\r\n b=';
  const used = new Set();
  const picked = [];
  for (const n of o.h) for (let i = headers.length - 1; i >= 0; i--) if (!used.has(i) && headers[i].toLowerCase().startsWith(n + ':')) { used.add(i); picked.push(headers[i]); break; }
  const canon = (f) => hc === 'relaxed' ? relaxH(f) : f;
  const data = Buffer.from(picked.map(f => canon(f) + '\r\n').join('') + canon(stub), 'latin1');
  const sig = o.alg === 'rsa-sha256' ? crypto.sign('sha256', data, o.key.privateKey) : crypto.sign(null, crypto.createHash('sha256').update(data).digest(), o.key.privateKey);
  const b64 = sig.toString('base64');
  return stub + b64.slice(0, 60) + '\r\n ' + b64.slice(60); // b= folded across two lines
}

const HEAD = ['From: Shop <orders@shop.example>', 'To: pat@receiver.example', 'Subject: Your order  has shipped', 'Date: Fri, 23 Oct 2026 09:14:00 +0000', 'Message-ID: <k1@shop.example>'];
const BODY = 'Hello Pat,\r\n\r\nYour order is on its way. \r\n\r\n-- \r\nThe shop\r\n\r\n';
const TOP = (dkim) => ['Received: from o1.sender.example (o1.sender.example [203.0.113.90]) by mx.receiver.example with ESMTPS id c1 for <pat@receiver.example>; Fri, 23 Oct 2026 09:14:02 +0000',
  'Authentication-Results: mx.receiver.example; dkim=' + dkim + ' header.d=shop.example header.s=s1; spf=pass smtp.mailfrom=b-1@bounce.mailer.example; dmarc=' + (dkim === 'pass' ? 'pass' : 'fail') + ' (p=REJECT sp=REJECT dis=NONE) header.from=shop.example'];
// A whole message: receiver fields, the signature, the signed fields, the body.
function eml(o) {
  o = o || {};
  const headers = o.headers || HEAD;
  const body = o.body === undefined ? BODY : o.body;
  const sig = sign(headers, body === null ? '' : body, o);
  return TOP(o.recorded || 'fail').concat([sig], o.after || headers).join('\r\n') + '\r\n' + (body === null ? '' : '\r\n' + (o.sentBody === undefined ? body : o.sentBody));
}

// A stand-in for fetch over a table of name: answer.
function dns(table, seen) {
  return (url, init) => {
    if (seen) seen.push({ url, init });
    const name = new URL(url).searchParams.get('name');
    const a = table[name];
    if (a === 'hang') return new Promise(() => {});
    if (a === 'http500') return Promise.resolve({ ok: false, status: 500, json: async () => ({}) });
    if (a === 'throw') return Promise.reject(new TypeError('Failed to fetch'));
    const json = a === undefined ? { Status: 3 } : a === 'nodata' ? { Status: 0 } : a === 'servfail' ? { Status: 2 } : a.Status !== undefined ? a : { Status: 0, Answer: [].concat(a).map(x => typeof x === 'string' ? { name, type: 16, data: /^"/.test(x) ? x : '"' + x + '"' } : x) };
    return Promise.resolve({ ok: true, status: 200, json: async () => json });
  };
}
const NAME = 's1._domainkey.shop.example';
const subtle = crypto.webcrypto.subtle;
const check = (text, table, o) => K.checkAll(text, dns(table), Object.assign({ source: 'file', subtle, now: Date.UTC(2026, 10, 13, 12), day: 'November 13, 2026' }, o));
const one = async (text, table, o) => (await check(text, table, o)).results[0];
const found = (text, c) => HA.analyze(text, { keyCheck: c }).finding;

test('RFC 8463 Appendix A: the published message verifies under both published keys', async () => {
  const table = {
    'brisbane._domainkey.football.example.com': 'v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=',
    'test._domainkey.football.example.com': '"v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDkHlOQoBTzWR" "iGs5V6NpP3idY6Wk08a5qhdR6wy5bdOKb2jLQiY/J16JYi0Qvx/byYzCNb3W91y3FutAC" "DfzwQ/BC/e/8uBsCR+yz1Lxj+PL6lHvqMKrM3rG4hstT5QjvHO9PzoxZyVYLzBfO2EeC3" "Ip3G+2kryOTIKT+l/K4w3QIDAQAB"',
  };
  const text = fixture('rfc8463-a3.eml');
  const c = await check(text, table);
  assert.deepEqual(c.results.map(r => [r.a, r.outcome, r.k, r.bits]), [['ed25519-sha256', 'pass', 'ed25519', 256], ['rsa-sha256', 'pass', 'rsa', 1024]]);
  // h= lists from, subject and date twice; the extra listings add nothing (RFC 6376 5.4.2)
  assert.deepEqual([c.results[0].signedCount, c.results[0].listed], [5, 8]);
  // The 1024-bit key works and is shorter than RFC 8301 3.2 recommends
  const kc = found(text, c).keyCheck;
  assert.equal(kc.results[0].notes.length, 0);
  assert.match(kc.results[1].notes[0].technical, /1024 bits\. RFC 8301 3\.2 says signers SHOULD use RSA keys of at least 2048 bits/);
  assert.match(kc.results[1].notes[0].plain, /shorter than mail systems now recommend/);
});

test('verify: every canonicalization pair passes, with a folded DKIM-Signature', async () => {
  for (const c of ['simple/simple', 'simple/relaxed', 'relaxed/simple', 'relaxed/relaxed', 'simple', 'relaxed']) {
    const r = await one(eml({ c }), { [NAME]: rec(RSA) });
    assert.equal(r.outcome, 'pass', c);
    assert.equal(r.body.matches, true, c);
  }
});

test('verify: relaxed forgives whitespace a relay changed, simple does not', async () => {
  const loose = (c) => eml({ c }).replace('Subject: Your order  has shipped', 'Subject:   Your order has shipped  ').replace('on its way. \r\n', 'on  its way.\r\n');
  assert.equal((await one(loose('relaxed/relaxed'), { [NAME]: rec(RSA) })).outcome, 'pass');
  assert.equal((await one(loose('simple/relaxed'), { [NAME]: rec(RSA) })).outcome, 'header-changed');
  assert.equal((await one(loose('relaxed/simple'), { [NAME]: rec(RSA) })).outcome, 'body-mismatch');
});

test('verify: l= covers a prefix, so text added after it still passes, and a short body fails', async () => {
  const l = Buffer.byteLength(canonB(BODY, 'relaxed'));
  const r = await one(eml({ l, sentBody: BODY.replace(/(\r\n)+$/, '\r\n') + 'A footer the list added.\r\n' }), { [NAME]: rec(RSA) });
  assert.deepEqual([r.outcome, r.l, r.body.length], ['pass', l, l]);
  const short = await one(eml({ l, sentBody: 'Hello Pat,\r\n' }), { [NAME]: rec(RSA) });
  assert.deepEqual([short.outcome, short.body.short], ['body-mismatch', true]);
});

test('verify: a name listed in h= more often than it appears passes, and an added copy breaks it', async () => {
  const h = ['from', 'from', 'to', 'subject', 'date', 'message-id', 'reply-to'];
  const r = await one(eml({ h }), { [NAME]: rec(RSA) });
  assert.deepEqual([r.outcome, r.signedCount, r.listed], ['pass', 5, 7]);
  const added = await one(eml({ h, after: HEAD.concat(['From: Someone else <x@other.example>']) }), { [NAME]: rec(RSA) });
  assert.equal(added.outcome, 'header-changed');
});

test('verify: a changed body, a changed signed field, and a different key are told apart', async () => {
  assert.equal((await one(eml({ sentBody: BODY + 'Sent through a filter.\r\n' }), { [NAME]: rec(RSA) })).outcome, 'body-mismatch');
  assert.equal((await one(eml({ after: HEAD.map(x => x.replace('Subject: ', 'Subject: [EXT] ')) }), { [NAME]: rec(RSA) })).outcome, 'header-changed');
  assert.equal((await one(eml(), { [NAME]: rec(RSA2) })).outcome, 'key-mismatch');
  // Both changed: the signed field is named, and the body hash is still reported
  const both = await one(eml({ sentBody: 'Other text\r\n', after: HEAD.map(x => x.replace('Your order', 'Their order')) }), { [NAME]: rec(RSA) });
  assert.deepEqual([both.outcome, both.body.matches], ['header-changed', false]);
});

test('verify: Ed25519 passes, and a failure does not say which cause', async () => {
  const o = { alg: 'ed25519-sha256', key: ED };
  const table = { [NAME]: 'v=DKIM1; k=ed25519; p=' + edP(ED) };
  assert.equal((await one(eml(o), table)).outcome, 'pass');
  const text = eml(Object.assign({ after: HEAD.map(x => x.replace('Your order', 'Their order')) }, o));
  const c = await check(text, table);
  assert.equal(c.results[0].outcome, 'ed25519-fail');
  const x = found(text, c).keyCheck.results[0];
  assert.match(x.line.plain, /can't tell whether the message changed or the key is wrong/);
  assert.match(x.line.technical, /does not show whether the signed data changed or the key differs/);
  // No WebCrypto Ed25519 in this browser: said, not guessed
  assert.equal((await one(eml(o), table, { subtle: null })).outcome, 'unsupported');
  // An RSA record cannot check an Ed25519 signature
  assert.equal((await one(eml(o), { [NAME]: rec(RSA) })).outcome, 'malformed');
});

test('verify: headers alone check the signed fields and the key, and say the text was not included', async () => {
  const text = eml({ body: null });
  const c = await check(text, { [NAME]: rec(RSA) }, { source: 'paste' });
  assert.deepEqual([c.results[0].outcome, c.results[0].body, c.bodyPresent], ['no-body', null, false]);
  const x = found(text, c).keyCheck.results[0];
  assert.equal(x.state, 'caveat');
  assert.match(x.line.plain, /signed details at the top of the message are intact and the key matches.*Drop the whole message file/);
  // A file past the size the page reads says that instead
  const big = await check(eml(), { [NAME]: rec(RSA) }, { truncated: true });
  assert.equal(big.results[0].outcome, 'no-body');
  assert.match(found(eml(), big).keyCheck.results[0].line.plain, /larger than this page reads/);
});

test('verify: a file that is not UTF-8 is hashed byte for byte', async () => {
  const body = 'Caf\xe9 au lait, 3\xa0\x80\r\n';
  const text = eml({ body, c: 'simple/simple' });
  assert.equal((await one(text, { [NAME]: rec(RSA) }, { encoding: 'latin1' })).outcome, 'pass');
  assert.equal((await one(text, { [NAME]: rec(RSA) }, { encoding: 'utf8' })).outcome, 'body-mismatch');
});

test('lookup: the request is the key name and type=TXT, and nothing else', async () => {
  const seen = [];
  await K.checkAll(eml(), dns({ [NAME]: rec(RSA) }, seen), { subtle });
  assert.equal(seen.length, 1);
  assert.equal(seen[0].url, 'https://cloudflare-dns.com/dns-query?name=' + NAME + '&type=TXT');
  assert.deepEqual(seen[0].init.headers, { accept: 'application/dns-json' });
  assert.equal(seen[0].init.credentials, 'omit');
  assert.equal(seen[0].init.referrerPolicy, 'no-referrer');
  assert.equal(seen[0].init.method, undefined);
  assert.equal(seen[0].init.body, undefined);
});

test('lookup: two signatures under one name make one query, and a name that is not DNS makes none', async () => {
  const seen = [];
  const two = TOP('fail').concat([sign(HEAD, BODY, {}), sign(HEAD, BODY, { c: 'simple/simple' })], HEAD).join('\r\n') + '\r\n\r\n' + BODY;
  const c = await K.checkAll(two, dns({ [NAME]: rec(RSA) }, seen), { subtle });
  assert.deepEqual([c.results.map(r => r.outcome), seen.length], [['pass', 'pass'], 1]);
  const odd = eml().replace('\r\n s=s1;', '\r\n s=s1/../x?y=1;');
  const r = await K.checkAll(odd, dns({}, seen), { subtle });
  assert.deepEqual([r.results[0].outcome, seen.length], ['incomplete', 1]);
});

test('lookup: NXDOMAIN and an empty answer are no key, and a CNAME chain names its target', async () => {
  const text = eml();
  assert.deepEqual([(await one(text, {})).outcome, (await one(text, {})).dns.status], ['no-key', 'nxdomain']);
  assert.deepEqual([(await one(text, { [NAME]: 'nodata' })).outcome, (await one(text, { [NAME]: 'nodata' })).dns.status], ['no-key', 'nodata']);
  const cn = [{ name: NAME, type: 5, data: 's1.dkim.mailer.example.' }, { name: 's1.dkim.mailer.example', type: 5, data: 'k9.keys.mailer.example.' }];
  const dead = await check(text, { [NAME]: { Status: 3, Answer: cn } });
  assert.deepEqual([dead.results[0].outcome, dead.results[0].dns.cname, dead.results[0].dns.target], ['no-key', ['s1.dkim.mailer.example', 'k9.keys.mailer.example'], 'k9.keys.mailer.example']);
  const x = found(text, dead).keyCheck.results[0];
  assert.match(x.line.technical, /returned NXDOMAIN.*The name is a CNAME to k9\.keys\.mailer\.example\. RFC 6376 6\.1\.2 has a verifier return PERMFAIL \(no key for signature\)/);
  assert.match(x.steps[1].technical, /is a CNAME to k9\.keys\.mailer\.example, which has no TXT record/);
  const live = await one(text, { [NAME]: { Status: 0, Answer: cn.concat([{ name: 'k9.keys.mailer.example', type: 16, data: '"' + rec(RSA) + '"' }]) } });
  assert.deepEqual([live.outcome, live.dns.target], ['pass', 'k9.keys.mailer.example']);
});

test('lookup: TXT strings join with nothing between them, and escapes are read', async () => {
  const p = rec(RSA);
  const split = '"' + p.slice(0, 100) + '" "' + p.slice(100, 255) + '" "' + p.slice(255) + '"';
  assert.equal(K.txtJoin(split), p);
  assert.equal(K.txtJoin('"v=DKIM1\; k=rsa\; p=AB" "CD"'), 'v=DKIM1; k=rsa; p=ABCD');
  assert.equal(K.txtJoin('"a\\034b"'), 'a"b');
  assert.equal((await one(eml(), { [NAME]: split })).outcome, 'pass');
});

test('lookup: SERVFAIL, a timeout, an HTTP error and a network error are no answer, never a failure', async () => {
  const text = eml();
  for (const [a, status] of [['servfail', 'servfail'], ['hang', 'timeout'], ['http500', 'error'], ['throw', 'error']]) {
    const c = await check(text, { [NAME]: a }, { timeoutMs: 20 });
    assert.deepEqual([c.results[0].outcome, c.results[0].dns.status], ['dns-failed', status], a);
    const x = found(text, c).keyCheck.results[0];
    assert.deepEqual([x.kind, x.state, x.cause], ['no-answer', 'unknown', false]);
    assert.match(x.line.plain, /^The lookup got no answer, so this check didn't run\. Try again in a minute\.$/);
  }
});

test('key record: tags per RFC 6376 3.6.1, revoked, malformed, and the key size', async () => {
  const k = K.parseKey('v=DKIM1; k=rsa; h=sha256; s=email; t=y:s; p=' + rsaP(RSA));
  assert.deepEqual([k.ok, k.v, k.k, k.h, k.s, k.t, k.testing, k.strict, k.bits], [true, 'DKIM1', 'rsa', ['sha256'], ['email'], ['y', 's'], true, true, 2048]);
  assert.deepEqual([K.parseKey('p=' + rsaP(RSA1024)).bits, K.parseKey('p=' + rsaP(RSA512)).bits], [1024, 512]);
  // A bare RSAPublicKey, the form RFC 6376 3.6.1 describes, reads too
  assert.equal(K.parseKey('p=' + RSA.publicKey.export({ type: 'pkcs1', format: 'der' }).toString('base64')).bits, 2048);
  assert.deepEqual([K.parseKey('v=DKIM1; p=').revoked, K.parseKey('v=DKIM1; k=rsa; p=').ok], [true, false]);
  for (const bad of ['v=DKIM2; p=' + rsaP(RSA), 'k=rsa; v=DKIM1; p=' + rsaP(RSA), 'v=DKIM1; k=rsa', 'v=DKIM1; p=not*base64', 'v=DKIM1; p=' + rsaP(RSA).slice(0, 40), 'v=DKIM1; k=ed25519; p=' + rsaP(RSA), 'v=DKIM1; k=dsa; p=AAAA', 'v=spf1 -all']) {
    const x = K.parseKey(bad);
    assert.ok(!x.ok && !x.revoked && x.error, bad);
  }
  const text = eml();
  assert.equal((await one(text, { [NAME]: 'v=DKIM1; p=' })).outcome, 'revoked');
  assert.equal((await one(text, { [NAME]: 'v=DKIM1; k=rsa; p=' + rsaP(RSA).slice(0, 80) })).outcome, 'malformed');
  // A stray TXT beside the key is ignored (RFC 6376 6.1.2); alone it is not a key
  assert.equal((await one(text, { [NAME]: ['v=spf1 -all', rec(RSA)] })).outcome, 'pass');
  assert.equal((await one(text, { [NAME]: 'v=spf1 -all' })).outcome, 'malformed');
  // h= or s= that rules this use out
  assert.equal((await one(text, { [NAME]: 'v=DKIM1; h=sha1; p=' + rsaP(RSA) })).outcome, 'malformed');
  assert.equal((await one(text, { [NAME]: 'v=DKIM1; s=other; p=' + rsaP(RSA) })).outcome, 'malformed');
});

test('key size: under 1024 bits is not valid (RFC 8301 3.2), and 1024 to 2047 is a caveat', async () => {
  const small = eml({ key: RSA512 });
  const c = await check(small, { [NAME]: rec(RSA512) });
  assert.deepEqual([c.results[0].outcome, c.results[0].bits], ['too-short', 512]);
  const x = found(small, c).keyCheck.results[0];
  assert.match(x.line.technical, /is 512 bits\. RFC 8301 3\.2 says verifiers MUST NOT consider signatures using RSA keys of less than 1024 bits as valid/);
  assert.match(x.line.plain, /too short for mail systems to trust/);
  assert.ok(!/\d{3,4}/.test(x.line.plain), 'the bit count stays in Technical');
  const mid = eml({ key: RSA1024, recorded: 'pass' });
  const m = await check(mid, { [NAME]: rec(RSA1024) });
  const y = found(mid, m).keyCheck.results[0];
  assert.deepEqual([y.kind, y.state, y.notes.length, y.notes[0].state], ['pass', 'pass', 1, 'caveat']);
  const full = eml({ recorded: 'pass' });
  assert.equal(found(full, await check(full, { [NAME]: rec(RSA) })).keyCheck.results[0].notes.length, 0);
});

test('rsa-sha1 is not verified and nothing is looked up for it', async () => {
  const seen = [];
  const text = eml().replace('a=rsa-sha256', 'a=rsa-sha1');
  const c = await K.checkAll(text, dns({ [NAME]: rec(RSA) }, seen), { subtle });
  assert.deepEqual([c.results[0].outcome, seen.length], ['sha1', 0]);
  const x = found(text, c).keyCheck.results[0];
  assert.deepEqual([x.kind, x.state], ['not-checked', 'unknown']);
  assert.match(x.line.technical, /RFC 8301 3\.1 says rsa-sha1 MUST NOT be used for signing or verifying/);
});

test('file against paste: only a file supports a failure, and the source is recorded', async () => {
  const text = eml({ sentBody: BODY + 'Changed.\r\n' });
  const file = await check(text, { [NAME]: rec(RSA) }, { source: 'file' });
  const paste = await check(text, { [NAME]: rec(RSA) }, { source: 'paste' });
  assert.deepEqual([file.source, paste.source, (await check(text, {}, { source: undefined })).source], ['file', 'paste', 'paste']);
  const f = found(text, file).keyCheck, p = found(text, paste).keyCheck;
  assert.deepEqual([f.results[0].kind, f.results[0].state, f.results[0].cause], ['body-mismatch', 'fail', true]);
  assert.deepEqual([p.results[0].kind, p.results[0].state, p.results[0].cause, p.results[0].steps.length], ['pasted', 'unknown', false, 0]);
  assert.match(p.results[0].line.plain, /^Copying can change spaces, so this check couldn't confirm the signature from pasted text\. Drop the message file on the box for a firm answer\.$/);
  assert.match(p.results[0].line.technical, /Seen here: .*does not equal bh=.*Only the message file gives a firm result/);
  assert.match(f.intro.technical, /from the message file/);
  assert.match(p.intro.technical, /from the pasted text/);
  // A pass is a pass from either source, and a missing key is a fact about DNS
  const good = eml({ recorded: 'pass' });
  assert.equal(found(good, await check(good, { [NAME]: rec(RSA) }, { source: 'paste' })).keyCheck.results[0].kind, 'pass');
  assert.equal(found(text, await check(text, {}, { source: 'paste' })).keyCheck.results[0].kind, 'no-key');
});

test('finding: a cause found replaces the line that the headers cannot show which, marked as checked today', async () => {
  const text = eml({ sentBody: BODY + 'Changed.\r\n' });
  const before = HA.analyze(text).finding;
  assert.equal(before.keyCheck, null);
  assert.match(before.details[0].technical, /the headers cannot show which/);
  assert.match(before.cause.technical, /or the key in DNS does not match/);
  const f = found(text, await check(text, { [NAME]: rec(RSA) }));
  assert.match(f.details[0].technical, /^DKIM failed for d=shop\.example s=s1\. Checked today \(November 13, 2026\): .*The body changed after signing/);
  assert.match(f.details[0].plain, /Checked today \(November 13, 2026\): The message text was changed after shop\.example signed it/);
  assert.match(f.cause.plain, /Checked today \(November 13, 2026\): The message text was changed/);
  for (const s of [f.details[0], f.cause].concat(f.fixes)) assert.ok(!/cannot show which|or the key in DNS does not match|check that the key at/.test(s.technical), s.technical);
  assert.deepEqual(f.fixes.slice(0, 3).map(x => x.plain), f.keyCheck.results[0].steps.map(x => x.plain));
  // A key cause sends the reader to DNS, not to a footer
  const wrong = eml();
  const w = found(wrong, await check(wrong, { [NAME]: rec(RSA2) }));
  assert.match(w.cause.technical, /The key in DNS is not the key that signed/);
  assert.match(w.fixes[0].plain, /current DKIM setting for shop\.example/);
  assert.ok(!w.fixes.some(x => /footer/.test(x.plain)));
  assert.match(w.keyCheck.results[0].who.plain, /^Whoever manages the DNS for shop\.example fixes this/);
  // The status and the receiver's results do not move
  assert.deepEqual([f.status, w.status, HA.analyze(text, { keyCheck: null }).auth.dkim[0].result], ['fail', 'fail', 'fail']);
});

test('finding: where the receiver and this check disagree, both are stated and no reason is given', async () => {
  // The receiver recorded a failure; this copy verifies today
  const ok = eml();
  const a = found(ok, await check(ok, { [NAME]: rec(RSA) }));
  const x = a.keyCheck.results[0];
  assert.deepEqual([x.kind, x.state, x.cause, x.received], ['pass-now', 'caveat', false, 'fail']);
  assert.match(x.recorded.plain, /recorded that this signature failed when the message arrived/);
  assert.match(x.recorded.technical, /^mx\.receiver\.example recorded dkim=fail for d=shop\.example s=s1 at delivery\.$/);
  assert.match(x.line.plain, /recorded a failure when the message arrived, but this copy checks out today\. This page can't show what was different then\.$/);
  assert.match(a.details[0].technical, /the headers cannot show which/, 'no cause was found, so the line stays');
  // The receiver recorded a pass; this check fails: unknown, and the finding is untouched
  const bad = eml({ recorded: 'pass', sentBody: BODY + 'Changed.\r\n' });
  const plain = HA.analyze(bad).finding;
  const b = found(bad, await check(bad, { [NAME]: rec(RSA) }));
  const y = b.keyCheck.results[0];
  assert.deepEqual([y.kind, y.state, y.cause, y.steps.length, y.who], ['passed-then', 'unknown', false, 0, null]);
  assert.match(y.line.plain, /recorded that this signature passed when the message arrived, but it doesn't check out today\. This page can't show what changed since then\.$/);
  assert.match(y.line.technical, /recorded dkim=pass at delivery\. Seen today: .*this page does not say which\.$/);
  assert.deepEqual([b.status, b.headline, b.cause, b.details, b.fixes], [plain.status, plain.headline, plain.cause, plain.details, plain.fixes]);
  // A key gone today, after a recorded pass, reads the same way
  const gone = eml({ recorded: 'pass' });
  assert.equal(found(gone, await check(gone, {})).keyCheck.results[0].kind, 'passed-then');
  // No receiver's record at all: the check stands alone
  const bare = eml().split('\r\n').slice(2).join('\r\n');
  const n = found(bare, await check(bare, { [NAME]: rec(RSA2) })).keyCheck.results[0];
  assert.deepEqual([n.kind, n.state, n.received], ['key-mismatch', 'fail', '']);
  assert.match(n.recorded.plain, /hold no record from a receiving mail system/);
});

test('finding: the result is marked as checked today, and analyze alone never looks anything up', async () => {
  const text = eml();
  const c = await check(text, { [NAME]: rec(RSA) });
  const kc = found(text, c).keyCheck;
  assert.match(kc.intro.plain, /^Checked today, November 13, 2026\. What the recipient's email provider recorded when the message arrived is shown separately\.$/);
  assert.equal(K.dayOf(new Date(2026, 10, 3, 9).getTime()), 'November 3, 2026');
  const real = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = () => { calls++; return Promise.reject(new Error('no network in tests')); };
  try { for (const f of fs.readdirSync(path.join(__dirname, 'fixtures'))) HA.analyze(fixture(f)); HA.analyze(text); } finally { globalThis.fetch = real; }
  assert.equal(calls, 0);
});

test('page: the lookup runs only from the button, never for a sample, and the usage note is unchanged', () => {
  const app = fs.readFileSync(path.join(__dirname, '..', 'ui', 'app.js'), 'utf8');
  assert.equal(app.split('HA.dkimkey.').length - 1, 1, 'one call site');
  const fn = app.slice(app.indexOf('function runKeyCheck()'), app.indexOf('// A plain text report'));
  assert.match(fn, /if \(!R \|\| keyBusy \|\| sample\) return;/);
  assert.match(fn, /HA\.dkimkey\.checkAll\(/);
  assert.equal(app.split('runKeyCheck()').length - 1, 2, 'defined once, called once');
  assert.match(app, /if \(e\.target\.closest\('#key-check'\)\) \{ runKeyCheck\(\); return; \}/);
  assert.match(app, /if \(sample\) return h \+ '<p class="fpara">' \+ esc\(KEY_UI\.sample\)/);
  assert.match(app, /send\(\{ tool: 'header-decoder', status: \(R\.finding && R\.finding\.status\) \|\| 'unknown', sample: !!sample, ref: referrerHost\(\) \}\);/);
  assert.equal(app.split('fetch(').length - 1, 2, 'the usage note and the key lookup');
  const ui = HA.finding.KEY_UI;
  assert.deepEqual([ui.failed, ui.check, ui.under], ['Find out why the signature failed', 'Check the signature', 'This looks up the sender\'s published key (DKIM key) and checks the signature again.']);
  // The only lookup address in the build is the one the decision names
  assert.equal(K.DOH, 'https://cloudflare-dns.com/dns-query');
});

test('verify: the building blocks match Node\'s own', () => {
  for (const n of [0, 1, 55, 56, 63, 64, 65, 1000]) {
    const b = crypto.randomBytes(n);
    assert.equal(Buffer.from(V.sha256(new Uint8Array(b))).toString('hex'), crypto.createHash('sha256').update(b).digest('hex'), 'sha256 of ' + n + ' bytes');
    assert.equal(V.b64encode(new Uint8Array(b)), b.toString('base64'));
    assert.deepEqual(Buffer.from(V.b64decode(b.toString('base64'))), b);
  }
  assert.equal(V.b64decode('not*base64'), null);
  assert.equal(V.canonHeader('SUBJect : a\t b \r\n\tc  ', 'relaxed'), 'subject:a b c');
  assert.equal(V.canonHeader('SUBJect : a\t b \r\n\tc  ', 'simple'), 'SUBJect : a\t b \r\n\tc  ');
  // RFC 6376 3.4.3 and 3.4.4: an empty body
  assert.deepEqual([V.canonBody('', 'simple'), V.canonBody('\r\n\r\n', 'simple'), V.canonBody('', 'relaxed'), V.canonBody(' \r\n\r\n', 'relaxed')], ['\r\n', '\r\n', '', '']);
  // RFC 6376 3.4.5, the body example
  assert.equal(V.canonBody(' C \r\nD \t E\r\n\r\n\r\n', 'relaxed'), ' C\r\nD E\r\n');
  assert.equal(V.canonBody(' C \r\nD \t E\r\n\r\n\r\n', 'simple'), ' C \r\nD \t E\r\n');
  assert.equal(V.withoutB('DKIM-Signature: v=1; bh=abc=;\r\n b=AAAA\r\n BBBB; d=x.example'), 'DKIM-Signature: v=1; bh=abc=;\r\n b=; d=x.example');
});
