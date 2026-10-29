'use strict';
// Step 2 check: auth.js against the 2026-10-23 spec, one block per item.
const test = require('node:test');
const assert = require('node:assert/strict');
const { HA, fixture } = require('./load.js');

const run = (name) => HA.analyze(fixture(name));
const row = (r, kind, domain) => r.alignment.rows.find(x => x.kind === kind && x.domain === domain);

// 1. Several Authentication-Results

test('item 1: an injected A-R above the real one is kept, untrusted, and never primary', () => {
  const r = run('ar-injected-above.txt');
  const a = r.auth;
  assert.equal(a.all.length, 2);
  const [fake, real] = a.all;
  assert.equal(fake.authserv, 'mail.sender.example');
  assert.equal(fake.untrusted, true);
  assert.equal(fake.primary, false);
  assert.equal(real.authserv, 'mx.google.com');
  assert.equal(real.untrusted, false);
  assert.equal(real.primary, true);
  assert.equal(a.primary, 1);
  assert.equal(a.primaryRule, 'operator');
  // The injected passes do not reach the reported results.
  assert.equal(a.spf.result, 'softfail');
  assert.equal(a.dkim[0].result, 'fail');
  assert.equal(a.dmarc.result, 'fail');
  assert.equal(a.computed.result, 'fail');
  assert.ok(a.notes.some(n => n.src.includes(fake.index) && /sender could have added it/.test(n.technical)));
  assert.ok(r.flags.includes('untrusted-ar'));
});

test('item 1: an A-R from a sender-side hop is untrusted too, since only the receiver strips its own', () => {
  const text = fixture('ar-injected-above.txt').replace('From: Alex Rivera', 'Received: from app.sender.example (app.sender.example [10.1.0.5])\n        by mail.sender.example (Postfix) with ESMTP id 1Aa1;\n        Fri, 23 Oct 2026 18:00:01 +0000 (UTC)\nFrom: Alex Rivera');
  const a = HA.analyze(text).auth;
  assert.equal(a.all[0].trust, 'sender-side');
  assert.equal(a.all[0].untrusted, true);
  assert.equal(a.all[1].primary, true);
});

test('item 1: Exchange Online, the topmost A-R with no authserv-id is primary when X-MS-Exchange-Organization headers are present', () => {
  const a = run('exchange-online-inbound.txt').auth;
  assert.equal(a.primary, 0);
  assert.equal(a.primaryRule, 'exchange-online');
  assert.equal(a.all[0].untrusted, false);
  // The same field without the Exchange Online headers cannot be tied to a writer.
  const bare = fixture('exchange-online-inbound.txt').split('\n').filter(l => !/^X-MS-Exchange-Organization-/.test(l) && !/^ BN2PEPF000044A7\.namprd04/.test(l)).join('\n');
  const b = HA.analyze(bare).auth;
  assert.equal(b.all[0].untrusted, true);
  assert.equal(b.primary, -1);
  assert.equal(b.computed.result, 'none');
});

test('item 1: only untrusted A-R fields means no primary and no reported results', () => {
  const text = fixture('ar-injected-above.txt').replace(/Authentication-Results: mx\.google\.com;[\s\S]*?header\.from=sender\.example\n/, '');
  const a = HA.analyze(text).auth;
  assert.equal(a.all.length, 1);
  assert.equal(a.primary, -1);
  assert.equal(a.dmarc.reported, false);
  assert.equal(a.computed.result, 'none');
  assert.equal(a.computed.why, 'no-trusted-results');
});

// 2. RFC 8601 parsing

test('item 2: methods spf, dkim, dmarc, arc, compauth, iprev and auth with result, reason, comment and properties', () => {
  const v = 'mx.example.org 1; spf=pass (sender ok) smtp.mailfrom=a@example.com smtp.helo=mail.example.com; ' +
    'dkim=fail reason="bad signature" header.d=example.com header.i=@example.com header.s=k1 header.b=AbCd1234; ' +
    'dmarc=pass (p=REJECT sp=NONE dis=NONE) header.from=example.com policy.dmarc=reject; arc=pass (i=1); ' +
    'compauth=softpass reason=201; iprev=pass policy.iprev=192.0.2.1 (mail.example.com); auth=pass smtp.auth=user@example.com';
  const ar = HA.auth.parseAuthResults(v);
  assert.equal(ar.authserv, 'mx.example.org');
  assert.equal(ar.version, '1');
  assert.deepEqual(ar.results.map(x => x.method), ['spf', 'dkim', 'dmarc', 'arc', 'compauth', 'iprev', 'auth']);
  const [spf, dkim, dmarc, arc, ca, iprev, auth] = ar.results;
  assert.deepEqual(spf.comments, ['sender ok']);
  assert.equal(spf.ids['smtp.mailfrom'], 'a@example.com');
  assert.equal(spf.ids['smtp.helo'], 'mail.example.com');
  assert.equal(dkim.result, 'fail');
  assert.equal(dkim.reason, 'bad signature');
  for (const k of ['header.d', 'header.i', 'header.s', 'header.b']) assert.ok(dkim.ids[k], k);
  assert.equal(dkim.ids['header.b'], 'AbCd1234');
  assert.equal(dmarc.ids['header.from'], 'example.com');
  assert.deepEqual(dmarc.policy, { dmarc: 'reject' });
  assert.deepEqual(arc.comments, ['i=1']);
  assert.equal(ca.reason, '201');
  assert.equal(iprev.result, 'pass');
  assert.deepEqual(iprev.policy, { iprev: '192.0.2.1' });
  assert.deepEqual(iprev.comments, ['mail.example.com']);
  assert.equal(auth.props['smtp.auth'], 'user@example.com');
});

test('item 2: Google dmarc comment becomes policy, subdomain policy, and disposition', () => {
  const d = run('ar-injected-above.txt').auth.dmarc;
  assert.equal(d.policy.p, 'reject');
  assert.equal(d.policy.sp, 'quarantine');
  assert.equal(d.policy.dis, 'quarantine');
  assert.equal(d.disposition.value, 'quarantine');
  assert.equal(d.disposition.source, 'dis');
  assert.equal(d.disposition.raw, 'dis=QUARANTINE');
});

test('item 2: Exchange Online action becomes disposition, compauth result and reason code kept raw', () => {
  const a = run('exchange-online-oreject.txt').auth;
  assert.equal(a.primaryRule, 'exchange-online');
  assert.equal(a.dmarc.result, 'fail');
  assert.equal(a.dmarc.policy.action, 'oreject');
  assert.equal(a.dmarc.disposition.source, 'action');
  assert.equal(a.dmarc.disposition.raw, 'action=oreject');
  assert.equal(a.dmarc.disposition.policy, 'reject');
  assert.equal(a.compauth.result, 'fail');
  assert.equal(a.compauth.reason, '000');
  assert.match(a.compauth.raw, /^compauth=fail reason=000$/);
  const disp = (action) => HA.analyze(fixture('exchange-online-oreject.txt').replace('action=oreject', 'action=' + action)).auth.dmarc.disposition;
  assert.deepEqual([disp('none').value, disp('quarantine').value, disp('reject').value], ['none', 'quarantine', 'reject']);
  for (const [w, pol] of [['pct.quarantine', 'quarantine'], ['pct.reject', 'reject']]) {
    const x = disp(w);
    assert.equal(x.raw, 'action=' + w);
    assert.equal(x.policy, pol);
    assert.equal(x.sampled, true);
  }
});

// 3. Received-SPF

test('item 3: Received-SPF result, comment and pairs; it is the SPF source when the primary A-R has no spf', () => {
  const r = run('received-spf-only.txt');
  const rs = r.auth.receivedSpf[0];
  assert.equal(rs.result, 'pass');
  assert.deepEqual(rs.comments, ['mailfrom']);
  assert.deepEqual(rs.props, { identity: 'mailfrom', 'client-ip': '192.0.2.70', helo: 'out.shop.example', 'envelope-from': 'orders@mail.shop.example', receiver: 'mx.receiver.example', mechanism: 'ip4:192.0.2.64/28' });
  assert.equal(rs.trusted, true);
  const spf = r.auth.spf;
  assert.equal(spf.reportedBy, 'Received-SPF');
  assert.equal(spf.result, 'pass');
  assert.equal(spf.domain, 'mail.shop.example');
  assert.equal(spf.identity, 'Received-SPF envelope-from');
  assert.equal(spf.ip, '192.0.2.70');
  assert.equal(spf.word, 'Aligned, relaxed');
  assert.ok(spf.src.includes(rs.src[0]));
});

test('item 3: Received-SPF with identity=helo checks the HELO domain', () => {
  const text = fixture('received-spf-only.txt').replace('identity=mailfrom', 'identity=helo');
  const spf = HA.analyze(text).auth.spf;
  assert.equal(spf.domain, 'out.shop.example');
  assert.equal(spf.identity, 'Received-SPF helo');
});

// 4. DKIM-Signature

test('item 4: two signatures with one d=, results matched by header.s and by header.b, l= and expired x= flagged', () => {
  const r = run('dkim-two-same-d.txt');
  const [k2, k1] = r.auth.signatures;
  assert.equal(k2.s, 'k2');
  assert.equal(k1.s, 'k1');
  for (const t of ['v', 'a', 'c', 'd', 's', 'i', 't', 'x', 'l', 'h', 'bh', 'b']) assert.ok(t in k1, 'tag ' + t);
  assert.equal(k1.v, '1');
  assert.equal(k1.b, 'AAAA1111SyntheticValue0705');
  assert.equal(k1.l, 1200);
  assert.equal(k1.partialBody, true);
  assert.equal(k1.expired, false);
  assert.equal(k2.partialBody, false);
  assert.equal(k2.expired, true);
  const [pass, fail] = r.auth.dkim;
  assert.equal(pass.selector, 'k1');
  assert.equal(pass.matchedBy, 'header.s');
  assert.equal(pass.signature, 1);
  assert.equal(fail.selector, 'k2');
  assert.equal(fail.matchedBy, 'header.b');
  assert.equal(fail.signature, 0);
  assert.equal(r.auth.dkim.length, 2);
  assert.ok(r.flags.includes('dkim-body-limit'));
  assert.ok(r.flags.includes('dkim-expired'));
  assert.ok(r.auth.notes.some(n => /l= body length limit/.test(n.technical) && n.src[0] === k1.src[0]));
  assert.ok(r.auth.notes.some(n => /expired before the message arrived/.test(n.technical) && n.src[0] === k2.src[0]));
});

test('item 4: two signatures with one d= and a result naming neither s nor b is not matched by guess', () => {
  const text = fixture('dkim-two-same-d.txt').replace(' header.s=k1', '');
  const d = HA.analyze(text).auth.dkim;
  const amb = d.find(x => x.result === 'pass');
  assert.equal(amb.signature, -1);
  assert.equal(amb.ambiguous, true);
  assert.equal(amb.selector, '');
  assert.equal(amb.domain, 'news.example');
});

// 5. ARC

test('item 5: a two set chain with cv=pass; i=1 results come from before the forward and name the first forwarder', () => {
  const a = run('arc-forwarded-i2.txt').auth;
  assert.equal(a.arc.state, 'pass');
  assert.equal(a.arc.firstForwarder, 'mx.list.example');
  assert.deepEqual(a.arc.instances[0].preForward.map(x => x.method + '=' + x.result), ['spf=pass', 'dkim=pass', 'dmarc=pass']);
  assert.equal(a.arcResult.result, 'pass');
});

test('item 5: cv=fail fails the chain, and the receiver\'s own arc= result stays beside it, not merged', () => {
  const r = run('arc-cv-fail.txt');
  assert.equal(r.auth.arc.state, 'fail');
  assert.ok(r.auth.arc.problems.some(p => /cv=fail/.test(p.text)));
  assert.equal(r.auth.arcResult.result, 'fail');
  const x = HA.analyze(fixture('arc-cv-fail.txt').replace('arc=fail (i=2', 'arc=pass (i=2')).auth;
  assert.equal(x.arc.state, 'fail');
  assert.equal(x.arcResult.result, 'pass');
});

test('item 5: a gap in i= fails the chain on its own', () => {
  const arc = run('arc-gap.txt').auth.arc;
  assert.equal(arc.state, 'fail');
  assert.deepEqual(arc.instances.map(s => s.i), [1, 3]);
  assert.equal(arc.problems.length, 1);
  assert.match(arc.problems[0].text, /not contiguous: i=3 follows i=1/);
});

// 6. Identifiers and alignment

test('item 6: a null Return-Path makes the HELO domain the SPF identifier', () => {
  const r = run('null-return-path-helo.txt');
  const spf = r.auth.spf;
  assert.equal(r.message.returnPath.empty, true);
  assert.equal(spf.nullPath, true);
  assert.equal(spf.identity, 'smtp.helo');
  assert.equal(spf.domain, 'mta.notify.example');
  assert.equal(spf.result, 'pass');
  assert.equal(spf.word, 'Aligned, relaxed');
  assert.equal(r.auth.computed.result, 'pass');
  assert.equal(r.auth.computed.strict, false);
  // With no smtp.helo either, the HELO name in the receiver's Received field is used.
  const noHelo = HA.analyze(fixture('null-return-path-helo.txt').replace(' smtp.helo=mta.notify.example', '')).auth.spf;
  assert.equal(noHelo.domain, 'mta.notify.example');
  assert.equal(noHelo.identity, 'Received HELO');
});

test('item 6: relaxed is the default, strict beside it, and a note says adkim and aspf are not in the headers', () => {
  const r = run('subdomain-relaxed.txt');
  assert.equal(r.auth.computed.result, 'pass');
  assert.equal(r.auth.computed.mode, 'relaxed');
  assert.equal(r.auth.computed.strict, false);
  const n = r.alignment.modeNote;
  assert.equal(n.state, 'unknown');
  assert.match(n.technical, /adkim and aspf/);
  assert.match(n.technical, /not in the headers/);
  assert.equal(run('gmail-show-original.txt').alignment.modeNote.state, 'unknown');
  assert.equal(r.alignment.from.org, 'brand.example');
});

test('item 6: a From field with addresses in two domains gives no single From domain', () => {
  const text = fixture('gmail-show-original.txt').replace('From: Alex Rivera <alex@sender.example>\n', 'From: Alex Rivera <alex@sender.example>, Sam <sam@other.example>\n');
  const r = HA.analyze(text);
  assert.equal(r.alignment.from.domain, '');
  assert.equal(r.alignment.from.why, 'multi-domain');
  assert.equal(r.auth.computed.result, 'none');
});

// 7. Computed DMARC

test('item 7: reported dmarc=pass with nothing aligned is its own flag, computed stays fail', () => {
  const r = run('dmarc-pass-unaligned.txt');
  assert.equal(r.auth.dmarc.result, 'pass');
  assert.equal(r.auth.computed.result, 'fail');
  assert.equal(r.auth.dmarc.disagreement.reason, 'local-policy');
  assert.ok(r.flags.includes('dmarc-disagreement'));
  assert.equal(row(r, 'dkim', 'esp.example').word, 'Passed, not aligned');
  assert.equal(row(r, 'spf', 'esp.example').word, 'Passed, not aligned');
});

test('item 7: computed is pass, fail or none and nothing else', () => {
  const names = ['gmail-show-original.txt', 'exchange-online-inbound.txt', 'icloud.txt', 'two-dkim.txt', 'spf-bounce-domain.txt', 'subdomain-relaxed.txt',
    'arc-forwarded-i2.txt', 'no-auth-results.txt', 'two-from.txt', 'ar-injected-above.txt', 'received-spf-only.txt', 'dkim-two-same-d.txt', 'null-return-path-helo.txt', 'dmarc-pass-unaligned.txt'];
  for (const n of names) assert.ok(['pass', 'fail', 'none'].includes(run(n).auth.computed.result), n);
  assert.equal(run('no-auth-results.txt').auth.computed.result, 'none');
  assert.ok(!run('gmail-show-original.txt').flags.includes('dmarc-disagreement'));
});

// 8. Two From headers

test('item 8: two From fields leave alignment undefined and compute nothing from either address', () => {
  const plain = run('two-from.txt');
  assert.ok(plain.flags.includes('two-from'));
  assert.equal(plain.alignment.from.domain, '');
  assert.equal(plain.alignment.from.why, 'two-from');
  assert.equal(plain.auth.computed.result, 'none');
  assert.equal(plain.auth.computed.why, 'two-from');
  const text = fixture('two-from.txt').replace('From: "Bank Support"', 'Authentication-Results: mx.receiver.example;\n       spf=pass smtp.mailfrom=support@attacker.example;\n       dkim=pass header.d=attacker.example header.s=a1;\n       dmarc=pass header.from=attacker.example\nFrom: "Bank Support"');
  const r = HA.analyze(text);
  assert.ok(r.flags.includes('two-from'));
  assert.equal(r.alignment.from.domain, '');
  assert.equal(r.auth.computed.result, 'none');
  assert.equal(r.auth.dmarc.result, 'pass');
  assert.equal(r.auth.dmarc.disagreement, null);
  for (const x of r.alignment.rows) {
    assert.equal(x.state, 'unknown');
    assert.equal(x.aligned, null);
    assert.equal(x.word, 'No single From domain');
  }
});

// Audit fixes, 2026-10-25

test('an A-R with the receiver\'s authserv-id below its first Received stamp fills no method', () => {
  // ar-injected-above.txt with the injected field moved under the receiver's
  // custody Received, written as mx.google.com, and the real dmarc= removed.
  const lines = fixture('ar-injected-above.txt').split('\n');
  const fake = lines.splice(0, 4).join('\n').replace('mail.sender.example;', 'mx.google.com;').replace('dmarc=pass', 'dmarc=pass header.from=sender.example;\n       arc=pass').replace('header.from=sender.example header.from', 'header.from');
  const text = lines.join('\n').replace(';\n       dmarc=fail (p=REJECT sp=QUARANTINE dis=QUARANTINE) header.from=sender.example', '').replace('DKIM-Signature:', fake + '\nDKIM-Signature:');
  const a = HA.analyze(text).auth;
  assert.equal(a.all.length, 2);
  assert.equal(a.all[1].authserv, 'mx.google.com');
  assert.equal(a.all[0].primary, true);
  assert.equal(a.dmarc.reported, false);
  assert.equal(a.arcResult, null);
  assert.equal(a.dkim[0].result, 'fail');
  assert.equal(a.computed.result, 'fail');
});

test('iCloud\'s per method A-R fields above its custody Received still fill every method', () => {
  const a = run('icloud.txt').auth;
  assert.equal(a.dmarc.result, 'pass');
  assert.equal(a.dkim[0].result, 'pass');
  assert.equal(a.spf.result, 'pass');
  assert.equal(a.arcResult.result, 'none');
  assert.deepEqual(a.receivedSpf.map(x => x.trusted), [true]);
});

test('with no sender side hop, a Received-SPF below the receiver\'s own stamp is not trusted', () => {
  const r = run('received-spf-direct-spoof.txt');
  assert.equal(r.chain.trust.boundaryIdx, 0);
  assert.deepEqual(r.auth.receivedSpf.map(x => x.trusted), [false]);
  assert.notEqual(r.auth.spf.result, 'pass');
  assert.notEqual(r.auth.spf.domain, 'bank.example');
  assert.equal(r.auth.computed.result, 'fail');
});

test('a DKIM result with only header.i is matched by header.b and takes d= from the signature', () => {
  const a = run('dkim-header-i-only.txt').auth;
  assert.equal(a.dkim.length, 1);
  const k = a.dkim[0];
  assert.equal(k.domain, 'shop.example');
  assert.equal(k.signature, 0);
  assert.equal(k.matchedBy, 'header.b');
  assert.equal(k.strict, true);
  assert.equal(a.computed.differ, false);
  assert.deepEqual(a.computed.tags, []);
});
