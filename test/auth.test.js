'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { HA, fixture } = require('./load.js');

const STATES = ['pass', 'caveat', 'fail', 'unknown'];
const run = (name) => HA.analyze(fixture(name));
const row = (r, kind, domain) => r.alignment.rows.find(x => x.kind === kind && x.domain === domain);

const ALL = ['gmail-show-original.txt', 'exchange-online-inbound.txt', 'exchange-online-internal.txt', 'icloud.txt', 'forwarded.txt', 'folded-garbage.txt',
  'missing-received.txt', 'two-from.txt', 'no-header-block.txt', 'two-dkim.txt', 'spf-bounce-domain.txt', 'subdomain-relaxed.txt', 'unlisted-suffix.txt',
  'arc-forwarded-i2.txt', 'arc-broken.txt', 'ar-unknown-host.txt', 'no-auth-results.txt'];

test('psl: country second-level suffixes, and an approximate flag outside the list', () => {
  assert.equal(HA.psl.orgDomain('mail.example.co.uk'), 'example.co.uk');
  assert.equal(HA.psl.orgDomain('a.b.example.com.au'), 'example.com.au');
  assert.equal(HA.psl.orgDomain('smtp.example.co.jp'), 'example.co.jp');
  assert.equal(HA.psl.orgDomain('news.loja.com.br'), 'loja.com.br');
  assert.equal(HA.psl.lookup('bounce.mailer.example').approximate, false); // generic TLD
  assert.equal(HA.psl.lookup('mail.example.de').approximate, false);       // flat ccTLD
  assert.equal(HA.psl.lookup('example.com.fj').approximate, true);         // fj second levels not listed
  assert.equal(HA.psl.lookup('example.fj').approximate, false);            // two labels: nothing to guess
});

test('Gmail: authserv-id mx.google.com is a Received by host, so the field is the primary and verified', () => {
  const r = run('gmail-show-original.txt');
  const a = r.auth;
  assert.equal(a.all.length, 1);
  assert.equal(a.primary, 0);
  const p = a.all[0];
  assert.equal(p.authserv, 'mx.google.com');
  assert.equal(p.matchedBy, 'host');
  assert.equal(p.trust, 'receiver');
  assert.equal(p.primary, true);
  assert.deepEqual(p.entries.map(e => e.method), ['dkim', 'spf', 'dmarc']);
  const dk = p.entries[0];
  assert.equal(dk.ids['header.i'], '@sender.example');
  assert.equal(dk.ids['header.s'], 'mail2026');
  assert.equal(p.entries[1].ids['smtp.mailfrom'], 'alex@sender.example');
  assert.equal(p.entries[2].ids['header.from'], 'sender.example');
  assert.equal(r.fields[p.src[0]].lower, 'authentication-results');
  assert.equal(a.dmarc.result, 'pass');
  assert.equal(a.dmarc.policy.p, 'quarantine');
  assert.equal(a.computed.result, 'pass');
  assert.equal(a.dmarc.disagreement, null);
});

test('Exchange Online: no authserv-id, writer tied by position, compauth parsed into fields and kept raw', () => {
  const a = run('exchange-online-inbound.txt').auth;
  const p = a.all[0];
  assert.equal(p.authserv, '');
  assert.equal(p.matchedBy, 'position');
  assert.equal(p.writer, 'BN2PEPF000044A7.mail.protection.outlook.com');
  assert.equal(p.trust, 'receiver');
  assert.deepEqual(p.entries.map(e => e.method), ['spf', 'dkim', 'dmarc', 'compauth']);
  assert.equal(a.compauth.result, 'pass');
  assert.equal(a.compauth.reason, '100');
  assert.match(a.compauth.raw, /^compauth=pass reason=100/);
  assert.equal(a.dmarc.policy.action, 'none');
  assert.equal(a.spf.domain, 'billing.vendor.example');
  assert.equal(a.spf.word, 'Aligned, relaxed');
  assert.equal(row(run('exchange-online-inbound.txt'), 'dkim', 'vendor.example').word, 'Aligned');
});

test('Exchange Online: an id-less field just below the receiving hop still belongs to the receiver', () => {
  const a = run('forwarded.txt').auth;
  assert.equal(a.all[0].trust, 'receiver');
  assert.equal(a.all[0].writer, 'DM6PR01CA0001.prod.exchangelabs.com');
});

test('iCloud: one field per method, all tied to Apple by operator, results gathered across them', () => {
  const a = run('icloud.txt').auth;
  assert.equal(a.all.length, 5);
  assert.ok(a.all.every(x => x.trust === 'receiver' && x.matchedBy === 'operator'));
  assert.equal(a.spf.result, 'pass');
  assert.equal(a.dkim[0].result, 'pass');
  assert.equal(a.dmarc.result, 'pass');
  assert.equal(a.arcResult.result, 'none');
});

test('two DKIM signatures: the brand one aligns, the ESP one passed but does not', () => {
  const r = run('two-dkim.txt');
  assert.equal(r.auth.dkim.length, 2);
  const brand = row(r, 'dkim', 'brand.example');
  const esp = row(r, 'dkim', 'esp-mail.example');
  assert.equal(brand.selector, 's1');
  assert.equal(brand.state, 'pass');
  assert.equal(brand.strict, true);
  assert.equal(esp.selector, 'esp1');
  assert.equal(esp.state, 'caveat');
  assert.equal(esp.word, 'Passed, not aligned');
  for (const x of [brand, esp]) assert.ok(x.src.some(i => r.fields[i].lower === 'dkim-signature') && x.src.some(i => r.fields[i].lower === 'authentication-results'));
  assert.equal(r.auth.computed.result, 'pass');
  assert.deepEqual(r.auth.computed.by.strict, ['DKIM brand.example']);
});

test('SPF passes on a bounce domain that does not align, DKIM fails: computed fail agrees with reported', () => {
  const r = run('spf-bounce-domain.txt');
  const spf = r.auth.spf;
  assert.equal(spf.domain, 'mailer.esp.example');
  assert.equal(spf.identity, 'smtp.mailfrom');
  assert.equal(spf.result, 'pass');
  assert.equal(spf.state, 'caveat');
  assert.equal(spf.relaxed, false);
  assert.equal(row(r, 'dkim', 'shop.example').state, 'fail');
  assert.equal(r.auth.computed.result, 'fail');
  assert.equal(r.auth.dmarc.result, 'fail');
  assert.equal(r.auth.dmarc.disagreement, null);
});

test('subdomain From aligns only in relaxed mode: both modes shown, the record decides', () => {
  const r = run('subdomain-relaxed.txt');
  const c = r.auth.computed;
  assert.equal(c.relaxed, true);
  assert.equal(c.strict, false);
  assert.equal(c.differ, true);
  assert.equal(c.result, 'depends');
  assert.deepEqual(c.tags, ['adkim', 'aspf']);
  assert.equal(r.alignment.from.org, 'brand.example');
  assert.ok(r.alignment.rows.every(x => x.relaxedOnly && x.state === 'pass' && x.word === 'Aligned, relaxed'));
  assert.ok(r.auth.notes.some(n => n.state === 'caveat' && /DMARC record|adkim/.test(n.technical)));
  assert.equal(r.auth.dmarc.disagreement, null); // reported pass matches the relaxed default
});

test('relaxed-only alignment the receiver reported as dmarc=fail names strict mode as the reason', () => {
  const r = HA.analyze(fixture('subdomain-relaxed.txt').replace('dmarc=pass (p=NONE', 'dmarc=fail (p=NONE'));
  assert.equal(r.auth.dmarc.disagreement.reason, 'strict-mode');
  assert.match(r.auth.dmarc.disagreement.technical, /adkim=s and aspf=s/);
});

test('From domain under a suffix outside the list: the organizational domain is flagged approximate', () => {
  const r = run('unlisted-suffix.txt');
  assert.equal(r.alignment.from.approximate, true);
  assert.ok(r.alignment.rows.every(x => x.approximate));
  const n = r.alignment.notes.find(x => /approximation without DNS/.test(x.technical));
  assert.ok(n);
  assert.equal(n.state, 'caveat');
});

test('ARC forwarded through a list and a forwarder: cv=pass at i=2, sealers and pre-forward results kept', () => {
  const r = run('arc-forwarded-i2.txt');
  const arc = r.auth.arc;
  assert.equal(arc.state, 'pass');
  assert.deepEqual(arc.problems, []);
  assert.deepEqual(arc.instances.map(s => s.i), [1, 2]);
  assert.deepEqual(arc.instances.map(s => s.cv), ['none', 'pass']);
  assert.deepEqual(arc.instances.map(s => s.sealer.domain), ['list.example', 'forward.example']);
  assert.deepEqual(arc.instances.map(s => s.sealer.host), ['mx.list.example', 'mx.forward.example']);
  // Each sealer is tied to the hop where it received the message.
  assert.equal(r.chain.hops[arc.instances[0].hopIdx].byHost, 'mx.list.example');
  assert.equal(r.chain.hops[arc.instances[1].hopIdx].byHost, 'mx.forward.example');
  assert.ok(arc.instances[0].preForward.some(x => x.method === 'dmarc' && x.result === 'pass'));
  assert.ok(arc.instances.every(s => s.src.length === 3 && s.src.every(i => /^arc-/.test(r.fields[i].lower))));
  assert.equal(r.auth.arcResult.result, 'pass');
  assert.equal(r.auth.dmarc.result, 'fail');
  assert.equal(r.auth.computed.result, 'fail');
});

test('a receiver that reports dmarc=pass on the strength of ARC gets the ARC override reason', () => {
  const text = fixture('arc-forwarded-i2.txt').replace('dmarc=fail (p=REJECT sp=REJECT dis=NONE) header.from=author.example', 'dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=author.example');
  const r = HA.analyze(text);
  assert.equal(r.auth.dmarc.result, 'pass');
  assert.equal(r.auth.computed.result, 'fail');
  assert.equal(r.auth.dmarc.disagreement.reason, 'arc-override');
});

test('a reported pass with nothing aligned and no ARC falls back to local policy', () => {
  const text = fixture('spf-bounce-domain.txt').replace('dmarc=fail (p=QUARANTINE', 'dmarc=pass (p=QUARANTINE');
  const d = HA.analyze(text).auth.dmarc.disagreement;
  assert.equal(d.reason, 'local-policy');
  assert.ok(STATES.includes(d.state));
});

test('broken ARC chain: gap, missing signature and cv=fail are each named', () => {
  const r = run('arc-broken.txt');
  const arc = r.auth.arc;
  assert.equal(arc.state, 'fail');
  assert.deepEqual(arc.instances.map(s => s.i), [1, 3]);
  const texts = arc.problems.map(p => p.text).join('\n');
  assert.match(texts, /not contiguous/);
  assert.match(texts, /i=3 is incomplete: no ARC-Message-Signature/);
  assert.match(texts, /i=3 carries cv=fail/);
  assert.equal(r.auth.arcResult.result, 'fail');
  assert.ok(r.auth.notes.filter(n => n.state === 'fail').length >= 3);
});

test('Authentication-Results from a host missing from the Received chain is unverified, not primary', () => {
  const r = run('ar-unknown-host.txt');
  const a = r.auth;
  assert.equal(a.all.length, 2);
  assert.equal(a.all[0].authserv, 'mx.receiver.example');
  assert.equal(a.all[0].primary, true);
  const forged = a.all[1];
  assert.equal(forged.authserv, 'mx.trusted-filter.example');
  assert.equal(forged.trust, 'unverified');
  assert.equal(forged.primary, false);
  const n = a.notes.find(x => /unverified/.test(x.technical));
  assert.equal(n.state, 'unknown');
  assert.match(n.technical, /sender could have added it/);
  assert.deepEqual(n.src, forged.src);
  // Its passes do not leak into the reported results.
  assert.equal(a.spf.result, 'fail');
  assert.equal(a.dmarc.result, 'fail');
});

test('no Authentication-Results: identifiers still drawn, every connector grey, computed DMARC unknown', () => {
  const r = run('no-auth-results.txt');
  assert.equal(r.auth.all.length, 0);
  assert.equal(r.auth.primary, -1);
  assert.equal(r.auth.computed.result, 'unknown');
  assert.equal(r.auth.computed.why, 'no-results');
  const dk = row(r, 'dkim', 'sender.example');
  assert.equal(dk.state, 'unknown');
  assert.equal(dk.selector, 'mail2026');
  assert.equal(r.auth.spf.identity, 'Return-Path');
  assert.equal(r.auth.spf.state, 'unknown');
  assert.ok(r.auth.notes.some(n => /No Authentication-Results/.test(n.technical)));
});

test('DKIM-Signature tags d, s, i, a, c, bh, h, t and x are read', () => {
  const s = HA.auth.parseDkimSignature('v=1; a=rsa-sha256; c=relaxed/simple; d=Example.COM; s=k1; i=@example.com; t=100; x=50; h=to:subject; bh=abc=; b=Zz');
  assert.equal(s.d, 'example.com');
  assert.equal(s.s, 'k1');
  assert.equal(s.i, '@example.com');
  assert.equal(s.a, 'rsa-sha256');
  assert.equal(s.c, 'relaxed/simple');
  assert.equal(s.bh, 'abc=');
  assert.deepEqual(s.signedHeaders, ['to', 'subject']);
  assert.equal(s.t, 100);
  assert.equal(s.x, 50);
  assert.ok(s.notes.some(n => /From/.test(n)));
  assert.ok(s.notes.some(n => /expiry/.test(n)));
});

test('every auth and alignment sentence carries both readers and cites real fields; results stay JSON-safe', () => {
  for (const name of ALL) {
    const r = run(name);
    for (const s of [].concat(r.auth.notes, r.alignment.notes, r.chain.notes)) {
      assert.ok(STATES.includes(s.state), name);
      assert.ok(s.technical && s.plain, name);
      for (const i of s.src) assert.ok(r.fields[i], name + ' src ' + i);
    }
    for (const x of r.alignment.rows) for (const i of x.src) assert.ok(r.fields[i], name + ' row src');
    assert.deepEqual(JSON.parse(JSON.stringify(r)), r, name);
  }
});
