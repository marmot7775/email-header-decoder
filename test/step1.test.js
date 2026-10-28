'use strict';
// Step 1 spec: input kinds, unfolding repair, addresses, dates, the hop
// chain, and the flags, asserted on analyze() over synthetic fixtures.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { HA, fixture } = require('./load.js');

const run = (name) => HA.analyze(fixture(name));
const hosts = (r) => r.chain.hops.map(h => h.byHost);

test('every fixture analyzes without throwing and returns the step 1 shape', () => {
  for (const f of fs.readdirSync(path.join(__dirname, 'fixtures'))) {
    const r = run(f);
    for (const k of ['input', 'message', 'chain', 'fields', 'flags']) assert.ok(k in r, f + ' has ' + k);
    assert.ok(Array.isArray(r.flags));
    assert.equal(typeof r.input.repairedLines, 'number');
  }
});

test('Gmail delivery: four hops oldest first, TLS on every hop, delays, slowest, total', () => {
  const r = run('gmail-four-hops-tls.txt');
  assert.equal(r.input.kind, 'headers');
  assert.equal(r.chain.count, 4);
  assert.deepEqual(hosts(r), ['smtp.sender.example', 'out2.relay.example', 'mx.google.com', 'gmr-mx.google.com']);
  assert.deepEqual(r.chain.hops.map(h => h.delaySec), [null, 4, 192, 1]);
  assert.ok(r.chain.hops.every(h => h.tls.state === 'pass' && h.tls.version === 'TLS 1.3'));
  assert.equal(r.chain.slowestIdx, 2);
  assert.equal(r.chain.totalSec, 197);
  assert.equal(HA.received.fmtDur(192), '3m 12s');
  assert.equal(r.chain.hops[0].authenticated, true);
  assert.equal(r.chain.hops[3].internal, true);
  // Origin is the address the receiver saw connect, not the laptop behind the relay.
  assert.equal(r.chain.originIp, '198.51.100.20');
  assert.deepEqual(r.flags, []);
});

test('lost indentation: the same headers with every fold stripped read the same, and the repairs are counted', () => {
  const a = run('gmail-four-hops-tls.txt'), b = run('stripped-folding.txt');
  assert.equal(b.fields.length, a.fields.length);
  assert.deepEqual(b.chain.hops.map(h => h.delaySec), a.chain.hops.map(h => h.delaySec));
  assert.equal(b.chain.originIp, a.chain.originIp);
  assert.equal(a.input.repairedLines, 0);
  assert.equal(b.input.repairedLines, 14);
});

test('CRLF line endings and a full .eml read the same as the bare block; the body is not read', () => {
  const a = run('gmail-four-hops-tls.txt');
  const c = run('crlf.txt'), e = run('eml-with-body.txt');
  assert.equal(c.fields.length, a.fields.length);
  assert.deepEqual(c.chain.hops.map(h => h.delaySec), a.chain.hops.map(h => h.delaySec));
  assert.equal(e.input.kind, 'eml');
  assert.equal(e.input.bodyPresent, true);
  assert.equal(e.fields.length, a.fields.length);
  assert.equal(e.message.subject.value, 'Four hops, all encrypted');
});

test('Show original copy: the summary table is skipped and the kind is recorded', () => {
  const r = run('gmail-show-original.txt');
  assert.equal(r.input.kind, 'show-original');
  assert.equal(r.fields[0].name, 'Delivered-To');
  assert.ok(!r.fields.some(f => f.name === 'SPF' || f.name === 'Created at'));
});

test('Microsoft 365: mapi and prod.outlook.com hops are internal, X-Originating-IP is a stated origin kept apart', () => {
  const r = run('m365-mapi-xoip.txt');
  assert.equal(r.chain.count, 3);
  assert.equal(r.chain.hops[0].protocol, 'mapi');
  assert.ok(r.chain.hops.every(h => h.internal));
  assert.equal(r.chain.groups.length, 1);
  assert.equal(r.chain.statedOriginIp.ip, '203.0.113.77');
  assert.notEqual(r.chain.originIp, '203.0.113.77');
  assert.deepEqual(r.message.cc.addresses.map(a => a.address), ['priya@client.example', 'ops@client.example']);
});

test('Exim: helo= and envelope-from read, (TLS1.3) recognised, esmtpsa is authenticated', () => {
  const r = run('exim-auth.txt');
  const [sub, relay] = r.chain.hops;
  assert.equal(sub.helo, 'jos-laptop');
  assert.equal(sub.fromIp, '203.0.113.15');
  assert.equal(sub.authenticated, true);
  assert.equal(sub.tls.version, 'TLS 1.3');
  assert.equal(sub.envelopeFrom, 'jo@isp.example');
  assert.equal(relay.tls.version, 'TLS 1.3');
  assert.equal(relay.delaySec, 2);
});

test('RFC 2047: B and Q words in two charsets join; display names decode; structured fields stay raw', () => {
  const r = run('rfc2047.txt');
  assert.equal(r.message.subject.value, 'Rechnung für Oktober');
  assert.equal(r.message.from.name, 'Jürgen Müller');
  assert.equal(r.message.from.localPart, 'juergen');
  assert.equal(r.message.from.domain, 'sender.example');
  const enc = HA.parse.parseHeaders('Received: from a (=?UTF-8?B?SsO8cmdlbg==?=) by b; Fri, 23 Oct 2026 10:00:00 +0000\nSubject: x\n').fields[0];
  assert.equal(enc.decoded, enc.value);
});

test('addresses: groups, quoted names with commas, the null sender', () => {
  const a = HA.parse.parseAddresses('Team: a@x.example, "B, C" <b@y.example>;, Undisclosed recipients:;');
  assert.deepEqual(a.map(x => x.address), ['a@x.example', 'b@y.example']);
  assert.equal(a[1].name, 'B, C');
  const nul = HA.parse.parseAddresses('<>')[0];
  assert.equal(nul.empty, true);
});

test('dates: PDT, a military zone read as unknown, a two digit year without seconds or weekday', () => {
  const r = run('dates.txt');
  const [a, b, c] = r.chain.hops;
  assert.equal(a.time, Date.UTC(2026, 9, 23, 17, 3, 0));
  assert.equal(a.tzKnown, true);
  assert.equal(b.tzKnown, false);
  assert.equal(c.time, Date.UTC(2026, 9, 23, 17, 5, 0));
  assert.deepEqual(r.chain.hops.map(h => h.delaySec), [null, 60, 60]);
  const d = HA.parse.parseDate('Fri, 23 Oct 2026 10:03:00 PDT (Pacific Daylight Time)');
  assert.equal(d.zone, 'PDT');
  assert.equal(HA.parse.parseDate('not a date').time, null);
});

test('clock skew: a negative delay is kept, flagged, and not chosen as slowest', () => {
  const r = run('negative-delay.txt');
  const h = r.chain.hops[2];
  assert.equal(h.delaySec, -30);
  assert.equal(h.skew, true);
  assert.equal(r.chain.clockSkew, true);
  assert.equal(r.chain.slowestIdx, 1);
  assert.equal(r.chain.totalSec, 10);
});

test('flags: two-from, no-received, no-date, empty-input, not-headers', () => {
  assert.deepEqual(run('two-from.txt').flags, ['two-from']);
  assert.ok(run('missing-received.txt').flags.includes('no-received'));
  assert.ok(HA.analyze('From: a@example.net\nSubject: x\n').flags.includes('no-date'));
  const e = HA.analyze('');
  assert.deepEqual(e.flags, ['empty-input']);
  assert.equal(e.input.kind, 'empty');
  const t = run('random-text.txt');
  assert.deepEqual(t.flags, ['not-headers']);
  assert.equal(t.input.kind, 'not-headers');
});

test('psl: organizationalDomain and sameOperator', () => {
  assert.equal(HA.psl.organizationalDomain('a.b.example.co.uk'), 'example.co.uk');
  assert.equal(HA.psl.sameOperator('mx1.example.com.au', 'smtp.example.com.au'), true);
  assert.equal(HA.psl.sameOperator('mx.example.com', 'mx.example.net'), false);
  assert.equal(HA.psl.sameOperator('', ''), false);
});

test('build: one self contained page whose CSP connects only to dns-audit.com, and no external URLs', () => {
  const { build } = require('../build.js');
  const { csp: CSP } = build();
  const html = fs.readFileSync(path.join(__dirname, '..', 'dist', 'index.html'), 'utf8');
  assert.match(html, /^<!doctype html>/);
  assert.ok(html.includes('http-equiv="Content-Security-Policy" content="' + CSP + '"'));
  // The usage note is the only connection the page may make
  assert.equal((CSP.match(/connect-src ([^;]*)/) || [])[1], 'https://dns-audit.com');
  // script-src allows only the hash of the one inline script, never 'unsafe-inline'.
  assert.ok(!/script-src[^;]*'unsafe-inline'/.test(CSP));
  const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/g)].map(m => m[1]);
  assert.equal(scripts.length, 1);
  const hash = require('crypto').createHash('sha256').update(scripts[0], 'utf8').digest('base64');
  assert.ok(CSP.includes("script-src 'sha256-" + hash + "'"));
  assert.ok(fs.readFileSync(path.join(__dirname, '..', 'dist', '_headers'), 'utf8').includes(CSP));
  // No inline event handlers, which a hash does not allow.
  assert.ok(!/<[a-z][^>]*\son[a-z]+\s*=/i.test(html.replace(/<script>[\s\S]*?<\/script>/g, '')));
  // The only links in the head are the canonical URL and a data: icon;
  // nothing the browser would fetch from another host.
  for (const l of html.match(/<link\b[^>]*>/g) || []) assert.match(l, /rel="canonical"|rel="icon" href="data:/, l);
  assert.ok(!/<script\s+src=|@import|url\(\s*['"]?https?:|<img\b[^>]*src="https?:/i.test(html));
});

test('build: the FAQ structured data matches the FAQ on the page', () => {
  const { build, faqFrom } = require('../build.js');
  build();
  const html = fs.readFileSync(path.join(__dirname, '..', 'dist', 'index.html'), 'utf8');
  const ld = JSON.parse(/<script type="application\/ld\+json">([\s\S]*?)<\/script>/.exec(html)[1]);
  const faq = ld['@graph'].find(x => x['@type'] === 'FAQPage');
  const page = fs.readFileSync(path.join(__dirname, '..', 'ui', 'page.html'), 'utf8');
  const visible = (page.match(/<div class="faq">[\s\S]*?<\/div>/)[0].match(/<summary>/g) || []).length;
  assert.ok(visible >= 3);
  assert.equal(faq.mainEntity.length, visible);
  assert.deepEqual(faq.mainEntity, faqFrom(page));
  assert.match(html, /<title>[^<]+<\/title>[\s\S]*<\/head>/);
  assert.ok(!/<body>[\s\S]*<title>/.test(html), 'title belongs in the head');
});
