'use strict';
// Regression tests for the confirmed bug reports of the 2026-11-01 review
// (issues 12 to 22). Synthetic input only.
const test = require('node:test');
const assert = require('node:assert/strict');
const { HA, fixture } = require('./load.js');

// Issue 12: the From address is the angle-addr outside quotes and comments.
test('parseAddresses ignores an address inside a quoted display name', () => {
  const a = HA.parse.parseAddresses('"PayPal <service@paypal.com>" <alerts@evil.example>');
  assert.equal(a.length, 1);
  assert.equal(a[0].domain, 'evil.example');
  assert.equal(a[0].display, 'PayPal <service@paypal.com>');
});

test('parseAddresses ignores an encoded word that decodes to an address', () => {
  const a = HA.parse.parseAddresses('=?utf-8?B?UGF5UGFsIDxzZXJ2aWNlQHBheXBhbC5jb20+?= <alerts@evil.example>');
  assert.equal(a.length, 1);
  assert.equal(a[0].domain, 'evil.example');
  assert.equal(a[0].display, 'PayPal <service@paypal.com>');
});

test('parseAddresses ignores an address inside a comment', () => {
  assert.equal(HA.parse.parseAddresses('alerts@bank.example (Bank <x@evil.example>)')[0].domain, 'bank.example');
  assert.equal(HA.parse.parseAddresses('Bank (x <a@evil.example>) <alerts@bank.example>')[0].domain, 'bank.example');
});

test('a quoted fake address in the display name sets the From domain and raises the display name flag', () => {
  const text = [
    'Received: from evil.example (evil.example [198.51.100.66])',
    '\tby mx.google.com with ESMTPS id abc',
    '\tfor <user@example.org>; Fri, 23 Oct 2026 11:00:02 -0700 (PDT)',
    'Authentication-Results: mx.google.com;',
    '\tdkim=pass header.i=@evil.example header.s=s1;',
    '\tspf=pass smtp.mailfrom=alerts@evil.example;',
    '\tdmarc=pass (p=NONE sp=NONE dis=NONE) header.from=evil.example',
    'DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=evil.example; s=s1; h=from:to:subject; bh=x=; b=Synthetic',
    'From: "PayPal <service@paypal.com>" <alerts@evil.example>',
    'To: user@example.org',
    'Subject: hi',
    'Date: Fri, 23 Oct 2026 18:00:00 +0000',
    'Message-ID: <a@evil.example>',
    'Return-Path: <alerts@evil.example>',
    ''].join('\n');
  const r = HA.analyze(text);
  assert.equal(r.message.from.domain, 'evil.example');
  assert.ok(!/paypal\.com publishes/.test(JSON.stringify(r.finding)));
  assert.ok(r.finding.flags.length > 0, 'display name flag');
});

// Issue 22: impossible dates are unreadable, not rolled forward.
test('parseDate returns no time for impossible dates', () => {
  for (const s of ['Fri, 23 Oct 2026 25:14:06 +0000', 'Fri, 31 Feb 2026 09:14:06 +0000', 'Fri, 23 Oct 2026 09:14:06 +9999', 'Fri, 23 Oct 2026 09:61:06 +0000', 'Fri, 23 Oct 2026 09:14:61 +0000', 'Fri, 0 Oct 2026 09:14:06 +0000']) {
    const d = HA.parse.parseDate(s);
    assert.equal(d.time, null, s);
    assert.equal(d.tzKnown, false, s);
  }
  assert.notEqual(HA.parse.parseDate('Sun, 29 Feb 2032 23:59:60 +0000').time, null);
  assert.notEqual(HA.parse.parseDate('Fri, 23 Oct 2026 09:14:06 +0530').time, null);
});

// Issue 13: a second id-less Authentication-Results at Exchange Online is not Microsoft's.
test('an injected id-less Authentication-Results under the Exchange Online stamp fills no method', () => {
  const t = fixture('forwarded.txt').replace('X-MS-Exchange-Organization-AuthSource', 'Authentication-Results: arc=pass\nX-MS-Exchange-Organization-AuthSource');
  const r = HA.analyze(t);
  assert.equal(r.auth.all.length, 2);
  assert.equal(r.auth.all[0].primary, true);
  assert.equal(r.auth.all[1].untrusted, true);
  assert.equal(r.auth.arcResult, null);
  assert.notEqual(r.finding.status, 'forwarded');
});

// Issue 16: a DKIM result with header.i and header.s only is matched inside the i= domain.
test('a DKIM result naming header.i is not matched to another domain\'s signature with the same selector', () => {
  const text = [
    'Authentication-Results: mx1.receiver.example;',
    ' dkim=pass header.i=@esp.example header.s=s1;',
    ' spf=pass smtp.mailfrom=esp.example;',
    ' dmarc=fail header.from=bank.example',
    'Received: from o1.esp.example (o1.esp.example [198.51.100.13])',
    '\tby mx1.receiver.example (Postfix) with ESMTPS id ABC',
    '\tfor <user@receiver.example>; Fri, 23 Oct 2026 16:20:05 +0000 (UTC)',
    'DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=bank.example; s=s1; h=from:to:subject; bh=x=; b=BankSigSynthetic',
    'DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=esp.example; s=s1; h=from:to:subject; bh=y=; b=EspSigSynthetic',
    'From: Bank <alerts@bank.example>',
    'To: user@receiver.example',
    'Subject: Statement',
    'Date: Fri, 23 Oct 2026 16:20:00 +0000',
    'Message-ID: <x@bank.example>',
    'Return-Path: <bounce@esp.example>',
    ''].join('\n');
  const r = HA.analyze(text);
  const bank = r.auth.dkim.find(x => x.domain === 'bank.example');
  const esp = r.auth.dkim.find(x => x.domain === 'esp.example');
  assert.equal(esp.result, 'pass');
  assert.equal(esp.aligned, false);
  assert.equal(bank.result, '');
  assert.equal(r.auth.computed.result, 'fail');
  assert.equal(r.finding.status, 'fail');
});

// Issue 17: the origin address is the bracketed literal, not digits inside a reverse DNS name.
test('findIp reads the address literal, not digits in a host name', () => {
  assert.equal(HA.received.findIp('static.7.100.51.198.clients.your-server.de. [198.51.100.7]'), '198.51.100.7');
  assert.equal(HA.received.findIp('static.7.100.51.198.clients.your-server.de.'), '');
  assert.equal(HA.received.findIp('mail.example [IPv6:2001:db8::7]'), '2001:db8::7');
  assert.equal(HA.received.findIp('203.0.113.20'), '203.0.113.20');
  assert.equal(HA.received.findIp('2603:10b6:408:111::32'), '2603:10b6:408:111::32');
});

const GMAIL = (received, extra) => [
  'Received: ' + received.join('\n\t'),
  'Authentication-Results: mx.google.com;',
  '\tspf=fail (google.com: domain of alerts@bank.example does not designate 198.51.100.66 as permitted sender) smtp.mailfrom=alerts@bank.example;',
  '\tdmarc=fail (p=REJECT sp=REJECT dis=REJECT) header.from=bank.example',
  extra || '',
  'From: Bank <alerts@bank.example>',
  'To: user@example.org',
  'Subject: hi',
  'Date: Fri, 23 Oct 2026 18:00:00 +0000',
  'Message-ID: <a@bank.example>',
  'Return-Path: <alerts@bank.example>',
  ''].filter(l => l !== '').join('\n') + '\n';

test('a reverse DNS name with digits does not become the origin IP', () => {
  const r = HA.analyze(GMAIL(['from mail.shop.example (static.7.100.51.198.clients.your-server.de. [198.51.100.7])', 'by mx.google.com with ESMTPS id abc', 'for <user@example.org>; Fri, 23 Oct 2026 11:00:02 -0700 (PDT)']));
  assert.equal(r.chain.originIp, '198.51.100.7');
});

// Issue 15: a Received line the sender wrote naming the receiver does not move custody.
test('a forged Received field naming the receiver does not move the trust line', () => {
  const real = ['from evil.example (evil.example [198.51.100.66])', 'by mx.google.com with ESMTPS id abc', 'for <user@example.org>; Fri, 23 Oct 2026 11:00:02 -0700 (PDT)'];
  const forged = 'Received: from mail.bank.example ([203.0.113.5])\n\tby mx.google.com with ESMTP id zzz\n\tfor <user@example.org>; Fri, 23 Oct 2026 10:59:58 -0700 (PDT)';
  const text = GMAIL(real, forged);
  // The forged line must sit below the real stamp, after the real Authentication-Results.
  const r = HA.analyze(text);
  assert.equal(r.chain.originIp, '198.51.100.66');
  assert.equal(r.chain.trust.boundaryIdx, r.chain.count - 1);
});

test('an Authentication-Results field between forged Received lines is not the receiver\'s', () => {
  const real = ['from evil.example (evil.example [198.51.100.66])', 'by mx.google.com with ESMTPS id abc', 'for <user@example.org>; Fri, 23 Oct 2026 11:00:02 -0700 (PDT)'];
  const extra = [
    'Received: from mail.bank.example ([203.0.113.5])\n\tby mx.google.com with ESMTP id zzz\n\tfor <user@example.org>; Fri, 23 Oct 2026 10:59:58 -0700 (PDT)',
    'Authentication-Results: mx.google.com; dkim=pass header.i=@bank.example header.s=s1 header.b=Ab12Cd34',
    'Received: from mail.bank.example ([203.0.113.5])\n\tby mx.google.com with ESMTP id yyy\n\tfor <user@example.org>; Fri, 23 Oct 2026 10:59:57 -0700 (PDT)'].join('\n');
  const r = HA.analyze(GMAIL(real, extra));
  assert.equal(r.chain.originIp, '198.51.100.66');
  assert.equal(r.auth.dkim.filter(d => d.result === 'pass').length, 0);
  assert.equal(r.finding.status, 'fail');
});

// Issue 18: public suffixes below a ccTLD are not shared organizational domains.
test('names under on.ca, il.us, vic.gov.au and wa.edu.au keep their own organizational domain', () => {
  const org = (d) => HA.psl.lookup(d).org;
  assert.notEqual(org('town.on.ca'), org('evil.on.ca'));
  assert.equal(org('ci.springfield.il.us'), 'springfield.il.us');
  assert.notEqual(org('education.vic.gov.au'), org('health.vic.gov.au'));
  assert.equal(org('x.wa.edu.au'), 'x.wa.edu.au');
});

test('a three label name under a ccTLD the list does not know deeply is marked approximate', () => {
  for (const d of ['x.mi.it', 'a.tokyo.jp', 'shop.example.us']) assert.equal(HA.psl.lookup(d).approximate, true, d);
  assert.equal(HA.psl.lookup('mail.example.co.uk').approximate, false);
});

test('DKIM and SPF from one Victorian government body do not align with another', () => {
  const text = [
    'Received: from mail.example.org (mail.example.org [198.51.100.9])',
    '\tby mx1.receiver.example (Postfix) with ESMTPS id ABC',
    '\tfor <user@receiver.example>; Fri, 23 Oct 2026 16:20:05 +0000 (UTC)',
    'Authentication-Results: mx1.receiver.example;',
    '\tdkim=pass header.d=education.vic.gov.au header.s=s1;',
    '\tspf=pass smtp.mailfrom=bounce@education.vic.gov.au',
    'DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=education.vic.gov.au; s=s1; h=from:to:subject; bh=x=; b=Synthetic',
    'From: Notices <notices@health.vic.gov.au>',
    'To: user@receiver.example',
    'Subject: hi',
    'Date: Fri, 23 Oct 2026 16:20:00 +0000',
    'Message-ID: <x@health.vic.gov.au>',
    'Return-Path: <bounce@education.vic.gov.au>',
    ''].join('\n');
  const r = HA.analyze(text);
  assert.equal(r.auth.computed.result, 'fail');
  assert.notEqual(r.finding.status, 'pass');
});

// Issue 19: the quoted sp= is not assigned to the parent when the disposition followed p=.
test('a subdomain whose disposition followed p= is not told the parent sp= applied', () => {
  const text = fixture('dmarc-subdomain-sp.txt').replace('(p=REJECT sp=NONE dis=NONE)', '(p=QUARANTINE sp=NONE dis=QUARANTINE)');
  const c = HA.analyze(text).finding.consequence;
  assert.ok(!/shop\.example publishes sp=none/.test(c.technical), c.technical);
  assert.match(c.technical, /quoted p=quarantine and sp=none/);
  assert.match(c.technical, /sent this message to spam \(dis=QUARANTINE\)/);
  assert.ok(!/asks for no action/.test(c.technical), c.technical);
  assert.ok(!/asks mail providers to send fake mail to spam/.test(c.plain) || /news\.shop\.example/.test(c.plain), c.plain);
});

// Issue 21: the link guard compares whole hosts, not prefixes.
test('build link guard refuses look-alike hosts, other accounts, case tricks and protocol-relative URLs', () => {
  const { badLinks, linkAllowed } = require('../build.js');
  for (const u of ['https://dns-audit.com.evil.example/x', 'https://github.com/marmot7775-phish/repo', 'https://www.linkedin.com/in/neilanuskiewiczfake', 'HTTPS://evil.example/', '//evil.example/x', 'https://evil.example/', 'https://datatracker.ietf.org/doc/rfc7489/', 'https://user@dns-audit.com@evil.example/', 'mailto:x@evil.example']) {
    assert.equal(linkAllowed(u), false, u);
    assert.deepEqual(badLinks('<a href="' + u + '">x</a>'), [u], u);
  }
  for (const u of ['https://dns-audit.com/about', 'https://headers.dns-audit.com/', 'https://aprf.dns-audit.com/', 'https://www.linkedin.com/in/neilanuskiewicz/', 'https://github.com/marmot7775/email-header-decoder', 'mailto:dns@dns-audit.com', '/', '#top']) {
    assert.equal(linkAllowed(u), true, u);
    assert.deepEqual(badLinks('<a href="' + u + '">x</a>'), [], u);
  }
});

test('build link guard also reads src, single quoted and unquoted attributes, and URLs in text', () => {
  const { badLinks } = require('../build.js');
  assert.deepEqual(badLinks('<img src=\'https://evil.example/a.png\'>'), ['https://evil.example/a.png']);
  assert.deepEqual(badLinks('<script src=//evil.example/x.js></script>'), ['//evil.example/x.js']);
  assert.deepEqual(badLinks('<p>see https://evil.example/page</p>'), ['https://evil.example/page']);
  assert.deepEqual(badLinks('<svg xmlns="http://www.w3.org/2000/svg"></svg>'), []);
});

test('build does not filter HTML with a script regular expression', () => {
  const src = require('fs').readFileSync(require('path').join(__dirname, '..', 'build.js'), 'utf8');
  assert.ok(!/<script\\b/i.test(src.replace(/'<script>'[^\n]*/g, '')), 'no script tag pattern');
});
