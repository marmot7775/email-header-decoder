'use strict';
// Regression tests for the hunt-2026-11 issues (27 to 43). Synthetic input only.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { HA, fixture } = require('./load.js');
const { SIMPLE_BANNED } = require('./simple-words.js');

const root = path.join(__dirname, '..');
const read = (p) => fs.readFileSync(path.join(root, p), 'utf8');
const j = (lines) => lines.join('\n') + '\n';

// Issue 27: SPF is the MAIL FROM result, never the HELO one, unless the
// reverse path is null (RFC 7208 2.4, RFC 9989 3.2.4).
const HELO_FIRST_AR = j([
  'Authentication-Results: mx.receiver.example;',
  ' spf=pass smtp.helo=mail.sender.example;',
  ' spf=fail smtp.mailfrom=bounce@sender.example;',
  ' dkim=none;',
  ' dmarc=fail (p=REJECT dis=REJECT) header.from=sender.example',
  'Received: from mail.sender.example (mail.sender.example [203.0.113.5])',
  ' by mx.receiver.example (Postfix) with ESMTPS id 1',
  ' for <me@receiver.example>; Mon, 02 Nov 2026 10:00:04 +0000',
  'Return-Path: <bounce@sender.example>',
  'From: News <news@sender.example>',
  'To: me@receiver.example',
  'Subject: Hello',
  'Date: Mon, 02 Nov 2026 10:00:00 +0000',
  'Message-ID: <1@sender.example>',
]);
const HELO_FIRST_RSPF = j([
  'Received-SPF: pass (mx.receiver.example: domain of relay.sender.example designates 203.0.113.5 as permitted sender) identity=helo; client-ip=203.0.113.5; helo=relay.sender.example; envelope-from=bounce@evil.example; receiver=me@receiver.example',
  'Received-SPF: fail (mx.receiver.example: domain of evil.example does not designate 203.0.113.5 as permitted sender) identity=mailfrom; client-ip=203.0.113.5; helo=relay.sender.example; envelope-from=bounce@evil.example; receiver=me@receiver.example',
  'Authentication-Results: mx.receiver.example; dkim=none; dmarc=fail header.from=sender.example',
  'Received: from relay.sender.example (relay.sender.example [203.0.113.5])',
  ' by mx.receiver.example (Postfix) with ESMTPS id 2',
  ' for <me@receiver.example>; Mon, 02 Nov 2026 10:00:04 +0000',
  'Return-Path: <bounce@evil.example>',
  'From: News <news@sender.example>',
  'To: me@receiver.example',
  'Subject: Hello',
  'Date: Mon, 02 Nov 2026 10:00:00 +0000',
  'Message-ID: <2@sender.example>',
]);

test('27: an Authentication-Results HELO pass listed first is not the Return-Path result', () => {
  const r = HA.analyze(HELO_FIRST_AR);
  assert.equal(r.auth.spf.result, 'fail');
  assert.equal(r.auth.spf.domain, 'sender.example');
  assert.equal(r.auth.spf.identity, 'smtp.mailfrom');
  assert.equal(r.auth.computed.result, 'fail');
  assert.equal(r.auth.dmarc.disagreement, null);
  assert.match(r.finding.headline.technical, /SPF failed for the Return-Path domain sender\.example/);
  assert.doesNotMatch(r.finding.cause.technical, /local policy/);
});

test('27: a Received-SPF HELO pass listed first is not the MAIL FROM result', () => {
  const r = HA.analyze(HELO_FIRST_RSPF);
  assert.equal(r.auth.spf.result, 'fail');
  assert.equal(r.auth.spf.domain, 'evil.example');
  assert.equal(r.auth.computed.result, 'fail');
  assert.equal(r.auth.dmarc.disagreement, null);
  assert.doesNotMatch(JSON.stringify([r.finding.headline, r.finding.fixes]), /aspf/);
});

test('27: a HELO-only Authentication-Results entry with a real Return-Path gives no SPF result', () => {
  const r = HA.analyze(HELO_FIRST_AR.replace(' spf=fail smtp.mailfrom=bounce@sender.example;\n', ''));
  assert.equal(r.auth.spf.result, '');
  assert.equal(r.auth.spf.domain, 'sender.example');
  assert.equal(r.auth.computed.result, 'fail');
});

test('27: a HELO entry still counts for a null reverse path', () => {
  const r = HA.analyze(fixture('null-return-path-helo.txt'));
  assert.equal(r.auth.spf.result, 'pass');
  assert.equal(r.auth.spf.domain, 'mta.notify.example');
  assert.equal(r.auth.computed.result, 'pass');
});

// Issue 28: the pass headline names the HELO identity for a null reverse path.
test('28: the pass headline for a null Return-Path names the HELO identity', () => {
  const r = HA.analyze(fixture('null-return-path-helo.txt'));
  assert.match(r.finding.headline.technical, /HELO identity mta\.notify\.example/);
  assert.doesNotMatch(r.finding.headline.technical, /Return-Path domain/);
  assert.match(r.finding.headline.plain, /called itself mta\.notify\.example/);
});

// Issue 29: a U-label From domain aligns with the same domain as an A-label.
const IDN = j([
  'Received: from mail.example (mail.example [203.0.113.5])',
  ' by mx.google.com with ESMTPS id a for <me@gmail.com>;',
  ' Mon, 02 Nov 2026 10:00:04 -0800 (PST)',
  'Authentication-Results: mx.google.com;',
  ' dkim=pass header.i=@xn--bcher-kva.example header.s=s1 header.b=abcd;',
  ' spf=pass smtp.mailfrom=bounce@xn--bcher-kva.example;',
  ' dmarc=pass (p=REJECT dis=NONE) header.from=xn--bcher-kva.example',
  'Return-Path: <bounce@xn--bcher-kva.example>',
  'From: Buecher <news@bücher.example>',
  'To: me@gmail.com',
  'Subject: Hello',
  'Date: Mon, 02 Nov 2026 10:00:00 -0000',
  'Message-ID: <1@xn--bcher-kva.example>',
  'DKIM-Signature: v=1; a=rsa-sha256; d=xn--bcher-kva.example; s=s1; h=from:to:subject; bh=x; b=abcdefg',
]);

test('29: a From domain in a U-label aligns with its A-label', () => {
  const r = HA.analyze(IDN);
  assert.equal(r.auth.computed.result, 'pass');
  assert.ok(r.auth.dkim[0].strict, 'DKIM strict');
  assert.ok(r.auth.spf.strict, 'SPF strict');
  assert.equal(r.finding.status, 'pass');
  assert.equal(r.finding.state, 'pass');
  assert.equal(r.alignment.from.domain, 'bücher.example', 'display keeps the U-label');
});

test('29: look-alike letters that NFKC folds to ASCII still never align', () => {
  const t = IDN.replace(/xn--bcher-kva/g, 'paypal').replace('news@bücher.example', 'news@𝐩𝐚𝐲𝐩𝐚𝐥.example');
  const r = HA.analyze(t);
  assert.equal(r.auth.computed.result, 'fail');
  assert.ok(r.finding.flags.some(f => f.lookalike));
});

// Issue 30: a DKIM result with only header.i and no matching signature.
const I_ONLY = j([
  'Received: from mail.sender.example (mail.sender.example [203.0.113.5])',
  ' by mx.google.com with ESMTPS id a for <me@gmail.com>;',
  ' Mon, 02 Nov 2026 10:00:04 -0800 (PST)',
  'Authentication-Results: mx.google.com;',
  ' dkim=pass header.i=@mail.sender.example header.s=s1 header.b=abcd;',
  ' spf=none smtp.mailfrom=bounce@other.example;',
  ' dmarc=pass (p=REJECT dis=NONE) header.from=sender.example',
  'Return-Path: <bounce@other.example>',
  'From: News <news@sender.example>',
  'To: me@gmail.com',
  'Subject: Hello',
  'Date: Mon, 02 Nov 2026 10:00:00 -0000',
  'Message-ID: <1@sender.example>',
]);

test('30: a DKIM row built from header.i alone leaves strict alignment unknown', () => {
  const r = HA.analyze(I_ONLY);
  const k = r.auth.dkim[0];
  assert.equal(k.dFromI, true);
  assert.equal(k.relaxed, true);
  assert.equal(k.strict, null);
  assert.equal(r.auth.computed.result, 'pass');
  assert.equal(r.auth.computed.strict, null);
  assert.doesNotMatch(r.finding.headline.technical, /DKIM d=/);
  assert.match(r.finding.headline.technical, /i=@mail\.sender\.example/);
  assert.doesNotMatch(JSON.stringify(r.alignment.notes), /adkim=s it would not count/);
});

test('30: with dmarc=fail the fix does not guess at d= or adkim', () => {
  const r = HA.analyze(I_ONLY.replace('dmarc=pass (p=REJECT dis=NONE)', 'dmarc=fail (p=REJECT dis=REJECT)'));
  const all = JSON.stringify(r.finding.fixes);
  assert.doesNotMatch(all, /Sign with d=sender\.example rather than a subdomain/);
  assert.doesNotMatch(all, /adkim=s/);
  assert.notEqual(r.auth.dmarc.disagreement && r.auth.dmarc.disagreement.reason, 'strict-mode');
});

test('30: header.i equal to an organizational From domain is a strict match', () => {
  const r = HA.analyze(I_ONLY.replace('header.i=@mail.sender.example', 'header.i=@sender.example'));
  assert.equal(r.auth.dkim[0].strict, true);
});

// Issue 31: invisible and bidirectional characters.
const ZW = '​';
const HIDDEN = j([
  'Received: from mail.sender.example (mail.sender.example [203.0.113.5])',
  ' by mx.google.com with ESMTPS id a for <me@gmail.com>;',
  ' Mon, 02 Nov 2026 10:00:04 -0800 (PST)',
  'Authentication-Results: mx.google.com;',
  ' dkim=pass header.i=@sender.example header.s=s1 header.b=abcd;',
  ' spf=fail smtp.mailfrom=bounce@other.example;',
  ' dmarc=fail (p=REJECT dis=REJECT) header.from=sen' + ZW + 'der.example',
  'From: News <news@sen' + ZW + 'der.example>',
  'To: me@gmail.com',
  'Subject: Hello',
  'Date: Mon, 02 Nov 2026 10:00:00 -0000',
  'Message-ID: <1@sender.example>',
  'DKIM-Signature: v=1; a=rsa-sha256; d=sender.example; s=s1; h=from:to:subject; bh=x; b=abcdefg',
]);

test('31: a zero width character in the From domain survives and is flagged', () => {
  const r = HA.analyze(HIDDEN);
  assert.ok(r.fields.find(f => f.lower === 'from').raw.includes(ZW));
  assert.ok(r.message.from.domain.includes(ZW));
  assert.equal(r.auth.dkim[0].relaxed, false);
  assert.equal(r.auth.computed.result, 'fail');
  assert.ok(r.flags.includes('hidden-characters'));
  const fl = r.finding.flags.find(f => f.hidden);
  assert.ok(fl, 'hidden character sentence');
  assert.equal(fl.state, 'fail');
  assert.match(fl.technical, /U\+200B/);
  assert.doesNotMatch(r.finding.cause.technical, /local policy/);
});

test('31: a bidirectional override in the From domain is flagged', () => {
  const r = HA.analyze(HIDDEN.replace(/sen​der\.example/g, 'sender‮.example'));
  assert.ok(r.flags.includes('hidden-characters'));
  assert.match(r.finding.flags.find(f => f.hidden).technical, /U\+202E/);
});

test('31: rich text soft hyphens inside field names are still removed', () => {
  const t = HIDDEN.replace(/sen​der\.example/g, 'sender.example').replace('Authentication-Results:', 'Authen­tication-Results:').replace('From: News <news@sender.example>', 'From: News <news@sen­der.example>');
  const r = HA.analyze(t);
  assert.ok(r.fields.some(f => f.lower === 'authentication-results'));
  assert.equal(r.message.from.domain, 'sender.example');
  assert.ok(!r.flags.includes('hidden-characters'));
});

test('31: the page marks hidden characters visibly', () => {
  const app = read('ui/app.js');
  assert.match(app, /U\+/, 'app.js writes a visible marker');
});

// Issue 32: a List-Id with nothing from before the list allows for forgery.
const FAKE_LIST = j([
  'Received: from mail.evil-lists.example (mail.evil-lists.example [203.0.113.5])',
  ' by mx.google.com with ESMTPS id a for <me@gmail.com>;',
  ' Mon, 02 Nov 2026 10:00:04 -0800 (PST)',
  'Authentication-Results: mx.google.com;',
  ' dkim=pass header.i=@evil-lists.example header.s=s1 header.b=abcd;',
  ' spf=pass smtp.mailfrom=bounce@evil-lists.example;',
  ' dmarc=fail (p=REJECT sp=REJECT dis=NONE) header.from=bank.example',
  'Return-Path: <bounce@evil-lists.example>',
  'List-Id: <alerts.evil-lists.example>',
  'From: Bank Alerts <alerts@bank.example>',
  'To: me@gmail.com',
  'Subject: [alerts] Verify your account today',
  'Date: Mon, 02 Nov 2026 10:00:00 -0000',
  'Message-ID: <1@evil-lists.example>',
  'DKIM-Signature: v=1; a=rsa-sha256; d=evil-lists.example; s=s1; h=from:to:subject; bh=x; b=abcdefg',
]);

test('32: a list claim resting only on sender-written fields allows for forgery', () => {
  const r = HA.analyze(FAKE_LIST);
  const f = r.finding;
  assert.equal(f.status, 'fail');
  assert.doesNotMatch(f.headline.plain, /because it came through the mailing list/);
  assert.match(f.cause.technical + f.cause.plain, /forg/i);
  assert.doesNotMatch(f.fixes[0].plain, /setup is(n't| not) the problem/);
  assert.match(f.fixes[0].technical, /forg/i);
});

test('32: a list that kept its record before the list is still explained as a list', () => {
  const r = HA.analyze(FAKE_LIST.replace('List-Id:', 'Authentication-Results-Original: mx.evil-lists.example; dkim=pass header.d=bank.example; spf=pass smtp.mailfrom=alerts@bank.example; dmarc=pass header.from=bank.example\nList-Id:'));
  assert.match(r.finding.headline.plain, /because it came through the mailing list/);
});

// Issue 33: an ignored Received-SPF field carries a note.
const RSPF_BELOW = j([
  'Received: from mail.sender.example (mail.sender.example [203.0.113.5])',
  ' by mx.google.com with ESMTPS id a for <me@gmail.com>;',
  ' Mon, 02 Nov 2026 10:00:04 -0800 (PST)',
  'Authentication-Results: mx.google.com;',
  ' dkim=none;',
  ' spf=fail smtp.mailfrom=alerts@bank.example;',
  ' dmarc=fail (p=REJECT dis=REJECT) header.from=bank.example',
  'Return-Path: <alerts@bank.example>',
  'Received-SPF: pass (mx.google.com: domain of alerts@bank.example designates 203.0.113.5 as permitted sender) client-ip=203.0.113.5; envelope-from=alerts@bank.example; helo=mail.bank.example;',
  'From: Bank <alerts@bank.example>',
  'To: me@gmail.com',
  'Subject: Hello',
  'Date: Mon, 02 Nov 2026 10:00:00 -0000',
  'Message-ID: <1@bank.example>',
]);

test('33: an untrusted Received-SPF field gets a note saying it was ignored', () => {
  const r = HA.analyze(RSPF_BELOW);
  assert.equal(r.auth.receivedSpf[0].trusted, false);
  const idx = r.fields.findIndex(f => f.lower === 'received-spf');
  const n = r.auth.notes.find(x => x.src.includes(idx) && /Received-SPF/.test(x.technical));
  assert.ok(n, 'note for the ignored Received-SPF');
  assert.equal(n.state, 'unknown');
  assert.match(n.technical, /ignored/);
});

test('33: the Authentication card labels each Received-SPF row by trust', () => {
  assert.match(read('ui/app.js'), /receivedSpf\.map\(x => [^\n]*trusted/);
});

// Issue 34: more than 50 ARC sets fail (RFC 8617 5.1.1).
const arcSets = (n) => Array.from({ length: n }, (_, i) => { const k = n - i; return 'ARC-Seal: i=' + k + '; a=rsa-sha256; cv=' + (k === 1 ? 'none' : 'pass') + '; d=x.example; s=s; b=x\nARC-Message-Signature: i=' + k + '; d=x.example; s=s; h=from; b=x\nARC-Authentication-Results: i=' + k + '; mx.x.example; spf=pass smtp.mailfrom=a@x.example'; }).join('\n');
const ARC_BASE = '\nReceived: from a (a [203.0.113.1]) by mx.google.com with ESMTPS; Mon, 02 Nov 2026 10:00:00 +0000\nAuthentication-Results: mx.google.com; dmarc=pass header.from=b.example\nFrom: a@b.example\nTo: c@d.example\nSubject: x\nDate: Mon, 02 Nov 2026 10:00:00 +0000\nMessage-ID: <1@b>\n';

test('34: an ARC chain of 50 sets passes and 51 or 60 fail with one problem', () => {
  assert.equal(HA.analyze(arcSets(50) + ARC_BASE).auth.arc.state, 'pass');
  for (const n of [51, 60]) {
    const a = HA.analyze(arcSets(n) + ARC_BASE).auth.arc;
    assert.equal(a.state, 'fail', n + ' sets');
    assert.equal(a.problems.length, 1, n + ' sets');
    assert.match(a.problems[0].text, /50/);
  }
});

// Issue 35: a multibyte character split across encoded words.
test('35: a UTF-8 character split across two B encoded words decodes whole', () => {
  const b = Buffer.from('日本語のテスト', 'utf8');
  const w1 = '=?UTF-8?B?' + b.slice(0, 4).toString('base64') + '?=';
  const w2 = '=?utf-8?B?' + b.slice(4).toString('base64') + '?=';
  assert.equal(HA.parse.decodeWords(w1 + ' ' + w2), '日本語のテスト');
});

test('35: a UTF-8 character split across two Q encoded words decodes whole', () => {
  const q = (buf) => '=?UTF-8?Q?' + Array.from(buf).map(x => '=' + x.toString(16).toUpperCase().padStart(2, '0')).join('') + '?=';
  const b = Buffer.from('Grüße', 'utf8');
  assert.equal(HA.parse.decodeWords(q(b.slice(0, 3)) + '\n ' + q(b.slice(3))), 'Grüße');
});

test('35: words in different charsets still decode one by one', () => {
  assert.equal(HA.parse.decodeWords('=?ISO-8859-1?Q?caf=E9?= =?UTF-8?B?w6k=?='), 'caféé');
});

// Issue 36: rsa-sha1 is permanently failed under RFC 8301.
const SHA1 = 'Received: from a (a [203.0.113.1]) by mx.google.com with ESMTPS; Mon, 02 Nov 2026 10:00:00 +0000\nAuthentication-Results: mx.google.com; dkim=pass header.i=@b.example header.s=s1 header.b=abcdefg; spf=none smtp.mailfrom=a@other.example; dmarc=pass header.from=b.example\nFrom: a@b.example\nTo: c@d.example\nSubject: x\nDate: Mon, 02 Nov 2026 10:00:00 +0000\nMessage-ID: <1@b>\nDKIM-Signature: v=1; a=rsa-sha1; d=b.example; s=s1; h=from:to:subject; bh=x; b=abcdefg\n';

test('36: the rsa-sha1 note quotes RFC 8301 3.1 and the pass carries a caveat', () => {
  const r = HA.analyze(SHA1);
  const note = r.auth.signatures[0].notes.join(' ');
  assert.doesNotMatch(note, /may ignore/);
  assert.match(note, /RFC 8301/);
  assert.match(note, /permanently failed/);
  assert.equal(r.auth.dkim[0].state, 'caveat');
  assert.equal(r.finding.state, 'caveat');
  assert.equal(r.finding.headline.state, 'caveat');
  assert.match(r.finding.headline.technical, /rsa-sha1/);
});

// Issue 37: the status chip words are Simple words.
test('37: the finding status words follow the Simple word list', () => {
  const W = HA.finding.STATUS_WORD;
  assert.equal(W.none, 'No DMARC setting');
  for (const [k, v] of Object.entries(W)) assert.ok(!SIMPLE_BANNED.test(v), k + ': ' + v);
  assert.doesNotMatch(read('ui/app.js'), /No DMARC policy/);
});

// Issue 38: an unknown DMARC result cites RFC 9989.
test('38: an unrecognized dmarc result cites RFC 9989, not RFC 7489', () => {
  const r = HA.analyze(HELO_FIRST_AR.replace('dmarc=fail (p=REJECT dis=REJECT)', 'dmarc=policy'));
  assert.match(r.finding.headline.technical, /RFC 9989/);
  assert.doesNotMatch(r.finding.headline.technical, /7489/);
});

// Issue 39: docs match the shipped page.
test('39: docs never use the word verdict and scope.md has no voice switch', () => {
  for (const f of fs.readdirSync(path.join(root, 'docs'))) assert.doesNotMatch(read('docs/' + f), /verdict/i, f);
  const scope = read('docs/scope.md');
  assert.doesNotMatch(scope, /The switch changes every sentence/);
  assert.doesNotMatch(scope, /never leave the visitor's machine/);
  assert.doesNotMatch(scope, /conflicts with the privacy claim/);
});

// Issues 40 to 42: the page itself.
test('40: an .eml can be chosen with a file input, not only dropped', () => {
  const page = read('ui/page.html');
  assert.match(page, /<input[^>]*type="file"[^>]*accept="[^"]*\.eml/);
  assert.match(read('ui/app.js'), /function loadFile\(/);
});

test('41: run() writes the finding to the live region', () => {
  const app = read('ui/app.js');
  assert.match(app, /announce\(STATUS_WORD\[R\.finding\.status\]/);
  assert.match(app, /announce\('Nothing to read/);
});

test('42: the raw header search box is a 44px target', () => {
  assert.match(read('ui/page.html'), /\.raw-tools input\s*\{[^}]*min-height:\s*44px/);
});

// Issue 43: origin addresses.
const mkHop = (f) => 'Authentication-Results: mx.receiver.example; spf=pass smtp.mailfrom=a@b.example; dmarc=pass header.from=b.example\nReceived: ' + f + '\n by mx.receiver.example (Postfix) with ESMTPS id 1 for <me@receiver.example>; Mon, 02 Nov 2026 10:00:04 +0000\nFrom: a@b.example\nTo: me@receiver.example\nSubject: x\nDate: Mon, 02 Nov 2026 10:00:00 +0000\n';

test('43: an out of range IPv4 number is not an origin address', () => {
  assert.equal(HA.received.findIp('[999.1.1.1]'), '');
  assert.equal(HA.received.findIp('host [256.0.0.1] and 198.51.100.7'), '198.51.100.7');
  assert.equal(HA.analyze(mkHop('from mail.b.example (mail.b.example [999.1.1.1])')).chain.originIp, '');
});

test('43: shared address space, 0.0.0.0/8 and mapped private addresses are private', () => {
  const r = HA.analyze(mkHop('from mail.b.example ([100.64.1.2])'));
  assert.equal(r.chain.originIp, '100.64.1.2');
  assert.equal(r.chain.trust.originPrivate, true);
  for (const ip of ['100.127.255.255', '0.1.2.3', '::ffff:10.0.0.1', '::ffff:192.168.1.1']) assert.ok(HA.received.isPrivateIp(ip), ip);
  for (const ip of ['100.63.0.1', '100.128.0.1', '::ffff:198.51.100.7']) assert.ok(!HA.received.isPrivateIp(ip), ip);
});
