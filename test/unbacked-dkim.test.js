'use strict';
// Issue 14: an Authentication-Results field below the receiver's only
// Received stamp stays the primary, since Gmail and Postfix write theirs
// there. When it is the only trusted field and reports dkim=pass with no
// DKIM-Signature in the paste, a limit says the sender could have written
// it. Synthetic input only.
const test = require('node:test');
const assert = require('node:assert/strict');
const { HA } = require('./load.js');

const STAMP = 'Received: from mail.attacker.example (mail.attacker.example [198.51.100.9])\n\tby mx1.receiver.example (Postfix) with ESMTPS id ABC\n\tfor <user@receiver.example>; Fri, 23 Oct 2026 16:20:05 +0000 (UTC)';
const AR = 'Authentication-Results: mx1.receiver.example; spf=pass smtp.mailfrom=bank.example;\n\tdkim=pass header.d=bank.example header.s=s1; dmarc=pass header.from=bank.example';
const SIG = 'DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=bank.example; s=s1; h=from:to:subject:date:message-id; bh=SyntheticBh=; b=s1SyntheticValue';
const MSG = ['From: Bank <alerts@bank.example>', 'To: user@receiver.example', 'Subject: Verify', 'Date: Fri, 23 Oct 2026 16:20:00 +0000', 'Message-ID: <x@bank.example>', 'Return-Path: <alerts@bank.example>'];
const join = (lines) => lines.join('\n') + '\n';
const unbacked = (f) => f.limits.filter(x => /could have written/.test(x.technical));

test('issue 14: a lone dkim=pass below the only stamp with no DKIM-Signature gets a caveat limit', () => {
  const f = HA.analyze(join([STAMP, AR].concat(MSG))).finding;
  // The current rule stands: the field is still the primary and the status is unchanged.
  assert.equal(f.status, 'pass');
  const l = unbacked(f);
  assert.equal(l.length, 1);
  assert.equal(l[0].state, 'caveat');
  assert.match(l[0].technical, /authserv-id mx1\.receiver\.example/);
  assert.match(l[0].technical, /no DKIM-Signature/);
  assert.match(l[0].plain, /The sender could have written these check results/);
  assert.deepEqual(l[0].src, [0, 1]);
});

test('issue 14: no caveat when the paste holds a DKIM-Signature', () => {
  const f = HA.analyze(join([STAMP, AR, SIG].concat(MSG))).finding;
  assert.equal(unbacked(f).length, 0);
});

test('issue 14: no caveat when the field sits above the receiver\'s stamp', () => {
  const f = HA.analyze(join([AR, STAMP].concat(MSG))).finding;
  assert.equal(unbacked(f).length, 0);
});

test('issue 14: no caveat when the field reports no dkim=pass', () => {
  const ar = 'Authentication-Results: mx1.receiver.example; spf=pass smtp.mailfrom=bank.example; dmarc=pass header.from=bank.example';
  const f = HA.analyze(join([STAMP, ar].concat(MSG))).finding;
  assert.equal(unbacked(f).length, 0);
});

test('issue 14: no caveat when a hop came before the receiver', () => {
  const inner = 'Received: from app.bank.example (app.bank.example [192.0.2.7])\n\tby mail.attacker.example (Postfix) with ESMTP id XYZ; Fri, 23 Oct 2026 16:20:02 +0000 (UTC)';
  const f = HA.analyze(join([STAMP, AR, inner].concat(MSG))).finding;
  assert.equal(unbacked(f).length, 0);
});

test('issue 14: no caveat when a second trusted field sits above the stamp', () => {
  const top = 'Authentication-Results: mx1.receiver.example; arc=none';
  const f = HA.analyze(join([top, STAMP, AR].concat(MSG))).finding;
  assert.equal(unbacked(f).length, 0);
});
