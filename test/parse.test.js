'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { HA, fixture } = require('./load.js');

const FIXTURES = ['gmail-show-original.txt', 'exchange-online-inbound.txt', 'exchange-online-internal.txt', 'icloud.txt', 'forwarded.txt', 'folded-garbage.txt', 'missing-received.txt', 'two-from.txt'];

function names(r) { return r.fields.map(f => f.name); }

test('every field keeps its raw line span, and the span reproduces the raw text', () => {
  for (const name of FIXTURES) {
    const text = fixture(name);
    const lines = text.replace(/\r\n?/g, '\n').split('\n');
    const r = HA.analyze(text);
    assert.ok(r.fields.length > 0, name);
    r.fields.forEach((f, i) => {
      assert.equal(f.index, i, name + ' index');
      assert.ok(Array.isArray(f.lines) && f.lines.length === 2, name + ' lines');
      assert.ok(f.lines[0] <= f.lines[1], name + ' span order');
      assert.equal(lines.slice(f.lines[0], f.lines[1] + 1).join('\n'), f.raw, name + ' ' + f.name);
    });
  }
});

test('Gmail Show original copy: the summary table above the headers is skipped', () => {
  const r = HA.analyze(fixture('gmail-show-original.txt'));
  assert.equal(r.fields[0].name, 'Delivered-To');
  assert.equal(r.fields.filter(f => f.lower === 'from').length, 1);
  assert.equal(r.input.format, 'gmail-original');
  assert.equal(r.input.bodyPresent, true);
});

test('Outlook Internet headers: the version banner is skipped and the format is named', () => {
  const r = HA.analyze(fixture('exchange-online-inbound.txt'));
  assert.equal(r.fields[0].name, 'Received');
  assert.equal(r.input.format, 'outlook-headers');
});

test('a full .eml is recognised by its body after the blank line', () => {
  const r = HA.analyze(fixture('missing-received.txt'));
  assert.equal(r.input.format, 'eml');
  assert.equal(r.input.bodyPresent, true);
});

test('duplicate fields are kept in order', () => {
  const r = HA.analyze(fixture('icloud.txt'));
  const ar = r.fields.filter(f => f.lower === 'authentication-results');
  assert.equal(ar.length, 5);
  assert.match(ar[0].value, /^bimi\.icloud\.com/);
  assert.match(ar[4].value, /^spf\.icloud\.com/);
  assert.ok(ar.every((f, i) => i === 0 || f.index > ar[i - 1].index));
});

test('unfolding joins continuation lines with one space', () => {
  const r = HA.analyze(fixture('exchange-online-inbound.txt'));
  const ar = r.fields.find(f => f.lower === 'authentication-results');
  assert.match(ar.value, /smtp\.mailfrom=billing\.vendor\.example; dkim=pass/);
  assert.ok(!/\n/.test(ar.value));
});

test('lost indentation is repaired: a Forefront line starting CIP: is a continuation, not a field', () => {
  const r = HA.analyze(fixture('exchange-online-inbound.txt'));
  assert.ok(!names(r).includes('CIP'));
  const ff = r.fields.find(f => f.lower === 'x-forefront-antispam-report');
  assert.match(ff.value, /^CIP:203\.0\.113\.20;/);
  assert.equal(ff.looseFold, true);
  assert.ok(r.input.notes.some(n => /X-Forefront-Antispam-Report/.test(n.technical)));
});

test('lost indentation is repaired: lines starting with a time or an IPv6 address are continuations', () => {
  const r = HA.analyze(fixture('folded-garbage.txt'));
  assert.ok(!names(r).some(n => /^\d/.test(n)), names(r).join(','));
  assert.ok(!names(r).includes('::::'));
  assert.ok(names(r).includes('From'));
  assert.ok(names(r).includes('Message-ID'));
});

test('RFC 2047: B and Q words decode, adjacent words join, bad words stay raw', () => {
  assert.equal(HA.analyze(fixture('icloud.txt')).message.subject.value, 'Your order has shipped');
  assert.equal(HA.analyze(fixture('gmail-show-original.txt')).message.subject.value, 'Q3 numbers and the renewal date');
  assert.equal(HA.analyze(fixture('exchange-online-inbound.txt')).message.subject.value, 'Invoice #4412 – October');
  assert.equal(HA.analyze(fixture('icloud.txt')).message.from.display, 'Café Shop');
  const g = HA.analyze(fixture('folded-garbage.txt')).message.subject.value;
  assert.match(g, /unterminated/);
});

test('addresses: quoted display names with commas, comments, bare addresses', () => {
  const a = HA.parse.parseAddresses('"Comma, In Name" <who@one.example> (a comment (nested)), bare@two.example');
  assert.equal(a.length, 2);
  assert.equal(a[0].display, 'Comma, In Name');
  assert.equal(a[0].domain, 'one.example');
  assert.equal(a[1].address, 'bare@two.example');
  const rp = HA.parse.parseAddresses('<>');
  assert.equal(rp[0].empty, true);
});

test('dates: numeric zones, obsolete named zones, two-digit years, comments', () => {
  const d1 = HA.parse.parseDate('Fri, 23 Oct 2026 09:14:05 -0700 (PDT)');
  assert.equal(d1.time, Date.UTC(2026, 9, 23, 16, 14, 5));
  assert.equal(d1.tzKnown, true);
  const d2 = HA.parse.parseDate('23 Oct 26 16:49 EST');
  assert.equal(d2.time, Date.UTC(2026, 9, 23, 21, 49, 0));
  const d3 = HA.parse.parseDate('Fri, 23 Oct 2026 16:30:14 GMT');
  assert.equal(d3.time, Date.UTC(2026, 9, 23, 16, 30, 14));
  const d4 = HA.parse.parseDate('Fri, 23 Oct 099 16:30:14 +0000');
  assert.equal(new Date(d4.time).getUTCFullYear(), 1999);
});

test('dates: -0000 and military zones are read as UTC with the zone marked unknown (RFC 5322 4.3)', () => {
  const a = HA.parse.parseDate('Fri, 23 Oct 2026 16:30:14 -0000');
  assert.equal(a.tzKnown, false);
  assert.equal(a.time, Date.UTC(2026, 9, 23, 16, 30, 14));
  const b = HA.parse.parseDate('Fri, 23 Oct 2026 16:30:14 Q');
  assert.equal(b.tzKnown, false);
  assert.equal(b.time, Date.UTC(2026, 9, 23, 16, 30, 14));
});

test('dates: asctime form without a zone is read as UTC and marked unknown', () => {
  const d = HA.parse.parseDate('Fri Oct 23 16:30:14 2026');
  assert.equal(d.time, Date.UTC(2026, 9, 23, 16, 30, 14));
  assert.equal(d.tzKnown, false);
});

test('dates: garbage gives no time rather than a guess', () => {
  const d = HA.parse.parseDate('not a date at all');
  assert.equal(d.time, null);
});

test('comments: stripped and extracted, nested parentheses respected', () => {
  assert.equal(HA.parse.stripComments('a (b (c) d) e'), 'a e');
  assert.deepEqual(HA.parse.extractComments('x (one) y (two (three))'), ['one', 'two (three)']);
});

test('tag=value lists keep order and drop folding whitespace', () => {
  const { tags, order } = HA.parse.parseTagList('v=1; a=rsa-sha256; d=shop.example; s=k1; h=from:to:\n subject; b=Ab 12');
  assert.deepEqual(order, ['v', 'a', 'd', 's', 'h', 'b']);
  assert.equal(tags.h, 'from:to:subject');
  assert.equal(tags.b, 'Ab12');
});
