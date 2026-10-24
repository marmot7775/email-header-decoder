'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { HA, fixture } = require('./load.js');

const STATES = ['pass', 'caveat', 'fail', 'unknown'];

// Every sentence object the page shows has both readers and its provenance.
function assertSentence(s, where) {
  assert.ok(STATES.includes(s.state), where + ' state ' + s.state);
  assert.equal(typeof s.technical, 'string', where);
  assert.equal(typeof s.plain, 'string', where);
  assert.ok(s.technical.length > 0 && s.plain.length > 0, where);
  assert.ok(Array.isArray(s.src), where + ' src');
}

test('result object: step 3 fills finding and decoded beside alignment and auth', () => {
  const r = HA.analyze(fixture('gmail-show-original.txt'));
  assert.equal(r.step, 3);
  assert.ok(r.finding && r.finding.headline);
  assert.ok(r.decoded && Array.isArray(r.decoded.filters) && r.decoded.platform && Array.isArray(r.decoded.list));
  assert.ok(r.message && r.chain && r.fields.length && r.alignment && r.auth);
  assert.equal('verdict' in r, false);
  assert.equal('pending' in r, false);
});

test('result object is JSON-safe', () => {
  const r = HA.analyze(fixture('exchange-online-inbound.txt'));
  assert.deepEqual(JSON.parse(JSON.stringify(r)), r);
});

test('message card values each carry the field index they came from', () => {
  const r = HA.analyze(fixture('gmail-show-original.txt'));
  const m = r.message;
  const at = (i) => r.fields[i].lower;
  assert.equal(m.from.address, 'alex@sender.example');
  assert.equal(at(m.from.src[0]), 'from');
  assert.equal(m.to.addresses[0].address, 'neil@example.org');
  assert.equal(at(m.to.src[0]), 'to');
  assert.equal(at(m.subject.src[0]), 'subject');
  assert.equal(m.date.time, Date.UTC(2026, 9, 23, 16, 9, 41));
  assert.equal(at(m.date.src[0]), 'date');
  assert.equal(m.messageId.value, 'CAF7x9Q2Lr8kWm4Pz@mail.sender.example');
  assert.equal(at(m.messageId.src[0]), 'message-id');
  assert.equal(m.returnPath.domain, 'sender.example');
  assert.equal(at(m.returnPath.src[0]), 'return-path');
});

test('Return-Path without angle brackets still gives its domain', () => {
  const r = HA.analyze(fixture('exchange-online-inbound.txt'));
  assert.equal(r.message.returnPath.domain, 'billing.vendor.example');
});

test('a folded Message-ID value is read whole', () => {
  const r = HA.analyze(fixture('exchange-online-internal.txt'));
  assert.equal(r.message.messageId.value, 'PH0PR12MB77441A2B3C4D5E6F@PH0PR12MB7744.namprd12.prod.outlook.com');
});

test('two From fields: the first is shown, both are cited, and the page is told in both voices', () => {
  const r = HA.analyze(fixture('two-from.txt'));
  assert.equal(r.message.fromCount, 2);
  assert.equal(r.message.from.domain, 'bank.example');
  const n = r.message.notes.find(x => /From/.test(x.technical));
  assertSentence(n, 'two-from note');
  assert.equal(n.state, 'fail');
  assert.equal(n.src.length, 2);
  assert.ok(n.src.every(i => r.fields[i].lower === 'from'));
});

test('missing Received: empty chain with a sentence that says what that means', () => {
  const r = HA.analyze(fixture('missing-received.txt'));
  assert.equal(r.chain.count, 0);
  assert.equal(r.chain.notes.length, 1);
  assertSentence(r.chain.notes[0], 'missing received');
  assert.equal(r.chain.notes[0].state, 'unknown');
  assert.match(r.chain.notes[0].technical, /Received/);
  assert.equal(r.message.from.address, 'alex@sender.example');
});

test('no header block: nothing parsed, and the input says so', () => {
  const r = HA.analyze(fixture('no-header-block.txt'));
  assert.equal(r.input.blockFound, false);
  assert.equal(r.fields.length, 0);
  assert.equal(r.message.from, null);
  assert.equal(r.chain.count, 0);
  assertSentence(r.input.notes[0], 'no block');
});

test('empty and whitespace input do not throw', () => {
  for (const t of ['', '   \n\n  ', null, undefined]) {
    const r = HA.analyze(t);
    assert.equal(r.input.blockFound, false);
  }
});

test('folded garbage: analyze survives and keeps the fields it can read', () => {
  const r = HA.analyze(fixture('folded-garbage.txt'));
  assert.equal(r.input.blockFound, true);
  assert.equal(r.message.from.display, 'Comma, In Name');
  assert.equal(r.message.date.tzKnown, true);
  assert.equal(r.message.date.time, Date.UTC(2026, 9, 23, 21, 49, 0));
  assert.ok(r.fields.find(f => f.name === 'X-Long').value.length >= 3000);
});

test('every sentence in the result carries both readers and provenance', () => {
  for (const name of ['gmail-show-original.txt', 'exchange-online-inbound.txt', 'exchange-online-internal.txt', 'icloud.txt', 'forwarded.txt', 'folded-garbage.txt', 'missing-received.txt', 'two-from.txt', 'no-header-block.txt']) {
    const r = HA.analyze(fixture(name));
    const f = r.finding;
    const fs = f ? [f.headline, f.cause].concat(f.consequence ? [f.consequence] : [], f.details, f.fixes, f.flags, f.limits) : [];
    for (const s of [].concat(r.input.notes, r.message.notes, r.chain.notes, fs, r.decoded.notes, [r.decoded.platform.statement])) {
      assertSentence(s, name);
      for (const i of s.src) assert.ok(r.fields[i], name + ' src ' + i);
    }
  }
});

test('slowest hop and total transit are stated as sentences that cite their fields', () => {
  const r = HA.analyze(fixture('gmail-show-original.txt'));
  const slow = r.chain.notes.find(n => /slowest/i.test(n.technical));
  assertSentence(slow, 'slowest');
  assert.equal(slow.src.length, 2); // this hop and the one before it
  const total = r.chain.notes.find(n => /end to end/i.test(n.technical));
  assertSentence(total, 'total');
});

test('a skewed chain reports no negative transit time', () => {
  const r = HA.analyze(fixture('folded-garbage.txt'));
  const n = r.chain.notes.find(x => /Transit time cannot be measured/.test(x.technical));
  assertSentence(n, 'skewed total');
  assert.equal(n.state, 'caveat');
  assert.ok(!r.chain.notes.some(x => /End to end: -/.test(x.technical)));
});

test('a plain external hop is a fail sentence', () => {
  const r = HA.analyze(fixture('two-from.txt'));
  assert.equal(r.chain.hops[0].tls.state, 'fail');
  const n = r.chain.notes.find(x => x.state === 'fail' && /TLS/.test(x.technical));
  assertSentence(n, 'plain hop');
  assert.deepEqual(n.src, r.chain.hops[0].src);
});
