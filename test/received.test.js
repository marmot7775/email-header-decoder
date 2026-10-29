'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { HA, fixture } = require('./load.js');

const chainOf = (name) => HA.analyze(fixture(name)).chain;

test('Gmail: hops run oldest first with per-hop delay, slowest hop and total transit', () => {
  const c = chainOf('gmail-show-original.txt');
  assert.equal(c.count, 4);
  assert.match(c.hops[0].fromHost, /198\.51\.100\.23/);
  assert.equal(c.hops[0].byHost, 'filter.sender.example');
  assert.equal(c.hops[3].byHost, '2002:a05:7300:5c11:b0:1b2:3f4e:aa10');
  assert.deepEqual(c.hops.map(h => h.delaySec), [null, 256, 7, 1]);
  assert.equal(c.slowestIdx, 1);
  assert.equal(c.hops[1].slowest, true);
  assert.equal(c.hops.filter(h => h.slowest).length, 1);
  assert.equal(c.totalSec, 264);
  assert.equal(c.clockSkew, false);
});

test('Gmail: TLS evidence per hop from the with clause and its comments', () => {
  const c = chainOf('gmail-show-original.txt');
  assert.equal(c.hops[0].tls.state, 'pass');      // ESMTPSA
  assert.equal(c.hops[0].authenticated, true);
  assert.equal(c.hops[1].tls.state, 'caveat');    // ESMTP inside the sender's own network
  assert.equal(c.hops[2].tls.state, 'pass');
  assert.equal(c.hops[2].tls.version, 'TLS 1.3');
  assert.equal(c.hops[2].tls.cipher, 'TLS_AES_256_GCM_SHA384');
  assert.equal(c.hops[3].tls.state, 'unknown');   // local handoff, no connection recorded
});

test('internal relays: private address, same operator, and local handoff are detected with a reason', () => {
  const c = chainOf('gmail-show-original.txt');
  assert.equal(c.hops[0].internal, false);
  assert.equal(c.hops[1].internal, true);
  assert.match(c.hops[1].internalReason, /private address/);
  assert.equal(c.hops[2].internal, false);
  assert.equal(c.hops[3].internal, true);
  assert.match(c.hops[3].internalReason, /no from clause/);
});

test('Exchange Online: Microsoft hops group under one row, the external hop stands alone', () => {
  const c = chainOf('exchange-online-inbound.txt');
  assert.equal(c.count, 5);
  assert.equal(c.hops[1].fromHost, 'mx1.vendor.example');
  assert.equal(c.hops[1].fromIp, '203.0.113.20');
  assert.equal(c.hops[1].internal, false);
  assert.deepEqual(c.hops.slice(2).map(h => h.internal), [true, true, true]);
  const g = c.groups.find(x => x.kind === 'internal');
  assert.deepEqual(g.hops, [2, 3, 4]);
  assert.equal(g.operator, 'Microsoft');
  assert.equal(c.groups.length, 3);
  assert.equal(c.hops[1].slowest, true);
  assert.equal(c.totalSec, 9);
});

test('Exchange Online: TLS read from Microsoft SMTP Server version= and with HTTPS', () => {
  const c = chainOf('exchange-online-inbound.txt');
  assert.equal(c.hops[0].tls.state, 'caveat'); // plain ESMTP inside vendor.example
  assert.equal(c.hops[1].tls.version, 'TLS 1.3');
  assert.equal(c.hops[3].tls.version, 'TLS 1.2');
  assert.equal(c.hops[4].tls.state, 'pass');
  assert.equal(c.hops[4].protocol, 'HTTPS');
});

test('Exchange Online: mapi submission is internal and its TLS state is unknown', () => {
  const c = chainOf('exchange-online-internal.txt');
  assert.equal(c.count, 2);
  assert.equal(c.hops[0].protocol, 'mapi');
  assert.equal(c.hops[0].internal, true);
  assert.match(c.hops[0].internalReason, /mapi/);
  assert.equal(c.hops[0].tls.state, 'unknown');
  assert.equal(c.groups.length, 1);
  assert.deepEqual(c.groups[0].hops, [0, 1]);
});

test('iCloud: GMT stamps parse, two single-label hosts count as internal, the inbound hop does not', () => {
  const c = chainOf('icloud.txt');
  assert.equal(c.count, 2);
  assert.equal(c.hops[0].tls.state, 'pass');
  assert.equal(c.hops[1].delaySec, 2);
  assert.equal(c.hops[0].internal, false);
  assert.equal(c.hops[1].internal, true);
  assert.match(c.hops[1].internalReason, /single-label/);
  assert.equal(c.hops[1].operator, 'Apple');
});

test('clock skew: a negative delay marks the hop and the chain', () => {
  const c = chainOf('folded-garbage.txt');
  assert.equal(c.clockSkew, true);
  const skewed = c.hops.filter(h => h.skew);
  assert.equal(skewed.length, 1);
  assert.ok(skewed[0].delaySec < 0);
  assert.ok(c.notes.some(n => n.state === 'caveat' && /clock/i.test(n.technical) && n.src.length >= 1));
});

test('a Received field with no parseable date has no time and no delay, and the chain still builds', () => {
  const c = chainOf('folded-garbage.txt');
  assert.equal(c.count, 3);
  const broken = c.hops.find(h => h.time === null);
  assert.ok(broken);
  assert.equal(broken.delaySec, null);
});

test('forwarded: the forwarder and the Microsoft hops are told apart', () => {
  const c = chainOf('forwarded.txt');
  assert.equal(c.count, 4);
  assert.equal(c.hops[0].byHost, 'mail-forwarder.relay.example');
  assert.equal(c.hops[0].tls.state, 'pass');
  assert.equal(c.hops[1].fromHost, 'mail-forwarder.relay.example');
  assert.equal(c.hops[1].internal, false);
  assert.deepEqual(c.hops.slice(2).map(h => h.internal), [true, true]);
});

test('every hop carries the index of the Received field it came from', () => {
  for (const name of ['gmail-show-original.txt', 'exchange-online-inbound.txt', 'icloud.txt', 'forwarded.txt']) {
    const r = HA.analyze(fixture(name));
    for (const h of r.chain.hops) {
      assert.equal(h.src.length, 1);
      assert.equal(r.fields[h.src[0]].lower, 'received', name);
    }
    const recv = r.fields.filter(f => f.lower === 'received').map(f => f.index).reverse();
    assert.deepEqual(r.chain.hops.map(h => h.src[0]), recv, name);
  }
});

test('trust line: the boundary is the receiver\'s first hop and the origin is the IP it saw, not the EHLO name', () => {
  const cases = { 'gmail-show-original.txt': [2, 'Google', '192.0.2.45'], 'exchange-online-inbound.txt': [1, 'Microsoft', '203.0.113.20'], 'forwarded.txt': [1, 'Microsoft', '198.51.100.25'], 'icloud.txt': [0, 'Apple', '192.0.2.80'], 'arc-forwarded-i2.txt': [4, 'Google', '198.51.100.80'] };
  for (const [name, [idx, op, ip]] of Object.entries(cases)) {
    const c = chainOf(name);
    assert.equal(c.trust.boundaryIdx, idx, name);
    assert.equal(c.trust.operator, op, name);
    assert.equal(c.trust.originIp, ip, name);
    assert.equal(c.originIp, ip, name);
    assert.deepEqual(c.trust.src, c.hops[idx].src, name);
  }
  assert.equal(chainOf('gmail-show-original.txt').trust.originHelo, 'mail.sender.example');
});

test('trust line: a forged Received naming the receiver before an outside hop does not move the boundary', () => {
  const c = chainOf('ar-unknown-host.txt');
  assert.equal(c.hops[0].byHost, 'mx.receiver.example'); // the forged line
  assert.equal(c.trust.boundaryIdx, 2);
  assert.equal(c.trust.originIp, '198.51.100.13');
  const n = c.notes.find(x => /Trust line/.test(x.technical));
  assert.match(n.technical, /two Received fields before it were written by the sender's side and can be forged/);
});

test('trust line: mail from inside the receiver\'s own network has no outside origin', () => {
  const c = chainOf('exchange-online-internal.txt');
  assert.equal(c.trust.boundaryIdx, 0);
  assert.equal(c.trust.originPrivate, true);
  assert.equal(c.notes.find(x => /Trust line/.test(x.technical)).state, 'caveat');
});
