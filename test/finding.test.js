'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { HA, fixture } = require('./load.js');

const run = (name) => HA.analyze(fixture(name));
const STATES = ['pass', 'caveat', 'fail', 'unknown'];
const STATUSES = ['pass', 'fail', 'forwarded', 'none', 'error', 'unknown'];
const FIXTURES = fs.readdirSync(path.join(__dirname, 'fixtures')).filter(f => f.endsWith('.txt')).sort();
const sentences = (f) => [f.headline, f.cause].concat(f.consequence ? [f.consequence] : [], f.details, f.fixes, f.flags, f.limits);

// One fixture per status.
test('status pass: the headline names the aligned identifiers and the From domain', () => {
  const f = run('gmail-show-original.txt').finding;
  assert.equal(f.status, 'pass');
  assert.equal(f.state, 'pass');
  assert.equal(f.headline.technical, 'DMARC passed because DKIM signed as sender.example and SPF checked sender.example, both aligned with the From domain sender.example.');
  assert.match(f.consequence.technical, /p=quarantine.*did not come into play/);
});

test('status fail: a sending service\'s own domains, in the one sentence the prompt describes', () => {
  const f = run('esp-unaligned.txt').finding;
  assert.equal(f.status, 'fail');
  assert.equal(f.headline.technical, 'DMARC failed because DKIM signed as mailer.example and SPF checked bounce.mailer.example, so neither aligned with the From domain shop.example.');
  assert.match(f.headline.plain, /signed by mailer\.example.*bounce address was at bounce\.mailer\.example.*neither belongs to shop\.example/);
  assert.match(f.cause.technical, /not shop\.example/);
  assert.match(f.consequence.technical, /p=quarantine.*sent this message to spam \(dis=QUARANTINE\)/);
  // No platform is known, so the fix does not name one.
  assert.ok(f.fixes.some(x => /domain authentication for shop\.example/.test(x.technical) && /the sending service/.test(x.technical)));
  assert.ok(f.fixes.every(x => !/SendGrid|Mailgun/.test(x.technical)));
});

test('status forwarded: the failure is blamed on the forward and the pre-forward results are quoted', () => {
  const r = run('forwarded.txt');
  const f = r.finding;
  assert.equal(f.status, 'forwarded');
  assert.equal(f.state, 'caveat');
  assert.equal(f.forwarded.yes, true);
  assert.deepEqual(f.forwarded.by, ['relay.example']);
  assert.equal(f.forwarded.preForward.result, 'pass');
  assert.match(f.headline.technical, /^DMARC failed because the message was forwarded by relay\.example: before the forward, relay\.example recorded spf=pass \(bounce\.newsletter\.example\.net\), dkim=pass \(newsletter\.example\.net\), and dmarc=pass \(newsletter\.example\.net\)/);
  assert.match(f.cause.technical, /^The failure belongs to the forward, not to the sender\./);
  assert.ok(f.fixes.some(x => /trusted ARC sealers/.test(x.technical)));
  assert.match(f.consequence.technical, /action=oreject/);
  assert.ok(r.flags.includes('forwarded'));
  // The quoted results cite the ARC-Authentication-Results field they came from.
  assert.equal(r.fields[f.forwarded.preForward.src[0]].lower, 'arc-authentication-results');
});

test('status forwarded through two forwarders: the earliest forwarder\'s record is the one quoted', () => {
  const f = run('arc-forwarded-i2.txt').finding;
  assert.equal(f.status, 'forwarded');
  assert.deepEqual(f.forwarded.by, ['list.example', 'forward.example']);
  assert.equal(f.forwarded.preForward.writer, 'mx.list.example');
  assert.match(f.headline.technical, /before the forward, mx\.list\.example recorded .*dmarc=pass \(author\.example\)/);
  assert.match(f.cause.technical, /the DKIM signature from author\.example, because the forward changed the message/);
});

test('forwarded mail that already failed before the forward stays a sender failure', () => {
  const f = run('forwarded-prefail.txt').finding;
  assert.equal(f.status, 'fail');
  assert.equal(f.forwarded.yes, true);
  assert.equal(f.forwarded.preForward.result, 'fail');
  assert.match(f.cause.technical, /^The message was already failing before the forward: mx\.forward\.example recorded spf=fail/);
  assert.ok(f.details.some(x => /^The forward is not the cause/.test(x.technical) && x.state === 'fail'));
  assert.ok(f.fixes.some(x => /Look at the sender, not the forward/.test(x.technical)));
  // The forwarder's own bounce domain is no reason to suggest a custom Return-Path.
  assert.ok(f.fixes.every(x => !/Return-Path/.test(x.technical)));
});

test('a broken ARC chain is not trusted to shift the blame', () => {
  const f = run('arc-cv-fail.txt').finding;
  assert.equal(f.status, 'fail');
  assert.ok(f.details.some(x => /not blamed on the forward/.test(x.technical)));
});

test('the receiver\'s own ARC seal is not a forward', () => {
  const f = run('two-dkim.txt').finding;
  assert.equal(f.status, 'pass');
  assert.equal(f.forwarded.yes, false);
});

test('status none: no DMARC record, with what the message would do under one', () => {
  const f = run('dmarc-none.txt').finding;
  assert.equal(f.status, 'none');
  assert.match(f.headline.technical, /^DMARC did not apply because mx\.receiver\.example found no DMARC record for bakery\.example; with one, this message would pass/);
  assert.ok(f.fixes.some(x => /_dmarc\.bakery\.example/.test(x.technical)));
  assert.match(f.consequence.technical, /publishes no DMARC policy/);
});

test('status error: a permanent error reading the DMARC record', () => {
  const f = run('dmarc-permerror.txt').finding;
  assert.equal(f.status, 'error');
  assert.equal(f.headline.technical, 'DMARC could not be evaluated because mx.receiver.example hit a permanent error reading the DMARC record for tools.example (dmarc=permerror).');
  assert.ok(f.fixes.some(x => /_dmarc\.tools\.example/.test(x.technical)));
  assert.equal(f.consequence, null);
});

test('status unknown: a sent copy, two From fields, and no Authentication-Results each say why', () => {
  const sent = run('missing-received.txt').finding;
  assert.equal(sent.status, 'unknown');
  assert.match(sent.headline.technical, /no Received fields: this is a sent or draft copy/);
  const two = run('two-from.txt').finding;
  assert.equal(two.status, 'unknown');
  assert.match(two.headline.technical, /carries two From fields, so there is no single author domain/);
  assert.equal(two.headline.state, 'fail');
  const none = run('no-auth-results.txt').finding;
  assert.equal(none.status, 'unknown');
  assert.match(none.headline.technical, /there is no Authentication-Results field/);
  assert.equal(none.limits.length, 0);
});

test('reported pass with nothing aligned explains the pass instead of repeating it', () => {
  const f = run('dmarc-pass-unaligned.txt').finding;
  assert.equal(f.status, 'pass');
  assert.equal(f.state, 'caveat');
  assert.match(f.headline.technical, /^DMARC passed at mx\.receiver\.example only because/);
});

test('relaxed-only alignment reported as fail points at strict mode and says the record is not in the headers', () => {
  const f = HA.analyze(fixture('subdomain-relaxed.txt').replace('dmarc=pass (p=NONE', 'dmarc=fail (p=NONE')).finding;
  assert.equal(f.status, 'fail');
  assert.match(f.headline.technical, /most likely requires strict alignment \(adkim=s or aspf=s\); the record itself is not in the headers\./);
});

test('a computed result is marked as worked out when the receiver recorded no DMARC result', () => {
  const f = HA.analyze(fixture('gmail-show-original.txt').replace(/;\n\s+dmarc=pass[^\n]*/g, '')).finding;
  assert.equal(f.status, 'pass');
  assert.match(f.headline.technical, /recorded no DMARC result; worked out from the identifiers, DMARC passes because/);
});

test('the policy consequence quotes what the receiver wrote and nothing more', () => {
  assert.match(run('exchange-online-oreject.txt').finding.consequence.technical, /^Microsoft recorded action=oreject.*does not say which/);
  const q = run('ar-unknown-host.txt').finding.consequence;
  assert.equal(q.state, 'unknown');
  assert.match(q.technical, /did not quote the DMARC policy/);
});

test('limits: adkim and aspf, the organizational domain, and Gmail\'s spam decision are stated, not assumed', () => {
  const g = run('subdomain-relaxed.txt').finding;
  assert.ok(g.limits.some(x => /adkim and aspf are set in the DMARC record, which is not in the headers/.test(x.technical)));
  assert.ok(g.limits.some(x => /organizational domain brand\.example comes from a short built in suffix list/.test(x.technical)));
  assert.ok(g.limits.some(x => /Gmail writes no spam/.test(x.technical)));
  assert.ok(g.limits.every(x => x.state === 'unknown'));
  const approx = run('unlisted-suffix.txt').finding;
  assert.ok(approx.limits.some(x => /it is an approximation/.test(x.technical)));
  const ms = run('exchange-online-inbound.txt').finding;
  assert.ok(ms.limits.every(x => !/Gmail/.test(x.technical)));
});

test('a known platform is named in the fixes; at high confidence only', () => {
  const r = run('platform-sendgrid.txt');
  assert.equal(r.decoded.platform.confidence, 'high');
  assert.ok(r.finding.fixes.some(x => /^At SendGrid, set up domain authentication for club\.example/.test(x.technical)));
  assert.match(r.finding.cause.technical, /SendGrid's own domain signs and bounces the mail/);
});

test('fixes have a plain wording a reader can act on, with no protocol jargon left in it', () => {
  for (const name of ['esp-unaligned.txt', 'platform-sendgrid.txt', 'dmarc-none.txt', 'dmarc-permerror.txt', 'forwarded.txt', 'exchange-online-oreject.txt', 'missing-received.txt']) {
    for (const x of run(name).finding.fixes) {
      assert.ok(x.plain.length > 40, name);
      assert.doesNotMatch(x.plain, /\b(d=|adkim|aspf|rua=|smtp\.mailfrom|header\.from|DKIM-Signature)\b/, name + ': ' + x.plain);
    }
  }
});

test('every finding sentence is built from identifiers in the headers: each domain it names is in the paste', () => {
  for (const name of FIXTURES) {
    const text = fixture(name).toLowerCase();
    const f = HA.analyze(fixture(name)).finding;
    if (!f) continue;
    for (const s of [f.headline, f.cause]) {
      for (const word of [s.technical, s.plain]) {
        for (const d of word.match(/\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:example|com|net|org|fj)\b/gi) || []) {
          if (/^(google|gmail|microsoft)\.com$/i.test(d)) continue;
          assert.ok(text.includes(d.toLowerCase()), name + ': ' + d + ' is not in the headers');
        }
      }
    }
  }
});

test('every finding has a known status, sentences in both voices with valid sources, and house style', () => {
  for (const name of FIXTURES) {
    const r = HA.analyze(fixture(name));
    const f = r.finding;
    if (!r.input.blockFound) { assert.equal(f, null, name); continue; }
    assert.ok(STATUSES.includes(f.status), name);
    for (const s of sentences(f)) {
      assert.ok(STATES.includes(s.state), name + ' state ' + s.state);
      assert.ok(s.technical && s.plain, name);
      for (const i of s.src) assert.ok(r.fields[i], name + ' src ' + i);
      for (const t of [s.technical, s.plain]) {
        assert.doesNotMatch(t, /[—–!]|undefined|null|NaN/, name + ': ' + t);
        assert.doesNotMatch(t, / - /, name + ': ' + t);
      }
    }
    assert.doesNotMatch(JSON.stringify([f, r.decoded]), /verdict/i, name);
  }
});

test('the result with a finding stays JSON-safe', () => {
  const r = run('arc-forwarded-i2.txt');
  assert.deepEqual(JSON.parse(JSON.stringify(r)), r);
});
