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
  assert.equal(f.headline.technical, 'DMARC at mx.google.com passed because DKIM d=sender.example s=mail2026 passed and SPF passed for the Return-Path domain sender.example (RFC5321.MailFrom), and both align with the From domain sender.example (RFC5322.From).');
  assert.match(f.consequence.technical, /p=quarantine.*did not come into play/);
});

test('status fail: a sending service\'s own domains, in the one sentence the prompt describes', () => {
  const f = run('esp-unaligned.txt').finding;
  assert.equal(f.status, 'fail');
  assert.equal(f.headline.technical, 'DMARC at mx.google.com failed because DKIM d=mailer.example s=m1 passed and SPF passed for the Return-Path domain bounce.mailer.example (RFC5321.MailFrom), but neither aligns with the From domain shop.example (RFC5322.From).');
  assert.match(f.headline.plain, /signed by mailer\.example and it came from a server that bounce\.mailer\.example allows\. Neither of those is shop\.example/);
  assert.match(f.cause.technical, /not shop\.example/);
  assert.match(f.consequence.technical, /p=quarantine.*sent this message to spam \(dis=QUARANTINE\)/);
  // No platform is known, so the fix does not name one.
  assert.ok(f.fixes.some(x => /domain authentication for shop\.example/.test(x.technical) && /the sending service/.test(x.technical)));
  assert.ok(f.fixes.every(x => !/SendGrid|Mailgun/.test(x.technical)));
});

test('status forwarded: the failure is blamed on the forward when the receiver vouched for the ARC seals', () => {
  // forwarded.txt carries compauth reason=000 and no arc=; reason 130 is Microsoft's ARC override.
  const r = HA.analyze(fixture('forwarded.txt').replace('compauth=fail reason=000', 'compauth=fail reason=130'));
  const f = r.finding;
  assert.equal(f.status, 'forwarded');
  assert.equal(f.state, 'caveat');
  assert.equal(f.forwarded.yes, true);
  assert.deepEqual(f.forwarded.by, ['relay.example']);
  assert.equal(f.forwarded.preForward.result, 'pass');
  assert.match(f.headline.technical, /^DMARC at .+? failed because the message was forwarded by relay\.example: before the forward, relay\.example recorded spf=pass \(bounce\.newsletter\.example\.net\), dkim=pass \(newsletter\.example\.net\), and dmarc=pass \(newsletter\.example\.net\)/);
  assert.match(f.cause.technical, /^The failure belongs to the forward, not to the sender\./);
  assert.ok(f.fixes.some(x => /trusted ARC sealers/.test(x.technical)));
  assert.match(f.consequence.technical, /action=oreject/);
  assert.ok(r.flags.includes('forwarded'));
  // The quoted results cite the ARC-Authentication-Results field they came from.
  assert.equal(r.fields[f.forwarded.preForward.src[0]].lower, 'arc-authentication-results');
});

test('a forward the receiver did not vouch for is not blamed: seals are not verified here', () => {
  const r = run('forwarded.txt');
  const f = r.finding;
  assert.equal(f.status, 'fail');
  assert.equal(f.forwarded.yes, true);
  assert.notEqual(f.forwarded.blamed, true);
  assert.ok(f.details.some(x => /did not report arc=pass, and this page does not verify ARC seals/.test(x.technical)));
  assert.ok(f.fixes.some(x => /copy delivered straight to the mailbox/.test(x.technical)));
  // SPF here checked the forwarder's server, so no SPF record fix.
  assert.ok(f.fixes.every(x => !/SPF record of/.test(x.technical) && !/trusted ARC sealers/.test(x.technical)));
});

test('a sender written i=1 ARC set does not turn a direct spoof into a forward', () => {
  const f = run('arc-self-sealed-spoof.txt').finding;
  assert.equal(f.status, 'fail');
  assert.notEqual(f.forwarded.blamed, true);
  assert.ok(sentences(f).every(x => !/trust the forwarding service|trusted ARC sealer/.test(x.technical + x.plain)));
});

test('status forwarded through two forwarders: the earliest forwarder\'s record is the one quoted', () => {
  const f = run('arc-forwarded-i2.txt').finding;
  assert.equal(f.status, 'forwarded');
  assert.deepEqual(f.forwarded.by, ['list.example', 'forward.example']);
  assert.equal(f.forwarded.preForward.writer, 'mx.list.example');
  assert.match(f.headline.technical, /before the forward, mx\.list\.example recorded .*dmarc=pass \(author\.example\)/);
  assert.match(f.cause.technical, /broke the DKIM signature from author\.example by changing the message/);
});

test('forwarded mail that already failed before the forward stays a sender failure', () => {
  const f = run('forwarded-prefail.txt').finding;
  assert.equal(f.status, 'fail');
  assert.equal(f.forwarded.yes, true);
  assert.equal(f.forwarded.preForward.result, 'fail');
  assert.match(f.cause.technical, /^The message was already failing before the forward: mx\.forward\.example recorded spf=fail/);
  // The cause says it, so no detail repeats it.
  assert.ok(f.details.every(x => !/^The forward is not the cause/.test(x.technical)));
  assert.ok(f.fixes.some(x => /Look at the sender, not the forward/.test(x.technical)));
  // The forwarder's own bounce domain is no reason to suggest a custom Return-Path.
  assert.ok(f.fixes.every(x => !/Return-Path/.test(x.technical)));
});

test('a broken ARC chain is not trusted to shift the blame', () => {
  const f = run('arc-cv-fail.txt').finding;
  assert.equal(f.status, 'fail');
  assert.ok(!f.forwarded.blamed);
  // The list re-sent it, so the list explanation applies, quoting its seal's record as unverified.
  assert.match(f.headline.technical, /came through the mailing list club\.list\.example/);
  assert.match(f.cause.technical, /in its ARC-Authentication-Results field\. The list's own server wrote that record and this page cannot verify it/);
});

test('the receiver\'s own ARC seal is not a forward', () => {
  const f = run('two-dkim.txt').finding;
  assert.equal(f.status, 'pass');
  assert.equal(f.forwarded.yes, false);
  const notes = run('gmail-show-original.txt').auth.notes;
  assert.ok(notes.some(n => /added its own record of the checks when the message arrived\. That isn.t a forward\./.test(n.plain)));
  assert.ok(notes.every(n => !/forwarding record/.test(n.plain)));
});

test('mailing list: a list that re-sent the message under its own domain is named as the cause, with its server\'s record quoted', () => {
  const r = run('mailing-list-original-ar.txt');
  const f = r.finding;
  assert.equal(f.status, 'fail');
  assert.match(f.headline.technical, /came through the mailing list club\.lists\.example, which changed it, breaking the DKIM signature from author\.example, and sent it on as lists\.example/);
  assert.match(f.cause.technical, /Before the list, mx\.lists\.example recorded .*dmarc=pass \(author\.example\) in its Authentication-Results-Original field/);
  assert.match(f.cause.technical, /list tag \[club\]/);
  assert.ok(f.fixes.some(x => /^Nothing to change at author\.example/.test(x.technical)));
  assert.ok(f.fixes.some(x => /in Mailman, set DMARC mitigation/.test(x.technical)));
  assert.ok(f.fixes.every(x => !/domain authentication|Return-Path/.test(x.technical)));
});

test('mailing list without a record from before the list says it cannot show the earlier result', () => {
  const f = HA.analyze(fixture('mailing-list-original-ar.txt').replace(/Authentication-Results-Original:[^]*?header\.from=author\.example\n/, '')).finding;
  assert.match(f.cause.technical, /^No record from before the list is in the headers/);
  assert.ok(f.fixes.some(x => /^Nothing to change at author\.example on the strength of this message/.test(x.technical)));
});

test('the same header block pasted twice reads as one message', () => {
  const t = fixture('mailing-list-original-ar.txt');
  const r = HA.analyze(t + t);
  assert.equal(r.message.fromCount, 1);
  assert.equal(r.fields.length, HA.analyze(t).fields.length);
  assert.equal(r.finding.status, 'fail');
  assert.ok(r.input.notes.some(n => /pasted twice/.test(n.plain)));
});

test('a paste repeated with text between, three times, or cut short still reads as one message', () => {
  const t = fixture('mailing-list-original-ar.txt');
  // Outlook's reading pane text above the headers, once without a blank
  // line (it folds into the field before it) and once with one (the
  // second copy then reads as a body and is ignored).
  const pre = '[club] Re: Meeting notes\nPat Author <pat@author.example>\nSee you Tuesday.\nhttps://lists.example/club\n';
  const preBlank = '[club] Re: Meeting notes\n\nSee you Tuesday.\n';
  const one = HA.analyze(t);
  const cut = t.split('\n').slice(0, 20).join('\n');
  for (const [name, text, copies] of [['text between', pre + t + pre + t, 'twice'], ['text with a blank line between', preBlank + t + preBlank + t, ''], ['three times', t + t + t, '3 times'], ['cut short', t + cut, 'twice']]) {
    const r = HA.analyze(text);
    assert.equal(r.message.fromCount, 1, name);
    assert.equal(r.fields.length, one.fields.length, name);
    assert.equal(r.finding.headline.technical, one.finding.headline.technical, name);
    if (copies) assert.ok(r.input.notes.some(n => n.plain.includes('pasted ' + copies)), name);
  }
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
  assert.match(f.headline.technical, /^DMARC passed at mx\.receiver\.example for a reason these headers do not show/);
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

test('no usable From address: status unknown, not a crash', () => {
  const base = fixture('no-from.txt');
  for (const text of [base, base.replace('To:', 'From: Alex Rivera\nTo:'), base.replace('To:', 'From:\nTo:')]) {
    const f = HA.analyze(text).finding;
    assert.equal(f.status, 'unknown');
    assert.match(f.headline.technical, /no usable From address/);
  }
});

test('a subdomain From quotes the organizational domain\'s sp=, not p=', () => {
  const c = run('dmarc-subdomain-sp.txt').finding.consequence;
  assert.match(c.technical, /^shop\.example publishes sp=none for subdomains such as news\.shop\.example, which asks for no action/);
  assert.ok(!/p=reject/.test(c.technical));
  assert.match(c.plain, /asks for no action/);
});

test('every fixture pasted twice gives the same finding as one paste', () => {
  for (const name of FIXTURES) {
    const t = fixture(name);
    const one = HA.analyze(t).finding, two = HA.analyze(t.trimEnd() + '\n' + t).finding;
    assert.equal(two && two.headline.technical, one && one.headline.technical, name);
  }
});

// The Simple voice word list in CLAUDE.md, over every sentence the
// page can show for every fixture.
const { SIMPLE_BANNED } = require('./simple-words.js');
test('Simple wording uses none of the technical words', () => {
  const bad = [];
  for (const name of FIXTURES) {
    const r = HA.analyze(fixture(name));
    const f = r.finding;
    const all = [].concat(f ? [f.headline, f.cause, f.consequence].concat(f.details, f.fixes, f.flags, f.limits) : [], r.input.notes, r.message.notes || [], r.decoded.notes || [], (r.decoded.filters || []).flatMap(g => g.items || []), r.decoded.list || [], r.decoded.platform && r.decoded.platform.statement ? [r.decoded.platform.statement] : [], r.chain.notes || [], r.auth.notes || []).filter(Boolean);
    // Microsoft's own setting name is quoted so an admin can find it.
    for (const x of all) if (x.plain && (SIMPLE_BANNED.test(x.plain.replace(/Trusted ARC sealers/g, '').replace(/\([^)]*\)/g, '')) || x.plain.includes(';'))) bad.push(name + ': ' + x.plain);
  }
  assert.deepEqual(Array.from(new Set(bad)).slice(0, 40), []);
});

// Patterns from real list traffic (kernel.org, 2026-10-29), rebuilt with synthetic names.
test('the receiver\'s results split across fields just below its own stamp are all read', () => {
  const r = run('ar-split-below-stamp.txt');
  assert.equal(r.finding.status, 'error');
  assert.equal(r.auth.dmarc.result, 'permerror');
  assert.equal(r.auth.spf.result, 'none');
});

test('Gmail\'s seal on sent mail is not a forward, and an author\'s [PATCH] is not a list tag', () => {
  const f = run('gmail-outbound-seal-list.txt').finding;
  assert.equal(f.forwarded.yes, false);
  assert.equal(f.status, 'fail');
  assert.match(f.headline.technical, /came through the mailing list dev\.lists\.example/);
  assert.doesNotMatch(f.cause.technical, /already failing|list tag/);
});

test('Microsoft 365 sealing a tenant\'s outgoing mail is not a forward', () => {
  const f = run('m365-outbound-seal.txt').finding;
  assert.equal(f.status, 'pass');
  assert.equal(f.forwarded.yes, false);
  assert.doesNotMatch(f.cause.technical, /forwarded by/);
});

test('a field with the receiver\'s authserv-id below the previous hop\'s stamp is still not trusted', () => {
  const text = fixture('ar-split-below-stamp.txt').replace('From: Sam Author', 'Authentication-Results: smtp.lists.example; dkim=pass header.d=author.example header.s=forged\nFrom: Sam Author');
  const a = HA.analyze(text).auth;
  assert.ok(!a.dkim.some(k => k.result === 'pass'));
});

test('mail straight from the sender: results below the receiver\'s only stamp come from its own ARC record', () => {
  const text = fixture('ar-split-below-stamp.txt').replace(/Received: by host\.author\.example[^\n]*\n[^\n]*\n/, '');
  const r = HA.analyze(text);
  assert.equal(r.auth.dmarc.result, 'permerror');
  assert.equal(r.auth.spf.result, 'none');
  assert.ok(r.auth.notes.some(n => /^The spf and dmarc results come from the ARC-Authentication-Results smtp\.lists\.example wrote/.test(n.technical)));
});

// Patterns from public phishing samples received at Outlook and Proton (2026-10-29), rebuilt with synthetic names.
test('Exchange Online: an Authentication-Results field in encoded words is decoded, a line of spaces does not end the headers, and look-alike letters in the From domain are flagged', () => {
  const r = run('exo-encoded-ar-lookalike.txt');
  assert.ok(r.fields.some(f => f.name === 'X-MS-Exchange-Organization-AuthAs'));
  assert.equal(r.auth.primary, 0);
  assert.equal(r.auth.spf.result, 'pass');
  assert.ok(r.finding.flags.some(f => /look-alike characters that read as funb-club\.example/.test(f.technical)));
});

test('Proton: its own fields under the whole Received block count, with a note', () => {
  const r = run('proton-ar-at-bottom.txt');
  assert.equal(r.finding.status, 'pass');
  assert.equal(r.auth.spf.result, 'pass');
  assert.ok(r.auth.notes.some(n => /^Proton puts its Authentication-Results fields under every Received field/.test(n.technical)));
});

test('a quoted display name split off by a comma is not a second From address', () => {
  const a = HA.parse.parseAddresses('"Promotions@shop.example", <service@other.example>');
  assert.deepEqual(a.map(x => x.domain), ['other.example']);
  assert.equal(HA.parse.parseAddresses('<x@trailing.example.>')[0].domain, 'trailing.example');
});

test('a look-alike From domain replaces the setup advice with a phishing warning', () => {
  const f = run('exo-encoded-ar-lookalike.txt').finding;
  assert.equal(f.fixes.length, 1);
  assert.match(f.fixes[0].technical, /^Treat the message as phishing/);
});
