'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { HA, fixture } = require('./load.js');

const run = (name) => HA.analyze(fixture(name));
const LEVELS = ['pass', 'info', 'warn', 'fail'];
const group = (r, id) => r.decoded.filters.find(g => g.id === id);
const get = (g, key) => g.items.find(i => i.key === key);

test('Microsoft: SCL, BCL, CAT, SFV, IPV, CIP and DIR decoded from X-Forefront-Antispam-Report, compauth reason decoded', () => {
  const r = run('forwarded.txt');
  const ms = group(r, 'microsoft');
  assert.equal(ms.side, 'receiver');
  assert.equal(get(ms, 'CAT').level, 'fail');
  assert.match(get(ms, 'CAT').technical, /^Threat category: Spoofing\./);
  assert.equal(get(ms, 'SFV').raw, 'SPM');
  assert.equal(get(ms, 'SFV').level, 'fail');
  assert.equal(get(ms, 'IPV').raw, 'NLI');
  assert.equal(get(ms, 'IPV').level, 'pass');
  assert.equal(get(ms, 'CIP').raw, '198.51.100.25');
  assert.equal(get(ms, 'DIR').raw, 'INB');
  assert.equal(get(ms, 'BCL').raw, '0');
  assert.equal(get(ms, 'BCL').level, 'pass');
  // SCL 5 in both the Forefront field and X-MS-Exchange-Organization-SCL: one item citing both.
  const scl = get(ms, 'SCL');
  assert.equal(scl.level, 'fail');
  assert.deepEqual(scl.src.map(i => r.fields[i].lower).sort(), ['x-forefront-antispam-report', 'x-ms-exchange-organization-scl']);
  assert.equal(ms.items.filter(i => /SCL/.test(i.key)).length, 1);
  const ca = get(ms, 'compauth');
  assert.equal(ca.raw, 'fail reason=000');
  assert.match(ca.technical, /explicit authentication failed/);
  assert.equal(ms.outcome.key, 'CAT');
});

test('Microsoft: codes outside the published tables are shown raw with no guess', () => {
  const r = run('m365-filter-codes.txt');
  const ms = group(r, 'microsoft');
  for (const k of ['SFV', 'SFTY']) {
    const it = get(ms, k);
    assert.equal(it.level, 'info', k);
    assert.match(it.technical, /is not in Microsoft's published table, so it is shown as written/, k);
  }
  assert.equal(get(ms, 'SFV').raw, 'QQQ');
  assert.equal(get(ms, 'SFTY').raw, '9.99');
  assert.equal(get(ms, 'CAT').level, 'warn');
  assert.equal(get(ms, 'SRV').level, 'warn');
  assert.equal(get(ms, 'IPV').level, 'pass');
  assert.equal(get(ms, 'BCL').level, 'fail');
  // SCL 7 has no meaning of its own; 3 has none either, and the two fields disagree, so both show.
  assert.equal(get(ms, 'SCL').level, 'warn');
  const org = get(ms, 'X-MS-Exchange-Organization-SCL');
  assert.equal(org.raw, '3');
  assert.equal(org.level, 'info');
  assert.match(org.technical, /no published meaning/);
  assert.match(get(ms, 'compauth').technical, /passed explicit or implicit authentication \(code 123 has no entry of its own\)/);
  assert.equal(HA.providers.compauthMeaning('xyz'), '');
});

test('Microsoft: X-MS-Exchange-Organization-SCL alone is decoded', () => {
  const ms = group(run('exchange-online-oreject.txt'), 'microsoft');
  const it = get(ms, 'X-MS-Exchange-Organization-SCL');
  assert.equal(it.raw, '9');
  assert.equal(it.level, 'fail');
  assert.match(it.technical, /high confidence spam/);
});

test('Microsoft: X-Microsoft-Antispam-Mailbox-Delivery is shown as written, with no meaning attached', () => {
  const r = run('m365-filter-codes.txt');
  const ms = group(r, 'microsoft');
  const it = get(ms, 'X-Microsoft-Antispam-Mailbox-Delivery');
  assert.equal(it.raw, 'ucf:0;jmr:0;auth:0;dest:J;ENG:(910005)(944506478)(944626604)(920097)(930097);');
  assert.equal(it.level, 'info');
  assert.match(it.technical, /Microsoft does not document/);
  assert.doesNotMatch(it.technical + it.plain, /[Jj]unk/);
  assert.equal(r.fields[it.src[0]].lower, 'x-microsoft-antispam-mailbox-delivery');
});

test('Google: X-Google-DKIM-Signature explained, spam markers shown raw, and the missing spam decision stated', () => {
  const r = run('google-markers.txt');
  const g = group(r, 'google');
  assert.equal(g.side, 'receiver');
  assert.equal(get(g, 'X-Google-DKIM-Signature').raw, 'd=1e100.net');
  assert.match(get(g, 'X-Google-DKIM-Signature').technical, /does not count for DMARC/);
  for (const k of ['X-Gm-Spam', 'X-Gm-Phishy']) {
    assert.equal(get(g, k).raw, '0');
    assert.match(get(g, k).technical, /Google does not document/);
  }
  assert.equal(get(g, 'X-Gm-Message-State').raw, 'opaque');
  assert.match(g.note.technical, /Gmail writes no spam, Promotions or inbox placement decision into headers/);
});

test('Proofpoint: rule and scores, written by a gateway in front of Microsoft 365', () => {
  const r = run('two-providers.txt');
  const pp = group(r, 'proofpoint');
  assert.equal(get(pp, 'rule').level, 'pass');
  assert.equal(get(pp, 'clxscore').raw, '1015');
  assert.equal(get(pp, 'clxscore').level, 'info');
  assert.equal(pp.side, 'before-custody');
  assert.ok(r.decoded.notes.some(n => /Proofpoint headers sit below the receiver's first stamp/.test(n.technical)));
});

test('a message carrying two providers lists both, in order, each with its own source', () => {
  const r = run('two-providers.txt');
  assert.deepEqual(r.decoded.filters.map(g => g.id), ['microsoft', 'proofpoint']);
  assert.equal(group(r, 'microsoft').side, 'receiver');
  const f = r.finding;
  assert.ok(f.details.some(d => /^Microsoft 365, CAT NONE/.test(d.technical)));
  assert.ok(f.details.some(d => /^Proofpoint, rule notspam/.test(d.technical)));
});

test('Mimecast: score raw, Impersonation Protect reduced to the checks that fired', () => {
  const r = run('mimecast.txt');
  const m = group(r, 'mimecast');
  assert.equal(get(m, 'Spam-Score').raw, '2');
  assert.equal(get(m, 'Spam-Score').level, 'info');
  const ip = get(m, 'Impersonation-Protect');
  assert.equal(ip.raw, 'nothing fired');
  assert.equal(ip.level, 'pass');
  const fired = group(HA.analyze(fixture('mimecast.txt').replace('Newly Observed Domain=false', 'Newly Observed Domain=true')), 'mimecast');
  assert.equal(get(fired, 'Impersonation-Protect').raw, 'Newly Observed Domain');
  assert.equal(get(fired, 'Impersonation-Protect').level, 'warn');
});

test('Cisco: the encoded result is called opaque, never decoded', () => {
  const c = group(run('cisco.txt'), 'cisco');
  assert.equal(c.name, 'Cisco Secure Email');
  assert.equal(get(c, 'X-IronPort-Anti-Spam-Result').raw, 'opaque');
  assert.match(get(c, 'X-IronPort-Anti-Spam-Result').technical, /Cisco does not publish how to read it/);
  assert.equal(get(c, 'Reputation').raw, '-3.2');
  assert.equal(get(c, 'Anti-Spam-Filtered').raw, 'true');
});

test('Barracuda: spam status with its score and levels', () => {
  const b = group(run('barracuda.txt'), 'barracuda');
  const s = get(b, 'Spam-Status');
  assert.equal(s.raw, 'Yes');
  assert.equal(s.level, 'fail');
  assert.match(s.technical, /score 7\.20, tag level 3\.5, block level 9\.0/);
});

test('SpamAssassin: status, score against the threshold, and the rules that matched across a fold', () => {
  const s = group(run('spamassassin.txt'), 'spamassassin');
  assert.equal(get(s, 'X-Spam-Status').level, 'fail');
  assert.match(get(s, 'X-Spam-Status').technical, /score 6\.4 against a threshold of 5\.0/);
  assert.equal(get(s, 'tests').raw, 'HTML_MESSAGE,URIBL_BLOCKED');
});

test('Rspamd: the action decides the level, the result line gives score and reject threshold', () => {
  const r = group(run('rspamd.txt'), 'rspamd');
  assert.equal(get(r, 'X-Rspamd-Action').level, 'pass');
  assert.equal(get(r, 'X-Spamd-Result').raw, '3.10 / 15.00');
  const odd = group(HA.analyze(fixture('rspamd.txt').replace('no action', 'quarantine please')), 'rspamd');
  assert.equal(get(odd, 'X-Rspamd-Action').level, 'info');
  assert.match(get(odd, 'X-Rspamd-Action').technical, /not in Rspamd's published table/);
});

test('a message with no filter headers says so, and still reads its list headers', () => {
  const r = run('icloud.txt');
  assert.equal(r.decoded.filters.length, 0);
  assert.ok(r.decoded.notes.some(n => /^No filter headers from Microsoft, Google, Proofpoint, Mimecast, Cisco, Barracuda, SpamAssassin or Rspamd/.test(n.technical)));
  assert.equal(r.decoded.notes[0].state, 'unknown');
});

test('platform: a platform header plus domains is high confidence, with the evidence cited', () => {
  const p = run('platform-sendgrid.txt').decoded.platform;
  assert.equal(p.name, 'SendGrid');
  assert.equal(p.confidence, 'high');
  assert.deepEqual(p.evidence.map(e => e.what), ['header', 'Return-Path', 'DKIM d=', 'first relay']);
  assert.ok(p.evidence.every(e => e.src.length));
});

test('platform: DKIM d= alone is medium, the relay name alone is low, a label boundary is required, and nothing is guessed', () => {
  const base = fixture('esp-unaligned.txt');
  assert.equal(HA.analyze(base).decoded.platform.name, '');
  assert.equal(HA.analyze(base).decoded.platform.confidence, '');
  const dkim = HA.analyze(base.replace(/mailer\.example; s=m1/, 'mailgun.org; s=m1').replace('header.i=@mailer.example', 'header.i=@mailgun.org')).decoded.platform;
  assert.equal(dkim.name, 'Mailgun');
  assert.equal(dkim.confidence, 'medium');
  const relay = HA.analyze(base.replace(/o1\.mailer\.example/g, 'o1.sparkpostmail.com')).decoded.platform;
  assert.equal(relay.name, 'SparkPost');
  assert.equal(relay.confidence, 'low');
  const near = HA.analyze(base.replace(/o1\.mailer\.example/g, 'o1.notsparkpostmail.com')).decoded.platform;
  assert.equal(near.name, '');
});

test('list headers: RFC 8058 one-click must be signed by a passing DKIM signature', () => {
  const ok = run('platform-sendgrid.txt').decoded.list;
  assert.equal(ok.find(i => i.key === 'List-Unsubscribe').raw, 'https and mailto');
  assert.equal(ok.find(i => i.key === 'List-Unsubscribe-Post').level, 'pass');
  const unsigned = HA.analyze(fixture('platform-sendgrid.txt').replace(':list-unsubscribe:list-unsubscribe-post;', ';')).decoded.list;
  const it = unsigned.find(i => i.key === 'List-Unsubscribe-Post');
  assert.equal(it.level, 'warn');
  assert.match(it.technical, /RFC 8058 section 4 requires/);
  const missing = HA.analyze(fixture('platform-sendgrid.txt').replace(/List-Unsubscribe-Post:[^\n]*\n/, '')).decoded.list;
  assert.equal(missing.find(i => i.key === 'List-Unsubscribe-Post').raw, 'missing');
  const mailtoOnly = HA.analyze(fixture('platform-sendgrid.txt').replace('<https://u2210.ct.sendgrid.net/unsub/602>, ', '')).decoded.list;
  assert.match(mailtoOnly.find(i => i.key === 'List-Unsubscribe-Post').technical, /needs an https address/);
  assert.equal(ok.find(i => i.key === 'Feedback-ID').raw, '2210:club:sendgrid');
});

test('list headers: Reply-To at another organization is a warning and a finding flag', () => {
  const r = HA.analyze(fixture('esp-unaligned.txt').replace('MIME-Version', 'Reply-To: help@desk.example\nMIME-Version'));
  const rt = r.decoded.list.find(i => i.key === 'Reply-To');
  assert.equal(rt.level, 'warn');
  assert.ok(r.finding.flags.some(f => /Replies go to desk\.example/.test(f.technical)));
});

test('every decoded item has a level, the raw value, both readers, and valid sources', () => {
  for (const name of fs.readdirSync(path.join(__dirname, 'fixtures')).filter(f => f.endsWith('.txt'))) {
    const r = HA.analyze(fixture(name));
    for (const it of r.decoded.filters.flatMap(g => g.items).concat(r.decoded.list)) {
      assert.ok(LEVELS.includes(it.level), name + ' ' + it.key);
      assert.equal(typeof it.raw, 'string');
      assert.ok(it.technical && it.plain, name + ' ' + it.key);
      assert.ok(it.src.length, name + ' ' + it.key);
      for (const i of it.src) assert.ok(r.fields[i], name + ' ' + it.key);
    }
  }
});
