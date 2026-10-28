// sentences.js: the sentence inventory. Drives src/finding.js through
// every status and cause with minimal synthetic headers built here, then
// adds every filter code meaning from src/providers.js, and writes the
// lot to docs/sentences.md so a diff shows every wording change.
// npm run sentences writes the file; test/sentences.test.js reads the
// same cases.
'use strict';
const fs = require('fs');
const path = require('path');
const { HA } = require('../test/load.js');

const FROM = 'Shop <orders@shop.example>';
const DATE = 'Fri, 23 Oct 2026 09:14:00 +0000';

function block(lines) { return lines.filter(Boolean).join('\n') + '\n'; }
function sig(d, s) { return 'DKIM-Signature: v=1; a=rsa-sha256; c=relaxed/relaxed; d=' + d + '; s=' + s + '; h=from:to:subject:date:message-id; bh=SyntheticBh=; b=' + s + 'SyntheticValue'; }
function message(from, extra) {
  return [].concat(from === null ? [] : [].concat(from).map(f => 'From: ' + f), ['To: pat@receiver.example', 'Subject: Synthetic case', 'Date: ' + DATE, 'Message-ID: <case@shop.example>'], extra || []);
}

// A receiver that writes the RFC 8601 form with an authserv-id.
function rcv(o) {
  return block([
    'Delivered-To: pat@receiver.example',
    o.received === false ? '' : 'Received: from o1.sender.example (o1.sender.example [203.0.113.90]) by mx.receiver.example with ESMTPS id c1 for <pat@receiver.example>; ' + DATE,
    o.ar === undefined ? '' : 'Authentication-Results: mx.receiver.example; ' + o.ar,
  ].concat(o.above || [], (o.sigs || []).map(x => sig(x[0], x[1])), message(o.from === undefined ? FROM : o.from, o.extra)));
}

// Exchange Online: the id-less Authentication-Results form.
function ms(ar, extra) {
  return block([
    'Received: from BN3PEPF0000B077.namprd04.prod.outlook.com (2603:10b6:408:ed:cafe::4c) by BN0PR04CA0123.outlook.office365.com (2603:10b6:408:ed::8) with Microsoft SMTP Server (version=TLS1_3, cipher=TLS_AES_256_GCM_SHA384) id 15.20.9100.14 via Frontend Transport; ' + DATE,
    'Authentication-Results: ' + ar,
    'Received: from o1.sender.example (198.51.100.44) by BN3PEPF0000B077.mail.protection.outlook.com (10.167.243.77) with Microsoft SMTP Server (version=TLS1_2, cipher=TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384) id 15.20.9100.14 via Frontend Transport; ' + DATE,
    'X-MS-Exchange-Organization-AuthAs: Anonymous',
  ].concat(extra || [], message(FROM)));
}

// A forward through forward.example, sealed i=1 with what it saw on arrival.
function fwd(ar, pre) {
  return block([
    'Received: from out.forward.example (out.forward.example [198.51.100.80]) by mx.receiver.example with ESMTPS id f2 for <pat@receiver.example>; ' + DATE,
    'Authentication-Results: mx.receiver.example; ' + ar,
    'ARC-Seal: i=1; a=rsa-sha256; cv=none; d=forward.example; s=arc1; b=SyntheticSeal',
    'ARC-Message-Signature: i=1; a=rsa-sha256; c=relaxed/relaxed; d=forward.example; s=arc1; h=from:to:subject:date:message-id; bh=SyntheticBh=; b=SyntheticAms',
    'ARC-Authentication-Results: i=1; mx.forward.example; ' + pre,
    'Received: from mx.forward.example (mx.forward.example [10.9.0.4]) by out.forward.example (Postfix) with ESMTP id f1; ' + DATE,
    'Received: from mail.shop.example (mail.shop.example [192.0.2.55]) by mx.forward.example (Postfix) with ESMTPS id f0 for <pat@forward.example>; ' + DATE,
    sig('shop.example', 's1'),
  ].concat(message(FROM)));
}

const PASS_PRE = 'spf=pass smtp.mailfrom=orders@shop.example; dkim=pass header.d=shop.example header.s=s1; dmarc=pass header.from=shop.example';
const REJECT = 'dmarc=fail (p=REJECT sp=REJECT dis=REJECT) header.from=shop.example';
const ESP_SPF = 'spf=pass smtp.mailfrom=b-1@bounce.mailer.example';
const msFail = (spf, dkim, action, ca) => ms(spf + '; ' + dkim + '; dmarc=fail action=' + action + ' header.from=shop.example; compauth=' + ca);
const MS_SPF_FAIL = 'spf=fail (sender IP is 198.51.100.44) smtp.mailfrom=shop.example';
const MS_NO_DKIM = 'dkim=none (message not signed) header.d=none';

// Case name, headers. Names are stable: the test and the doc key on them.
const CASES = [
  ['pass by DKIM', rcv({ ar: 'dkim=pass header.d=shop.example header.s=s1; ' + ESP_SPF + '; dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=shop.example', sigs: [['shop.example', 's1']] })],
  ['pass by SPF', rcv({ ar: 'spf=pass smtp.mailfrom=orders@shop.example; dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=shop.example' })],
  ['pass by both', rcv({ ar: 'dkim=pass header.d=shop.example header.s=s1; spf=pass smtp.mailfrom=orders@shop.example; dmarc=pass (p=NONE sp=NONE dis=NONE) header.from=shop.example', sigs: [['shop.example', 's1']] })],
  ['pass reported with nothing aligned', rcv({ ar: ESP_SPF + '; dmarc=pass (p=REJECT sp=REJECT dis=NONE) header.from=shop.example' })],
  ['pass computed, no DMARC result reported', rcv({ ar: 'dkim=pass header.d=shop.example header.s=s1; ' + ESP_SPF, sigs: [['shop.example', 's1']] })],
  ['fail with no DKIM signature', rcv({ ar: 'spf=neutral smtp.mailfrom=orders@shop.example; ' + REJECT })],
  ['fail with DKIM unaligned', rcv({ ar: 'dkim=pass header.d=mailer.example header.s=m1; ' + ESP_SPF + '; ' + REJECT, sigs: [['mailer.example', 'm1']] })],
  ['fail with DKIM broken in transit', rcv({ ar: 'dkim=fail (body hash did not verify) header.d=shop.example header.s=s1; ' + ESP_SPF + '; ' + REJECT, sigs: [['shop.example', 's1']] })],
  ['fail with SPF for the bounce domain only', rcv({ ar: ESP_SPF + '; ' + REJECT })],
  ['fail with SPF for HELO only', rcv({ ar: 'spf=pass smtp.helo=o1.mailer.example; ' + REJECT, above: ['Return-Path: <>'] })],
  ['fail with SPF fail', rcv({ ar: 'spf=fail smtp.mailfrom=orders@shop.example; ' + REJECT })],
  ['fail with SPF softfail', rcv({ ar: 'spf=softfail smtp.mailfrom=orders@shop.example; ' + REJECT })],
  ['fail with SPF none', rcv({ ar: 'spf=none smtp.mailfrom=orders@shop.example; ' + REJECT })],
  ['fail with SPF permerror', rcv({ ar: 'spf=permerror smtp.mailfrom=orders@shop.example; ' + REJECT })],
  ['fail with SPF temperror', rcv({ ar: 'spf=temperror smtp.mailfrom=orders@shop.example; ' + REJECT })],
  ['fail with DKIM permerror', rcv({ ar: 'dkim=permerror (no key for signature) header.d=shop.example header.s=s1; ' + ESP_SPF + '; ' + REJECT, sigs: [['shop.example', 's1']] })],
  ['fail with DKIM temperror', rcv({ ar: 'dkim=temperror (key query timeout) header.d=shop.example header.s=s1; ' + ESP_SPF + '; ' + REJECT, sigs: [['shop.example', 's1']] })],
  ['fail computed, no DMARC result reported', rcv({ ar: 'dkim=pass header.d=mailer.example header.s=m1; spf=none smtp.mailfrom=orders@shop.example', sigs: [['mailer.example', 'm1']] })],
  ['fail through a mailing list', rcv({ ar: 'dkim=fail header.d=shop.example header.s=s1; spf=pass smtp.mailfrom=owner@list.example; ' + REJECT, sigs: [['shop.example', 's1']], extra: ['List-Id: <club.list.example>'] })],
  ['fail through a mailing list that kept its record', rcv({ ar: 'dkim=fail header.d=shop.example header.s=s1; spf=pass smtp.mailfrom=owner@list.example; ' + REJECT, sigs: [['shop.example', 's1']], extra: ['List-Id: <club.list.example>', 'Authentication-Results-Original: mx.list.example; dkim=pass header.d=shop.example header.s=s1; spf=pass smtp.mailfrom=news@shop.example; dmarc=pass header.from=shop.example'] })],
  ['fail with the receiver judging differently', rcv({ ar: 'dkim=pass header.d=shop.example header.s=s1; ' + REJECT, sigs: [['shop.example', 's1']] })],
  ['strict alignment suspected', rcv({ ar: 'dkim=pass header.d=mail.shop.example header.s=s1; ' + ESP_SPF + '; ' + REJECT, sigs: [['mail.shop.example', 's1']] })],
  ['dmarc none, would pass', rcv({ ar: 'dkim=pass header.d=shop.example header.s=s1; ' + ESP_SPF + '; dmarc=none header.from=shop.example', sigs: [['shop.example', 's1']] })],
  ['dmarc none, would fail', rcv({ ar: ESP_SPF + '; dmarc=none header.from=shop.example' })],
  ['dmarc bestguesspass', rcv({ ar: 'spf=pass smtp.mailfrom=orders@shop.example; dmarc=bestguesspass header.from=shop.example' })],
  ['dmarc permerror', rcv({ ar: 'spf=pass smtp.mailfrom=orders@shop.example; dmarc=permerror header.from=shop.example' })],
  ['dmarc temperror', rcv({ ar: ESP_SPF + '; dmarc=temperror header.from=shop.example' })],
  ['dmarc result outside RFC 7489', rcv({ ar: ESP_SPF + '; dmarc=policy header.from=shop.example' })],
  ['forwarded with arc=pass', fwd('dkim=fail header.d=shop.example header.s=s1; arc=pass; spf=softfail smtp.mailfrom=orders@shop.example; ' + REJECT, PASS_PRE)],
  ['forwarded, noted but not relied on', fwd('dkim=fail header.d=shop.example header.s=s1; spf=softfail smtp.mailfrom=orders@shop.example; ' + REJECT, PASS_PRE)],
  ['forwarded, already failing before the forward', fwd('spf=pass smtp.mailfrom=srs@forward.example; arc=pass; ' + REJECT, 'spf=fail smtp.mailfrom=orders@shop.example; dmarc=fail header.from=shop.example')],
  ['no Authentication-Results', rcv({ sigs: [['shop.example', 's1']] })],
  ['Authentication-Results with no results', rcv({ ar: 'none' })],
  ['untrusted Authentication-Results claims a pass', rcv({ ar: 'dkim=pass header.d=mailer.example header.s=m1; spf=fail smtp.mailfrom=orders@shop.example; ' + REJECT, sigs: [['mailer.example', 'm1']], extra: ['Authentication-Results: spoof.example; dmarc=pass header.from=shop.example'] })],
  ['no Received', rcv({ received: false, sigs: [['shop.example', 's1']] })],
  ['two From fields', rcv({ ar: 'spf=pass smtp.mailfrom=orders@shop.example; dmarc=pass header.from=shop.example', from: [FROM, 'Bank <alerts@bank.example>'] })],
  ['From naming two domains', rcv({ ar: 'spf=pass smtp.mailfrom=orders@shop.example', from: 'orders@shop.example, alerts@bank.example' })],
  ['no From', rcv({ ar: 'spf=pass smtp.mailfrom=orders@shop.example', from: null })],
  ['display name impersonation', rcv({ ar: 'dkim=pass header.d=notify.example header.s=n1; spf=pass smtp.mailfrom=alerts@notify.example; dmarc=pass header.from=notify.example', sigs: [['notify.example', 'n1']], from: '"security@bank.example" <alerts@notify.example>' })],
  ['Microsoft action oreject', msFail(MS_SPF_FAIL, MS_NO_DKIM, 'oreject', 'fail reason=000')],
  ['Microsoft action quarantine', msFail('spf=softfail (sender IP is 198.51.100.44) smtp.mailfrom=shop.example', 'dkim=fail (body hash did not verify) header.d=shop.example', 'quarantine', 'fail reason=000')],
  ['Microsoft action none', msFail('spf=pass (sender IP is 198.51.100.44) smtp.mailfrom=bounce.mailer.example', 'dkim=pass (signature was verified) header.d=mailer.example', 'none', 'fail reason=001')],
  ['compauth 0xx, explicit fail', msFail(MS_SPF_FAIL, MS_NO_DKIM, 'reject', 'fail reason=002')],
  ['compauth 1xx, pass', ms('spf=pass (sender IP is 198.51.100.44) smtp.mailfrom=shop.example; dkim=pass (signature was verified) header.d=shop.example; dmarc=pass action=none header.from=shop.example; compauth=pass reason=100')],
  ['compauth 2xx, soft pass', ms(MS_SPF_FAIL + '; ' + MS_NO_DKIM + '; dmarc=none action=none header.from=shop.example; compauth=softpass reason=201')],
  ['compauth 3xx, not checked', ms(MS_SPF_FAIL + '; ' + MS_NO_DKIM + '; dmarc=none action=none header.from=shop.example; compauth=none reason=300')],
  ['compauth 4xx, bypassed', msFail(MS_SPF_FAIL, MS_NO_DKIM, 'none', 'none reason=451')],
  ['compauth 5xx, bounce not enforced', msFail(MS_SPF_FAIL, MS_NO_DKIM, 'none', 'pass reason=501')],
  ['compauth 6xx, implicit fail', msFail(MS_SPF_FAIL, MS_NO_DKIM, 'quarantine', 'fail reason=601')],
  ['compauth 7xx, history pass', msFail(MS_SPF_FAIL, MS_NO_DKIM, 'none', 'pass reason=701')],
  ['compauth 8xx, not in the table', msFail(MS_SPF_FAIL, MS_NO_DKIM, 'quarantine', 'fail reason=801')],
  ['compauth 9xx, complex routing', msFail(MS_SPF_FAIL, MS_NO_DKIM, 'none', 'none reason=905')],
];

function run(name, text) {
  const r = HA.analyze(text);
  if (!r.finding) throw new Error(name + ': no finding');
  return r.finding;
}

// Every Sentence a case shows, labelled, in page order.
function lines(f) {
  const out = [];
  const pair = (label, s) => { if (s) out.push([label + ', plain', s.plain], [label + ', technical', s.technical]); };
  out.push(['Plain headline', f.headline.plain], ['Technical headline', f.headline.technical]);
  pair('Cause', f.cause);
  if (f.consequence) pair('Policy', f.consequence); else out.push(['Policy', 'none written']);
  f.details.forEach((s, i) => pair('Detail ' + (i + 1), s));
  f.fixes.forEach((s, i) => pair('Fix ' + (i + 1), s));
  f.flags.forEach((s, i) => pair('Flag ' + (i + 1), s));
  return out;
}

// Each filter code driven through providers.js with a synthetic field,
// so the line is what the page shows. One line per code.
function meanings() {
  const T = HA.providers.TABLES;
  const out = [];
  const decode = (hdrs, compauth) => {
    const fields = HA.parse.parseHeaders(block(hdrs.concat(message(FROM)))).fields;
    const auth = { compauth: compauth ? { result: compauth[0], reason: compauth[1], src: [] } : null };
    return [HA.providers.decodeMicrosoft(fields, auth)].concat(HA.providers.decodeGateways(fields)).filter(Boolean);
  };
  const emit = (vendor, groups) => { for (const g of groups) for (const it of g.items) out.push([vendor + ' ' + it.key + ' ' + it.raw + ' (' + it.level + ')', it.technical, it.plain]); };
  const ff = (k, v) => decode(['X-Forefront-Antispam-Report: ' + k + ':' + v]);
  for (const k of Object.keys(T.MS_CAT)) emit('Microsoft', ff('CAT', k));
  for (const k of Object.keys(T.MS_SFV)) emit('Microsoft', ff('SFV', k));
  for (const k of ['-1', '0', '1', '2', '5', '6', '7', '9', '10']) emit('Microsoft', ff('SCL', k));
  for (let n = 0; n <= 9; n++) emit('Microsoft', ff('BCL', String(n)));
  for (const k of ['1', '4', '9']) emit('Microsoft', decode(['X-MS-Exchange-Organization-PCL: ' + k]));
  for (const k of ['CAL', 'NLI', 'XYZ']) emit('Microsoft', ff('IPV', k));
  emit('Microsoft', ff('SRV', 'BULK'));
  for (const k of Object.keys(T.MS_SFTY)) emit('Microsoft', ff('SFTY', k));
  for (const k of Object.keys(T.MS_DIR)) emit('Microsoft', ff('DIR', k));
  for (const [k, v] of [['CIP', '198.51.100.44'], ['CTRY', 'US'], ['H', 'o1.sender.example'], ['PTR', 'o1.sender.example'], ['SFS', '(13230040)']]) emit('Microsoft', ff(k, v));
  for (const k of ['Internal', 'Anonymous', 'External', 'Partner']) emit('Microsoft', decode(['X-MS-Exchange-Organization-AuthAs: ' + k]));
  emit('Microsoft', decode(['X-MS-Exchange-Organization-AuthSource: BN3PEPF0000B077.namprd04.prod.outlook.com']));
  const codes = Object.keys(T.COMPAUTH).concat(['701', '702', '703', '704', '299', '399', '499', '699', '799', '999', '801']);
  for (const k of codes) emit('Microsoft', decode([], ['fail', k]));
  emit('Proofpoint', decode(['X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 spamscore=0 phishscore=0 bulkscore=0 malwarescore=0 suspectscore=0 impostorscore=0 adultscore=0 mlxscore=0 clxscore=0']));
  emit('Proofpoint', decode(['X-Proofpoint-Spam-Details: rule=spam']));
  emit('Proofpoint', decode(['X-Proofpoint-Spam-Details: rule=custom_rule']));
  emit('Mimecast', decode(['X-Mimecast-Spam-Score: 4', 'X-Mimecast-Impersonation-Protect: Policy=Default;Similar Internal Domain=false;Similar Monitored External Domain=true', 'X-Mimecast-Bulk-Signature: yes']));
  emit('Mimecast', decode(['X-Mimecast-Impersonation-Protect: Policy=Default;Similar Internal Domain=false']));
  emit('Mimecast', decode(['X-Mimecast-Impersonation-Protect: opaque']));
  emit('Mimecast', decode(['X-Mimecast-Spam-Signature: x']));
  emit('Cisco', decode(['X-IronPort-Anti-Spam-Filtered: true', 'X-IronPort-Anti-Spam-Result: A0ABCD', 'X-IPAS-Result: A0ABCD', 'X-IronPort-Reputation: -3.1', 'X-IronPort-AV: E=Sophos;i="6.00"']));
  emit('Cisco', decode(['X-IronPort-MID: 12345']));
  emit('Barracuda', decode(['X-Barracuda-Spam-Status: Yes, SCORE=7.1 using global scores of TAG_LEVEL=3.5 QUARANTINE_LEVEL=1000.0 KILL_LEVEL=6.0']));
  emit('Barracuda', decode(['X-Barracuda-Spam-Status: No, SCORE=0.2 using global scores of TAG_LEVEL=3.5 KILL_LEVEL=6.0']));
  emit('Barracuda', decode(['X-Barracuda-Spam-Status: Maybe']));
  emit('Barracuda', decode(['X-Barracuda-Spam-Score: 1.5', 'X-Barracuda-Spam-Flag: YES']));
  emit('Barracuda', decode(['X-Barracuda-Spam-Flag: NO']));
  emit('SpamAssassin', decode(['X-Spam-Status: Yes, score=6.2 required=5.0 tests=BAYES_99,URIBL_BLOCKED']));
  emit('SpamAssassin', decode(['X-Spam-Status: No, score=0.1 required=5.0']));
  emit('SpamAssassin', decode(['X-Spam-Status: Unclear']));
  emit('SpamAssassin', decode(['X-Spam-Flag: YES', 'X-Spam-Score: 6.2']));
  emit('SpamAssassin', decode(['X-Spam-Flag: NO']));
  for (const k of Object.keys(T.RSPAMD_ACTIONS).concat(['quarantine'])) emit('Rspamd', decode(['X-Rspamd-Action: ' + k]));
  emit('Rspamd', decode(['X-Spamd-Result: default: True [16.20 / 15.00]']));
  emit('Rspamd', decode(['X-Spamd-Result: default: False [2.10 / 15.00]']));
  emit('Rspamd', decode(['X-Spamd-Result: unreadable']));
  return out;
}

function render() {
  let md = '# Sentence inventory\n';
  for (const [name, text] of CASES) {
    md += '\n## ' + name + '\n\n';
    md += lines(run(name, text)).map(([l, s]) => l + ': ' + s).join('\n\n') + '\n';
  }
  md += '\n## Filter code meanings\n\n';
  md += meanings().map(([code, t, p]) => code + '. Technical: ' + t + ' Plain: ' + p).join('\n\n') + '\n';
  return md;
}

const OUT = path.join(__dirname, '..', 'docs', 'sentences.md');
if (require.main === module) fs.writeFileSync(OUT, render());

module.exports = { CASES, run, lines, meanings, render, OUT };
