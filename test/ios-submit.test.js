'use strict';
// An iPhone user pasted headers and found no way to run the analysis
// (2026-11-03). Three causes, each pinned here:
// - Regex lookbehind, which Safari parses only from iOS 16.4. On older
//   iOS the whole page script failed to parse, so the button, the paste
//   listener, and Cmd+Enter all did nothing.
// - The button said Decode, which did not read as the control to press.
// - The paste box used a 13px font, so iOS zoomed in on focus and the
//   page sat zoomed after the paste.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');
const { HA } = require('./load.js');
const { SRC } = require('../build.js');

const ROOT = path.join(__dirname, '..');
const page = fs.readFileSync(path.join(ROOT, 'ui', 'page.html'), 'utf8');

test('no shipped script uses regex lookbehind, which iOS Safari before 16.4 cannot parse', () => {
  const files = SRC.map(f => path.join('src', f)).concat([path.join('ui', 'app.js')]);
  for (const f of files) {
    const text = fs.readFileSync(path.join(ROOT, f), 'utf8');
    assert.ok(!/\(\?<[=!]/.test(text), f + ' uses regex lookbehind');
  }
});

test('the Analyze headers button sits right after the paste box and runs on a tap', () => {
  const m = /<textarea id="headers"[^>]*><\/textarea>\s*<div class="actions">\s*(<button[^>]*>[^<]*<\/button>)/.exec(page);
  assert.ok(m, 'the first control after the paste box is a button');
  assert.match(m[1], /id="go"/);
  assert.match(m[1], /type="button"/);
  assert.match(m[1], />Analyze headers</);
});

test('on a phone the button takes its own full width row and the paste box does not trigger zoom', () => {
  const rule = /@media \(max-width: 640px\)\s*\{\s*textarea \{ font-size: 16px; \}\s*\.actions #go \{ flex: 1 1 100%; \}\s*\}/;
  assert.match(page, rule);
  assert.match(page, /\.btn \{[^}]*min-height: 44px;[^}]*touch-action: manipulation;/);
});

test('properties are read the same without lookbehind', () => {
  const ar = HA.auth.parseAuthResults('mx.example.net; dkim=pass header.d=example.com header.s="s1"x.y=2 policy.dkim-rules=none; spf=pass smtp.mailfrom=bounce.example.com');
  const dkim = ar.results.find(r => r.method === 'dkim');
  assert.equal(dkim.props['header.d'], 'example.com');
  assert.equal(dkim.props['header.s'], 's1');
  // A name right after a closing quote still starts a property.
  assert.equal(dkim.props['x.y'], '2');
  assert.equal(dkim.policy['dkim-rules'], 'none');
  assert.equal(ar.results.find(r => r.method === 'spf').props['smtp.mailfrom'], 'bounce.example.com');
  // A name never starts in the middle of a run: abc.def.ghi=1 reads as def.ghi.
  const r2 = HA.auth.parseAuthResults('mx.example.net; spf=pass abc.def.ghi=1');
  assert.deepEqual(Object.keys(r2.results[0].props), ['def.ghi']);
});

test('Proofpoint key=value pairs are read the same without lookbehind', () => {
  const text = 'Received: from mx.example.net by mx.example.org; Mon, 2 Nov 2026 10:00:00 +0000\n' +
    'X-Proofpoint-Spam-Details: rule=notspam policy=default score=0 xrule=1 spamscore=0\n' +
    'From: a@example.com\nTo: b@example.org\nSubject: hi\nDate: Mon, 2 Nov 2026 10:00:00 +0000\n';
  const pp = HA.analyze(text).decoded.filters.find(g => g.id === 'proofpoint');
  assert.ok(pp, 'Proofpoint group present');
  const rule = pp.items.find(i => i.key === 'rule');
  assert.equal(rule.raw, 'notspam');
  assert.equal(rule.level, 'pass');
  assert.equal(pp.items.find(i => i.key === 'spamscore').raw, '0');
});
