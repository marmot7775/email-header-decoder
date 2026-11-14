'use strict';
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const S = require('../scripts/sentences.js');
const { SIMPLE_BANNED } = require('./simple-words.js');
const { HA } = require('./load.js');

// A hyphen with space on both sides, or an en or em dash anywhere.
const DASH = /[–—]|\s-+\s/;

function check(where, s) {
  assert.ok(!DASH.test(s), where + ' uses a dash as punctuation: ' + s);
  assert.ok(!/verdict/i.test(s), where + ' uses the word verdict: ' + s);
  assert.ok(!/ {2}/.test(s), where + ' has a double space: ' + s);
}

test('sentences: every case runs, and no sentence breaks the copy rules', () => {
  for (const [name, text, keyCheck] of S.CASES) {
    let f;
    assert.doesNotThrow(() => { f = S.run(name, text, keyCheck); }, name + ' threw');
    for (const [label, s] of S.lines(f)) {
      check(name + ', ' + label, s);
      if (/plain/i.test(label)) assert.ok(!/;/.test(s), name + ', ' + label + ' has a semicolon: ' + s);
      if (/plain/i.test(label)) assert.ok(!SIMPLE_BANNED.test(s.replace(/Trusted ARC sealers/g, '').replace(/\([^)]*\)/g, '')), name + ', ' + label + ' uses a word Simple avoids: ' + s);
    }
  }
  for (const [k, v] of Object.entries(HA.finding.SIGNAL_UI)) { check('question ' + k, v); assert.ok(!SIMPLE_BANNED.test(v), 'question ' + k + ' uses a word Simple avoids: ' + v); }
  for (const [k, v] of Object.entries(HA.finding.KEY_UI)) { check('label ' + k, v); assert.ok(!/;/.test(v) && !SIMPLE_BANNED.test(v.replace(/\([^)]*\)/g, '')), 'label ' + k + ' uses a word Simple avoids: ' + v); }
  for (const [code, t, p] of S.meanings()) { check(code, t); check(code, p); assert.ok(!SIMPLE_BANNED.test(p.replace(/Trusted ARC sealers/g, '').replace(/\([^)]*\)/g, '')), code + ' Simple uses a word Simple avoids: ' + p); }
});

// A case may repeat a cause when it is there for a limit the other lacks,
// as the DKIM pass nothing backs is (issue 14).
test('sentences: no two cases share a cause and its limits', () => {
  const seen = new Map();
  for (const [name, text, check] of S.CASES) {
    const f = S.run(name, text, check);
    const c = f.cause;
    // A signature check case is there for what the check found.
    const kc = f.keyCheck ? f.keyCheck.results.flatMap(x => [x.line].concat(x.notes)) : [];
    const sg = f.signals ? f.signals.sender.items.concat(f.signals.spam.items, [f.signals.spam.answer]) : [];
    const key = [c].concat(f.limits, kc, sg).map(s => s.technical + '\n' + s.plain).join('\n');
    assert.ok(!seen.has(key), name + ' and ' + seen.get(key) + ' produce the same cause: ' + c.technical);
    seen.set(key, name);
  }
});

test('sentences: docs/sentences.md is current (run npm run sentences)', () => {
  assert.strictEqual(fs.readFileSync(S.OUT, 'utf8'), S.render());
});
