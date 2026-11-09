'use strict';
// The usage notes carry fixed fields only, never header text, addresses or
// domains (CLAUDE.md). The functions are cut from ui/app.js and run with
// stubbed globals, so the test checks what the page really posts.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const src = fs.readFileSync(path.join(__dirname, '..', 'ui', 'app.js'), 'utf8');
const cut = (name) => {
  const m = new RegExp('function ' + name + '\\([^)]*\\) \\{[\\s\\S]*?\\n  \\}\\n').exec(src);
  assert.ok(m, name + '() not found');
  return m[0];
};

function posted(referrer, script) {
  const out = [];
  const fetch = (url, opts) => { out.push({ url, body: JSON.parse(opts.body) }); return Promise.resolve(); };
  const document = { referrer }, location = { hostname: 'headers.dns-audit.com' };
  const R = { finding: { status: 'fail', sentence: 'alice@client-example.com failed' } };
  const sample = '';
  // eval is intended: it runs functions cut from this repository's own app.js
  eval(cut('referrerHost') + cut('send') + 'let noted = null;' + cut('note') + script);
  void fetch; void document; void location; void R; void sample;
  return out;
}

test('a visit note is sent once on load with the tool and linking host only', () => {
  const visit = /\n  send\(\{ tool: 'header-decoder', visit: true[^\n]*\n/.exec(src);
  assert.ok(visit, 'visit note not found');
  assert.equal(src.split("visit: true").length - 1, 1);
  const out = posted('https://www.linkedin.com/feed/?x=1', visit[0]);
  assert.deepEqual(out, [{ url: 'https://dns-audit.com/api/usage',
    body: { tool: 'header-decoder', visit: true, ref: 'www.linkedin.com' } }]);
});

test('a link from the page itself is not a source', () => {
  const out = posted('https://headers.dns-audit.com/', "send({ tool: 'header-decoder', visit: true, ref: referrerHost() });");
  assert.deepEqual(out[0].body, { tool: 'header-decoder', visit: true });
});

test('a use note holds exactly tool, status, sample and ref, once per read', () => {
  const out = posted('https://dns-audit.com/', "note('a'); note('a');");
  assert.equal(out.length, 1);
  assert.deepEqual(out[0].body, { tool: 'header-decoder', status: 'fail', sample: false, ref: 'dns-audit.com' });
  assert.doesNotMatch(JSON.stringify(out), /client-example/);
});
