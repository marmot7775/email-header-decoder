'use strict';
// The header and footer are dns-audit's canonical chrome
// (docs/site-chrome.html in that repo). These lists are that copy, with the
// three repo links pointing here. Change the chrome there first.
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const page = fs.readFileSync(path.join(__dirname, '..', 'ui', 'page.html'), 'utf8');
const REPO = 'https://github.com/marmot7775/email-header-decoder';

const NAV = [
  ['DNS Audit', 'https://dns-audit.com/'],
  ['Header Decoder', 'https://headers.dns-audit.com/'],
  ['APRF Reader', 'https://aprf.dns-audit.com/'],
  ['Articles', 'https://dns-audit.com/articles/'],
  ['About', 'https://dns-audit.com/about'],
];
const FOOTER = [
  ['Articles', 'https://dns-audit.com/articles/'],
  ['About', 'https://dns-audit.com/about'],
  ['Privacy', 'https://dns-audit.com/privacy'],
  ['GitHub', REPO],
  ['Email dns@dns-audit.com', 'mailto:dns@dns-audit.com'],
  ['message me on LinkedIn', 'https://www.linkedin.com/in/neilanuskiewicz/'],
  ['Security policy', REPO + '/security/policy'],
  ['MIT License', REPO + '/blob/main/LICENSE'],
];

const block = (re) => (re.exec(page) || [])[0] || '';
const firstNav = block(/<nav\b[\s\S]*?<\/nav>/);
const footer = block(/<footer\b[\s\S]*?<\/footer>/);
const anchors = (html) => [...html.matchAll(/<a\b([^>]*)>([\s\S]*?)<\/a>/g)];
// The tool links carry a long and a short label; the long one is the name.
const label = (inner) => ((/<span class="nav-long">([\s\S]*?)<\/span>/.exec(inner) || [])[1] || inner).replace(/<[^>]+>/g, '').replace(/\s+/g, ' ').trim();
const pairs = (html) => anchors(html).map(([, attrs, inner]) => [label(inner), (/\bhref="([^"]*)"/.exec(attrs) || [])[1]]);

test('chrome: the header nav is the canonical list', () => {
  assert.deepEqual(pairs(firstNav), NAV);
});

test('chrome: the footer is the canonical list, with the repo links pointing here', () => {
  assert.deepEqual(pairs(footer), FOOTER);
});

test('chrome: only the Header Decoder link is marked current', () => {
  const marked = anchors(firstNav).filter(([, attrs]) => /aria-current=/.test(attrs) || /\bnav-link-active\b/.test(attrs));
  assert.equal(marked.length, 1);
  const attrs = marked[0][1];
  assert.match(attrs, /aria-current="page"/);
  assert.match(attrs, /class="[^"]*\bnav-link-active\b/);
  assert.equal(label(marked[0][2]), 'Header Decoder');
});
