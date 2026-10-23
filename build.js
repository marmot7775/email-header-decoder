#!/usr/bin/env node
// build.js: concatenate src and ui into one self-contained page.
// dist/index.html is the artifact form (no doctype; the host wraps it).
// dist/standalone.html is a full document to host anywhere.
'use strict';
const fs = require('fs');
const path = require('path');

const ROOT = __dirname;
// Load order matters: each module reads the HA namespace the one before it filled.
const SRC = ['parse.js', 'psl.js', 'received.js', 'analyze.js'];
// Fixtures shown as samples on the page. Synthetic only; never real headers.
const SAMPLES = { gmail: 'gmail-show-original.txt', exchange: 'exchange-online-inbound.txt', forwarded: 'forwarded.txt' };

function read(p) { return fs.readFileSync(path.join(ROOT, p), 'utf8'); }

function build() {
  const page = read('ui/page.html');
  const samples = {};
  for (const [k, f] of Object.entries(SAMPLES)) samples[k] = read('test/fixtures/' + f);
  const js = SRC.map(f => read('src/' + f)).join('\n') + '\n' +
    'window.SAMPLES = ' + JSON.stringify(samples).replace(/</g, '\\u003c') + ';\n' +
    read('ui/app.js');
  if (js.includes('</script')) throw new Error('script text contains </script');
  const body = page.replace('<!-- SCRIPTS -->', '<script>\n' + js + '\n</script>');
  fs.mkdirSync(path.join(ROOT, 'dist'), { recursive: true });
  fs.writeFileSync(path.join(ROOT, 'dist/index.html'), body);
  const standalone = '<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n' +
    '<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">\n</head>\n<body>\n' + body + '\n</body>\n</html>\n';
  fs.writeFileSync(path.join(ROOT, 'dist/standalone.html'), standalone);
  return { bytes: Buffer.byteLength(body) };
}

if (require.main === module) {
  const r = build();
  console.log('dist/index.html and dist/standalone.html written, ' + r.bytes + ' bytes');
}
module.exports = { build, SRC };
