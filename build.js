#!/usr/bin/env node
// build.js: inline src and ui into self-contained pages.
// dist/index.html is a full document that opens from disk with the
// network off. Its Content-Security-Policy has no connect-src, so the
// browser blocks any attempt to send pasted headers anywhere.
// dist/artifact.html is the same body without the document shell, for
// hosts that wrap the page themselves (the claude.ai preview).
'use strict';
const fs = require('fs');
const path = require('path');

const ROOT = __dirname;
// Load order matters: each module reads the HA namespace the one before it filled.
const SRC = ['parse.js', 'psl.js', 'received.js', 'auth.js', 'analyze.js'];
// Fixtures shown as samples on the page. Synthetic only; never real headers.
const SAMPLES = { gmail: 'gmail-show-original.txt', exchange: 'exchange-online-inbound.txt', forwarded: 'forwarded.txt', arc: 'arc-forwarded-i2.txt', twodkim: 'two-dkim.txt', relaxed: 'subdomain-relaxed.txt' };
const CSP = "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src data:; form-action 'none'; base-uri 'none'";

function read(p) { return fs.readFileSync(path.join(ROOT, p), 'utf8'); }

function build() {
  const page = read('ui/page.html');
  const samples = {};
  for (const [k, f] of Object.entries(SAMPLES)) samples[k] = read('test/fixtures/' + f);
  const js = SRC.map(f => read('src/' + f)).join('\n') + '\n' +
    'window.SAMPLES = ' + JSON.stringify(samples).replace(/</g, '\\u003c') + ';\n' +
    read('ui/app.js');
  if (js.includes('</script')) throw new Error('script text contains </script');
  if (/https?:\/\/(?!datatracker|www\.rfc-editor)/.test(page)) throw new Error('ui/page.html references an external URL');
  const body = page.replace('<!-- SCRIPTS -->', '<script>\n' + js + '\n</script>');
  fs.mkdirSync(path.join(ROOT, 'dist'), { recursive: true });
  fs.writeFileSync(path.join(ROOT, 'dist/artifact.html'), body);
  const full = '<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n' +
    '<meta http-equiv="Content-Security-Policy" content="' + CSP + '">\n' +
    '<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">\n</head>\n<body>\n' + body + '\n</body>\n</html>\n';
  fs.writeFileSync(path.join(ROOT, 'dist/index.html'), full);
  const old = path.join(ROOT, 'dist/standalone.html');
  if (fs.existsSync(old)) fs.unlinkSync(old);
  return { bytes: Buffer.byteLength(full) };
}

if (require.main === module) {
  const r = build();
  console.log('dist/index.html (' + r.bytes + ' bytes, CSP, opens from disk) and dist/artifact.html written');
}
module.exports = { build, SRC, CSP };
