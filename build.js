#!/usr/bin/env node
// build.js: inline src and ui into self-contained pages.
// dist/index.html is a full document that opens from disk with the
// network off. Its Content-Security-Policy has no connect-src, so the
// browser blocks requests the page makes, and script-src allows only the
// hash of the one inline script.
// dist/artifact.html is the same body without the document shell, for
// hosts that wrap the page themselves (the claude.ai preview).
// The rest of dist is what the static host serves beside the page:
// robots.txt, sitemap.xml, _headers, and the share card.
'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ROOT = __dirname;
const SITE = 'https://headers.dns-audit.com/';
// Load order matters: each module reads the HA namespace the one before it filled.
const SRC = ['parse.js', 'psl.js', 'received.js', 'auth.js', 'providers.js', 'finding.js', 'analyze.js'];
// Fixtures shown as samples on the page. Synthetic only; never real headers.
const SAMPLES = { gmail: 'gmail-show-original.txt', esp: 'esp-unaligned.txt', forwarded: 'forwarded.txt', exchange: 'exchange-online-inbound.txt', arc: 'arc-forwarded-i2.txt', twodkim: 'two-dkim.txt' };
// script-src names the sha256 of the inline script, so no other script runs.
const cspFor = (script) => "default-src 'none'; script-src 'sha256-" + crypto.createHash('sha256').update(script, 'utf8').digest('base64') + "'; style-src 'unsafe-inline'; img-src data:; form-action 'none'; base-uri 'none'";
// Links the page may carry. A link sends nothing until someone follows it;
// the CSP still blocks every request the page itself could make.
const LINKS = /https?:\/\/(?!datatracker\.ietf\.org|www\.rfc-editor\.org|dns-audit\.com|www\.linkedin\.com\/in\/neilanuskiewicz|github\.com\/marmot7775)/;

const TITLE = 'Email Header Decoder: why SPF, DKIM, or DMARC failed';
const DESCRIPTION = 'This free email header analyzer runs in your browser and sends nothing. It shows in one sentence why a message passed or failed SPF, DKIM, and DMARC, and what to fix.';
const ICON = "data:image/svg+xml," + encodeURIComponent('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="7" fill="#2f5fcc"/><path d="M7 10h18v12H7z" fill="none" stroke="#fff" stroke-width="2.2" stroke-linejoin="round"/><path d="m7 10 9 7 9-7" fill="none" stroke="#fff" stroke-width="2.2" stroke-linejoin="round"/></svg>');

function read(p) { return fs.readFileSync(path.join(ROOT, p), 'utf8'); }
const attr = (s) => String(s).replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;');
const text = (html) => html.replace(/<[^>]+>/g, '').replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&amp;/g, '&').replace(/\s+/g, ' ').trim();

// The FAQ structured data is read from the page's own FAQ, so the two
// cannot drift apart.
function faqFrom(page) {
  const block = (/<div class="faq">([\s\S]*?)<\/div>/.exec(page) || [])[1] || '';
  const out = [];
  const re = /<details><summary>([\s\S]*?)<\/summary><p>([\s\S]*?)<\/p><\/details>/g;
  let m;
  while ((m = re.exec(block))) out.push({ '@type': 'Question', name: text(m[1]), acceptedAnswer: { '@type': 'Answer', text: text(m[2]) } });
  return out;
}

function jsonLd(page) {
  const graph = [
    {
      '@type': 'WebApplication',
      '@id': SITE + '#app',
      name: 'Email Header Decoder',
      alternateName: 'Email header analyzer',
      url: SITE,
      description: DESCRIPTION,
      applicationCategory: 'SecurityApplication',
      operatingSystem: 'Web',
      browserRequirements: 'Requires JavaScript. Runs entirely in the browser.',
      isAccessibleForFree: true,
      offers: { '@type': 'Offer', price: '0', priceCurrency: 'USD' },
      featureList: [
        'SPF, DKIM, and DMARC results with alignment against the From domain',
        'DMARC result computed independently beside the receiver\'s',
        'Forwarded mail read through the ARC chain',
        'Hop timeline with delays, TLS, and the receiver custody point',
        'Spam filter headers decoded for Microsoft 365, Google, Proofpoint, Mimecast, Cisco, Barracuda, SpamAssassin, and Rspamd',
        'No network requests: pasted headers never leave the browser',
      ],
      author: { '@id': 'https://dns-audit.com/about#neil' },
      isPartOf: { '@type': 'WebSite', name: 'dns-audit.com', url: 'https://dns-audit.com/' },
    },
    {
      '@type': 'Person',
      '@id': 'https://dns-audit.com/about#neil',
      name: 'Neil Anuskiewicz',
      jobTitle: 'Email Deliverability and DNS Consultant',
      url: 'https://dns-audit.com/about',
      sameAs: ['https://www.linkedin.com/in/neilanuskiewicz/', 'https://github.com/marmot7775'],
    },
  ];
  const faq = faqFrom(page);
  if (faq.length) graph.push({ '@type': 'FAQPage', '@id': SITE + '#faq', mainEntity: faq });
  return JSON.stringify({ '@context': 'https://schema.org', '@graph': graph }, null, 2).replace(/</g, '\\u003c');
}

function head(page, csp) {
  return [
    '<meta charset="utf-8">',
    '<meta http-equiv="Content-Security-Policy" content="' + csp + '">',
    '<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">',
    '<title>' + attr(TITLE) + '</title>',
    '<meta name="description" content="' + attr(DESCRIPTION) + '">',
    '<link rel="canonical" href="' + SITE + '">',
    '<link rel="icon" href="' + attr(ICON) + '">',
    '<meta name="theme-color" content="#0b1220" media="(prefers-color-scheme: dark)">',
    '<meta name="theme-color" content="#f4f6f9" media="(prefers-color-scheme: light)">',
    '<meta property="og:type" content="website">',
    '<meta property="og:site_name" content="dns-audit.com">',
    '<meta property="og:url" content="' + SITE + '">',
    '<meta property="og:title" content="' + attr(TITLE) + '">',
    '<meta property="og:description" content="' + attr(DESCRIPTION) + '">',
    '<meta property="og:image" content="' + SITE + 'og-card.png">',
    '<meta property="og:image:width" content="1200">',
    '<meta property="og:image:height" content="630">',
    '<meta property="og:image:alt" content="Email Header Decoder: one sentence on why a message failed, and the fix">',
    '<meta name="twitter:card" content="summary_large_image">',
    '<script type="application/ld+json">\n' + jsonLd(page) + '\n</script>',
  ].join('\n');
}

// What the static host serves beside the page. The CSP goes out as a real
// header too, where frame-ancestors works; the meta copy keeps the page
// safe when it is opened from disk.
const headers = (csp) => '/*\n  Content-Security-Policy: ' + csp + "; frame-ancestors 'none'\n  X-Content-Type-Options: nosniff\n  Referrer-Policy: strict-origin-when-cross-origin\n  Permissions-Policy: camera=(), microphone=(), geolocation=()\n";
const ROBOTS = 'User-agent: *\nAllow: /\n\nSitemap: ' + SITE + 'sitemap.xml\n';
const sitemap = (day) => '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n  <url><loc>' + SITE + '</loc><lastmod>' + day + '</lastmod></url>\n</urlset>\n';

function build() {
  const page = read('ui/page.html');
  if (LINKS.test(page)) throw new Error('ui/page.html references an external URL outside the allowed links');
  const samples = {};
  for (const [k, f] of Object.entries(SAMPLES)) samples[k] = read('test/fixtures/' + f);
  const js = SRC.map(f => read('src/' + f)).join('\n') + '\n' +
    'window.SAMPLES = ' + JSON.stringify(samples).replace(/</g, '\\u003c') + ';\n' +
    read('ui/app.js');
  if (js.includes('</script')) throw new Error('script text contains </script');
  const script = '\n' + js + '\n';
  const csp = cspFor(script);
  const body = page.replace('<!-- SCRIPTS -->', () => '<script>' + script + '</script>');
  const dist = path.join(ROOT, 'dist');
  fs.mkdirSync(dist, { recursive: true });
  fs.writeFileSync(path.join(dist, 'artifact.html'), body);
  // The full document takes the title and preview meta out of the body
  // and puts a real head in front.
  const inner = body.replace(/^<title>[^<]*<\/title>\n/, '').replace(/^<meta name="claude:[^>]*>\n/m, '');
  const full = '<!doctype html>\n<html lang="en">\n<head>\n' + head(page, csp) + '\n</head>\n<body>\n' + inner + '\n</body>\n</html>\n';
  fs.writeFileSync(path.join(dist, 'index.html'), full);
  fs.writeFileSync(path.join(dist, '_headers'), headers(csp));
  fs.writeFileSync(path.join(dist, 'robots.txt'), ROBOTS);
  // artifact.html is for the claude.ai preview, not the public site.
  fs.writeFileSync(path.join(dist, '.assetsignore'), 'artifact.html\n');
  fs.writeFileSync(path.join(dist, 'sitemap.xml'), sitemap(new Date().toISOString().slice(0, 10)));
  const card = path.join(ROOT, 'ui/og-card.png');
  if (fs.existsSync(card)) fs.copyFileSync(card, path.join(dist, 'og-card.png'));
  const old = path.join(dist, 'standalone.html');
  if (fs.existsSync(old)) fs.unlinkSync(old);
  return { bytes: Buffer.byteLength(full), csp };
}

if (require.main === module) {
  const r = build();
  console.log('dist/index.html (' + r.bytes + ' bytes, CSP, opens from disk), dist/artifact.html, and the host files written');
}
module.exports = { build, SRC, cspFor, faqFrom };
