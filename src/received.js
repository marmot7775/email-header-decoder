// received.js: Received headers into a chronological hop list with delays.
// Received fields appear newest first; the chain here runs oldest first.
(function (root) {
  'use strict';
  const HA = (root.HA = root.HA || {});
  const P = HA.parse;

  const IPV4 = /\b(\d{1,3}(?:\.\d{1,3}){3})\b/;
  const IPV6 = /\[?(?:IPv6:)?([0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7})\]?/i;

  function findIp(text) {
    if (!text) return '';
    const m4 = IPV4.exec(text);
    if (m4) return m4[1];
    const m6 = IPV6.exec(text);
    if (m6 && m6[1].includes(':')) return m6[1];
    return '';
  }

  function isPrivateIp(ip) {
    if (!ip) return false;
    if (/^10\./.test(ip) || /^192\.168\./.test(ip) || /^127\./.test(ip) || /^169\.254\./.test(ip)) return true;
    const m = /^172\.(\d+)\./.exec(ip);
    if (m && +m[1] >= 16 && +m[1] <= 31) return true;
    if (/^(::1|fe80:|fc|fd)/i.test(ip)) return true;
    return false;
  }

  // Split one Received value into its clauses. The date follows the last
  // semicolon (RFC 5321 4.4). Clause keywords are matched outside comments.
  function parseReceived(value) {
    const hop = { raw: value, from: '', fromHost: '', fromIp: '', fromComment: '', by: '', with: '', id: '', via: '', for: '', date: null, tzKnown: true, dateText: '', tls: null, tlsVersion: '', tlsCipher: '', internal: false };
    const semi = value.lastIndexOf(';');
    let clause = value, dateText = '';
    if (semi >= 0) { clause = value.slice(0, semi); dateText = value.slice(semi + 1); }
    const d = P.parseDate(dateText);
    hop.date = d.date; hop.tzKnown = d.tzKnown; hop.dateText = d.text;

    // Walk the clause, tracking comment depth so "by" inside (...) is ignored.
    const KEYS = ['from', 'by', 'with', 'id', 'via', 'for'];
    const segs = [];
    let depth = 0, cur = { key: null, text: '' }, i = 0;
    while (i < clause.length) {
      const c = clause[i];
      if (c === '(') depth++;
      else if (c === ')') depth = Math.max(0, depth - 1);
      if (depth === 0 && (i === 0 || /\s/.test(clause[i - 1]))) {
        let matched = null;
        for (const k of KEYS) {
          if (clause.substr(i, k.length).toLowerCase() === k && /\s/.test(clause[i + k.length] || ' ')) { matched = k; break; }
        }
        if (matched && !(matched === cur.key && cur.text.trim() === '')) {
          if (cur.key || cur.text.trim()) segs.push(cur);
          cur = { key: matched, text: '' };
          i += matched.length;
          continue;
        }
      }
      cur.text += c;
      i++;
    }
    if (cur.key || cur.text.trim()) segs.push(cur);
    for (const s of segs) {
      const t = s.text.trim();
      if (!s.key) continue;
      if (!hop[s.key]) hop[s.key] = t; else hop[s.key] += ' ' + t;
    }
    hop.fromHost = P.stripComments(hop.from).split(/\s/)[0] || '';
    const comments = P.extractComments(hop.from);
    hop.fromComment = comments.join(' ');
    hop.fromIp = findIp(hop.fromComment) || findIp(hop.fromHost) || '';
    hop.byHost = P.stripComments(hop.by).split(/\s/)[0] || '';
    hop.forAddress = P.stripComments(hop.for).replace(/^<|>$/g, '');
    const withText = P.stripComments(hop.with);
    hop.protocol = /^Microsoft SMTP/i.test(withText) ? 'Microsoft SMTP' : (withText.split(/\s/)[0] || '');

    // TLS evidence: ESMTPS/ESMTPSA protocols, or version=/using TLS in text.
    const all = value;
    const ver = /(?:version=|using\s+)(TLS\s?v?[0-9._]+|SSLv[0-9.]+)/i.exec(all);
    const cipher = /cipher[=\s]+([A-Z0-9_-]+)/i.exec(all);
    if (ver) { hop.tls = true; hop.tlsVersion = ver[1].replace(/_/g, '.').replace(/TLS\s?v?/i, 'TLS '); }
    if (cipher) hop.tlsCipher = cipher[1];
    if (hop.tls === null && /^E?SMTPSA?$/i.test(hop.protocol)) hop.tls = /S/i.test(hop.protocol.slice(-2));
    if (/\bESMTPSA\b|\bauthenticated\b|\(Authenticated sender/i.test(all)) hop.authenticated = true;
    if (hop.tls === null && /^(HTTP|HTTPS|local|LMTP)$/i.test(hop.protocol)) hop.tls = /HTTPS/i.test(hop.protocol);
    // Internal relays: Exchange mapi/Frontend Transport, localhost, private IPs.
    if (/\bmapi\b|Mailbox Transport|\bwith HTTPS?\b/i.test(all) || isPrivateIp(hop.fromIp) || /^(localhost|127\.0\.0\.1)$/i.test(hop.fromHost)) hop.internal = true;
    // A hop between two hosts of the same operator is an internal relay.
    if (hop.fromHost && hop.byHost && hop.fromHost.includes('.') && hop.byHost.includes('.') && HA.psl.orgDomain(hop.fromHost) === HA.psl.orgDomain(hop.byHost)) hop.internal = true;
    return hop;
  }

  function buildChain(fields) {
    const received = fields.filter(f => f.lower === 'received').map(f => parseReceived(f.value));
    const hops = received.slice().reverse(); // oldest first
    let prev = null, slowest = -1, slowestIdx = -1, skew = false;
    for (let i = 0; i < hops.length; i++) {
      const h = hops[i];
      h.index = i + 1;
      h.delaySec = null;
      if (h.date && prev && prev.date) {
        h.delaySec = Math.round((h.date - prev.date) / 1000);
        if (h.delaySec < 0) skew = true;
        if (h.delaySec > slowest) { slowest = h.delaySec; slowestIdx = i; }
      }
      if (h.date) prev = h;
    }
    const dated = hops.filter(h => h.date);
    const totalSec = dated.length >= 2 ? Math.round((dated[dated.length - 1].date - dated[0].date) / 1000) : null;
    const origin = hops.find(h => h.fromIp && !isPrivateIp(h.fromIp)) || hops[0] || null;
    return { hops, totalSec, slowestIdx, slowestSec: slowest > 0 ? slowest : 0, clockSkew: skew, originIp: origin ? origin.fromIp : '', originHost: origin ? origin.fromHost : '', count: hops.length };
  }

  HA.received = { parseReceived, buildChain, findIp, isPrivateIp };
})(typeof globalThis !== 'undefined' ? globalThis : this);
