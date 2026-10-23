// parse.js: turn pasted text into a list of header fields.
// Pure functions, no DOM, no network. Everything downstream reads the
// field list this module returns; nothing downstream re-reads raw text.
(function (root) {
  'use strict';
  const HA = (root.HA = root.HA || {});

  // Header names that mark where a real header block starts. Used to
  // skip the summary table Gmail's "Show original" puts above the
  // headers, mbox "From " lines, and other leading noise.
  const STRONG_ANCHORS = /^(Delivered-To|Return-Path|Received|ARC-Seal|ARC-Message-Signature|ARC-Authentication-Results|Authentication-Results|DKIM-Signature|X-Received|X-Google-Smtp-Source|Received-SPF):/i;
  const FIELD_START = /^([!-9;-~]+):(.*)$/; // RFC 5322 field-name is printable US-ASCII except colon

  function normalizeText(text) {
    return String(text || '')
      .replace(/^﻿/, '')
      .replace(/\r\n?/g, '\n')
      .replace(/ /g, ' ');
  }

  // Find the header block inside whatever was pasted: a bare header
  // list, a full .eml, or a copy of a whole "Show original" page.
  function locateHeaderBlock(lines) {
    let start = -1;
    for (let i = 0; i < lines.length; i++) {
      if (STRONG_ANCHORS.test(lines[i])) { start = i; break; }
    }
    if (start === -1) {
      for (let i = 0; i < lines.length; i++) {
        if (FIELD_START.test(lines[i]) && lines[i].length < 2000) { start = i; break; }
      }
    }
    if (start === -1) return { start: 0, end: 0 };
    // Walk back to the first line of the contiguous block the anchor sits in.
    while (start > 0 && lines[start - 1].trim() !== '' && (FIELD_START.test(lines[start - 1]) || /^[ \t]/.test(lines[start - 1]))) start--;
    let end = lines.length;
    for (let i = start; i < lines.length; i++) {
      if (lines[i].trim() === '') { end = i; break; }
    }
    return { start, end };
  }

  // Build fields. Continuation lines start with WSP (RFC 5322 folding).
  // Pastes from some clients lose the leading whitespace, so a line that
  // cannot be a field start is also treated as a continuation.
  function parseHeaders(text) {
    const lines = normalizeText(text).split('\n');
    const { start, end } = locateHeaderBlock(lines);
    const fields = [];
    const notes = [];
    let current = null;
    for (let i = start; i < end; i++) {
      const line = lines[i];
      const m = FIELD_START.exec(line);
      const isContinuation = /^[ \t]/.test(line) || !m;
      if (isContinuation && current) {
        current.rawLines.push(line);
        if (!/^[ \t]/.test(line)) current.looseFold = true;
        continue;
      }
      if (!m) continue; // garbage before the first field
      current = { name: m[1], rawLines: [line], firstLine: i, looseFold: false };
      fields.push(current);
    }
    for (const f of fields) {
      const first = f.rawLines[0].slice(f.name.length + 1);
      const rest = f.rawLines.slice(1);
      // Unfold: join folded lines with a single space, collapse runs of WSP.
      f.value = [first].concat(rest).map(s => s.replace(/^[ \t]+/, '')).join(' ').replace(/[ \t]+/g, ' ').trim();
      f.raw = f.rawLines.join('\n');
      f.lower = f.name.toLowerCase();
      f.decoded = decodeWords(f.value);
      delete f.rawLines;
      if (f.looseFold) notes.push('Folded lines under ' + f.name + ' had lost their leading whitespace and were rejoined.');
    }
    const bodyPresent = end < lines.length && lines.slice(end + 1).some(l => l.trim() !== '');
    return { fields, notes, headerLineCount: end - start, bodyPresent, blockFound: fields.length > 0 };
  }

  // RFC 2047 encoded words: =?charset?B|Q?text?=
  function decodeWords(value) {
    if (!/=\?[^?]+\?[bBqQ]\?[^?]*\?=/.test(value)) return value;
    // Adjacent encoded words separated only by WSP are joined (RFC 2047 6.2).
    const joined = value.replace(/(\?=)\s+(=\?)/g, '$1$2');
    return joined.replace(/=\?([^?]+)\?([bBqQ])\?([^?]*)\?=/g, (all, charset, enc, text) => {
      try {
        let bytes;
        if (enc.toUpperCase() === 'B') {
          const bin = atobSafe(text);
          bytes = new Uint8Array(bin.length);
          for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
        } else {
          const out = [];
          for (let i = 0; i < text.length; i++) {
            const c = text[i];
            if (c === '_') out.push(0x20);
            else if (c === '=' && /^[0-9A-Fa-f]{2}$/.test(text.substr(i + 1, 2))) { out.push(parseInt(text.substr(i + 1, 2), 16)); i += 2; }
            else out.push(c.charCodeAt(0) & 0xff);
          }
          bytes = new Uint8Array(out);
        }
        const cs = charset.replace(/\*.*$/, '').toLowerCase(); // strip RFC 2231 language tag
        return new TextDecoder(cs === 'us-ascii' ? 'utf-8' : cs).decode(bytes);
      } catch (e) {
        return all;
      }
    });
  }

  function atobSafe(s) {
    s = s.replace(/[^A-Za-z0-9+/=]/g, '');
    if (typeof atob === 'function') return atob(s);
    return Buffer.from(s, 'base64').toString('binary');
  }

  // Strip RFC 5322 comments (nested parentheses) outside quoted strings.
  function stripComments(s) {
    let out = '', depth = 0, inQuote = false;
    for (let i = 0; i < s.length; i++) {
      const c = s[i];
      if (inQuote) {
        if (c === '\\' && i + 1 < s.length) { out += c + s[++i]; continue; }
        if (c === '"') inQuote = false;
        out += c;
        continue;
      }
      if (c === '"' && depth === 0) { inQuote = true; out += c; continue; }
      if (c === '(') { depth++; continue; }
      if (c === ')') { if (depth > 0) depth--; continue; }
      if (depth === 0) out += c;
    }
    return out.replace(/\s+/g, ' ').trim();
  }

  // Return the comments (parenthesised text) in order, outermost only.
  function extractComments(s) {
    const comments = [];
    let depth = 0, buf = '', inQuote = false;
    for (let i = 0; i < s.length; i++) {
      const c = s[i];
      if (inQuote) { if (c === '"') inQuote = false; if (depth > 0) buf += c; continue; }
      if (c === '"' && depth === 0) { inQuote = true; continue; }
      if (c === '(') { if (depth > 0) buf += c; depth++; continue; }
      if (c === ')') { depth--; if (depth === 0) { comments.push(buf.trim()); buf = ''; } else if (depth > 0) buf += c; if (depth < 0) depth = 0; continue; }
      if (depth > 0) buf += c;
    }
    return comments;
  }

  // Addresses in a From, To, Reply-To, Sender or Return-Path value.
  function parseAddresses(value) {
    if (!value) return [];
    const v = decodeWords(value);
    const out = [];
    for (const box of splitMailboxes(v)) {
      const m = /<([^<>]*)>/.exec(box);
      if (m) {
        const display = stripComments(box.slice(0, m.index)).replace(/^"|"$/g, '').trim();
        out.push(mkAddress(m[1].trim(), display));
      } else {
        const b = stripComments(box).trim();
        if (b.includes('@')) out.push(mkAddress(b, ''));
        else if (b === '<>' || b === '') out.push(mkAddress('', ''));
      }
    }
    return out;
  }

  // Split an address list on commas outside quotes, comments and angle brackets.
  function splitMailboxes(v) {
    const boxes = [];
    let buf = '', inQuote = false, depth = 0, inAngle = false;
    for (let i = 0; i < v.length; i++) {
      const c = v[i];
      if (inQuote) { buf += c; if (c === '\\') { buf += v[++i] || ''; continue; } if (c === '"') inQuote = false; continue; }
      if (c === '"') { inQuote = true; buf += c; continue; }
      if (c === '(') depth++; else if (c === ')') depth = Math.max(0, depth - 1);
      if (c === '<') inAngle = true; else if (c === '>') inAngle = false;
      if (c === ',' && depth === 0 && !inAngle) { boxes.push(buf); buf = ''; continue; }
      buf += c;
    }
    boxes.push(buf);
    return boxes.map(s => s.trim()).filter(s => s !== '' || boxes.length === 1);
  }

  function mkAddress(addr, display) {
    addr = addr.replace(/^mailto:/i, '');
    const at = addr.lastIndexOf('@');
    const domain = at >= 0 ? addr.slice(at + 1).replace(/^\[|\]$/g, '').toLowerCase() : '';
    return { address: addr, display: display || '', domain, local: at >= 0 ? addr.slice(0, at) : addr, empty: addr === '' };
  }

  function domainOf(addrOrDomain) {
    if (!addrOrDomain) return '';
    const s = String(addrOrDomain).trim().replace(/^<|>$/g, '');
    const at = s.lastIndexOf('@');
    return (at >= 0 ? s.slice(at + 1) : s).toLowerCase().replace(/\.$/, '');
  }

  // RFC 5322 date-time, with the obsolete forms that still show up in
  // Received lines. Returns {date: Date|null, tzKnown, text}.
  const ZONES = { UT: 0, UTC: 0, GMT: 0, Z: 0, EST: -300, EDT: -240, CST: -360, CDT: -300, MST: -420, MDT: -360, PST: -480, PDT: -420,
    CET: 60, CEST: 120, BST: 60, IST: 330, JST: 540, AEST: 600, AEDT: 660 };
  const MONTHS = { jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5, jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11 };
  function parseDate(text) {
    const result = { date: null, tzKnown: true, text: (text || '').trim() };
    if (!text) return result;
    const s = stripComments(text).replace(/^(Mon|Tue|Wed|Thu|Fri|Sat|Sun)[a-z]*,?\s*/i, '');
    const m = /^(\d{1,2})\s+([A-Za-z]{3})[a-z]*\.?\s+(\d{2,4})\s+(\d{1,2}):(\d{2})(?::(\d{2}))?\s*([+-]\d{4}|[A-Za-z]{1,5})?/.exec(s);
    if (!m) {
      const d = new Date(s);
      if (!isNaN(d.getTime())) result.date = d; else result.tzKnown = false;
      return result;
    }
    let year = parseInt(m[3], 10);
    if (m[3].length === 2) year += year < 50 ? 2000 : 1900;
    const mon = MONTHS[m[2].toLowerCase()];
    if (mon === undefined) return result;
    let offsetMin = 0;
    const z = m[7];
    if (!z) { result.tzKnown = false; }
    else if (/^[+-]\d{4}$/.test(z)) {
      const sign = z[0] === '-' ? -1 : 1;
      offsetMin = sign * (parseInt(z.slice(1, 3), 10) * 60 + parseInt(z.slice(3, 5), 10));
      if (z === '-0000') result.tzKnown = false; // RFC 5322 3.3: -0000 means no zone information
    } else if (ZONES[z.toUpperCase()] !== undefined) {
      offsetMin = ZONES[z.toUpperCase()];
    } else { result.tzKnown = false; }
    const utc = Date.UTC(year, mon, parseInt(m[1], 10), parseInt(m[4], 10), parseInt(m[5], 10), m[6] ? parseInt(m[6], 10) : 0);
    result.date = new Date(utc - offsetMin * 60000);
    return result;
  }

  // Tag=value lists used by DKIM-Signature, ARC-*, DMARC and BIMI records.
  function parseTagList(value) {
    const tags = {};
    const order = [];
    for (const part of String(value || '').split(';')) {
      const i = part.indexOf('=');
      if (i < 0) continue;
      const k = part.slice(0, i).trim();
      const v = part.slice(i + 1).trim().replace(/\s+/g, '');
      if (!k) continue;
      if (!(k in tags)) order.push(k);
      tags[k] = v;
    }
    return { tags, order };
  }

  HA.parse = { parseHeaders, decodeWords, stripComments, extractComments, parseAddresses, parseDate, parseTagList, domainOf, normalizeText };
})(typeof globalThis !== 'undefined' ? globalThis : this);
