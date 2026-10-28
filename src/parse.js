// parse.js: turn pasted text into a list of header fields.
// Pure functions, no DOM, no network. Everything downstream reads the
// field list this module returns; nothing downstream re-reads raw text.
(function (root) {
  'use strict';
  const HA = (root.HA = root.HA || {});

  // Header names that mark where a real header block starts. Used to
  // skip the summary table Gmail's "Show original" puts above the
  // headers, Outlook's version banner, mbox "From " lines, and other
  // leading noise.
  const STRONG_ANCHORS = /^(Delivered-To|Return-Path|Received|ARC-Seal|ARC-Message-Signature|ARC-Authentication-Results|Authentication-Results|DKIM-Signature|X-Received|X-Google-Smtp-Source|Received-SPF):/i;
  const FIELD_START = /^([!-9;-~]+):(.*)$/; // RFC 5322 field-name is printable US-ASCII except colon
  // Names real mail uses. RFC 5322 allows more, but a "name" such as
  // 16, 2603 or h=from is a folded line that lost its indentation.
  const PLAUSIBLE_NAME = /^[A-Za-z][A-Za-z0-9_-]*$/;
  // Fields that can start a header block on their own when no strong anchor is present.
  const KNOWN = new Set(['from', 'to', 'cc', 'bcc', 'subject', 'date', 'message-id', 'mime-version', 'content-type', 'content-transfer-encoding',
    'reply-to', 'sender', 'in-reply-to', 'references', 'return-path', 'received', 'delivered-to', 'authentication-results', 'dkim-signature',
    'received-spf', 'list-unsubscribe', 'list-unsubscribe-post', 'list-id', 'thread-topic', 'thread-index', 'x-mailer', 'user-agent',
    'arc-seal', 'arc-message-signature', 'arc-authentication-results', 'x-received', 'importance', 'precedence', 'feedback-id',
    'comments', 'keywords', 'organization', 'sensitivity', 'priority', 'autocrypt', 'encrypted', 'lines', 'path', 'newsgroups']);
  // Structured fields: RFC 2047 encoded words are never decoded inside them.
  const NO_DECODE = new Set(['received', 'dkim-signature', 'arc-seal', 'arc-message-signature', 'arc-authentication-results', 'authentication-results', 'x-google-dkim-signature', 'received-spf']);

  function normalizeText(text) {
    return String(text || '')
      .replace(/^﻿/, '')
      .replace(/\r\n?/g, '\n')
      .replace(/ /g, ' ');
  }

  function isFieldStart(line) {
    const m = FIELD_START.exec(line);
    // A URL (https://...) is text, not a field named https.
    return m && PLAUSIBLE_NAME.test(m[1]) && !line.slice(m[1].length + 1).startsWith('//') ? m : null;
  }

  // Find the header block inside whatever was pasted: a bare header
  // list, a full .eml, a copy of a whole "Show original" page, or
  // Outlook's Internet headers box.
  function locateHeaderBlock(lines) {
    let start = -1;
    for (let i = 0; i < lines.length; i++) {
      if (STRONG_ANCHORS.test(lines[i])) { start = i; break; }
    }
    let weak = false;
    if (start === -1) {
      for (let i = 0; i < lines.length; i++) {
        if (isFieldStart(lines[i]) && lines[i].length < 2000) { start = i; weak = true; break; }
      }
    }
    if (start === -1) return null;
    // Walk back to the first line of the contiguous block the anchor sits in.
    while (start > 0 && lines[start - 1].trim() !== '' && (isFieldStart(lines[start - 1]) || /^[ \t]/.test(lines[start - 1]))) start--;
    let end = lines.length;
    for (let i = start; i < lines.length; i++) {
      if (lines[i].trim() === '') { end = i; break; }
    }
    // Without a strong anchor, the block has to hold at least one field real mail carries.
    if (weak && !lines.slice(start, end).some(l => { const m = isFieldStart(l); return m && KNOWN.has(m[1].toLowerCase()); })) return null;
    return { start, end };
  }

  function detectFormat(lines, block, bodyPresent) {
    const before = lines.slice(0, block.start).join('\n');
    if (/^Microsoft Mail Internet Headers Version/im.test(before)) return 'outlook-headers';
    if (/^(Original Message|Download original|Created at:)/im.test(before) || /Copy to clipboard/i.test(before)) return 'gmail-original';
    if (bodyPresent) return 'eml';
    return 'bare';
  }

  // A sentence the page shows. Every one carries a state (pass, caveat,
  // fail, unknown), a technical wording, a plain wording for a reader
  // who is not technical, and the indexes of the fields it came from.
  // Simple wording uses contractions (house style). Technical keeps the
  // long forms, since it can quote a receiver's own words.
  const CONTRACT = { 'is not': "isn't", 'are not': "aren't", 'was not': "wasn't", 'were not': "weren't", 'do not': "don't", 'does not': "doesn't", 'did not': "didn't", 'could not': "couldn't", 'would not': "wouldn't", 'should not': "shouldn't", 'has not': "hasn't", 'have not': "haven't", 'will not': "won't", 'cannot': "can't" };
  function contract(text) {
    if (typeof text !== 'string') return text;
    return text.replace(/\b(is|are|was|were|do|does|did|could|would|should|has|have|will) not\b|\bcannot\b/gi, (m) => {
      const c = CONTRACT[m.toLowerCase()];
      return m[0] === m[0].toUpperCase() ? c[0].toUpperCase() + c.slice(1) : c;
    }).replace(/\b(it|that|there|here) is (?=[a-z])/gi, "$1's ");
  }

  function sentence(state, technical, plain, src) {
    return { state, technical, plain: contract(plain), src: (src || []).filter(i => i !== null && i !== undefined) };
  }

  // Build fields. Continuation lines start with WSP (RFC 5322 folding).
  // Pastes from Outlook and web pages lose the leading whitespace, so a
  // line that cannot be a field start is a continuation, and so is one
  // whose name is unknown, does not start with X-, and has no hyphen:
  // that catches Re:, Fwd:, https:, times, and Outlook's unindented
  // CIP: line under X-Forefront-Antispam-Report. Each such line is
  // counted as repaired.
  // Every field keeps its index and the span of raw lines it came from.
  function parseHeaders(text) {
    const lines = normalizeText(text).split('\n');
    const block = locateHeaderBlock(lines);
    const notes = [];
    if (!block) {
      notes.push(sentence('unknown', 'No header block found: no line in the paste has the form Name: value with a field real mail carries.', 'This looks like the text of an email, not its headers. Copy the message source instead. The box below the paste area says where to find it.', []));
      return { fields: [], notes, block: null, format: 'none', bodyPresent: false, blockFound: false, repairedLines: 0 };
    }
    const fields = [];
    let current = null, repaired = 0;
    for (let i = block.start; i < block.end; i++) {
      const line = lines[i];
      const m = isFieldStart(line);
      let continuation = /^[ \t]/.test(line) || !m;
      if (!continuation && current && !KNOWN.has(m[1].toLowerCase()) && !/^x-/i.test(m[1]) && !m[1].includes('-')) continuation = true;
      if (continuation && current) {
        current.rawLines.push(line);
        current.lastLine = i;
        if (!/^[ \t]/.test(line)) { current.looseFold = true; repaired++; }
        continue;
      }
      if (continuation) continue; // garbage before the first field
      current = { name: m[1], rawLines: [line], firstLine: i, lastLine: i, looseFold: false };
      fields.push(current);
    }
    // The same block pasted more than once (Outlook text and all, three
    // times, or a second copy cut short): read one copy. Fields match by
    // name and first line, so text pasted between copies, which the loop
    // above folds into the field before it, does not hide a repeat. At
    // each position the copy with the fewest lines is kept, which drops
    // that folded-in text.
    const key = (f) => f.name.toLowerCase() + ':' + f.rawLines[0].slice(f.name.length + 1).trim();
    let copies = 1;
    for (let k = 2; k <= fields.length - 2; k++) {
      if (key(fields[k]) !== key(fields[0])) continue;
      let j = k;
      while (j < fields.length && key(fields[j]) === key(fields[j % k])) j++;
      if (j < fields.length) continue;
      copies = Math.ceil(fields.length / k);
      const keep = [];
      for (let i = 0; i < k; i++) {
        let best = fields[i];
        for (let m = i + k; m < fields.length; m += k) if (fields[m].rawLines.length < best.rawLines.length) best = fields[m];
        keep.push(best);
      }
      fields.length = 0; fields.push(...keep);
      repaired = keep.reduce((n, f) => n + (f.looseFold ? f.rawLines.slice(1).filter(l => !/^[ \t]/.test(l)).length : 0), 0);
      break;
    }
    const out = fields.map((f, index) => {
      const first = f.rawLines[0].slice(f.name.length + 1);
      const rest = f.rawLines.slice(1);
      // Unfold: join folded lines with a single space, collapse runs of WSP.
      const value = [first].concat(rest).map(s => s.replace(/^[ \t]+/, '')).join(' ').replace(/[ \t]+/g, ' ').trim();
      if (f.looseFold) notes.push(sentence('caveat', 'Lines under ' + f.name + ' had lost their leading whitespace and were rejoined as one field.', 'Some lines lost their indentation when they were copied, so they were joined back to the line they belong to.', [index]));
      return { index, name: f.name, lower: f.name.toLowerCase(), value, decoded: NO_DECODE.has(f.name.toLowerCase()) ? value : decodeWords(value), raw: f.rawLines.join('\n'), lines: [f.firstLine, f.lastLine], looseFold: f.looseFold };
    });
    if (copies > 1) notes.unshift(sentence('caveat', 'The header block appears ' + (copies === 2 ? 'twice' : copies + ' times') + ' in the paste. One copy was read.', 'The headers were pasted ' + (copies === 2 ? 'twice' : copies + ' times') + '. Only one copy was read.', []));
    const bodyPresent = block.end < lines.length && lines.slice(block.end + 1).some(l => l.trim() !== '');
    return { fields: out, notes, block: [block.start, block.end - 1], format: detectFormat(lines, block, bodyPresent), bodyPresent, blockFound: out.length > 0, repairedLines: repaired };
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
    for (let box of splitMailboxes(v)) {
      // Group syntax (RFC 5322 3.4): "name: a@x, b@y;" and the empty
      // "Undisclosed recipients:;". The group name is not an address.
      const g = /^\s*(?:"[^"]*"|[^<>"@:,])*:/.exec(box);
      if (g && !/^\s*<?mailto:/i.test(box)) { box = box.slice(g[0].length); if (!box.replace(/[;\s]/g, '')) continue; }
      box = box.replace(/;\s*$/, '');
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
    const local = at >= 0 ? addr.slice(0, at) : addr;
    return { address: addr, display: display || '', name: display || '', domain, local, localPart: local, empty: addr === '' };
  }

  function domainOf(addrOrDomain) {
    if (!addrOrDomain) return '';
    const s = String(addrOrDomain).trim().replace(/^<|>$/g, '');
    const at = s.lastIndexOf('@');
    return (at >= 0 ? s.slice(at + 1) : s).toLowerCase().replace(/\.$/, '');
  }

  // RFC 5322 date-time, with the obsolete forms that still show up in
  // Received lines. Returns {time, tzKnown, text}; time is UTC
  // milliseconds or null. Only the zones RFC 5322 4.3 defines are
  // trusted. Military letters and other names are read as -0000, which
  // means UTC with the zone unknown, as 4.3 says to.
  const ZONES = { UT: 0, UTC: 0, GMT: 0, EST: -300, EDT: -240, CST: -360, CDT: -300, MST: -420, MDT: -360, PST: -480, PDT: -420 };
  const MONTHS = { jan: 0, feb: 1, mar: 2, apr: 3, may: 4, jun: 5, jul: 6, aug: 7, sep: 8, oct: 9, nov: 10, dec: 11 };
  function parseDate(text) {
    const result = { time: null, tzKnown: false, zone: '', text: (text || '').trim() };
    if (!text) return result;
    const s = stripComments(text).replace(/^(Mon|Tue|Wed|Thu|Fri|Sat|Sun)[a-z]*,?\s*/i, '');
    const m = /^(\d{1,2})\s+([A-Za-z]{3})[a-z]*\.?\s+(\d{2,4})\s+(\d{1,2}):(\d{2})(?::(\d{2}))?\s*([+-]\d{4}|[A-Za-z]{1,5})?(?:\s|$)/.exec(s);
    if (m) {
      // obs-year: two digits are 19xx from 50 up and 20xx below; three digits add 1900.
      let year = parseInt(m[3], 10);
      if (m[3].length === 2) year += year < 50 ? 2000 : 1900;
      else if (m[3].length === 3) year += 1900;
      const mon = MONTHS[m[2].toLowerCase()];
      if (mon === undefined) return result;
      let offsetMin = 0;
      const z = m[7];
      result.zone = z || '';
      if (z && /^[+-]\d{4}$/.test(z)) {
        const sign = z[0] === '-' ? -1 : 1;
        offsetMin = sign * (parseInt(z.slice(1, 3), 10) * 60 + parseInt(z.slice(3, 5), 10));
        result.tzKnown = z !== '-0000'; // -0000 means no zone information
      } else if (z && ZONES[z.toUpperCase()] !== undefined) {
        offsetMin = ZONES[z.toUpperCase()];
        result.tzKnown = true;
      }
      result.time = Date.UTC(year, mon, parseInt(m[1], 10), parseInt(m[4], 10), parseInt(m[5], 10), m[6] ? parseInt(m[6], 10) : 0) - offsetMin * 60000;
      return result;
    }
    // asctime, as some older MTAs write it: Fri Oct 23 16:30:14 2026. No zone.
    const a = /^([A-Za-z]{3})\s+(\d{1,2})\s+(\d{1,2}):(\d{2}):(\d{2})\s+(\d{4})/.exec(s);
    if (a && MONTHS[a[1].toLowerCase()] !== undefined) {
      result.time = Date.UTC(+a[6], MONTHS[a[1].toLowerCase()], +a[2], +a[3], +a[4], +a[5]);
      return result;
    }
    // ISO 8601 with an explicit offset. Without one the zone would be a guess.
    const iso = /^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:?\d{2})$/.exec(s);
    if (iso) { const t = Date.parse(s.replace(' ', 'T')); if (!isNaN(t)) { result.time = t; result.tzKnown = true; } }
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

  HA.parse = { parseHeaders, sentence, contract, decodeWords, stripComments, extractComments, parseAddresses, parseDate, parseTagList, domainOf, normalizeText };
  // Node: require() returns this layer; the browser reads HA instead.
  if (typeof module !== 'undefined' && module.exports) module.exports = HA.parse;
})(typeof globalThis !== 'undefined' ? globalThis : this);
