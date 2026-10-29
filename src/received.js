// received.js: Received headers into a chronological hop list with delays.
// Received fields appear newest first; the chain here runs oldest first.
// Every hop carries src, the index of the field it came from.
(function (root) {
  'use strict';
  const HA = (root.HA = root.HA || {});
  const P = HA.parse;
  const say = P.sentence;

  const IPV4 = /\b(\d{1,3}(?:\.\d{1,3}){3})\b/;
  const IPV6 = /\[?(?:IPv6:)?([0-9a-f]{0,4}(?::[0-9a-f]{0,4}){2,7})(?:%\d+)?\]?/i;

  function findIp(text) {
    if (!text) return '';
    const m4 = IPV4.exec(text);
    if (m4) return m4[1];
    const m6 = IPV6.exec(text);
    if (m6 && m6[1].includes(':')) return m6[1];
    return '';
  }

  function isIpLiteral(host) {
    return /^\[?(IPv6:)?[0-9a-f:.]+(%\d+)?\]?$/i.test(host || '') && /[:.]/.test(host);
  }

  function isPrivateIp(ip) {
    if (!ip) return false;
    if (/^10\./.test(ip) || /^192\.168\./.test(ip) || /^127\./.test(ip) || /^169\.254\./.test(ip)) return true;
    const m = /^172\.(\d+)\./.exec(ip);
    if (m && +m[1] >= 16 && +m[1] <= 31) return true;
    if (/^(::1$|fe80:|fc|fd)/i.test(ip)) return true;
    return false;
  }

  // Mail operators that run hosts under more than one registered domain.
  // A hop between two names on this list is one operator's own relay.
  const OPERATORS = {
    Microsoft: ['outlook.com', 'office365.com', 'exchangelabs.com', 'microsoft.com', 'hotmail.com', 'live.com', 'outlook.cn'],
    Google: ['google.com', 'gmail.com', 'googlemail.com', '1e100.net'],
    Apple: ['icloud.com', 'me.com', 'mac.com', 'apple.com'],
    Yahoo: ['yahoo.com', 'yahoodns.net', 'yahoo.net', 'aol.com'],
    Proton: ['protonmail.ch', 'protonmail.com', 'proton.me', 'pm.me'],
  };
  const OPERATOR_OF = {};
  for (const [name, list] of Object.entries(OPERATORS)) for (const d of list) OPERATOR_OF[d] = name;

  // The operator behind a host name: a known operator's name, otherwise
  // its organizational domain. IP literals and single labels have none.
  function operatorOf(host) {
    if (!host || isIpLiteral(host) || !host.includes('.')) return '';
    const org = HA.psl.orgDomain(host.replace(/\.$/, '').toLowerCase());
    return OPERATOR_OF[org] || org;
  }

  // RFC 3848 and RFC 6531 protocol names; S means TLS, A means authenticated.
  const PROTO = /^(UTF8)?(E?SMTP|LMTP)(S)?(A)?$/i;

  function tlsVersion(text) {
    // Google and Microsoft: version=TLS1_3. Postfix: using TLSv1.3. Exim: (TLS1.3).
    const m = /(?:version=|using\s+)(TLS\s?v?[0-9._]+|SSLv?[0-9.]+)/i.exec(text) || /\b(TLS1_[0-3])\b/.exec(text) || /\((TLSv?1[._][0-3])\)/i.exec(text);
    if (!m) return '';
    return m[1].replace(/_/g, '.').replace(/^TLS\s?v?/i, 'TLS ').replace(/^SSL\s?v?/i, 'SSL ');
  }

  // TLS evidence, from the with clause and the comments around it.
  // States: pass (TLS), caveat (TLS older than 1.2, or plain inside one
  // operator's network), fail (plain across the network), unknown
  // (nothing recorded, or no network connection to record).
  function readTls(hop, value) {
    const version = tlsVersion(value);
    const cipherM = /cipher[=\s]+([A-Z0-9_-]+)/i.exec(value);
    const tls = { state: 'unknown', label: 'Not recorded', version, cipher: cipherM ? cipherM[1] : '', evidence: '' };
    const proto = PROTO.exec(hop.protocol);
    let encrypted = null;
    if (version) { encrypted = true; tls.evidence = 'version ' + version; }
    else if (proto && proto[3]) { encrypted = true; tls.evidence = 'with ' + hop.protocol; }
    else if (/^SMTPS$/i.test(hop.protocol) || /^HTTPS$/i.test(hop.protocol)) { encrypted = true; tls.evidence = 'with ' + hop.protocol; }
    else if (proto || /^HTTP$/i.test(hop.protocol) || hop.protocol === 'Microsoft SMTP') { encrypted = false; tls.evidence = 'with ' + (hop.protocol === 'Microsoft SMTP' ? 'Microsoft SMTP Server' : hop.protocol) + ' and no TLS version'; }
    if (!hop.from) { tls.label = 'No connection'; return tls; } // a local handoff crosses no network
    if (encrypted === true) {
      const old = /^(SSL|TLS 1(\.[01])?$)/.test(version);
      tls.state = old ? 'caveat' : 'pass';
      tls.label = version || 'TLS';
      if (old) tls.label += ', outdated';
    } else if (encrypted === false) {
      tls.state = hop.internal ? 'caveat' : 'fail';
      tls.label = hop.internal ? 'Plain, internal' : 'Plain';
    }
    return tls;
  }

  // Split one Received value into its clauses. The date follows the last
  // semicolon (RFC 5321 4.4). Clause keywords are matched outside comments.
  function parseReceived(value) {
    const hop = { from: '', fromHost: '', fromIp: '', fromComment: '', by: '', byHost: '', with: '', id: '', via: '', for: '', protocol: '', time: null, tzKnown: false, dateText: '', authenticated: false, internal: false, internalReason: '', operator: '' };
    const semi = value.lastIndexOf(';');
    let clause = value, dateText = '';
    if (semi >= 0) { clause = value.slice(0, semi); dateText = value.slice(semi + 1); }
    const d = P.parseDate(dateText);
    hop.time = d.time; hop.tzKnown = d.tzKnown; hop.dateText = d.text;

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
      hop[s.key] = hop[s.key] ? hop[s.key] + ' ' + t : t;
    }
    hop.fromHost = P.stripComments(hop.from).split(/\s/)[0] || '';
    hop.fromComment = P.extractComments(hop.from).join(' ');
    hop.fromIp = findIp(hop.fromComment) || findIp(hop.fromHost) || '';
    hop.byHost = P.stripComments(hop.by).split(/\s/)[0] || '';
    hop.forAddress = P.stripComments(hop.for).replace(/^<|>$/g, '');
    const withText = P.stripComments(hop.with);
    hop.protocol = /^Microsoft SMTP/i.test(withText) ? 'Microsoft SMTP' : (withText.split(/\s/)[0] || '');
    if (/^E?SMTPS?A$|^UTF8SMTPS?A$|^LMTPS?A$/i.test(hop.protocol) || /\(Authenticated sender|\bauthenticated\b/i.test(value)) hop.authenticated = true;

    // The sending host's name for operator purposes: its HELO name, or
    // the reverse DNS name in the comment when the HELO is an IP literal.
    // Only the "name [ip]" comment form counts, so an address in an
    // "(Authenticated sender: ...)" comment is never read as a host.
    const rdnsM = /(?:^|\s)([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)\.?\s*\[/.exec(hop.fromComment);
    const rdns = rdnsM && !isIpLiteral(rdnsM[1]) ? rdnsM[1] : '';
    hop.fromName = hop.fromHost && hop.fromHost.includes('.') && !isIpLiteral(hop.fromHost) ? hop.fromHost : rdns;
    // The name the sender stated: Exim writes helo= in the comment,
    // Postfix and Sendmail put it first. Reverse DNS is the name in the comment.
    const heloM = /\bhelo=([^\s)\]]+)/i.exec(hop.fromComment);
    hop.helo = heloM ? heloM[1] : hop.fromHost;
    hop.rdns = rdns;
    const envM = /envelope-from\s+<([^>]*)>/i.exec(value);
    hop.envelopeFrom = envM ? envM[1] : '';
    hop.fromOperator = operatorOf(hop.fromName);
    hop.byOperator = operatorOf(hop.byHost);
    return { hop, value };
  }

  function classify(hop, prev) {
    const reasons = [];
    if (/^mapi$/i.test(hop.protocol)) reasons.push('mapi submission inside Exchange');
    if (!hop.from) reasons.push('no from clause: a handoff inside one server');
    if (isPrivateIp(hop.fromIp)) reasons.push('private address ' + hop.fromIp);
    if (/^(localhost|127\.0\.0\.1|\[127\.0\.0\.1\])$/i.test(hop.fromHost)) reasons.push('localhost');
    if (hop.fromOperator && hop.byOperator && hop.fromOperator === hop.byOperator) reasons.push('both hosts belong to ' + hop.fromOperator);
    // Two machines that both use single-label names are inside one network;
    // a public relay announces a full name.
    const single = (h) => h && !h.includes('.') && !isIpLiteral(h);
    if (single(hop.byHost) && single(hop.fromHost)) reasons.push('single-label host names ' + hop.fromHost + ' and ' + hop.byHost);
    hop.internal = reasons.length > 0;
    hop.internalReason = reasons.join('; ');
    // A local handoff happens on the machine that received the previous hop.
    hop.operator = hop.byOperator || hop.fromOperator || (!hop.from && prev ? prev.operator : '') || '';
  }

  function fmtDur(sec) {
    if (sec === null || sec === undefined) return '';
    const s = Math.abs(sec), neg = sec < 0 ? '-' : '';
    const two = (a, ua, b, ub) => a + ua + (b ? ' ' + b + ub : '');
    if (s < 60) return neg + s + 's';
    if (s < 3600) return neg + two(Math.floor(s / 60), 'm', s % 60, 's');
    if (s < 86400) return neg + two(Math.floor(s / 3600), 'h', Math.floor((s % 3600) / 60), 'm');
    return neg + two(Math.floor(s / 86400), 'd', Math.floor((s % 86400) / 3600), 'h');
  }

  // AP style: one through nine in words.
  const numWord = (n) => n >= 0 && n < 10 ? ['zero', 'one', 'two', 'three', 'four', 'five', 'six', 'seven', 'eight', 'nine'][n] : String(n);
  function plainDur(sec) {
    const s = Math.abs(sec);
    const unit = (n, w) => numWord(n) + ' ' + w + (n === 1 ? '' : 's');
    if (s < 60) return unit(s, 'second');
    if (s < 3600) return unit(Math.floor(s / 60), 'minute') + (s % 60 ? ' ' + unit(s % 60, 'second') : '');
    if (s < 86400) return unit(Math.floor(s / 3600), 'hour') + (Math.floor((s % 3600) / 60) ? ' ' + unit(Math.floor((s % 3600) / 60), 'minute') : '');
    return unit(Math.floor(s / 86400), 'day') + (Math.floor((s % 86400) / 3600) ? ' ' + unit(Math.floor((s % 86400) / 3600), 'hour') : '');
  }

  const label = (h) => h.fromName || h.fromHost || h.fromIp || 'an unnamed host';

  function buildChain(fields) {
    const parsed = fields.filter(f => f.lower === 'received').map(f => Object.assign(parseReceived(f.value), { src: [f.index] }));
    parsed.reverse(); // oldest first
    const hops = [];
    let prevDated = null, slowestIdx = -1, slowestSec = 0, skew = false;
    parsed.forEach((p, i) => {
      const h = p.hop;
      h.index = i;
      h.src = p.src;
      classify(h, hops[i - 1]);
      h.tls = readTls(h, p.value);
      h.delaySec = null;
      h.skew = false;
      h.slowest = false;
      h.prevDated = null;
      if (h.time !== null && prevDated) {
        h.delaySec = Math.round((h.time - prevDated.time) / 1000);
        h.prevDated = prevDated.index;
        if (h.delaySec < 0) { h.skew = true; skew = true; }
        if (h.delaySec > slowestSec) { slowestSec = h.delaySec; slowestIdx = i; }
      }
      if (h.time !== null) prevDated = h;
      hops.push(h);
    });
    if (slowestIdx >= 0) hops[slowestIdx].slowest = true;

    // Runs of two or more internal hops of one operator collapse into one row.
    const groups = [];
    for (let i = 0; i < hops.length;) {
      let j = i;
      if (hops[i].internal) while (j + 1 < hops.length && hops[j + 1].internal && hops[j + 1].operator === hops[i].operator) j++;
      if (j > i) {
        const run = hops.slice(i, j + 1);
        const known = run.filter(h => h.delaySec !== null);
        groups.push({ kind: 'internal', hops: run.map(h => h.index), operator: hops[i].operator || 'one server', delaySec: known.length ? known.reduce((a, h) => a + h.delaySec, 0) : null, src: run.map(h => h.src[0]) });
      } else groups.push({ kind: 'hop', hops: [i], operator: hops[i].operator, delaySec: hops[i].delaySec, src: hops[i].src.slice() });
      i = j + 1;
    }

    const dated = hops.filter(h => h.time !== null);
    const totalSec = dated.length >= 2 ? Math.round((dated[dated.length - 1].time - dated[0].time) / 1000) : null;
    const trust = trustLine(hops);
    // A stated origin is what the submitting client or server claims, kept
    // apart from the observed one because the sender's side can write it.
    const xo = fields.find(f => f.lower === 'x-originating-ip' || f.lower === 'x-sender-ip');
    const statedOriginIp = xo ? { ip: findIp(xo.value) || xo.value.replace(/[\[\]]/g, '').trim(), name: xo.name, src: [xo.index] } : null;
    const chain = { hops, groups, totalSec, slowestIdx, slowestSec, clockSkew: skew, originIp: trust.originIp, statedOriginIp, trust, count: hops.length, notes: [] };
    chain.notes = chainNotes(chain);
    return chain;
  }

  const sameHost = (a, b) => !!a && !!b && a.toLowerCase().replace(/\.$/, '') === b.toLowerCase().replace(/\.$/, '');

  // Trust line. Each hop's receiving side gets an operator: its by host's
  // own, or, when the by host has no usable name, the operator of the
  // hop's internal group (step 1: private address, local handoff, two
  // hosts of one operator) or of the next hop's from host when that is
  // the same machine. The boundary is the earliest hop of the unbroken
  // run, ending at the final hop, whose receiving side is the final
  // operator. Its from address, the IP the receiver saw connect, is the
  // origin. Every Received field before it was written by the sender's
  // side and can be forged; a forged "by mx.google.com" line before a
  // real hop from elsewhere does not move the boundary.
  function trustLine(hops) {
    const t = { boundaryIdx: -1, operator: '', sides: hops.map(() => ''), originIp: '', originHelo: '', originPrivate: false, src: [] };
    for (let i = hops.length - 1; i >= 0; i--) {
      const h = hops[i], next = hops[i + 1];
      t.sides[i] = h.byOperator || (h.internal ? h.operator : '') ||
        (next && sameHost(h.byHost, next.fromHost) ? (next.fromOperator || t.sides[i + 1]) : '');
    }
    if (!hops.length || !t.sides[hops.length - 1]) return t;
    t.operator = t.sides[hops.length - 1];
    let b = hops.length - 1;
    while (b > 0 && t.sides[b - 1] === t.operator) b--;
    const h = hops[b];
    t.boundaryIdx = b;
    t.src = h.src.slice();
    t.originIp = h.fromIp;
    t.originHelo = h.fromHost && !isIpLiteral(h.fromHost) ? h.fromHost : '';
    t.originPrivate = !h.from || isPrivateIp(h.fromIp);
    return t;
  }

  function chainNotes(c) {
    const notes = [];
    const allSrc = c.hops.map(h => h.src[0]);
    if (!c.count) {
      notes.push(say('unknown', 'No Received fields. This copy never passed through a receiving server, which is what a sent or draft copy looks like.', 'This copy has no delivery stamps, so it looks like a sent or draft copy rather than one that arrived in a mailbox. Paste the headers from the recipient\'s copy.', []));
      return notes;
    }
    const t = c.trust;
    if (t.boundaryIdx < 0) {
      notes.push(say('unknown', 'No trust line: the final Received field names no receiving host this page can tie to an operator, so it cannot say which stamps the receiver wrote.', 'It is not clear which delivery stamps the receiving mail system wrote, so treat all of them with care.', [c.hops[c.count - 1].src[0]]));
    } else {
      const before = t.boundaryIdx;
      const tail = before ? ' The ' + (before === 1 ? 'Received field' : numWord(before) + ' Received fields') + ' before it ' + (before === 1 ? 'was' : 'were') + ' written by the sender\'s side and can be forged.' : '';
      const plainTail = before ? ' The ' + (before === 1 ? 'stamp' : numWord(before) + ' stamps') + ' before that came from the sender\'s side and could be made up.' : '';
      if (t.originPrivate) {
        notes.push(say('caveat', 'Trust line at hop ' + (before + 1) + ': ' + t.operator + ' took custody from ' + (t.originIp ? 'private address ' + t.originIp : 'a local handoff') + ', so the message started inside ' + t.operator + '\'s own network and there is no outside origin address.' + tail,
          'The message started inside the receiving organization\'s own mail system, so there is no outside sending address to show.' + plainTail, t.src));
      } else {
        notes.push(say('pass', 'Trust line at hop ' + (before + 1) + ': ' + t.operator + ' took custody from ' + (t.originIp || 'an address it did not record') + (t.originHelo ? ' (EHLO ' + t.originHelo + ', the name the sender gave)' : '') + '. That address is the origin as the receiver saw it.' + tail,
          'The receiving mail system (' + t.operator + ') took the message from ' + (t.originIp || 'an address it did not record') + '. That part of the record can be trusted.' + plainTail, t.src));
      }
    }
    if (c.statedOriginIp) {
      const so = c.statedOriginIp;
      const same = so.ip && so.ip === t.originIp;
      notes.push(say('unknown', so.name + ' states ' + so.ip + ' as the client address.' + (same ? ' That matches the observed origin.' : ' This is what the sender\'s side wrote, kept apart from the observed origin' + (t.originIp ? ' ' + t.originIp : '') + '; it is not verified.'),
        'The sending system says the message was written on a device at ' + so.ip + '. That is its own claim, not something the receiver checked.', so.src));
    }
    if (c.totalSec !== null && c.totalSec >= 0) {
      const caveat = c.clockSkew || c.hops.some(h => h.time !== null && !h.tzKnown);
      notes.push(say(caveat ? 'caveat' : 'pass',
        'End to end: ' + fmtDur(c.totalSec) + ' across ' + c.count + ' hop' + (c.count === 1 ? '' : 's') + ', from the first Received stamp to the last' + (caveat ? '. Some stamps disagree or lack a zone, so treat it as approximate.' : '.'),
        'The message took ' + plainDur(c.totalSec) + ' to arrive' + (caveat ? ', roughly. Some server clocks disagree.' : '.'), allSrc));
    } else if (c.totalSec !== null) {
      notes.push(say('caveat', 'Transit time cannot be measured: the last Received stamp is ' + fmtDur(-c.totalSec) + ' earlier than the first, so the servers\' clocks disagree.', 'The delivery stamps disagree about the time, so it is not possible to say how long the message took.', allSrc));
    } else {
      notes.push(say('unknown', 'Transit time cannot be measured: fewer than two Received stamps carry a readable date.', 'The delivery stamps do not carry enough readable times to say how long the message took.', allSrc));
    }
    if (c.slowestIdx >= 0) {
      const h = c.hops[c.slowestIdx];
      const p = c.hops[h.prevDated];
      const long = h.delaySec >= 600;
      const where = h.internal ? 'inside ' + (h.operator || 'one server') : 'between ' + (h.fromOperator || label(h)) + ' and ' + (h.byOperator || h.byHost || 'the next server');
      notes.push(say(long ? 'caveat' : 'pass',
        'Hop ' + (h.index + 1) + ' is the slowest: ' + fmtDur(h.delaySec) + ' from ' + label(h) + ' to ' + (h.byHost || 'an unnamed host') + '.' + (long ? ' Waits this long usually mean greylisting, throttling, or a queue on the sending side.' : ''),
        'The longest wait was ' + plainDur(h.delaySec) + ', ' + where + '.' + (long ? ' A wait that long usually means a server held the message back on purpose.' : ''),
        [p.src[0], h.src[0]]));
    }
    const noTz = c.hops.filter(h => h.time !== null && !h.tzKnown);
    if (noTz.length) {
      const n = noTz.length, which = noTz.map(h => h.index + 1);
      notes.push(say('caveat', (n === 1 ? 'Hop ' + which[0] + ' has' : 'Hops ' + which.slice(0, -1).join(', ') + ' and ' + which[n - 1] + ' have') + ' no usable time zone (-0000, a military letter, a nonstandard name, or none), so ' + (n === 1 ? 'it is' : 'they are') + ' read as UTC and delays may be off by hours.',
        (n === 1 ? 'One server' : numWord(n).replace(/^./, (x) => x.toUpperCase()) + ' servers') + ' did not say which time zone ' + (n === 1 ? 'it was' : 'they were') + ' in, so the timing could be off by hours.', noTz.flatMap(h => h.src)));
    }
    for (const h of c.hops) {
      if (h.skew) {
        const p = c.hops[h.prevDated];
        notes.push(say('caveat', 'Hop ' + (h.index + 1) + ' is stamped ' + fmtDur(-h.delaySec) + ' earlier than hop ' + (p.index + 1) + ' before it, so the two servers\' clocks disagree. Delays around it are unreliable.', 'Two servers disagree about the time, so the timing around this step is not reliable.', [p.src[0], h.src[0]]));
      }
      if (h.time === null) {
        notes.push(say('unknown', 'Hop ' + (h.index + 1) + ' has no readable date' + (h.dateText ? ' ("' + h.dateText.slice(0, 60) + '")' : '') + ', so its delay is not shown.', 'One delivery stamp has no readable time.', h.src));
      }
      if (h.tls.state === 'fail') {
        notes.push(say('fail', 'Hop ' + (h.index + 1) + ' from ' + label(h) + ' to ' + (h.byHost || 'an unnamed host') + ' was recorded ' + h.tls.evidence + ', so the message crossed the network unencrypted there.', 'At one step the message crossed the internet without encryption.', h.src));
      } else if (h.tls.state === 'caveat' && h.tls.version) {
        notes.push(say('caveat', 'Hop ' + (h.index + 1) + ' used ' + h.tls.version + ', which RFC 8996 deprecates.', 'One step used an old form of encryption that is no longer considered safe.', h.src));
      }
    }
    return notes;
  }

  HA.received = { parseReceived, buildChain, findIp, isPrivateIp, isIpLiteral, operatorOf, sameHost, fmtDur, plainDur };
  // Node: require() returns this layer; the browser reads HA instead.
  if (typeof module !== 'undefined' && module.exports) module.exports = HA.received;
})(typeof globalThis !== 'undefined' ? globalThis : this);
