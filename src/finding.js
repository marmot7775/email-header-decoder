// finding.js: the one result the page leads with. Reads the auth,
// alignment, chain and decoded objects and writes no DOM. Every sentence
// is built from identifiers in the headers. Where the headers cannot
// show something (adkim and aspf, the organizational domain, Gmail's
// spam decision) the finding says so instead of assuming a default.
//
// finding = { status, state, headline, cause, consequence, details,
//   fixes, flags, limits, forwarded }
//   status is pass | fail | forwarded | none | error | unknown:
//     forwarded  failed here, but the forwarder's record shows a pass
//                before the forward, so the forward is to blame
//     none       the From domain has no DMARC record
//     error      the receiver could not read the DMARC record
//     unknown    the headers hold nothing to judge by
//   headline, cause and consequence are Sentences; the rest are lists.
(function (root) {
  'use strict';
  const HA = (root.HA = root.HA || {});
  const P = HA.parse;
  const say = P.sentence;

  const STATE_OF = { pass: 'pass', fail: 'fail', forwarded: 'caveat', none: 'caveat', error: 'caveat', unknown: 'unknown' };
  const MAILBOX_OPERATORS = ['Google', 'Microsoft', 'Apple', 'Yahoo'];
  const LEVEL_STATE = { pass: 'pass', warn: 'caveat', fail: 'fail', info: 'unknown' };
  const uniq = (a) => Array.from(new Set(a.filter(i => i !== null && i !== undefined))).sort((x, y) => x - y);
  const numWord = (n) => ['no', 'one', 'two', 'three', 'four', 'five', 'six', 'seven', 'eight', 'nine'][n] || String(n);

  function joinList(items, word) {
    if (items.length <= 1) return items.join('');
    if (items.length === 2) return items[0] + ' ' + (word || 'and') + ' ' + items[1];
    return items.slice(0, -1).join(', ') + ', ' + (word || 'and') + ' ' + items[items.length - 1];
  }

  // The receiver as the page names it: the primary field's authserv-id,
  // or Microsoft 365 for the Exchange Online form that names none.
  function receiverOf(auth, chain) {
    const rec = auth.primary >= 0 ? auth.all[auth.primary] : null;
    if (rec && rec.authserv) return rec.authserv;
    if (rec && auth.exchangeOnline) return 'Microsoft 365';
    return chain.trust.operator || 'the receiver';
  }

  // The receiver as Simple wording names it: the mailbox provider people
  // know, never an authserv-id.
  function plainReceiver(r) {
    if (r === 'Microsoft 365') return 'Microsoft';
    const o = HA.psl.orgDomain(r) || r;
    return { 'google.com': 'Gmail', 'outlook.com': 'Microsoft', 'microsoft.com': 'Microsoft', 'office365.com': 'Microsoft', 'yahoo.com': 'Yahoo', 'yahoodns.net': 'Yahoo', 'aol.com': 'AOL', 'icloud.com': 'iCloud Mail', 'me.com': 'iCloud Mail', 'apple.com': 'iCloud Mail' }[o] || 'the recipient\'s email provider';
  }

  // How a fix names the sending service: by name only at high confidence,
  // with the name as a pointer at medium, unnamed otherwise.
  function serviceOf(platform) {
    if (platform && platform.confidence === 'high') return { t: platform.name, p: platform.name };
    if (platform && platform.confidence === 'medium') return { t: 'the sending service (the headers point to ' + platform.name + ')', p: 'the service that sends this mail (probably ' + platform.name + ')' };
    return { t: 'the sending service', p: 'the service that sends this mail' };
  }

  // One phrase per identifier that did not carry DMARC, in both voices.
  // unaligned marks a pass on a domain that is not the From domain's.
  const SPF_WORD = { fail: 'failed', softfail: 'soft failed', neutral: 'was neutral', none: 'found no record', permerror: 'hit a permanent error in the record', temperror: 'hit a temporary DNS error', policy: 'was overridden by local policy' };
  function dkimPiece(k) {
    const d = k.domain || 'an unnamed domain';
    const id = 'DKIM d=' + d + (k.selector ? ' s=' + k.selector : '');
    if (k.result === 'pass' && !k.relaxed) return { t: id + ' passed', p: 'it was signed by ' + d, unaligned: true, src: k.src };
    if (k.result === 'pass') return null;
    if (k.result === 'fail') return { t: id + ' failed verification', p: 'the signature from ' + d + ' did not check out', src: k.src };
    if (!k.result) return { t: 'the DKIM signature from ' + d + ' has no recorded result', p: 'the signature from ' + d + ' was not checked', src: k.src };
    return { t: 'DKIM for ' + d + ' returned ' + k.result, p: 'the signature from ' + d + ' could not be checked', src: k.src };
  }
  function spfPiece(spf) {
    const helo = /helo/i.test(spf.identity);
    const d = spf.domain;
    if (!spf.result) return { t: 'no SPF result was recorded', p: 'no check of the sending server was recorded', src: spf.src };
    if (!d) return { t: 'SPF returned ' + spf.result + ' with no domain named', p: 'the sending server check named no domain', src: spf.src };
    const name = helo ? 'the HELO identity ' + d : 'the Return-Path domain ' + d + ' (RFC5321.MailFrom)';
    if (spf.result === 'pass' && !spf.relaxed) return { t: 'SPF passed for ' + name, p: helo ? 'the sending server called itself ' + d : 'it came from a server that ' + d + ' allows', unaligned: true, src: spf.src };
    if (spf.result === 'pass') return null;
    const plain = { fail: 'the sending server is not on ' + d + '\'s list of approved servers', softfail: 'the sending server is not on ' + d + '\'s list of approved servers', none: d + ' publishes no list of approved servers' }[spf.result] || { neutral: d + '\'s list of approved servers gave no clear answer', permerror: d + '\'s list of approved servers is set up wrong, so it couldn\'t be read', temperror: d + '\'s list of approved servers couldn\'t be read this time' }[spf.result] || 'the sending server check for ' + d + ' gave no clear answer';
    return { t: 'SPF ' + (SPF_WORD[spf.result] || 'returned ' + spf.result) + ' for ' + name, p: plain, src: spf.src };
  }
  function failPieces(auth) {
    const pieces = [];
    if (!auth.dkim.length) pieces.push({ t: 'there was no DKIM signature', p: 'it carried no signature', src: [] });
    for (const k of auth.dkim) { const x = dkimPiece(k); if (x) pieces.push(x); }
    const s = spfPiece(auth.spf); if (s) pieces.push(s);
    return pieces;
  }
  // "..., so neither aligned with the From domain shop.example."
  const upFirst = (x) => x.charAt(0).toUpperCase() + x.slice(1);
  function failClause(pieces, from) {
    const un = pieces.filter(x => x.unaligned).length;
    const t = joinList(pieces.map(x => x.t));
    const p = joinList(pieces.map(x => x.p.split('the signature from ' + from).join('the signature').split(from + '\'s list of').join('the sender\'s list of')));
    if (un && un === pieces.length) return { t: t + ', but ' + (un === 1 ? 'it does not align' : 'neither aligns') + ' with the From domain ' + from + ' (RFC5322.From).', p: p + '. ' + (un === 1 ? 'That is not ' : 'Neither of those is ') + from + ', the domain in the From address.' };
    if (un) return { t: t + ', and nothing that passed aligns with the From domain ' + from + ' (RFC5322.From).', p: p + '. Nothing that checked out matches ' + from + ', the domain in the From address.' };
    return { t: t + ', so no identifier passed for the From domain ' + from + ' (RFC5322.From).', p: p + '. Nothing proved it came from ' + from + '.' };
  }
  function passPieces(auth) {
    const out = [];
    for (const k of auth.dkim) if (k.result === 'pass' && k.relaxed) out.push({ t: 'DKIM d=' + k.domain + (k.selector ? ' s=' + k.selector : '') + ' passed', p: 'it was signed by ' + k.domain, d: k.domain, kind: 'dkim', relaxedOnly: k.relaxedOnly, src: k.src });
    const s = auth.spf;
    if (s.result === 'pass' && s.relaxed) out.push({ t: 'SPF passed for the Return-Path domain ' + s.domain + ' (RFC5321.MailFrom)', p: 'it came from a server that ' + s.domain + ' allows', d: s.domain, kind: 'spf', relaxedOnly: s.relaxedOnly, src: s.src });
    return out;
  }
  function passClause(pieces, from) {
    const relaxed = pieces.some(x => x.relaxedOnly) ? ' under relaxed alignment, through the organizational domain' : '';
    // Every pass is the From domain itself: name it once.
    const own = !relaxed && pieces.every(x => x.d === from);
    const both = pieces.length > 1;
    const ownP = both ? 'it was signed by ' + from + ', the domain in the From address, and came from a server it allows.'
      : pieces[0] && pieces[0].kind === 'spf' ? 'it came from a server allowed by ' + from + ', the domain in the From address.' : 'it was signed by ' + from + ', the domain in the From address.';
    return {
      t: joinList(pieces.map(x => x.t)) + ', and ' + (pieces.length === 1 ? 'it aligns' : 'both align') + ' with the From domain ' + from + ' (RFC5322.From)' + relaxed + '.',
      p: own ? ownP : joinList(pieces.map(x => x.p)) + '. ' + (pieces.length === 1 ? 'That' : 'Both') + (relaxed ? ' belong' + (pieces.length === 1 ? 's' : '') + ' to ' + from + ', the domain in the From address, or to its parent domain.' : ' match' + (pieces.length === 1 ? 'es ' : ' ') + from + ', the domain in the From address.'),
    };
  }

  // Per identifier, the longer statement the details list carries.
  function rowSentence(r, from, via) {
    const forwarded = via === 'forward';
    const note = r.comments && r.comments[0] && r.comments[0].length <= 80 ? ' (' + r.comments[0] + ')' : '';
    if (r.kind === 'dkim') {
      const d = r.domain || 'an unnamed domain';
      const sel = r.selector ? ' s=' + r.selector : '';
      if (r.ambiguous) return say('unknown', 'A DKIM result for d=' + d + ' names neither s= nor b=, and two signatures carry d=' + d + ', so this page cannot tell which one it describes.', 'One signature result could belong to either of two signatures, so this page does not pick one.', r.src);
      if (!r.result) return say('unknown', 'DKIM-Signature d=' + d + sel + ' carries no result from the receiver.', 'One signature on the message was not checked by the receiver.', r.src);
      if (r.result === 'pass') return r.relaxed
        ? say('pass', 'DKIM passed for d=' + d + sel + ', which aligns with ' + from + (r.relaxedOnly ? ' in relaxed mode only.' : '.'), 'The message was signed by ' + d + ', which belongs to the sender.', r.src)
        : say('caveat', 'DKIM passed for d=' + d + sel + ', which does not align with ' + from + '. A pass on another domain does not count for DMARC.', 'The message was signed, but by ' + d + ', not by the sender\'s own domain.', r.src);
      if (r.result === 'fail') return say('fail', 'DKIM failed for d=' + d + sel + note + '.' + (forwarded ? ' The message was forwarded, and forwarders often change it enough to break the signature.' : via === 'list' ? ' The message came through a mailing list, and lists change it enough to break the signature.' : ' Something changed the signed headers or body after signing, or the key in DNS does not match; the headers cannot show which.'), 'The signature from ' + d + ' did not check out' + (forwarded ? ', most likely because the forward changed the message.' : via === 'list' ? ', because the mailing list changed the message.' : '.'), r.src);
      return say(r.state, 'DKIM returned ' + r.result + ' for d=' + d + sel + note + '.', 'The signature from ' + d + ' could not be checked.', r.src);
    }
    if (r.absent) return say('unknown', 'No SPF domain: there is no smtp.mailfrom, Received-SPF envelope-from or Return-Path to read it from.', 'The headers do not say which domain the sending server was checked against.', r.src);
    const id = /helo/i.test(r.identity) ? 'the HELO name ' + r.domain : r.domain;
    const ip = r.ip ? ' for ' + r.ip : '';
    if (r.result === 'pass') return r.relaxed
      ? say('pass', 'SPF passed for ' + id + ip + ', which aligns with ' + from + (r.relaxedOnly ? ' in relaxed mode only.' : '.'), 'The sending server is approved by ' + r.domain + ', which belongs to the sender.', r.src)
      : say('caveat', 'SPF passed for ' + id + ip + ', which does not align with ' + from + '. A pass on another domain does not count for DMARC.', 'The sending server is approved, but by ' + r.domain + ', not by the sender\'s own domain.', r.src);
    if (!r.result) return say('unknown', 'SPF domain ' + id + ' (from ' + r.identity + ') carries no result from the receiver.', 'The receiver did not record a check of the sending server.', r.src);
    return say(r.state, 'SPF ' + (SPF_WORD[r.result] || 'returned ' + r.result) + ' for ' + id + ip + note + '.' + (forwarded && /fail/.test(r.result) ? ' A forward sends from the forwarder\'s own server, which the sender\'s SPF record does not list.' : ''), 'The check of the sending server against ' + r.domain + ' came out ' + r.result + '.', r.src);
  }

  // Forwarding, from the ARC chain. An ARC set the final receiver sealed
  // itself is not a forward. The earliest forwarding set's
  // ARC-Authentication-Results holds what that forwarder saw on arrival.
  function forwardOf(auth, chain, from) {
    const op = chain.trust.operator;
    const opOf = (s) => HA.received.operatorOf(s.sealer.host) || HA.received.operatorOf(s.sealer.domain);
    const sets = auth.arc.instances.filter(s => !op || opOf(s) !== op);
    if (!sets.length) return { yes: false, by: [], writer: '', pre: [], preResult: '', intact: false, receiverArc: '', src: [] };
    const set = sets[0];
    const pre = set.preForward;
    const dm = pre.find(x => x.method === 'dmarc');
    let preResult = '';
    if (dm) preResult = dm.result;
    else if (pre.length && from.defined) {
      const ok = pre.some(x => x.result === 'pass' && (x.method === 'dkim' ? HA.auth.alignRow('dkim', P.domainOf(x.ids['header.d'] || x.ids['header.i'] || ''), 'pass', from).relaxed : x.method === 'spf' ? HA.auth.alignRow('spf', P.domainOf(x.ids['smtp.mailfrom'] || ''), 'pass', from).relaxed : false));
      preResult = ok ? 'pass' : 'fail';
    }
    return { yes: true, by: sets.map(s => s.sealer.domain || s.sealer.host || 'an unnamed forwarder'), writer: set.sealer.host || set.sealer.domain || 'the first forwarder', set: set.i, pre, preResult, derived: !dm && !!preResult, intact: auth.arc.state === 'pass', receiverArc: auth.arcResult ? auth.arcResult.result : '', src: uniq(sets.flatMap(s => s.src)), aarSrc: set.aar ? [set.aar.field] : set.src.slice() };
  }
  function preText(fw) {
    return joinList(fw.pre.filter(x => ['spf', 'dkim', 'dmarc'].includes(x.method)).map(x => {
      const id = x.ids['header.d'] || x.ids['header.from'] || x.ids['smtp.mailfrom'] || '';
      return x.method + '=' + x.result + (id ? ' (' + id + ')' : '');
    }));
  }

  // Mailing lists, from List-Id. A list that tags the subject or adds a
  // footer breaks the author's DKIM and sends the message on from its own
  // domain. Mailman and others keep what the list's server recorded on
  // arrival in Authentication-Results-Original (or X-Original-
  // Authentication-Results); it is quoted, never relied on.
  function listOf(ctx) {
    const { decoded, auth, message } = ctx;
    const fields = ctx.fields || [];
    const lid = decoded.list.find(i => i.key === 'List-Id');
    if (!lid) return { yes: false, take: false };
    const m = /<([^<>]+)>/.exec(lid.raw); // [^<>] keeps a long run of < linear
    const id = (m ? m[1] : lid.raw).trim().toLowerCase();
    const org = HA.psl.orgDomain(id) || id;
    const ofList = (d) => !!d && HA.psl.orgDomain(d) === org;
    const resent = auth.dkim.some(k => k.result === 'pass' && !k.relaxed && ofList(k.domain)) || (auth.spf.result === 'pass' && !auth.spf.relaxed && ofList(auth.spf.domain));
    const orig = fields.find(f => f.lower === 'authentication-results-original' || f.lower === 'x-original-authentication-results');
    const ar = orig ? HA.auth.parseAuthResults(orig.value) : null;
    const pre = ar ? ar.results.filter(x => ['spf', 'dkim', 'dmarc'].includes(x.method)) : [];
    const dmPre = pre.find(x => x.method === 'dmarc');
    const tag = /^\s*(?:(?:re|fwd?|aw)\s*:\s*)*(\[[^\]]+\])/i.exec(message.subject ? message.subject.value : '');
    return { yes: true, id, org, resent, broken: auth.dkim.filter(k => k.result === 'fail' && !ofList(k.domain)), writer: (ar && ar.authserv) || 'the list\'s server', origName: orig ? orig.name : '', pre, preResult: dmPre ? dmPre.result : '', preSrc: orig ? [orig.index] : [], tag: tag ? tag[1] : '', mailman: fields.some(f => f.lower === 'x-mailman-version'), src: lid.src };
  }

  // What the DMARC policy meant for this message, as far as the receiver
  // quoted it. Microsoft's oreject and pct.* are named, not interpreted:
  // auth.js keeps their disposition empty for the reason given there.
  // A subdomain From falls under the organizational domain's sp= when the
  // receiver quoted one.
  function consequenceOf(status, dm, from, receiver, org) {
    const pol = dm.policy, disp = dm.disposition;
    const src = dm.src;
    if (status === 'none') return say('caveat', from + ' publishes no DMARC policy, so nothing tells receivers what to do with mail that fails. Each receiver decides on its own.', from + ' has no DMARC setting, so it gives mail providers no instructions for fake mail. Each provider decides for itself.', src);
    if (status === 'unknown' || status === 'error') return null;
    if (pol.action) {
      const a = pol.action;
      const fails = status !== 'pass';
      const M = {
        none: fails ? 'Microsoft recorded action=none: it applied no DMARC action to this message.' : 'Microsoft recorded action=none; the message passed, so no action was needed.',
        quarantine: 'Microsoft recorded action=quarantine: the policy sent this message to junk or quarantine.',
        reject: 'Microsoft recorded action=reject.',
        oreject: 'Microsoft recorded action=oreject: the domain\'s policy is reject and Microsoft overrode it. Microsoft\'s own pages disagree on whether that means junk or quarantine, so the page does not say which. The message was not refused outright.',
        'pct.quarantine': 'Microsoft recorded action=pct.quarantine: the policy is quarantine with pct below 100, and this message was picked to be delivered anyway.',
        'pct.reject': 'Microsoft recorded action=pct.reject: the policy is reject with pct below 100, and this message was picked to be delivered anyway.',
      };
      const t = M[a] || 'Microsoft recorded action=' + a + ', which is not in its published list, so it is shown as written.';
      const plain = { quarantine: 'Microsoft put the message in junk or quarantine because of the sender\'s DMARC setting.', reject: 'Microsoft refused the message because of the sender\'s DMARC setting.', oreject: 'The sender\'s DMARC setting says to refuse fake mail. Microsoft kept the message but treated it as suspicious instead.', 'pct.quarantine': 'The sender\'s DMARC setting covers only part of its mail, and this message happened to be let through.', 'pct.reject': 'The sender\'s DMARC setting covers only part of its mail, and this message happened to be let through.' }[a] || (fails ? 'Microsoft took no action over the failure, so it didn\'t send the message to junk for this reason.' : 'The message passed, so the sender\'s DMARC setting didn\'t come into play.');
      return say(fails ? (a === 'none' || /^pct/.test(a) ? 'caveat' : 'fail') : 'pass', t, plain, src);
    }
    if (!pol.p) return say('unknown', receiver + ' did not quote the DMARC policy of ' + from + ', so the headers do not show what a failure means for this domain. The record is in DNS, which this page does not read.', 'The headers don\'t say what ' + from + ' asks mail providers to do with fake mail.', src);
    const sub = !!pol.sp && !!org && org !== from;
    const pv = sub ? pol.sp : pol.p, tag = sub ? 'sp=' : 'p=';
    const P_WORD = { none: 'which asks for no action', quarantine: 'which asks for failing mail to go to spam', reject: 'which asks for failing mail to be refused' };
    const pw = tag + pv + (sub ? ' for subdomains such as ' + from : '') + (P_WORD[pv] ? ', ' + P_WORD[pv] : '');
    const pub = (sub ? org : from) + ' publishes ' + pw;
    if (status === 'pass') return say('pass', pub + '. This message passed, so the policy did not come into play.', 'The message passed, so the sender\'s DMARC setting didn\'t come into play.', src);
    if (disp.source === 'dis') {
      const D = { none: 'did not apply it to this message', quarantine: 'sent this message to spam', reject: 'refused this message' };
      const did = D[disp.value] || 'recorded ' + disp.raw;
      return say(disp.value === 'none' ? 'caveat' : 'fail', pub + ', and ' + receiver + ' ' + did + ' (' + disp.raw + ').', (sub ? org : from) + '\'s DMARC setting ' + (pv === 'reject' ? 'asks providers to refuse fake mail' : pv === 'quarantine' ? 'asks providers to send fake mail to spam' : 'only watches and asks for no action') + '. ' + plainReceiver(receiver).replace(/^t/, 'T') + ' ' + did + '.', src);
    }
    return say('unknown', pub + '. The headers do not record what ' + receiver + ' did with this message.', 'The headers show ' + (sub ? org : from) + '\'s DMARC setting, but not what ' + plainReceiver(receiver) + ' did with this message.', src);
  }

  function fixesOf(status, ctx) {
    const { auth, svc, receiver, fw, dm } = ctx;
    const from = ctx.alignment.from.domain;
    const f = [];
    const add = (state, t, p, src) => f.push(say(state, t, p, src || []));
    if (status === 'unknown') {
      if (ctx.why === 'no-received') add('unknown', 'Paste the headers of the copy the recipient received. This copy never passed through a receiving server, so nothing was checked.', 'These headers come from a sent or draft copy. Open the message in the recipient\'s mailbox and copy its headers from there.');
      else if (ctx.why === 'two-from' || ctx.why === 'multi-domain') add('fail', 'Treat the message as suspicious: with no single From domain, DMARC cannot protect the recipient.', 'Do not trust this message. It names more than one sender, which is a common trick in forged mail.');
      else if (ctx.why === 'no-from') add('unknown', 'Paste the complete header block; there is no usable From address to check against.', 'The sender\'s address is missing, so copy the full headers again and make sure the From line is included.');
      else add('unknown', 'Get the same message from a Gmail or Microsoft 365 mailbox; both record SPF, DKIM and DMARC results.', 'Send the same message to a Gmail or Outlook mailbox and copy the headers from there. Those services write down the results this page needs.');
      return f;
    }
    if (status === 'forwarded') {
      add('caveat', 'Nothing at the sender fixes a forward. If the forward is yours, have the final mailbox trust the forwarder\'s ARC seal: Gmail weighs ARC on its own; Microsoft 365 honors it only for sealers an admin adds as trusted ARC sealers in the Defender portal.', 'The sender did nothing wrong. If you set up this forward, ask whoever runs the receiving mailbox to trust the forwarding service (' + fw.by[fw.by.length - 1] + '). In Microsoft 365, an administrator adds it under Trusted ARC sealers in the Defender portal.', fw.src);
      add('caveat', 'If the forward is not yours, authentication worked as designed. Judge the sender by a copy delivered straight to the mailbox.', 'If you did not set up this forward, there is nothing to change. Ask for a copy sent straight to you to check the sender.', fw.src);
      return f;
    }
    if (ctx.list && ctx.list.take) {
      const L = ctx.list, ok = L.preResult === 'pass';
      add('caveat', 'Nothing to change at ' + from + (ok ? ': its mail passed before the list.' : ' on the strength of this message.') + ' Mail through a list that changes messages fails DMARC unless the list rewrites the From address or the receiver trusts the list\'s ARC seal.', 'If you sent this, your setup is not the problem' + (ok ? '' : ' as far as these headers show') + '. Mailing lists that change messages break these checks. That\'s a known side effect.', L.preSrc.concat(L.src));
      add('caveat', 'If you run ' + L.id + ': ' + (L.mailman ? 'in Mailman, set DMARC mitigation to replace the From address with the list\'s own for every post, not only for domains with p=quarantine or p=reject' : 'have the list rewrite the From address to its own') + '; or stop tagging the subject and adding a footer; or ARC-seal outgoing mail so receivers that trust the seal see the result from before the list.', 'If you run the list: have it send under its own address (it can keep the sender\'s name), or stop it adding a subject tag and a footer.', L.src);
      return f;
    }
    // A forwarder claims a pass the receiver did not confirm: the failure
    // could be the forward or a forgery, and SPF here checked the forwarder.
    const unproven = fw.yes && fw.preResult === 'pass';
    if (unproven) add('caveat', 'Judge the sender by a copy delivered straight to the mailbox. The forwarder\'s record shows a pass before the forward, but the receiver did not confirm it, so this failure could come from the forward or from a forgery.', 'Ask for a copy sent straight to you, without the forward, and check that one. The forwarding service says the message passed before it forwarded it, but nothing here confirms that.', fw.src);
    if (fw.yes && fw.preResult === 'fail') add('fail', 'Look at the sender, not the forward: the message failed before it was forwarded. If ' + from + ' did not send it, it is forged and DMARC did its job.', 'The problem started before the forward. If ' + from + ' did not send this message, it is forged, and the failed check is working as it should.', fw.aarSrc);
    if (status === 'none') {
      add('caveat', 'Publish a DMARC record at _dmarc.' + from + ' with p=none and a rua= address, read the reports, then move to p=quarantine once every real source passes.', 'Ask whoever manages the DNS for ' + from + ' to add a DMARC record. Start with the setting that only sends reports, and tighten it once the reports show all your real mail passes.', dm.src);
    }
    if (status === 'error') {
      if (dm.result === 'permerror') add('fail', 'Fix the DMARC record at _dmarc.' + from + ': ' + receiver + ' could not parse it. Look for a mistyped tag, a missing v=DMARC1 at the start, or two records at the same name.', 'The sender\'s DMARC record is written wrong, so mail systems ignore it. Ask whoever manages the DNS for ' + from + ' to check the record named _dmarc.' + from + ' for typos, or for a second copy that should be deleted.', dm.src);
      else add('caveat', 'The DMARC lookup failed for a temporary reason, so there is nothing to fix from these headers. If it repeats, check the DNS hosting of ' + from + '.', 'The check failed for a temporary reason. If it keeps happening, ask whoever hosts the DNS for ' + from + ' whether their servers had trouble.', dm.src);
    }
    const dkimAligned = auth.dkim.some(k => k.result === 'pass' && k.relaxed);
    const spfAligned = auth.spf.result === 'pass' && auth.spf.relaxed;
    const unaligned = auth.dkim.find(k => k.result === 'pass' && !k.relaxed);
    const failed = auth.dkim.find(k => k.result === 'fail');
    const perm = auth.dkim.find(k => k.result === 'permerror');
    if (!dkimAligned) {
      if (!auth.dkim.length) add(status === 'pass' ? 'caveat' : 'fail', (status === 'pass' ? 'DMARC rests on SPF alone, and forwarding breaks SPF. ' : '') + 'Turn on DKIM signing for ' + from + ' at ' + svc.t + '. Aligned DKIM is what lets DMARC pass and keep passing when mail is forwarded.', 'Turn on email signing (DKIM) for ' + from + ' in the settings of ' + svc.p + '. It adds a digital signature with your domain to every message, and that signature still works when mail is forwarded.', auth.spf.src);
      else if (unaligned) add(status === 'pass' ? 'caveat' : 'fail', 'At ' + svc.t + ', set up domain authentication for ' + from + ' so the DKIM signature carries d=' + from + ' or a subdomain of it, instead of d=' + unaligned.domain + '.', 'In the settings of ' + svc.p + ', turn on domain authentication for ' + from + '. The service gives you a few DNS records to add, and after that your mail is signed with your own domain instead of ' + unaligned.domain + '.', unaligned.src);
      if (failed && !fw.yes) add('fail', 'The signature from d=' + failed.domain + ' broke between signing and ' + receiver + '. Look for anything that edits mail after ' + svc.t + ' signs it (a gateway, footer, disclaimer, or link rewriting), and check that the key at ' + (failed.selector || '<selector>') + '._domainkey.' + failed.domain + ' is the one it signs with.', 'The signature on this message was damaged on the way. Ask whoever manages your mail whether anything adds a footer, a disclaimer, or tracking links after messages leave ' + svc.p + '. That is the usual cause.', failed.src);
      if (perm) add('fail', 'Publish or repair the DKIM key at ' + (perm.selector || '<selector>') + '._domainkey.' + perm.domain + '; ' + receiver + ' could not use it.', 'The key that checks this signature could not be read. Ask whoever manages the DNS for ' + perm.domain + ' to compare the record named ' + (perm.selector || '<selector>') + '._domainkey.' + perm.domain + ' with what ' + svc.p + ' says it should be.', perm.src);
    }
    const s = auth.spf;
    if (s.domain && !/helo/i.test(s.identity) && !unproven) {
      if (s.result === 'fail' || s.result === 'softfail') add('fail', 'If this is your mail, add ' + svc.t + ' to the SPF record of ' + s.domain + (s.ip ? ' so it covers ' + s.ip : '') + '. If it is not, SPF did its job.', 'If you sent this, ask whoever manages the DNS for ' + s.domain + ' to add ' + svc.p + ' to its list of allowed servers (the SPF record). The service\'s setup page gives the exact entry. If you didn\'t send it, someone else used your domain and this check caught it.', s.src);
      else if (s.result === 'none') add('fail', 'Publish an SPF record for ' + s.domain + ' that lists the servers that send for it.', 'Ask whoever manages the DNS for ' + s.domain + ' to publish an SPF record listing the services that send your mail.', s.src);
      else if (s.result === 'permerror') add('fail', 'Repair the SPF record of ' + s.domain + ': check its syntax and keep it within 10 DNS lookups.', 'The SPF record for ' + s.domain + ' is broken, often because it lists too many services. Ask whoever manages its DNS to check and simplify it.', s.src);
      else if (s.result === 'pass' && !s.relaxed && !fw.yes && (dkimAligned || unaligned || !auth.dkim.length) && status !== 'pass') add('caveat', 'Second, after DKIM: set a custom Return-Path (bounce) domain under ' + from + ' at ' + svc.t + ' so SPF aligns too.', 'Once the signature is fixed, you can also give ' + svc.p + ' a custom return address on ' + from + '. Services call it a custom return path or sending domain. It\'s optional.', s.src);
    }
    if (status === 'pass') {
      if (!spfAligned && s.result === 'pass' && dkimAligned) add('pass', 'Alignment comes from DKIM alone, which is enough. For SPF to align too, set a custom Return-Path domain under ' + from + ' at ' + svc.t + '.', 'Nothing needs fixing. If you want both checks to match, give ' + svc.p + ' a custom return address on ' + from + ' (often called a custom return path).', s.src);
      // A mailbox provider's own domain is not the reader's to change.
      if (dm.policy.p === 'none' && !MAILBOX_OPERATORS.includes(HA.received.operatorOf(from))) add('caveat', from + ' publishes p=none, so forged mail is not stopped. Once aggregate reports show every real source passing, move to p=quarantine.', 'Your DMARC setting only watches. It doesn\'t stop fake mail that uses your domain. Once the DMARC reports show all your real mail passing, ask whoever manages the DNS for ' + from + ' to change it to quarantine.', dm.src);
    }
    if (!f.length && status !== 'pass') add('unknown', 'Nothing in these headers points at a single change. Compare with a copy of the same message delivered to a different mailbox provider.', 'These headers do not show one clear fix. Send the same message to another mailbox, such as Gmail or Outlook, and compare.');
    return f;
  }

  function limitsOf(ctx) {
    const { auth, alignment, chain, fw } = ctx;
    const l = [];
    if (alignment.modeNote) l.push(alignment.modeNote);
    const from = alignment.from;
    const relaxedRows = alignment.rows.filter(r => r.passed && r.relaxedOnly);
    const approx = [from].concat(alignment.rows).filter(x => x.approximate && x.domain);
    if (from.defined && (relaxedRows.length || approx.length)) {
      l.push(say('unknown', 'The organizational domain' + (from.org ? ' ' + from.org : '') + ' comes from a short built in suffix list, not from DNS or the full Public Suffix List that receivers use' + (approx.length ? '; for ' + Array.from(new Set(approx.map(x => x.domain))).join(', ') + ' it is an approximation' : '') + '. Relaxed alignment here rests on it.', 'This page works out where the sender\'s organization begins from its own short list, so the looser domain match is its best reading, not a certainty.', from.src.concat(relaxedRows.flatMap(r => r.src))));
    }
    if (chain.trust.operator === 'Google') l.push(say('unknown', 'Gmail writes no spam, Promotions or inbox placement decision into headers, so these headers cannot show where the message landed.', 'Gmail does not record in the headers whether it put the message in spam. Only the mailbox shows that.', []));
    if (fw.yes) l.push(say('unknown', 'ARC seals are not verified here, so the results before the forward are the forwarder\'s own record' + (fw.receiverArc === 'pass' ? '; ' + ctx.receiver + ' reported arc=pass, which means it did verify them.' : '.'), 'This page can\'t confirm the forwarding service\'s own record, so what it saw before the forward is taken on its word.', fw.src));
    return l;
  }

  function flagsOf(ctx) {
    const { message, auth, decoded, status } = ctx;
    const fl = [];
    const fa = message.from;
    if (fa && fa.display && /@/.test(fa.display)) {
      const m = fa.display.match(/[^\s<>"'()]+@[^\s<>"'()]+/);
      const dd = m ? P.domainOf(m[0]) : '';
      if (dd && fa.domain && HA.psl.orgDomain(dd) !== HA.psl.orgDomain(fa.domain)) fl.push(say('fail', 'The display name shows an address at ' + dd + ', while the real From domain is ' + fa.domain + '. That is a common impersonation layout.', 'The name shown for the sender contains an address at ' + dd + ', but the message really comes from ' + fa.domain + '. Forged mail often does this.', fa.src));
    }
    const untrustedPass = auth.all.filter(r => r.untrusted && r.entries.some(e => e.method === 'dmarc' && e.result === 'pass'));
    if (untrustedPass.length && status !== 'pass') fl.push(say('caveat', 'An Authentication-Results field the receiver did not write claims dmarc=pass. It is ignored here: the sender or a hop before the receiver could have written it.', 'One set of results in the headers claims the message passed, but the receiving system did not write it, so it is ignored.', untrustedPass.flatMap(r => r.src)));
    for (const it of decoded.list) if (it.key === 'Reply-To' && it.level === 'warn') fl.push(say('caveat', it.technical, it.plain, it.src));
    return fl;
  }

  function build(ctx) {
    const { message, chain, auth, alignment, decoded } = ctx;
    const from = alignment.from;
    const fd = from.domain;
    const receiver = receiverOf(auth, chain);
    const svc = serviceOf(decoded.platform);
    const dm = auth.dmarc;
    const fw = forwardOf(auth, chain, from);
    const list = listOf(ctx);
    // The list is blamed only when it re-sent the mail under its own domain
    // and its server did not record a failure before the list.
    list.take = list.yes && list.resent && !fw.yes && list.preResult !== 'fail';
    const c = Object.assign({}, ctx, { receiver, svc, fw, dm, list });
    const out = { status: 'unknown', state: 'unknown', headline: null, cause: null, consequence: null, details: [], fixes: [], flags: [], limits: [], forwarded: { yes: fw.yes, by: fw.by, preForward: fw.yes ? { writer: fw.writer, result: fw.preResult, derived: !!fw.derived, text: preText(fw), src: fw.aarSrc } : null, src: fw.src } };
    const finish = (status, headline, cause) => {
      out.status = status;
      out.state = status === 'pass' && dm.disagreement ? 'caveat' : STATE_OF[status];
      out.headline = headline; out.cause = withCompauth(cause, auth.compauth);
      out.consequence = consequenceOf(status, dm, fd, receiver, from.org);
      out.fixes = fixesOf(status, c);
      out.limits = from.defined && auth.primary >= 0 ? limitsOf(c) : [];
      out.flags = flagsOf(Object.assign({ status }, c));
      return out;
    };

    // Nothing to judge by.
    if (!from.defined) {
      c.why = from.why;
      const fdoms = message.from ? message.from.domains || [] : [];
      const T = { 'two-from': ['the message carries ' + numWord(message.fromCount) + ' From fields', 'the message names more than one sender'], 'multi-domain': ['the From field names addresses in ' + numWord(fdoms.length) + ' domains (' + joinList(fdoms) + ')', 'the sender line names addresses at more than one domain'], 'no-from': ['there is no usable From address', 'the sender\'s address is missing'] }[from.why];
      return finish('unknown', say(from.why === 'no-from' ? 'unknown' : 'fail', 'DMARC cannot be judged because ' + T[0] + ', so there is no single author domain to align with.', 'This page cannot check who sent the message, because ' + T[1] + '.', from.src),
        say('unknown', (from.why === 'no-from' ? 'DMARC aligns SPF and DKIM with the author domain, and without one there is nothing to align with. ' : 'DMARC checks one author domain. ') + (dm.reported ? receiver + ' still reported dmarc=' + dm.result + (dm.headerFrom ? ' for header.from=' + dm.headerFrom : '') + ', but which address it judged is not in the headers.' : 'Nothing is computed from any of the addresses.'), dm.reported ? 'The receiving system recorded a result, but the headers do not say which sender it checked.' : 'Without one clear sender there is nothing to check.', from.src.concat(dm.src)));
    }
    if (auth.primary < 0) {
      c.why = !chain.count ? 'no-received' : 'no-results';
      const sigs = auth.signatures.map(s => 'd=' + s.d + (HA.auth.alignRow('dkim', s.d, 'pass', from).relaxed ? ' (would align)' : ' (would not align)'));
      out.details = sigs.length ? [say('unknown', 'DKIM signatures present, not checked by any receiver here: ' + joinList(sigs) + '.', 'The message carries a signature, but no receiver\'s check of it is recorded.', auth.signatures.flatMap(s => s.src))] : [];
      if (!chain.count) return finish('unknown', say('unknown', 'Nothing was checked because these headers have no Received fields: this is a sent or draft copy, and SPF, DKIM and DMARC are checked only by a receiving server.', 'This is the sender\'s own copy, so no mail system has checked it yet.', []),
        say('unknown', 'A receiver writes Authentication-Results when it accepts the message. A copy that was never received has none.', 'The checks happen when a message arrives, and this copy never arrived anywhere.', []));
      const rcv = chain.trust.operator || 'the receiving server';
      return finish('unknown', say('unknown', auth.all.length ? 'Nothing can be judged because no Authentication-Results field here was written by ' + rcv + '; ' + (auth.all.length === 1 ? 'the one present was' : 'the ' + numWord(auth.all.length) + ' present were') + ' written before it took custody or cannot be tied to it.' : 'Nothing can be judged because there is no Authentication-Results field: ' + rcv + ' recorded no SPF, DKIM or DMARC result here.', 'The receiving mail system did not record its checks in these headers.', auth.all.flatMap(r => r.src)),
        say('unknown', 'Some servers skip Authentication-Results, and some mail programs strip it when exporting. Results written by anyone else could be forged, so they are not used.', 'Without the receiver\'s own record there is nothing trustworthy to read.', auth.all.flatMap(r => r.src)));
    }
    const primary = auth.all[auth.primary];
    if (!dm.reported && !auth.spf.result && auth.dkim.every(k => !k.result)) {
      c.why = 'no-results';
      return finish('unknown', say('unknown', receiver + ' wrote Authentication-Results but recorded no SPF, DKIM or DMARC result in it, so there is nothing to judge.', 'The receiving mail system recorded no checks for this message.', primary.src),
        say('unknown', 'The field is there, but it lists no method this page reads' + (primary.none ? ' (it reports none).' : '.'), 'There is nothing in the record to go on.', primary.src));
    }

    const via = fw.yes ? 'forward' : list.take ? 'list' : '';
    for (const k of auth.dkim) out.details.push(rowSentence(k, fd, via));
    out.details.push(rowSentence(auth.spf, fd, via));
    const allSrc = uniq(dm.src.concat(auth.computed.src));

    // Reported result first; computed only when the receiver wrote none.
    const result = dm.reported ? dm.result : auth.computed.result;
    const computedOnly = !dm.reported;
    const lead = computedOnly ? receiver + ' recorded no DMARC result; worked out from the identifiers, DMARC ' : 'DMARC at ' + receiver + ' ';
    const plainLead = computedOnly ? 'The receiving system did not record the sender check, so this page worked it out. This message ' : 'This message ';

    if (dm.disagreement) out.details.push(say(dm.disagreement.state, dm.disagreement.technical, dm.disagreement.plain, dm.disagreement.src));
    for (const g of decoded.filters) if (g.outcome) out.details.push(say(LEVEL_STATE[g.outcome.level], g.name + ', ' + g.outcome.key + ' ' + g.outcome.raw + ': ' + g.outcome.technical, g.name + ': ' + g.outcome.plain, g.outcome.src));
    const listId = decoded.list.find(i => i.key === 'List-Id');

    if (result === 'pass') {
      const pp = passPieces(auth);
      if (pp.length) {
        const cl = passClause(pp, fd);
        const head = say(computedOnly ? 'caveat' : 'pass', lead + (computedOnly ? 'passes' : 'passed') + ' because ' + cl.t, plainLead + 'passed the sender check (DMARC). ' + upFirst(cl.p), uniq(pp.flatMap(x => x.src).concat(from.src)));
        const dkimCarries = auth.dkim.some(k => k.result === 'pass' && k.relaxed), spfCarries = auth.spf.result === 'pass' && auth.spf.relaxed;
        const lasts = dkimCarries && spfCarries ? 'For ' + fd + ', both SPF and DKIM carry the pass, so it survives a forward that breaks SPF.' : dkimCarries ? 'For ' + fd + ', aligned DKIM carries the pass, and it survives forwarding as long as nothing alters the signed headers or body.' : 'For ' + fd + ', only SPF carries the pass. A forward or a mailing list breaks it, because SPF checks whichever server hands the message over; aligned DKIM would keep it.';
        const cause = say('pass', lasts + (computedOnly ? ' Worked out here; the receiver recorded no DMARC result.' : '') + (fw.yes ? ' The message was forwarded by ' + joinList(fw.by) + ' and still passed.' : ''), 'A message passes when it is signed by, or sent for, the domain in its From address, and this one was.', allSrc);
        return finish('pass', head, cause);
      }
      // Reported pass with nothing aligned: say why the receiver passed it.
      const d = dm.disagreement;
      const why = d && d.reason === 'arc-override' ? 'it trusted the ARC record from ' + joinList(fw.by.length ? fw.by : auth.arc.sealers.filter(Boolean)) + ', whose results before the forward show a pass' : 'of a local policy or a result it did not write into these headers';
      const fp = failPieces(auth);
      return finish('pass', say('caveat', 'DMARC passed at ' + receiver + ' only because ' + why + '; in these headers ' + joinList(fp.map(x => x.t)) + ', and nothing aligned with the From domain ' + fd + '.', 'This message was let through on trust: its own checks do not match ' + fd + ', but the receiving system accepted ' + (d && d.reason === 'arc-override' ? 'the forwarder\'s word that they passed earlier.' : 'it under its own rules.'), uniq(fp.flatMap(x => x.src).concat(dm.src))),
        say('caveat', d ? d.technical : 'The receiver reported dmarc=pass with no aligned pass in these headers.', d ? d.plain : 'The receiving system passed the message for reasons the headers do not show.', allSrc));
    }

    if (result === 'none' || result === 'bestguesspass') {
      const comp = auth.computed;
      const would = comp.result === 'pass' ? 'pass, because ' + passClause(passPieces(auth), fd).t : 'fail, because ' + failClause(failPieces(auth), fd).t;
      const head = result === 'bestguesspass'
        ? say('caveat', 'DMARC did not apply: ' + receiver + ' reported dmarc=bestguesspass, meaning ' + fd + ' has no DMARC record but the message would pass if it had one.', fd + ' has no DMARC setting, so the sender check didn\'t apply. The message would pass if the domain had one.', dm.src)
        : say('caveat', 'DMARC did not apply because ' + receiver + ' found no DMARC record for ' + fd + '; with one, this message would ' + comp.result + '.', fd + ' has no DMARC setting, so the sender check didn\'t apply. With one, this message would ' + (comp.result === 'pass' ? 'pass.' : 'fail.'), allSrc);
      return finish('none', head, say('caveat', 'Without a DMARC record nothing ties SPF and DKIM to the From domain, so a receiver judges the message on its own signals, and anyone can put ' + fd + ' in a From address without failing a policy. With a record this message would ' + would, 'Without a DMARC setting, nothing stops others from sending mail that claims to be from ' + fd + '. ' + (comp.result === 'pass' ? 'This message is set up to pass once there is one.' : 'This message wouldn\'t pass if one were added.'), allSrc));
    }

    if (result === 'permerror' || result === 'temperror') {
      const perm = result === 'permerror';
      return finish('error', say('caveat', 'DMARC could not be evaluated because ' + receiver + ' hit ' + (perm ? 'a permanent error reading the DMARC record' : 'a temporary DNS error looking up the DMARC record') + ' for ' + fd + ' (dmarc=' + result + ').', 'The sender check could not run because ' + (perm ? 'the DMARC record of ' + fd + ' is written wrong.' : 'looking up the DMARC record of ' + fd + ' failed for a temporary reason.'), dm.src),
        say('caveat', (perm ? 'A permanent error means the record exists but cannot be read: a syntax mistake, a missing v=DMARC1, or more than one record. ' : 'A temporary error says nothing about the record itself. ') + 'Computed from the identifiers, the message ' + (auth.computed.result === 'pass' ? 'would pass.' : 'would fail.'), perm ? 'The record is there but broken, so mail systems treat the domain as if it had none.' : 'The lookup failed this time. The next one may work.', allSrc));
    }

    if (result !== 'fail') {
      return finish('unknown', say('unknown', receiver + ' reported dmarc=' + result + ', a result outside RFC 7489, so it is shown as written.', 'The receiving system recorded a sender check result this page does not know.', dm.src),
        say('unknown', 'The identifiers are in the details below; the page does not guess what the receiver meant.', 'The details below show what was checked.', dm.src));
    }

    // Failed. Forwarded mail first: blame the forward when the forwarder's
    // record shows a pass on arrival, the chain holds together, and the
    // receiver vouched for the seals (arc=pass, or Microsoft compauth
    // reason 130). The page does not verify seals, and a sender can write
    // an i=1 set of its own.
    const fp = failPieces(auth);
    const fcl = failClause(fp, fd);
    if (fw.yes) {
      const pre = preText(fw);
      const preSay = 'before the forward, ' + fw.writer + ' recorded ' + (pre || 'no results') + (fw.derived ? ', which aligns with ' + fd : '');
      const vouched = fw.receiverArc === 'pass' || !!(auth.compauth && auth.compauth.reason === '130');
      if (fw.preResult === 'pass' && fw.intact && vouched) {
        const after = joinList(fp.map(x => x.t));
        const head = say('caveat', lead + (computedOnly ? 'fails' : 'failed') + ' because the message was forwarded by ' + joinList(fw.by) + ': ' + preSay + ', and after it ' + after + '.', plainLead + 'failed the sender check (DMARC) because it was forwarded by ' + joinList(fw.by) + '. It passed before the forward, and the forward broke it.', uniq(fw.aarSrc.concat(fp.flatMap(x => x.src))));
        const broke = [];
        if (fw.pre.some(x => x.method === 'spf' && x.result === 'pass') && !(auth.spf.result === 'pass' && auth.spf.relaxed)) broke.push('The forward broke SPF: it sent the message on from ' + (auth.spf.ip || 'its own server') + (!auth.spf.domain ? '.' : auth.spf.result === 'pass' ? ', so SPF now checks ' + auth.spf.domain + ', which is not ' + fd + '.' : ', which the SPF record of ' + auth.spf.domain + ' does not authorize (spf=' + auth.spf.result + ').'));
        const dkBroke = auth.dkim.filter(k => k.result === 'fail' && fw.pre.some(x => x.method === 'dkim' && x.result === 'pass' && P.domainOf(x.ids['header.d'] || x.ids['header.i'] || '') === k.domain));
        if (dkBroke.length) broke.push('It also broke the DKIM signature from ' + joinList(dkBroke.map(k => k.domain)) + ' by changing the message.');
        const cause = say('caveat', 'The failure belongs to the forward, not to the sender. The message passed on arrival at ' + fw.writer + '. ' + (broke.length ? broke.join(' ').replace(/^It also broke/, 'The forward broke') : 'After the forward nothing aligned with ' + fd + '.'), 'The sender set things up correctly. Forwarding changed the message on the way, which is a known side effect of forwarding.', uniq(fw.aarSrc.concat(fp.flatMap(x => x.src))));
        out.forwarded.blamed = true;
        return finish('forwarded', head, cause);
      }
      if (fw.preResult === 'fail') {
        out.details.push(say('fail', 'The forward is not the cause: ' + preSay + ', so the message was already failing when it arrived there.', 'The message already failed the check before it was forwarded, so the problem is at the sender.', fw.aarSrc));
      } else if (fw.preResult === 'pass') {
        out.details.push(say('caveat', 'The forwarder\'s record says ' + preSay + ', but ' + (!fw.intact ? 'the ARC chain is broken' : fw.receiverArc === 'fail' ? receiver + ' reported arc=fail' : receiver + ' did not report arc=pass, and this page does not verify ARC seals') + ', so that record is not relied on and the failure is not blamed on the forward.', 'The forwarder claims the message passed before it was forwarded, but its record does not hold up, so this page does not rely on it.', fw.src.concat(auth.arcResult ? auth.arcResult.src : [])));
      }
    } else if (list.take) {
      const bd = Array.from(new Set(list.broken.map(k => k.domain)));
      const head = say('caveat', 'DMARC failed because the message came through the mailing list ' + list.id + ', which ' + (bd.length ? 'changed it, breaking the DKIM signature' + (bd.length > 1 ? 's' : '') + ' from ' + joinList(bd) + ', and ' : '') + 'sent it on as ' + list.org + ', which does not align with the From domain ' + fd + ' (RFC5322.From).',
        'This message failed the sender check (DMARC) because it came through the mailing list ' + list.id + '. The list ' + (bd.length ? 'changed the message, which broke the sender\'s signature, and ' : '') + 'sent it on under its own domain, ' + list.org + ', not ' + fd + '.', uniq(list.src.concat(list.broken.flatMap(k => k.src), auth.spf.src)));
      const how = list.tag ? ' The subject carries the list tag ' + list.tag + ', one such change; a footer added to the body is another.' : ' Lists break signatures by tagging the subject or adding a footer.';
      const howPlain = list.tag ? ', for example by adding ' + list.tag + ' to the subject.' : ', for example by adding a footer.';
      const cause = list.pre.length
        ? say('caveat', 'Before the list, ' + list.writer + ' recorded ' + preText(list) + ' in its ' + list.origName + ' field. The list\'s own server wrote that record and this page cannot verify it' + (list.preResult === 'pass' ? ', but it shows the message passed on arrival.' : '.') + how,
          list.preResult === 'pass' ? 'Before the list, the list\'s own server recorded that the message passed. The sender\'s setup looks fine. The list broke the checks by changing the message' + howPlain : 'The list\'s own server kept a record of the checks before the list, but it does not show a clear pass. The list changed the message' + howPlain, uniq(list.preSrc.concat(list.src)))
        : say('caveat', 'No record from before the list is in the headers, so this page cannot show that the message passed before the list changed it.' + how, 'The headers carry no record of how the message looked before the list, so this page cannot confirm the sender\'s own setup. Lists break these checks by changing the message' + howPlain, list.src);
      return finish('fail', head, cause);
    } else if (listId) {
      out.details.push(say('caveat', 'List-Id ' + listId.raw + ' shows the message came through a mailing list, and lists often change the subject or body. With no ARC record there is no result from before the list to compare with.', 'The message came through a mailing list, which can break these checks. The headers carry no record of how it looked before the list.', listId.src));
    }

    const d = dm.disagreement;
    if (d && d.reason === 'strict-mode') {
      const pp = passPieces(auth);
      return finish('fail', say('fail', lead + (computedOnly ? 'fails' : 'failed') + ' even though ' + joinList(pp.map(x => x.t)) + ' aligns with ' + fd + ' in relaxed mode, so the DMARC record most likely requires strict alignment (' + joinList(auth.computed.tags.map(t => t + '=s'), 'or') + '); the record itself is not in the headers.', plainLead + 'failed the sender check (DMARC) although it was signed by a domain in the same organization as ' + fd + '. The sender\'s DMARC setting probably demands an exact domain match.', uniq(pp.flatMap(x => x.src).concat(dm.src))),
        say('caveat', d.technical, d.plain, d.src));
    }
    if (d) {
      const pp = passPieces(auth);
      return finish('fail', say('fail', lead + 'failed at ' + receiver + ' even though ' + joinList(pp.map(x => x.t)) + ' aligns with the From domain ' + fd + '.', plainLead + 'failed the sender check (DMARC), though it was signed for ' + fd + '. The receiving system judged it differently from this page.', uniq(pp.flatMap(x => x.src).concat(dm.src))),
        say('caveat', d.technical, d.plain, d.src));
    }
    const head = say('fail', lead + (computedOnly ? 'fails' : 'failed') + ' because ' + fcl.t, plainLead + (computedOnly ? 'fails' : 'failed') + ' the sender check (DMARC). ' + upFirst(fcl.p), uniq(fp.flatMap(x => x.src).concat(from.src, dm.src)));
    return finish('fail', head, fw.yes && fw.preResult === 'fail'
      ? say('fail', 'The message was already failing before the forward: ' + fw.writer + ' recorded ' + (preText(fw) || 'no passing result') + '. ' + (auth.spf.result === 'pass' && !auth.spf.relaxed && auth.spf.domain ? 'SPF now passes only for the forwarder\'s domain ' + auth.spf.domain + ', which does not count for ' + fd + '.' : 'Nothing after the forward aligns with ' + fd + ' either.'), 'The message failed the check before it was ever forwarded, so the problem is with the sender, not the forward.', uniq(fw.aarSrc.concat(auth.spf.src)))
      : causeOfFail(auth, fd, receiver, svc));
  }

  // Microsoft's composite authentication is its own stated reason, so the
  // cause quotes it when the receiver wrote one.
  function withCompauth(cause, c) {
    if (!cause || !c) return cause;
    const m = HA.providers.compauthMeaning(c.reason);
    const t = 'Microsoft recorded compauth=' + c.result + (c.reason ? ' reason=' + c.reason : '') + (m ? ', meaning ' + m + '.' : c.reason ? ', a code not in its published table.' : '.');
    return say(cause.state, cause.technical + ' ' + t, cause.plain + ({ fail: ' Microsoft\'s own sender check failed it too.', pass: ' Microsoft\'s own sender check still passed it.', softpass: ' Microsoft\'s own sender check gave it a soft pass.' }[c.result] || ''), uniq(cause.src.concat(c.src)));
  }

  // The mechanism behind a failure, in a sentence or two.
  function causeOfFail(auth, fd, receiver, svc) {
    const src = uniq(auth.dkim.flatMap(k => k.src).concat(auth.spf.src));
    const passedElsewhere = auth.dkim.filter(k => k.result === 'pass' && !k.relaxed).map(k => k.domain).concat(auth.spf.result === 'pass' && !auth.spf.relaxed && auth.spf.domain ? [auth.spf.domain] : []);
    const failedSig = auth.dkim.find(k => k.result === 'fail');
    const dkimErr = auth.dkim.find(k => k.result && !['pass', 'fail'].includes(k.result));
    const spf = auth.spf;
    const spfFailed = ['fail', 'softfail'].includes(spf.result);
    const spfErr = ['none', 'neutral', 'permerror', 'temperror'].includes(spf.result) && spf.domain;
    const heloOnly = spf.result === 'pass' && !spf.relaxed && /helo/i.test(spf.identity) && !auth.dkim.some(k => k.result === 'pass');
    if (heloOnly && !failedSig && !dkimErr) return say('fail', 'SPF passed only for the server name ' + spf.domain + ', which is not ' + fd + '. The bounce address was empty, so SPF checked the name the sending server gave itself (HELO) instead of a sender domain, and nothing else passed for ' + fd + '.', 'The message had no hidden return address (Return-Path), so the only check that passed was on the sending server\'s own name, which does not belong to ' + fd + '.', src);
    if (passedElsewhere.length && !failedSig && !dkimErr && !spfFailed && !spfErr) {
      const own = svc.t === 'the sending service' ? 'the sending service\'s own' : svc.t + '\'s own';
      return say('fail', 'The checks passed, but for ' + joinList(Array.from(new Set(passedElsewhere))) + ', ' + (passedElsewhere.length === 1 ? 'a domain' : 'domains') + ' that ' + (passedElsewhere.length === 1 ? 'is' : 'are') + ' not ' + fd + '. That is what happens when ' + own + ' domain signs and bounces the mail. DMARC counts a pass only on the From domain or, in relaxed mode, its organizational domain.', 'The service sending this mail is using its own domain instead of ' + fd + ', so the checks pass for the service but not for the sender.', src);
    }
    const parts = [];
    const ip = spf.ip ? ', ' + spf.ip + ',' : '';
    if (!auth.dkim.length) parts.push('There is no DKIM signature, so DMARC rests on SPF alone.');
    const elsewhere = auth.dkim.filter(k => k.result === 'pass' && !k.relaxed).map(k => k.domain);
    if (elsewhere.length) parts.push('DKIM passed only for ' + joinList(elsewhere) + ', which is not ' + fd + '.');
    if (failedSig) parts.push('The DKIM signature from ' + failedSig.domain + ' did not verify at ' + receiver + (failedSig.comments && failedSig.comments[0] ? ' (' + failedSig.comments[0] + ')' : '') + ': something changed the signed part of the message after signing, or the key in DNS does not match.');
    if (dkimErr) parts.push({ permerror: 'The DKIM signature from ' + dkimErr.domain + ' could not be checked at ' + receiver + ' (dkim=permerror): the key at ' + (dkimErr.selector || '<selector>') + '._domainkey.' + dkimErr.domain + ' is missing or unreadable, or the signature itself is malformed.', temperror: 'The DKIM signature from ' + dkimErr.domain + ' could not be checked at ' + receiver + ' (dkim=temperror): a temporary DNS error kept it from fetching the key.' }[dkimErr.result] || 'DKIM for ' + dkimErr.domain + ' returned ' + dkimErr.result + ' at ' + receiver + ', which is not a pass.');
    if (spf.result === 'fail') parts.push('The server that handed the message over' + ip + ' is not authorized by the SPF record of ' + spf.domain + ', as ' + receiver + ' reported.');
    if (spf.result === 'softfail') parts.push('The SPF record of ' + spf.domain + ' does not authorize the server that handed the message over' + ip + ' and asks receivers to treat it as suspicious rather than fail it outright (softfail), as ' + receiver + ' reported.');
    if (spfErr) parts.push({ none: spf.domain + ' publishes no SPF record, so SPF could not pass.', neutral: 'The SPF record of ' + spf.domain + ' makes no statement about the server that handed the message over (neutral), so SPF did not pass.', permerror: 'The SPF record of ' + spf.domain + ' could not be evaluated (permerror): it has a syntax error or needs more than 10 DNS lookups.', temperror: 'A temporary DNS error kept ' + receiver + ' from evaluating the SPF record of ' + spf.domain + ' (temperror).' }[spf.result]);
    if (spf.result === 'pass' && !spf.relaxed && spf.domain) parts.push('SPF passed only for ' + (/helo/i.test(spf.identity) ? 'the server name ' : '') + spf.domain + ', which is not ' + fd + '.');
    if (!parts.length) parts.push('Neither SPF nor DKIM produced a pass on a domain that aligns with ' + fd + '.');
    const plain = failedSig ? 'The message was changed after it was signed, or the signature does not match the sender\'s published key.'
      : dkimErr ? 'The signature on the message could not be checked, and nothing else proves it came from ' + fd + '.'
        : spfFailed ? 'The server that sent this is not on the sender\'s list of approved servers (SPF).'
          : spf.result === 'none' && spfErr ? 'The sender\'s domain publishes no list of approved servers, and nothing else proves the mail came from ' + fd + '.'
            : spfErr ? 'The sender\'s list of approved servers (SPF) could not be read, and nothing else proves the mail came from ' + fd + '.'
              : 'Nothing in the message proves it came from ' + fd + '.';
    return say('fail', parts.join(' '), plain, src);
  }

  HA.finding = { build, forwardOf, joinList };
  // Node: require() returns this layer; the browser reads HA instead.
  if (typeof module !== 'undefined' && module.exports) module.exports = HA.finding;
})(typeof globalThis !== 'undefined' ? globalThis : this);
