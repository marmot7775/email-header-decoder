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
    if (k.result === 'pass' && !k.relaxed) return { t: 'DKIM signed as ' + d, p: 'it was signed by ' + d, unaligned: true, src: k.src };
    if (k.result === 'pass') return null;
    if (k.result === 'fail') return { t: 'the DKIM signature from ' + d + ' failed', p: 'the signature from ' + d + ' did not check out', src: k.src };
    if (!k.result) return { t: 'the DKIM signature from ' + d + ' has no recorded result', p: 'the signature from ' + d + ' was not checked', src: k.src };
    return { t: 'DKIM for ' + d + ' returned ' + k.result, p: 'the signature from ' + d + ' could not be checked', src: k.src };
  }
  function spfPiece(spf) {
    const helo = /helo/i.test(spf.identity);
    const d = spf.domain;
    if (!spf.result) return { t: 'no SPF result was recorded', p: 'no check of the sending server was recorded', src: spf.src };
    if (!d) return { t: 'SPF returned ' + spf.result + ' with no domain named', p: 'the sending server check named no domain', src: spf.src };
    const name = helo ? 'the server name ' + d : d;
    if (spf.result === 'pass' && !spf.relaxed) return { t: 'SPF checked ' + name, p: helo ? 'the sending server called itself ' + d : 'its bounce address was at ' + d, unaligned: true, src: spf.src };
    if (spf.result === 'pass') return null;
    const plain = { fail: 'the sending server is not on ' + d + '\'s list of approved servers', softfail: 'the sending server is not on ' + d + '\'s list of approved servers', none: d + ' publishes no list of approved servers' }[spf.result] || 'the sending server check for ' + d + ' came out ' + spf.result;
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
  function failClause(pieces, from) {
    const un = pieces.filter(x => x.unaligned).length;
    const t = joinList(pieces.map(x => x.t));
    const p = joinList(pieces.map(x => x.p));
    if (un && un === pieces.length) return { t: t + ', so ' + (un === 1 ? 'it did not align' : 'neither aligned') + ' with the From domain ' + from + '.', p: p + ', and ' + (un === 1 ? 'that does not belong' : 'neither belongs') + ' to ' + from + ', the domain in the From address.' };
    if (un) return { t: t + ', and nothing that passed aligned with the From domain ' + from + '.', p: p + '. Nothing that checked out belongs to ' + from + ', the domain in the From address.' };
    return { t: t + ', so no check passed for the From domain ' + from + '.', p: p + ', so nothing proved the mail came from ' + from + '.' };
  }
  function passPieces(auth) {
    const out = [];
    for (const k of auth.dkim) if (k.result === 'pass' && k.relaxed) out.push({ t: 'DKIM signed as ' + k.domain, p: 'it was signed by ' + k.domain, relaxedOnly: k.relaxedOnly, src: k.src });
    const s = auth.spf;
    if (s.result === 'pass' && s.relaxed) out.push({ t: 'SPF checked ' + s.domain, p: 'its bounce address was at ' + s.domain, relaxedOnly: s.relaxedOnly, src: s.src });
    return out;
  }
  function passClause(pieces, from) {
    const relaxed = pieces.some(x => x.relaxedOnly) ? ' (relaxed alignment, through the organizational domain)' : '';
    return {
      t: joinList(pieces.map(x => x.t)) + ', ' + (pieces.length === 1 ? 'which aligns' : 'both aligned') + ' with the From domain ' + from + relaxed + '.',
      p: joinList(pieces.map(x => x.p)) + ', and ' + (pieces.length === 1 ? 'that belongs' : 'both belong') + ' to ' + (relaxed ? 'the same organization as ' + from : from) + ', the domain in the From address.',
    };
  }

  // Per identifier, the longer statement the details list carries.
  function rowSentence(r, from, forwarded) {
    const note = r.comments && r.comments[0] && r.comments[0].length <= 80 ? ' (' + r.comments[0] + ')' : '';
    if (r.kind === 'dkim') {
      const d = r.domain || 'an unnamed domain';
      const sel = r.selector ? ' s=' + r.selector : '';
      if (r.ambiguous) return say('unknown', 'A DKIM result for d=' + d + ' names neither s= nor b=, and two signatures carry d=' + d + ', so this page cannot tell which one it describes.', 'One signature result could belong to either of two signatures, so this page does not pick one.', r.src);
      if (!r.result) return say('unknown', 'DKIM-Signature d=' + d + sel + ' carries no result from the receiver.', 'One signature on the message was not checked by the receiver.', r.src);
      if (r.result === 'pass') return r.relaxed
        ? say('pass', 'DKIM passed for d=' + d + sel + ', which aligns with ' + from + (r.relaxedOnly ? ' in relaxed mode only.' : '.'), 'The message was signed by ' + d + ', which belongs to the sender.', r.src)
        : say('caveat', 'DKIM passed for d=' + d + sel + ', which does not align with ' + from + '. A pass on another domain does not count for DMARC.', 'The message was signed, but by ' + d + ', not by the sender\'s own domain.', r.src);
      if (r.result === 'fail') return say('fail', 'DKIM failed for d=' + d + sel + note + '.' + (forwarded ? ' The message was forwarded, and forwarders often change it enough to break the signature.' : ' Something changed the signed headers or body after signing, or the key in DNS does not match; the headers cannot show which.'), 'The signature from ' + d + ' did not check out' + (forwarded ? ', most likely because the forward changed the message.' : '.'), r.src);
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

  // What the DMARC policy meant for this message, as far as the receiver
  // quoted it. Microsoft's oreject and pct.* are named, not interpreted:
  // auth.js keeps their disposition empty for the reason given there.
  function consequenceOf(status, dm, from, receiver) {
    const pol = dm.policy, disp = dm.disposition;
    const src = dm.src;
    if (status === 'none') return say('caveat', from + ' publishes no DMARC policy, so nothing tells receivers what to do with mail that fails. Each receiver decides on its own.', 'The sender\'s domain gives mail systems no instructions for forged mail, so each one decides for itself.', src);
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
      const plain = { quarantine: 'Microsoft put the message in junk or quarantine because of the sender\'s policy.', oreject: 'The sender\'s policy says to refuse forged mail. Microsoft kept the message but treated it as suspicious instead.', 'pct.quarantine': 'The sender\'s policy only applies to part of its mail, and this message happened to be let through.', 'pct.reject': 'The sender\'s policy only applies to part of its mail, and this message happened to be let through.' }[a] || (fails ? 'Microsoft did not act on the sender\'s policy for this message.' : 'The message passed, so the sender\'s policy did not come into play.');
      return say(fails ? (a === 'none' || /^pct/.test(a) ? 'caveat' : 'fail') : 'pass', t, plain, src);
    }
    if (!pol.p) return say('unknown', receiver + ' did not quote the DMARC policy of ' + from + ', so the headers do not show what a failure means for this domain. The record is in DNS, which this page does not read.', 'The headers do not say what the sender\'s domain asks mail systems to do with forged mail.', src);
    const P_WORD = { none: 'p=none, which asks for no action', quarantine: 'p=quarantine, which asks for failing mail to go to spam', reject: 'p=reject, which asks for failing mail to be refused' };
    const pw = P_WORD[pol.p] || 'p=' + pol.p;
    if (status === 'pass') return say('pass', from + ' publishes ' + pw + '. This message passed, so the policy did not come into play.', 'The message passed, so the sender\'s policy did not come into play.', src);
    if (disp.source === 'dis') {
      const D = { none: 'did not apply it to this message', quarantine: 'sent this message to spam', reject: 'refused this message' };
      const did = D[disp.value] || 'recorded ' + disp.raw;
      return say(disp.value === 'none' ? 'caveat' : 'fail', from + ' publishes ' + pw + ', and ' + receiver + ' ' + did + ' (' + disp.raw + ').', 'The sender\'s domain asks for ' + (pol.p === 'reject' ? 'forged mail to be refused' : pol.p === 'quarantine' ? 'forged mail to go to spam' : 'no action') + '. The receiving system (' + receiver + ') ' + did + '.', src);
    }
    return say('unknown', from + ' publishes ' + pw + '. The headers do not record what ' + receiver + ' did with this message.', 'The headers say what the sender\'s domain asks for, but not what was done with this message.', src);
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
      add('caveat', 'Nothing at the sender fixes a forward. If the forward is yours, have the final mailbox trust the forwarder\'s ARC seal: Gmail weighs ARC on its own; Microsoft 365 honors it only for sealers an admin adds as trusted ARC sealers in the Defender portal.', 'The sender did nothing wrong. If you set up this forward, ask whoever runs the receiving mailbox to trust the forwarding service (' + fw.by[fw.by.length - 1] + '). In Microsoft 365 an administrator adds it as a trusted ARC sealer.', fw.src);
      add('caveat', 'If the forward is not yours, authentication worked as designed. Judge the sender by a copy delivered straight to the mailbox.', 'If you did not set up this forward, there is nothing to change. Ask for a copy sent straight to you to check the sender.', fw.src);
      return f;
    }
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
      if (!auth.dkim.length) add(status === 'pass' ? 'caveat' : 'fail', (status === 'pass' ? 'DMARC rests on SPF alone, and forwarding breaks SPF. ' : '') + 'Turn on DKIM signing for ' + from + ' at ' + svc.t + '. Aligned DKIM is what lets DMARC pass and keep passing when mail is forwarded.', 'Turn on DKIM for ' + from + ' in the settings of ' + svc.p + '. It adds a signature with your domain to every message, and that signature still works when mail is forwarded.', auth.spf.src);
      else if (unaligned) add(status === 'pass' ? 'caveat' : 'fail', 'At ' + svc.t + ', set up domain authentication for ' + from + ' so the DKIM signature carries d=' + from + ' or a subdomain of it, instead of d=' + unaligned.domain + '.', 'In the settings of ' + svc.p + ', turn on domain authentication for ' + from + '. The service gives you a few DNS records to add, and after that your mail is signed with your own domain instead of ' + unaligned.domain + '.', unaligned.src);
      if (failed && !fw.yes) add('fail', 'The signature from d=' + failed.domain + ' broke between signing and ' + receiver + '. Look for anything that edits mail after ' + svc.t + ' signs it (a gateway, footer, disclaimer, or link rewriting), and check that the key at ' + (failed.selector || '<selector>') + '._domainkey.' + failed.domain + ' is the one it signs with.', 'The signature on this message was damaged on the way. Ask whoever manages your mail whether anything adds a footer, a disclaimer, or tracking links after messages leave ' + svc.p + '. That is the usual cause.', failed.src);
      if (perm) add('fail', 'Publish or repair the DKIM key at ' + (perm.selector || '<selector>') + '._domainkey.' + perm.domain + '; ' + receiver + ' could not use it.', 'The key that checks this signature could not be read. Ask whoever manages the DNS for ' + perm.domain + ' to compare the record named ' + (perm.selector || '<selector>') + '._domainkey.' + perm.domain + ' with what ' + svc.p + ' says it should be.', perm.src);
    }
    const s = auth.spf;
    if (s.domain && !/helo/i.test(s.identity)) {
      if (s.result === 'fail' || s.result === 'softfail') add('fail', 'If this is your mail, add ' + svc.t + ' to the SPF record of ' + s.domain + (s.ip ? ' so it covers ' + s.ip : '') + '. If it is not, SPF did its job.', 'If you sent this, ask whoever manages the DNS for ' + s.domain + ' to add ' + svc.p + ' to its SPF record; the service\'s setup page gives the exact entry. If you did not send it, someone else used your domain and this check caught it.', s.src);
      else if (s.result === 'none') add('fail', 'Publish an SPF record for ' + s.domain + ' that lists the servers that send for it.', 'Ask whoever manages the DNS for ' + s.domain + ' to publish an SPF record listing the services that send your mail.', s.src);
      else if (s.result === 'permerror') add('fail', 'Repair the SPF record of ' + s.domain + ': check its syntax and keep it within 10 DNS lookups.', 'The SPF record for ' + s.domain + ' is broken, often because it lists too many services. Ask whoever manages its DNS to check and simplify it.', s.src);
      else if (s.result === 'pass' && !s.relaxed && !fw.yes && (dkimAligned || unaligned || !auth.dkim.length) && status !== 'pass') add('caveat', 'Second, after DKIM: set a custom Return-Path (bounce) domain under ' + from + ' at ' + svc.t + ' so SPF aligns too.', 'Optional, once the signature is fixed: in the settings of ' + svc.p + ', set up a custom bounce domain that ends in ' + from + '. Then the second check lines up as well.', s.src);
    }
    if (status === 'pass') {
      if (!spfAligned && s.result === 'pass' && dkimAligned) add('pass', 'Alignment comes from DKIM alone, which is enough. For SPF to align too, set a custom Return-Path domain under ' + from + ' at ' + svc.t + '.', 'Nothing needs fixing. If you want the second check to line up as well, set up a custom bounce domain ending in ' + from + ' in the settings of ' + svc.p + '.', s.src);
      // A mailbox provider's own domain is not the reader's to change.
      if (dm.policy.p === 'none' && !MAILBOX_OPERATORS.includes(HA.received.operatorOf(from))) add('caveat', from + ' publishes p=none, so forged mail is not stopped. Once aggregate reports show every real source passing, move to p=quarantine.', 'Your domain\'s policy only watches; it does not stop forged mail. Once the reports show all your real mail passes, ask whoever manages the DNS for ' + from + ' to change the policy to quarantine.', dm.src);
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
    if (fw.yes) l.push(say('unknown', 'ARC seals are not verified here, so the results before the forward are the forwarder\'s own record' + (fw.receiverArc === 'pass' ? '; ' + ctx.receiver + ' reported arc=pass, which means it did verify them.' : '.'), 'This page cannot check the forwarder\'s seal, so what the forwarder saw is taken from its own record.', fw.src));
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
    const c = Object.assign({}, ctx, { receiver, svc, fw, dm });
    const out = { status: 'unknown', state: 'unknown', headline: null, cause: null, consequence: null, details: [], fixes: [], flags: [], limits: [], forwarded: { yes: fw.yes, by: fw.by, preForward: fw.yes ? { writer: fw.writer, result: fw.preResult, derived: !!fw.derived, text: preText(fw), src: fw.aarSrc } : null, src: fw.src } };
    const finish = (status, headline, cause) => {
      out.status = status;
      out.state = status === 'pass' && dm.disagreement ? 'caveat' : STATE_OF[status];
      out.headline = headline; out.cause = cause;
      out.consequence = consequenceOf(status, dm, fd, receiver);
      out.fixes = fixesOf(status, c);
      out.limits = from.defined && auth.primary >= 0 ? limitsOf(c) : [];
      out.flags = flagsOf(Object.assign({ status }, c));
      return out;
    };

    // Nothing to judge by.
    if (!from.defined) {
      c.why = from.why;
      const T = { 'two-from': ['the message carries ' + numWord(message.fromCount) + ' From fields', 'the message names more than one sender'], 'multi-domain': ['the From field names addresses in ' + numWord(message.from.domains.length) + ' domains (' + joinList(message.from.domains) + ')', 'the sender line names addresses at more than one domain'], 'no-from': ['there is no usable From address', 'the sender\'s address is missing'] }[from.why];
      return finish('unknown', say(from.why === 'no-from' ? 'unknown' : 'fail', 'DMARC cannot be judged because ' + T[0] + ', so there is no single author domain to align with.', 'This page cannot check who sent the message, because ' + T[1] + '.', from.src),
        say('unknown', 'DMARC checks one author domain. ' + (dm.reported ? receiver + ' still reported dmarc=' + dm.result + (dm.headerFrom ? ' for header.from=' + dm.headerFrom : '') + ', but which address it judged is not in the headers.' : 'Nothing is computed from any of the addresses.'), dm.reported ? 'The receiving system recorded a result, but the headers do not say which sender it checked.' : 'Without one clear sender there is nothing to check.', from.src.concat(dm.src)));
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

    for (const k of auth.dkim) out.details.push(rowSentence(k, fd, fw.yes));
    out.details.push(rowSentence(auth.spf, fd, fw.yes));
    const allSrc = uniq(dm.src.concat(auth.computed.src));

    // Reported result first; computed only when the receiver wrote none.
    const result = dm.reported ? dm.result : auth.computed.result;
    const computedOnly = !dm.reported;
    const lead = computedOnly ? receiver + ' recorded no DMARC result; worked out from the identifiers, DMARC ' : 'DMARC ';
    const plainLead = computedOnly ? 'The receiving system did not record the sender check, but working it out from what it did record, this message ' : 'This message ';

    if (dm.disagreement) out.details.push(say(dm.disagreement.state, dm.disagreement.technical, dm.disagreement.plain, dm.disagreement.src));
    for (const g of decoded.filters) if (g.outcome) out.details.push(say(LEVEL_STATE[g.outcome.level], g.name + ', ' + g.outcome.key + ' ' + g.outcome.raw + ': ' + g.outcome.technical, g.name + ': ' + g.outcome.plain, g.outcome.src));
    const listId = decoded.list.find(i => i.key === 'List-Id');

    if (result === 'pass') {
      const pp = passPieces(auth);
      if (pp.length) {
        const cl = passClause(pp, fd);
        const head = say(computedOnly ? 'caveat' : 'pass', lead + (computedOnly ? 'passes' : 'passed') + ' because ' + cl.t, plainLead + 'passed the sender check (DMARC): ' + cl.p, uniq(pp.flatMap(x => x.src).concat(from.src)));
        const cause = say('pass', 'DMARC needs SPF or DKIM to pass on a domain that aligns with the From domain, and ' + joinList(pp.map(x => x.t)) + ', ' + (computedOnly ? 'so it would pass.' : 'as ' + receiver + ' recorded.') + (fw.yes ? ' The message was forwarded by ' + joinList(fw.by) + ' and still passed.' : ''), 'A message passes when it is signed by, or sent for, the domain in its From address, and this one was.', allSrc);
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
      const would = comp.result === 'pass' ? 'pass, because ' + passClause(passPieces(auth), fd).t.replace(/\.$/, '') : 'fail, because ' + failClause(failPieces(auth), fd).t.replace(/\.$/, '');
      const head = result === 'bestguesspass'
        ? say('caveat', 'DMARC did not apply: ' + receiver + ' reported dmarc=bestguesspass, meaning ' + fd + ' has no DMARC record but the message would pass if it had one.', fd + ' has no DMARC policy, so the sender check did not apply; the message would pass it if the domain had one.', dm.src)
        : say('caveat', 'DMARC did not apply because ' + receiver + ' found no DMARC record for ' + fd + '; with one, this message would ' + would + '.', fd + ' has no DMARC policy, so the sender check did not apply. With one, this message would ' + (comp.result === 'pass' ? 'pass.' : 'fail.'), allSrc);
      return finish('none', head, say('caveat', 'Without a DMARC record nothing ties SPF and DKIM to the From domain, so a receiver judges the message on its own signals. Anyone can put ' + fd + ' in a From address without failing a policy.', 'Without a policy, nothing stops others from sending mail that claims to be from ' + fd + '.', dm.src));
    }

    if (result === 'permerror' || result === 'temperror') {
      const perm = result === 'permerror';
      return finish('error', say('caveat', 'DMARC could not be evaluated because ' + receiver + ' hit ' + (perm ? 'a permanent error reading the DMARC record' : 'a temporary DNS error looking up the DMARC record') + ' for ' + fd + ' (dmarc=' + result + ').', 'The sender check could not run because ' + (perm ? 'the DMARC record of ' + fd + ' is written wrong.' : 'looking up the DMARC record of ' + fd + ' failed for a temporary reason.'), dm.src),
        say('caveat', (perm ? 'A permanent error means the record exists but cannot be read: a syntax mistake, a missing v=DMARC1, or more than one record. ' : 'A temporary error says nothing about the record itself. ') + 'Computed from the identifiers, the message ' + (auth.computed.result === 'pass' ? 'would pass.' : 'would fail.'), perm ? 'The record is there but broken, so mail systems treat the domain as if it had none.' : 'The lookup failed this time; the next one may work.', allSrc));
    }

    if (result !== 'fail') {
      return finish('unknown', say('unknown', receiver + ' reported dmarc=' + result + ', a result outside RFC 7489, so it is shown as written.', 'The receiving system recorded a sender check result this page does not know.', dm.src),
        say('unknown', 'The identifiers are in the details below; the page does not guess what the receiver meant.', 'The details below show what was checked.', dm.src));
    }

    // Failed. Forwarded mail first: blame the forward when the forwarder's
    // record shows a pass on arrival and the chain holds together.
    const fp = failPieces(auth);
    const fcl = failClause(fp, fd);
    if (fw.yes) {
      const pre = preText(fw);
      const preSay = 'before the forward, ' + fw.writer + ' recorded ' + (pre || 'no results') + (fw.derived ? ', which aligns with ' + fd : '');
      if (fw.preResult === 'pass' && fw.intact && fw.receiverArc !== 'fail') {
        const after = joinList(fp.map(x => x.t));
        const head = say('caveat', lead + (computedOnly ? 'fails' : 'failed') + ' because the message was forwarded by ' + joinList(fw.by) + ': ' + preSay + ', and after it ' + after + '.', plainLead + 'failed the sender check (DMARC) because it was forwarded by ' + joinList(fw.by) + '. Before the forward it passed; the forward broke it.', uniq(fw.aarSrc.concat(fp.flatMap(x => x.src))));
        const broke = [];
        if (fw.pre.some(x => x.method === 'spf' && x.result === 'pass') && !(auth.spf.result === 'pass' && auth.spf.relaxed)) broke.push('SPF, because the forward sent it on from ' + (auth.spf.ip || 'its own server') + (auth.spf.domain ? ' and SPF now checks ' + auth.spf.domain : ''));
        const dkBroke = auth.dkim.filter(k => k.result === 'fail' && fw.pre.some(x => x.method === 'dkim' && x.result === 'pass' && P.domainOf(x.ids['header.d'] || x.ids['header.i'] || '') === k.domain));
        if (dkBroke.length) broke.push('the DKIM signature from ' + joinList(dkBroke.map(k => k.domain)) + ', because the forward changed the message');
        const cause = say('caveat', 'The failure belongs to the forward, not to the sender. The message passed on arrival at ' + fw.writer + '; ' + (broke.length ? 'the forward then broke ' + joinList(broke) + '.' : 'after the forward nothing aligned with ' + fd + '.'), 'The sender set things up correctly. Forwarding changed the message on the way, which is a known side effect of forwarding.', uniq(fw.aarSrc.concat(fp.flatMap(x => x.src))));
        out.forwarded.blamed = true;
        return finish('forwarded', head, cause);
      }
      if (fw.preResult === 'fail') {
        out.details.push(say('fail', 'The forward is not the cause: ' + preSay + ', so the message was already failing when it arrived there.', 'The message already failed the check before it was forwarded, so the problem is at the sender.', fw.aarSrc));
      } else if (fw.preResult === 'pass') {
        out.details.push(say('caveat', 'The forwarder\'s record says ' + preSay + ', but ' + (!fw.intact ? 'the ARC chain is broken' : receiver + ' reported arc=fail') + ', so that record is not relied on and the failure is not blamed on the forward.', 'The forwarder claims the message passed before it was forwarded, but its record does not hold up, so this page does not rely on it.', fw.src.concat(auth.arcResult ? auth.arcResult.src : [])));
      }
    } else if (listId) {
      out.details.push(say('caveat', 'List-Id ' + listId.raw + ' shows the message came through a mailing list, and lists often change the subject or body. With no ARC record there is no result from before the list to compare with.', 'The message came through a mailing list, which can break these checks. The headers carry no record of how it looked before the list.', listId.src));
    }

    const d = dm.disagreement;
    if (d && d.reason === 'strict-mode') {
      const pp = passPieces(auth);
      return finish('fail', say('fail', lead + (computedOnly ? 'fails' : 'failed') + ' even though ' + joinList(pp.map(x => x.t)) + ' aligns with ' + fd + ' in relaxed mode, so the DMARC record most likely requires strict alignment (' + joinList(auth.computed.tags.map(t => t + '=s'), 'or') + '); the record itself is not in the headers.', plainLead + 'failed the sender check (DMARC) although it was signed by a domain in the same organization as ' + fd + '. The sender\'s policy probably demands an exact domain match.', uniq(pp.flatMap(x => x.src).concat(dm.src))),
        say('caveat', d.technical, d.plain, d.src));
    }
    if (d) {
      const pp = passPieces(auth);
      return finish('fail', say('fail', lead + 'failed at ' + receiver + ' even though ' + joinList(pp.map(x => x.t)) + ' aligns with the From domain ' + fd + '.', plainLead + 'failed the sender check (DMARC), though it was signed for ' + fd + '. The receiving system judged it differently from this page.', uniq(pp.flatMap(x => x.src).concat(dm.src))),
        say('caveat', d.technical, d.plain, d.src));
    }
    const head = say('fail', lead + (computedOnly ? 'fails' : 'failed') + ' because ' + fcl.t, plainLead + (computedOnly ? 'fails' : 'failed') + ' the sender check (DMARC) because ' + fcl.p, uniq(fp.flatMap(x => x.src).concat(from.src, dm.src)));
    return finish('fail', head, fw.yes && fw.preResult === 'fail'
      ? say('fail', 'The message was already failing before the forward: ' + fw.writer + ' recorded ' + (preText(fw) || 'no passing result') + '. ' + (auth.spf.result === 'pass' && !auth.spf.relaxed && auth.spf.domain ? 'SPF now passes only for the forwarder\'s domain ' + auth.spf.domain + ', which does not count for ' + fd + '.' : 'Nothing after the forward aligns with ' + fd + ' either.'), 'The message failed the check before it was ever forwarded, so the problem is with the sender, not the forward.', uniq(fw.aarSrc.concat(auth.spf.src)))
      : causeOfFail(auth, fd, receiver, svc));
  }

  // The mechanism behind a failure, in a sentence or two.
  function causeOfFail(auth, fd, receiver, svc) {
    const src = uniq(auth.dkim.flatMap(k => k.src).concat(auth.spf.src));
    const passedElsewhere = auth.dkim.filter(k => k.result === 'pass' && !k.relaxed).map(k => k.domain).concat(auth.spf.result === 'pass' && !auth.spf.relaxed && auth.spf.domain ? [auth.spf.domain] : []);
    const failedSig = auth.dkim.find(k => k.result === 'fail');
    const spfFailed = ['fail', 'softfail'].includes(auth.spf.result);
    if (passedElsewhere.length && !failedSig && !spfFailed) {
      const own = svc.t === 'the sending service' ? 'the sending service\'s own' : svc.t + '\'s own';
      return say('fail', 'The checks passed, but for ' + joinList(Array.from(new Set(passedElsewhere))) + ', ' + (passedElsewhere.length === 1 ? 'a domain' : 'domains') + ' that ' + (passedElsewhere.length === 1 ? 'is' : 'are') + ' not ' + fd + '. That is what happens when ' + own + ' domain signs and bounces the mail. DMARC counts a pass only on the From domain or, in relaxed mode, its organizational domain.', 'The service sending this mail is using its own domain instead of ' + fd + ', so the checks pass for the service but not for the sender.', src);
    }
    const parts = [];
    if (!auth.dkim.length) parts.push('There is no DKIM signature, so DMARC rests on SPF alone.');
    if (failedSig) parts.push('The DKIM signature from ' + failedSig.domain + ' did not verify at ' + receiver + (failedSig.comments && failedSig.comments[0] ? ' (' + failedSig.comments[0] + ')' : '') + ': something changed the signed part of the message after signing, or the key in DNS does not match.');
    if (spfFailed) parts.push('The server that handed the message over' + (auth.spf.ip ? ', ' + auth.spf.ip + ',' : '') + ' is not authorized by the SPF record of ' + auth.spf.domain + ', as ' + receiver + ' reported.');
    if (!parts.length) parts.push('Neither SPF nor DKIM produced a pass on a domain that aligns with ' + fd + '.');
    return say('fail', parts.join(' '), failedSig ? 'The message was changed after it was signed, or the signature does not match the sender\'s published key.' : spfFailed ? 'The server that sent this is not on the sender\'s list of approved servers.' : 'Nothing in the message proves it came from ' + fd + '.', src);
  }

  HA.finding = { build, forwardOf, joinList };
  // Node: require() returns this layer; the browser reads HA instead.
  if (typeof module !== 'undefined' && module.exports) module.exports = HA.finding;
})(typeof globalThis !== 'undefined' ? globalThis : this);
