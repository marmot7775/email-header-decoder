// verdict.js: the sentence that explains the result, and the fix.
// Reads the auth, chain, and provider objects; writes no DOM. Every
// sentence is built from identifiers in the headers, never from guesses
// about DNS, which this tool does not query.
(function (root) {
  'use strict';
  const HA = (root.HA = root.HA || {});

  const SPF_WORDS = { pass: 'passed', fail: 'failed', softfail: 'soft failed', neutral: 'was neutral', none: 'found no SPF record', temperror: 'hit a temporary DNS error', permerror: 'hit a permanent error in the SPF record', policy: 'was overridden by local policy' };

  function joinList(items) {
    if (items.length <= 1) return items.join('');
    return items.slice(0, -1).join(', ') + ', and ' + items[items.length - 1];
  }

  function describeSpf(spf, fromDomain, platform) {
    if (!spf.reported) return { text: 'The receiver recorded no SPF result.', level: 'warn', ok: false };
    const who = spf.identity === 'helo' ? 'the HELO name ' + spf.domain : (spf.domain || 'an empty sender');
    const verb = SPF_WORDS[spf.result] || ('returned ' + spf.result);
    if (spf.result === 'pass') {
      if (spf.align.aligned) return { text: 'SPF passed for ' + spf.domain + ', which aligns with the From domain' + (spf.align.strict ? '.' : ' (relaxed: same organizational domain).'), level: 'ok', ok: true };
      const pf = platform && platform.confident ? platform.name + "'s" : 'the sending platform\'s';
      return { text: 'SPF passed, but for ' + who + ', ' + (spf.identity === 'helo' ? 'not a sender domain' : pf + ' bounce domain') + ', which does not align with ' + fromDomain + '. SPF alone cannot carry DMARC here.', level: 'warn', ok: false };
    }
    if (spf.result === 'fail' || spf.result === 'softfail') return { text: 'SPF ' + verb + ': the sending IP' + (spf.ip ? ' ' + spf.ip : '') + ' is not authorized by the SPF record of ' + who + '.', level: 'bad', ok: false };
    if (spf.result === 'none') return { text: 'SPF found no SPF record for ' + who + '.', level: 'bad', ok: false };
    if (spf.result === 'permerror') return { text: 'SPF hit a permanent error evaluating ' + who + ', usually a syntax problem or more than 10 DNS lookups. Receivers treat this as no SPF.', level: 'bad', ok: false };
    if (spf.result === 'temperror') return { text: 'SPF hit a temporary DNS error for ' + who + '. The result says nothing about the record itself.', level: 'warn', ok: false };
    return { text: 'SPF ' + verb + ' for ' + who + '.', level: 'warn', ok: false };
  }

  function describeDkim(dkim, sigs, fromDomain, platform, forwarded) {
    if (!dkim.length && !sigs.length) return { text: 'There is no DKIM signature on this message, so DKIM cannot carry DMARC.', level: 'bad', ok: false, missing: true };
    const lines = [];
    let ok = false, level = 'bad';
    for (const k of dkim) {
      const d = k.domain || 'an unknown domain';
      const sel = k.selector ? ' (selector ' + k.selector + ')' : '';
      if (k.unreported) { lines.push('A DKIM signature by ' + d + sel + ' is present but the receiver recorded no result for it.'); continue; }
      if (k.result === 'pass') {
        if (k.align.aligned) { ok = true; level = 'ok'; lines.push('DKIM passed for ' + d + sel + ', which aligns with the From domain' + (k.align.strict ? '.' : ' (relaxed).')); }
        else { lines.push('DKIM passed, but signed as ' + d + sel + ', ' + (platform && platform.confident ? platform.name + "'s own domain" : 'a domain that is not yours') + ', so it does not align with ' + fromDomain + '.'); if (level !== 'ok') level = 'warn'; }
      } else if (k.result === 'fail') {
        lines.push('The DKIM signature by ' + d + sel + ' failed verification' + (k.align.aligned ? ' and it is the one that should have aligned.' : '.') + (forwarded ? ' The message was forwarded, and forwarders often change the body or headers enough to break the signature.' : ' Something changed the signed headers or body between signing and this receiver, or the published key does not match.'));
      } else if (k.result === 'permerror') {
        lines.push('DKIM for ' + d + sel + ' returned permerror: the receiver could not use the public key, which usually means the selector record is missing or malformed.');
      } else if (k.result === 'temperror') {
        lines.push('DKIM for ' + d + sel + ' returned temperror: the key lookup timed out.'); if (level !== 'ok') level = 'warn';
      } else if (k.result === 'neutral' || k.result === 'policy') {
        lines.push('DKIM for ' + d + sel + ' returned ' + k.result + ': the signature was not evaluated or was rejected by local policy.'); if (level !== 'ok') level = 'warn';
      } else if (k.result === 'none') {
        lines.push('The receiver reported dkim=none: no signature it could evaluate.');
      } else {
        lines.push('DKIM for ' + d + sel + ' returned ' + k.result + '.');
      }
    }
    return { text: lines.join(' '), level, ok };
  }

  function policyConsequence(policy, delivered) {
    const p = policy.p || '';
    if (!p && !policy.action) return '';
    if (policy.action) {
      const map = { none: 'Microsoft recorded action=none, so the policy asked for no enforcement.', oreject: 'Microsoft recorded action=oreject: the domain asks for reject, and Microsoft overrode that to junk the message instead of refusing it, as it does by default.', quarantine: 'Microsoft recorded action=quarantine: the message went to junk or quarantine.', pct_reject: 'Microsoft recorded action=pct_reject, a reject policy with pct= sampling, so this message was not enforced.', pct_quarantine: 'Microsoft recorded action=pct_quarantine.', permerror: 'Microsoft could not read the DMARC record (permerror).', temperror: 'Microsoft hit a temporary error reading the DMARC record.' };
      return map[policy.action] || ('Microsoft recorded action=' + policy.action + '.');
    }
    if (p === 'reject') return 'The From domain publishes p=reject' + (delivered ? ', so a failing message should have been refused; if you are reading it in a mailbox, the receiver chose to accept it anyway' + (policy.dis ? ' (disposition ' + policy.dis + ')' : '') + '.' : '.');
    if (p === 'quarantine') return 'The From domain publishes p=quarantine, so a failing message is expected to land in spam' + (policy.dis && policy.dis !== 'quarantine' ? ', though this receiver recorded disposition ' + policy.dis : '') + '.';
    if (p === 'none') return 'The From domain publishes p=none, so a failure changes nothing about delivery today; it only shows up in aggregate reports.';
    return '';
  }

  function fixFor(ctx) {
    const { spf, dkimD, fromDomain, platform, forwarded, status, sigs } = ctx;
    const pf = platform && platform.confident ? platform.name : 'the sending platform';
    const fixes = [];
    if (status === 'pass') {
      if (!dkimD.ok && spf.ok) fixes.push('DMARC rests on SPF alone. Any forward or mailing list will break SPF, so turn on DKIM signing for ' + fromDomain + ' at ' + pf + ' before that happens.');
      if (dkimD.ok && !spf.ok && spf.reported && spf.result === 'pass') fixes.push('Alignment comes from DKIM only. That is fine, and if you want SPF to align too, set a custom bounce (return path) domain under ' + fromDomain + ' at ' + pf + '.');
      return fixes;
    }
    if (forwarded) {
      fixes.push('This copy was forwarded. Judge the sender by a copy delivered straight from ' + pf + ' before changing anything; forwarders break SPF by design and often DKIM too.');
    }
    if (dkimD.missing) fixes.push('Turn on DKIM signing for ' + fromDomain + ' at ' + pf + '. That is the one change that makes DMARC pass and survives forwarding.');
    else if (!dkimD.ok) {
      const unaligned = ctx.dkim.find(k => k.result === 'pass' && !k.align.aligned);
      const failed = ctx.dkim.find(k => k.result === 'fail');
      const perm = ctx.dkim.find(k => k.result === 'permerror');
      if (unaligned) fixes.push('At ' + pf + ', authenticate ' + fromDomain + ' as a sending domain so the signature uses d=' + fromDomain + ' (or a subdomain of it) instead of ' + unaligned.domain + '. Platforms call this a custom, branded, or authenticated sending domain.');
      if (failed && !forwarded) fixes.push('The signature by ' + failed.domain + ' broke in transit. Check for a gateway or filter on the sending side that rewrites the body or subject after signing, and confirm the key at ' + (failed.selector || '<selector>') + '._domainkey.' + failed.domain + ' matches what ' + pf + ' signs with.');
      if (perm) fixes.push('Publish or repair the key record at ' + (perm.selector || '<selector>') + '._domainkey.' + perm.domain + '; the receiver could not read it.');
    }
    if (spf.reported && spf.result === 'pass' && !spf.align.aligned && !dkimD.ok) fixes.push('If you want SPF to count too, set a custom bounce domain under ' + fromDomain + ' at ' + pf + '. DKIM is the stronger fix; do this second.');
    if (spf.reported && (spf.result === 'fail' || spf.result === 'softfail')) fixes.push('Add ' + pf + "'s include to the SPF record of " + (spf.domain || fromDomain) + ' if this is your mail. If it is not your mail, SPF did its job.');
    if (spf.reported && spf.result === 'none' && spf.domain) fixes.push('Publish an SPF record for ' + spf.domain + '.');
    if (spf.reported && spf.result === 'permerror') fixes.push('Fix the SPF record of ' + (spf.domain || fromDomain) + ': check syntax and keep it under 10 DNS lookups.');
    if (!fixes.length) fixes.push('Nothing in these headers points at a single change. Compare with a copy delivered to a different receiver.');
    return fixes;
  }

  function build(ctx) {
    const { auth, chain, fields, fromAddr, fromAddrs, decoded } = ctx;
    const fromDomain = fromAddr ? fromAddr.domain : '';
    const platform = decoded.platform;
    const flags = [];
    const v = { status: 'unknown', headline: '', cause: '', detail: [], fixes: [], flags, policyText: '', forwarded: false, forwardEvidence: [] };

    // Structural problems first: they change what everything else means.
    const fromFields = fields.filter(f => f.lower === 'from');
    if (fromFields.length === 0) { v.status = 'unknown'; v.headline = 'No From header'; v.cause = 'There is no From header in the pasted block, so there is nothing to align against. Paste the full headers from the delivered copy.'; return v; }
    if (fromFields.length > 1) flags.push({ level: 'bad', text: 'The message carries ' + fromFields.length + ' From headers. RFC 5322 allows one, and RFC 7489 6.6.1 says a DMARC receiver may reject the message outright.' });
    if (fromAddrs.length > 1) flags.push({ level: 'warn', text: 'The From header lists ' + fromAddrs.length + ' addresses. DMARC evaluates the first one; receivers differ on how they treat the rest.' });
    if (!fromDomain) { v.status = 'unknown'; v.headline = 'From has no domain'; v.cause = 'The From header does not contain a usable address, so DMARC cannot be evaluated.'; return v; }
    if (fromAddr.display && /@/.test(fromAddr.display)) { const dd = HA.parse.domainOf(fromAddr.display.match(/[^\s<>"']+@[^\s<>"']+/)[0]); if (dd && dd !== fromDomain) flags.push({ level: 'bad', text: 'The display name shows an address at ' + dd + ' while the real From domain is ' + fromDomain + '. This is the classic impersonation layout.' }); }

    // Forwarding evidence.
    if (auth.arc.present) { v.forwarded = true; v.forwardEvidence.push('ARC chain sealed by ' + joinList(auth.arc.sealers.filter(Boolean))); }
    if (fields.some(f => f.lower === 'x-forwarded-to' || f.lower === 'x-forwarded-for')) { v.forwarded = true; v.forwardEvidence.push('Gmail X-Forwarded-To header'); }
    const listId = fields.find(f => f.lower === 'list-id');
    const listPost = fields.find(f => f.lower === 'list-post');
    if (listId && listPost) { v.forwarded = true; v.forwardEvidence.push('mailing list ' + listId.value); }
    if (fields.some(f => f.lower === 'x-ms-exchange-forwarded' || f.lower === 'x-ms-exchange-inbox-rules-loop')) { v.forwarded = true; v.forwardEvidence.push('Exchange forwarding rule'); }
    // Gmail's ARC on direct delivery: Google seals mail it receives too, so ARC alone is weak evidence of forwarding. Only count it when the sealer is not the final receiver.
    if (auth.arc.present && v.forwardEvidence.length === 1 && auth.primary && auth.arc.sealers.every(s => s && auth.primary.authserv.endsWith(HA.psl.orgDomain(s)))) { v.forwarded = false; v.forwardEvidence = []; }

    // What the first ARC sealer saw before it forwarded the message.
    let orig = null;
    if (auth.arc.present && auth.arc.chain[0] && auth.arc.chain[0].aar) {
      const aar = auth.arc.chain[0].aar;
      const g = m => aar.results.find(r => r.method === m) || null;
      orig = { sealer: auth.arc.sealers[0] || aar.authserv, spf: g('spf'), dkim: aar.results.filter(r => r.method === 'dkim'), dmarc: g('dmarc') };
    }

    const spfD = describeSpf(auth.spf, fromDomain, platform);
    const dkimD = describeDkim(auth.dkim, auth.dkimSignatures, fromDomain, platform, v.forwarded);
    const dm = auth.dmarc;

    if (!auth.primary) {
      const sent = chain.count === 0;
      v.status = 'unknown';
      v.headline = sent ? 'These look like headers from a sent or draft copy' : 'No authentication results recorded';
      v.cause = sent ? 'There are no Received headers, so this copy never passed through a receiving server. SPF, DKIM, and DMARC are evaluated by the receiver, so paste the headers from the recipient\'s copy (Gmail: Show original; Outlook: View message source).' : 'The receiving system wrote no Authentication-Results header. Some servers skip it, and some clients strip it on export. Without it, this page can only describe the signatures present.';
      if (auth.dkimSignatures.length) v.detail.push('Signatures present: ' + joinList(auth.dkimSignatures.map(s => 'd=' + s.d + ' s=' + s.s + (HA.auth.alignment(fromDomain, s.d, 'r').aligned ? ' (would align)' : ' (would not align)'))) + '.');
      else v.detail.push('No DKIM signature is present.');
      if (auth.returnPath && auth.returnPath.domain) v.detail.push('Return-Path domain is ' + auth.returnPath.domain + (HA.auth.alignment(fromDomain, auth.returnPath.domain, 'r').aligned ? ', which would align for SPF.' : ', which would not align for SPF.'));
      v.fixes = sent ? [] : ['Get the same message from a Gmail or Microsoft 365 mailbox; both record full results.'];
      return v;
    }

    const receiver = auth.primary.authserv || (auth.compauth ? 'Microsoft 365' : 'the receiver');
    if (dm.reported && dm.result === 'pass') {
      v.status = 'pass';
      v.headline = 'DMARC passed for ' + fromDomain;
      const how = [];
      if (dkimD.ok) how.push('DKIM signed as ' + joinList(auth.computed.dkimDomains));
      if (spfD.ok) how.push('SPF passed for ' + auth.spf.domain);
      v.cause = (how.length ? joinList(how) + (how.length > 1 ? ' both align' : ' aligns') + ' with the From domain, as ' + receiver + ' recorded.' : receiver + ' reported dmarc=pass, though neither identifier in these headers aligns on its own; the receiver may have applied an ARC override or a local policy.');
      if (!dkimD.ok) v.detail.push(dkimD.text);
      if (!spfD.ok) v.detail.push(spfD.text);
      if (auth.arcResult && auth.arcResult.result === 'pass' && !auth.computed.pass) v.detail.push('arc=pass: the receiver trusted an earlier hop\'s results through ARC.');
    } else if (dm.reported && dm.result === 'fail') {
      v.status = 'fail';
      v.headline = 'DMARC failed for ' + fromDomain;
      const reasons = [];
      if (dkimD.missing) reasons.push('there is no DKIM signature');
      else if (!dkimD.ok) {
        const un = auth.dkim.filter(k => k.result === 'pass' && !k.align.aligned);
        const failed = auth.dkim.filter(k => k.result === 'fail');
        if (un.length) reasons.push('DKIM passed but signed as ' + joinList(un.map(k => k.domain)) + ', not ' + fromDomain);
        if (failed.length) reasons.push('the DKIM signature by ' + joinList(failed.map(k => k.domain)) + ' failed verification');
        if (!un.length && !failed.length) reasons.push('no DKIM signature verified');
      }
      if (auth.spf.reported) {
        if (auth.spf.result === 'pass' && !auth.spf.align.aligned) reasons.push('SPF passed only for ' + (auth.spf.identity === 'helo' ? 'the HELO name' : 'the bounce domain') + ' ' + auth.spf.domain + ', which does not align');
        else if (auth.spf.result !== 'pass') reasons.push('SPF ' + (SPF_WORDS[auth.spf.result] || auth.spf.result) + (auth.spf.domain ? ' for ' + auth.spf.domain : ''));
      } else reasons.push('no SPF result was recorded');
      v.cause = 'Neither identifier aligned: ' + joinList(reasons) + '.';
      if (v.forwarded && orig && orig.dmarc && orig.dmarc.result === 'pass') {
        const seen = [];
        if (orig.spf) seen.push('SPF ' + orig.spf.result);
        if (orig.dkim.length) seen.push('DKIM ' + orig.dkim.map(k => k.result).join('/'));
        seen.push('DMARC pass');
        const dkFailed = auth.dkim.some(k => k.result === 'fail');
        v.cause = 'The copy you have was forwarded by ' + orig.sealer + '. Before the forward, ' + orig.sealer + ' recorded ' + joinList(seen) + ' for ' + fromDomain + '. The forward re-sent the message from ' + (auth.spf.ip || 'its own server') + ', which the SPF record of ' + (auth.spf.domain || fromDomain) + ' does not list' + (dkFailed ? ', and changed it enough to break the DKIM signature' : '') + '. The failure belongs to the forward, not to the sender.';
        v.forwardBroke = true;
      } else if (v.forwarded && orig && orig.dmarc && orig.dmarc.result === 'fail') {
        v.detail.push('The message was already failing DMARC when ' + orig.sealer + ' received it, before the forward.');
      }
      if (!v.forwardBroke && auth.computed.pass) v.cause = receiver + ' reported dmarc=fail even though ' + (auth.computed.byDkim ? 'DKIM signed as ' + joinList(auth.computed.dkimDomains) : 'SPF for ' + auth.spf.domain) + ' passes and aligns under relaxed alignment. The domain may publish strict alignment (adkim=s or aspf=s), which this page cannot see without DNS.';
      v.detail.push(dkimD.text); v.detail.push(spfD.text);
      if (auth.arcResult && auth.arcResult.result === 'pass') v.detail.push('arc=pass: an earlier hop vouched for the original results, and this receiver may have accepted the message on that basis.');
      if (auth.compauth) v.detail.push(compauthText(auth.compauth));
    } else if (dm.reported && dm.result === 'none') {
      v.status = 'none';
      v.headline = 'No DMARC policy for ' + fromDomain;
      v.cause = receiver + ' found no DMARC record for ' + fromDomain + ', so nothing was enforced. ' + (auth.computed.pass ? 'With a record in place this message would pass: ' + (auth.computed.byDkim ? 'DKIM signed as ' + joinList(auth.computed.dkimDomains) + ' aligns' : '') + (auth.computed.byDkim && auth.computed.bySpf ? ' and ' : '') + (auth.computed.bySpf ? 'SPF for ' + auth.spf.domain + ' aligns' : '') + '.' : 'With a record in place this message would fail, because neither SPF nor DKIM aligns.');
      v.detail.push(dkimD.text); v.detail.push(spfD.text);
      v.fixes.push('Publish a DMARC record for ' + fromDomain + ' at p=none with a rua= address, then read the reports before moving to enforcement.');
    } else if (dm.reported) {
      v.status = 'unknown';
      v.headline = 'DMARC ' + dm.result + ' for ' + fromDomain;
      v.cause = receiver + ' recorded dmarc=' + dm.result + (dm.result === 'permerror' ? ': the DMARC record could not be parsed. Check the record for syntax errors or multiple records.' : dm.result === 'temperror' ? ': a temporary DNS failure. The result says nothing about the record.' : dm.result === 'bestguesspass' ? ': Microsoft\'s best guess pass, used when no DMARC record exists but SPF or DKIM would have aligned.' : '.');
      v.detail.push(dkimD.text); v.detail.push(spfD.text);
    } else {
      // SPF or DKIM reported, DMARC not.
      v.status = auth.computed.pass ? 'pass' : 'fail';
      v.headline = (auth.computed.pass ? 'DMARC would pass for ' : 'DMARC would fail for ') + fromDomain + ' (computed)';
      v.cause = receiver + ' did not record a DMARC result, so this is worked out from the SPF and DKIM identifiers under relaxed alignment. ' + (auth.computed.pass ? joinList([].concat(auth.computed.byDkim ? ['DKIM signed as ' + joinList(auth.computed.dkimDomains)] : [], auth.computed.bySpf ? ['SPF for ' + auth.spf.domain] : [])) + ' aligns with the From domain.' : 'Neither SPF nor DKIM passes and aligns.');
      v.detail.push(dkimD.text); v.detail.push(spfD.text);
    }

    v.policyText = policyConsequence(dm.policy, true);
    if (v.forwardBroke) v.fixes = ['Nothing at the sender fixes a broken forward. If the forward is yours (an old address passing mail to a new mailbox), have the receiving side trust the forwarder\'s ARC seal: Gmail honors ARC on its own; Microsoft 365 honors it only for sealers an admin lists under ARC trusted sealers in the Defender portal.', 'If the forward is not yours, authentication worked as designed. Judge the sender by a copy delivered straight to the mailbox.'];
    else v.fixes = v.fixes.concat(fixFor({ spf: Object.assign({ ok: spfD.ok }, auth.spf), dkim: auth.dkim, dkimD, fromDomain, platform, forwarded: v.forwarded, status: v.status, sigs: auth.dkimSignatures }));

    // Transit flags.
    if (chain.slowestSec >= 600) flags.push({ level: 'warn', text: 'Hop ' + (chain.slowestIdx + 1) + ' waited ' + fmtDur(chain.slowestSec) + ' before the next server accepted the message. Delays this size usually mean greylisting, throttling, or a queue on the sending side.' });
    if (chain.clockSkew) flags.push({ level: 'info', text: 'At least one hop shows a negative delay, so two servers disagree about the time. Delays around it are unreliable.' });
    const plainExternal = chain.hops.filter(h => !h.internal && h.tls === false);
    if (plainExternal.length) flags.push({ level: 'warn', text: plainExternal.length + ' external hop' + (plainExternal.length > 1 ? 's' : '') + ' recorded no TLS. The message crossed the public internet in the clear at that point.' });
    if (auth.arc.problems.length) for (const p of auth.arc.problems) flags.push({ level: 'warn', text: p });
    for (const s of auth.dkimSignatures) for (const n of s.notes) flags.push({ level: 'info', text: 'DKIM d=' + s.d + ': ' + n });
    return v;
  }

  // Microsoft composite authentication reason codes, per Microsoft Learn.
  function compauthText(c) {
    const r = c.reason || '';
    const map = { '000': 'explicit authentication failed (DMARC fail)', '001': 'implicit authentication failed (no DMARC record, and SPF and DKIM did not line up with the From)', '002': 'the sender\'s organization policy marked it as a spoof', '010': 'DMARC failed with a reject or quarantine policy' };
    let why = '';
    if (map[r]) why = map[r];
    else if (/^[17]/.test(r)) why = 'the message passed explicit or implicit authentication';
    else if (/^2/.test(r)) why = 'soft pass through implicit authentication';
    else if (/^3/.test(r)) why = 'composite authentication was not checked';
    else if (/^[49]/.test(r)) why = 'composite authentication was bypassed by a rule or allow entry';
    return 'Microsoft compauth=' + c.result + (r ? ' reason=' + r : '') + (why ? ': ' + why + '.' : '.');
  }

  function fmtDur(sec) {
    if (sec === null || sec === undefined) return '';
    const s = Math.abs(sec);
    if (s < 60) return sec + ' s';
    if (s < 3600) return (sec < 0 ? '-' : '') + Math.floor(s / 60) + ' min ' + (s % 60) + ' s';
    if (s < 86400) return (sec < 0 ? '-' : '') + Math.floor(s / 3600) + ' h ' + Math.floor((s % 3600) / 60) + ' min';
    return (sec < 0 ? '-' : '') + Math.floor(s / 86400) + ' d ' + Math.floor((s % 86400) / 3600) + ' h';
  }

  HA.verdict = { build, fmtDur, compauthText };
  // Node: require() returns this layer; the browser reads HA instead.
  if (typeof module !== 'undefined' && module.exports) module.exports = HA.verdict;
})(typeof globalThis !== 'undefined' ? globalThis : this);
