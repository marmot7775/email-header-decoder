// providers.js: decode the filter and platform headers that receivers
// and sending services add, into plain statements with a level.
// Levels: ok, info, warn, bad. Unknown codes are shown raw, never guessed.
(function (root) {
  'use strict';
  const HA = (root.HA = root.HA || {});
  const P = HA.parse;

  function item(key, value, meaning, level) { return { key, value, meaning, level: level || 'info' }; }

  // Microsoft 365 / Exchange Online Protection. Field meanings follow
  // Microsoft Learn, "Anti-spam message headers in Microsoft 365".
  const MS_SCL = { '-1': ['Filtering skipped: safe sender, safe recipient, or allowed IP', 'ok'], '0': ['Not spam', 'ok'], '1': ['Not spam', 'ok'], '5': ['Spam', 'bad'], '6': ['Spam', 'bad'], '7': ['High confidence spam', 'bad'], '8': ['High confidence spam', 'bad'], '9': ['High confidence spam', 'bad'] };
  const MS_SFV = { BLK: ['Blocked: sender on the recipient block list', 'bad'], NSPM: ['Not spam', 'ok'], SPM: ['Marked as spam by the filter', 'bad'], SKA: ['Skipped filtering: sender on the safe list', 'ok'], SKB: ['Blocked by a sender block entry', 'bad'], SKI: ['Skipped: intra-organization mail', 'ok'], SKN: ['Marked not spam by a mail flow rule or safe sender', 'ok'], SKQ: ['Released from quarantine', 'info'], SKS: ['Marked as spam by a mail flow rule', 'bad'] };
  const MS_CAT = { NONE: ['No threat category', 'ok'], SPM: ['Spam', 'bad'], HSPM: ['High confidence spam', 'bad'], PHSH: ['Phishing', 'bad'], HPHSH: ['High confidence phishing', 'bad'], HPHISH: ['High confidence phishing', 'bad'], BULK: ['Bulk', 'warn'], MALW: ['Malware', 'bad'], SPOOF: ['Spoof: the From domain failed authentication', 'bad'], DIMP: ['Domain impersonation', 'bad'], GIMP: ['Mailbox intelligence impersonation', 'bad'], UIMP: ['User impersonation', 'bad'], AMP: ['Anti-malware', 'bad'], SAP: ['Safe Attachments', 'bad'], OSPM: ['Outbound spam', 'warn'], INTOS: ['Intra-organization spoof', 'bad'] };
  const MS_IPV = { CAL: ['Connecting IP on an allow list', 'ok'], NLI: ['Connecting IP not on any reputation list', 'ok'] };
  const MS_DIR = { INB: 'Inbound', OUT: 'Outbound', INT: 'Internal' };

  function decodeMicrosoft(fields, out) {
    const ff = fields.find(f => f.lower === 'x-forefront-antispam-report');
    const items = [];
    if (ff) {
      const kv = {};
      for (const part of ff.value.split(';')) { const i = part.indexOf(':'); if (i > 0) kv[part.slice(0, i).trim().toUpperCase()] = part.slice(i + 1).trim(); }
      if (kv.SCL !== undefined) { const m = MS_SCL[kv.SCL]; items.push(item('SCL', kv.SCL, m ? m[0] : 'Spam confidence level', m ? m[1] : 'info')); }
      if (kv.CAT) { const m = MS_CAT[kv.CAT.toUpperCase()]; items.push(item('CAT', kv.CAT, m ? m[0] : 'Threat category (code not in the published table)', m ? m[1] : 'info')); }
      if (kv.SFV) { const m = MS_SFV[kv.SFV.toUpperCase()]; items.push(item('SFV', kv.SFV, m ? m[0] : 'Spam filter verdict (code not in the published table)', m ? m[1] : 'info')); }
      if (kv.IPV) { const m = MS_IPV[kv.IPV.toUpperCase()]; items.push(item('IPV', kv.IPV, m ? m[0] : 'IP verdict', m ? m[1] : 'info')); }
      if (kv.SRV) items.push(item('SRV', kv.SRV, kv.SRV.toUpperCase() === 'BULK' ? 'Identified as bulk mail' : 'Service verdict', kv.SRV.toUpperCase() === 'BULK' ? 'warn' : 'info'));
      if (kv.DIR) items.push(item('DIR', kv.DIR, (MS_DIR[kv.DIR.toUpperCase()] || 'Direction') + ' mail', 'info'));
      if (kv.CIP) items.push(item('CIP', kv.CIP, 'Connecting IP as EOP saw it', 'info'));
      if (kv.CTRY) items.push(item('CTRY', kv.CTRY, 'Country of the connecting IP', 'info'));
      if (kv.PTR) items.push(item('PTR', kv.PTR, 'Reverse DNS of the connecting IP', 'info'));
      if (kv.H) items.push(item('H', kv.H, 'HELO/EHLO name the sender used', 'info'));
      if (kv.SFTY) items.push(item('SFTY', kv.SFTY, 'Safety tip shown to the user (9.19 domain impersonation, 9.20 user impersonation; other codes as published by Microsoft)', 'warn'));
      if (kv.SFS) items.push(item('SFS', kv.SFS, 'Spam filter rules that matched', 'info'));
    }
    const bcl = fields.find(f => f.lower === 'x-microsoft-antispam');
    if (bcl) { const m = /BCL:(\d+)/i.exec(bcl.value); if (m) { const n = +m[1]; items.push(item('BCL', m[1], n === 0 ? 'Not from a bulk sender' : n <= 3 ? 'Bulk sender with few complaints' : n <= 7 ? 'Bulk sender with a mixed complaint record' : 'Bulk sender with a high complaint rate', n === 0 ? 'ok' : n <= 3 ? 'info' : n <= 7 ? 'warn' : 'bad')); } }
    const scl = fields.find(f => f.lower === 'x-ms-exchange-organization-scl');
    if (scl && !ff) { const m = MS_SCL[scl.value.trim()]; items.push(item('SCL', scl.value, m ? m[0] : 'Spam confidence level', m ? m[1] : 'info')); }
    const pcl = fields.find(f => f.lower === 'x-ms-exchange-organization-pcl');
    if (pcl) items.push(item('PCL', pcl.value, +pcl.value >= 4 ? 'Phishing confidence level: suspicious' : 'Phishing confidence level', +pcl.value >= 4 ? 'warn' : 'info'));
    const authAs = fields.find(f => f.lower === 'x-ms-exchange-organization-authas');
    if (authAs) items.push(item('AuthAs', authAs.value, authAs.value.toLowerCase() === 'internal' ? 'Treated as internal (authenticated) mail' : authAs.value.toLowerCase() === 'anonymous' ? 'Treated as external, unauthenticated mail' : 'Authentication class', 'info'));
    const authSrc = fields.find(f => f.lower === 'x-ms-exchange-organization-authsource');
    if (authSrc) items.push(item('AuthSource', authSrc.value, 'Server that assigned the authentication class', 'info'));
    const msgsource = fields.find(f => f.lower === 'x-ms-exchange-organization-messagedirectionality');
    if (msgsource) items.push(item('Directionality', msgsource.value, 'Message direction as Exchange classified it', 'info'));
    const skip = fields.find(f => f.lower === 'x-ms-exchange-organization-skiplistedinternetsender' || f.lower === 'x-ms-exchange-organization-bypassclutter');
    if (skip) items.push(item(skip.name, skip.value, 'Filtering bypass flag', 'info'));
    if (items.length) out.push({ name: 'Microsoft 365 (Exchange Online Protection)', items });
  }

  function decodeGoogle(fields, out) {
    const items = [];
    const gdkim = fields.find(f => f.lower === 'x-google-dkim-signature');
    if (gdkim) { const { tags } = P.parseTagList(gdkim.value); items.push(item('X-Google-DKIM-Signature', 'd=' + (tags.d || ''), 'Google re-signs mail it relays for its own internal checks; this is not the sender\'s DKIM and does not count for DMARC', 'info')); }
    if (fields.some(f => f.lower === 'x-gm-message-state')) items.push(item('X-Gm-Message-State', 'opaque', 'Internal Gmail state token, carries no verdict', 'info'));
    if (fields.some(f => f.lower === 'x-google-smtp-source')) items.push(item('X-Google-Smtp-Source', 'opaque', 'Internal Gmail routing token, carries no verdict', 'info'));
    const fid = fields.find(f => f.lower === 'feedback-id');
    if (fid) items.push(item('Feedback-ID', fid.value, 'Sender identifier used by Google Postmaster Tools to group campaign statistics', 'info'));
    if (items.length) out.push({ name: 'Google (Gmail and Workspace)', items, note: 'Gmail does not write its spam verdict into headers. The placement decision is only visible in the mailbox.' });
  }

  function decodeGateways(fields, out) {
    // Proofpoint
    const pp = fields.find(f => f.lower === 'x-proofpoint-spam-details');
    if (pp) {
      const items = [];
      const kv = {};
      for (const m of pp.value.matchAll(/([a-z]+)=([^\s]+)/gi)) kv[m[1].toLowerCase()] = m[2];
      if (kv.rule) items.push(item('rule', kv.rule, kv.rule === 'notspam' ? 'Classified as not spam' : kv.rule === 'spam' ? 'Classified as spam' : 'Classification rule that fired', kv.rule === 'notspam' ? 'ok' : kv.rule === 'spam' ? 'bad' : 'info'));
      if (kv.policy) items.push(item('policy', kv.policy, 'Policy route applied', 'info'));
      if (kv.score !== undefined) items.push(item('score', kv.score, 'Overall spam score (0 to 100)', +kv.score >= 50 ? 'bad' : +kv.score > 0 ? 'warn' : 'ok'));
      for (const k of ['spamscore', 'phishscore', 'bulkscore', 'suspectscore', 'malwarescore', 'mlxscore', 'adultscore', 'impostorscore', 'clxscore', 'priorityscore', 'lowpriorityscore']) if (kv[k] !== undefined) items.push(item(k, kv[k], 'Sub-score', +kv[k] >= 50 ? 'bad' : +kv[k] > 0 ? 'warn' : 'ok'));
      if (kv.engine) items.push(item('engine', kv.engine, 'Engine version', 'info'));
      out.push({ name: 'Proofpoint', items });
    }
    // Mimecast
    const mcs = fields.find(f => f.lower === 'x-mimecast-spam-score');
    if (mcs) {
      const items = [item('Spam-Score', mcs.value, 'Mimecast spam score; higher is worse', +mcs.value >= 5 ? 'bad' : +mcs.value > 0 ? 'warn' : 'ok')];
      const bulk = fields.find(f => f.lower === 'x-mimecast-bulk-signature');
      if (bulk) items.push(item('Bulk-Signature', bulk.value, 'Bulk mail signature', 'warn'));
      const imp = fields.find(f => f.lower === 'x-mimecast-impersonation-protect');
      if (imp) items.push(item('Impersonation-Protect', imp.value, 'Impersonation Protect result', 'warn'));
      out.push({ name: 'Mimecast', items });
    }
    // Cisco IronPort / Secure Email
    const ip = fields.filter(f => /^x-ironport-/i.test(f.name));
    if (ip.length) {
      const items = [];
      const av = ip.find(f => f.lower === 'x-ironport-av');
      if (av) items.push(item('X-IronPort-AV', av.value, 'Anti-virus engine stamp', 'info'));
      const asr = ip.find(f => f.lower === 'x-ironport-anti-spam-result');
      if (asr) items.push(item('X-IronPort-Anti-Spam-Result', 'opaque', 'Encoded anti-spam verdict; readable only by Cisco', 'info'));
      const filt = ip.find(f => f.lower === 'x-ironport-anti-spam-filtered');
      if (filt) items.push(item('X-IronPort-Anti-Spam-Filtered', filt.value, 'Anti-spam scanning was applied', 'info'));
      out.push({ name: 'Cisco Secure Email (IronPort)', items });
    }
    // Barracuda
    const bss = fields.find(f => f.lower === 'x-barracuda-spam-status');
    const bsc = fields.find(f => f.lower === 'x-barracuda-spam-score');
    if (bss || bsc) {
      const items = [];
      if (bss) { const yes = /^yes/i.test(bss.value); const sc = /SCORE=([\d.]+)/i.exec(bss.value); items.push(item('Spam-Status', bss.value.split(',')[0], yes ? 'Classified as spam' : 'Classified as not spam', yes ? 'bad' : 'ok')); if (sc) items.push(item('Score', sc[1], 'Barracuda score against its thresholds', +sc[1] >= 3 ? 'warn' : 'ok')); }
      else if (bsc) items.push(item('Spam-Score', bsc.value, 'Barracuda score', +bsc.value >= 3 ? 'warn' : 'ok'));
      const bb = fields.find(f => f.lower === 'x-barracuda-bayes');
      if (bb) items.push(item('Bayes', bb.value, 'Bayesian classifier result', 'info'));
      out.push({ name: 'Barracuda', items });
    }
    // SpamAssassin and compatible (many hosting providers)
    const xss = fields.find(f => f.lower === 'x-spam-status');
    const xsf = fields.find(f => f.lower === 'x-spam-flag');
    const xscore = fields.find(f => f.lower === 'x-spam-score');
    if (xss || xsf || xscore) {
      const items = [];
      if (xss) {
        const yes = /^yes/i.test(xss.value);
        const score = /score=(-?[\d.]+)/i.exec(xss.value);
        const req = /required=(-?[\d.]+)/i.exec(xss.value);
        const tests = /tests=([^\s]+)/i.exec(xss.value);
        items.push(item('Spam-Status', yes ? 'Yes' : 'No', yes ? 'Classified as spam' : 'Classified as not spam', yes ? 'bad' : 'ok'));
        if (score) items.push(item('score', score[1] + (req ? ' of ' + req[1] + ' required' : ''), 'Score against the threshold', req && +score[1] >= +req[1] ? 'bad' : +score[1] > 2 ? 'warn' : 'ok'));
        if (tests) items.push(item('tests', tests[1].split(',').join(', '), 'Rules that fired', 'info'));
      } else {
        if (xsf) items.push(item('Spam-Flag', xsf.value, /yes/i.test(xsf.value) ? 'Classified as spam' : 'Classified as not spam', /yes/i.test(xsf.value) ? 'bad' : 'ok'));
        if (xscore) items.push(item('Spam-Score', xscore.value, 'Score', 'info'));
      }
      out.push({ name: 'SpamAssassin (or compatible filter)', items });
    }
    // Rspamd
    const rs = fields.find(f => f.lower === 'x-spamd-result');
    if (rs) { const d = /default:\s*(True|False)\s*\[(-?[\d.]+)\s*\/\s*(-?[\d.]+)\]/i.exec(rs.value); out.push({ name: 'Rspamd', items: [item('Result', d ? (d[1] + ' ' + d[2] + ' of ' + d[3]) : rs.value.slice(0, 80), d ? (/true/i.test(d[1]) ? 'Classified as spam' : 'Classified as not spam') : 'Rspamd result', d && /true/i.test(d[1]) ? 'bad' : 'ok')] }); }
    // Symantec / Broadcom
    if (fields.some(f => f.lower === 'x-brightmail-tracker')) out.push({ name: 'Symantec Messaging Gateway', items: [item('X-Brightmail-Tracker', 'opaque', 'Encoded tracking token, carries no readable verdict', 'info')] });
    // Trend Micro
    const tm = fields.find(f => /^x-tm-as-result/i.test(f.name));
    if (tm) out.push({ name: 'Trend Micro', items: [item(tm.name, tm.value, 'Anti-spam result', /yes/i.test(tm.value) ? 'bad' : 'info')] });
    // Sophos
    const soph = fields.find(f => /^x-sophos-/i.test(f.name));
    if (soph) out.push({ name: 'Sophos', items: [item(soph.name, soph.value, 'Sophos gateway stamp', 'info')] });
  }

  // Sending platform fingerprints: header names, DKIM d=, Return-Path
  // domains, and relay hostnames. Evidence is listed, the name is a
  // best match, and nothing claims the platform when evidence is thin.
  const PLATFORMS = [
    { name: 'SendGrid', headers: ['x-sg-eid', 'x-sg-id'], domains: ['sendgrid.net', 'sendgrid.info'] },
    { name: 'Mailgun', headers: ['x-mailgun-sid', 'x-mailgun-sending-ip', 'x-mailgun-tag'], domains: ['mailgun.org', 'mailgun.net', 'mg.'] },
    { name: 'Amazon SES', headers: ['x-ses-outgoing', 'x-ses-configuration-set', 'x-ses-receipt'], domains: ['amazonses.com'] },
    { name: 'Mailchimp', headers: ['x-mc-user', 'x-mailchimp-ab'], domains: ['mcsv.net', 'mcdlv.net', 'rsgsv.net', 'mail.mcsignup.com'] },
    { name: 'Mandrill', headers: ['x-mandrill-user'], domains: ['mandrillapp.com'] },
    { name: 'HubSpot', headers: ['x-hubspot-sent-from', 'x-hs-cid', 'x-hubspot-correlation-id'], domains: ['hubspotemail.net', 'hubspot.com', 'hs-send.com', 'hsmails.com'] },
    { name: 'Klaviyo', headers: ['x-klaviyo-message-id', 'x-klaviyo-id'], domains: ['klaviyomail.com', 'klaviyo.com'] },
    { name: 'Constant Contact', headers: ['x-roving-id', 'x-roving-campaignid'], domains: ['ccsend.com', 'constantcontact.com'] },
    { name: 'Salesforce Marketing Cloud', headers: ['x-sfmc-stack', 'x-sfdc-user'], domains: ['exacttarget.com', 'exct.net', 'bounce.s', 'mcsv.net'] },
    { name: 'Salesforce (CRM)', headers: ['x-sfdc-lk', 'x-sfdc-x-tls-ciphersuite', 'x-sfdc-user'], domains: ['salesforce.com', 'bnc.salesforce.com'] },
    { name: 'Marketo', headers: ['x-mktmailid', 'x-mktmailto', 'x-msfbl'], domains: ['mktomail.com', 'mktdns.com', 'mktoweb.com'] },
    { name: 'Pardot', headers: ['x-pardot-route', 'x-pardot-lb'], domains: ['pardot.com'] },
    { name: 'SparkPost', headers: ['x-msfbl', 'x-sparkpost-id'], domains: ['sparkpostmail.com', 'sparkpost.com'] },
    { name: 'Postmark', headers: ['x-pm-message-id', 'x-pm-tag'], domains: ['mtasv.net', 'pstmrk.it', 'postmarkapp.com'] },
    { name: 'Brevo (Sendinblue)', headers: ['x-sib-id', 'x-mailin-client'], domains: ['sendibm1.com', 'sendibm2.com', 'sendibm3.com', 'sendinblue.com', 'brevo.com'] },
    { name: 'Mailjet', headers: ['x-mj-mid', 'x-mailjet-sent-from'], domains: ['mailjet.com', 'mjt.lu'] },
    { name: 'Campaign Monitor', headers: ['x-cm-message-id', 'x-cm-campaign'], domains: ['cmail1.com', 'cmail19.com', 'cmail20.com', 'createsend.com', 'cmail'] },
    { name: 'ActiveCampaign', headers: ['x-ac-id'], domains: ['acemlna.com', 'acemlnb.com', 'acemlnc.com', 'acemlnd.com', 'activehosted.com'] },
    { name: 'Customer.io', headers: ['x-cio-id', 'x-cio-run-id'], domains: ['customeriomail.com', 'e.customeriomail.com'] },
    { name: 'Braze', headers: ['x-braze-id'], domains: ['braze.com', 'brazeemail.com'] },
    { name: 'Iterable', headers: ['x-iterable-id'], domains: ['iterable.com'] },
    { name: 'Zoho', headers: ['x-zohomailclient', 'x-zoho-virus-status'], domains: ['zcsend.net', 'zoho.com', 'zohomail.com'] },
    { name: 'Zendesk', headers: ['x-zendesk-from-account-id'], domains: ['zendesk.com'] },
    { name: 'Intercom', headers: ['x-intercom-id'], domains: ['intercom-mail.com'] },
    { name: 'Freshdesk', headers: ['x-freshdesk-ticket-id'], domains: ['freshdesk.com', 'freshemail.io'] },
    { name: 'Microsoft 365 (sent through)', headers: [], domains: ['outbound.protection.outlook.com'] },
    { name: 'Google Workspace or Gmail (sent through)', headers: [], domains: ['mail-', 'google.com'] },
    { name: 'Outlook.com', headers: [], domains: ['outbound.protection.outlook.com', 'hotmail.com', 'outlook.com', 'live.com'] },
    { name: 'Apple iCloud', headers: [], domains: ['icloud.com', 'mail.me.com', 'apple.com'] },
    { name: 'Yahoo', headers: [], domains: ['yahoo.com', 'yahoodns.net', 'aol.com'] },
    { name: 'Proton', headers: [], domains: ['protonmail.ch', 'proton.me', 'protonmail.com'] },
    { name: 'Fastmail', headers: [], domains: ['messagingengine.com', 'fastmail.com'] },
    { name: 'Mailtrap', headers: ['x-mailtrap-id'], domains: ['mailtrap.io'] },
  ];

  function detectPlatform(fields, auth, chain) {
    const evidence = [];
    const names = new Set(fields.map(f => f.lower));
    const domains = [];
    if (auth.returnPath && auth.returnPath.domain) domains.push({ d: auth.returnPath.domain, src: 'Return-Path' });
    if (auth.spf.domain) domains.push({ d: auth.spf.domain, src: 'SPF identity' });
    for (const k of auth.dkim) if (k.domain) domains.push({ d: k.domain, src: 'DKIM d=' });
    const firstExternal = chain.hops.find(h => h.fromIp && !HA.received.isPrivateIp(h.fromIp));
    if (firstExternal && firstExternal.fromHost) domains.push({ d: firstExternal.fromHost.toLowerCase(), src: 'first relay' });
    const scores = new Map();
    for (const p of PLATFORMS) {
      for (const h of p.headers) if (names.has(h)) { scores.set(p.name, (scores.get(p.name) || 0) + 3); evidence.push({ platform: p.name, what: 'header ' + h }); }
      for (const d of p.domains) for (const x of domains) if (x.d.endsWith(d) || x.d.includes(d)) { scores.set(p.name, (scores.get(p.name) || 0) + 2); evidence.push({ platform: p.name, what: x.src + ' ' + x.d }); }
    }
    const xmailer = fields.find(f => f.lower === 'x-mailer' || f.lower === 'user-agent');
    let best = null, bestScore = 0;
    for (const [n, s] of scores) if (s > bestScore) { best = n; bestScore = s; }
    return { name: best, confident: bestScore >= 3, evidence: evidence.filter(e => e.platform === best), xmailer: xmailer ? xmailer.value : '' };
  }

  // Headers that say how the message was sent and how it can be left.
  function listAndMisc(fields, fromAddr) {
    const items = [];
    const lu = fields.find(f => f.lower === 'list-unsubscribe');
    const lup = fields.find(f => f.lower === 'list-unsubscribe-post');
    if (lu) {
      const hasHttps = /<https:/i.test(lu.value), hasMailto = /<mailto:/i.test(lu.value);
      items.push(item('List-Unsubscribe', (hasHttps ? 'https' : '') + (hasHttps && hasMailto ? ' and ' : '') + (hasMailto ? 'mailto' : ''), 'Unsubscribe mechanism offered to the receiver', 'ok'));
      if (lup && /One-Click/i.test(lup.value)) items.push(item('List-Unsubscribe-Post', lup.value, 'RFC 8058 one-click unsubscribe; required by Google and Yahoo for bulk senders', 'ok'));
      else if (hasHttps) items.push(item('List-Unsubscribe-Post', 'missing', 'No RFC 8058 one-click header; Google and Yahoo require it for bulk senders with an https unsubscribe link', 'warn'));
    }
    const lid = fields.find(f => f.lower === 'list-id');
    if (lid) items.push(item('List-Id', lid.value, 'Mailing list or campaign list identifier', 'info'));
    const prec = fields.find(f => f.lower === 'precedence');
    if (prec) items.push(item('Precedence', prec.value, /bulk|list/i.test(prec.value) ? 'Declares bulk or list mail; auto-responders should stay quiet' : 'Precedence hint', 'info'));
    const auto = fields.find(f => f.lower === 'auto-submitted');
    if (auto && !/^no$/i.test(auto.value)) items.push(item('Auto-Submitted', auto.value, 'Generated automatically (RFC 3834)', 'info'));
    const replyTo = fields.find(f => f.lower === 'reply-to');
    if (replyTo) {
      const rt = P.parseAddresses(replyTo.value)[0];
      if (rt && fromAddr && rt.domain && rt.domain !== fromAddr.domain) items.push(item('Reply-To', rt.address, 'Replies go to a different domain than the From; expected for some platforms, a phishing marker when unexpected', 'warn'));
    }
    const sender = fields.find(f => f.lower === 'sender');
    if (sender) { const s = P.parseAddresses(sender.value)[0]; if (s && fromAddr && s.domain !== fromAddr.domain) items.push(item('Sender', s.address, 'Sent on behalf of the From by another domain', 'info')); }
    const mid = fields.find(f => f.lower === 'message-id');
    if (mid) { const d = P.domainOf(mid.value.replace(/[<>]/g, '')); if (d && fromAddr && d !== fromAddr.domain && HA.psl.orgDomain(d) !== HA.psl.orgDomain(fromAddr.domain)) items.push(item('Message-ID', d, 'Message-ID domain differs from the From domain; normal for sending platforms', 'info')); }
    const xoip = fields.find(f => f.lower === 'x-originating-ip');
    if (xoip) items.push(item('X-Originating-IP', xoip.value.replace(/[\[\]]/g, ''), 'Client address recorded by the submission server', 'info'));
    const prio = fields.find(f => f.lower === 'x-priority' || f.lower === 'importance');
    if (prio && /high|^1|^2/i.test(prio.value)) items.push(item(prio.name, prio.value, 'Marked high priority; filters treat this as a weak spam signal', 'info'));
    return items;
  }

  function decodeAll(fields, auth, chain, fromAddr) {
    const providers = [];
    decodeMicrosoft(fields, providers);
    decodeGoogle(fields, providers);
    decodeGateways(fields, providers);
    return { providers, platform: detectPlatform(fields, auth, chain), misc: listAndMisc(fields, fromAddr) };
  }

  HA.providers = { decodeAll, detectPlatform, decodeMicrosoft, decodeGateways, listAndMisc, PLATFORMS };
})(typeof globalThis !== 'undefined' ? globalThis : this);
