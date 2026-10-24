// providers.js: the filter verdicts receivers and gateways write, the
// sending platform the headers point to, and the list and sending
// headers. Every item carries state (pass, caveat, fail, unknown, or ''
// for a plain fact), technical and plain wording, and src. Codes not in a
// vendor's published table are shown raw, never guessed.
(function (root) {
  'use strict';
  const HA = (root.HA = root.HA || {});
  const P = HA.parse;
  const say = P.sentence;

  function item(key, value, state, technical, plain, src) { return { key, value, state: state || '', technical, plain: plain || technical, src: src || [] }; }

  // Microsoft 365. Meanings follow Microsoft Learn, "Anti-spam message
  // headers in cloud organizations" (message-headers-eop-mdo).
  const MS_SFV = {
    NSPM: ['pass', 'Spam filtering marked it not spam.', 'Microsoft\'s spam filter decided this is not spam.'],
    SPM: ['fail', 'Spam filtering marked it as spam.', 'Microsoft\'s spam filter decided this is spam.'],
    BLK: ['fail', 'Filtering skipped; blocked because the sender is on the user\'s Blocked Senders list.', 'The recipient had blocked this sender.'],
    SFE: ['pass', 'Filtering skipped; allowed because the sender is on the user\'s Safe Senders list.', 'The recipient had marked this sender as safe, so filtering was skipped.'],
    SKA: ['pass', 'Filtering skipped; the sender is on an allowed senders or domains list in an anti-spam policy.', 'An administrator had allowed this sender, so filtering was skipped.'],
    SKB: ['fail', 'Marked as spam: the sender matched a blocked senders or domains list in an anti-spam policy.', 'An administrator had blocked this sender.'],
    SKI: ['pass', 'Filtering skipped: the source IP is on the IP Allow List in the connection filter policy.', 'An administrator had allowed the sending server, so filtering was skipped.'],
    SKN: ['pass', 'Filtering bypassed by an Exchange mail flow rule.', 'A rule set by an administrator let this message skip the spam filter.'],
    SKQ: ['unknown', 'Released from quarantine to the recipients.', 'The message was held in quarantine and then released.'],
    SKS: ['fail', 'Marked as spam before filtering, by a mail flow rule or an on-premises hybrid decision.', 'A rule set by an administrator marked this message as spam.'],
  };
  const MS_CAT = {
    NONE: ['pass', 'No threat policy applied.', 'No threat was detected.'],
    SPM: ['fail', 'Spam.', 'Filed as spam.'], HSPM: ['fail', 'High confidence spam.', 'Filed as spam with high confidence.'],
    PHSH: ['fail', 'Phishing.', 'Treated as phishing.'], HPHSH: ['fail', 'High confidence phishing.', 'Treated as phishing with high confidence.'], HPHISH: ['fail', 'High confidence phishing.', 'Treated as phishing with high confidence.'],
    BULK: ['caveat', 'Bulk.', 'Treated as bulk mail, such as a newsletter.'],
    SPOOF: ['fail', 'Spoofing: the From domain did not authenticate.', 'Treated as a forged sender because the sender\'s domain did not check out.'],
    MALW: ['fail', 'Malware.', 'Malware was found.'], AMP: ['fail', 'Anti-malware policy.', 'Caught by the malware filter.'], FTBP: ['fail', 'Anti-malware common attachments filter.', 'Caught by the attachment type filter.'],
    SAP: ['fail', 'Safe Attachments (Defender for Office 365).', 'Caught by attachment scanning.'],
    DIMP: ['fail', 'Domain impersonation (Defender for Office 365).', 'Looked like it was pretending to be a protected domain.'], UIMP: ['fail', 'User impersonation (Defender for Office 365).', 'Looked like it was pretending to be a protected person.'],
    GIMP: ['fail', 'Mailbox intelligence impersonation (Defender for Office 365).', 'Looked like it was pretending to be someone the recipient usually hears from.'], BIMP: ['fail', 'Brand impersonation (Defender for Office 365).', 'Looked like it was pretending to be a known brand.'],
    INTOS: ['fail', 'Intra-organization phishing.', 'Treated as phishing from inside the organization.'], OSPM: ['caveat', 'Outbound spam.', 'Treated as outgoing spam.'],
  };
  const MS_SFTY = { '9.19': 'domain impersonation safety tip', '9.20': 'user impersonation safety tip', '9.25': 'first contact safety tip' };
  const MS_DIR = { INB: 'Inbound', OUT: 'Outbound', INT: 'Internal' };

  function decodeMicrosoft(fields) {
    const ff = fields.find(f => f.lower === 'x-forefront-antispam-report');
    const xma = fields.find(f => f.lower === 'x-microsoft-antispam');
    const scl = fields.find(f => f.lower === 'x-ms-exchange-organization-scl');
    const authAs = fields.find(f => f.lower === 'x-ms-exchange-organization-authas');
    if (!ff && !xma && !scl && !authAs) return null;
    const items = [];
    let outcome = null;
    if (ff) {
      const s = [ff.index];
      const kv = {};
      for (const part of ff.value.split(';')) { const i = part.indexOf(':'); if (i > 0) kv[part.slice(0, i).trim().toUpperCase()] = part.slice(i + 1).trim(); }
      if (kv.CAT) {
        const m = MS_CAT[kv.CAT.toUpperCase()];
        items.push(m ? item('CAT', kv.CAT, m[0], 'Threat category: ' + m[1] + ' In cloud tenants CAT, not SCL, says how the message was filed.', m[2], s)
          : item('CAT', kv.CAT, 'unknown', 'Threat category ' + kv.CAT + ' is not in Microsoft\'s published table.', 'Microsoft recorded a category this page does not know.', s));
        if (m) outcome = { state: m[0], key: 'CAT:' + kv.CAT, technical: m[1], plain: m[2], src: s };
      }
      if (kv.SFV) {
        const m = MS_SFV[kv.SFV.toUpperCase()];
        items.push(m ? item('SFV', kv.SFV, m[0], m[1], m[2], s) : item('SFV', kv.SFV, 'unknown', 'Spam filter verdict ' + kv.SFV + ' is not in Microsoft\'s published table.', 'Microsoft recorded a filter result this page does not know.', s));
      }
      if (kv.SCL !== undefined && kv.SCL !== '') items.push(sclItem(kv.SCL, s));
      if (kv.SRV && kv.SRV.toUpperCase() === 'BULK') items.push(item('SRV', kv.SRV, 'caveat', 'Identified as bulk by spam filtering and the BCL threshold.', 'Treated as bulk mail.', s));
      if (kv.IPV) {
        const v = kv.IPV.toUpperCase();
        items.push(v === 'CAL' ? item('IPV', kv.IPV, 'pass', 'Skipped spam filtering: the source IP is on the IP Allow List.', 'An administrator had allowed the sending server.', s)
          : v === 'NLI' ? item('IPV', kv.IPV, '', 'The IP address was not found on any IP reputation list.', 'The sending server was not on any reputation list Microsoft checks.', s)
            : item('IPV', kv.IPV, 'unknown', 'IP verdict ' + kv.IPV + ' is not in Microsoft\'s published table.', 'Microsoft recorded an IP result this page does not know.', s));
      }
      if (kv.SFTY) {
        const t = MS_SFTY[kv.SFTY];
        items.push(item('SFTY', kv.SFTY, t ? 'caveat' : 'unknown', t ? 'Identified as phishing and given the ' + t + '.' : 'Safety tip code ' + kv.SFTY + ' is not in Microsoft\'s published table.', t ? 'Outlook showed a warning: ' + t.replace(' safety tip', '') + '.' : 'Outlook showed a warning this page does not know.', s));
      }
      if (kv.DIR) items.push(item('DIR', kv.DIR, '', (MS_DIR[kv.DIR.toUpperCase()] || kv.DIR) + ' message.', 'Direction: ' + (MS_DIR[kv.DIR.toUpperCase()] || kv.DIR).toLowerCase() + '.', s));
      if (kv.CIP) items.push(item('CIP', kv.CIP, '', 'Connecting IP as Microsoft saw it.', 'The address of the server that handed the message to Microsoft.', s));
      if (kv.CTRY) items.push(item('CTRY', kv.CTRY, '', 'Country or region of the connecting IP.', 'Where the sending server is.', s));
      if (kv.H) items.push(item('H', kv.H, '', 'HELO or EHLO name the connecting server gave.', 'The name the sending server gave itself.', s));
      if (kv.PTR) items.push(item('PTR', kv.PTR, '', 'Reverse DNS of the connecting IP.', 'The name registered for the sending server\'s address.', s));
    }
    if (xma) {
      const m = /BCL:(\d+)/i.exec(xma.value);
      if (m) {
        const n = +m[1];
        const [st, t, p] = n === 0 ? ['pass', 'not from a bulk sender', 'Not bulk mail.'] : n <= 3 ? ['', 'bulk sender with few complaints', 'Bulk mail from a sender with few complaints.'] : n <= 7 ? ['caveat', 'bulk sender with a mixed complaint record', 'Bulk mail from a sender people sometimes complain about.'] : ['fail', 'bulk sender with a high complaint rate', 'Bulk mail from a sender people often complain about.'];
        items.push(item('BCL', m[1], st, 'Bulk complaint level ' + n + ': ' + t + '. The tenant\'s bulk threshold, not shown here, decides the action.', p, [xma.index]));
      }
    }
    if (scl && !ff) items.push(sclItem(scl.value.trim(), [scl.index]));
    if (authAs) {
      const v = authAs.value.trim().toLowerCase();
      items.push(item('AuthAs', authAs.value.trim(), '', v === 'internal' ? 'Treated as internal, authenticated mail.' : v === 'anonymous' ? 'Treated as external, unauthenticated mail.' : 'Authentication class ' + authAs.value.trim() + '.', v === 'internal' ? 'Microsoft treated this as mail from inside the organization.' : 'Microsoft treated this as mail from outside the organization.', [authAs.index]));
    }
    return { name: 'Microsoft 365', items, outcome, note: say('', 'Fields of X-Forefront-Antispam-Report that Microsoft does not document are left out.', 'Only the parts Microsoft explains publicly are shown.', ff ? [ff.index] : []) };
  }

  function sclItem(v, src) {
    const n = parseInt(v, 10);
    const [st, t] = n === -1 ? ['pass', 'filtering skipped'] : n <= 1 ? ['pass', 'not spam'] : n <= 6 ? ['fail', 'spam'] : n <= 9 ? ['fail', 'high confidence spam'] : ['unknown', 'not in the published range'];
    return item('SCL', v, st, 'Spam confidence level ' + v + ': ' + t + '. In cloud tenants SCL mostly matters for on-premises and hybrid Junk filing.', 'Spam score ' + v + ' of 9: ' + t + '.', src);
  }

  // Microsoft composite authentication reason codes, same page.
  const COMPAUTH = {
    '000': 'explicit authentication failed: DMARC failed and the policy is quarantine or reject',
    '001': 'implicit authentication failed: no authentication records, or only weak ones (SPF ~all or ?all, DMARC p=none)',
    '002': 'the organization prohibits this sender and domain pair from sending spoofed mail',
    '010': 'DMARC failed with quarantine or reject, and the From domain is one of the organization\'s own accepted domains',
    '100': 'SPF or DKIM passed and aligns with the From domain', '101': 'DKIM signed by the From domain', '102': 'SPF passed and the MAIL FROM aligns with the From domain',
    '103': 'the From domain aligns with the PTR record of the source IP', '104': 'the PTR record of the source IP aligns with the From domain',
    '108': 'DKIM failed because an earlier legitimate hop modified the body', '109': 'no DMARC record, but the message would pass', '111': 'DMARC hit an error, but SPF or DKIM aligns with the From domain',
    '112': 'a DNS timeout prevented the DMARC record lookup', '115': 'sent from a Microsoft 365 organization where the From domain is an accepted domain', '116': 'the MX record of the From domain aligns with the PTR record of the connecting IP',
    '130': 'an ARC result from a trusted ARC sealer overrode the DMARC failure', '201': 'the PTR of the From domain aligns with the subnet of the connecting IP\'s PTR', '202': 'the From domain aligns with the domain of the connecting IP\'s PTR record',
    '501': 'DMARC not enforced: a valid bounce where sender and recipient had prior contact', '502': 'DMARC not enforced: a valid bounce for a message this organization sent',
    '601': 'the From domain is one of the organization\'s accepted domains (self-to-self or intra-org spoofing)', '905': 'DMARC not enforced because of complex routing, such as mail through on-premises Exchange or another service first',
  };
  const COMPAUTH_CLASS = { '1': 'passed explicit or implicit authentication', '2': 'soft-passed implicit authentication', '3': 'not checked for composite authentication', '4': 'bypassed composite authentication', '6': 'failed implicit authentication', '7': 'passed implicit authentication: DMARC not enforced because the organization has a history of legitimate mail from this infrastructure', '9': 'bypassed composite authentication' };
  function compauthMeaning(reason) {
    const r = String(reason || '').trim();
    if (COMPAUTH[r]) return COMPAUTH[r];
    if (/^\d{3}$/.test(r) && COMPAUTH_CLASS[r[0]]) return COMPAUTH_CLASS[r[0]] + ' (code ' + r + ' is not listed on its own)';
    return '';
  }

  // Gateways and on-host filters. Each is shown only when its headers are.
  function decodeGateways(fields) {
    const out = [];
    const pp = fields.find(f => f.lower === 'x-proofpoint-spam-details');
    if (pp) {
      const s = [pp.index], kv = {}, items = [];
      for (const m of pp.value.matchAll(/([a-z]+)=([^\s]+)/gi)) kv[m[1].toLowerCase()] = m[2];
      if (kv.rule) items.push(item('rule', kv.rule, /^notspam$/i.test(kv.rule) ? 'pass' : /spam|phish|malware/i.test(kv.rule) ? 'fail' : '', 'Classification rule that matched: ' + kv.rule + '.', /^notspam$/i.test(kv.rule) ? 'Proofpoint decided this is not spam.' : 'Proofpoint applied the rule ' + kv.rule + '.', s));
      if (kv.policy) items.push(item('policy', kv.policy, '', 'Policy route applied.', 'The Proofpoint policy that handled it.', s));
      for (const k of ['score', 'spamscore', 'phishscore', 'bulkscore', 'malwarescore', 'suspectscore', 'impostorscore', 'adultscore', 'mlxscore', 'clxscore']) {
        if (kv[k] === undefined) continue;
        const n = +kv[k];
        items.push(item(k, kv[k], isNaN(n) ? 'unknown' : n === 0 ? 'pass' : n >= 50 ? 'caveat' : '', k + ' ' + kv[k] + ' (0 to 100; the customer sets the thresholds).', k.replace('score', '') + ' score ' + kv[k] + ' out of 100.', s));
      }
      out.push({ name: 'Proofpoint', items, outcome: null });
    }
    const mcs = fields.find(f => f.lower === 'x-mimecast-spam-score');
    if (mcs) {
      const items = [item('Spam-Score', mcs.value.trim(), '', 'Mimecast spam score; higher is worse. Thresholds are set per customer.', 'Mimecast\'s spam score. Higher is worse.', [mcs.index])];
      const imp = fields.find(f => f.lower === 'x-mimecast-impersonation-protect');
      if (imp) items.push(item('Impersonation-Protect', imp.value.trim(), 'caveat', 'Impersonation Protect evaluated this message.', 'Mimecast checked whether the sender was pretending to be someone.', [imp.index]));
      out.push({ name: 'Mimecast', items, outcome: null });
    }
    const bss = fields.find(f => f.lower === 'x-barracuda-spam-status');
    const bsc = fields.find(f => f.lower === 'x-barracuda-spam-score');
    if (bss || bsc) {
      const items = [];
      if (bss) { const yes = /^yes/i.test(bss.value.trim()); items.push(item('Spam-Status', bss.value.split(',')[0].trim(), yes ? 'fail' : 'pass', yes ? 'Classified as spam.' : 'Classified as not spam.', yes ? 'Barracuda decided this is spam.' : 'Barracuda decided this is not spam.', [bss.index])); }
      if (bsc) items.push(item('Spam-Score', bsc.value.trim(), '', 'Barracuda score against the customer\'s thresholds.', 'Barracuda\'s spam score.', [bsc.index]));
      out.push({ name: 'Barracuda', items, outcome: null });
    }
    const xss = fields.find(f => f.lower === 'x-spam-status');
    const xsf = fields.find(f => f.lower === 'x-spam-flag');
    if (xss || xsf) {
      const items = [];
      if (xss) {
        const yes = /^\s*yes/i.test(xss.value);
        const score = /score=(-?[\d.]+)/i.exec(xss.value), req = /required=(-?[\d.]+)/i.exec(xss.value), tests = /tests=([^\s]+(?:\s*,\s*[^\s,]+)*)/i.exec(xss.value);
        items.push(item('X-Spam-Status', yes ? 'Yes' : 'No', yes ? 'fail' : 'pass', yes ? 'Classified as spam' + (score && req ? ': score ' + score[1] + ' against a threshold of ' + req[1] + '.' : '.') : 'Classified as not spam' + (score && req ? ': score ' + score[1] + ' against a threshold of ' + req[1] + '.' : '.'), yes ? 'The filter decided this is spam.' : 'The filter decided this is not spam.', [xss.index]));
        if (tests) items.push(item('tests', tests[1].replace(/\s+/g, ''), '', 'Rules that fired.', 'The filter rules this message matched.', [xss.index]));
      } else {
        const yes = /yes/i.test(xsf.value);
        items.push(item('X-Spam-Flag', xsf.value.trim(), yes ? 'fail' : 'pass', yes ? 'Classified as spam.' : 'Classified as not spam.', yes ? 'The filter decided this is spam.' : 'The filter decided this is not spam.', [xsf.index]));
      }
      out.push({ name: 'SpamAssassin or compatible', items, outcome: null });
    }
    const rs = fields.find(f => f.lower === 'x-spamd-result');
    if (rs) {
      const d = /default:\s*(True|False)\s*\[(-?[\d.]+)\s*\/\s*(-?[\d.]+)\]/i.exec(rs.value);
      const yes = d && /true/i.test(d[1]);
      out.push({ name: 'Rspamd', outcome: null, items: [d ? item('Result', d[2] + ' / ' + d[3], yes ? 'fail' : 'pass', (yes ? 'Classified as spam' : 'Classified as not spam') + ': score ' + d[2] + ' against a threshold of ' + d[3] + '.', yes ? 'The filter decided this is spam.' : 'The filter decided this is not spam.', [rs.index]) : item('Result', rs.value.slice(0, 80), 'unknown', 'Rspamd result in a form this page does not read.', 'A filter result this page cannot read.', [rs.index])] });
    }
    return out;
  }

  // Google writes no spam verdict into headers; say so when Google
  // received the message, and explain the two Google fields people ask about.
  function decodeGoogle(fields, chain) {
    const items = [];
    const g = fields.find(f => f.lower === 'x-google-dkim-signature');
    if (g) { const { tags } = P.parseTagList(g.value); items.push(item('X-Google-DKIM-Signature', 'd=' + (tags.d || ''), '', 'Google\'s own internal signature on mail it relays. It is not the sender\'s DKIM and does not count for DMARC.', 'An internal Google stamp. It says nothing about the sender.', [g.index])); }
    const fid = fields.find(f => f.lower === 'feedback-id');
    if (fid) items.push(item('Feedback-ID', fid.value.trim(), '', 'Sender-set identifier Google Postmaster Tools uses to group a sender\'s spam rates (feedback loop).', 'A label the sender adds so Google can report complaint rates back to them.', [fid.index]));
    const receivedByGoogle = chain.trust.operator === 'Google';
    if (!items.length && !receivedByGoogle) return null;
    return { name: 'Google', items, outcome: null, note: receivedByGoogle ? say('unknown', 'Gmail writes no spam or Promotions verdict into headers. Where the message landed is only visible in the mailbox.', 'Gmail does not record in the headers whether it put the message in spam.', []) : null };
  }

  // Sending platforms. A domain matches on a label boundary only, so
  // mg.example is not Mailgun. One header, or two different domain
  // identifiers, make a confident match; one domain is a likely match.
  // Only fingerprints this page can vouch for; a platform missing here
  // is left unnamed rather than guessed.
  const PLATFORMS = [
    { name: 'SendGrid', headers: ['x-sg-eid', 'x-sg-id'], domains: ['sendgrid.net'] },
    { name: 'Mailgun', headers: ['x-mailgun-sid', 'x-mailgun-variables'], domains: ['mailgun.org', 'mailgun.net'] },
    { name: 'Amazon SES', headers: ['x-ses-outgoing'], domains: ['amazonses.com'] },
    { name: 'Mailchimp', headers: ['x-mc-user'], domains: ['mcsv.net', 'mcdlv.net', 'rsgsv.net'] },
    { name: 'Mandrill', headers: ['x-mandrill-user'], domains: ['mandrillapp.com'] },
    { name: 'HubSpot', headers: ['x-hs-cid'], domains: ['hubspotemail.net'] },
    { name: 'Klaviyo', headers: [], domains: ['klaviyomail.com'] },
    { name: 'Constant Contact', headers: ['x-roving-id'], domains: ['ccsend.com'] },
    { name: 'Salesforce Marketing Cloud', headers: ['x-sfmc-stack'], domains: ['exacttarget.com', 'exct.net'] },
    { name: 'Salesforce', headers: [], domains: ['salesforce.com'] },
    { name: 'Marketo', headers: [], domains: ['mktomail.com'] },
    { name: 'SparkPost', headers: [], domains: ['sparkpostmail.com'] },
    { name: 'Postmark', headers: ['x-pm-message-id'], domains: ['mtasv.net'] },
    { name: 'Brevo', headers: [], domains: ['sendinblue.com', 'brevo.com'] },
    { name: 'Mailjet', headers: ['x-mj-mid'], domains: ['mailjet.com', 'mjt.lu'] },
    { name: 'Campaign Monitor', headers: [], domains: ['createsend.com', 'cmail19.com', 'cmail20.com'] },
    { name: 'Customer.io', headers: [], domains: ['customeriomail.com'] },
    { name: 'Zendesk', headers: ['x-zendesk-from-account-id'], domains: ['zendesk.com'] },
    { name: 'Intercom', headers: [], domains: ['intercom-mail.com'] },
    { name: 'Microsoft 365', headers: [], domains: ['outbound.protection.outlook.com', 'onmicrosoft.com'] },
    { name: 'Google Workspace', headers: [], domains: ['gappssmtp.com'] },
  ];
  const onDomain = (d, base) => !!d && (d === base || d.endsWith('.' + base));

  function detectPlatform(fields, message, auth, chain) {
    const names = new Map(fields.map(f => [f.lower, f.index]));
    const ids = [];
    if (message.returnPath && message.returnPath.domain) ids.push({ d: message.returnPath.domain, what: 'Return-Path', src: message.returnPath.src });
    if (auth.spf.domain && !(message.returnPath && message.returnPath.domain === auth.spf.domain)) ids.push({ d: auth.spf.domain, what: 'SPF domain', src: auth.spf.src });
    for (const k of auth.dkim) if (k.domain) ids.push({ d: k.domain, what: 'DKIM d=', src: k.src });
    const t = chain.trust;
    if (t.boundaryIdx >= 0) { const h = chain.hops[t.boundaryIdx]; if (h.fromName) ids.push({ d: h.fromName.toLowerCase(), what: 'sending server', src: h.src }); }
    let best = null;
    for (const p of PLATFORMS) {
      const ev = [];
      for (const h of p.headers) if (names.has(h)) ev.push({ kind: 'header', what: 'header ' + h, src: [names.get(h)] });
      for (const x of ids) if (p.domains.some(b => onDomain(x.d, b))) ev.push({ kind: x.what, what: x.what + ' ' + x.d, src: x.src });
      if (!ev.length) continue;
      const kinds = new Set(ev.map(e => e.kind));
      const score = (kinds.has('header') ? 3 : 0) + kinds.size;
      if (!best || score > best.score) best = { name: p.name, score, evidence: ev, confident: kinds.has('header') || kinds.size >= 2 };
    }
    const xm = fields.find(f => f.lower === 'x-mailer' || f.lower === 'user-agent');
    if (!best) return { name: '', confident: false, evidence: [], mailer: xm ? { value: xm.value.trim(), src: [xm.index] } : null };
    return { name: best.name, confident: best.confident, evidence: best.evidence.map(e => ({ what: e.what, src: e.src })), mailer: xm ? { value: xm.value.trim(), src: [xm.index] } : null };
  }

  // List and sending headers: unsubscribe (RFC 2369, RFC 8058), Reply-To
  // and Sender at another domain, Precedence and Auto-Submitted.
  function listItems(fields, message) {
    const items = [];
    const from = message.from && message.from.domain ? message.from.domain : '';
    const org = (d) => HA.psl.orgDomain(d);
    const lu = fields.find(f => f.lower === 'list-unsubscribe');
    const lup = fields.find(f => f.lower === 'list-unsubscribe-post');
    if (lu) {
      const https = /<https:/i.test(lu.value), mailto = /<mailto:/i.test(lu.value);
      const kinds = [https && 'https', mailto && 'mailto'].filter(Boolean).join(' and ') || 'unreadable';
      items.push(item('List-Unsubscribe', kinds, https || mailto ? 'pass' : 'unknown', 'Unsubscribe link offered (RFC 2369): ' + kinds + '.', 'The message offers an unsubscribe link.', [lu.index]));
      if (lup && /List-Unsubscribe=One-Click/i.test(lup.value)) {
        items.push(item('List-Unsubscribe-Post', 'One-Click', https ? 'pass' : 'caveat', https ? 'RFC 8058 one-click unsubscribe, as Gmail and Yahoo require of bulk senders.' : 'One-click declared, but RFC 8058 needs an https link in List-Unsubscribe and there is none.', https ? 'Recipients can unsubscribe with one click.' : 'One-click unsubscribe is declared but cannot work without a web link.', [lup.index, lu.index]));
      } else if (https) {
        items.push(item('List-Unsubscribe-Post', 'missing', 'caveat', 'No RFC 8058 List-Unsubscribe-Post. Gmail and Yahoo require one-click unsubscribe from bulk senders.', 'There is no one-click unsubscribe, which Gmail and Yahoo require of bulk senders.', [lu.index]));
      }
    }
    const lid = fields.find(f => f.lower === 'list-id');
    if (lid) items.push(item('List-Id', lid.decoded.trim(), '', 'Mailing list identifier (RFC 2919).', 'The message came through a mailing list or campaign list.', [lid.index]));
    const rt = fields.find(f => f.lower === 'reply-to');
    if (rt && from) {
      const a = P.parseAddresses(rt.value)[0];
      if (a && a.domain && org(a.domain) !== org(from)) items.push(item('Reply-To', a.address, 'caveat', 'Replies go to ' + a.domain + ', a different organization from ' + from + '. Normal for some platforms and help desks, a phishing marker when unexpected.', 'Replies go to a different company than the one the message says it is from. Check that this is expected.', [rt.index]));
    }
    const snd = fields.find(f => f.lower === 'sender');
    if (snd && from) {
      const a = P.parseAddresses(snd.value)[0];
      if (a && a.domain && org(a.domain) !== org(from)) items.push(item('Sender', a.address, '', 'Sent on behalf of the From by ' + a.domain + '. DMARC still checks the From domain.', 'Another company sent this on the sender\'s behalf.', [snd.index]));
    }
    const prec = fields.find(f => f.lower === 'precedence');
    if (prec) items.push(item('Precedence', prec.value.trim(), '', /bulk|list|junk/i.test(prec.value) ? 'Declares bulk or list mail; auto-responders should not answer it.' : 'Precedence ' + prec.value.trim() + '.', 'The sender marked this as bulk mail.', [prec.index]));
    const auto = fields.find(f => f.lower === 'auto-submitted');
    if (auto && !/^\s*no\b/i.test(auto.value)) items.push(item('Auto-Submitted', auto.value.trim(), '', 'Generated automatically (RFC 3834).', 'A machine sent this, not a person.', [auto.index]));
    return items;
  }

  function decodeAll(fields, message, auth, chain) {
    const filters = [];
    const ms = decodeMicrosoft(fields); if (ms) filters.push(ms);
    const g = decodeGoogle(fields, chain); if (g) filters.push(g);
    for (const x of decodeGateways(fields)) filters.push(x);
    return { filters, platform: detectPlatform(fields, message, auth, chain), list: listItems(fields, message) };
  }

  HA.providers = { decodeAll, decodeMicrosoft, decodeGateways, decodeGoogle, detectPlatform, listItems, compauthMeaning, PLATFORMS };
})(typeof globalThis !== 'undefined' ? globalThis : this);
