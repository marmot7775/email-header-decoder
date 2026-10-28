// providers.js: the filter results receivers and gateways write, the
// sending platform the headers point to, and the list and sending
// headers. Every item is { key, raw, level, technical, plain, src }:
// level is pass, info, warn or fail, raw is the value as written. Codes
// not in a vendor's published table are shown raw, never guessed.
(function (root) {
  'use strict';
  const HA = (root.HA = root.HA || {});
  const P = HA.parse;
  const say = P.sentence;

  function item(key, raw, level, technical, plain, src) { return { key, raw: String(raw), level: level || 'info', technical, plain: P.contract(plain || technical), src: src || [] }; }
  const notListed = (key, raw, vendor, src) => item(key, raw, 'info', key + ' ' + raw + ' is not in ' + vendor + '\'s published table, so it is shown as written.', vendor + ' recorded a code this page does not know. It is shown as written.', src);
  const first = (fields, name) => fields.find(f => f.lower === name) || null;

  // Microsoft 365. Meanings follow Microsoft Learn, "Anti-spam message
  // headers in cloud organizations" (message-headers-eop-mdo), the SCL
  // and BCL pages, and the composite authentication reason table.
  const MS_SFV = {
    NSPM: ['pass', 'Spam filtering marked it as not spam.', 'Microsoft\'s spam filter decided this is not spam.'],
    SPM: ['fail', 'Spam filtering marked it as spam.', 'Microsoft\'s spam filter decided this is spam.'],
    BLK: ['fail', 'Filtering skipped; blocked because the sender is on the user\'s Blocked Senders list.', 'The recipient had blocked this sender.'],
    SFE: ['pass', 'Filtering skipped; allowed because the sender is on the user\'s Safe Senders list.', 'The recipient had marked this sender as safe, so filtering was skipped.'],
    SKA: ['pass', 'Filtering skipped: the sender is on an allowed senders or domains list in an anti-spam policy.', 'An administrator had allowed this sender, so filtering was skipped.'],
    SKB: ['fail', 'Marked as spam: the sender matched a blocked senders or domains list in an anti-spam policy.', 'An administrator had blocked this sender.'],
    SKI: ['pass', 'Filtering skipped: the source IP is on the IP Allow List in the connection filter policy.', 'An administrator had allowed the sending server, so filtering was skipped.'],
    SKN: ['pass', 'Filtering bypassed by an Exchange mail flow rule.', 'A rule set by an administrator let this message skip the spam filter.'],
    SKQ: ['info', 'Released from quarantine to the recipients.', 'The message was held in quarantine and then released.'],
    SKS: ['fail', 'Marked as spam before filtering, by a mail flow rule or an on-premises hybrid decision.', 'A rule set by an administrator marked this message as spam.'],
  };
  const MS_CAT = {
    NONE: ['pass', 'No threat policy applied.', 'No threat was detected.'],
    SPM: ['fail', 'Spam.', 'Filed as spam.'], HSPM: ['fail', 'High confidence spam.', 'Filed as spam with high confidence.'],
    PHSH: ['fail', 'Phishing.', 'Treated as phishing.'], HPHSH: ['fail', 'High confidence phishing.', 'Treated as phishing with high confidence.'], HPHISH: ['fail', 'High confidence phishing.', 'Treated as phishing with high confidence.'],
    BULK: ['warn', 'Bulk.', 'Treated as bulk mail, such as a newsletter.'],
    SPOOF: ['fail', 'Spoofing.', 'Treated as a forged sender.'],
    MALW: ['fail', 'Malware.', 'Malware was found.'], AMP: ['fail', 'Anti-malware policy.', 'Caught by the malware filter.'], FTBP: ['fail', 'Anti-malware common attachments filter.', 'Caught by the attachment type filter.'],
    SAP: ['fail', 'Safe Attachments (Defender for Office 365).', 'Caught by attachment scanning.'],
    DIMP: ['fail', 'Domain impersonation (Defender for Office 365).', 'Looked like it was pretending to be a protected domain.'], UIMP: ['fail', 'User impersonation (Defender for Office 365).', 'Looked like it was pretending to be a protected person.'],
    GIMP: ['fail', 'Mailbox intelligence impersonation (Defender for Office 365).', 'Looked like it was pretending to be someone the recipient usually hears from.'], BIMP: ['fail', 'Brand impersonation (Defender for Office 365).', 'Looked like it was pretending to be a known brand.'],
    INTOS: ['fail', 'Intra-organization phishing.', 'Treated as phishing from inside the organization.'], OSPM: ['warn', 'Outbound spam.', 'Treated as outgoing spam.'],
  };
  const MS_SFTY = { '9.19': 'domain impersonation', '9.20': 'user impersonation', '9.25': 'first contact' };
  const MS_DIR = { INB: 'inbound', OUT: 'outbound', INT: 'internal' };

  // SCL: Microsoft publishes -1, 0 and 1, 5 and 6, and 9, and says 5 or
  // higher generally means bad. 2 to 4 have no published meaning.
  function sclItem(v, src, name) {
    const raw = String(v).trim();
    const n = /^-?\d+$/.test(raw) ? parseInt(raw, 10) : NaN;
    const tail = ' In cloud organizations SCL does not decide the filing; CAT does.';
    const known = { '-1': ['pass', 'filtering skipped', 'Spam filtering was skipped.'], 0: ['pass', 'not spam', 'Not spam.'], 1: ['pass', 'not spam', 'Not spam.'], 5: ['fail', 'spam', 'Rated as spam.'], 6: ['fail', 'spam', 'Rated as spam.'], 9: ['fail', 'high confidence spam', 'Rated as spam with high confidence.'] };
    const k = known[n];
    if (k) return item(name, raw, k[0], 'Spam confidence level ' + raw + ': ' + k[1] + '.' + tail, k[2], src);
    if (n === 7 || n === 8) return item(name, raw, 'warn', 'Spam confidence level ' + raw + '. Microsoft gives this value no meaning of its own and says 5 or higher generally means the message is considered bad.' + tail, 'Rated as likely spam.', src);
    if (n >= 2 && n <= 4) return item(name, raw, 'info', 'Spam confidence level ' + raw + ' is inside Microsoft\'s range but has no published meaning, so it is shown as written.' + tail, 'Microsoft recorded a spam score this page cannot interpret.', src);
    return notListed(name, raw, 'Microsoft', src);
  }

  function bclItem(raw, src) {
    const n = /^\d+$/.test(raw) ? +raw : NaN;
    if (!(n >= 0 && n <= 9)) return notListed('BCL', raw, 'Microsoft', src);
    const [lvl, t, p] = n === 0 ? ['pass', 'not from a bulk sender', 'Not bulk mail.'] : n <= 3 ? ['info', 'a bulk sender that generates few complaints', 'Bulk mail from a sender with few complaints.'] : n <= 7 ? ['warn', 'a bulk sender that generates a mixed number of complaints', 'Bulk mail from a sender people sometimes complain about.'] : ['fail', 'a bulk sender that generates a high number of complaints', 'Bulk mail from a sender people often complain about.'];
    return item('BCL', raw, lvl, 'Bulk complaint level ' + n + ': ' + t + '. The tenant\'s threshold decides the action (7 by default, 6 Standard, 5 Strict); it is not in the headers.', p, src);
  }

  // PCL: Exchange publishes 1 to 3 as Neutral and 4 to 8 as Suspicious.
  function pclItem(raw, src) {
    const n = /^\d+$/.test(raw) ? +raw : NaN;
    if (n >= 1 && n <= 3) return item('PCL', raw, 'pass', 'Phishing confidence level ' + n + ': Neutral, the content is not likely phishing.', 'The content did not look like phishing.', src);
    if (n >= 4 && n <= 8) return item('PCL', raw, 'warn', 'Phishing confidence level ' + n + ': Suspicious, the content is likely phishing.', 'The content looked like phishing.', src);
    return notListed('PCL', raw, 'Microsoft', src);
  }

  // Composite authentication reason codes. A code missing from the table
  // gets the meaning Microsoft gives its hundreds class, and says so.
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
  const COMPAUTH_CLASS = { '1': 'passed explicit or implicit authentication', '2': 'soft-passed implicit authentication', '3': 'not checked for composite authentication', '4': 'bypassed composite authentication', '6': 'failed implicit authentication', '7': 'passed implicit authentication', '9': 'bypassed composite authentication' };
  function compauthMeaning(reason) {
    const r = String(reason || '').trim();
    if (COMPAUTH[r]) return COMPAUTH[r];
    if (/^70[1-4]$/.test(r)) return 'DMARC not enforced because the organization has a history of legitimate mail from this infrastructure';
    if (/^\d{3}$/.test(r) && COMPAUTH_CLASS[r[0]]) return COMPAUTH_CLASS[r[0]] + ' (code ' + r + ' has no entry of its own)';
    return '';
  }
  function compauthItem(c) {
    const lvl = { pass: 'pass', fail: 'fail', softpass: 'warn' }[c.result] || 'info';
    const meaning = compauthMeaning(c.reason);
    const raw = c.result + (c.reason ? ' reason=' + c.reason : '');
    if (c.reason && !meaning) return item('compauth', raw, lvl, 'Composite authentication ' + c.result + '. Reason code ' + c.reason + ' is not in Microsoft\'s published table, so it is shown as written.', 'Microsoft\'s own sender check ' + ({ pass: 'passed', fail: 'failed', softpass: 'gave it a soft pass', none: 'came out neutral' }[c.result] || 'came out ' + c.result) + '. Its reason code isn\'t one Microsoft explains publicly.', c.src);
    return item('compauth', raw, lvl, 'Composite authentication ' + c.result + (meaning ? ': ' + meaning + '.' : '.'), 'Microsoft\'s own sender check ' + ({ pass: 'passed', fail: 'failed', softpass: 'gave it a soft pass', none: 'came out neutral' }[c.result] || 'came out ' + c.result) + '. The Technical view gives its reason.', c.src);
  }

  function decodeMicrosoft(fields, auth) {
    const ff = first(fields, 'x-forefront-antispam-report');
    const xma = first(fields, 'x-microsoft-antispam');
    const scl = first(fields, 'x-ms-exchange-organization-scl');
    const authAs = first(fields, 'x-ms-exchange-organization-authas');
    const authSrc = first(fields, 'x-ms-exchange-organization-authsource');
    const pclF = first(fields, 'x-ms-exchange-organization-pcl');
    if (!ff && !xma && !scl && !authAs && !authSrc && !pclF && !auth.compauth) return null;
    const items = [];
    let kv = {};
    if (ff) {
      const s = [ff.index];
      for (const part of ff.value.split(';')) { const i = part.indexOf(':'); if (i > 0) kv[part.slice(0, i).trim().toUpperCase()] = part.slice(i + 1).trim(); }
      if (kv.CAT) {
        const m = MS_CAT[kv.CAT.toUpperCase()];
        items.push(m ? item('CAT', kv.CAT, m[0], 'Threat category: ' + m[1] + ' In cloud organizations CAT, not SCL, says how the message was filtered.', m[2], s) : notListed('CAT', kv.CAT, 'Microsoft', s));
      }
      if (kv.SFV) { const m = MS_SFV[kv.SFV.toUpperCase()]; items.push(m ? item('SFV', kv.SFV, m[0], m[1], m[2], s) : notListed('SFV', kv.SFV, 'Microsoft', s)); }
      if (kv.SCL) items.push(sclItem(kv.SCL, scl && scl.value.trim() === kv.SCL ? [ff.index, scl.index] : s, 'SCL'));
      if (kv.SRV) items.push(kv.SRV.toUpperCase() === 'BULK' ? item('SRV', kv.SRV, 'warn', 'Identified as bulk by spam filtering and the BCL threshold.', 'Treated as bulk mail.', s) : notListed('SRV', kv.SRV, 'Microsoft', s));
      if (kv.IPV) {
        const v = kv.IPV.toUpperCase();
        items.push(v === 'CAL' ? item('IPV', kv.IPV, 'pass', 'Skipped spam filtering: the source IP is on the IP Allow List.', 'An administrator had allowed the sending server.', s)
          : v === 'NLI' ? item('IPV', kv.IPV, 'pass', 'The IP address was not found on any IP reputation list.', 'The sending server was not on any reputation list Microsoft checks.', s)
            : notListed('IPV', kv.IPV, 'Microsoft', s));
      }
      if (kv.SFTY) {
        const t = MS_SFTY[kv.SFTY];
        items.push(t ? item('SFTY', kv.SFTY, 'warn', 'Identified as phishing and given the ' + t + ' safety tip.', 'Outlook showed a warning: ' + t + '.', s) : notListed('SFTY', kv.SFTY, 'Microsoft', s));
      }
      if (kv.DIR) { const d = MS_DIR[kv.DIR.toUpperCase()]; items.push(d ? item('DIR', kv.DIR, 'info', 'Direction: ' + d + ' message.', 'Microsoft treated this as ' + d + ' mail.', s) : notListed('DIR', kv.DIR, 'Microsoft', s)); }
      if (kv.CIP) items.push(item('CIP', kv.CIP, 'info', 'Connecting IP as Microsoft saw it.', 'The address of the server that handed the message to Microsoft.', s));
      if (kv.CTRY) items.push(item('CTRY', kv.CTRY, 'info', 'Country or region of the connecting IP, which may differ from where the message started.', 'Where the server that handed it over is.', s));
      if (kv.H) items.push(item('H', kv.H, 'info', 'HELO or EHLO name the connecting server gave.', 'The name the sending server gave itself.', s));
      if (kv.PTR) items.push(item('PTR', kv.PTR, 'info', 'Reverse DNS of the connecting IP, as Microsoft looked it up.', 'The name registered for the sending server\'s address.', s));
      // SFS lists internal spam rule IDs; Microsoft publishes no meanings for them.
      if (kv.SFS) items.push(notListed('SFS', kv.SFS, 'Microsoft', s));
    }
    const bcl = kv.BCL !== undefined ? { raw: kv.BCL, src: [ff.index] } : xma && /BCL:(\d+)/i.test(xma.value) ? { raw: /BCL:(\d+)/i.exec(xma.value)[1], src: [xma.index] } : null;
    if (bcl) items.push(bclItem(bcl.raw, bcl.src));
    if (scl && !(kv.SCL && scl.value.trim() === kv.SCL)) items.push(sclItem(scl.value, [scl.index], 'X-MS-Exchange-Organization-SCL'));
    const pcl = pclF ? { raw: pclF.value.trim(), src: [pclF.index] } : xma && /PCL:(-?\d+)/i.test(xma.value) ? { raw: /PCL:(-?\d+)/i.exec(xma.value)[1], src: [xma.index] } : null;
    if (pcl) items.push(pclItem(pcl.raw, pcl.src));
    if (authAs) {
      const v = authAs.value.trim();
      const known = { internal: ['Treated as internal, authenticated mail.', 'Microsoft treated this as mail from inside the organization.'], anonymous: ['Treated as external, unauthenticated mail.', 'Microsoft treated this as mail from outside the organization.'],
        external: ['Authentication source External.', 'Microsoft recorded this as authenticated mail from outside the organization.'], partner: ['Authentication source Partner.', 'Microsoft recorded this as mail from a partner organization.'] }[v.toLowerCase()];
      items.push(known ? item('AuthAs', v, 'info', known[0], known[1], [authAs.index]) : notListed('AuthAs', v, 'Microsoft', [authAs.index]));
    }
    if (authSrc && authSrc.value.trim()) items.push(item('AuthSource', authSrc.value.trim(), 'info', 'The server that evaluated authentication for the organization.', 'The Microsoft server that checked who sent this.', [authSrc.index]));
    if (auth.compauth) items.push(compauthItem(auth.compauth));
    const catItem = items.find(i => i.key === 'CAT');
    return group('microsoft', 'Microsoft 365', items, ff ? say('unknown', 'Fields of X-Forefront-Antispam-Report that Microsoft does not document are left out; Microsoft says they are for its own diagnostics.', 'Only the parts Microsoft explains publicly are shown.', [ff.index]) : null, catItem || null);
  }

  // Google writes no spam or placement decision into headers. Its own
  // fields are explained; X-Gm-Spam and X-Gm-Phishy are not documented
  // by Google, so their values are shown as written.
  function decodeGoogle(fields, chain) {
    const items = [];
    const g = first(fields, 'x-google-dkim-signature');
    if (g) { const { tags } = P.parseTagList(g.value); items.push(item('X-Google-DKIM-Signature', 'd=' + (tags.d || ''), 'info', 'Google\'s own internal signature on mail it handles. It is not the sender\'s DKIM and does not count for DMARC.', 'An internal Google stamp. It says nothing about the sender.', [g.index])); }
    for (const name of ['x-gm-spam', 'x-gm-phishy']) {
      const f = first(fields, name);
      if (f) items.push(item(f.name, f.value.trim(), 'info', f.name + ' is a Gmail marker Google does not document, so its value is shown as written.', 'Gmail added a marker it does not explain publicly.', [f.index]));
    }
    for (const name of ['x-gm-message-state', 'x-google-smtp-source']) {
      const f = first(fields, name);
      if (f) items.push(item(f.name, 'opaque', 'info', f.name + ' is an internal Gmail token and carries no readable result.', 'An internal Gmail stamp with nothing readable in it.', [f.index]));
    }
    const byGoogle = chain.trust.operator === 'Google';
    if (!items.length && !byGoogle) return null;
    return group('google', 'Google', items, byGoogle ? say('unknown', 'Gmail writes no spam, Promotions or inbox placement decision into headers. Where the message landed is visible only in the mailbox.', 'Gmail does not record in the headers whether it put the message in spam.', []) : null, null);
  }

  // Rspamd actions, from its documentation. The action is what the
  // filter did; the result line carries the score and reject threshold.
  const RSPAMD_ACTIONS = { 'no action': ['pass', 'No action: the message is not spam.', 'Rspamd decided this is not spam.'], greylist: ['warn', 'Greylisted: delivery was delayed once.', 'Rspamd delayed the message once as a test.'], 'add header': ['fail', 'Marked as spam with a header.', 'Rspamd marked this as spam.'], 'rewrite subject': ['fail', 'Marked as spam in the subject line.', 'Rspamd marked this as spam in its subject.'], 'soft reject': ['warn', 'Temporarily refused.', 'Rspamd asked the sender to try again later.'], reject: ['fail', 'Rejected as spam.', 'Rspamd refused this as spam.'] };

  // Gateways and on-host filters. Each is shown only when its headers are.
  function decodeGateways(fields) {
    const out = [];
    const pp = first(fields, 'x-proofpoint-spam-details');
    if (pp) {
      const s = [pp.index], kv = {}, items = [];
      for (const m of pp.value.matchAll(/([a-z]+)=([^\s]+)/gi)) kv[m[1].toLowerCase()] = m[2];
      if (kv.rule) {
        const r = kv.rule.toLowerCase();
        items.push(r === 'notspam' ? item('rule', kv.rule, 'pass', 'Classification rule notspam: not spam.', 'Proofpoint decided this is not spam.', s)
          : r === 'spam' ? item('rule', kv.rule, 'fail', 'Classification rule spam: spam.', 'Proofpoint decided this is spam.', s)
            : item('rule', kv.rule, 'info', 'Classification rule ' + kv.rule + '. The customer names its own rules, so it is shown as written.', 'Proofpoint applied a rule named ' + kv.rule + '.', s));
      }
      if (kv.policy) items.push(item('policy', kv.policy, 'info', 'Policy route applied.', 'The Proofpoint rule set that handled the message.', s));
      for (const k of ['score', 'spamscore', 'phishscore', 'bulkscore', 'malwarescore', 'suspectscore', 'impostorscore', 'adultscore', 'mlxscore', 'clxscore']) {
        if (kv[k] !== undefined) items.push(item(k, kv[k], 'info', k + ' ' + kv[k] + '. The customer sets the thresholds, which are not in the headers, so the score is shown as written.', 'A Proofpoint score of ' + kv[k] + '. What it leads to is set by the receiving organization.', s));
      }
      out.push(group('proofpoint', 'Proofpoint', items, null, items.find(i => i.key === 'rule' && i.level !== 'info') || null));
    }
    const mc = fields.filter(f => /^x-mimecast-/.test(f.lower));
    if (mc.length) {
      const items = [];
      const sc = first(fields, 'x-mimecast-spam-score');
      if (sc) items.push(item('Spam-Score', sc.value.trim(), 'info', 'Mimecast spam score; higher is worse. Mimecast publishes no scale for it and the customer sets the thresholds.', 'Mimecast\'s spam score. Higher is worse.', [sc.index]));
      const imp = first(fields, 'x-mimecast-impersonation-protect');
      if (imp) {
        // Policy=name;Check=true|false;... Only the checks that fired are named.
        const kv = imp.value.split(';').map(x => x.split('=')).filter(x => x.length === 2).map(x => [x[0].trim(), x[1].trim()]);
        const pol = kv.find(x => x[0] === 'Policy');
        const fired = kv.filter(x => /^true$/i.test(x[1])).map(x => x[0]);
        const known = kv.length > 1;
        items.push(!known ? item('Impersonation-Protect', imp.value.trim().slice(0, 60), 'info', 'Impersonation Protect ran; its value is in a form this page does not read, so it is shown as written.', 'Mimecast checked whether the sender was pretending to be someone.', [imp.index])
          : item('Impersonation-Protect', fired.length ? fired.join(', ') : 'nothing fired', fired.length ? 'warn' : 'pass', 'Impersonation Protect' + (pol ? ' (policy ' + pol[1] + ')' : '') + (fired.length ? ' flagged: ' + fired.join(', ') + '.' : ': none of its ' + (kv.length - (pol ? 1 : 0)) + ' checks fired.'), fired.length ? 'Mimecast thought the sender might be pretending to be someone.' : 'Mimecast found no sign the sender was pretending to be someone.', [imp.index]));
      }
      const bulk = first(fields, 'x-mimecast-bulk-signature');
      if (bulk) items.push(item('Bulk-Signature', bulk.value.trim(), 'info', 'Mimecast bulk signature, shown as written.', 'Mimecast checked whether this is bulk mail.', [bulk.index]));
      if (!items.length) items.push(item(mc[0].name, 'present', 'info', 'Mimecast handled this message; its other fields carry no documented result.', 'Mimecast handled this message.', mc.map(f => f.index)));
      out.push(group('mimecast', 'Mimecast', items, null, null));
    }
    const ip = fields.filter(f => /^x-ironport-/.test(f.lower) || f.lower === 'x-ipas-result');
    if (ip.length) {
      const items = [];
      const filt = first(fields, 'x-ironport-anti-spam-filtered');
      if (filt) items.push(item('Anti-Spam-Filtered', filt.value.trim(), 'info', 'Anti-spam scanning ran on this message.', 'Cisco scanned this message for spam.', [filt.index]));
      for (const name of ['x-ironport-anti-spam-result', 'x-ipas-result']) {
        const f = first(fields, name);
        if (f) items.push(item(f.name, 'opaque', 'info', 'An encoded anti-spam result. Cisco does not publish how to read it.', 'Cisco recorded a result in a form only Cisco can read.', [f.index]));
      }
      const rep = first(fields, 'x-ironport-reputation');
      if (rep) items.push(item('Reputation', rep.value.trim(), 'info', 'SenderBase reputation score of the connecting IP, from -10 to +10; lower is worse. The customer\'s mail policies decide what a score does.', 'Cisco\'s reputation score for the sending server. Lower is worse.', [rep.index]));
      const av = first(fields, 'x-ironport-av');
      if (av) items.push(item('AV', av.value.trim().slice(0, 80), 'info', 'Anti-virus engine stamp, shown as written.', 'Cisco scanned this message for viruses.', [av.index]));
      if (!items.length) items.push(item(ip[0].name, ip[0].value.trim().slice(0, 80), 'info', 'A Cisco Secure Email field with no documented result, shown as written.', 'Cisco handled this message.', [ip[0].index]));
      out.push(group('cisco', 'Cisco Secure Email', items, null, null));
    }
    const bss = first(fields, 'x-barracuda-spam-status'), bsc = first(fields, 'x-barracuda-spam-score'), bsf = first(fields, 'x-barracuda-spam-flag');
    if (bss || bsc || bsf) {
      const items = [];
      if (bss) {
        const yes = /^\s*yes/i.test(bss.value), no = /^\s*no/i.test(bss.value);
        const score = /SCORE=(-?[\d.]+)/i.exec(bss.value), tag = /TAG_LEVEL=(-?[\d.]+)/i.exec(bss.value), kill = /KILL_LEVEL=(-?[\d.]+)/i.exec(bss.value);
        const where = score ? ': score ' + score[1] + (tag ? ', tag level ' + tag[1] : '') + (kill ? ', block level ' + kill[1] : '') : '';
        items.push(yes ? item('Spam-Status', bss.value.split(',')[0].trim(), 'fail', 'Classified as spam' + where + '.', 'Barracuda decided this is spam.', [bss.index])
          : no ? item('Spam-Status', bss.value.split(',')[0].trim(), 'pass', 'Classified as not spam' + where + '.', 'Barracuda decided this is not spam.', [bss.index])
            : notListed('Spam-Status', bss.value.trim().slice(0, 40), 'Barracuda', [bss.index]));
      }
      if (bsc && !bss) items.push(item('Spam-Score', bsc.value.trim(), 'info', 'Barracuda score; the customer sets the thresholds.', 'Barracuda\'s spam score.', [bsc.index]));
      if (bsf && !bss) items.push(/yes/i.test(bsf.value) ? item('Spam-Flag', bsf.value.trim(), 'fail', 'Flagged as spam.', 'Barracuda flagged this as spam.', [bsf.index]) : item('Spam-Flag', bsf.value.trim(), 'pass', 'Not flagged as spam.', 'Barracuda did not flag this as spam.', [bsf.index]));
      out.push(group('barracuda', 'Barracuda', items, null, items.find(i => i.level !== 'info') || null));
    }
    const xss = first(fields, 'x-spam-status'), xsf = first(fields, 'x-spam-flag'), xsc = first(fields, 'x-spam-score');
    if (xss || xsf || xsc) {
      const items = [];
      if (xss) {
        const yes = /^\s*yes\b/i.test(xss.value), no = /^\s*no\b/i.test(xss.value);
        const score = /score=(-?[\d.]+)/i.exec(xss.value), req = /required=(-?[\d.]+)/i.exec(xss.value), tests = /tests=([^\s,]+(?:,\s*[^\s,]+)*)/i.exec(xss.value);
        const where = score && req ? ': score ' + score[1] + ' against a threshold of ' + req[1] : '';
        items.push(yes || no ? item('X-Spam-Status', yes ? 'Yes' : 'No', yes ? 'fail' : 'pass', (yes ? 'Classified as spam' : 'Classified as not spam') + where + '.', yes ? 'The filter decided this is spam.' : 'The filter decided this is not spam.', [xss.index])
          : notListed('X-Spam-Status', xss.value.trim().slice(0, 40), 'SpamAssassin', [xss.index]));
        if (tests) items.push(item('tests', tests[1].replace(/\s+/g, ''), 'info', 'Rules that matched.', 'The filter rules this message matched.', [xss.index]));
      } else if (xsf) {
        const yes = /yes/i.test(xsf.value);
        items.push(item('X-Spam-Flag', xsf.value.trim(), yes ? 'fail' : 'pass', yes ? 'Flagged as spam.' : 'Not flagged as spam.', yes ? 'The filter flagged this as spam.' : 'The filter did not flag this as spam.', [xsf.index]));
      }
      if (xsc && !xss) items.push(item('X-Spam-Score', xsc.value.trim(), 'info', 'Spam score; the threshold is not in the headers.', 'The filter\'s spam score.', [xsc.index]));
      out.push(group('spamassassin', 'SpamAssassin or a compatible filter', items, null, items.find(i => i.level !== 'info') || null));
    }
    const rs = first(fields, 'x-spamd-result'), ra = first(fields, 'x-rspamd-action');
    if (rs || ra) {
      const items = [];
      if (ra) { const a = RSPAMD_ACTIONS[ra.value.trim().toLowerCase()]; items.push(a ? item('X-Rspamd-Action', ra.value.trim(), a[0], a[1], a[2], [ra.index]) : notListed('X-Rspamd-Action', ra.value.trim(), 'Rspamd', [ra.index])); }
      if (rs) {
        const d = /default:\s*(True|False)\s*\[(-?[\d.]+)\s*\/\s*(-?[\d.]+)\]/i.exec(rs.value);
        if (!d) items.push(notListed('X-Spamd-Result', rs.value.trim().slice(0, 60), 'Rspamd', [rs.index]));
        else {
          const over = /true/i.test(d[1]);
          items.push(item('X-Spamd-Result', d[2] + ' / ' + d[3], ra ? 'info' : over ? 'fail' : 'info', 'Score ' + d[2] + ' against a reject threshold of ' + d[3] + (over ? ': over it.' : ': under it. Lower actions, such as adding a spam header, have their own thresholds, which are not in the headers.'), over ? 'Rspamd scored this as spam.' : 'Rspamd scored this below its refusal level.', [rs.index]));
        }
      }
      out.push(group('rspamd', 'Rspamd', items, null, items.find(i => i.level !== 'info') || null));
    }
    return out;
  }

  // Which side wrote a filter header: the receiver when it sits above the
  // Received field the receiver wrote on taking custody. Below that line
  // it was written before custody, by a gateway in front of the receiver
  // or by the sender's side. Exchange Online strips X-MS-Exchange-
  // Organization fields arriving from outside and places its filter
  // fields anywhere in the block, and Google's own fields are Google's,
  // so those groups count as the receiver's when that operator received.
  function sideOf(group, chain) {
    const op = chain.trust.operator;
    if ((group.id === 'microsoft' && op === 'Microsoft') || (group.id === 'google' && op === 'Google')) return 'receiver';
    const b = chain.trust.boundaryIdx;
    if (b < 0) return 'unknown';
    const custody = chain.hops[b].src[0];
    return group.src.every(i => i < custody) ? 'receiver' : 'before-custody';
  }

  function group(id, name, items, note, outcome) {
    const src = Array.from(new Set(items.flatMap(i => i.src))).sort((a, b) => a - b);
    return { id, name, items, note, outcome, src, side: '' };
  }

  // Sending platforms. A domain matches on a label boundary only, so
  // mg.example is not Mailgun. A platform header, or two kinds of domain
  // evidence, make high confidence; Return-Path or DKIM d= alone is
  // medium; the first relay's name alone is low. A platform missing here
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
    const names = new Map();
    for (const f of fields) if (!names.has(f.lower)) names.set(f.lower, f.index);
    const ids = [];
    const rp = message.returnPath && message.returnPath.domain ? message.returnPath : null;
    if (rp) ids.push({ d: rp.domain.toLowerCase(), kind: 'return-path', what: 'Return-Path', src: rp.src });
    for (const k of auth.dkim) if (k.domain) ids.push({ d: k.domain, kind: 'dkim', what: 'DKIM d=', src: k.src });
    const t = chain.trust;
    if (t.boundaryIdx >= 0) { const h = chain.hops[t.boundaryIdx]; if (h.fromName) ids.push({ d: h.fromName.toLowerCase(), kind: 'relay', what: 'first relay', src: h.src }); }
    let best = null;
    for (const p of PLATFORMS) {
      const ev = [];
      for (const h of p.headers) if (names.has(h)) ev.push({ kind: 'header', what: 'header', value: fields[names.get(h)].name, src: [names.get(h)] });
      for (const x of ids) if (p.domains.some(b => onDomain(x.d, b))) ev.push({ kind: x.kind, what: x.what, value: x.d, src: x.src });
      if (!ev.length) continue;
      const kinds = new Set(ev.map(e => e.kind));
      const confidence = kinds.has('header') || kinds.size >= 2 ? 'high' : kinds.has('relay') ? 'low' : 'medium';
      const score = (kinds.has('header') ? 3 : 0) + kinds.size;
      if (!best || score > best.score) best = { name: p.name, score, confidence, evidence: ev.map(e => ({ what: e.what, value: e.value, src: e.src })) };
    }
    const xm = fields.find(f => f.lower === 'x-mailer' || f.lower === 'user-agent');
    const mailer = xm ? { name: xm.name, value: xm.decoded.trim(), src: [xm.index] } : null;
    if (!best) return { name: '', confidence: '', evidence: [], mailer, statement: say('unknown', 'No sending platform this page knows is named in the headers, the DKIM d= domains, the Return-Path, or the first relay. It is left unnamed rather than guessed.', 'These headers do not show which service sent the message.', []) };
    const evText = best.evidence.map(e => e.what + ' ' + e.value).join(', ');
    const allSrc = Array.from(new Set(best.evidence.flatMap(e => e.src))).sort((a, b) => a - b);
    const CONF = { high: ['pass', 'High confidence: '], medium: ['caveat', 'Medium confidence, one domain only: '], low: ['caveat', 'Low confidence, the relay name only: '] };
    const c = CONF[best.confidence];
    return { name: best.name, confidence: best.confidence, evidence: best.evidence, mailer,
      statement: say(c[0], c[1] + 'sent through ' + best.name + ', from ' + evText + '.', best.confidence === 'high' ? 'This message was sent through ' + best.name + '.' : 'This message seems to have been sent through ' + best.name + ', but only one clue points there.', allSrc) };
  }

  // List and sending headers: unsubscribe (RFC 2369, RFC 8058), list
  // identity, Reply-To and Sender at another organization, Message-ID domain, Precedence,
  // Auto-Submitted, and Feedback-ID.
  function listItems(fields, message, auth) {
    const items = [];
    const from = message.from && message.from.domain ? message.from.domain : '';
    const org = (d) => HA.psl.orgDomain(d);
    const lu = first(fields, 'list-unsubscribe');
    const lup = first(fields, 'list-unsubscribe-post');
    if (lu) {
      const https = /<https:/i.test(lu.value), mailto = /<mailto:/i.test(lu.value);
      const kinds = [https && 'https', mailto && 'mailto'].filter(Boolean).join(' and ');
      items.push(kinds ? item('List-Unsubscribe', kinds, 'pass', 'List-Unsubscribe offers ' + kinds + ' (RFC 2369).', https ? 'The message has an unsubscribe link.' : 'The message offers a way to unsubscribe by email.', [lu.index])
        : item('List-Unsubscribe', lu.value.trim().slice(0, 60), 'warn', 'List-Unsubscribe has no https or mailto URI this page can read.', 'The message has an unsubscribe option, but no link in it works.', [lu.index]));
      if (lup && /^\s*List-Unsubscribe=One-Click\s*$/i.test(lup.value)) {
        // RFC 8058 section 4: a DKIM signature must cover both fields.
        const covering = auth.signatures.filter(s => s.signedHeaders.includes('list-unsubscribe') && s.signedHeaders.includes('list-unsubscribe-post'));
        const passed = covering.filter(s => auth.dkim.some(k => k.signature === auth.signatures.indexOf(s) && k.result === 'pass'));
        const sigSrc = covering.flatMap(s => s.src);
        if (!https) items.push(item('List-Unsubscribe-Post', 'One-Click', 'warn', 'List-Unsubscribe-Post declares one-click, but List-Unsubscribe has no https URI, which RFC 8058 requires.', 'One-click unsubscribe is turned on, but it can\'t work without a web link.', [lup.index, lu.index]));
        else if (!covering.length) items.push(item('List-Unsubscribe-Post', 'One-Click', 'warn', 'One-click is declared, but no DKIM-Signature has both List-Unsubscribe and List-Unsubscribe-Post in h=. RFC 8058 section 4 requires that.', 'One-click unsubscribe is turned on, but the digital signature doesn\'t cover it, so Gmail and Yahoo may not offer it. The sender\'s email service can fix that.', [lup.index, lu.index].concat(auth.signatures.flatMap(s => s.src))));
        else if (!passed.length) items.push(item('List-Unsubscribe-Post', 'One-Click', 'warn', 'One-click is declared and signed by d=' + covering.map(s => s.d).join(', ') + ', but no result shows that signature passing.', 'One-click unsubscribe is turned on, but the digital signature that covers it didn\'t check out.', [lup.index, lu.index].concat(sigSrc)));
        else items.push(item('List-Unsubscribe-Post', 'One-Click', 'pass', 'One-click unsubscribe per RFC 8058, covered by the passing DKIM signature of d=' + passed.map(s => s.d).join(', ') + '. Gmail and Yahoo require it of bulk senders.', 'Recipients can unsubscribe with one click, the way Gmail and Yahoo expect.', [lup.index, lu.index].concat(passed.flatMap(s => s.src))));
      } else if (lup) {
        items.push(item('List-Unsubscribe-Post', lup.value.trim().slice(0, 60), 'warn', 'List-Unsubscribe-Post must read exactly List-Unsubscribe=One-Click (RFC 8058). The value is shown as written.', 'The one-click unsubscribe setting is written wrong, so it won\'t work.', [lup.index]));
      } else if (https) {
        items.push(item('List-Unsubscribe-Post', 'missing', 'warn', 'No List-Unsubscribe-Post, so there\'s no one-click unsubscribe (RFC 8058). Gmail and Yahoo require it of bulk senders.', 'There\'s no one-click unsubscribe. Gmail and Yahoo require it from anyone who sends bulk mail.', [lu.index]));
      }
    }
    const lid = first(fields, 'list-id');
    if (lid) items.push(item('List-Id', lid.decoded.trim(), 'info', 'Mailing list identifier (RFC 2919).', 'The message came through a mailing list or a campaign list.', [lid.index]));
    const rt = first(fields, 'reply-to');
    if (rt && from) {
      const a = P.parseAddresses(rt.value)[0];
      if (a && a.domain && org(a.domain) !== org(from)) items.push(item('Reply-To', a.address, 'warn', 'Replies go to ' + a.domain + ', a different organization from ' + from + '. Normal for some platforms and help desks; a phishing sign when unexpected.', 'Replies go to a different company than the one in the From address. Check that you expected that.', [rt.index]));
    }
    const snd = first(fields, 'sender');
    if (snd && from) {
      const a = P.parseAddresses(snd.value)[0];
      if (a && a.domain && org(a.domain) !== org(from)) items.push(item('Sender', a.address, 'info', 'Sent on behalf of the From address by ' + a.domain + '. DMARC still checks the From domain.', 'Another company sent this on the sender\'s behalf.', [snd.index]));
    }
    const mid = message.messageId && /@([^@\s>]+)$/.exec(message.messageId.value);
    if (mid && from) {
      const d = mid[1].toLowerCase();
      items.push(org(d) === org(from) ? item('Message-ID', d, 'info', 'Message-ID domain ' + d + ', the same organization as ' + from + '.', 'The message ID was made by the sender\'s own domain.', message.messageId.src)
        : item('Message-ID', d, 'info', 'Message-ID domain ' + d + ', a different organization from ' + from + '. Usually the sending platform or mail server that created the message.', 'The message ID was made by ' + d + ', usually the service or server that created the message.', message.messageId.src));
    }
    const prec = first(fields, 'precedence');
    if (prec) {
      // bulk, list and junk are the values auto-responders act on (RFC 3834 section 3.1.8).
      const v = prec.value.trim(), known = /^(bulk|list|junk)$/i.test(v);
      items.push(item('Precedence', v, 'info', known ? 'Precedence: ' + v.toLowerCase() + ' marks bulk or list mail, so auto-responders shouldn\'t answer it.' : 'Precedence: ' + v + ' isn\'t bulk, list, or junk, the values mail software acts on. It has no defined effect.',
        known ? 'The sender marked this as ' + (/list/i.test(v) ? 'mailing list' : 'bulk') + ' mail, so automatic replies skip it.' : 'The sender added a label that mail software ignores.', [prec.index]));
    }
    const auto = first(fields, 'auto-submitted');
    if (auto && !/^\s*no\b/i.test(auto.value)) items.push(item('Auto-Submitted', auto.value.trim(), 'info', 'Generated automatically (RFC 3834).', 'A machine sent this, not a person.', [auto.index]));
    const fid = first(fields, 'feedback-id');
    if (fid) items.push(item('Feedback-ID', fid.value.trim(), 'info', 'Sender-set identifier Google Postmaster Tools uses to group the sender\'s spam rates.', 'A label the sender adds so Gmail can report complaint rates back to them.', [fid.index]));
    return items;
  }

  function decodeAll(fields, message, auth, chain) {
    const filters = [];
    const ms = decodeMicrosoft(fields, auth); if (ms) filters.push(ms);
    const g = decodeGoogle(fields, chain); if (g) filters.push(g);
    for (const x of decodeGateways(fields)) filters.push(x);
    for (const f of filters) f.side = f.src.length ? sideOf(f, chain) : 'receiver';
    const notes = [];
    for (const f of filters) {
      if (f.side === 'before-custody') notes.push(say('caveat', f.name + ' headers sit below the receiver\'s first stamp, so they were written before ' + (chain.trust.operator || 'the receiver') + ' took custody, by a gateway in front of it or by the sender\'s side. The headers cannot show which.', 'The ' + f.name + ' results were written before the message reached the receiving mail system, so they may not be that system\'s own.', f.src));
    }
    if (!filters.some(f => f.items.length)) notes.push(say('unknown', 'No filter headers from Microsoft, Google, Proofpoint, Mimecast, Cisco, Barracuda, SpamAssassin or Rspamd. Either no filter wrote one or it was removed before delivery.', 'No spam filter left a readable result in these headers.', []));
    return { filters, platform: detectPlatform(fields, message, auth, chain), list: listItems(fields, message, auth), notes };
  }

  HA.providers = { decodeAll, decodeMicrosoft, decodeGateways, decodeGoogle, detectPlatform, listItems, compauthMeaning, PLATFORMS, TABLES: { MS_SFV, MS_CAT, MS_SFTY, MS_DIR, COMPAUTH, RSPAMD_ACTIONS } };
  // Node: require() returns this layer; the browser reads HA instead.
  if (typeof module !== 'undefined' && module.exports) module.exports = HA.providers;
})(typeof globalThis !== 'undefined' ? globalThis : this);
