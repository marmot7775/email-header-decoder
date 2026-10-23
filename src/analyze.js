// analyze.js: the one entry point. analyze(text) returns a plain object
// the page renders and the tests assert on. The result is JSON-safe
// except for Date objects on hops, which the renderer formats.
(function (root) {
  'use strict';
  const HA = (root.HA = root.HA || {});
  const P = HA.parse;

  function first(fields, name) { return fields.find(f => f.lower === name) || null; }

  function analyze(text) {
    const parsed = P.parseHeaders(text);
    const fields = parsed.fields;
    const fromField = first(fields, 'from');
    const fromAddrs = fromField ? P.parseAddresses(fromField.value) : [];
    const fromAddr = fromAddrs[0] || null;
    const fromDomain = fromAddr ? fromAddr.domain : '';

    const chain = HA.received.buildChain(fields);
    const auth = HA.auth.buildAuth(fields, fromDomain);
    const decoded = HA.providers.decodeAll(fields, auth, chain, fromAddr);
    const verdict = HA.verdict.build({ auth, chain, fields, fromAddr, fromAddrs, decoded });

    const toField = first(fields, 'to');
    const subj = first(fields, 'subject');
    const dateField = first(fields, 'date');
    const mid = first(fields, 'message-id');
    const message = {
      from: fromAddr, fromDisplay: fromField ? fromField.decoded : '',
      to: toField ? P.parseAddresses(toField.value) : [],
      subject: subj ? subj.decoded : '',
      date: dateField ? P.parseDate(dateField.value) : null,
      messageId: mid ? mid.value.replace(/^<|>$/g, '') : '',
      deliveredTo: (first(fields, 'delivered-to') || { value: '' }).value,
    };

    // Alignment rows: one per identifier the receiver evaluated.
    const rows = [];
    const org = HA.psl.orgDomain(fromDomain);
    rows.push({ id: 'From', domain: fromDomain, result: '', aligned: null, note: org && org !== fromDomain ? 'organizational domain ' + org : 'organizational domain' });
    if (auth.spf.reported || auth.spf.domain) rows.push({ id: 'SPF', domain: auth.spf.domain, identity: auth.spf.identity, result: auth.spf.result, aligned: auth.spf.align.aligned, strict: auth.spf.align.strict, mode: auth.spf.align.mode, note: auth.spf.identity === 'helo' ? 'HELO identity only' : auth.spf.identity === 'return-path' ? 'from Return-Path, no SPF result recorded' : '' });
    for (const k of auth.dkim) rows.push({ id: 'DKIM', domain: k.domain, selector: k.selector, result: k.result || 'not evaluated', aligned: k.align.aligned, strict: k.align.strict, mode: k.align.mode, note: k.unreported ? 'signature present, no result recorded' : (k.matched ? '' : 'result recorded, signature header not found') });

    return {
      version: '0.1',
      input: { headerLineCount: parsed.headerLineCount, fieldCount: fields.length, bodyPresent: parsed.bodyPresent, blockFound: parsed.blockFound, notes: parsed.notes },
      message, verdict,
      alignment: { fromDomain, orgDomain: org, rows, policy: auth.dmarc.policy, computed: auth.computed, reported: auth.dmarc.result },
      auth, chain, decoded, fields,
    };
  }

  HA.analyze = analyze;
})(typeof globalThis !== 'undefined' ? globalThis : this);
