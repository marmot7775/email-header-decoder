// analyze.js: the one entry point. analyze(text) returns a plain,
// JSON-safe object the page renders and the tests assert on.
//
// Shapes every step keeps:
//   Sentence = { state, technical, plain, src }
//     state is pass | caveat | fail | unknown. caveat is a pass that does
//     not count or carries a condition. technical and plain are the same
//     finding for two readers. src lists the field indexes it came from.
//   Any value the page shows carries src the same way.
//   verdict (step 3) = { state, headline: Sentence, cause: Sentence,
//     consequence: Sentence | null, details: [Sentence], fixes: [Sentence],
//     flags: [Sentence], forwarded: { yes, evidence: [Sentence] } }
//
// Step 2 adds alignment and auth beside input, message, chain and fields.
// verdict and decoded stay null, and pending names the step that fills them.
(function (root) {
  'use strict';
  const HA = (root.HA = root.HA || {});
  const P = HA.parse;
  const say = P.sentence;

  const STEP = 2;
  const PENDING = { verdict: 3, decoded: 3 };

  function all(fields, name) { return fields.filter(f => f.lower === name); }
  function first(fields, name) { return fields.find(f => f.lower === name) || null; }

  function buildMessage(fields) {
    const notes = [];
    const froms = all(fields, 'from');
    let from = null;
    if (froms.length) {
      const addrs = P.parseAddresses(froms[0].value);
      if (addrs[0]) from = Object.assign({}, addrs[0], { src: [froms[0].index], count: addrs.length, domains: Array.from(new Set(addrs.map(a => a.domain).filter(Boolean))) });
      if (addrs.length > 1) notes.push(say('caveat', 'The From field lists ' + addrs.length + ' addresses. DMARC evaluates one author domain; receivers differ on how they treat the rest.', 'The message names more than one sender, which some mail systems treat with suspicion.', [froms[0].index]));
      if (!addrs[0] || !addrs[0].domain) notes.push(say('fail', 'The From field holds no usable address, so there is no author domain to check.', 'The sender\'s address is missing or broken.', [froms[0].index]));
    } else if (fields.length) {
      notes.push(say('fail', 'There is no From field. RFC 5322 3.6 requires one, and without it there is no author domain to check.', 'The message does not say who sent it.', []));
    }
    if (froms.length > 1) {
      notes.push(say('fail', 'The message carries ' + froms.length + ' From fields. RFC 5322 3.6 allows exactly one; the card shows the first. Receivers handle this differently, and many reject the message.', 'This message names two different senders. That is not allowed, and it is a common trick in forged mail.', froms.map(f => f.index)));
    }
    const list = (name) => { const f = first(fields, name); return f ? { addresses: P.parseAddresses(f.value), text: f.decoded, src: [f.index] } : null; };
    const toF = first(fields, 'to');
    const subjF = first(fields, 'subject');
    const dateF = first(fields, 'date');
    const midF = first(fields, 'message-id');
    const rpF = first(fields, 'return-path');
    let returnPath = null;
    if (rpF) {
      const a = P.parseAddresses(rpF.value)[0] || { address: '', domain: '', empty: true };
      returnPath = { address: a.address, domain: a.domain, empty: !!a.empty, src: [rpF.index] };
    }
    let date = null;
    if (dateF) { const d = P.parseDate(dateF.value); date = { text: dateF.value, time: d.time, tzKnown: d.tzKnown, src: [dateF.index] }; }
    return {
      from, fromCount: froms.length,
      to: toF ? { addresses: P.parseAddresses(toF.value), text: toF.decoded, src: [toF.index] } : null,
      cc: list('cc'), sender: list('sender'), replyTo: list('reply-to'), deliveredTo: list('delivered-to'),
      subject: subjF ? { value: subjF.decoded, src: [subjF.index] } : null,
      date,
      messageId: midF ? { value: midF.value.replace(/^<|>$/g, '').trim(), src: [midF.index] } : null,
      returnPath,
      notes,
    };
  }

  // Machine flags the tests and later steps key on. Sentences carry the
  // wording; these carry only the condition.
  function flagsOf(text, parsed, message, chain, auth) {
    const f = [];
    if (!String(text || '').trim()) { f.push('empty-input'); return f; }
    if (!parsed.blockFound) { f.push('not-headers'); return f; }
    if (message.fromCount > 1) f.push('two-from');
    if (!chain.count) f.push('no-received');
    if (!message.date) f.push('no-date');
    if (auth.all.some(r => r.untrusted)) f.push('untrusted-ar');
    if (auth.signatures.some(s => s.partialBody)) f.push('dkim-body-limit');
    if (auth.signatures.some(s => s.expired)) f.push('dkim-expired');
    if (auth.dmarc.disagreement) f.push('dmarc-disagreement');
    return f;
  }

  // The input kind: bare headers, a full .eml, a copy of Gmail's Show
  // original page, or Outlook's Internet headers box.
  const KINDS = { bare: 'headers', eml: 'eml', 'gmail-original': 'show-original', 'outlook-headers': 'outlook-headers', none: 'not-headers' };

  function analyze(text) {
    const parsed = P.parseHeaders(text);
    const fields = parsed.fields;
    const message = buildMessage(fields);
    const chain = HA.received.buildChain(fields);
    const { auth, alignment } = HA.auth.buildAuth(fields, chain, message);
    return {
      version: '0.3',
      step: STEP,
      input: { kind: String(text || '').trim() ? KINDS[parsed.format] || parsed.format : 'empty', bytes: typeof TextEncoder !== 'undefined' ? new TextEncoder().encode(String(text || '')).length : String(text || '').length, repairedLines: parsed.repairedLines, blockFound: parsed.blockFound, format: parsed.format, block: parsed.block, fieldCount: fields.length, bodyPresent: parsed.bodyPresent, notes: parsed.notes },
      message,
      chain,
      verdict: null,
      alignment,
      auth,
      decoded: null,
      pending: Object.assign({}, PENDING),
      fields,
      flags: flagsOf(text, parsed, message, chain, auth),
    };
  }

  HA.analyze = analyze;
  // Node: require() returns this layer; the browser reads HA instead.
  if (typeof module !== 'undefined' && module.exports) module.exports = HA.analyze;
})(typeof globalThis !== 'undefined' ? globalThis : this);
