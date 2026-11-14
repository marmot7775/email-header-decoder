'use strict';
// The delivery sentence: what the result means for mail from here on,
// written only where an RFC or a published sender rule covers it.
const test = require('node:test');
const assert = require('node:assert');
const S = require('../scripts/sentences.js');

const of = (name) => { const c = S.CASES.find(x => x[0] === name); return S.run(c[0], c[1], c[2]).delivery; };

test('delivery: a pass on SPF and DKIM meets the bulk sender rules, and says what the headers leave out', () => {
  const d = of('pass by DKIM');
  assert.equal(d.state, 'pass');
  assert.match(d.technical, /SPF and DKIM both pass, and one aligns.*publishes a DMARC record/);
  assert.match(d.plain, /spam complaints and unsubscribe links, which the headers don't show/);
  assert.match(of('pass computed, no DMARC result reported').technical, /DMARC record, which these headers do not show/);
});

test('delivery: a pass on one method alone falls short of the bulk rule', () => {
  const d = of('pass by SPF');
  assert.equal(d.state, 'caveat');
  assert.match(d.technical, /^Only SPF passes here.*bulk senders need both/);
  assert.match(d.plain, /digital signature \(DKIM\)/);
});

test('delivery: a failure names the policy it falls under, quoted from the receiver', () => {
  const r = of('fail with DKIM unaligned');
  assert.equal(r.state, 'fail');
  assert.match(r.technical, /^The DMARC record of shop\.example carries p=reject.*RFC 9989 4\.7.*not required to honor/);
  assert.match(of('Microsoft action quarantine').technical, /action=quarantine shows.*treat mail that fails DMARC as suspicious/);
  assert.match(of('Microsoft action oreject').plain, /refuse mail that fails this way/);
});

test('delivery: with no policy quoted, the provider rule speaks', () => {
  assert.match(of('fail computed, no DMARC result reported').technical, /Bulk senders must pass DMARC with SPF or DKIM aligned/);
  assert.match(of('compauth 4xx, bypassed').technical, /passed neither SPF nor DKIM.*5\.7\.26/);
  assert.match(of('dmarc none, would pass').technical, /must publish a DMARC record, at least p=none/);
  assert.match(of('dmarc permerror').technical, /no DMARC processing.*stands as a domain with no record/);
});

test('delivery: forwards and lists speak of the copies, not the sender', () => {
  assert.match(of('forwarded with arc=pass').technical, /RFC 7960 2\.2.*Mail sent straight from shop\.example is not affected/);
  assert.match(of('fail through a mailing list').technical, /RFC 7960 3\.2\.3/);
  assert.doesNotMatch(of('fail through a mailing list').plain, /straight to people/);
  assert.match(of('fail through a mailing list that kept its record').plain, /straight to people/);
});

test('delivery: nothing is written where no source covers it', () => {
  for (const n of ['pass reported with nothing aligned', 'fail with SPF temperror', 'fail with DKIM temperror', 'dmarc temperror', 'fail with the receiver judging differently', 'dmarc result outside RFC 9989', 'forwarded, noted but not relied on', 'pass reported with DKIM nothing backs', 'no Authentication-Results', 'no Received', 'two From fields', 'display name impersonation', 'fail with a list claim and nothing from before the list', 'fail with a hidden character in the From domain'])
    assert.equal(of(n), null, n);
});

test('delivery: an rsa-sha1 pass says what a current verifier does with it', () => {
  const d = of('pass by an rsa-sha1 signature');
  assert.equal(d.state, 'caveat');
  assert.match(d.technical, /RFC 8301 3\.1.*DMARC fails there.*carries p=reject/);
});
