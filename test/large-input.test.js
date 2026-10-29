// Large pastes: analyze() has to stay fast on each of these, so no regular
// expression or loop can go quadratic on a long value. docs/plan.md step 4.
'use strict';
const test = require('node:test');
const assert = require('assert');
const { HA } = require('./load');
const inputs = require('./large-inputs');

const LIMIT_MS = 500;

const { RUNS, ...five } = inputs;
for (const [name, build] of Object.entries(five).concat(Object.entries(RUNS))) {
  test('analyze() under ' + LIMIT_MS + ' ms: ' + name, () => {
    const text = build();
    const t = process.hrtime.bigint();
    const R = HA.analyze(text);
    const ms = Number(process.hrtime.bigint() - t) / 1e6;
    assert.ok(R.input.blockFound, 'header block found');
    assert.ok(ms < LIMIT_MS, name + ' took ' + ms.toFixed(0) + ' ms');
  });
}

test('rich text from Outlook reads every field', () => {
  const R = HA.analyze(inputs['Outlook rich text']());
  assert.strictEqual(R.chain.count, 60);
  assert.ok(R.fields.some(f => f.lower === 'authentication-results'));
});
