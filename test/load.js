// Loads the src modules into one HA namespace, in build order, the way the page does.
'use strict';
const fs = require('fs');
const path = require('path');
const { SRC } = require('../build.js');

const ALL = ['parse.js', 'psl.js', 'received.js', 'auth.js', 'providers.js', 'verdict.js', 'analyze.js'];

const files = process.env.HV_SRC === 'all' ? ALL : SRC;
for (const f of files) require(path.join(__dirname, '..', 'src', f));

function fixture(name) { return fs.readFileSync(path.join(__dirname, 'fixtures', name), 'utf8'); }

module.exports = { HA: globalThis.HA, fixture };
