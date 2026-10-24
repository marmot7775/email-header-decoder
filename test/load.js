// Loads the src modules into one HA namespace, in build order, the way the page does.
'use strict';
const fs = require('fs');
const path = require('path');
const { SRC } = require('../build.js');

for (const f of SRC) require(path.join(__dirname, '..', 'src', f));

function fixture(name) { return fs.readFileSync(path.join(__dirname, 'fixtures', name), 'utf8'); }

module.exports = { HA: globalThis.HA, fixture };
