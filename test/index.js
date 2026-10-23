// Entry point so `node --test test/` works: Node 24 resolves a directory
// argument to its index.js instead of scanning it for test files.
'use strict';
const fs = require('fs');
const path = require('path');
for (const f of fs.readdirSync(__dirname).filter(f => f.endsWith('.test.js')).sort()) require(path.join(__dirname, f));
