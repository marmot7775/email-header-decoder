#!/bin/bash
# The full test suite plus the build, as the nightly fix run calls it.
set -euo pipefail
node --test test/
node build.js
