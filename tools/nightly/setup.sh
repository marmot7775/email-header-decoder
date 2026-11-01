#!/bin/bash
# Installs what the nightly fix run needs to run this repository's tests.
# Zero dependency project: Node 22 from the runner is enough.
set -euo pipefail
node --version
