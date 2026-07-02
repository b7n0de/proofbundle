#!/usr/bin/env bash
# Offline tamper demo (v1.6.1): the pip-only `proofbundle demo` run, plus an exit-code contract.
# Exits 0 iff the honest receipt verifies AND every tamper is caught AND the swapped sample is
# rejected — so this doubles as a fail-closed smoke test for CI. No files, no network, no extras.
set -euo pipefail

PYTHON="${PYTHON:-python3}"

echo "== proofbundle tamper demo (offline, in memory) =="
# run_demo already returns non-zero if any guarantee fails; -m works from a src checkout too.
if [ -d "src/proofbundle" ]; then
  PYTHONPATH="${PYTHONPATH:-}:src" "$PYTHON" -m proofbundle.cli demo
else
  "$PYTHON" -m proofbundle.cli demo
fi
echo
echo "tamper demo passed: honest OK, all tampers caught, swapped sample rejected."
