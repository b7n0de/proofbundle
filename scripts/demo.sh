#!/usr/bin/env bash
# Offline, reproducible demonstrator: a REAL eval log -> a signed proofbundle receipt -> verified OK.
# No network, no API key, no GPU. The fixtures under tests/fixtures/ are genuine logs generated offline
# (inspect_ai mockllm/model + lm-evaluation-harness --model dummy). Needs: pip install "proofbundle[eval,inspect]".
set -euo pipefail
cd "$(dirname "$0")/.."
PY="${PYTHON:-python3}"   # portable: default python3, override with PYTHON=... (e.g. a venv python)
echo "== proofbundle offline demo =="
echo
echo "-- inspect_ai (mockllm) eval log  ->  signed receipt  ->  verify --"
"$PY" examples/inspect_receipt.py
echo
echo "-- lm-evaluation-harness (dummy) results  ->  signed receipt  ->  verify --"
"$PY" examples/lm_eval_receipt.py
echo
echo "-- a plain payload bundle round-trip (emit -> verify, in memory) --"
# In-memory so the demo never mutates a tracked file (a clean git tree after the run).
"$PY" -c "from proofbundle import verify_bundle; from proofbundle.emit import emit_bundle, generate_signer; \
b = emit_bundle(b'demo payload', generate_signer()); r = verify_bundle(b); \
print('\n'.join(f'[{\"PASS\" if c.ok else \"FAIL\"}] {c.name}' for c in r.checks)); \
print('=> OK' if r.ok else '=> FAILED'); raise SystemExit(0 if r.ok else 1)"
echo
echo "-- v0.9 standards moat: in-toto test-result (DSSE) / C2SP checkpoint / EEE converter --"
"$PY" examples/intoto_dsse_export.py
"$PY" examples/checkpoint_example.py | tail -2
"$PY" examples/eee_receipt.py
echo
echo "== demo complete: real eval logs turned into signed, offline-verifiable receipts =="
