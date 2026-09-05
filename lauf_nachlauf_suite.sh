#!/bin/bash
# Vollsuite + Kill-Beweis des tlogproof-Operators auf f6ff2af7, selbst gefahren (Owner 21:15Z, Punkt 2).
cd /mnt/bigstore/claude_scratch/kraxo_f6ff2af || exit 9
PY=/home/konrad/proofbundle/.venv/bin/python
{
  echo "=== NACHMESSUNG nachlauf-Lane, Commit f6ff2af7bd8d2466e2c7ee4267b5d566de4b279a ==="
  echo "Erzeugt: $(date -u +%Y-%m-%dT%H:%M:%SZ)  Konto kraxo, eigener Worktree, kein Lane-Baum"
  echo "HEAD: $(git rev-parse HEAD)"
  echo "git status:"; git --no-optional-locks status --porcelain=v1
  echo "Interpreter: $PY  ($($PY -V 2>&1))"
  echo "--- VOLLSUITE ---"
} > vollsuite_f6ff2af_raw.log 2>&1
PYTHONPATH="$PWD/src:$PWD/scripts" "$PY" -m pytest tests/ -q -p no:randomly >> vollsuite_f6ff2af_raw.log 2>&1
rc=$?
echo "EXIT_CODE=$rc" >> vollsuite_f6ff2af_raw.log
echo "PYTEST_DONE rc=$rc" >> vollsuite_f6ff2af_raw.log
echo "FERTIG $(date -u +%Y-%m-%dT%H:%M:%SZ) rc=$rc" > vollsuite_f6ff2af_ENDE.txt
