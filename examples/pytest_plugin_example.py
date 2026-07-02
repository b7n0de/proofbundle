#!/usr/bin/env python3
"""Show the pytest plugin emitting a signed receipt of a test run (opt-in), offline.

In practice: `pip install "proofbundle[pytest,eval]"`, then `PROOFBUNDLE_EMIT=1 pytest --proofbundle`. Here we
run a tiny suite in a subprocess and verify the emitted receipt."""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

from proofbundle import verify_bundle


def main() -> int:
    work = Path(tempfile.mkdtemp())
    (work / "test_demo.py").write_text("def test_ok(): assert 1 + 1 == 2\ndef test_also(): assert 'x' in 'xy'\n")
    env = {**os.environ, "PROOFBUNDLE_EMIT": "1", "PROOFBUNDLE_OUT": str(work), "PROOFBUNDLE_THRESHOLD": "0.5"}
    subprocess.run([sys.executable, "-m", "pytest", "-q", "--proofbundle", "test_demo.py"],
                   cwd=work, env=env, capture_output=True, text=True)
    receipt = work / "proofbundle_pytest_receipt.json"
    ok = receipt.is_file() and verify_bundle(json.loads(receipt.read_text())).ok
    print(f"receipt: {receipt if receipt.is_file() else 'MISSING'}")
    print("=> OK" if ok else "=> FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
