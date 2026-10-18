"""Foreign verifiers as a countercheck of the translator's statements (``proofbundle.receipt_cose``).

Each verifier runs only where the environment names it, and is skipped otherwise, never passed:

* ``PROOFBUNDLE_FOREIGN_PYCOSE_PYTHON``: a Python interpreter with pycose 1.1.0 and cbor2 5.9.0 (pycose 1.1.0
  reads no COSE message with cbor2 6.x, measured on 2026-10-03);
* ``PROOFBUNDLE_FOREIGN_GOCOSE``: a program that verifies a tagged COSE_Sign1 with go-cose v1.3.0, called as
  ``<program> <statement file> <SubjectPublicKeyInfo hex>``, exit 0 for verified;
* ``PROOFBUNDLE_FOREIGN_SCITT_VERIFIER`` with ``PROOFBUNDLE_FOREIGN_SCITT_KEYS``: microsoft/scitt-verifier 0.4.0
  and a SCITT key set file for its ``verify`` command.

The expectations are the measured behaviour of these pinned versions: alg -8 verifies in pycose and go-cose,
alg -19 is refused by both as an unknown algorithm, a changed signature fails in both, and scitt-verifier
evaluates no Ed25519 statement signature under either value. A foreign verifier that starts reading -19 makes
its row red on purpose: the measurement behind the alg card has moved.
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
VECTORS = json.loads((REPO / "tests" / "fixtures" / "receipt_cose" / "vectors.json").read_text(encoding="utf-8"))
STATEMENTS = {v["id"]: bytes.fromhex(v["statement_hex"]) for v in VECTORS["forward"] if "statement_hex" in v}
#: The forward direction writes -19 only (owner choice B, 2026-10-04); the -8 statement is the read vector B2.
STATEMENTS["B2"] = bytes.fromhex(next(v for v in VECTORS["backward"] if v["id"] == "B2")["statement_hex"])
STATEMENTS["B2_changed_signature"] = STATEMENTS["B2"][:-1] + bytes([STATEMENTS["B2"][-1] ^ 1])
ISSUER_KEY = bytes.fromhex(VECTORS["keys_hex"]["issuer"])
SPKI_HEX = "302a300506032b6570032100" + ISSUER_KEY.hex()
_ENV = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "PYTHONHOME")}

_PYCOSE = r"""
import sys
from pycose.keys import OKPKey
from pycose.messages import CoseMessage
data, key = bytes.fromhex(sys.argv[1]), bytes.fromhex(sys.argv[2])
try:
    message = CoseMessage.decode(data)
except Exception as exc:
    print("DECODE_ERROR", type(exc).__name__, exc)
    raise SystemExit(0)
message.key = OKPKey(crv="ED25519", x=key)
try:
    print("verify_signature=" + str(message.verify_signature()))
except Exception as exc:
    print("VERIFY_ERROR", type(exc).__name__, exc)
"""


def _tool(name: str) -> str:
    path = os.environ.get(name)
    if not path:
        pytest.skip(f"{name} is not set; this foreign verifier is not part of this run")
    return path


@pytest.mark.parametrize("vector, expected", [
    ("B2", "verify_signature=True"),
    ("F1", "DECODE_ERROR CoseException Unknown COSE attribute with value: [CoseAlgorithm - -19]"),
    ("B2_changed_signature", "verify_signature=False"),
])
def test_pycose(vector, expected):
    python = _tool("PROOFBUNDLE_FOREIGN_PYCOSE_PYTHON")
    versions = subprocess.run([python, "-c", "import importlib.metadata as m; print(m.version('pycose'), "
                               "m.version('cbor2'))"], capture_output=True, text=True, env=_ENV, check=True)
    assert versions.stdout.split() == ["1.1.0", "5.9.0"], versions.stdout
    out = subprocess.run([python, "-c", _PYCOSE, STATEMENTS[vector].hex(), ISSUER_KEY.hex()], capture_output=True,
                         text=True, env=_ENV, timeout=60, check=False)
    assert out.stdout.strip() == expected, (out.stdout, out.stderr)


@pytest.mark.parametrize("vector, code, expected", [
    ("B2", 0, "VERIFIED alg=-8 (EdDSA)"),
    ("F1", 3, "VERIFIER_ERROR alg=-19 can't create new Verifier for Algorithm(-19): unknown algorithm: "
              "algorithm not supported"),
    ("B2_changed_signature", 1, "VERIFY_FAIL alg=-8 verification error"),
])
def test_go_cose(vector, code, expected, tmp_path):
    program = _tool("PROOFBUNDLE_FOREIGN_GOCOSE")
    statement = tmp_path / f"{vector}.cose"
    statement.write_bytes(STATEMENTS[vector])
    out = subprocess.run([program, str(statement), SPKI_HEX], capture_output=True, text=True, timeout=60, check=False)
    assert (out.returncode, out.stdout.strip()) == (code, expected), out.stderr


@pytest.mark.parametrize("vector, algorithm", [("F1", "alg(-19)"), ("B2", "EdDSA")])
def test_scitt_verifier(vector, algorithm, tmp_path):
    program = _tool("PROOFBUNDLE_FOREIGN_SCITT_VERIFIER")
    keys = _tool("PROOFBUNDLE_FOREIGN_SCITT_KEYS")
    statement, policy = tmp_path / f"{vector}.cose", tmp_path / "policy.json"
    statement.write_bytes(STATEMENTS[vector])
    policy.write_text(json.dumps({"policyId": "receipt-cose/foreign", "policyVersion": "1",
                                  "assertions": {"issuer": [VECTORS["issuer"]]}}), encoding="utf-8")
    out = subprocess.run([program, "verify", "--statement", str(statement), "--scitt-keys", keys, "--policy",
                          str(policy), "--format", "json"], capture_output=True, text=True, timeout=60, check=False)
    report = json.loads(out.stdout)
    statement_seen, appraisal = report["signedStatement"], report["appraisal"]
    codes = {d["code"] for d in appraisal["diagnostics"] if d["severity"] == "error"}
    assert (out.returncode, statement_seen["algorithm"], statement_seen["signatureValid"]) == (3, algorithm, None)
    assert appraisal["checks"]["statementSignature"] == "cannot-evaluate"
    assert "StatementSignatureNotEvaluated" in codes
