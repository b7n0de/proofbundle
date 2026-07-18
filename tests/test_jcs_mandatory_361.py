"""3.6.1 — RFC-8785 (JCS) canonicalization is mandatory for security verify (PB-2026-0717-06).

Owner-GO (3.6.1): rfc8785 moves from the ``[eval]`` extra into the CORE dependencies. Before 3.6.1
a fresh install WITHOUT rfc8785 accepted a deliberately non-canonical, validly-signed decision
payload with ``ok=true`` / ``structure_ok=true`` on the ``strict=False`` path (False Accept,
PB-2026-0717-06). The fix makes an absent canonicalizer a HARD failure regardless of ``strict`` —
a broken install can never return ok=true over possibly non-canonical bytes — and a non-canonical
payload fails hash_binding. The security profile therefore enforces canonicality by DEFAULT.
"""
import json
import pathlib
import re
import unittest
from unittest import mock

from proofbundle import dsse
from proofbundle.decision import (
    INTOTO_STATEMENT_PAYLOAD_TYPE,
    build_decision_statement,
    emit_decision_receipt,
    verify_decision_receipt,
)
from proofbundle.emit import generate_signer

_EXAMPLES = pathlib.Path(__file__).resolve().parents[1] / "examples"
_PYPROJECT = pathlib.Path(__file__).resolve().parents[1] / "pyproject.toml"
BASE_PRED = json.loads((_EXAMPLES / "decision_receipt_deny.json").read_text(encoding="utf-8"))


def _pub_bytes(signer):
    return signer.public_key().public_bytes_raw()


class JcsMandatory(unittest.TestCase):
    def test_rfc8785_is_core_dependency(self):
        # the Owner-GO'd remediation: rfc8785 is a CORE dependency, not merely an [eval] extra.
        # Parsed without tomllib (core supports Python 3.9+; tomllib is 3.11+): match the
        # `dependencies = [...]` array in [project] and assert rfc8785 is a member.
        text = _PYPROJECT.read_text(encoding="utf-8")
        m = re.search(r"^dependencies\s*=\s*\[(.*?)\]", text, re.MULTILINE | re.DOTALL)
        self.assertIsNotNone(m, "could not find [project].dependencies in pyproject.toml")
        self.assertIn("rfc8785", m.group(1), f"rfc8785 must be a core dependency, got {m.group(1)!r}")

    def test_missing_jcs_engine_is_hard_failure(self):
        # a valid, canonical receipt verified in an install where the JCS engine is UNAVAILABLE must
        # fail closed (structure_ok=False, ok not True) — never a silent pass. Uses the DEFAULT
        # strict=False, proving the security profile enforces canonicality by default.
        signer = generate_signer()
        env = emit_decision_receipt(BASE_PRED, signer, strict=True)
        with mock.patch("proofbundle.decision._rfc8785_available", return_value=False):
            r = verify_decision_receipt(env, _pub_bytes(signer))  # strict defaults to False
        self.assertIs(r["crypto_ok"], True)
        self.assertIs(r["structure_ok"], False)
        self.assertIsNot(r["ok"], True)
        self.assertTrue(any("canonicalizer unavailable" in e for e in r["errors"]), r["errors"])
        self.assertIsNot((r.get("automation") or {}).get("safeForAutomation"), True)

    def test_strict_security_profile_is_default(self):
        # explicit: the missing-JCS hard failure fires on the DEFAULT-parameter call (no strict=True
        # needed). Absence of the canonicalizer is fail-closed by default.
        signer = generate_signer()
        env = emit_decision_receipt(BASE_PRED, signer, strict=True)
        with mock.patch("proofbundle.decision._rfc8785_available", return_value=False):
            default_call = verify_decision_receipt(env, _pub_bytes(signer))
        self.assertIsNot(default_call["ok"], True)
        self.assertIs(default_call["structure_ok"], False)

    def test_noncanonical_statement_fails(self):
        # a validly-signed but deliberately NON-canonical payload fails hash_binding even with the
        # JCS engine present (received bytes are not their own RFC-8785 canonicalization).
        signer = generate_signer()
        stmt = build_decision_statement(BASE_PRED)
        noncanon = json.dumps(stmt, indent=2, sort_keys=False).encode("utf-8")  # pretty, not JCS
        env = dsse.sign_envelope(noncanon, signer, payload_type=INTOTO_STATEMENT_PAYLOAD_TYPE)
        r = verify_decision_receipt(env, _pub_bytes(signer))  # strict defaults to False
        self.assertIs(r["crypto_ok"], True)   # signature is valid over the non-canonical bytes
        self.assertIs(r["structure_ok"], False)   # but canonicality is caught -> fail-closed
        self.assertIsNot(r["ok"], True)

    def test_canonical_statement_still_verifies(self):
        # regression: an honest canonical receipt still verifies (the fix does not break the happy path).
        signer = generate_signer()
        env = emit_decision_receipt(BASE_PRED, signer, strict=True)
        r = verify_decision_receipt(env, _pub_bytes(signer))
        self.assertIs(r["crypto_ok"], True)
        self.assertIs(r["structure_ok"], True)


if __name__ == "__main__":
    unittest.main()
