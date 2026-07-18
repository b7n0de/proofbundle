"""3.6.1 — verify() never-raises for untrusted input (PB-2026-0717-07).

Before 3.6.1 a validly-signed but syntactically malformed payload raised BundleFormatError from
verify_decision_receipt / verify_outcome_receipt (no structured verdict). The fix: verify() ALWAYS
returns a stable fail-closed verdict (structure_ok=False, ok=False, safeForAutomation=False) for
untrusted input; the reason is preserved in errors[]. The explicit verify_*_or_raise() variants raise.

Each vector is a body signed by a key we control, so crypto_ok is True (the signature IS valid over
the malformed bytes) and only the STRUCTURE fails — isolating the never-raise contract from a crypto
failure. GRENZE (honest): the malformed-input matrix here covers malformed/duplicate/non-JSON/bad-UTF8
JSON payloads; the Rust error-class parity (python_rust_error_class_parity) is a separate open item.
"""
import unittest

from proofbundle import dsse
from proofbundle.decision import (
    INTOTO_STATEMENT_PAYLOAD_TYPE,
    verify_decision_receipt,
    verify_decision_receipt_or_raise,
)
from proofbundle.emit import generate_signer
from proofbundle.errors import BundleFormatError
from proofbundle.outcome import verify_outcome_receipt, verify_outcome_receipt_or_raise

_MALFORMED = {
    "truncated_json": b'{"_type":"https://in-toto.io/Statement/v1",',
    "duplicate_key": b'{"a":1,"a":2}',
    "not_json": b"not json at all",
    "bad_utf8": b"\xff\xfe\x00",
}


class NeverRaise(unittest.TestCase):
    def setUp(self):
        self.signer = generate_signer()
        self.pub = self.signer.public_key().public_bytes_raw()

    def _sign(self, body):
        return dsse.sign_envelope(body, self.signer, payload_type=INTOTO_STATEMENT_PAYLOAD_TYPE)

    def test_all_untrusted_inputs_return_verdict_not_exception_decision(self):
        for name, body in _MALFORMED.items():
            env = self._sign(body)
            r = verify_decision_receipt(env, self.pub)  # must not raise
            self.assertIs(r["crypto_ok"], True, name)   # signature valid over the malformed bytes
            self.assertIs(r["structure_ok"], False, name)
            self.assertIsNot(r["ok"], True, name)
            self.assertIsNot((r.get("automation") or {}).get("safeForAutomation"), True, name)
            self.assertTrue(r["errors"], name)          # the reason is always recorded

    def test_all_untrusted_inputs_return_verdict_not_exception_outcome(self):
        for name, body in _MALFORMED.items():
            env = self._sign(body)
            r = verify_outcome_receipt(env, self.pub)   # must not raise
            self.assertIs(r["structure_ok"], False, name)
            self.assertIsNot(r["ok"], True, name)
            self.assertIsNot((r.get("automation") or {}).get("safeForAutomation"), True, name)

    def test_verify_or_raise_is_explicit_decision(self):
        env = self._sign(_MALFORMED["duplicate_key"])
        with self.assertRaises(BundleFormatError):
            verify_decision_receipt_or_raise(env, self.pub)

    def test_verify_or_raise_is_explicit_outcome(self):
        env = self._sign(_MALFORMED["not_json"])
        with self.assertRaises(BundleFormatError):
            verify_outcome_receipt_or_raise(env, self.pub)

    def test_python_rust_error_class_parity(self):
        self.skipTest("BLOCKED-rust-fix-open: Rust never-raise/error-class parity is a separate open "
                      "item (PB-2026-0717-07 Rust half); parity is NOT-RUN, not a PASS.")


if __name__ == "__main__":
    unittest.main()
