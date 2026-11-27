"""The producer signs no JCS bytes the verifier's parser refuses (RFC 8785 appendix B against the I-JSON rule).

RFC 8785 section 3.2.2.3 writes a double by ECMAScript's Number::toString: an integral double below 1e21 is written
as an integer literal, so the doubles 2**53, -(2**53), 2**68 and 999999999999999700000 of appendix B are written
``9007199254740992``, ``-9007199254740992``, ``295147905179352830000`` and ``999999999999999700000``.
``loads_strict`` refuses every integer literal outside +-(2**53 - 1) (owner choice A of 2026-10-22, the rule of
the Rust verifier). Measured on main c6a32bf7 before this test: ``canonicalize_statement`` wrote those literals,
``export_eval_result_dsse`` signed a statement carrying one, and ``verify_eval_result_dsse`` refused its own
export at the parser. The producer now refuses such a double, so every byte string it signs is one the verifier
reads; every other line of appendix B keeps its RFC 8785 form.
"""
from __future__ import annotations

import struct
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from proofbundle import intoto as I
from proofbundle._strict_json import loads_strict
from proofbundle.canonical import canonicalize_statement
from proofbundle.errors import BundleFormatError


def _double(hexbits: str) -> float:
    return struct.unpack(">d", bytes.fromhex(hexbits))[0]


#: Appendix B lines whose RFC 8785 form is an integer literal outside +-(2**53 - 1).
_OUTSIDE = (("4340000000000000", "9007199254740992"), ("c340000000000000", "-9007199254740992"),
            ("4430000000000000", "295147905179352830000"), ("444b1ae4d6e2ef4e", "999999999999999700000"),
            ("444b1ae4d6e2ef4f", "999999999999999900000"))

#: Every other finite line of appendix B, with the form RFC 8785 gives it.
_INSIDE = (("0000000000000000", "0"), ("8000000000000000", "0"), ("0000000000000001", "5e-324"),
           ("8000000000000001", "-5e-324"), ("7fefffffffffffff", "1.7976931348623157e+308"),
           ("ffefffffffffffff", "-1.7976931348623157e+308"), ("44b52d02c7e14af5", "9.999999999999997e+22"),
           ("44b52d02c7e14af6", "1e+23"), ("44b52d02c7e14af7", "1.0000000000000001e+23"),
           ("444b1ae4d6e2ef50", "1e+21"), ("3eb0c6f7a0b5ed8c", "9.999999999999997e-7"),
           ("3eb0c6f7a0b5ed8d", "0.000001"), ("41b3de4355555553", "333333333.3333332"),
           ("41b3de4355555554", "333333333.33333325"), ("41b3de4355555555", "333333333.3333333"),
           ("41b3de4355555556", "333333333.3333334"), ("41b3de4355555557", "333333333.33333343"),
           ("becbf647612f3696", "-0.0000033333333333333333"), ("43143ff3c1cb0959", "1424953923781206.2"))

_SIGNER = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
_PUB = _SIGNER.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
_CLAIM = {
    "schema": "proofbundle/eval-claim/v0.1",
    "suite": "safety-refusals", "suite_version": "1.2.0",
    "metric": "refusal_rate", "comparator": ">=", "threshold": "0.98", "passed": True,
    "n": 500,
    "model_id_commit": "sha256:" + "a1" * 32,
    "dataset_id_commit": "sha256:" + "b2" * 32,
    "commit_alg": "sha256-salted-v1",
    "issuer": "ed25519:AAAA",
    "timestamp": "2026-07-05T12:00:00Z",
    "assurance_level": "self_attested",
}


class TheProducerSignsOnlyWhatTheParserReads(unittest.TestCase):
    def test_a_double_written_as_an_integer_outside_ijson_is_refused(self):
        for hexbits, form in _OUTSIDE:
            with self.subTest(form=form):
                with self.assertRaises(ValueError) as fang:
                    canonicalize_statement({"v": _double(hexbits)})
                self.assertIn("I-JSON", str(fang.exception))
                # The refusal names the literal RFC 8785 writes, which for 2.0**68 is not int(2.0**68).
                self.assertIn("integer literal %s," % form, str(fang.exception))
                with self.assertRaises(BundleFormatError):
                    loads_strict('{"v":%s}' % form)

    def test_every_other_appendix_b_line_keeps_its_rfc8785_form_and_reads_back(self):
        for hexbits, form in _INSIDE + (("433fffffffffffff", "9007199254740991"),
                                        ("c33fffffffffffff", "-9007199254740991")):
            with self.subTest(form=form):
                body = canonicalize_statement({"v": _double(hexbits)})
                self.assertEqual(body, ('{"v":%s}' % form).encode("ascii"))
                self.assertEqual(canonicalize_statement(loads_strict(body.decode("ascii"))), body)

    def test_the_eval_result_export_is_refused_where_its_verify_would_refuse(self):
        for hexbits, form in _OUTSIDE:
            with self.subTest(form=form):
                try:
                    env = I.export_eval_result_dsse(_CLAIM, _SIGNER, harness={"name": "h", "seed": _double(hexbits)})
                except BundleFormatError as exc:
                    self.assertIn("I-JSON", str(exc))
                    continue
                res = I.verify_eval_result_dsse(env, _PUB)
                self.fail(f"export signed a statement with {form}; its own verify gave ok={res['ok']}: "
                          f"{res.get('content_root_detail') or res.get('statement_detail')}")

    def test_an_export_inside_the_range_still_verifies(self):
        for seed in (9007199254740991.0, 1e21, -0.0, 0.5):
            with self.subTest(seed=seed):
                env = I.export_eval_result_dsse(_CLAIM, _SIGNER, harness={"name": "h", "seed": seed})
                self.assertIs(I.verify_eval_result_dsse(env, _PUB)["ok"], True)


if __name__ == "__main__":
    unittest.main()
