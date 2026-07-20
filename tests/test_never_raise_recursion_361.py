"""3.6.1 — never-raise covers RecursionError on ALL verify surfaces (PB-2026-0718-11).

The Teil-3 adversarial deep-gate found the never-raise contract broken on the CLI, not only the API: a deeply
nested pack (deep_array.json) raised a RAW, uncaught RecursionError out of `anchor verify-pack` (the
handler used a raw json.load whose except did not cover RecursionError). The strict parser already OWNS
RecursionError (maps it to BundleFormatError "JSON nesting is too deep"); the fix routes every verify
surface through it. This guard asserts the property across the surfaces API + CLI + bundle + key-extract,
with the API and CLI mapping deep nesting to the SAME clean malformed class (never a raw traceback).

NOTE: the full Python-matrix requirement (3.9-3.13) is a CI concern; this asserts the property on the
interpreter it runs under. The parse-depth bound is interpreter-independent (it is the parser's own limit
mapped to a clean error), so a single-version pass is representative of the fix, not of the whole matrix.
"""
import pathlib
import tempfile
import unittest

from proofbundle import dsse
from proofbundle.bundle import load_bundle
from proofbundle.cli import _read_pubkey_line, main
from proofbundle.decision import INTOTO_STATEMENT_PAYLOAD_TYPE, verify_decision_receipt
from proofbundle.emit import generate_signer
from proofbundle.errors import BundleFormatError
from proofbundle._strict_json import loads_strict

_DEEP_ARRAY = "[" * 4000 + "]" * 4000
_DEEP_OBJECT = '{"a":' * 4000 + "1" + "}" * 4000


def _write(text: str) -> str:
    fd, path = tempfile.mkstemp(suffix=".json")
    pathlib.Path(path).write_text(text, encoding="utf-8")
    return path


class BoundedDepth(unittest.TestCase):
    def test_bounded_json_nesting_depth(self):
        # the one parse chokepoint maps pathologically deep nesting to a clean malformed-input error.
        for deep in (_DEEP_ARRAY, _DEEP_OBJECT):
            with self.assertRaises(BundleFormatError) as ctx:
                loads_strict(deep)
            self.assertIn("nesting is too deep", str(ctx.exception))

    def test_bounded_depth_is_interpreter_independent(self):
        # PB-2026-0718-11b: the 4000-deep cases above rely on CPython <=3.11 raising RecursionError DURING
        # parse — on 3.12+ the C scanner accepts far deeper nesting WITHOUT raising, so the RecursionError
        # mapping alone left the bounded-depth guarantee version-dependent (the 3 CI failures on 3.12/3.13/
        # 3.14). This probes a MODERATE depth that parses cleanly on EVERY interpreter (well under any
        # C-recursion limit) yet exceeds the explicit budget.json_depth (64) — so it must be refused by the
        # explicit bound, not by an interpreter-version accident. It fails on 3.11 too without the fix.
        from proofbundle.budget import DEFAULT_BUDGET
        n = DEFAULT_BUDGET.json_depth + 20
        for opener, closer, tail in (("[", "]", ""), ('{"a":', "}", "1")):
            payload = opener * n + tail + closer * n
            with self.assertRaises(BundleFormatError) as ctx:
                loads_strict(payload)
            self.assertIn("nesting is too deep", str(ctx.exception))

    def test_legitimate_depth_still_parses(self):
        # No false positive: a document at the repo's deepest legitimate nesting (observed max 9) must
        # still parse — the depth cap (64) is comfortably above legitimate use.
        import json as _json
        d = 1
        for _ in range(9):
            d = {"n": d}
        self.assertEqual(loads_strict(_json.dumps(d)), d)


class NeverRaiseAllSurfaces(unittest.TestCase):
    def test_cli_anchor_verify_pack_no_raw_recursionerror(self):
        # was a raw RecursionError; now a clean exit 2 (malformed input), no traceback escapes main().
        path = _write(_DEEP_ARRAY)
        try:
            rc = main(["anchor", "verify-pack", path])   # must RETURN, never raise
        finally:
            pathlib.Path(path).unlink()
        self.assertEqual(rc, 2)

    def test_cli_anchor_inspect_no_raw_recursionerror(self):
        path = _write(_DEEP_OBJECT)
        try:
            rc = main(["anchor", "inspect", path])       # must RETURN an int, never raise
        finally:
            pathlib.Path(path).unlink()
        self.assertIsInstance(rc, int)

    def test_api_decision_verify_deep_payload_returns_verdict(self):
        # a validly-signed but pathologically deep payload -> stable fail-closed verdict, never a raise.
        signer = generate_signer()
        env = dsse.sign_envelope(_DEEP_OBJECT.encode("utf-8"), signer,
                                 payload_type=INTOTO_STATEMENT_PAYLOAD_TYPE)
        r = verify_decision_receipt(env, signer.public_key().public_bytes_raw())
        self.assertIs(r["structure_ok"], False)
        self.assertIsNot(r["ok"], True)

    def test_bundle_load_deep_is_clean_malformed(self):
        # load_bundle reads a FILE and routes through loads_strict -> deep nesting is a clean
        # BundleFormatError, never a raw RecursionError.
        path = _write(_DEEP_OBJECT)
        try:
            with self.assertRaises(BundleFormatError):
                load_bundle(path)
        finally:
            pathlib.Path(path).unlink()

    def test_pubkey_extract_deep_returns_empty(self):
        # a hostile "key file" of deep nesting -> "" (fail-closed), never a raw RecursionError.
        self.assertEqual(_read_pubkey_line(_DEEP_OBJECT), "")


class BudgetNeverRaise(unittest.TestCase):
    """PB-2026-0718-11 RE-GATE: budget overruns (wide json_nodes / oversized input_bytes) map to a
    fail-closed verdict on the verify API, never a raw uncaught BudgetExceeded (a ProofBundleError sibling
    of BundleFormatError that the never-raise except tuple originally missed)."""

    def _signed(self, payload_bytes):
        signer = generate_signer()
        env = dsse.sign_envelope(payload_bytes, signer, payload_type=INTOTO_STATEMENT_PAYLOAD_TYPE)
        return env, signer.public_key().public_bytes_raw()

    def test_wide_payload_over_node_budget_returns_verdict(self):
        import json as _json
        from proofbundle.decision import verify_decision_receipt as vd
        from proofbundle.outcome import verify_outcome_receipt as vo
        env, pub = self._signed(_json.dumps([0] * 200005).encode("utf-8"))  # json_nodes over cap, under bytes
        for fn in (vd, vo):
            r = fn(env, pub)   # must NOT raise BudgetExceeded
            self.assertIs(r["structure_ok"], False)
            self.assertIsNot(r["ok"], True)

    def test_oversized_payload_over_byte_budget_returns_verdict(self):
        import json as _json
        from proofbundle.decision import verify_decision_receipt as vd
        env, pub = self._signed(_json.dumps([0] * 3000000).encode("utf-8"))  # ~12MB, over the 8MiB byte cap
        r = vd(env, pub)   # dsse.verify_envelope budget-checks BEFORE parse -> must be caught, not raised
        self.assertIs(r["structure_ok"], False)
        self.assertIsNot(r["ok"], True)


class ApiCliErrorClassParity(unittest.TestCase):
    def test_api_cli_error_class_parity(self):
        # API surface: deep nesting -> BundleFormatError (a ProofBundleError). CLI surface: deep nesting ->
        # exit 2 (malformed input). Same class of outcome (clean malformed), never a raw crash on either.
        with self.assertRaises(BundleFormatError):
            loads_strict(_DEEP_ARRAY)
        path = _write(_DEEP_ARRAY)
        try:
            self.assertEqual(main(["anchor", "verify-pack", path]), 2)
        finally:
            pathlib.Path(path).unlink()


if __name__ == "__main__":
    unittest.main()
