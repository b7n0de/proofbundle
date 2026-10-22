"""DELTA-LOADS-STRICT-NUR-JSON-ZAHLEN-01: the strict reader takes only JSON as RFC 8259 and I-JSON define it.

`proofbundle._strict_json.loads_strict` refused duplicate keys, a lone surrogate and bytes after the value, and at
07b6122c it still took five things no JSON reader of another verifier takes (measured 2026-10-22): the constants
`NaN`, `Infinity` and `-Infinity`, a number that overflows to an infinite double (`1e400`), a UTF-8 byte order mark in
front of bytes, and bytes in UTF-16 or UTF-32. Each is refused now with the error a duplicate key already raises
(`BundleFormatError`), so every caller handles it the way it handles a duplicate key.

The first class holds the reader. The second holds one case per verify path whose outcome changed: each was a
positive verdict before (or a value that left the surface as JSON no reader parses) and is a refusal now. Integers
outside the I-JSON range are not decided here; that is a question to the owner.
"""
from __future__ import annotations

import base64
import contextlib
import hashlib
import io
import json
import os
import tempfile
import unittest
import zlib

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from proofbundle import generate_signer
from proofbundle._strict_json import loads_strict
from proofbundle.errors import BundleFormatError

BOM = b"\xef\xbb\xbf"


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _unb64u(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _raw_pub(key) -> bytes:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _resigned(compact_jws: str, key, *, payload: bytes = None, header: bytes = None) -> str:
    """A compact JWS with its header or payload bytes replaced and signed again with ``key`` (EdDSA)."""
    h, p, _s = compact_jws.split(".")
    h = _b64u(header) if header is not None else h
    p = _b64u(payload) if payload is not None else p
    return f"{h}.{p}.{_b64u(key.sign(f'{h}.{p}'.encode('ascii')))}"


class TheReaderTakesOnlyJson(unittest.TestCase):

    REFUSED_NUMBERS = ('{"a": NaN}', '[Infinity]', '[-Infinity]', '{"a": [1, {"b": NaN}]}', '1e400', '-1e400',
                       '[1E400]', '{"a": 1.5e309}', '[-2e308]')

    def test_RED_nan_infinity_and_numbers_that_overflow_to_infinity_are_refused(self):
        for text in self.REFUSED_NUMBERS:
            for form in (text, text.encode("utf-8")):
                with self.subTest(form=form):
                    with self.assertRaises(BundleFormatError):
                        loads_strict(form)

    def test_CONTROL_finite_numbers_up_to_the_largest_double_are_taken(self):
        for text, want in (("1.7976931348623157e308", 1.7976931348623157e308),
                           ("-1.7976931348623157e308", -1.7976931348623157e308),
                           ("5e-324", 5e-324), ("1e308", 1e308), ("0.0", 0.0), ("-0.0", -0.0), ("1e-400", 0.0)):
            with self.subTest(text=text):
                self.assertEqual(loads_strict(text), want)
                self.assertEqual(loads_strict(text.encode("ascii")), want)

    def test_RED_a_byte_order_mark_in_front_of_bytes_is_refused(self):
        with self.assertRaises(BundleFormatError):
            loads_strict(BOM + b'{"a": 1}')

    def test_RED_bytes_in_utf16_or_utf32_are_refused(self):
        text = '{"a": 1}'
        for codec in ("utf-16", "utf-16-le", "utf-16-be", "utf-32", "utf-32-le", "utf-32-be"):
            with self.subTest(codec=codec):
                with self.assertRaises(BundleFormatError):
                    loads_strict(text.encode(codec))

    def test_CONTROL_utf8_bytes_and_text_are_read_as_before(self):
        self.assertEqual(loads_strict(b'{"a": "\xc3\xa9", "b": [1, 2.5, true, null]}'),
                         {"a": "é", "b": [1, 2.5, True, None]})
        self.assertEqual(loads_strict('{"a": "é"}'), {"a": "é"})

    def test_CONTROL_text_with_a_byte_order_mark_stays_refused_as_before(self):
        """Python's json refuses a leading U+FEFF in text with JSONDecodeError (a ValueError); that is
        unchanged."""
        with self.assertRaises(ValueError):
            loads_strict("﻿{}")

    def test_the_refusal_is_the_error_of_a_duplicate_key(self):
        refusals = []
        for form in ('{"a": 1, "a": 2}', '{"a": NaN}', BOM + b"{}", "{}".encode("utf-16")):
            try:
                loads_strict(form)
            except Exception as exc:  # noqa: BLE001 - the type is what is measured
                refusals.append(type(exc))
        self.assertEqual(refusals, [BundleFormatError] * 4)


class EachVerifyPathWhoseOutcomeChanged(unittest.TestCase):
    """One case per verify path of step 1 whose verdict changes. Each asserts the outcome now."""

    def test_RED_a_key_binding_jwt_with_iat_nan_is_not_fresh_forever(self):
        """kbjwt.verify_key_binding read `iat` as int or float; with NaN both freshness comparisons are false,
        so the presentation was fresh at any evaluation time (ok and fresh True at 07b6122c)."""
        from test_kbjwt import IAT, _issue_presented  # noqa: PLC0415
        from proofbundle.kbjwt import split_key_binding, verify_key_binding  # noqa: PLC0415
        presented, _issuer, holder = _issue_presented()
        sd_part, kb = split_key_binding(presented)
        payload = json.loads(_unb64u(kb.split(".")[1]))
        self.assertTrue(verify_key_binding(presented, expected_aud="verifier.example", expected_nonce="n-1",
                                           now=IAT + 10)["ok"], "precondition: the genuine presentation verifies")
        payload["iat"] = float("nan")
        forged_kb = _resigned(kb, holder, payload=json.dumps(payload).encode("utf-8"))
        res = verify_key_binding(sd_part + forged_kb, expected_aud="verifier.example", expected_nonce="n-1",
                                 now=IAT + 10 ** 9)
        self.assertFalse(res["ok"], res)
        self.assertIsNot(res["fresh"], True, res)

    def _status_token(self):
        from proofbundle.statuslist import issue_status_list_token  # noqa: PLC0415
        signer = generate_signer()
        token = issue_status_list_token([0, 1, 0, 0], uri="https://issuer.example/sl/1", signer=signer,
                                        iat=1_780_000_000)
        return token, signer

    def test_RED_a_status_list_token_with_a_byte_order_mark_or_in_utf16_is_refused(self):
        from proofbundle.statuslist import verify_status_snapshot  # noqa: PLC0415
        token, signer = self._status_token()
        body = _unb64u(token.split(".")[1])
        args = dict(expected_uri="https://issuer.example/sl/1", index=0, issuer_pubkey=_raw_pub(signer))
        self.assertTrue(verify_status_snapshot(token, **args)["ok"], "precondition")
        for label, raw in (("BOM", BOM + body), ("UTF-16", body.decode("utf-8").encode("utf-16"))):
            with self.subTest(label=label):
                res = verify_status_snapshot(_resigned(token, signer, payload=raw), **args)
                self.assertFalse(res["ok"], res)

    def test_RED_an_enclave_attestation_carrying_nan_is_refused(self):
        from proofbundle.experimental.enclave import (issue_enclave_attestation,  # noqa: PLC0415
                                                      verify_enclave_attestation)
        signer = generate_signer()
        eat = issue_enclave_attestation("binding-1", signer, profile="p", tier="affirming")
        args = dict(verifier_pubkey=_raw_pub(signer), expected_binding="binding-1")
        self.assertTrue(verify_enclave_attestation(eat, **args)["ok"], "precondition")
        claims = json.loads(_unb64u(eat.split(".")[1]))
        claims["tier_score"] = float("nan")
        res = verify_enclave_attestation(_resigned(eat, signer, payload=json.dumps(claims).encode()), **args)
        self.assertFalse(res["ok"], res)

    def test_RED_an_sd_jwt_whose_issuer_header_has_a_byte_order_mark_is_refused(self):
        from test_kbjwt import _issue_presented  # noqa: PLC0415
        from proofbundle.sdjwt import verify_sd_jwt  # noqa: PLC0415
        presented, issuer, _holder = _issue_presented()
        jwt, rest = presented.split("~", 1)
        self.assertTrue(verify_sd_jwt(presented, _raw_pub(issuer))["sig_ok"], "precondition")
        forged = _resigned(jwt, issuer, header=BOM + _unb64u(jwt.split(".")[0])) + "~" + rest
        res = verify_sd_jwt(forged, _raw_pub(issuer))
        self.assertFalse(res["sig_ok"] and res["structure_ok"], res)

    def test_RED_a_sample_disclosure_with_a_byte_order_mark_is_refused(self):
        from proofbundle import merkle  # noqa: PLC0415
        from proofbundle.persample import build_sample_tree, sample_opening, verify_sample_opening  # noqa: PLC0415
        tree = build_sample_tree([{"id": f"s{i}", "ok": True} for i in range(4)], b"tree-secret-0123456789abcdef")
        good = list(tree["disclosures"])
        disclosures = good[:2] + [_b64u(BOM + _unb64u(good[2]))] + good[3:]
        # the leaves are the ASCII disclosure strings, as build_sample_tree commits them
        root = base64.b64encode(merkle.merkle_tree_hash([d.encode("ascii") for d in disclosures])).decode()
        good_root = tree["root_b64"]
        self.assertEqual(base64.b64encode(merkle.merkle_tree_hash([d.encode("ascii") for d in good])).decode(),
                         good_root, "precondition: the root is computed as the tree builder computes it")
        self.assertTrue(verify_sample_opening(sample_opening(good, 2), good_root, 4)["ok"], "precondition")
        res = verify_sample_opening(sample_opening(disclosures, 2), root, 4)
        self.assertFalse(res["ok"], res)

    def test_RED_a_receipt_token_whose_bundle_has_a_byte_order_mark_is_refused(self):
        from proofbundle import emit_bundle  # noqa: PLC0415
        from proofbundle.hf_evals import _unpack_receipt_token  # noqa: PLC0415
        bundle = emit_bundle(b'{"hello": 1}', generate_signer())
        raw = json.dumps(bundle, sort_keys=True, separators=(",", ":")).encode("utf-8")
        self.assertEqual(_unpack_receipt_token("pb1." + _b64u(zlib.compress(raw, 9))), bundle, "precondition")
        with self.assertRaises(BundleFormatError):
            _unpack_receipt_token("pb1." + _b64u(zlib.compress(BOM + raw, 9)))

    def test_RED_a_dsse_payload_with_nan_is_malformed_even_where_canonical_form_is_not_required(self):
        from proofbundle._statement_payload import load_statement_strict  # noqa: PLC0415
        head = (b'{"_type":"https://in-toto.io/Statement/v1","predicateType":"t",'
                b'"subject":[{"name":"t","digest":{"sha256":"' + b"a" * 64 + b'"}}],"predicate":{"x":')
        self.assertEqual(load_statement_strict(head + b'1}}', require_canonical=False)["predicate"], {"x": 1},
                         "precondition: the same statement with a finite number is taken")
        with self.assertRaises(BundleFormatError):
            load_statement_strict(head + b'NaN}}', require_canonical=False)

    def test_RED_decision_inspect_prints_no_nan_into_its_json(self):
        """cli `decision inspect` decoded the payload and printed it with json.dumps, which writes NaN: output no
        JSON reader parses. Now the payload is refused with a clean exit."""
        from proofbundle.cli import main  # noqa: PLC0415
        payload = b'{"_type":"https://in-toto.io/Statement/v1","predicate":{"x":NaN}}'
        env = {"payloadType": "application/vnd.in-toto+json", "payload": base64.b64encode(payload).decode(),
               "signatures": []}
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "env.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(env, fh)
            out = io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                try:
                    rc = main(["decision", "inspect", path])
                except SystemExit as exc:
                    rc = exc.code
        self.assertNotEqual(rc, 0)
        self.assertNotIn("NaN", out.getvalue())


def _sd_jwt(header: bytes = b'{"alg":"EdDSA"}', disclosure: bytes = b'["c2FsdA","n",1]') -> str:
    d = _b64u(disclosure)
    payload = b'{"_sd":' + json.dumps([_b64u(hashlib.sha256(d.encode("ascii")).digest())]).encode() + b"}"
    return f"{_b64u(header)}.{_b64u(payload)}.~{d}~"


class TheRefusalNamesItsOwnReason(unittest.TestCase):
    """RESTRISIKO_600 S104: kbjwt and sdjwt folded every refusal of the reader onto the text of a duplicate key.
    With NaN, a byte order mark or UTF-16 refused by the reader, that text would be false for each of them, so the
    reader's own reason is passed on (bounded), and a duplicate key still reads as one."""

    def test_RED_an_sd_jwt_header_or_disclosure_refused_for_another_reason_does_not_say_duplicate(self):
        from proofbundle.sdjwt import verify_sd_jwt  # noqa: PLC0415
        self.assertTrue(verify_sd_jwt(_sd_jwt())["structure_ok"], "precondition: the control is well formed")
        for label, kwargs, reason in (
                ("NaN in the header", {"header": b'{"alg":"EdDSA","x":NaN}'}, "is not a JSON number"),
                ("a byte order mark before the header", {"header": BOM + b'{"alg":"EdDSA"}'}, "byte order mark"),
                ("a lone surrogate in the header", {"header": b'{"alg":"EdDSA","x":"\\ud800"}'}, "surrogate"),
                ("NaN in a disclosure", {"disclosure": b'["c2FsdA","n",NaN]'}, "is not a JSON number")):
            with self.subTest(label=label):
                res = verify_sd_jwt(_sd_jwt(**kwargs))
                self.assertFalse(res["structure_ok"], res)
                self.assertNotIn("duplicate", res["detail"].lower(), res["detail"])
                self.assertIn(reason, res["detail"])

    def test_CONTROL_a_duplicate_key_in_an_sd_jwt_still_reads_as_a_duplicate_key(self):
        from proofbundle.sdjwt import verify_sd_jwt  # noqa: PLC0415
        for kwargs in ({"header": b'{"alg":"EdDSA","alg":"none"}'}, {"disclosure": b'["c2FsdA","n",{"a":1,"a":2}]'}):
            with self.subTest(kwargs=kwargs):
                res = verify_sd_jwt(_sd_jwt(**kwargs))
                self.assertFalse(res["structure_ok"], res)
                self.assertIn("duplicate JSON key", res["detail"])

    def test_RED_a_key_binding_jwt_refused_for_nan_does_not_say_duplicate_and_a_duplicate_still_does(self):
        from test_kbjwt import IAT, _issue_presented  # noqa: PLC0415
        from proofbundle.kbjwt import split_key_binding, verify_key_binding  # noqa: PLC0415
        presented, _issuer, holder = _issue_presented()
        sd_part, kb = split_key_binding(presented)
        header = json.loads(_unb64u(kb.split(".")[0]))
        for label, raw, reason in (
                ("NaN", json.dumps({**header, "x": float("nan")}).encode(), "is not a JSON number"),
                ("a duplicate key", b'{"alg":"EdDSA","alg":"EdDSA"}', "duplicate JSON key")):
            with self.subTest(label=label):
                res = verify_key_binding(sd_part + _resigned(kb, holder, header=raw), expected_aud="verifier.example",
                                         expected_nonce="n-1", now=IAT + 10)
                self.assertFalse(res["ok"], res)
                self.assertIn(reason, res["detail"])
                if label == "NaN":
                    self.assertNotIn("duplicate", res["detail"].lower(), res["detail"])


if __name__ == "__main__":
    unittest.main()
