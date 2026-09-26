"""A zlib field is ONE complete stream and nothing after it, and a token is capped before it is decoded.

WHERE THIS COMES FROM. Deep gate against main 5b53ab3e, finding L2-Z195-TOKEN-TRAILING-DATA-01
(confirmed 2 of 3): `verify_receipt_token` checked only that the output stayed under its cap. It never
asked whether the zlib stream had ended or whether bytes followed it. A genuine `pb1.` token with
bytes appended after the end of its stream verified ok=True, from the library and from `hf-token
--verify`; with 12 MiB appended the library still said ok=True while the CLI refused the same token on
its input budget. The token body was also base64-decoded in full before any size check. The status
list's `lst` field had the same shape.

WHAT IS PINNED. For both fields: a genuine value verifies (the precondition), bytes after the stream
and a truncated stream are refused, and the output cap keeps its own message. For the token, an
oversized body is refused before decoding. The counter-direction is pinned too, because one juror
was right about it: the token has no single wire form, so another zlib level or other JSON
whitespace must still verify. The fix refuses bytes outside the stream, not other encodings.
"""
from __future__ import annotations

import base64
import json
import time
import unittest
import zlib

from proofbundle import emit_bundle, generate_signer
from proofbundle._inflate import InflateCapExceeded, inflate_whole_stream
from proofbundle.errors import BundleFormatError
from proofbundle.hf_evals import TOKEN_PREFIX, receipt_token, verify_receipt_token
from proofbundle.statuslist import issue_status_list_token, verify_status_snapshot

URI = "https://example.com/status/1"


def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _unb64url(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _token_with_stream(stream: bytes) -> str:
    return TOKEN_PREFIX + _b64url(stream)


class TheHelper(unittest.TestCase):

    def test_one_complete_stream_inflates(self):
        self.assertEqual(inflate_whole_stream(zlib.compress(b"abc"), 10), b"abc")

    def test_content_of_exactly_the_cap_is_not_read_as_truncated(self):
        data = bytes(range(256)) * 4
        self.assertEqual(inflate_whole_stream(zlib.compress(data, 9), len(data)), data)
        with self.assertRaises(InflateCapExceeded):
            inflate_whole_stream(zlib.compress(data, 9), len(data) - 1)

    def test_bytes_after_the_stream_and_a_truncated_stream_are_refused(self):
        good = zlib.compress(b"abc")
        for label, data, fragment in (("one byte after", good + b"X", "follow the end"),
                                      ("a second stream", good + zlib.compress(b"evil"), "follow the end"),
                                      ("truncated", good[:-4], "truncated")):
            with self.subTest(case=label), self.assertRaises(ValueError) as ctx:
                inflate_whole_stream(data, 1000)
            self.assertIn(fragment, str(ctx.exception))
            self.assertNotIsInstance(ctx.exception, InflateCapExceeded)


class TheToken(unittest.TestCase):

    def setUp(self):
        self.bundle = emit_bundle(b'{"x":1}', generate_signer())
        self.token = receipt_token(self.bundle)
        self.stream = _unb64url(self.token[len(TOKEN_PREFIX):])

    def test_precondition_the_genuine_token_verifies(self):
        result, bundle = verify_receipt_token(self.token)
        self.assertIs(result.ok, True)
        self.assertEqual(bundle, self.bundle)

    def test_bytes_after_the_stream_are_refused(self):
        for label, tail in (("one byte", b"X"), ("sixteen NUL bytes", b"\x00" * 16),
                            ("a second zlib stream", zlib.compress(b'{"evil":1}')),
                            ("prose", b"EVIL-TRAILING-DATA" * 4)):
            with self.subTest(case=label):
                token = _token_with_stream(self.stream + tail)
                self.assertNotEqual(token, self.token)
                with self.assertRaises(BundleFormatError) as ctx:
                    verify_receipt_token(token)
                self.assertIn("follow the end of the zlib stream", str(ctx.exception))

    def test_a_truncated_stream_is_refused(self):
        with self.assertRaises(BundleFormatError) as ctx:
            verify_receipt_token(_token_with_stream(self.stream[:-4]))
        self.assertIn("truncated", str(ctx.exception))

    def test_an_oversized_body_is_refused_before_it_is_decoded(self):
        from proofbundle.budget import DEFAULT_BUDGET
        body = "A" * (DEFAULT_BUDGET.input_bytes + 1)
        t0 = time.perf_counter()
        with self.assertRaises(BundleFormatError) as ctx:
            verify_receipt_token(TOKEN_PREFIX + body)
        self.assertIn("pre-decode", str(ctx.exception))
        # 64 MiB of 'A' took 0.97 s to refuse after a full decode on main 1f7a62d2; a length check takes
        # microseconds.
        self.assertLess(time.perf_counter() - t0, 0.1)

    def test_the_decompression_cap_keeps_its_own_message(self):
        with self.assertRaises(BundleFormatError) as ctx:
            verify_receipt_token(_token_with_stream(zlib.compress(b" " * 300_000, 9)))
        self.assertIn("decompression cap", str(ctx.exception))

    def test_other_encodings_of_the_same_bundle_still_verify(self):
        """Counter-direction: the token has no single wire form, and the fix must not invent one."""
        for label, raw in (("zlib level 1", json.dumps(self.bundle, sort_keys=True).encode()),
                           ("indented JSON", json.dumps(self.bundle, indent=2).encode()),
                           ("other key order", json.dumps(dict(reversed(list(self.bundle.items())))).encode())):
            with self.subTest(case=label):
                level = 1 if label == "zlib level 1" else 9
                result, bundle = verify_receipt_token(_token_with_stream(zlib.compress(raw, level)))
                self.assertIs(result.ok, True)
                self.assertEqual(bundle, self.bundle)


class TheStatusList(unittest.TestCase):

    def setUp(self):
        self.signer = generate_signer()
        self.pub = self.signer.public_key().public_bytes_raw()

    def _signed_with_lst(self, lst: str) -> str:
        header = {"alg": "EdDSA", "typ": "statuslist+jwt"}
        payload = {"sub": URI, "iat": 1_700_000_000, "status_list": {"bits": 1, "lst": lst}}
        si = _b64url(json.dumps(header).encode()) + "." + _b64url(json.dumps(payload).encode())
        return si + "." + _b64url(self.signer.sign(si.encode("ascii")))

    def test_precondition_a_genuine_list_verifies(self):
        token = issue_status_list_token([0, 1], uri=URI, signer=self.signer, iat=1_700_000_000)
        r = verify_status_snapshot(token, expected_uri=URI, index=1, issuer_pubkey=self.pub)
        self.assertIs(r["ok"], True)
        self.assertEqual(r["status_label"], "INVALID")

    def test_a_signed_lst_with_bytes_after_its_stream_or_cut_short_is_refused(self):
        stream = zlib.compress(bytes([0b10]), 9)
        self.assertIs(verify_status_snapshot(self._signed_with_lst(_b64url(stream)), expected_uri=URI,
                                             index=1, issuer_pubkey=self.pub)["ok"], True)
        for label, data in (("bytes after", stream + b"\xff" * 8), ("truncated", stream[:-4])):
            with self.subTest(case=label):
                r = verify_status_snapshot(self._signed_with_lst(_b64url(data)), expected_uri=URI,
                                           index=1, issuer_pubkey=self.pub)
                self.assertIs(r["ok"], False)
                self.assertIn("lst is not valid", r["detail"])

    def test_the_status_list_cap_keeps_its_own_message(self):
        from proofbundle import statuslist
        original = statuslist._MAX_STATUS_LIST_BYTES
        statuslist._MAX_STATUS_LIST_BYTES = 8
        try:
            r = verify_status_snapshot(self._signed_with_lst(_b64url(zlib.compress(b"\x00" * 64))),
                                       expected_uri=URI, index=0, issuer_pubkey=self.pub)
        finally:
            statuslist._MAX_STATUS_LIST_BYTES = original
        self.assertIs(r["ok"], False)
        self.assertIn("maximum decompressed size", r["detail"])


if __name__ == "__main__":
    unittest.main()
