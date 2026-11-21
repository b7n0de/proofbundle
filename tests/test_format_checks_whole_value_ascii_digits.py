"""Every format rule matches the whole value, and its digits are the ASCII digits 0 to 9.

In a Python str pattern `$` also matches before a trailing line feed, and `\\d` matches the decimal
digits of every script. Each check below is held to two counter-cases: the valid value with a
trailing line feed, and the valid value with one ASCII digit replaced by U+0661 ARABIC-INDIC DIGIT
ONE. Measured on 19cadafc: every check listed here refuses both; this module pins that, and the
last class runs the fields both verifiers read (`declaredAt` and the target digest of a relation
edge) through `proofbundle decision verify` and `pb_verify_rs verify-relation` over the same bytes.
"""
from __future__ import annotations

import base64
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import pytest

try:
    import _pb_verify_rs  # tests/_pb_verify_rs.py, the one way to the binary
    from test_declared_at_takes_only_ascii_digits import _edge, _signed_without_the_emitter
except ModuleNotFoundError:  # `python -m unittest tests.<module>` puts the root on sys.path
    from tests import _pb_verify_rs
    from tests.test_declared_at_takes_only_ascii_digits import _edge, _signed_without_the_emitter

REPO = Path(__file__).resolve().parents[1]
ARABIC_ONE = "١"
H64 = "0123456789abcdef" * 4
T = "2026-11-21T13:00:47Z"


def _counter_cases(valid: str) -> dict:
    i = next(i for i, c in enumerate(valid) if c in "0123456789")
    return {"trailing line feed": valid + "\n",
            "U+0661 digit": valid[:i] + ARABIC_ONE + valid[i + 1:]}


def _checks():
    from proofbundle import _schema_shapes as ss
    from proofbundle import agent_review, assurance, decision, evalclaim, intoto, policy, renewal
    from proofbundle import scitt_ccf, verifier_block
    from proofbundle import _statement_payload as sp
    from proofbundle.adapters import sigstore_bundle as sb
    from proofbundle.adapters import trace_record as tr
    sri = "sha256-" + base64.b64encode(bytes(32)).decode().replace("A", "1", 1)
    return [
        ("_schema_shapes.SHA256_HEX", lambda v: ss.SHA256_HEX.match(v), H64),
        ("_schema_shapes.RFC3339_Z", lambda v: ss.RFC3339_Z.match(v), T),
        ("_schema_shapes.SEMVER_0_1_X", lambda v: ss.SEMVER_0_1_X.match(v), "0.1.7"),
        ("verifier_block._SHA256_HEX", lambda v: verifier_block._SHA256_HEX.match(v), H64),
        ("verifier_block._SEMVERISH", lambda v: verifier_block._SEMVERISH.match(v), "6.6.1"),
        ("renewal._HEXRE", lambda v: renewal._HEXRE.match(v), H64),
        ("intoto._is_rfc3339", intoto._is_rfc3339, "2026-11-21T13:00:47+01:00"),
        ("intoto._DECIMAL_STRING_RE", lambda v: intoto._DECIMAL_STRING_RE.match(v), "0.95"),
        ("scitt_ccf._TXID", lambda v: scitt_ccf._TXID.fullmatch(v), "2.15"),
        ("evalclaim._DECIMAL_RE", lambda v: evalclaim._DECIMAL_RE.match(v), "0.95"),
        ("evalclaim._COMMIT_RE", lambda v: evalclaim._COMMIT_RE.match(v), "sha256:" + H64),
        ("assurance._SHA256_HEX", lambda v: assurance._SHA256_HEX.match(v), H64),
        ("policy._BITCOIN_HEIGHT", lambda v: policy._BITCOIN_HEIGHT.fullmatch(v), "840000"),
        ("policy._BITCOIN_ROOT", lambda v: policy._BITCOIN_ROOT.fullmatch(v), H64),
        ("policy._HEX64", lambda v: policy._HEX64.match(v), H64),
        ("policy._parse_iso_utc", lambda v: policy._parse_iso_utc(v) is not None, T),
        ("_statement_payload._LOWER_HEX_RE", lambda v: sp._LOWER_HEX_RE.match(v), H64),
        ("sigstore_bundle._DECIMAL", lambda v: sb._DECIMAL.match(v), "12345"),
        ("sigstore_bundle._RFC3339", lambda v: sb._RFC3339.match(v), T),
        ("sigstore_bundle._LOWER_HEX", lambda v: sb._LOWER_HEX.match(v), H64),
        ("sigstore_bundle._DIGEST_ARG", lambda v: sb._DIGEST_ARG.match(v), "sha256:" + H64),
        ("sigstore_bundle._SRI_ARG", lambda v: sb._SRI_ARG.match(v), sri),
        ("sigstore_bundle._GITHUB_REPOSITORY", lambda v: sb._GITHUB_REPOSITORY.match(v), "github:o1/r1"),
        ("trace_record._DIGEST", lambda v: tr._DIGEST.fullmatch(v), "sha256:" + H64),
        ("trace_record._SUBJECT", lambda v: tr._SUBJECT.fullmatch(v), "did:web1:x1"),
        ("trace_record._RETENTION", lambda v: tr._RETENTION.fullmatch(v), "P30D"),
        ("trace_record._SIGNATURE", lambda v: tr._SIGNATURE.fullmatch(v), "abc1"),
        ("trace_record._PCR", lambda v: tr._PCR.fullmatch(v), "pcr:7"),
        ("trace_record._URI", lambda v: tr._URI.fullmatch(v), "https://example.org/1"),
        ("agent_review._SHA256_HEX", lambda v: agent_review._SHA256_HEX.match(v), H64),
        ("agent_review._GIT_SHA", lambda v: agent_review._GIT_SHA.match(v), H64[:40]),
        ("agent_review._SEMVER_0_1_X", lambda v: agent_review._SEMVER_0_1_X.match(v), "0.1.3"),
        ("agent_review._HEX64", lambda v: agent_review._HEX64.match(v), H64),
        ("decision._expiresat_posix", lambda v: decision._expiresat_posix(v) is not None, T),
        ("decision._mikrosekunden", lambda v: decision._mikrosekunden(v) is not None, "2026-11-21T13:00:47.5Z"),
    ]


@pytest.mark.parametrize("name", [c[0] for c in _checks()])
def test_each_check_takes_the_whole_value_and_ascii_digits(name):
    _, check, valid = next(c for c in _checks() if c[0] == name)
    assert check(valid), f"{name} refused its own valid value {valid!r}"
    for case, value in _counter_cases(valid).items():
        assert not check(value), f"{name} accepted the {case}: {value!r}"


class BothVerifiersReadTheEdgeFieldsAlike(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.rust = _pb_verify_rs.binary_or_skip()

    def _both(self, edge: dict):
        import test_declared_at_takes_only_ascii_digits as base  # noqa: PLC0415
        echt = base._edge
        base._edge = lambda _declared_at: edge
        try:
            env, pub = _signed_without_the_emitter(edge.get("declaredAt", T))
        finally:
            base._edge = echt
        pub_b64 = base64.b64encode(pub).decode("ascii")
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "receipt.json"
            path.write_text(json.dumps(env), encoding="utf-8")
            py = subprocess.run(
                [sys.executable, "-c",
                 "import sys; sys.path.insert(0, %r); from proofbundle.cli import main; "
                 "sys.exit(main(sys.argv[1:]))" % str(REPO / "src"),
                 "decision", "verify", str(path), "--pub", pub_b64],
                capture_output=True, text=True, timeout=120)
            rs = subprocess.run([str(self.rust), "verify-relation", str(path), pub_b64],  # noqa: S603
                                capture_output=True, text=True, timeout=120)
        return py, rs

    def test_positive_control(self):
        py, rs = self._both(_edge(T))
        self.assertEqual(py.returncode, 0, py.stdout + py.stderr)
        self.assertEqual(rs.returncode, 0, rs.stdout + rs.stderr)

    def test_declared_at_counter_cases(self):
        for case, value in _counter_cases(T).items():
            with self.subTest(case=case):
                py, rs = self._both(_edge(value))
                self.assertEqual(rs.returncode, 2, rs.stdout + rs.stderr)
                self.assertEqual(py.returncode, rs.returncode, py.stdout + py.stderr)

    def test_target_digest_counter_cases(self):
        for case, value in _counter_cases(H64).items():
            with self.subTest(case=case):
                edge = _edge(T)
                edge["targetReceiptDigest"]["digest"] = value
                py, rs = self._both(edge)
                self.assertEqual(rs.returncode, 2, rs.stdout + rs.stderr)
                self.assertEqual(py.returncode, rs.returncode, py.stdout + py.stderr)
