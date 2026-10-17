"""Every verifier that reads an in-toto Statement through the one oracle reads its subject.

WHERE THIS COMES FROM. The second reading of finding L5-03 measured the neighbour on main 570dd164:
decision, outcome, relation-statement, verification-summary, run-ledger and trust-pack verify reported
ok=True and structure_ok=True for the statement of their own emitter re-signed without a subject, with an
empty subject, with subject null and with a subject entry without a digest, and the Rust verifier exited 0
on the same bytes on `verify-relation`, `verify-relation-statement` and `verify-trust-pack-threshold`. The
owner decided on 2026-10-17 that the subject rule belongs in the one oracle.

WHAT IS PINNED. `_statement_payload.load_statement_strict` refuses a Statement whose subject names no
artifact by digest (`statement_subject_problem`), and the Rust `statement_typ_problem` refuses the same
bytes with the same words. For each verifier: the re-signed statement of its emitter stays the positive
control of tests/test_a_statement_says_it_is_an_in_toto_statement.py, and every wrong subject below is a
structure failure with a valid signature. An attached target without a subject is malformed at the
resolver on both sides, and the trust-pack threshold of the Rust verifier refuses each wrong subject with
Python's own refusal, word for word.

THE CASES ARE THIS FILE'S OWN: each names a subject chosen from the spec text (each subject element MUST
have digest set) and a fragment of the refusal. Run against main 570dd164, every case whose name does not
start with `test_control` fails; the controls pass there and here.
"""
from __future__ import annotations

import base64
import contextlib
import io
import json
import pathlib
import subprocess
import sys
import tempfile
import unittest

import test_a_statement_says_it_is_an_in_toto_statement as basis  # the emitters and the re-signing

from proofbundle import anchors, dsse
from proofbundle._statement_payload import STATEMENT_TYPE, load_statement_strict
from proofbundle.emit import generate_signer
from proofbundle.errors import BundleFormatError

REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "conformance"))
from common_vocabulary import compare, exit_class, label_from_verify  # noqa: E402

try:
    import _pb_verify_rs  # tests/_pb_verify_rs.py, the one way to the binary
except ModuleNotFoundError:  # `python -m unittest tests.<module>` puts the root on sys.path
    from tests import _pb_verify_rs

_FEHLT = object()
EINTRAG = {"name": "artifact", "digest": {"sha256": "a" * 64}}

# (case, the subject or _FEHLT for an absent one, a fragment of the refusal)
WRONG_SUBJECTS = (
    ("absent", _FEHLT, "subject is required"),
    ("null", None, "subject must be an array of ResourceDescriptors, got NoneType"),
    ("an object", {"0": EINTRAG}, "subject must be an array of ResourceDescriptors, got dict"),
    ("empty", [], "subject must name at least one artifact"),
    ("an entry that is no object", ["artifact"], "subject[0] must be a ResourceDescriptor object, got str"),
    ("an entry with a name only", [{"name": "artifact"}], "subject[0] MUST carry digest"),
    ("an entry with a uri only", [{"uri": "https://example.invalid/a"}], "subject[0] MUST carry digest"),
    ("a second entry without digest", [EINTRAG, {"name": "b"}], "subject[1] MUST carry digest"),
    ("digest null", [{"digest": None}], "subject[0]: digest must be a DigestSet object, got NoneType"),
    ("digest a list of pairs", [{"digest": [["sha256", "a" * 64]]}],
     "subject[0]: digest must be a DigestSet object, got list"),
    ("digest empty", [{"digest": {}}], "subject[0]: digest is empty"),
    ("an empty algorithm name", [{"digest": {"": "ab"}}], "subject[0]: digest has an empty algorithm name"),
    ("a digest value that is no string", [{"digest": {"sha256": 5}}], "must be a non-empty string"),
    ("an empty digest value", [{"digest": {"x": ""}}], "must be a non-empty string"),
    ("sha256 of 63 characters", [{"digest": {"sha256": "a" * 63}}], "must be 64 lowercase hex characters"),
    ("sha256 in capitals", [{"digest": {"sha256": "A" * 64}}], "must be 64 lowercase hex characters"),
    ("sha512 of sha256 length", [{"digest": {"sha512": "a" * 64}}], "must be 128 lowercase hex characters"),
)


def _mit_subject(statement: dict, wert) -> dict:
    s = dict(statement)
    if wert is _FEHLT:
        s.pop("subject", None)
    else:
        s["subject"] = wert
    return s


class TheOracle(unittest.TestCase):

    def _statement(self, wert):
        return _mit_subject({"_type": STATEMENT_TYPE, "subject": [], "predicateType": "x", "predicate": {}}, wert)

    def test_each_wrong_subject_is_refused_and_named(self):
        for name, wert, worte in WRONG_SUBJECTS:
            with self.subTest(fall=name):
                with self.assertRaises(BundleFormatError) as ctx:
                    load_statement_strict(json.dumps(self._statement(wert)).encode())
                self.assertIn("not an in-toto Statement v1: ", str(ctx.exception))
                self.assertIn(worte, str(ctx.exception))

    def test_control_a_subject_the_spec_allows_passes(self):
        for name, wert in (("one entry", [EINTRAG]),
                           ("two entries", [EINTRAG, {"digest": {"sha512": "b" * 128}}]),
                           ("an algorithm the package does not know", [{"digest": {"x": "y"}}]),
                           ("a digest beside a uri", [{"uri": "https://example.invalid/a",
                                                       "digest": {"sha256": "c" * 64}}])):
            with self.subTest(fall=name):
                s = self._statement(wert)
                self.assertEqual(load_statement_strict(json.dumps(s).encode()), s)


class EverySingleSignerVerifier(unittest.TestCase):

    def test_a_wrong_subject_is_a_structure_failure_everywhere(self):
        for verifier, emit in basis.SINGLE_SIGNER.items():
            sk = generate_signer()
            stmt = basis._statement(emit(sk))
            for name, wert, worte in WRONG_SUBJECTS:
                with self.subTest(verifier=verifier, fall=name):
                    r = basis._verify(verifier, basis._signed(_mit_subject(stmt, wert), sk), basis._pub(sk))
                    self.assertIs(r["crypto_ok"], True)
                    self.assertIs(r["structure_ok"], False)
                    self.assertIs(r["ok"], False)
                    if isinstance(r.get("automation"), dict):
                        self.assertIs(r["automation"]["safeForAutomation"], False)
                    self.assertTrue(any(worte in e for e in r["errors"]), r["errors"])

    def test_control_the_re_signed_statements_verify(self):
        for verifier, emit in basis.SINGLE_SIGNER.items():
            with self.subTest(verifier=verifier):
                sk = generate_signer()
                r = basis._verify(verifier, basis._signed(basis._statement(emit(sk)), sk), basis._pub(sk))
                self.assertIs(r["ok"], True, r["errors"])


class TheTrustPack(unittest.TestCase):

    def test_a_pack_reads_its_subject(self):
        from proofbundle.trust_pack import verify_trust_pack
        env, sk = basis._trust_pack()
        stmt = basis._statement(env)
        for name, wert, worte in WRONG_SUBJECTS:
            with self.subTest(fall=name):
                r = verify_trust_pack(basis._resigned_pack(_mit_subject(stmt, wert), sk))
                self.assertIs(r["structure_ok"], False)
                self.assertIs(r["ok"], False)
                self.assertTrue(any(worte in e for e in r["errors"]), r["errors"])


class TheResolver(unittest.TestCase):

    def test_an_attached_target_without_a_usable_subject_is_malformed(self):
        from proofbundle.cli import _load_related
        sk = generate_signer()
        stmt = basis._statement(basis._decision(sk))
        with tempfile.TemporaryDirectory() as d:
            for name, wert, _ in WRONG_SUBJECTS[:4]:
                with self.subTest(fall=name):
                    env = basis._signed(_mit_subject(stmt, wert), sk)
                    path = pathlib.Path(d) / "target.json"
                    path.write_text(json.dumps(env), encoding="utf-8")
                    related, errs = _load_related([str(path)], basis._pub(sk))
                    eintrag = related[anchors.statement_content_root(dsse.load_payload(env)).hex()]
                    self.assertEqual(errs, [])
                    self.assertIs(eintrag["verified"], False)
                    self.assertIn("subject", eintrag["payload_malformed"] or "")

    def test_control_an_attached_target_with_its_subject_verifies(self):
        from proofbundle.cli import _load_related
        sk = generate_signer()
        env = basis._signed(basis._statement(basis._decision(sk)), sk)
        with tempfile.TemporaryDirectory() as d:
            path = pathlib.Path(d) / "target.json"
            path.write_text(json.dumps(env), encoding="utf-8")
            related, errs = _load_related([str(path)], basis._pub(sk))
        eintrag = related[anchors.statement_content_root(dsse.load_payload(env)).hex()]
        self.assertEqual(errs, [])
        self.assertIs(eintrag["verified"], True)
        self.assertFalse(eintrag["payload_malformed"])


class RustParity(unittest.TestCase):
    """The same bytes, the same exit class and lineage on both verifiers, and the trust-pack refusal in
    the same words."""

    @classmethod
    def setUpClass(cls):
        cls.rust = _pb_verify_rs.binary_or_skip()

    def _both(self, verb: str, sub: str, env: dict, sk):
        from proofbundle.cli import main as cli
        pub_b64 = base64.b64encode(basis._pub(sk)).decode()
        with tempfile.TemporaryDirectory() as d:
            path = pathlib.Path(d) / "env.json"
            path.write_text(json.dumps(env), encoding="utf-8")
            out = io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                try:
                    py_rc = cli([verb, "verify", str(path), "--pub", pub_b64, "--json"])
                except SystemExit as e:
                    py_rc = e.code
            rs = subprocess.run([str(self.rust), sub, str(path), pub_b64], capture_output=True, text=True,
                                timeout=120)
        py = label_from_verify(py_rc, json.loads(out.getvalue()))
        rs_label = label_from_verify(rs.returncode, json.loads(rs.stdout))
        zwei = ("exitClass", "lineage")
        return {a: py[a] for a in zwei}, {a: rs_label[a] for a in zwei}

    def test_a_wrong_subject_on_the_verified_statement(self):
        for verb, sub, emit in (("relation-statement", "verify-relation-statement", basis._relation_statement),
                                ("decision", "verify-relation", basis._decision),
                                ("outcome", "verify-relation", basis._outcome)):
            sk = generate_signer()
            stmt = basis._statement(emit(sk))
            for name, wert, _ in WRONG_SUBJECTS:
                with self.subTest(verifier=verb, fall=name):
                    py, rs = self._both(verb, sub, basis._signed(_mit_subject(stmt, wert), sk), sk)
                    self.assertEqual(compare(py, rs)[1] + compare(rs, py)[1], [], (py, rs))
                    self.assertEqual(py["exitClass"], exit_class(2))

    def test_a_wrong_subject_on_a_trust_pack_reads_the_same_on_both_sides(self):
        from proofbundle.trust_pack import verify_trust_pack
        env, sk = basis._trust_pack()
        stmt = basis._statement(env)
        for name, wert, _ in WRONG_SUBJECTS:
            with self.subTest(fall=name):
                pack = basis._resigned_pack(_mit_subject(stmt, wert), sk)
                py = verify_trust_pack(pack)
                with tempfile.TemporaryDirectory() as d:
                    path = pathlib.Path(d) / "tp.json"
                    path.write_text(json.dumps(pack), encoding="utf-8")
                    rs = subprocess.run([str(self.rust), "verify-trust-pack-threshold", str(path)],
                                        capture_output=True, text=True, timeout=120)
                self.assertIs(py["structure_ok"], False, py["errors"])
                grund = py["errors"][0].split("(fail-closed): ", 1)[1]
                self.assertEqual((rs.returncode, rs.stdout.strip()), (2, "MALFORMED: " + grund))

    def test_control_the_untouched_statements_agree_and_pass(self):
        for verb, sub, emit in (("relation-statement", "verify-relation-statement", basis._relation_statement),
                                ("decision", "verify-relation", basis._decision),
                                ("outcome", "verify-relation", basis._outcome)):
            sk = generate_signer()
            with self.subTest(verifier=verb):
                py, rs = self._both(verb, sub, basis._signed(basis._statement(emit(sk)), sk), sk)
                self.assertEqual(compare(py, rs)[1] + compare(rs, py)[1], [], (py, rs))
                self.assertEqual(py["exitClass"], exit_class(0))


if __name__ == "__main__":
    unittest.main()
