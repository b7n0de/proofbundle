"""`intoto --verify` and `svr --verify` name the reason of every check that does not hold.

Measured on main f79d6c8e: both commands printed the reason under the FAIL line only when the in-toto
Statement layer failed (`statement_detail`) or, for eval-result v0.2, its shape (`predicate_shape_detail`).
For every other failed check they printed `[FAIL] ...` and `=> FAILED` and nothing between: an envelope with
empty `signatures` (vector OP17 of the HCTP delivery -3), a payload in base64 without its padding (OP20), a
signature that does not verify under the given key, a payload that is not canonical for its declared
contentRootAlg, an eval-result claim field the claim rule refuses, and for `svr --verify` another
predicateType. `decision verify` and `outcome verify` name their reason in each of these cases.

The verifiers already carry the reason: `content_root_detail` is the merged reason of every check but the
signature itself, and `signature_ok` says whether the DSSE check held. The commands now print what they had not
printed of it, and the signature as its own line where the DSSE check ran.

THE PROPERTY, over every case here: a FAIL line is followed by at least one reason line before `=> FAILED`, no
reason line is printed twice, and a PASS prints none. The cases are this file's own, each with a fragment of the
reason it must give. Run against main f79d6c8e, every case whose name does not start with `test_control` fails.
"""
import base64
import io
import json
import unittest
from contextlib import redirect_stderr, redirect_stdout

from proofbundle import dsse, intoto
from proofbundle.cli import main
from proofbundle.emit import generate_signer

STATEMENT_V1 = "https://in-toto.io/Statement/v1"
EINTRAG = {"name": "artifact", "digest": {"sha256": "a" * 64}}

# The members eval-result v0.1 requires, each with a value the claim rule accepts (as in
# tests/test_the_intoto_verifiers_read_the_statement_layer.py).
_V01_PRAEDIKAT = {
    "verifier": {"id": "https://b7n0de.com/proofbundle"}, "evaluatedAt": "2026-10-17T12:00:00Z",
    "suite": {"name": "s", "version": "1"},
    "claims": [{"metric": "m", "comparator": ">=", "threshold": "0.5", "passed": True}],
    "sampleSize": 1,
    "commitments": {"model": {"alg": "sha256-salted-v1", "value": "a1" * 32, "salted": True},
                    "dataset": {"alg": "sha256-salted-v1", "value": "b2" * 32, "salted": True}},
    "assuranceLevel": "self_attested", "subjectProfile": "receipt",
}
_SVR_PRAEDIKAT = {"verifier": {"id": "https://example.invalid/v"}, "timeCreated": "2026-10-17T12:00:00Z",
                  "properties": []}

# The command, the FAIL and PASS label it prints, and its predicate type with a predicate that judges nothing else.
BEFEHLE = {
    "intoto": ("eval-result attestation", intoto.EVAL_RESULT_PREDICATE_TYPE, _V01_PRAEDIKAT),
    "svr": ("SVR attestation", intoto.SVR_PREDICATE_TYPE, _SVR_PRAEDIKAT),
}


def _statement(befehl: str) -> dict:
    _, typ, praedikat = BEFEHLE[befehl]
    return {"_type": STATEMENT_V1, "subject": [dict(EINTRAG)], "predicateType": typ,
            "predicate": json.loads(json.dumps(praedikat))}


def _legacy(st) -> bytes:
    # The legacy serialization: the statement declares no contentRootAlg, and its binding holds.
    return json.dumps(st, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _mit_padding(st: dict) -> dict:
    """The statement with a subject name whose legacy bytes are not a multiple of three long, so their base64
    ends in padding that a case can take away."""
    while len(_legacy(st)) % 3 == 0:
        st["subject"][0]["name"] += "x"
    return st


class _Basis(unittest.TestCase):

    def setUp(self):
        self.signer = generate_signer()
        self.pub = self.signer.public_key().public_bytes_raw()
        self.fremd = generate_signer().public_key().public_bytes_raw()

    def _huelle(self, st, body: bytes | None = None) -> dict:
        return dsse.sign_envelope(_legacy(st) if body is None else body, self.signer,
                                  payload_type=intoto.INTOTO_STATEMENT_PAYLOAD_TYPE)

    def _lauf(self, befehl: str, env: dict, pub: bytes | None = None) -> tuple[int, list[str]]:
        import tempfile  # noqa: PLC0415
        from pathlib import Path  # noqa: PLC0415
        with tempfile.TemporaryDirectory() as td:
            pfad = Path(td) / "env.json"
            pfad.write_text(json.dumps(env), encoding="utf-8")
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                rc = main([befehl, str(pfad), "--verify", "--pub",
                           base64.b64encode(self.pub if pub is None else pub).decode("ascii")])
        self.assertNotIn("Traceback", err.getvalue())
        return rc, out.getvalue().splitlines()

    def _gruende(self, befehl: str, zeilen: list[str]) -> list[str]:
        """The lines between the FAIL line and `=> FAILED`."""
        etikett = BEFEHLE[befehl][0]
        anfang = next(i for i, z in enumerate(zeilen) if z.startswith("[FAIL]") and etikett in z)
        ende = zeilen.index("=> FAILED")
        return zeilen[anfang + 1:ende]

    def _faellt_mit(self, befehl: str, env: dict, worte: str, pub: bytes | None = None) -> list[str]:
        rc, zeilen = self._lauf(befehl, env, pub)
        self.assertEqual(rc, 1, zeilen)
        gruende = self._gruende(befehl, zeilen)
        self.assertTrue(gruende, f"a FAIL line without a reason: {zeilen}")
        self.assertEqual(len(gruende), len(set(gruende)), f"a reason printed twice: {gruende}")
        self.assertTrue(all(g.startswith("    ") for g in gruende), gruende)
        self.assertIn(worte, "\n".join(gruende), zeilen)
        return gruende


class TestEachFailedCheckIsNamed(_Basis):

    def _faelle(self, befehl: str):
        """(case, envelope, public key or None, the words the reason must give)."""
        st = _mit_padding(_statement(befehl))
        gut = self._huelle(st)
        leer = dict(gut, signatures=[])
        ohne = {k: v for k, v in gut.items() if k != "signatures"}
        ohne_padding = dict(gut, payload=gut["payload"].rstrip("="))
        sig = gut["signatures"][0]["sig"]
        sig_ohne_padding = dict(gut, signatures=[dict(gut["signatures"][0], sig=sig.rstrip("="))])
        andere_art = dict(gut, payloadType="application/json")
        nicht_kanonisch = self._huelle(st, json.dumps(st, indent=1, sort_keys=True).encode("utf-8"))
        yield "OP17 empty signatures", leer, None, "signatures must be a non-empty list"
        yield "no signatures", ohne, None, "signatures must be a non-empty list"
        yield "OP20 a payload without its padding", ohne_padding, None, "payload is not valid base64"
        yield "a signature without its padding", sig_ohne_padding, None, "no signature verifies under the key"
        yield "another key", gut, self.fremd, "no signature verifies under the key"
        yield "another payloadType", andere_art, None, "payloadType 'application/json' is not"
        yield "a payload that is not canonical", nicht_kanonisch, None, "payload is not canonical"

    def test_each_case_names_its_reason_under_intoto_verify(self):
        for name, env, pub, worte in self._faelle("intoto"):
            with self.subTest(fall=name):
                self._faellt_mit("intoto", env, worte, pub)

    def test_each_case_names_its_reason_under_svr_verify(self):
        for name, env, pub, worte in self._faelle("svr"):
            with self.subTest(fall=name):
                self._faellt_mit("svr", env, worte, pub)

    def test_a_claim_field_the_claim_rule_refuses_is_named(self):
        st = _statement("intoto")
        st["predicate"]["commitments"]["model"]["value"] = "x"
        self._faellt_mit("intoto", self._huelle(st), "commitments")

    def test_a_layer_reason_beside_another_is_not_repeated_in_it(self):
        """The layer reason has its own line; the merged reason of the verifier holds it too, and only the rest
        of it is printed. At the first fix of this file it stood twice, once in each line."""
        st = _statement("intoto")
        del st["subject"]
        st["predicate"]["commitments"]["model"]["value"] = "x"
        gruende = self._faellt_mit("intoto", self._huelle(st), "commitments")
        self.assertEqual(sum("subject is required" in g for g in gruende), 1, gruende)
        self.assertEqual(len(gruende), 2, gruende)

    def test_a_member_v01_requires_is_named_when_it_is_absent(self):
        st = _statement("intoto")
        del st["predicate"]["suite"]
        self._faellt_mit("intoto", self._huelle(st), "suite")

    def test_intoto_names_a_type_that_is_neither_eval_result_version(self):
        st = _statement("svr")   # a valid SVR statement handed to the eval-result command
        self._faellt_mit("intoto", self._huelle(st), "is neither")

    def test_svr_names_another_predicate_type(self):
        st = _statement("svr")
        st["predicateType"] = "https://example.invalid/attestation/other/v1"
        self._faellt_mit("svr", self._huelle(st), "!= expected")

    def test_a_wrong_key_over_a_null_payload_names_both_the_payload_and_the_signature(self):
        """The DSSE check runs on a payload that decodes to JSON null, so both reasons stand. `svr --verify`
        ends such a payload with exit 2 as malformed and is not judged here."""
        gruende = self._faellt_mit("intoto", self._huelle(None, b"null"),
                                   "payload is not a JSON in-toto Statement object", self.fremd)
        self.assertIn("no signature verifies under the key", "\n".join(gruende))

    def test_a_rejected_payload_names_its_rejection_and_no_signature(self):
        """A payload the verifier rejects before the DSSE check is not a signature that failed."""
        for befehl in BEFEHLE:
            with self.subTest(befehl=befehl):
                env = self._huelle(_mit_padding(_statement(befehl)))
                env["signatures"] = []
                gruende = self._faellt_mit(befehl, env, "signatures must be a non-empty list")
                self.assertNotIn("no signature verifies", "\n".join(gruende))


class TestControls(_Basis):

    def test_control_a_valid_envelope_passes_without_a_reason_line(self):
        for befehl in BEFEHLE:
            with self.subTest(befehl=befehl):
                rc, zeilen = self._lauf(befehl, self._huelle(_statement(befehl)))
                self.assertEqual(rc, 0, zeilen)
                self.assertEqual(zeilen, [f"[PASS] {BEFEHLE[befehl][0]}", "=> OK"])

    def test_control_the_statement_layer_reason_is_printed_once(self):
        for befehl in BEFEHLE:
            with self.subTest(befehl=befehl):
                st = _statement(befehl)
                del st["subject"]
                gruende = self._faellt_mit(befehl, self._huelle(st), "subject is required")
                self.assertEqual(len(gruende), 1, gruende)
                self.assertTrue(gruende[0].startswith("    subject is required"), gruende)


if __name__ == "__main__":
    unittest.main()
