"""Every in-toto verifier of this package reads the Statement v1 layer before it says ok.

in-toto Statement v1 (spec/v1/statement.md) requires `_type`, which is always
`https://in-toto.io/Statement/v1`, and `subject`, a list of ResourceDescriptors in which each element
MUST have `digest` set, because subject artifacts are matched purely by digest. Measured on main
570dd164: `verify_eval_result_dsse` (eval-result v0.1) and `verify_intoto_dsse` returned ok=True for a
validly signed statement without a subject, with an empty subject, with a subject entry that has no
digest, without `_type` or with another `_type`; `verify_svr_dsse` did so for `subject` null as well;
and `proofbundle intoto --verify` printed `[PASS] eval-result attestation` with exit 0 for an
eval-result attestation without a subject. Only eval-result v0.2 read the layer, in its shape check.

The rule stands once, in `intoto._statement_layer_problem`, which the verdict builder shared by the
three verifiers calls. A subject entry's DigestSet is judged by the module's one DigestSet rule
(`_digest_set_problem`, which eval-result v0.2 uses too).

THE CASES ARE THIS FILE'S OWN: each one names the statement it signs and the words the verdict must
give, written from the spec text and not from the module's function. Run against main 570dd164, every
case whose name does not start with `test_control` fails; the controls pass there and here.
"""
import base64
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import proofbundle
from proofbundle import dsse, intoto
from proofbundle.emit import generate_signer

REPO = Path(__file__).resolve().parents[1]
# The CLI cases run the package this process imported, so a run against another source tree measures
# that tree on the CLI path too.
PAKET_SRC = Path(proofbundle.__file__).resolve().parents[1]
STATEMENT_V1 = "https://in-toto.io/Statement/v1"
EINTRAG = {"name": "artifact", "digest": {"sha256": "a" * 64}}

# The three verifiers: the payload type each one pins, the predicate type it expects by default, and
# a predicate of that type that judges nothing else.
FLAECHEN = {
    "eval-result": (intoto.verify_eval_result_dsse, "application/vnd.in-toto+json",
                    "https://b7n0de.com/attestation/eval-result/v0.1", {}),
    "test-result": (intoto.verify_intoto_dsse, "application/vnd.in-toto.test-result+json",
                    "https://in-toto.io/attestation/test-result/v0.1", {}),
    "svr": (intoto.verify_svr_dsse, "application/vnd.in-toto+json",
            "https://in-toto.io/attestation/svr/v0.1",
            {"verifier": {"id": "https://example.invalid/v"}, "timeCreated": "2026-10-17T12:00:00Z",
             "properties": []}),
}

_FEHLT = object()

# (case, the field set to a value or removed, the words the verdict must give)
FAELLE = (
    ("no _type", ("_type", _FEHLT), "_type is absent, expected"),
    ("_type null", ("_type", None), "_type is None, expected"),
    ("_type of another version", ("_type", "https://in-toto.io/Statement/v0.1"), "_type is "),
    ("_type a number", ("_type", 1), "_type is 1, expected"),
    ("_type a list holding the right value", ("_type", [STATEMENT_V1]), "_type is "),
    ("no subject", ("subject", _FEHLT), "subject is required"),
    ("subject null", ("subject", None), "subject must be an array"),
    ("subject an object", ("subject", {"0": EINTRAG}), "subject must be an array"),
    ("subject empty", ("subject", []), "subject must name at least one artifact"),
    ("an entry that is no object", ("subject", ["artifact"]), "subject[0] must be a ResourceDescriptor"),
    ("an entry with a name only", ("subject", [{"name": "artifact"}]), "subject[0] MUST carry digest"),
    ("an entry with a uri only", ("subject", [{"uri": "https://example.invalid/a"}]),
     "subject[0] MUST carry digest"),
    ("a second entry without digest", ("subject", [EINTRAG, {"name": "b"}]), "subject[1] MUST carry digest"),
    ("digest null", ("subject", [{"name": "a", "digest": None}]), "subject[0]: digest must be a DigestSet"),
    ("digest a list of pairs", ("subject", [{"name": "a", "digest": [["sha256", "a" * 64]]}]),
     "subject[0]: digest must be a DigestSet"),
    ("digest empty", ("subject", [{"name": "a", "digest": {}}]), "subject[0]: digest is empty"),
    ("a digest value that is no string", ("subject", [{"name": "a", "digest": {"sha256": 5}}]),
     "must be a non-empty string"),
    ("sha256 of 63 characters", ("subject", [{"name": "a", "digest": {"sha256": "a" * 63}}]),
     "must be 64 lowercase hex characters"),
    ("sha256 in capitals", ("subject", [{"name": "a", "digest": {"sha256": "A" * 64}}]),
     "must be 64 lowercase hex characters"),
)


class _Basis(unittest.TestCase):

    def setUp(self):
        self.signer = generate_signer()
        self.pub = self.signer.public_key().public_bytes_raw()

    def _statement(self, flaeche, feld=None, wert=None):
        _, _, praedikattyp, praedikat = FLAECHEN[flaeche]
        st = {"_type": STATEMENT_V1, "subject": [dict(EINTRAG)], "predicateType": praedikattyp,
              "predicate": dict(praedikat)}
        if feld is not None:
            if wert is _FEHLT:
                del st[feld]
            else:
                st[feld] = wert
        return st

    def _huelle(self, flaeche, st):
        # The legacy serialization, so the statement declares no contentRootAlg and its content-root
        # binding holds whatever the layer says: the layer is what each case refuses.
        _, nutzlastart, _, _ = FLAECHEN[flaeche]
        body = json.dumps(st, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        return dsse.sign_envelope(body, self.signer, payload_type=nutzlastart)

    def _verifiziere(self, flaeche, st, **kw):
        return FLAECHEN[flaeche][0](self._huelle(flaeche, st), self.pub, **kw)


class TestEachVerifierRefusesAStatementWithoutTheLayer(_Basis):

    def test_each_case_is_refused_by_each_verifier_and_named(self):
        for flaeche in FLAECHEN:
            for name, (feld, wert), worte in FAELLE:
                with self.subTest(flaeche=flaeche, fall=name):
                    res = self._verifiziere(flaeche, self._statement(flaeche, feld, wert))
                    self.assertIs(res["ok"], False, res["content_root_detail"])
                    self.assertIs(res.get("statement_ok"), False)
                    self.assertIn(worte, res.get("statement_detail", ""))
                    self.assertIn(worte, res["content_root_detail"])
                    self.assertIs(res["content_root_ok"], True, "the binding holds; the layer refuses")

    def test_opting_out_of_the_type_check_does_not_opt_out_of_the_layer(self):
        for flaeche in FLAECHEN:
            with self.subTest(flaeche=flaeche):
                res = self._verifiziere(flaeche, self._statement(flaeche, "subject", _FEHLT),
                                        expected_predicate_type=None)
                self.assertIs(res["ok"], False, res["content_root_detail"])
                self.assertIs(res.get("statement_ok"), False)

    def test_the_shipped_cli_fails_an_eval_result_without_a_subject(self):
        r = self._cli("intoto", "eval-result", self._statement("eval-result", "subject", _FEHLT))
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("=> FAILED", r.stdout)
        self.assertNotIn("[PASS]", r.stdout)
        self.assertIn("    subject is required", r.stdout, "the FAIL line is followed by its reason")

    def test_the_shipped_cli_fails_an_svr_without_a_subject(self):
        r = self._cli("svr", "svr", self._statement("svr", "subject", _FEHLT))
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("=> FAILED", r.stdout)
        self.assertNotIn("[PASS]", r.stdout)
        self.assertIn("    subject is required", r.stdout, "the FAIL line is followed by its reason")

    def test_control_the_shipped_cli_passes_both_with_a_subject(self):
        for befehl, flaeche in (("intoto", "eval-result"), ("svr", "svr")):
            with self.subTest(befehl=befehl):
                r = self._cli(befehl, flaeche, self._statement(flaeche))
                self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
                self.assertIn("[PASS]", r.stdout)

    def _cli(self, befehl, flaeche, st):
        with tempfile.TemporaryDirectory() as d:
            pfad = os.path.join(d, "att.json")
            Path(pfad).write_text(json.dumps(self._huelle(flaeche, st)), encoding="utf-8")
            return subprocess.run(
                [sys.executable, "-B", "-m", "proofbundle.cli", befehl, pfad, "--verify",
                 "--pub", base64.b64encode(self.pub).decode("ascii")],
                capture_output=True, text=True, cwd=REPO,
                env={"PYTHONPATH": str(PAKET_SRC), "PYTHONDONTWRITEBYTECODE": "1"})


class TestControlAStatementWithTheLayerVerifies(_Basis):

    def test_control_each_verifier_accepts_the_layer_as_the_spec_states_it(self):
        for flaeche in FLAECHEN:
            for name, subjekt in (
                    ("one entry", [dict(EINTRAG)]),
                    ("two entries", [dict(EINTRAG), {"name": "b", "digest": {"sha512": "b" * 128}}]),
                    ("an algorithm the module does not know", [{"name": "m", "digest": {"x": "y"}}]),
                    ("a digest beside a uri", [{"uri": "https://example.invalid/a",
                                                "digest": {"sha256": "c" * 64}}])):
                with self.subTest(flaeche=flaeche, fall=name):
                    res = self._verifiziere(flaeche, self._statement(flaeche, "subject", subjekt))
                    self.assertIs(res["ok"], True, res["content_root_detail"])

    def test_control_a_rejected_payload_still_fails_closed(self):
        for flaeche in FLAECHEN:
            with self.subTest(flaeche=flaeche):
                env = self._huelle(flaeche, self._statement(flaeche))
                env["payload"] = "not base64!"
                res = FLAECHEN[flaeche][0](env, self.pub)
                self.assertIs(res["ok"], False)
                self.assertIsNone(res.get("statement_ok"))


if __name__ == "__main__":
    unittest.main()
