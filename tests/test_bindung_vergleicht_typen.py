"""The binding check compares JSON types, not only values — and does not over-refuse.

WHERE THIS CAME FROM. On 2026-09-24, after the R-B4 establisher landed as `_verdict.require_bool_verdict`
(PR 260, merge `058ed6fc`), an adversarial lens of the house deep-gate was asked for an EXECUTED bypass
rather than an opinion. It found that `sdjwt_issue.check_binds_bundle` never calls the establisher and
compares with a bare `!=`, and `bool` subclasses `int`.

MEASURED ON `058ed6fc` BEFORE ANY CHANGE, which is why these are cases and not a paragraph:

    SD-JWT passed=True  vs claim passed=1          -> bound      (require_bool_verdict: REFUSES the claim)
    SD-JWT passed=True  vs claim passed=1.0        -> bound      (require_bool_verdict: REFUSES the claim)
    SD-JWT threshold=0  vs claim threshold=False   -> bound
    SD-JWT passed=True  vs claim passed=False      -> not bound  (the control: not blindly true)
    SD-JWT passed=True  vs claim passed="true"     -> not bound

TWO CORRECTIONS TO THE LENS, both from the measurement above and both kept here as cases. It named only
`passed`; the loop compares FIVE fields the same way and `threshold` falls identically. And it called
this a bypass, which does not carry: `1` and `True` are the same verdict, so no verdict flips and
nothing false-passes. What breaks is the promise the function makes about itself, `check_binds_bundle`
docstring: the always-open claims "MUST match the signed bundle payload bit-exact".

THE OVER-REFUSAL GUARD IS THE LOAD-BEARING ONE HERE, because the obvious fix is wrong. A rule of
"equal value AND identical type" would also refuse `1` against `1.0`. Measured with the `rfc8785`
canonicalizer: JCS serialises `true`/`1`/`1.0` as `true`/`1`/`1` — so `true` and `1` differ and must
refuse, while `1` and `1.0` are the SAME canonical bytes and must keep binding. A fix that refused them
would be a new defect pointing the other way, and nothing in the red probe would have caught it.

AND THE BACKWARD-COMPATIBILITY ARM, stated because this changes a verify verdict. An honest issuance
copies `passed` from the claim verbatim, so both sides always carried the SAME type and no honestly
issued receipt is affected. A pre-establisher bundle whose claim held `passed: 1` had an SD-JWT holding
`1` too; that pair must still bind. Only CROSS-type pairs change, and those arise from no honest path.
"""
from __future__ import annotations

import base64
import json
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from proofbundle._membership import same_json_value
from proofbundle.emit import generate_signer
from proofbundle.errors import BundleFormatError
from proofbundle.evalclaim import build_eval_claim, issuer_fingerprint
from proofbundle.sdjwt_issue import check_binds_bundle, issue_sd_jwt
from proofbundle._verdict import require_bool_verdict

ROOT = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
TS = "2026-09-19T12:00:00Z"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _claim(signer, **ueberschreibt) -> dict:
    """A claim from the blessed emitter, so a refusal below means something."""
    claim, _salts = build_eval_claim(
        suite="safety-refusal", suite_version="v1", metric="refusal_rate",
        comparator=">=", threshold="0.80", score="0.92", n=500,
        model_id="acme/model-x", dataset_id="acme/dataset-y",
        issuer=issuer_fingerprint(signer), timestamp=TS,
        model_salt=b"0" * 16, dataset_salt=b"1" * 16)
    claim = dict(claim)
    claim.update(ueberschreibt)
    return claim


def _sd_jwt_von_hand(claim: dict, signer: Ed25519PrivateKey, *, root_b64: str = ROOT) -> str:
    """A compact SD-JWT built the way `issue_sd_jwt` built one BEFORE the establisher landed.

    Needed because `issue_sd_jwt` now refuses a non-bool `passed` — which is correct, and which means
    the pre-establisher artefact can only be reconstructed by hand. It copies `passed` verbatim, as the
    old code did, so the issuance side of the measurement is the real one and not a stand-in.
    """
    payload = {"passed": claim["passed"], "threshold": claim["threshold"],
               "comparator": claim["comparator"], "suite": claim["suite"],
               "issuer": claim["issuer"], "receipt": {"root_b64": root_b64},
               "vct": "https://b7n0de.com/proofbundle/vct/eval-receipt/v1"}
    header = {"alg": "EdDSA", "typ": "dc+sd-jwt"}
    signing_input = (_b64url(json.dumps(header).encode("utf-8")) + "."
                     + _b64url(json.dumps(payload).encode("utf-8")))
    return signing_input + "." + _b64url(signer.sign(signing_input.encode("ascii"))) + "~"


class TestDieRotprobeGegenDenElternstand(unittest.TestCase):
    """Every case here BOUND on `058ed6fc`. That they now refuse is the whole change."""

    def setUp(self):
        self.signer = generate_signer()
        self.echt = issue_sd_jwt(_claim(self.signer, passed=True), self.signer, root_b64=ROOT)

    def test_wahr_bindet_nicht_an_eins(self):
        self.assertFalse(check_binds_bundle(self.echt, _claim(self.signer, passed=1), ROOT),
                         "an SD-JWT for `true` bound to a claim carrying the number 1")

    def test_wahr_bindet_nicht_an_eins_komma_null(self):
        self.assertFalse(check_binds_bundle(self.echt, _claim(self.signer, passed=1.0), ROOT))

    def test_die_abgewiesene_seite_ist_wirklich_abgewiesen(self):
        """The pairing that makes the finding sharp: the bundle claim these bound to is one the
        establisher refuses outright. Without this the case would only be about a type."""
        for wert in (1, 1.0):
            with self.subTest(passed=wert):
                with self.assertRaises(BundleFormatError):
                    require_bool_verdict(_claim(self.signer, passed=wert), wo="probe")

    def test_die_klasse_trifft_nicht_nur_passed(self):
        """The lens named `passed`. The loop compares five fields the same way."""
        compact = _sd_jwt_von_hand(_claim(self.signer, passed=True, threshold=0), self.signer)
        self.assertFalse(
            check_binds_bundle(compact, _claim(self.signer, passed=True, threshold=False), ROOT),
            "threshold 0 bound to threshold false — the fix reached only the field it was named for")

    def test_verschachtelt_faellt_genauso(self):
        """A scalar-only rule would close the instance and leave this open."""
        self.assertFalse(same_json_value([True], [1]))
        self.assertFalse(same_json_value({"a": {"b": [False]}}, {"a": {"b": [0]}}))


class TestKeineUeberAbweisung(unittest.TestCase):
    """THE GUARD AGAINST FIXING TOO HARD. Nothing in the red probe would catch these."""

    def test_eins_bleibt_gleich_eins_komma_null(self):
        """RFC 8785 serialises both as `1`. Refusing them would be a new defect facing the other way."""
        self.assertTrue(same_json_value(1, 1.0))
        self.assertTrue(same_json_value([1, {"a": 2}], [1.0, {"a": 2.0}]))

    def test_ein_ehrlich_abgeleitetes_sd_jwt_bindet_weiter(self):
        """WITHOUT THIS THE FILE PROVES NOTHING: a rule that refused everything would pass every case
        above."""
        signer = generate_signer()
        claim = _claim(signer, passed=True)
        self.assertTrue(check_binds_bundle(issue_sd_jwt(claim, signer, root_b64=ROOT), claim, ROOT))

    def test_ein_falsches_verdikt_bindet_auch_weiter(self):
        """The other polarity of the same guard: `False` is a verdict, not an absence."""
        signer = generate_signer()
        claim = _claim(signer, passed=False)
        self.assertTrue(check_binds_bundle(issue_sd_jwt(claim, signer, root_b64=ROOT), claim, ROOT))

    def test_rueckwaertskompatibel_gleicher_typ_auf_beiden_seiten(self):
        """A pre-establisher receipt: the old issuance copied `passed` verbatim, so both sides held the
        same type. Such a pair must still bind — only CROSS-type pairs change."""
        signer = generate_signer()
        for wert in (1, 0, "false"):
            with self.subTest(passed=wert):
                claim = _claim(signer, passed=wert)
                self.assertTrue(check_binds_bundle(_sd_jwt_von_hand(claim, signer), claim, ROOT))


class TestDieNegativkontrolleHaelt(unittest.TestCase):
    """Proof the comparison did not become blindly false."""

    def test_wahr_bindet_nicht_an_falsch(self):
        signer = generate_signer()
        echt = issue_sd_jwt(_claim(signer, passed=True), signer, root_b64=ROOT)
        self.assertFalse(check_binds_bundle(echt, _claim(signer, passed=False), ROOT))

    def test_ein_fremdes_feld_bindet_nicht(self):
        signer = generate_signer()
        echt = issue_sd_jwt(_claim(signer, passed=True), signer, root_b64=ROOT)
        self.assertFalse(check_binds_bundle(echt, _claim(signer, passed=True, suite="andere"), ROOT))

    def test_ein_fehlendes_feld_bindet_nicht(self):
        signer = generate_signer()
        echt = issue_sd_jwt(_claim(signer, passed=True), signer, root_b64=ROOT)
        ohne = _claim(signer, passed=True)
        ohne.pop("suite")
        self.assertFalse(check_binds_bundle(echt, ohne, ROOT))


class TestDasPrimitivSelbst(unittest.TestCase):
    """Direct arm, so a later caller inherits a measured function rather than a measured call site."""

    def test_die_bool_zahl_grenze_in_beide_richtungen(self):
        for a, b, erwartet in [(True, 1, False), (1, True, False), (False, 0, False),
                               (0, False, False), (True, True, True), (False, False, True),
                               (True, False, False), (True, 1.0, False), (True, "true", False)]:
            with self.subTest(a=a, b=b):
                self.assertIs(same_json_value(a, b), erwartet)

    def test_die_uebrigen_json_arten_vergleichen_wie_zuvor(self):
        for a, b, erwartet in [(None, None, True), (None, 0, False), ("a", "a", True),
                               ("a", "b", False), ([], [], True), ([], {}, False),
                               ({"a": 1}, {"a": 1}, True), ({"a": 1}, {"b": 1}, False),
                               ([1, 2], [1, 2, 3], False)]:
            with self.subTest(a=a, b=b):
                self.assertIs(same_json_value(a, b), erwartet)

    def test_tiefe_verschachtelung_wirft_nicht(self):
        """The `!=` this replaces recursed in C, where CPython guards the depth. A hand-written
        recursion would raise RecursionError out of a never-raise verify surface."""
        tief_a: object = "grund"
        tief_b: object = "grund"
        for _ in range(5000):
            tief_a = [tief_a]
            tief_b = [tief_b]
        self.assertIs(same_json_value(tief_a, tief_b), True)
        self.assertIs(same_json_value(tief_a, [tief_b]), False)

    def test_das_budget_weist_ab_und_wirft_nicht(self):
        gross = list(range(50))
        self.assertIs(same_json_value(gross, gross, pair_budget=5), False)
        self.assertIs(same_json_value(gross, gross), True)

    def test_ein_wert_dessen_eq_wirft_ist_nicht_gleich(self):
        class Bissig:
            def __eq__(self, andere):
                raise RuntimeError("no comparison for you")

        self.assertIs(same_json_value(Bissig(), 1), False)


if __name__ == "__main__":
    unittest.main()
