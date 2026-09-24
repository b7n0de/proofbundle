"""One receipt binder, one guard — and the exporter that hand-rolled it skipped the check.

WHERE THIS CAME FROM. A lens of the house deep-gate, asked on 2026-09-24 for an executed bypass of
the R-B4 establisher, reported a side finding instead: `intoto.export_intoto_dsse` reads
`claim["model_id_commit"]` and `claim["timestamp"]` by raw subscript before the establisher runs, so a
malformed claim leaves by an exception type that belongs to none of the three refusal forms
`tests/test_abweisungsformen_sind_drei.py` measures.

READING THE FILE MADE THE FINDING SHARPER THAN THE LENS PUT IT. The receipt binder is not one site
with a missing check; it is the SAME binder at three call sites, and only one of them hand-rolled it:

    export_eval_result_dsse   -> resolve_subject(...)   guarded, and its own comment says so:
                                                        "fail-closed BEFORE building the
                                                        (receipt-profile) subject binder"
    export_svr_dsse           -> resolve_subject(...)   guarded
    export_intoto_dsse        -> an inline copy         unguarded

Measured before the change: the inline copy and `resolve_subject` produce the SAME sha256 for the same
claim, byte for byte — same fields, same `sort_keys` dump. The difference was never the digest. It was
the guard.

AND THE SHARED BUILDER HAD ITS OWN HALF OF THE GAP, which is why this file tests three surfaces and
not one. `resolve_subject` refused a dict missing a field with a typed `BundleFormatError` and called
`claim.get` on a non-dict, where it left as a bare `AttributeError`. So routing the exporter through
the shared builder fixed the dict-shaped cases and left `None`/`[]`/`1` raw. That was measured after
the first half of the repair, not reasoned about — the measurement was already on the screen before
the repair and it took the second measurement to make it a question.

WHAT THIS IS NOT. Nothing is signed before any of these refusals: a signer proxy counted zero calls in
every case. It is a shape question, not an exposure, and the R-B4 input itself was always refused
correctly here. Saying otherwise would overstate it.
"""
from __future__ import annotations

import base64
import json
import unittest

from proofbundle import intoto
from proofbundle.emit import generate_signer
from proofbundle.errors import BundleFormatError, ProofBundleError
from proofbundle.evalclaim import build_eval_claim, issuer_fingerprint

ROOT = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
TS = "2026-09-19T12:00:00Z"
#: Every shape a claim can arrive in that is not a usable claim object.
UNFOERMIG = (None, [], "x", 1, True, {})


def _claim(signer, **ueberschreibt) -> dict:
    claim, _salts = build_eval_claim(
        suite="safety-refusal", suite_version="v1", metric="refusal_rate",
        comparator=">=", threshold="0.80", score="0.92", n=500,
        model_id="acme/model-x", dataset_id="acme/dataset-y",
        issuer=issuer_fingerprint(signer), timestamp=TS,
        model_salt=b"0" * 16, dataset_salt=b"1" * 16)
    claim = dict(claim)
    claim.update(ueberschreibt)
    return claim


class TestEineAbweisungHatEineForm(unittest.TestCase):
    """THE CATCH PROOF. Every one of these left as a raw TypeError, KeyError or AttributeError."""

    def setUp(self):
        self.signer = generate_signer()

    def test_alle_drei_flaechen_weisen_typisiert_ab(self):
        rufe = {
            "export_intoto_dsse":
                lambda x: intoto.export_intoto_dsse(x, self.signer, root_b64=ROOT),
            "export_eval_result_dsse":
                lambda x: intoto.export_eval_result_dsse(x, self.signer, root_b64=ROOT),
            "resolve_subject":
                lambda x: intoto.resolve_subject("receipt", x, root_b64=ROOT),
        }
        for name, ruf in rufe.items():
            for form in UNFOERMIG:
                with self.subTest(flaeche=name, claim=form):
                    with self.assertRaises(ProofBundleError):
                        ruf(form)

    def test_die_meldung_nennt_den_typ_und_nicht_ein_fehlendes_feld(self):
        """`as_dict` would also work and is deliberately not used: it turns the wrong TYPE into an
        empty mapping, and the caller then reads that a field is missing from something that was
        never a claim. Naming the type is what `_verdict.require_bool_verdict` does."""
        with self.assertRaises(BundleFormatError) as gefangen:
            intoto.resolve_subject("receipt", None, root_b64=ROOT)
        self.assertIn("NoneType", str(gefangen.exception))

    def test_ein_fehlendes_feld_bleibt_ein_fehlendes_feld(self):
        """The other polarity: a real claim object missing a real field must still say so."""
        ohne = _claim(self.signer)
        ohne.pop("timestamp")
        with self.assertRaises(BundleFormatError) as gefangen:
            intoto.resolve_subject("receipt", ohne, root_b64=ROOT)
        self.assertIn("timestamp", str(gefangen.exception))


class TestDerBinderIstEINER(unittest.TestCase):
    """The digest was never the difference, and this pins that so a later reader does not wonder
    whether routing through the shared builder changed what gets signed."""

    def test_das_attest_ist_byte_gleich_zum_geteilten_bauer(self):
        signer = generate_signer()
        claim = _claim(signer)
        envelope = intoto.export_intoto_dsse(claim, signer, root_b64=ROOT)
        statement = json.loads(base64.b64decode(envelope["payload"]))
        self.assertEqual(statement["subject"][0]["digest"],
                         intoto.resolve_subject("receipt", claim, root_b64=ROOT)[0]["digest"])


class TestDieWaechter(unittest.TestCase):
    """WITHOUT THESE THE FILE PROVES NOTHING: a builder that refused everything would make every
    case above green."""

    def test_ein_gueltiger_anspruch_wird_weiter_exportiert(self):
        signer = generate_signer()
        envelope = intoto.export_intoto_dsse(_claim(signer), signer, root_b64=ROOT)
        self.assertIn("payload", envelope)
        self.assertIn("signatures", envelope)

    def test_das_public_model_profil_liest_den_anspruch_gar_nicht(self):
        """The new type check sits in the receipt branch and not at the top of `resolve_subject`,
        because this profile never touches `claim`. A guard at the top would refuse it for a reason
        that does not apply to it."""
        subject = intoto.resolve_subject("public-model", None, subject_name="m",
                                         subject_sha256="a" * 64)
        self.assertEqual(subject[0]["name"], "m")

    def test_die_rb4_eingabe_wird_weiter_als_bundleformaterror_abgewiesen(self):
        """The class this exporter was already correct about stays correct."""
        signer = generate_signer()
        with self.assertRaises(BundleFormatError):
            intoto.export_intoto_dsse(_claim(signer, passed="false"), signer, root_b64=ROOT)


if __name__ == "__main__":
    unittest.main()


class _ZweizuengigesDict(dict):
    """`get` reports one value, the stored item is another.

    THIS IS NOT AN EXOTIC SHAPE, it is the only shape in which "check" and "use" are two values at
    all. A plain dict cannot exhibit the defect, which is exactly why reading twice looks harmless
    in every test written with plain dicts — and why the establisher `_verdict.require_bool_verdict`
    had to exist for `passed` in the first place. The defect needs no attacker: any `Mapping`
    wrapper with a caching or defaulting `get` is the same divergence by accident.
    """

    def __init__(self, echt: dict, meldet: dict):
        super().__init__(echt)
        self._meldet = meldet

    def get(self, key, default=None):
        if key in self._meldet:
            return self._meldet[key]
        return super().get(key, default)


class _StummesDict(dict):
    """`get` answers, `__getitem__` raises. The other polarity: not a wrong value but a wrong
    EXCEPTION TYPE, escaping past a guard that had just approved the claim."""

    def __getitem__(self, key):
        raise KeyError(key)


class TestGeprueftUndBenutztSindEINWert(unittest.TestCase):
    """THE CATCH PROOF for the read-once class. Against the parent state every case here fails,
    and it fails for the right reason: the value that went into the signed material was not the
    value the guard had approved."""

    def setUp(self):
        self.signer = generate_signer()

    def test_der_binder_traegt_den_geprueften_wert(self):
        """`resolve_subject` checked `claim.get(...)` and bound `claim[...]`."""
        echt = _claim(self.signer)
        gemeldet = {"model_id_commit": "a" * 64, "timestamp": "2026-01-01T00:00:00Z"}
        zweizuengig = _ZweizuengigesDict({**echt, "model_id_commit": "b" * 64,
                                          "timestamp": "2026-12-31T23:59:59Z"}, gemeldet)
        erwartet = intoto.resolve_subject("receipt", {**echt, **gemeldet}, root_b64=ROOT)
        self.assertEqual(intoto.resolve_subject("receipt", zweizuengig, root_b64=ROOT)[0]["digest"],
                         erwartet[0]["digest"])

    def test_die_signierte_annotation_traegt_den_geprueften_wert(self):
        """`to_test_result_statement` checked `claim.get("provenance")` and emitted
        `claim["provenance"]` into an annotation that is part of the signed statement."""
        echt = _claim(self.signer)
        zweizuengig = _ZweizuengigesDict({**echt, "provenance": "nicht-geprueft"},
                                         {"provenance": "geprueft"})
        statement = intoto.to_test_result_statement(
            zweizuengig, subject_digest={"sha256": "a" * 64}, root_b64=ROOT)
        self.assertEqual(
            statement["predicate"]["configuration"][0]["annotations"]["provenance"], "geprueft")

    def test_ein_stummes_getitem_kommt_nicht_als_keyerror_heraus(self):
        """The guard approved the claim through `get`; the parent then subscripted it anyway."""
        echt = _claim(self.signer)
        subject = intoto.resolve_subject("receipt", _StummesDict(echt), root_b64=ROOT)
        self.assertEqual(subject[0]["digest"],
                         intoto.resolve_subject("receipt", echt, root_b64=ROOT)[0]["digest"])


class TestDieWaechterDerLeseregel(unittest.TestCase):
    """WITHOUT THESE the class above proves nothing: a builder that ignored the claim entirely, or
    one that fabricated a field, would make every case green."""

    def setUp(self):
        self.signer = generate_signer()

    def test_ein_fehlendes_provenance_wird_nicht_erfunden(self):
        statement = intoto.to_test_result_statement(
            _claim(self.signer), subject_digest={"sha256": "a" * 64}, root_b64=ROOT)
        self.assertNotIn("provenance",
                         statement["predicate"]["configuration"][0]["annotations"])

    def test_ein_echtes_provenance_kommt_unveraendert_durch(self):
        statement = intoto.to_test_result_statement(
            _claim(self.signer, provenance="slsa-l3"),
            subject_digest={"sha256": "a" * 64}, root_b64=ROOT)
        self.assertEqual(
            statement["predicate"]["configuration"][0]["annotations"]["provenance"], "slsa-l3")

    def test_der_binder_haengt_weiterhin_an_seinen_feldern(self):
        """A digest that ignored the claim would satisfy the cases above. Two claims that differ in
        exactly one bound field must not share a digest."""
        echt = _claim(self.signer)
        anders = {**echt, "timestamp": "2020-01-01T00:00:00Z"}
        self.assertNotEqual(
            intoto.resolve_subject("receipt", echt, root_b64=ROOT)[0]["digest"],
            intoto.resolve_subject("receipt", anders, root_b64=ROOT)[0]["digest"])


class TestDerFALSCHESATZIMKommentar(unittest.TestCase):
    """The claim this file's own fix made about `suite` was wrong, and a cross-reading said so.

    The first repair of `to_test_result_statement` left a comment reading "`suite` below already does
    it right and is left alone". An adversarial cross-reading (third family, over the provider path)
    refuted the claim that an unguarded raw subscript next to a checked read is a DIFFERENT class.
    Measured: `claim["suite"]` went into the signed annotation while `claim.get("suite")` decided
    `passedTests`, so ONE signed statement carried the same field under two values.

    A comment is not a measurement. This case is the measurement.
    """

    def test_ein_feld_traegt_in_einem_statement_nicht_zwei_werte(self):
        signer = generate_signer()
        echt = _claim(signer)
        zweizuengig = _ZweizuengigesDict({**echt, "suite": "gespeichert"},
                                         {"suite": "geprueft"})
        statement = intoto.to_test_result_statement(
            zweizuengig, subject_digest={"sha256": "a" * 64}, root_b64=ROOT)
        annotation = statement["predicate"]["configuration"][0]["annotations"]["suite"]
        liste = (statement["predicate"].get("passedTests")
                 or statement["predicate"].get("failedTests") or [])
        self.assertEqual([annotation], liste,
                         "die signierte Annotation und passedTests tragen dasselbe Feld — sie "
                         f"duerfen nicht auseinandergehen: {annotation!r} gegen {liste!r}")

    def test_die_beiden_stellen_tragen_den_gemeldeten_wert(self):
        """WHICH of the two values wins is part of the contract: the one the accessor reported,
        because that is the value a guard would have seen."""
        signer = generate_signer()
        echt = _claim(signer)
        zweizuengig = _ZweizuengigesDict({**echt, "suite": "gespeichert"},
                                         {"suite": "geprueft"})
        statement = intoto.to_test_result_statement(
            zweizuengig, subject_digest={"sha256": "a" * 64}, root_b64=ROOT)
        self.assertEqual(
            statement["predicate"]["configuration"][0]["annotations"]["suite"], "geprueft")

    def test_ein_gewoehnlicher_anspruch_bleibt_unveraendert(self):
        """THE GUARD: a plain dict must produce exactly what it produced before, or the fix is a
        behaviour change dressed as a repair."""
        signer = generate_signer()
        statement = intoto.to_test_result_statement(
            _claim(signer), subject_digest={"sha256": "a" * 64}, root_b64=ROOT)
        self.assertEqual(
            statement["predicate"]["configuration"][0]["annotations"]["suite"], "safety-refusal")
        self.assertEqual(statement["predicate"].get("passedTests"), ["safety-refusal"])
