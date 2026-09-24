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
