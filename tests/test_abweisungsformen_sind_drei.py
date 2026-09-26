"""Three disjoint refusal forms, and the docstring that promised one. The types are MEASURED here.

WHERE THIS CAME FROM. On 2026-09-24 the house deep-gate ran two lenses over the landed R-B4 fix
(`237bb07ae4`) against three pre-registered falsification targets. The third one was

    F3 — the refusals are typed so differently that a caller cannot catch them with one `except`.

An independent Claude lens REFUTED it, with executed proof, and the sentence it refuted is in this
repository, written by the same session that wrote the fix:

    ``sdjwt_issue._require_bool_verdict``, docstring, as landed:
      "``BundleFormatError`` and not ``ValueError``: ``issue_sd_jwt`` already raises ``ValueError``
       for a malformed ``status`` and a wrong-length holder key … so a caller that guards one guards
       all five with one ``except``."

Its second half is true: the five R-B4 sites all raise `BundleFormatError`, so one
`except BundleFormatError` covers those five. What it left out is what a reader takes away from the
first half — `BundleFormatError` is NOT a `ValueError`, so `issue_sd_jwt` has TWO DISJOINT refusal
families and no single `except` covers all of ITS refusals. And one layer out there is a third form
that is not an exception at all: `decode_eval_claim` refuses a non-bool `passed` by returning `None`.

WHY A TEST AND NOT JUST A CORRECTED SENTENCE. The lens measured the types with `issubclass` and found
no test in this repository that does. A promise about exception types belongs in a contract, because
prose about types is exactly the thing that goes stale without anything breaking — this docstring was
wrong on the day it landed, and nothing failed.

THE GUARDS MATTER AS MUCH AS THE CATCH PROOFS HERE. A file that only proved "these two excepts do not
overlap" would also pass if the refusals stopped happening altogether. So the control arm issues a
VALID claim, and one case pins the half of the docstring that was RIGHT.
"""
from __future__ import annotations

import json
import unittest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from proofbundle.emit import emit_bundle, generate_signer
from proofbundle.errors import BundleFormatError, ProofBundleError, UnsupportedError
from proofbundle.evalclaim import (
    EvalClaimError,
    build_eval_claim,
    decode_eval_claim,
    emit_eval_receipt,
    issuer_fingerprint,
)
from proofbundle.intoto import (
    to_eval_result_predicate,
    to_intoto_statement,
    to_test_result_statement,
)
from proofbundle.sdjwt_issue import issue_sd_jwt

TS = "2026-09-19T12:00:00Z"
ROOT = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"


def _claim(signer):
    """A claim from the blessed emitter — the control arm, so a refusal below means something."""
    claim, _salts = build_eval_claim(
        suite="safety-refusal", suite_version="v1", metric="refusal_rate",
        comparator=">=", threshold="0.80", score="0.92", n=500,
        model_id="acme/model-x", dataset_id="acme/dataset-y",
        issuer=issuer_fingerprint(signer), timestamp=TS,
        model_salt=b"0" * 16, dataset_salt=b"1" * 16)
    return claim


def _claim_mit_string_verdikt(signer) -> dict:
    """The R-B4 shape: `passed` as the STRING "false", which `bool()` reads as True."""
    c = dict(_claim(signer))
    c["passed"] = "false"
    return c


class TestDieHierarchieIstGemessenNichtBehauptet(unittest.TestCase):
    """The four facts the lens established with `issubclass`, pinned so prose cannot drift from them."""

    def test_bundleformaterror_ist_kein_valueerror(self):
        self.assertFalse(issubclass(BundleFormatError, ValueError),
                         "BundleFormatError is a ValueError — then the docstring's reading would hold")
        self.assertTrue(issubclass(BundleFormatError, ProofBundleError))

    def test_evalclaimerror_ist_ein_valueerror_und_kein_proofbundleerror(self):
        """The two families cross here: this one sits on the OTHER side from BundleFormatError."""
        self.assertTrue(issubclass(EvalClaimError, ValueError))
        self.assertFalse(issubclass(EvalClaimError, ProofBundleError),
                         "EvalClaimError joined the ProofBundleError tree — then one except would reach it")

    def test_unsupportederror_liegt_auf_derselben_seite_wie_bundleformaterror(self):
        """Stated because it is the same question for the sibling: no ValueError there either."""
        self.assertFalse(issubclass(UnsupportedError, ValueError))
        self.assertTrue(issubclass(UnsupportedError, ProofBundleError))


class TestZweiDisjunkteFamilienInEinerFunktion(unittest.TestCase):
    """Executed in BOTH directions. One direction alone would not show disjointness."""

    def test_except_valueerror_faengt_die_rb4_abweisung_nicht(self):
        """THE CATCH PROOF for the docstring's misleading reading."""
        signer = generate_signer()
        gefangen = None
        try:
            issue_sd_jwt(_claim_mit_string_verdikt(signer), signer, root_b64=ROOT)
        except ValueError as exc:            # what the docstring's first half invites
            gefangen = ("ValueError", exc)
        except BundleFormatError as exc:     # what actually comes
            gefangen = ("BundleFormatError", exc)
        self.assertIsNotNone(gefangen, "issue_sd_jwt signed a string verdict — R-B4 is open again")
        self.assertEqual(gefangen[0], "BundleFormatError",
                         "the R-B4 refusal arrived as a ValueError — the two families merged")

    def test_except_proofbundleerror_faengt_die_status_abweisung_nicht(self):
        """THE OTHER DIRECTION, and it is what makes the two families DISJOINT rather than nested.

        A malformed `status` is a genuine ValueError from the same function, and a caller guarding the
        R-B4 family alone does not see it.
        """
        signer = generate_signer()
        gefangen = None
        try:
            issue_sd_jwt(_claim(signer), signer, root_b64=ROOT, status={"kein_status_list": 1})
        except ProofBundleError as exc:
            gefangen = ("ProofBundleError", exc)
        except ValueError as exc:
            gefangen = ("ValueError", exc)
        self.assertIsNotNone(gefangen, "a malformed status was accepted")
        self.assertEqual(gefangen[0], "ValueError",
                         "the status refusal arrived inside the ProofBundleError tree")

    def test_kein_einzelnes_except_faengt_beide(self):
        """The statement of the finding itself, as one case: neither type covers both refusals."""
        signer = generate_signer()
        for typ in (ValueError, ProofBundleError):
            entkommen = []
            for ruf in (lambda: issue_sd_jwt(_claim_mit_string_verdikt(signer), signer, root_b64=ROOT),
                        lambda: issue_sd_jwt(_claim(signer), signer, root_b64=ROOT,
                                             status={"kein_status_list": 1})):
                try:
                    ruf()
                except typ:
                    pass
                except Exception as exc:          # noqa: BLE001 — that it escapes IS the measurement
                    entkommen.append(type(exc).__name__)
            self.assertEqual(len(entkommen), 1,
                             f"except {typ.__name__} covered both refusals, escaped: {entkommen}")


class TestDieHaelfteDieRICHTIGWar(unittest.TestCase):
    """The docstring was right that ONE except covers the five R-B4 sites. That half is kept."""

    def test_ein_except_bundleformaterror_faengt_die_rb4_stellen(self):
        signer = generate_signer()
        c = _claim_mit_string_verdikt(signer)
        rufe = {
            "sdjwt_issue.issue_sd_jwt": lambda: issue_sd_jwt(c, signer, root_b64=ROOT),
            "intoto.to_intoto_statement": lambda: to_intoto_statement(c, root_b64=ROOT),
            "intoto.to_test_result_statement": lambda: to_test_result_statement(
                c, subject_digest={"sha256": "0" * 64}, root_b64=ROOT),
            "intoto.to_eval_result_predicate": lambda: to_eval_result_predicate(c, root_b64=ROOT),
        }
        for name, ruf in rufe.items():
            with self.subTest(stelle=name):
                try:
                    ruf()
                except BundleFormatError:
                    continue
                except Exception as exc:          # noqa: BLE001 — a foreign type is the finding
                    self.fail(f"{name} refused with {type(exc).__name__}, not BundleFormatError: {exc}")
                self.fail(f"{name} accepted a string verdict — R-B4 is open at this site")


class TestDieDritteFormIstGarKeineAusnahme(unittest.TestCase):
    """`decode_eval_claim` refuses by RETURNING None. A caller guarding either family sees nothing."""

    def _signiert_mit_string_verdikt(self):
        # Signed with emit_bundle, as the sanity arm below says: emit_eval_receipt runs the same claim
        # validation as decode and refuses this claim before signing, so the carrier goes past it.
        signer = Ed25519PrivateKey.generate()
        return emit_bundle(json.dumps(_claim_mit_string_verdikt(signer)).encode(), signer)

    def test_decode_gibt_none_und_wirft_nicht(self):
        buendel = self._signiert_mit_string_verdikt()
        self.assertIsNone(decode_eval_claim(buendel),
                          "a signed bundle with a string verdict decoded as a claim")

    def test_der_folgezugriff_entkommt_beiden_except_zweigen(self):
        """What a caller actually experiences: a TypeError from the subscript, through both guards."""
        buendel = self._signiert_mit_string_verdikt()
        for typ in (BundleFormatError, ProofBundleError, ValueError):
            with self.subTest(guard=typ.__name__):
                entkommen = None
                try:
                    decode_eval_claim(buendel)["suite"]
                except typ as exc:
                    self.fail(f"except {typ.__name__} caught the None-refusal: {exc!r}")
                except TypeError as exc:
                    entkommen = exc
                self.assertIsNotNone(entkommen,
                                     "the subscript on None neither raised TypeError nor was caught")

    def test_kontrollarm_ein_gueltiger_anspruch_dekodiert_weiter(self):
        """WITHOUT THIS THE FILE PROVES NOTHING. If decode refused everything, every case above would
        be green and the boundary would be broken in the other direction."""
        signer = generate_signer()
        dekodiert = decode_eval_claim(emit_eval_receipt(_claim(signer), signer))
        self.assertIsInstance(dekodiert, dict)
        self.assertIsInstance(dekodiert["passed"], bool)

    def test_kontrollarm_ein_gueltiger_anspruch_wird_weiter_ausgestellt(self):
        """The same guard for the signing side: the refusals above are not a dead issuer."""
        signer = generate_signer()
        compact = issue_sd_jwt(_claim(signer), signer, root_b64=ROOT)
        self.assertTrue(compact.endswith("~"))
        self.assertIn(".", compact.split("~")[0])


class TestDerBuendelWegBleibtUnberuehrt(unittest.TestCase):
    """A sanity arm: emit_bundle is used by the third-form cases only as a carrier, not as a subject."""

    def test_emit_bundle_traegt_beliebige_nutzlast(self):
        signer = generate_signer()
        self.assertIsInstance(emit_bundle(b'{"a": 1}', signer), dict)


if __name__ == "__main__":
    unittest.main()
