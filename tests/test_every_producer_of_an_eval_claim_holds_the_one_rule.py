"""Every producer that turns an eval claim into signed or digested output holds the verifier's rule.

THE CLASS: two copies of one rule. A producer signs claim content that it checked with its own subset
of the rule. `emit_eval_receipt` was brought onto `decode_eval_claim`'s rule (`_claim_violation`) in
62e8bbab. The review lens at that commit found the other producers of the same content still on their
own subsets. Measured at 62e8bbab:

- `export_eval_result_dsse` and `export_intoto_dsse` signed a claim whose commitments were `sha256:x`,
  `not-a-commitment` or `sha256:` followed by 64 upper-case hex digits; `verify_eval_result_dsse` and
  `verify_intoto_dsse` returned ok=True for those envelopes; `to_intoto_statement` built a subject
  digest from the placeholder. `_require_export_fields` checked presence and the type of `passed`.
- The same exporters and `issue_sd_jwt` signed a claim with comparator `==`, threshold `inf`, n=-1,
  commit_alg `md5-plain` and schema `x`.
- The emitter checked the Python object and signed its RFC 8785 serialization. An `int` subclass
  holding 500 whose `__int__` returns -1 was serialized as -1, and a `str` subclass that compares equal
  to anything passed `schema` and `commit_alg`; both claims were signed and decode refused both.
- `decode_eval_claim` accepted `provenance={"run_attempts": 2**53}` (also -2**53 and 2**60), which the
  emitter refused.

THE ORACLES ARE THIS FILE'S OWN. Which commitment is well formed and which integer is in the safe range
is decided below with a regular expression and a walk written here, not with `_COMMIT_RE` or
`_is_unsafe_int`, so a module and a test that shared one misreading could not agree with each other.
The agreement property uses `decode_eval_claim` as the reference, because agreeing with the verifier
is the property.

WHICH CASES ARE CATCH PROOFS. Run against the source of 62e8bbab, every case in this file whose name
does not start with `test_control` fails; the controls pass there and here. The counts are in the
commit message.
"""
import base64
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import test_eval_claim_commitment_pattern_holds as korpus_quelle  # the generator of the existing property

import proofbundle
from proofbundle import canonical, dsse, intoto
from proofbundle.emit import emit_bundle, generate_signer
from proofbundle.errors import BundleFormatError
from proofbundle.evalclaim import (
    EvalClaimError,
    build_eval_claim,
    decode_eval_claim,
    emit_eval_receipt,
    issuer_fingerprint,
)
from proofbundle.sdjwt_issue import issue_sd_jwt

REPO = Path(__file__).resolve().parents[1]
# The CLI case runs the package this process imported, so a run against another source tree measures
# that tree on the CLI path too, and not this checkout's src.
PAKET_SRC = Path(proofbundle.__file__).resolve().parents[1]
ROOT_B64 = base64.b64encode(bytes(range(32))).decode("ascii")
COMMIT_FIELDS = ("model_id_commit", "dataset_id_commit")
PLATZHALTER = ("sha256:x", "not-a-commitment", "sha256:" + "A" * 64)
# The claim the lens signed through every exporter, and each of its parts on its own.
BREIT = (("comparator", "=="), ("threshold", "inf"), ("n", -1), ("commit_alg", "md5-plain"),
         ("schema", "x"), ("model_id_commit", "sha256:x"))
SICHER = 2 ** 53 - 1

# ---- the independent oracles -------------------------------------------------------------------------

_HEX64 = re.compile(r"[0-9a-f]{64}")


def orakel_commitment(wert) -> bool:
    """`sha256:` and exactly 64 lower-case hex digits, nothing before or after."""
    return (isinstance(wert, str) and len(wert) == 71 and wert[:7] == "sha256:"
            and _HEX64.fullmatch(wert[7:]) is not None)


def orakel_ganzzahlen_sicher(wert) -> bool:
    """No integer (bool excluded) of magnitude above 2**53-1 anywhere inside `wert`."""
    if isinstance(wert, bool):
        return True
    if isinstance(wert, int):
        return -SICHER <= wert <= SICHER
    if isinstance(wert, dict):
        return all(orakel_ganzzahlen_sicher(v) for v in wert.values())
    if isinstance(wert, (list, tuple)):
        return all(orakel_ganzzahlen_sicher(v) for v in wert)
    return True


# ---- the producers under test ------------------------------------------------------------------------

def _produzenten():
    """Every producer that turns an eval claim into signed or digested output, by the name it reports.

    Found with `grep` over src/proofbundle for the exporters that read `model_id_commit`, `passed` or a
    claim argument: the eight sites the lens named. `export_svr_dsse` and `hf_evals` take a BUNDLE and
    decode it first; `to_eval_results_entry` publishes the bundle itself. They are covered by decode.
    """
    subjekt = [{"name": "eval-receipt", "digest": {"sha256": "0" * 64}}]
    return {
        "export_eval_result_dsse": lambda c, s: intoto.export_eval_result_dsse(c, s, root_b64=ROOT_B64),
        "to_eval_result_statement": lambda c, s: intoto.to_eval_result_statement(c, subject=subjekt),
        "to_eval_result_predicate": lambda c, s: intoto.to_eval_result_predicate(c),
        "export_intoto_dsse": lambda c, s: intoto.export_intoto_dsse(c, s, root_b64=ROOT_B64),
        "to_test_result_statement": lambda c, s: intoto.to_test_result_statement(
            c, subject_digest={"sha256": "0" * 64}),
        "to_intoto_statement": lambda c, s: intoto.to_intoto_statement(c),
        "resolve_subject": lambda c, s: intoto.resolve_subject("receipt", c, root_b64=ROOT_B64),
        "issue_sd_jwt": lambda c, s: issue_sd_jwt(c, s, root_b64=ROOT_B64),
    }


def _nutzlast(env) -> dict:
    return json.loads(base64.b64decode(env["payload"]))


def _immer_offen(compact: str) -> dict:
    teil = compact.split("~", 1)[0].split(".")[1]
    return json.loads(base64.urlsafe_b64decode(teil + "=" * (-len(teil) % 4)))


class _Basis(unittest.TestCase):

    def setUp(self):
        self.signer = generate_signer()
        claim, _ = build_eval_claim(
            suite="safety-refusal", suite_version="v1", metric="refusal_rate",
            comparator=">=", threshold="0.80", score="0.92", n=500,
            model_id="acme/model-x", dataset_id="acme/dataset-y",
            issuer=issuer_fingerprint(self.signer), timestamp="2026-09-19T12:00:00Z",
            model_salt=b"0" * 16, dataset_salt=b"1" * 16)
        self.basis = dict(claim)
        self.pub = self.signer.public_key().public_bytes_raw()

    def _hand_signed(self, claim):
        return emit_bundle(json.dumps(claim, sort_keys=True, separators=(",", ":")).encode(), self.signer)

    def _alle_weisen_ab(self, claim, feld=None):
        """Every producer raises BundleFormatError, and the reason names `feld` right after the site."""
        for name, erzeuge in _produzenten().items():
            with self.subTest(produzent=name):
                with self.assertRaises(BundleFormatError) as ctx:
                    erzeuge(claim, self.signer)
                if feld is not None:
                    grund = str(ctx.exception).split(": ", 1)[-1]
                    self.assertTrue(grund.startswith(feld), str(ctx.exception))


class TestEachProducerRefusesWhatTheRuleRefuses(_Basis):

    def test_control_every_producer_accepts_the_valid_claim(self):
        self.assertIsInstance(decode_eval_claim(self._hand_signed(self.basis)), dict)
        for name, erzeuge in _produzenten().items():
            with self.subTest(produzent=name):
                self.assertIsNotNone(erzeuge(self.basis, self.signer))

    def test_each_placeholder_commitment_is_refused_by_every_producer(self):
        for feld in COMMIT_FIELDS:
            for wert in PLATZHALTER:
                with self.subTest(feld=feld, wert=wert):
                    self.assertFalse(orakel_commitment(wert), "the oracle must call it malformed")
                    claim = dict(self.basis, **{feld: wert})
                    self.assertIsNone(decode_eval_claim(self._hand_signed(claim)))
                    self._alle_weisen_ab(claim, feld)

    def test_the_wide_bad_claim_is_refused_by_every_producer(self):
        self._alle_weisen_ab(dict(self.basis, **dict(BREIT)))

    def test_each_part_of_the_wide_claim_alone_is_refused_and_named(self):
        for feld, wert in BREIT:
            with self.subTest(feld=feld, wert=wert):
                self._alle_weisen_ab(dict(self.basis, **{feld: wert}), feld)

    def test_control_the_plaintext_guard_still_answers_first(self):
        """The salt-leak guard of the eval-result export stays the first refusal of a plaintext key.

        The claim rule would refuse `model_id` too, as an unknown field; the guard is ordered before it
        so its message, which says why a name must never reach an attestation, is the one a caller
        reads, and so the mutation operator that disables it (scripts/mutation_check.py) is still
        killed. A control: it holds at 62e8bbab as well.
        """
        for erzeuge in (lambda c: intoto.to_eval_result_predicate(c),
                        lambda c: intoto.export_eval_result_dsse(c, self.signer)):
            with self.assertRaises(BundleFormatError) as ctx:
                erzeuge(dict(self.basis, model_id="acme/model-x"))
            self.assertIn("plaintext", str(ctx.exception))


class TestEachVerifierRefusesAHandMadeEnvelope(_Basis):
    """A validly signed, canonically serialized envelope whose predicate carries a claim value the rule
    refuses. The signature and the content-root binding hold; what refuses is the claim rule."""

    def _eval_result(self, veraendere):
        stmt = intoto.to_eval_result_statement(
            self.basis, subject=intoto.resolve_subject("receipt", self.basis, root_b64=ROOT_B64),
            root_b64=ROOT_B64)
        veraendere(stmt["predicate"])
        env = dsse.sign_envelope(canonical.canonicalize_statement(stmt), self.signer,
                                 payload_type=intoto.INTOTO_STATEMENT_PAYLOAD_TYPE)
        return intoto.verify_eval_result_dsse(env, self.pub)

    def _test_result(self, veraendere):
        stmt = intoto.to_test_result_statement(self.basis, subject_digest={"sha256": "0" * 64})
        veraendere(stmt["predicate"])
        env = dsse.sign_envelope(canonical.canonicalize_statement(stmt), self.signer,
                                 payload_type=intoto.TEST_RESULT_PAYLOAD_TYPE)
        return intoto.verify_intoto_dsse(env, self.pub)

    def _abgewiesen(self, res, bezeichnung):
        self.assertIs(res["ok"], False, res["content_root_detail"])
        self.assertTrue(res["content_root_ok"], "the binding holds; the claim rule is what refuses")
        self.assertIs(res["predicate_claim_ok"], False)
        self.assertIn(bezeichnung, res["content_root_detail"])

    def test_control_the_unchanged_hand_made_envelopes_verify(self):
        for res in (self._eval_result(lambda p: None), self._test_result(lambda p: None)):
            self.assertTrue(res["ok"], res["content_root_detail"])

    def test_eval_result_verify_agrees_with_the_oracle_on_each_commitment(self):
        """Three placeholders refused, and two well-formed values accepted: the anti-parity half."""
        for rolle in ("model", "dataset"):
            for hexwert in ("x", "not-a-commitment", "A" * 64, "b" * 64, "0123456789abcdef" * 4):
                with self.subTest(rolle=rolle, wert=hexwert):
                    def setze(p, rolle=rolle, hexwert=hexwert):
                        p["commitments"][rolle]["value"] = hexwert
                    res = self._eval_result(setze)
                    if orakel_commitment("sha256:" + hexwert):
                        self.assertTrue(res["ok"], res["content_root_detail"])
                        self.assertIs(res["predicate_claim_ok"], True)
                    else:
                        self._abgewiesen(res, f"commitments.{rolle}")

    def test_eval_result_verify_refuses_each_part_of_the_wide_claim(self):
        teile = (
            ("claims[0]", "comparator", lambda p: p["claims"][0].update(comparator="==")),
            ("claims[0]", "threshold", lambda p: p["claims"][0].update(threshold="inf")),
            ("sampleSize", "n", lambda p: p.update(sampleSize=-1)),
            ("commitments.model", "commit_alg",
             lambda p: p["commitments"]["model"].update(alg="md5-plain")),
            ("commitments.dataset", "salted",
             lambda p: p["commitments"]["dataset"].update(salted=False)),
        )
        for bezeichnung, feld, veraendere in teile:
            with self.subTest(teil=bezeichnung, feld=feld):
                res = self._eval_result(veraendere)
                self._abgewiesen(res, bezeichnung)
                self.assertIn(feld, res["content_root_detail"])

    def test_test_result_verify_agrees_with_the_oracle_on_each_commitment(self):
        schluessel = {"model": (0, intoto.MODEL_COMMIT_DIGEST_KEY),
                      "dataset": (1, intoto.DATASET_COMMIT_DIGEST_KEY)}
        for rolle, (index, key) in schluessel.items():
            for hexwert in ("x", "not-a-commitment", "A" * 64, "b" * 64):
                with self.subTest(rolle=rolle, wert=hexwert):
                    def setze(p, index=index, key=key, hexwert=hexwert):
                        p["configuration"][index]["digest"][key] = hexwert
                    res = self._test_result(setze)
                    if orakel_commitment("sha256:" + hexwert):
                        self.assertTrue(res["ok"], res["content_root_detail"])
                        self.assertIs(res["predicate_claim_ok"], True)
                    else:
                        self._abgewiesen(res, f"configuration[{index}]")

    def test_test_result_verify_refuses_a_bad_annotation_of_the_commitment_entry(self):
        for feld, wert in (("comparator", "=="), ("threshold", "inf"), ("passed", "false")):
            with self.subTest(feld=feld):
                res = self._test_result(lambda p, f=feld, w=wert: p["configuration"][0]["annotations"]
                                        .update({f: w}))
                self._abgewiesen(res, "configuration[0]")

    def test_control_a_generic_test_result_entry_is_not_judged(self):
        """A test-result entry without a proofbundle commitment digest is not an eval claim."""
        def fremd(p):
            p["configuration"] = [{"name": "m", "digest": {"x": "y"},
                                   "annotations": {"threshold": "anything"}}]
        res = self._test_result(fremd)
        self.assertTrue(res["ok"], res["content_root_detail"])
        self.assertIn(res.get("predicate_claim_ok"), (True, None))

    def test_the_shipped_cli_fails_a_placeholder_envelope(self):
        def setze(p):
            p["commitments"]["model"]["value"] = "x"
        stmt = intoto.to_eval_result_statement(
            self.basis, subject=intoto.resolve_subject("receipt", self.basis), root_b64=ROOT_B64)
        setze(stmt["predicate"])
        env = dsse.sign_envelope(canonical.canonicalize_statement(stmt), self.signer,
                                 payload_type=intoto.INTOTO_STATEMENT_PAYLOAD_TYPE)
        with tempfile.TemporaryDirectory() as d:
            pfad = os.path.join(d, "att.json")
            Path(pfad).write_text(json.dumps(env), encoding="utf-8")
            r = subprocess.run(
                [sys.executable, "-B", "-m", "proofbundle.cli", "intoto", pfad, "--verify",
                 "--pub", base64.b64encode(self.pub).decode("ascii")],
                capture_output=True, text=True, cwd=REPO,
                env={"PYTHONPATH": str(PAKET_SRC), "PYTHONDONTWRITEBYTECODE": "1"})
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertIn("=> FAILED", r.stdout)
        self.assertNotIn("Traceback", r.stderr)


class _ZahlMitAndererInt(int):
    """Holds 500, and `int()` of it is -1. rfc8785 calls `int()`, so its bytes say -1."""

    def __int__(self):
        return -1


class _GleichAllem(str):
    """Compares equal to anything, so `claim.get("schema") != EVAL_CLAIM_SCHEMA` is False."""

    def __eq__(self, other):
        return True

    def __ne__(self, other):
        return False

    __hash__ = str.__hash__


class _ZweiZugriffe(dict):
    """`get("passed")` answers `wert`; the stored item, which a serializer copies, is something else."""

    wert = True

    def get(self, k, d=None):  # noqa: D102
        return self.wert if k == "passed" else super().get(k, d)


class TestThePlantedObjectIsJudgedAsItSerializes(_Basis):

    def test_an_int_that_serializes_differently_is_refused_by_every_producer(self):
        claim = dict(self.basis, n=_ZahlMitAndererInt(500))
        with self.assertRaises(EvalClaimError):
            emit_eval_receipt(claim, self.signer)
        self._alle_weisen_ab(claim, "n")

    def test_a_str_equal_to_everything_is_refused_by_every_producer(self):
        claim = dict(self.basis, schema=_GleichAllem("x"), commit_alg=_GleichAllem("md5-plain"))
        with self.assertRaises(EvalClaimError):
            emit_eval_receipt(claim, self.signer)
        self._alle_weisen_ab(claim)

    def test_a_dict_whose_get_disagrees_with_its_items_is_refused(self):
        claim = _ZweiZugriffe(self.basis)
        claim["passed"] = "false"
        with self.assertRaises(EvalClaimError):
            emit_eval_receipt(claim, self.signer)
        self._alle_weisen_ab(claim, "passed")

    def test_the_value_used_is_the_value_serialized(self):
        """`get` says True, the stored item is False: both booleans, so the rule passes either one. The
        output must carry False, the value in the canonical bytes, at every producer that writes the
        verdict. At 62e8bbab `to_eval_result_predicate` wrote True, the value the check had read."""
        claim = _ZweiZugriffe(self.basis)
        claim["passed"] = False
        s = self.signer
        self.assertIs(intoto.to_eval_result_predicate(claim)["claims"][0]["passed"], False)
        self.assertIs(_nutzlast(intoto.export_eval_result_dsse(claim, s))["predicate"]["claims"][0]
                      ["passed"], False)
        self.assertEqual(intoto.to_test_result_statement(
            claim, subject_digest={"sha256": "0" * 64})["predicate"]["result"], "FAILED")
        self.assertIs(intoto.to_intoto_statement(claim)["predicate"]["claims"][0]["passed"], False)
        self.assertIs(_immer_offen(issue_sd_jwt(claim, s, root_b64=ROOT_B64))["passed"], False)

    def test_control_an_honest_int_subclass_is_accepted(self):
        """The read-back must not refuse a subclass whose bytes say what it holds."""
        class Ehrlich(int):
            pass
        claim = dict(self.basis, n=Ehrlich(500))
        self.assertIsInstance(decode_eval_claim(emit_eval_receipt(claim, self.signer)), dict)
        for name, erzeuge in _produzenten().items():
            with self.subTest(produzent=name):
                self.assertIsNotNone(erzeuge(claim, self.signer))
        self.assertEqual(intoto.to_eval_result_predicate(claim)["sampleSize"], 500)


class TestTheSafeRangeHoldsAtDecode(_Basis):
    UNSICHER = (2 ** 53, -(2 ** 53), 2 ** 60)
    GRENZE = (SICHER, -SICHER)

    def _claims(self, werte):
        for wert in werte:
            yield wert, dict(self.basis, provenance={"run_attempts": wert})
            yield wert, dict(self.basis, provenance={"a": [{"b": wert}]})

    def test_decode_refuses_an_integer_beyond_the_safe_range_anywhere(self):
        for wert, claim in self._claims(self.UNSICHER):
            with self.subTest(wert=wert, provenance=claim["provenance"]):
                self.assertFalse(orakel_ganzzahlen_sicher(claim))
                self.assertIsNone(decode_eval_claim(self._hand_signed(claim)))

    def test_control_decode_accepts_the_edge_of_the_range(self):
        for wert, claim in self._claims(self.GRENZE):
            with self.subTest(wert=wert, provenance=claim["provenance"]):
                self.assertTrue(orakel_ganzzahlen_sicher(claim))
                self.assertIsInstance(decode_eval_claim(self._hand_signed(claim)), dict)
                self.assertIsInstance(decode_eval_claim(emit_eval_receipt(claim, self.signer)), dict)

    def test_emit_and_every_producer_agree_with_decode_on_the_range(self):
        for wert, claim in self._claims(self.UNSICHER + self.GRENZE):
            with self.subTest(wert=wert, provenance=claim["provenance"]):
                nimmt = decode_eval_claim(self._hand_signed(claim)) is not None
                try:
                    emit_eval_receipt(claim, self.signer)
                    signiert = True
                except EvalClaimError:
                    signiert = False
                self.assertEqual(signiert, nimmt)
                for name, erzeuge in _produzenten().items():
                    try:
                        erzeuge(claim, self.signer)
                        erzeugt = True
                    except BundleFormatError:
                        erzeugt = False
                    self.assertEqual(erzeugt, nimmt, name)


class TestEveryProducerAgreesWithDecode(_Basis):
    """THE PROPERTY, over the generated corpus of tests/test_eval_claim_commitment_pattern_holds.py
    (every schema property set to each palette value, and removed) plus its probes, the placeholders,
    the wide claim and the range cases.

    The issuer binding stays outside, as the docstring of `_claim_violation` says: it compares the
    claim's `issuer` with the key that signed the bundle, and an exporter has no bundle. So the
    reference for the exporters is decode of the claim with a present `issuer` set to the signer's; a
    missing `issuer` stays missing. For the emitter the reference is its own two normalizations, as in
    the existing property.
    """

    def _faelle(self):
        faelle = korpus_quelle._korpus(self.basis, mit_loeschungen=True)
        for feld, wert in korpus_quelle.PROBEN:
            claim = dict(self.basis, **{feld: wert})
            if feld == "samples":
                claim["n"] = 500
            faelle.append((f"probe {feld}={wert!r}", claim))
        for feld in COMMIT_FIELDS:
            for wert in PLATZHALTER:
                faelle.append((f"{feld}={wert}", dict(self.basis, **{feld: wert})))
        faelle.append(("wide", dict(self.basis, **dict(BREIT))))
        for wert in (2 ** 53, -(2 ** 53), 2 ** 60, SICHER):
            faelle.append((f"provenance {wert}", dict(self.basis, provenance={"k": wert})))
        return faelle

    #: The one place a producer is STRICTER than decode, measured over this corpus, with its reason. A
    #: stricter producer signs nothing decode refuses, which is the property; it is listed so that the
    #: set cannot grow unnoticed and so that an entry that stops occurring fails as stale.
    #: `intoto._require_export_fields` counts an empty string as a missing field (`_EXPORT_REQUIRED`),
    #: and `resolve_subject("receipt")` needs a non-empty timestamp for its binder. The eval-result
    #: predicate's `evaluatedAt` is an RFC 3339 timestamp (docs/upstream/eval-result.md), and "" is
    #: none; the claim schema types `timestamp` only as a string, so decode accepts it.
    STRENGER = {("timestamp=''", name) for name in (
        "export_eval_result_dsse", "to_eval_result_statement", "to_eval_result_predicate",
        "resolve_subject")}

    def test_every_producer_and_emit_agree_with_decode(self):
        fp = issuer_fingerprint(self.signer)
        erzeugt_gesamt = abgewiesen_gesamt = 0
        strenger_gesehen = set()
        for fall, claim in self._faelle():
            referenz = dict(claim, issuer=fp) if "issuer" in claim else dict(claim)
            nimmt = decode_eval_claim(self._hand_signed(referenz)) is not None
            fuer_emit = dict(claim, issuer=fp)
            fuer_emit.setdefault("assurance_level", "self_attested")
            emit_nimmt = decode_eval_claim(self._hand_signed(fuer_emit)) is not None
            with self.subTest(fall=fall, produzent="emit_eval_receipt"):
                try:
                    emit_eval_receipt(claim, self.signer)
                    signiert = True
                except EvalClaimError:
                    signiert = False
                self.assertEqual(signiert, emit_nimmt)
            for name, erzeuge in _produzenten().items():
                with self.subTest(fall=fall, produzent=name):
                    try:
                        erzeuge(claim, self.signer)
                        erzeugt = True
                    except BundleFormatError:
                        erzeugt = False
                    if (fall, name) in self.STRENGER and nimmt and not erzeugt:
                        strenger_gesehen.add((fall, name))
                        continue
                    self.assertEqual(erzeugt, nimmt, f"{name} {'produced' if erzeugt else 'refused'}, "
                                                     f"decode {'accepts' if nimmt else 'refuses'}")
                    if erzeugt:
                        erzeugt_gesamt += 1
                        # The independent half: nothing a producer accepted is malformed by this
                        # file's own reading of the two properties the lens found broken.
                        self.assertTrue(all(orakel_commitment(claim[f]) for f in COMMIT_FIELDS))
                        self.assertTrue(orakel_ganzzahlen_sicher(claim))
                    else:
                        abgewiesen_gesamt += 1
        # Both outcomes occur, or the agreement would be vacuous.
        self.assertGreater(erzeugt_gesamt, 0)
        self.assertGreater(abgewiesen_gesamt, 0)
        self.assertEqual(strenger_gesehen, self.STRENGER, "a listed stricter case no longer occurs")


if __name__ == "__main__":
    unittest.main()
