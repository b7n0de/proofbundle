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

WHICH CASES ARE CATCH PROOFS. The classes above the "round 3" marker were written against 62e8bbab,
the ones between the "round 3" and the "round 4" marker against 835df85b, where a second review lens
found the shape class and five siblings, and the ones below the "round 4" marker against 6893586f,
where a third lens found a withheld value judged on one read and signed from another, the statement
`subject` never walked, a key serialized through its own `encode`, and two generic fields that
contradict the signed verdict. Run against its reference commit, every case whose name does not start
with `test_control` fails; the controls pass there and here. One round-3 control changed in round 4
(`TestResultAndPassedAgree.test_control_agreement_verifies`, see its docstring). The counts are in the
commit messages.
"""
import base64
import json
import os
import re
import subprocess
import sys
import tempfile
import unicodedata
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

    def _claim_mit(self, **werte):
        """A claim built like `basis`, with some values replaced (score="0.50" gives passed=False)."""
        kw = dict(suite="safety-refusal", suite_version="v1", metric="refusal_rate",
                  comparator=">=", threshold="0.80", score="0.92", n=500,
                  model_id="acme/model-x", dataset_id="acme/dataset-y",
                  issuer=issuer_fingerprint(self.signer), timestamp="2026-09-19T12:00:00Z",
                  model_salt=b"0" * 16, dataset_salt=b"1" * 16)
        kw.update(werte)
        claim, _ = build_eval_claim(**kw)
        return dict(claim)

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


# ---- round 3: lens run 2 at 835df85b ------------------------------------------------------------------

class TestAMisshapenContainerIsAReason(_Basis):
    """THE CLASS: a walk over claim fields that reads a PRESENT container of the wrong shape as "no
    claim fields" and leaves `ok` alone. Measured at 835df85b: each envelope below, validly signed and
    canonically serialized, verified ok=True with a placeholder commitment; for (b) and (d) the verdict
    even said predicate_claim_ok=True. Absent containers stay unjudged (the controls)."""

    def _signiert(self, stmt, payload_type):
        return dsse.sign_envelope(canonical.canonicalize_statement(stmt), self.signer,
                                  payload_type=payload_type)

    def _eval_result(self, veraendere):
        stmt = intoto.to_eval_result_statement(
            self.basis, subject=intoto.resolve_subject("receipt", self.basis, root_b64=ROOT_B64),
            root_b64=ROOT_B64)
        stmt["predicate"]["commitments"]["model"]["value"] = "x"
        veraendere(stmt)
        env = self._signiert(stmt, intoto.INTOTO_STATEMENT_PAYLOAD_TYPE)
        return env, intoto.verify_eval_result_dsse(env, self.pub)

    def _test_result(self, veraendere, platzhalter=True):
        stmt = intoto.to_test_result_statement(self.basis, subject_digest={"sha256": "0" * 64})
        if platzhalter:
            stmt["predicate"]["configuration"][0]["digest"][intoto.MODEL_COMMIT_DIGEST_KEY] = "x"
        veraendere(stmt)
        return intoto.verify_intoto_dsse(self._signiert(stmt, intoto.TEST_RESULT_PAYLOAD_TYPE), self.pub)

    def _abgewiesen(self, res, text):
        self.assertIs(res["ok"], False, res["content_root_detail"])
        self.assertTrue(res["content_root_ok"], "the binding holds; the shape is what refuses")
        self.assertIs(res["predicate_claim_ok"], False)
        self.assertIn(text, res["content_root_detail"])

    def test_a_eval_result_predicate_wrapped_in_a_list(self):
        _, res = self._eval_result(lambda st: st.update(predicate=[st["predicate"]]))
        self._abgewiesen(res, "predicate must be an object")

    def test_a_the_shipped_cli_fails_it(self):
        env, _ = self._eval_result(lambda st: st.update(predicate=[st["predicate"]]))
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
        self.assertNotIn("[PASS]", r.stdout)

    def test_b_test_result_configuration_as_an_object(self):
        def umbau(st):
            cfg = st["predicate"]["configuration"]
            st["predicate"]["configuration"] = {str(i): e for i, e in enumerate(cfg)}
        self._abgewiesen(self._test_result(umbau), "configuration: must be an array")

    def test_b_test_result_configuration_as_the_single_entry(self):
        def umbau(st):
            st["predicate"]["configuration"] = st["predicate"]["configuration"][0]
        self._abgewiesen(self._test_result(umbau), "configuration: must be an array")

    def test_c_test_result_predicate_wrapped_in_a_list(self):
        self._abgewiesen(self._test_result(lambda st: st.update(predicate=[st["predicate"]])),
                         "predicate must be an object")

    def test_d_test_result_digest_as_a_list_of_pairs(self):
        def umbau(st):
            st["predicate"]["configuration"][0]["digest"] = [[intoto.MODEL_COMMIT_DIGEST_KEY, "x"]]
        self._abgewiesen(self._test_result(umbau), "configuration[0].digest: must be an object")

    def test_an_entry_that_is_not_an_object(self):
        def umbau(st):
            st["predicate"]["configuration"][0] = "model-id-commitment"
        self._abgewiesen(self._test_result(umbau, platzhalter=False), "configuration[0]: must be an object")

    def test_the_annotations_of_the_dataset_entry_are_judged_too(self):
        def umbau(st):
            st["predicate"]["configuration"][1]["annotations"] = {"comparator": "=="}
        self._abgewiesen(self._test_result(umbau, platzhalter=False), "configuration[1]")

    def test_control_absent_containers_make_no_claim(self):
        """An absent `configuration`, an entry without `digest`, and an absent predicate verify."""
        for name, umbau in (
                ("no configuration", lambda st: st["predicate"].pop("configuration")),
                ("entry without digest", lambda st: st["predicate"]["configuration"][0].pop("digest")),
                ("no predicate", lambda st: st.pop("predicate"))):
            with self.subTest(fall=name):
                res = self._test_result(umbau, platzhalter=False)
                self.assertTrue(res["ok"], res["content_root_detail"])


class TestResultAndPassedAgree(_Basis):
    """Item 5: `result` is what a generic in-toto verifier reads; `passed` is the signed verdict beside
    it. When both are present they must agree. At 835df85b a contradiction verified ok=True."""

    def _test_result(self, result, passed, claim=None):
        stmt = intoto.to_test_result_statement(claim or self.basis, subject_digest={"sha256": "0" * 64})
        stmt["predicate"]["result"] = result
        stmt["predicate"]["configuration"][0]["annotations"]["passed"] = passed
        env = dsse.sign_envelope(canonical.canonicalize_statement(stmt), self.signer,
                                 payload_type=intoto.TEST_RESULT_PAYLOAD_TYPE)
        return intoto.verify_intoto_dsse(env, self.pub)

    def test_a_contradiction_is_refused(self):
        for result, passed in (("PASSED", False), ("FAILED", True), ("WARNED", True), ("WARNED", False)):
            with self.subTest(result=result, passed=passed):
                res = self._test_result(result, passed)
                self.assertIs(res["ok"], False, res["content_root_detail"])
                self.assertIn("predicate result", res["content_root_detail"])

    def test_control_agreement_verifies(self):
        """Round 4: the FAILED case is built from a failing claim. The case lists take part in the
        agreement now, and the passing claim lists its suite under `passedTests`."""
        for result, passed, claim in (("PASSED", True, None),
                                      ("FAILED", False, self._claim_mit(score="0.50"))):
            with self.subTest(result=result, passed=passed):
                self.assertTrue(self._test_result(result, passed, claim)["ok"])


class TestSvrPropertiesHoldsTheRule(_Basis):
    """Item 1: `svr_properties` is public and builds the list `export_svr_dsse` signs. At 835df85b it
    returned THRESHOLD_MET and SAMPLE_ROOT_VALID for a claim decode refuses."""

    def _ergebnis(self):
        from proofbundle.errors import VerificationResult  # noqa: PLC0415
        res = VerificationResult()
        res.add("ed25519-signature", True, "")
        res.add("merkle-inclusion", True, "")
        return res

    def test_a_claim_decode_refuses_gets_no_properties(self):
        schlecht = dict(self.basis, comparator="==", threshold="inf", model_id_commit="sha256:x",
                        samples={"root_b64": "x", "n": -1, "leaf_alg": "md5"})
        self.assertIsNone(decode_eval_claim(self._hand_signed(schlecht)))
        faelle = [("whole", schlecht)] + [(k, dict(self.basis, **{k: v})) for k, v in (
            ("comparator", "=="), ("threshold", "inf"), ("model_id_commit", "sha256:x"),
            ("samples", {"root_b64": "x", "n": 500, "leaf_alg": "md5"}))]
        for name, claim in faelle:
            with self.subTest(fall=name):
                with self.assertRaises(BundleFormatError):
                    intoto.svr_properties(self._ergebnis(), claim)

    def test_control_a_valid_claim_still_earns_its_properties(self):
        props = intoto.svr_properties(self._ergebnis(), self.basis)
        self.assertEqual(props, ["PROOFBUNDLE_SIGNATURE_VALID", "PROOFBUNDLE_RECEIPT_UNCHANGED",
                                 "PROOFBUNDLE_THRESHOLD_MET"])


class TestAStringThatCannotBeEncodedIsATypedRefusal(_Basis):
    """Item 2: a lone surrogate in a provenance KEY. rfc8785 sorts keys by encoding them as UTF-16 and
    raised a raw UnicodeEncodeError out of the emitter and every producer at 835df85b."""

    def test_emit_and_every_producer_refuse_with_their_typed_error(self):
        claim = dict(self.basis, provenance={chr(0xD800): 1})
        self.assertIsNone(decode_eval_claim(emit_bundle(
            json.dumps(claim, sort_keys=True, separators=(",", ":")).encode("ascii"), self.signer)))
        with self.assertRaises(EvalClaimError):
            emit_eval_receipt(claim, self.signer)
        self._alle_weisen_ab(claim)


class TestTheWithheldNumbersOfAnSdJwtAreJudged(_Basis):
    """Item 3: `issue_sd_jwt` signs `ci95` and `exact_score` as disclosures. At 835df85b `["inf",
    "nan"]` and `"1e400"` were signed."""

    def test_a_bad_ci95_or_exact_score_is_refused(self):
        for name, kwargs in (("ci95 inf nan", {"ci95": ["inf", "nan"]}),
                             ("ci95 one value", {"ci95": ["0.9"]}),
                             ("ci95 floats", {"ci95": [0.9, 0.95]}),
                             ("exact_score 1e400", {"exact_score": "1e400"}),
                             ("exact_score float", {"exact_score": 0.92}),
                             ("exact_score nan", {"exact_score": "nan"})):
            with self.subTest(fall=name):
                with self.assertRaises(BundleFormatError) as ctx:
                    issue_sd_jwt(self.basis, self.signer, root_b64=ROOT_B64, **kwargs)
                self.assertIn(next(iter(kwargs)), str(ctx.exception))

    def test_control_decimal_strings_are_issued(self):
        compact = issue_sd_jwt(self.basis, self.signer, root_b64=ROOT_B64, exact_score="0.92",
                               ci95=["0.90", "0.94"])
        self.assertEqual(len(compact.rstrip("~").split("~")), 3)   # the JWT and two disclosures


class TestTheEmitProfileIsJudgedOnTheBytes(_Basis):
    """Item 4: a `str` subclass whose `__ne__` always answers False passed the NFC test on the object,
    and a decomposed `suite` was signed at 835df85b."""

    class _UngleichLuegt(str):
        def __ne__(self, other):
            return False

        def __eq__(self, other):
            return str.__eq__(self, other)

        __hash__ = str.__hash__

    def test_a_decomposed_string_is_refused_however_it_compares(self):
        zerlegt = unicodedata.normalize("NFD", "café")
        self.assertNotEqual(unicodedata.normalize("NFC", zerlegt), zerlegt)
        for name, wert in (("plain", zerlegt), ("lying subclass", self._UngleichLuegt(zerlegt))):
            with self.subTest(fall=name):
                with self.assertRaises(EvalClaimError) as ctx:
                    emit_eval_receipt(dict(self.basis, suite=wert), self.signer)
                self.assertIn("NFC", str(ctx.exception))

    def test_control_a_composed_string_is_signed(self):
        claim = dict(self.basis, suite=unicodedata.normalize("NFC", "café"))
        self.assertIsInstance(decode_eval_claim(emit_eval_receipt(claim, self.signer)), dict)


# ---- round 4: lens run 3 at 6893586f ------------------------------------------------------------------

def _offenlegungen(compact: str) -> dict:
    """name -> value of every disclosure of a compact SD-JWT."""
    werte = {}
    for teil in compact.rstrip("~").split("~")[1:]:
        _salz, name, wert = json.loads(base64.urlsafe_b64decode(teil + "=" * (-len(teil) % 4)))
        werte[name] = wert
    return werte


class _ZweiDurchlaeufe(list):
    """The first iteration yields `geprueft`, every later one `signiert`."""

    def __init__(self, geprueft, signiert):
        super().__init__(geprueft)
        self._folge = [list(geprueft), list(signiert)]

    def __iter__(self):
        return iter(self._folge.pop(0) if len(self._folge) > 1 else self._folge[0])


class _ListeLaengeLuegt(list):
    def __len__(self):
        return 2


class _TupelLaengeLuegt(tuple):
    def __len__(self):
        return 2


class _BytesLaengeLuegt(bytes):
    def __len__(self):
        return 32


class _EnthaeltLuegt(dict):
    def __contains__(self, schluessel):
        return True


class TestTheWithheldValueSignedIsTheValueJudged(_Basis):
    """Item 1: `issue_sd_jwt` judged an argument through one read and signed it from another. Measured
    at 6893586f: `ci95` judged on one iteration and signed from a second (["0.1", "0.2"] judged,
    ["inf", "nan"] or the floats NaN and Infinity signed), a `ci95` whose `__len__` said 2 signed with
    three values, a `holder_public_key` whose `__len__` said 32 signed as 64 bytes, and a `status`
    whose `__contains__` claimed a `status_list` signed without one."""

    def test_ci95_is_read_once_and_the_judged_list_is_signed(self):
        for name, signiert in (("strings", ["inf", "nan"]), ("floats", [float("nan"), float("inf")])):
            with self.subTest(zweiter_durchlauf=name):
                compact = issue_sd_jwt(self.basis, self.signer, root_b64=ROOT_B64,
                                       ci95=_ZweiDurchlaeufe(["0.1", "0.2"], signiert))
                self.assertEqual(_offenlegungen(compact)["ci95"], ["0.1", "0.2"])

    def test_a_ci95_whose_length_lies_is_refused(self):
        for name, ci95 in (("list", _ListeLaengeLuegt(["0.1", "0.2", "0.3"])),
                           ("tuple", _TupelLaengeLuegt(("0.1", "0.2", "0.3")))):
            with self.subTest(fall=name):
                with self.assertRaises(BundleFormatError) as ctx:
                    issue_sd_jwt(self.basis, self.signer, root_b64=ROOT_B64, ci95=ci95)
                self.assertIn("ci95", str(ctx.exception))

    def test_the_holder_key_is_judged_by_its_bytes(self):
        for name, schluessel in (("bytes subclass, __len__ says 32, holds 64", _BytesLaengeLuegt(bytes(64))),
                                 ("a str of 32 characters", "a" * 32),
                                 ("an int", 32)):
            with self.subTest(fall=name):
                with self.assertRaises(ValueError) as ctx:
                    issue_sd_jwt(self.basis, self.signer, root_b64=ROOT_B64, holder_public_key=schluessel)
                self.assertIn("32-byte", str(ctx.exception))

    def test_a_status_whose_membership_lies_is_refused(self):
        with self.assertRaises(ValueError) as ctx:
            issue_sd_jwt(self.basis, self.signer, root_b64=ROOT_B64, status=_EnthaeltLuegt({"x": 1}))
        self.assertIn("status_list", str(ctx.exception))

    def test_control_plain_arguments_are_issued_as_before(self):
        roh = generate_signer().public_key().public_bytes_raw()
        status = {"status_list": {"idx": 7, "uri": "https://example.org/status/1"}}
        for name, schluessel in (("bytes", roh), ("bytearray", bytearray(roh)), ("memoryview", memoryview(roh))):
            with self.subTest(schluessel=name):
                compact = issue_sd_jwt(self.basis, self.signer, root_b64=ROOT_B64, ci95=("0.90", "0.94"),
                                       holder_public_key=schluessel, status=status)
                offen = _immer_offen(compact)
                self.assertEqual(offen["cnf"]["jwk"]["x"],
                                 base64.urlsafe_b64encode(roh).rstrip(b"=").decode("ascii"))
                self.assertEqual(offen["status"], status)
                self.assertEqual(_offenlegungen(compact)["ci95"], ["0.90", "0.94"])


class TestADisclosedScoreEarnsTheVerdict(_Basis):
    """Item 4, second half: a disclosed `exact_score` that the claim's comparator and threshold do not
    map to the claim's `passed` contradicts the always-open verdict. Measured at 6893586f: "0.10" was
    signed beside passed=true for >= 0.80."""

    def _faelle(self):
        besteht = self.basis                                            # >= 0.80, passed True
        scheitert = self._claim_mit(score="0.50")                       # >= 0.80, passed False
        kleiner = self._claim_mit(comparator="<", threshold="0.10", score="0.05")   # passed True
        self.assertIs(scheitert["passed"], False)
        self.assertIs(kleiner["passed"], True)
        return besteht, scheitert, kleiner

    def test_a_score_that_contradicts_passed_is_refused(self):
        besteht, scheitert, kleiner = self._faelle()
        for name, claim, wert in (("passing >= 0.80, 0.10", besteht, "0.10"),
                                  ("passing >= 0.80, 0.79", besteht, "0.79"),
                                  ("failing >= 0.80, 0.92", scheitert, "0.92"),
                                  ("failing >= 0.80, the threshold", scheitert, "0.80"),
                                  ("passing < 0.10, 0.10", kleiner, "0.10")):
            with self.subTest(fall=name):
                with self.assertRaises(BundleFormatError) as ctx:
                    issue_sd_jwt(claim, self.signer, root_b64=ROOT_B64, exact_score=wert)
                self.assertIn("exact_score", str(ctx.exception))
                self.assertIn("passed", str(ctx.exception))

    def test_control_a_score_that_earns_passed_is_issued(self):
        besteht, scheitert, kleiner = self._faelle()
        for name, claim, wert in (("passing >= 0.80, 0.92", besteht, "0.92"),
                                  ("passing >= 0.80, the threshold", besteht, "0.80"),
                                  ("passing >= 0.80, 0.800", besteht, "0.800"),
                                  ("failing >= 0.80, 0.50", scheitert, "0.50"),
                                  ("passing < 0.10, 0.05", kleiner, "0.05")):
            with self.subTest(fall=name):
                compact = issue_sd_jwt(claim, self.signer, root_b64=ROOT_B64, exact_score=wert)
                self.assertEqual(_offenlegungen(compact)["exact_score"], wert)


class TestTheCaseListsAgreeWithTheVerdict(_Basis):
    """Item 4, first half: `passedTests`, `warnedTests` and `failedTests` are generic fields a generic
    in-toto verifier reads, like `result`. `verifier_block.validate_test_result_statement` derives the
    result from them for its own statements; the eval test-result export now holds the same rule where
    a commitment entry annotates `passed`, and lists the annotated suite where its verdict puts it.
    Measured at 6893586f: `result` PASSED with the suite under `failedTests`, and `passedTests` naming
    another suite, each verified ok=True."""

    def _test_result(self, veraendere, claim=None):
        stmt = intoto.to_test_result_statement(claim or self.basis, subject_digest={"sha256": "0" * 64})
        veraendere(stmt["predicate"])
        env = dsse.sign_envelope(canonical.canonicalize_statement(stmt), self.signer,
                                 payload_type=intoto.TEST_RESULT_PAYLOAD_TYPE)
        return intoto.verify_intoto_dsse(env, self.pub)

    def test_a_case_list_that_contradicts_passed_is_refused(self):
        suite = self.basis["suite"]
        scheitert = self._claim_mit(score="0.50")

        def ohne_result(p):
            p.pop("result")
            p["failedTests"] = p.pop("passedTests")
        faelle = (
            ("suite under failedTests, result PASSED", None,
             lambda p: p.update(failedTests=p.pop("passedTests")), "case lists"),
            ("passedTests names another suite", None,
             lambda p: p.update(passedTests=["another-suite"]), "passedTests"),
            ("the suite under passedTests and failedTests", None,
             lambda p: p.update(failedTests=[suite]), "case lists"),
            ("the suite under warnedTests as well", None,
             lambda p: p.update(warnedTests=[suite]), "case lists"),
            ("the suite listed twice", None,
             lambda p: p.update(passedTests=[suite, suite]), "case lists"),
            ("passedTests a string", None, lambda p: p.update(passedTests=suite), "passedTests"),
            ("every list empty", None, lambda p: p.update(passedTests=[], failedTests=[]), "case lists"),
            ("no result, the suite under failedTests", None, ohne_result, "case lists"),
            ("failing claim, the suite under passedTests", scheitert,
             lambda p: p.update(passedTests=p.pop("failedTests")), "case lists"),
        )
        for name, claim, veraendere, text in faelle:
            with self.subTest(fall=name):
                res = self._test_result(veraendere, claim)
                self.assertIs(res["ok"], False, res["content_root_detail"])
                self.assertTrue(res["content_root_ok"], "the binding holds; the rule is what refuses")
                self.assertIs(res["predicate_claim_ok"], False)
                self.assertIn(f"predicate {text}", res["content_root_detail"])

    def test_control_lists_that_agree_verify(self):
        """The export's own lists for a passing and a failing claim, a further passing case beside the
        suite (the lists derive the verdict, and the verdict says nothing about other cases), and a
        generic test result with case lists and no commitment of ours, which is not judged."""
        suite = self.basis["suite"]

        def generisch(p):
            p["configuration"] = [{"name": "m", "digest": {"x": "y"}}]
            p["failedTests"] = ["t1"]
        for name, claim, veraendere in (
                ("passing, as exported", None, lambda p: None),
                ("failing, as exported", self._claim_mit(score="0.50"), lambda p: None),
                ("passing, a further passed case", None,
                 lambda p: p.update(passedTests=[suite, "another-suite"])),
                ("generic, no commitment of ours", None, generisch)):
            with self.subTest(fall=name):
                res = self._test_result(veraendere, claim)
                self.assertTrue(res["ok"], res["content_root_detail"])


class TestTheSubjectIsJudgedByTheOwnershipRule(_Basis):
    """Item 2: the ownership rule "a descriptor is ours when its digest carries the proofbundle
    commitment key" held in the test-result `configuration` only. Measured at 6893586f: a validly signed
    test-result or eval-result statement whose `subject` was
    [{"name": "model-id-commitment", "digest": {"proofbundleModelCommitV1": "x"}}] verified ok=True with
    predicate_claim_ok True, and `proofbundle intoto --verify` printed PASS. The subject is now walked
    with the same descriptor rule wherever the statement is of the verifier's own type."""

    ARTEN = ("eval-result", "test-result")

    def _statement(self, art):
        if art == "eval-result":
            return intoto.to_eval_result_statement(
                self.basis, subject=intoto.resolve_subject("receipt", self.basis, root_b64=ROOT_B64),
                root_b64=ROOT_B64)
        return intoto.to_test_result_statement(self.basis, subject_digest={"sha256": "0" * 64})

    def _signiert(self, art, stmt):
        typ = intoto.INTOTO_STATEMENT_PAYLOAD_TYPE if art == "eval-result" else intoto.TEST_RESULT_PAYLOAD_TYPE
        return dsse.sign_envelope(canonical.canonicalize_statement(stmt), self.signer, payload_type=typ)

    def _verifiziert(self, art, veraendere):
        stmt = self._statement(art)
        veraendere(stmt)
        env = self._signiert(art, stmt)
        if art == "eval-result":
            return intoto.verify_eval_result_dsse(env, self.pub)
        return intoto.verify_intoto_dsse(env, self.pub)

    def _abgewiesen(self, res, text):
        self.assertIs(res["ok"], False, res["content_root_detail"])
        self.assertTrue(res["content_root_ok"], "the binding holds; the rule is what refuses")
        self.assertIs(res["predicate_claim_ok"], False)
        self.assertIn(text, res["content_root_detail"])

    def test_subject_verify_agrees_with_the_oracle_on_each_commitment(self):
        for art in self.ARTEN:
            for schluessel, feld in ((intoto.MODEL_COMMIT_DIGEST_KEY, "model_id_commit"),
                                     (intoto.DATASET_COMMIT_DIGEST_KEY, "dataset_id_commit")):
                for hexwert in ("x", "not-a-commitment", "A" * 64, "b" * 64):
                    with self.subTest(art=art, schluessel=schluessel, wert=hexwert):
                        res = self._verifiziert(art, lambda st, k=schluessel, h=hexwert: st.update(
                            subject=[{"name": "commitment", "digest": {k: h}}]))
                        if orakel_commitment("sha256:" + hexwert):
                            self.assertTrue(res["ok"], res["content_root_detail"])
                            self.assertIs(res["predicate_claim_ok"], True)
                        else:
                            self._abgewiesen(res, f"subject[0]: {feld}")

    def test_a_second_subject_entry_is_judged(self):
        for art in self.ARTEN:
            with self.subTest(art=art):
                res = self._verifiziert(art, lambda st: st["subject"].append(
                    {"name": "model-id-commitment", "digest": {intoto.MODEL_COMMIT_DIGEST_KEY: "x"}}))
                self._abgewiesen(res, "subject[1]: model_id_commit")

    def test_a_misshapen_subject_is_a_reason(self):
        eintrag = {"name": "model-id-commitment", "digest": {intoto.MODEL_COMMIT_DIGEST_KEY: "x"}}
        for art in self.ARTEN:
            for name, subjekt, text in (
                    ("subject an object", {"0": eintrag}, "subject: must be an array"),
                    ("an entry that is not an object", ["model-id-commitment"], "subject[0]: must be an object"),
                    ("a digest as a list of pairs",
                     [{"name": "m", "digest": [[intoto.MODEL_COMMIT_DIGEST_KEY, "x"]]}],
                     "subject[0].digest: must be an object")):
                with self.subTest(art=art, fall=name):
                    self._abgewiesen(self._verifiziert(art, lambda st, s=subjekt: st.update(subject=s)), text)

    def test_the_annotations_of_a_subject_entry_of_ours_are_judged(self):
        ours = {"name": "model-id-commitment", "digest": {intoto.MODEL_COMMIT_DIGEST_KEY: "b" * 64}}
        for art in self.ARTEN:
            with self.subTest(art=art, fall="threshold inf"):
                res = self._verifiziert(art, lambda st: st.update(
                    subject=[dict(ours, annotations={"threshold": "inf"})]))
                self._abgewiesen(res, "subject[0]: threshold")
        with self.subTest(art="test-result", fall="passed false beside result PASSED"):
            res = self._verifiziert("test-result", lambda st: st.update(
                subject=[dict(ours, annotations={"passed": False})]))
            self._abgewiesen(res, "predicate result")

    def test_the_shipped_cli_fails_a_placeholder_subject(self):
        stmt = self._statement("eval-result")
        stmt["subject"] = [{"name": "model-id-commitment", "digest": {intoto.MODEL_COMMIT_DIGEST_KEY: "x"}}]
        env = self._signiert("eval-result", stmt)
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
        self.assertNotIn("[PASS]", r.stdout)

    def test_control_a_subject_that_is_not_ours_makes_no_claim(self):
        """The subjects the package writes, a generic digest, an entry without a digest, and an absent
        subject verify, and so does every statement the two exporters produce for a passing and a
        failing claim, over the three subject profiles and both content-root algorithms."""
        for art in self.ARTEN:
            for name, veraendere in (
                    ("as written", lambda st: None),
                    ("generic digest", lambda st: st.update(subject=[{"name": "m", "digest": {"x": "y"}}])),
                    ("entry without digest", lambda st: st.update(subject=[{"name": "m", "uri": "https://x"}])),
                    ("no subject", lambda st: st.pop("subject"))):
                with self.subTest(art=art, fall=name):
                    res = self._verifiziert(art, veraendere)
                    self.assertTrue(res["ok"], res["content_root_detail"])
        for claim in (self.basis, self._claim_mit(score="0.50")):
            for alg in (intoto.CONTENT_ROOT_ALG, intoto.LEGACY_CONTENT_ROOT_ALG):
                for profil in intoto.SUBJECT_PROFILES:
                    extra = {} if profil == "receipt" else {"subject_name": "m", "subject_sha256": "ab" * 32}
                    with self.subTest(passed=claim["passed"], alg=alg, export="eval-result", profil=profil):
                        env = intoto.export_eval_result_dsse(claim, self.signer, subject_profile=profil,
                                                             root_b64=ROOT_B64, content_root_alg=alg, **extra)
                        res = intoto.verify_eval_result_dsse(env, self.pub)
                        self.assertTrue(res["ok"], res["content_root_detail"])
                with self.subTest(passed=claim["passed"], alg=alg, export="test-result"):
                    env = intoto.export_intoto_dsse(claim, self.signer, root_b64=ROOT_B64, content_root_alg=alg)
                    res = intoto.verify_intoto_dsse(env, self.pub)
                    self.assertTrue(res["ok"], res["content_root_detail"])


class _KodiertMitFehler(str):
    def encode(self, *args, **kwargs):
        raise LookupError("no such encoding")


class _KodiertAlsZahl(str):
    def encode(self, *args, **kwargs):
        return 0


class _KodiertAnders(str):
    """Encodes "aaa" as b"\\xff", so rfc8785 sorted it after "bbb"."""

    def encode(self, *args, **kwargs):
        return b"\xff" if str.__eq__(self, "aaa") else str.encode(self, *args, **kwargs)


class _KeinStrMitEncode:
    """A key that is not a string but has an `encode` method."""

    def encode(self, *args, **kwargs):
        return b"k"


class _AndererHash(str):
    """Equal to "a" as a string, but hashed apart, so a dict holds it beside a plain "a"."""

    def __hash__(self):
        return 12345


class TestAKeyIsSerializedByItsCharacters(_Basis):
    """Item 3: rfc8785 sorts object keys through the key's own `encode("utf-16be")`. Measured at
    6893586f: a `str` subclass key in `provenance` whose `encode` raised LookupError or returned an int
    escaped the emitter, the eight producers and `svr_properties` as a raw exception; one that encoded a
    key differently got a payload signed whose keys were not in canonical order; a non-string key with an
    `encode` method raised a raw TypeError; and the same keys in the `harness` argument escaped the two
    exporters, or were signed in an order their own verifier refuses. The canonicalizers now serialize a
    plain copy (keys and strings as plain `str`); the except around rfc8785 is not widened."""

    def _alle_produzieren(self, claim):
        from proofbundle.errors import VerificationResult  # noqa: PLC0415
        ergebnis = VerificationResult()
        ergebnis.add("ed25519-signature", True, "")
        ergebnis.add("merkle-inclusion", True, "")
        erzeuger = dict(_produzenten(), svr_properties=lambda c, s: intoto.svr_properties(ergebnis, c))
        for name, erzeuge in erzeuger.items():
            with self.subTest(produzent=name):
                self.assertIsNotNone(erzeuge(claim, self.signer))

    def test_a_key_whose_encode_fails_is_serialized_by_its_characters(self):
        for name, schluessel in (("raises LookupError", _KodiertMitFehler("a")),
                                 ("returns an int", _KodiertAlsZahl("a"))):
            with self.subTest(encode=name):
                claim = dict(self.basis, provenance={schluessel: 1, "b": 2})
                gelesen = decode_eval_claim(emit_eval_receipt(claim, self.signer))
                self.assertEqual(gelesen["provenance"], {"a": 1, "b": 2})
                self._alle_produzieren(claim)

    def test_the_emitted_payload_is_canonical_whatever_a_key_encodes_to(self):
        import rfc8785  # noqa: PLC0415
        claim = dict(self.basis, provenance={_KodiertAnders("aaa"): 1, "bbb": 2})
        payload = base64.b64decode(emit_eval_receipt(claim, self.signer)["payload_b64"])
        self.assertEqual(rfc8785.dumps(json.loads(payload)), payload)

    def test_a_key_that_is_not_a_string_is_a_typed_refusal(self):
        claim = dict(self.basis, provenance={_KeinStrMitEncode(): 1})
        with self.assertRaises(EvalClaimError):
            emit_eval_receipt(claim, self.signer)
        self._alle_weisen_ab(claim)

    def test_a_harness_key_is_serialized_by_its_characters(self):
        paare = (("export_eval_result_dsse", intoto.export_eval_result_dsse, intoto.verify_eval_result_dsse),
                 ("export_intoto_dsse", intoto.export_intoto_dsse, intoto.verify_intoto_dsse))
        for name, harness in (("encode raises LookupError", {_KodiertMitFehler("a"): 1}),
                              ("encode sorts it elsewhere", {_KodiertAnders("aaa"): 1, "bbb": 2})):
            for export, exportiere, pruefe in paare:
                with self.subTest(harness=name, export=export):
                    env = exportiere(self.basis, self.signer, root_b64=ROOT_B64, harness=harness)
                    res = pruefe(env, self.pub)
                    self.assertTrue(res["ok"], res["content_root_detail"])

    def test_control_two_keys_equal_as_strings_are_refused(self):
        """JSON has one key for both. rfc8785 wrote both, and the read-back refused the duplicate; the
        plain copy refuses it before that. Typed in both, so this is a control."""
        claim = dict(self.basis, provenance={_AndererHash("a"): 1, "a": 2})
        self.assertEqual(len(claim["provenance"]), 2)
        with self.assertRaises(EvalClaimError):
            emit_eval_receipt(claim, self.signer)
        self._alle_weisen_ab(claim)


# ---- round 5: lens run 4 at c3ca546b ------------------------------------------------------------------

class _NenntSichStatusList(str):
    """A key that hashes and compares like "status_list" and whose characters are something else."""

    def __hash__(self):
        return hash("status_list")

    def __eq__(self, other):
        return other == "status_list" or str.__eq__(self, other)


class TestTheLastTwoReadsOfRoundFour(_Basis):
    """Lens run 4 at c3ca546b, two P3. The `status` copy kept a key that claimed to be "status_list"
    through `__hash__` and `__eq__`, so the membership test passed and the signed status carried the
    key's own characters, without a `status_list`. And `_plain_for_jcs` copied a list through a list
    comprehension, a frame of its own per level on Python 3.10, so `canonicalize` refused lists nested
    497 deep that `rfc8785.dumps` writes."""

    def test_a_status_key_is_judged_by_its_characters(self):
        status = {_NenntSichStatusList("revocation-off"): {"idx": 7, "uri": "https://example.org/status/1"}}
        self.assertIn("status_list", status)                     # the premise: the lie works on a dict
        with self.assertRaises(ValueError) as ctx:
            issue_sd_jwt(self.basis, self.signer, root_b64=ROOT_B64, status=status)
        self.assertIn("status_list", str(ctx.exception))

    def test_a_status_key_that_is_no_string_is_refused(self):
        with self.assertRaises(ValueError):
            issue_sd_jwt(self.basis, self.signer, root_b64=ROOT_B64,
                         status={"status_list": {"idx": 7, "uri": "https://example.org/status/1"}, 5: 1})

    def test_the_copy_reads_lists_as_deep_as_the_serializer(self):
        import rfc8785  # noqa: PLC0415
        from proofbundle.evalclaim import canonicalize  # noqa: PLC0415
        for tiefe in (497, 900):
            with self.subTest(tiefe=tiefe):
                wert: object = 1
                for _ in range(tiefe):
                    wert = [wert]
                self.assertEqual(canonicalize({"provenance": wert}), rfc8785.dumps({"provenance": wert}))

    def test_control_a_plain_status_is_signed_as_given(self):
        status = {"status_list": {"idx": 7, "uri": "https://example.org/status/1"}}
        self.assertEqual(_immer_offen(issue_sd_jwt(self.basis, self.signer, root_b64=ROOT_B64,
                                                   status=status))["status"], status)


if __name__ == "__main__":
    unittest.main()
