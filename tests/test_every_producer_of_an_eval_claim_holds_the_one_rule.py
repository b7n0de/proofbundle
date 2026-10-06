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
contradict the signed verdict. The ones below the "round 5" marker were written against c3ca546b,
except its recursion-limit case (round 6, written against 5a21b199, where only its `canonicalize`
half fails; its emit half guards main 1e95b197). The ones below the "round 7" marker were written
against 93b3c6f5, where a fifth lens found a copy and a budget that read a caller's container through
methods the caller can override while the serializer wrote something else, and a circular or deep
container that escaped as a raw exception. The ones below the "round 8" marker were written against
c8205c18, where a sixth lens found that caller code still ran inside the copy and after it; one
round-2 case changed its expectation in round 8
(`TestThePlantedObjectIsJudgedAsItSerializes.test_an_int_that_serializes_differently_is_written_as_what_it_holds`).
The ones below the "round 9" marker were written against ee489403, where a seventh lens found a
refusal that raised while naming a type, a band of depths in which a serializer after the copy
raised RecursionError, numbers and a `subject_digest` that reached a serializer or `dict()` raw, an
OrderedDict copied in its storage order, and caller-attested flags read by their truth. In round 9
the round-8 proof passes plain booleans as the flags of `export_svr_dsse`, because a recording int is
refused there now before the rest of the path runs; the recording ints stay as a case of their own.
The ones below the "round 10" marker were written against 493c2f86, where an eighth lens found that
the reading which decided whether an OrderedDict key hashes through the caller's code could be
misled by a `__hash__` bound under a key that only compares equal to the name, a flag read by its
truth, and a string argument compared through the caller's own methods; a second lens added the `ok`
of a check that `svr_properties` read by its truth. In round 10 one round-9 case changed its expected
message
(`TestAnOrderedDictIsReadInItsOwnOrder.test_a_key_that_computes_its_own_hash_is_refused_without_running_it`),
and one round-10 case fails at 493c2f86 because its refusal is new there, not because it catches a
defect (`TestAFlagIsReadAsABoolean.test_the_bytes_path_refuses_a_flag_that_is_no_bool_too`).
`TestVerifyCommitmentAnswersABool`, the last class of round 10, was written against 6b223d8e, the
first commit of that round, and is run against that commit.
Run against its reference commit, every case whose name does not start with `test_control` fails;
the controls pass there and here. One round-3 control changed in round 4
(`TestResultAndPassedAgree.test_control_agreement_verifies`, see its docstring). The counts are in
the commit messages.
"""
import base64
import collections
import ctypes
import enum
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
from proofbundle.errors import BundleFormatError, ProofBundleError
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
        """Every producer raises BundleFormatError, and the reason names `feld` right after the site.

        Round 8: the eval-result producers' own presence-and-type check (`_require_export_fields`)
        names a field in backticks ("`passed` is str 'false'"). It answered first for a plain claim
        before round 8 too; it now reads the plain copy of every claim, so it answers first for a
        dict subclass whose `get` lies as well."""
        for name, erzeuge in _produzenten().items():
            with self.subTest(produzent=name):
                with self.assertRaises(BundleFormatError) as ctx:
                    erzeuge(claim, self.signer)
                if feld is not None:
                    grund = str(ctx.exception).split(": ", 1)[-1]
                    self.assertTrue(grund.lstrip("`").startswith(feld), str(ctx.exception))


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
    """Holds 500, and `int()` of it is -1. rfc8785 calls `int()`, so its bytes said -1 until the plain
    copy read it by its stored value (round 8)."""

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

    def test_an_int_that_serializes_differently_is_refused(self):
        """Round 2 against 62e8bbab: this int was serialized as -1 there and signed. Rounds 2 to 7
        refused it, because the read-back found -1 where 500 had been checked. Round 8 (lens run 6,
        F4) read an int subclass by the value it stores and wrote 500. Since the 6.2.0 chain carries
        PR 293 the one copy rule (`_plain_value.plain_json`) refuses a subclass of int outright, and
        the JCS copy agrees: the emitter and every producer refuse it, and nothing carries -1 or 500
        (owner decision OA-c7d6ff7121). Red at 62e8bbab (-1 signed) and at the D4 head 7cc8fa0b (500
        signed)."""
        claim = dict(self.basis, n=_ZahlMitAndererInt(500))
        with self.assertRaises(EvalClaimError) as ctx:
            emit_eval_receipt(claim, self.signer)
        self.assertIn("a subclass of int", str(ctx.exception))
        self._alle_weisen_ab(claim)

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

    def test_an_honest_int_subclass_is_refused_too(self):
        """Until the 6.2.0 chain carried PR 293 this was the control that the read-back does not refuse a
        subclass whose bytes say what it holds. The one copy rule refuses every subclass of int, an
        honest one included, because the check cannot know it is honest without running its code (owner
        decision OA-c7d6ff7121). The plain int is the control (`_Basis`)."""
        class Ehrlich(int):
            pass
        claim = dict(self.basis, n=Ehrlich(500))
        with self.assertRaises(EvalClaimError):
            emit_eval_receipt(claim, self.signer)
        self._alle_weisen_ab(claim)
        self.assertIsInstance(decode_eval_claim(emit_eval_receipt(dict(self.basis, n=500), self.signer)), dict)


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
        # Nachtrag 48/48b (F3): svr_properties earns a property only for a result bound to exactly this claim and
        # produced by this process's verify_bundle; use the real (result, claim) pair of one eval receipt.
        from _svr_binding import bound_svr_result  # type: ignore  # noqa: PLC0415
        result, claim = bound_svr_result(self.basis, self.signer)
        props = intoto.svr_properties(result, claim)
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
        for name, schluessel in (("bytes", roh), ("bytearray", bytearray(roh))):
            with self.subTest(schluessel=name):
                compact = issue_sd_jwt(self.basis, self.signer, root_b64=ROOT_B64, ci95=("0.90", "0.94"),
                                       holder_public_key=schluessel, status=status)
                offen = _immer_offen(compact)
                self.assertEqual(offen["cnf"]["jwk"]["x"],
                                 base64.urlsafe_b64encode(roh).rstrip(b"=").decode("ascii"))
                self.assertEqual(offen["status"], status)
                self.assertEqual(_offenlegungen(compact)["ci95"], ["0.90", "0.94"])
        # A memoryview holder key is refused for its type since the 6.2.0 chain carries PR 293
        # (`signature.plain_bytes`: bytes or bytearray only); the D4 head 7cc8fa0b bound it.
        with self.assertRaises(ValueError) as ctx:
            issue_sd_jwt(self.basis, self.signer, root_b64=ROOT_B64, holder_public_key=memoryview(roh))
        self.assertIn("must be bytes or bytearray", str(ctx.exception))


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
        """The JCS copy itself still reads lists as deep as rfc8785 writes them. `canonicalize` no longer
        reaches that depth since the 6.2.0 chain carries PR 293: it reads the claim first through
        `_plain_value.plain_json`, the one copy rule, which refuses a value nested past the structural
        budget (64 levels) with its own EvalClaimError. At the D4 head 7cc8fa0b `canonicalize` wrote
        both depths."""
        import rfc8785  # noqa: PLC0415
        from proofbundle.evalclaim import canonicalize  # noqa: PLC0415
        for tiefe in (497, 900):
            with self.subTest(tiefe=tiefe):
                wert: object = 1
                for _ in range(tiefe):
                    wert = [wert]
                self.assertEqual(rfc8785.dumps(canonical._plain_for_jcs({"provenance": wert}, ValueError)),
                                 rfc8785.dumps({"provenance": wert}))
                with self.assertRaises(EvalClaimError) as ctx:
                    canonicalize({"provenance": wert})
                self.assertIn("nests deeper than 64 levels", str(ctx.exception))

    def test_a_claim_nested_past_the_recursion_limit_is_a_typed_refusal(self):
        """Lens run 5 at 5a21b199 (both foreign lenses asked about depth): the profile walk that runs
        before the serializer raised a bare RecursionError out of `canonicalize` for a provenance of
        995 and of 5000 nested lists. It is the typed refusal the serializer's own depth gives now.

        Corrected in round 7: the first wording said `emit_eval_receipt` raised it at 5a21b199 too.
        Measured there, it already gave EvalClaimError at every depth from 980 to 1000, at 2000 and
        at 5000, because `_claim_read_back` catches the RecursionError; it raised the bare one on
        main 1e95b197 (995 and 5000). So the emit half of this case cannot fail at 5a21b199; it
        guards main's behaviour."""
        from proofbundle.evalclaim import canonicalize  # noqa: PLC0415
        for tiefe in (995, 5000):
            with self.subTest(tiefe=tiefe):
                wert: object = 1
                for _ in range(tiefe):
                    wert = [wert]
                claim = dict(self.basis, provenance={"x": wert})
                with self.assertRaises(EvalClaimError):
                    canonicalize(claim)
                with self.assertRaises(EvalClaimError):
                    emit_eval_receipt(claim, self.signer)

    def test_control_a_plain_status_is_signed_as_given(self):
        status = {"status_list": {"idx": 7, "uri": "https://example.org/status/1"}}
        self.assertEqual(_immer_offen(issue_sd_jwt(self.basis, self.signer, root_b64=ROOT_B64,
                                                   status=status))["status"], status)


# ---- round 7: lens run 5 at 5a21b199 and 93b3c6f5 ------------------------------------------------------

class _IterUndGetitem(dict):
    """`__iter__` overridden (by the base method) and `__getitem__` raising. `dict()` of such an
    object reads `keys()` and `__getitem__`, and raises; what it holds is an ordinary dict."""

    def __iter__(self):
        return dict.__iter__(self)

    def __getitem__(self, schluessel):
        raise KeyError(schluessel)


class _ZeigtFremdes(dict):
    """`__iter__`, `keys` and `__getitem__` show a `status_list` that the storage does not hold."""

    def __iter__(self):
        return iter(["status_list"])

    def keys(self):
        return ["status_list"]

    def __getitem__(self, schluessel):
        return {"idx": 99, "uri": "https://example.org/other"}


class _ListeZeigtFremdes(list):
    """Holds what it was built from; iterating it shows 99."""

    def __iter__(self):
        return iter([99])


class _ZeigtNichts(dict):
    """Holds what it was built from; `items`, `values`, `keys` and `__len__` show nothing."""

    def items(self):
        return iter(())

    def values(self):
        return iter(())

    def keys(self):
        return iter(())

    def __len__(self):
        return 0


class _ListeZeigtNichts(list):
    """Holds what it was built from; iterating it shows nothing and `__len__` says 0."""

    def __iter__(self):
        return iter(())

    def __len__(self):
        return 0


class _UnechtesDict:
    """Not a dict, but `__class__` says dict, so `isinstance(x, dict)` answers True."""

    __class__ = dict  # type: ignore[assignment]

    def keys(self):
        return ["idx"]

    def __getitem__(self, schluessel):
        return 5


class _UnechterStr:
    __class__ = str  # type: ignore[assignment]


class _UnechteZahl:
    __class__ = int  # type: ignore[assignment]


def _geschachtelt(tiefe: int, art: str = "list"):
    wert: object = 1
    for _ in range(tiefe):
        wert = [wert] if art == "list" else {"a": wert}
    return wert


class TestAContainerIsReadByWhatItHolds(_Basis):
    """Item 1. The plain copy (`canonical._plain_for_jcs`) read a container through methods the caller
    can override: `dict(value)`, which calls `keys()` and `__getitem__` once `__iter__` is overridden,
    and `list(value)`, which calls `__iter__`. Measured at 93b3c6f5 (lens run 5 at 5a21b199): a
    `status` holding a dict subclass whose `__getitem__` raises escaped `issue_sd_jwt` as a raw
    KeyError where c3ca546b signed what it holds, and the same object in a `provenance` made the
    emitter and the producers raise KeyError (on main 1e95b197 too). The copy now reads what a
    container holds, and so does the claim rule's own walk."""

    def test_a_status_is_signed_as_its_stored_contents(self):
        for name, status, erwartet in (
                ("a dict whose __getitem__ raises", {"status_list": _IterUndGetitem({"idx": 7})},
                 {"status_list": {"idx": 7}}),
                ("a list whose __iter__ shows 99",
                 {"status_list": {"idx": 7, "bits": _ListeZeigtFremdes([1, 0])}},
                 {"status_list": {"idx": 7, "bits": [1, 0]}})):
            with self.subTest(fall=name):
                compact = issue_sd_jwt(self.basis, self.signer, root_b64=ROOT_B64, status=status)
                self.assertEqual(_immer_offen(compact)["status"], erwartet)

    def test_a_status_list_that_only_the_methods_show_is_refused(self):
        """At 93b3c6f5 the status below was signed with the `status_list` its methods show."""
        status = _ZeigtFremdes({"x": 1})
        self.assertEqual(list(status), ["status_list"])          # the premise: iterating shows one
        with self.assertRaises(ValueError) as ctx:
            issue_sd_jwt(self.basis, self.signer, root_b64=ROOT_B64, status=status)
        self.assertIn("status_list", str(ctx.exception))

    def test_a_provenance_is_signed_as_its_stored_contents(self):
        claim = dict(self.basis, provenance={"k": _IterUndGetitem({"idx": 7}),
                                             "l": _ListeZeigtFremdes([1, 0])})
        gelesen = decode_eval_claim(emit_eval_receipt(claim, self.signer))
        self.assertEqual(gelesen["provenance"], {"k": {"idx": 7}, "l": [1, 0]})
        for name, erzeuge in _produzenten().items():
            with self.subTest(produzent=name):
                self.assertIsNotNone(erzeuge(claim, self.signer))

    def test_the_claim_rule_reads_what_is_serialized(self):
        """At 93b3c6f5 and on main 1e95b197 the profile walk read `values()` and the claim rule read
        `__iter__`: `canonicalize` wrote a float that its profile forbids, and `emit_eval_receipt`
        signed an empty list where the list held 2**60."""
        from proofbundle.evalclaim import canonicalize  # noqa: PLC0415
        with self.assertRaises(EvalClaimError) as ctx:
            canonicalize(dict(self.basis, provenance={"k": _ZeigtNichts({"f": 0.5})}))
        self.assertIn("float", str(ctx.exception))
        claim = dict(self.basis, provenance={"k": _ListeZeigtNichts([2 ** 60])})
        with self.assertRaises(EvalClaimError) as ctx:
            emit_eval_receipt(claim, self.signer)
        self.assertIn("provenance holds integer", str(ctx.exception))
        self._alle_weisen_ab(claim, "provenance")

    def test_a_value_whose_class_claims_a_json_type_is_refused(self):
        """`isinstance` reads `__class__`, which an object sets itself. At 93b3c6f5 a status holding
        such a dict was signed as {"idx": 5}, such a string raised a raw TypeError, and in a
        provenance such a dict, string or int raised a raw AttributeError or TypeError out of the
        emitter and every producer; in a statement, a raw TypeError out of the budget."""
        for name, status in (("a dict", {"status_list": _UnechtesDict()}),
                             ("a string value", {"status_list": {"v": _UnechterStr()}}),
                             ("a string key", {"status_list": {}, _UnechterStr(): 1})):
            with self.subTest(status=name):
                with self.assertRaises(ValueError):
                    issue_sd_jwt(self.basis, self.signer, root_b64=ROOT_B64, status=status)
        for name, wert in (("a dict", _UnechtesDict()), ("a string", _UnechterStr()),
                           ("an int", _UnechteZahl())):
            claim = dict(self.basis, provenance={"k": wert})
            with self.subTest(provenance=name):
                with self.assertRaises(EvalClaimError):
                    emit_eval_receipt(claim, self.signer)
                self._alle_weisen_ab(claim)
        with self.assertRaises(BundleFormatError):
            canonical.canonicalize_statement({"_type": "t", "predicate": _UnechtesDict()})


class TestACircularOrDeepContainerIsATypedRefusal(_Basis):
    """Item 2. At 93b3c6f5 (lens run 5 at 5a21b199) a circular `status` raised RecursionError where
    c3ca546b and main 1e95b197 gave json's ValueError, and a status nested past the recursion limit
    raised RecursionError (on main too, from json.dumps). Both are the documented ValueError now,
    and so is the band of depths in which the copy passed and json.dumps raised."""

    def test_a_circular_status_is_refused(self):
        zirkel: dict = {"status_list": {}}
        zirkel["status_list"]["self"] = zirkel
        liste: list = []
        liste.append(liste)
        for name, status in (("dict", zirkel), ("list", {"status_list": liste})):
            with self.subTest(kreis=name):
                with self.assertRaises(ValueError) as ctx:
                    issue_sd_jwt(self.basis, self.signer, root_b64=ROOT_B64, status=status)
                # Since the 6.2.0 chain carries PR 293 the status is read first by
                # `_plain_value.plain_json`, the one copy rule, which meets a circle as a value nested past
                # the structural budget; at the D4 head 7cc8fa0b the JCS copy named the circle.
                self.assertIn("nests deeper than 64 levels", str(ctx.exception))

    def test_a_status_nested_past_the_limit_is_refused_at_every_depth(self):
        """The depth at which a status stops signing depends on how deep the caller's stack is, so it
        is searched here, from one helper frame, and the eight depths past it must each be the
        ValueError. At 93b3c6f5 they were RecursionError.

        Since the 6.2.0 chain carries PR 293 the status is read first by `_plain_value.plain_json`, the
        one copy rule, whose structural budget (64 levels) ends the signed depths long before the
        recursion limit: the deepest signed status is at most 64 deep now, where the D4 head 7cc8fa0b
        signed several hundred levels."""
        for art in ("list", "dict"):
            def ergebnis(tiefe, art=art):
                try:
                    issue_sd_jwt(self.basis, self.signer, root_b64=ROOT_B64,
                                 status={"status_list": _geschachtelt(tiefe, art)})
                    return "signed"
                except ValueError:
                    return "ValueError"
                except RecursionError:
                    return "RecursionError"
            unten, oben = 1, 3000                   # unten signs, oben does not
            while oben - unten > 1:
                mitte = (unten + oben) // 2
                if ergebnis(mitte) == "signed":
                    unten = mitte
                else:
                    oben = mitte
            with self.subTest(art=art, tiefste_signierte=unten):
                self.assertGreater(unten, 1)        # a nested status still signs; the case is not vacuous
                self.assertLessEqual(unten, 64)     # the one copy rule's structural budget
                for tiefe in list(range(unten + 1, unten + 9)) + [5000]:
                    self.assertEqual(ergebnis(tiefe), "ValueError", tiefe)


class TestTheBudgetJudgesWhatIsSerialized(_Basis):
    """Item 3. `canonicalize_statement` applies the structural budget before the copy, and the budget
    read a dict through `items()` and a list through `__iter__`. Measured at 93b3c6f5 and on main
    1e95b197: a dict subclass whose `items`, `values` and `keys` show nothing hid 500 nested lists
    from the depth bound of 64 (1036 bytes written) and 2000 raised a raw RecursionError; a list
    subclass that iterates as empty hid them too and was written as []. The budget now reads what a
    container holds. The shape guard of the same function asked `__contains__`."""

    def test_depth_hidden_from_the_budget_is_refused(self):
        for name, huelle in (("dict: items, values, keys show nothing", lambda w: _ZeigtNichts({"deep": w})),
                             ("list: iterates as empty", lambda w: _ListeZeigtNichts([w]))):
            for tiefe in (500, 2000):
                with self.subTest(huelle=name, tiefe=tiefe):
                    with self.assertRaises(BundleFormatError) as ctx:
                        canonical.canonicalize_statement({"_type": "t", "predicate": huelle(_geschachtelt(tiefe))})
                    self.assertIn("too deep", str(ctx.exception))

    def test_the_shape_guard_reads_the_stored_keys(self):
        stmt = _EnthaeltLuegt({"predicate": {"x": 1}})
        self.assertIn("_type", stmt)                             # the premise: the lie works on `in`
        with self.assertRaises(ProofBundleError) as ctx:
            canonical.canonicalize_statement(stmt, require_statement_shape=True)
        self.assertIn("_type", str(ctx.exception))

    def test_control_budget_verdicts_on_plain_input_are_unchanged(self):
        """Every axis of the budget on plain input, with a small budget so the case stays cheap: each
        verdict has the class it had before (the same cases pass at 93b3c6f5)."""
        from proofbundle._strict_json import enforce_structural_budget  # noqa: PLC0415
        from proofbundle.budget import BudgetExceeded, VerificationBudget  # noqa: PLC0415
        klein = VerificationBudget(json_nodes=10, json_depth=4, string_len=5, int_bits=8)
        for name, wert, erwartet in (
                ("depth 4", _geschachtelt(3), None),
                ("depth 5", _geschachtelt(4), (BundleFormatError, "too deep")),
                ("depth 5 through dicts", _geschachtelt(4, "dict"), (BundleFormatError, "too deep")),
                ("10 nodes", list(range(10)), None),
                ("11 nodes", list(range(11)), (BudgetExceeded, "json_nodes")),
                ("11 nodes in a tuple", tuple(range(11)), (BudgetExceeded, "json_nodes")),
                ("11 keys", {str(i): i for i in range(11)}, (BudgetExceeded, "json_nodes")),
                ("a set", {1, 2}, None),
                ("a 6-character string", "abcdef", (BudgetExceeded, "string_len")),
                ("a 6-character key", {"abcdef": 1}, (BudgetExceeded, "string_len")),
                ("6 bytes", b"abcdef", (BudgetExceeded, "string_len")),
                ("a 9-bit integer", 2 ** 8, (BudgetExceeded, "int_bits")),
                ("an 8-bit integer", 2 ** 8 - 1, None),
                ("true, a float, null", [True, 1.5, None], None),
                ("a lone surrogate", "\ud800", (BundleFormatError, "surrogate")),
                ("an object", object(), (BundleFormatError, "not a JSON value"))):
            with self.subTest(fall=name):
                if erwartet is None:
                    enforce_structural_budget(wert, budget=klein)
                    continue
                klasse, text = erwartet
                with self.assertRaises(ProofBundleError) as ctx:
                    enforce_structural_budget(wert, budget=klein)
                self.assertIs(type(ctx.exception), klasse)
                self.assertIn(text, str(ctx.exception))


def _zufallswert(rng, tiefe: int, mit_floats: bool):
    """A plain JSON value, the lens's generator in a bounded form: strings from a small alphabet of
    awkward characters, integers in the safe range, floats at the edges of their formatting."""
    zeichen = ["a", "B", "\u00e9", "e\u0301", "\U0001F600", "\uffff", "\u007f", " ", "\"", "\\",
               "\x00", "\x1f", "\ud7ff", "", "z"]
    art = rng.randint(0, 9 if tiefe < 5 else 5)
    if art == 0:
        return rng.choice([True, False, None])
    if art == 1:
        return rng.randint(-2 ** 53 + 1, 2 ** 53 - 1)
    if art == 2:
        if mit_floats:
            return rng.choice([0.0, -0.0, 1e21, 1e-7, 5e-324, 1.7976931348623157e308, 0.1, 123.456])
        return rng.randint(-9, 9)
    if art in (3, 4, 5):
        return "".join(rng.choice(zeichen) for _ in range(rng.randint(0, 4)))
    if art in (6, 7):
        return [_zufallswert(rng, tiefe + 1, mit_floats) for _ in range(rng.randint(0, 3))]
    return {"".join(rng.choice(zeichen) for _ in range(rng.randint(0, 4))):
            _zufallswert(rng, tiefe + 1, mit_floats) for _ in range(rng.randint(0, 3))}


class TestPlainInputIsWrittenAsBefore(_Basis):
    """The controls of round 7. A plain value is copied as itself and written with the bytes the two
    serializers write for it, through each of the three readers of the copy; the same cases pass at
    93b3c6f5, so its output for them is unchanged. `TestTheSubjectIsJudgedByTheOwnershipRule
    .test_control_a_subject_that_is_not_ours_makes_no_claim` holds the package's own export paths."""

    def test_control_random_plain_values_give_the_serializers_bytes(self):
        import random  # noqa: PLC0415

        import rfc8785  # noqa: PLC0415
        from proofbundle.evalclaim import _jcs_bytes  # noqa: PLC0415
        rng = random.Random(20260927)
        for nummer in range(300):
            wert = {"provenance": _zufallswert(rng, 0, mit_floats=nummer % 2 == 0)}
            with self.subTest(nummer=nummer):
                erwartet = rfc8785.dumps(wert)
                kopie = canonical._plain_for_jcs(wert, ValueError)
                self.assertEqual(kopie, wert)
                self.assertEqual(json.dumps(kopie), json.dumps(wert))
                self.assertEqual(canonical.canonicalize_statement(wert), erwartet)
                self.assertEqual(_jcs_bytes(wert), erwartet)
                status = {"status_list": wert}
                self.assertEqual(_immer_offen(issue_sd_jwt(self.basis, self.signer, root_b64=ROOT_B64,
                                                           status=status))["status"], status)

    def test_control_canonicalize_writes_to_within_two_levels_of_the_serializer(self):
        """The limit the CHANGELOG states: called from the same place, the JCS copy refuses by type
        at most the two deepest levels that `rfc8785.dumps` writes. Measured on Python 3.10.12.

        Every call goes through `ergebnis`, from `tiefste`, because the depth that is written moves
        with the caller's own stack: the first form of this case checked the next level from one
        frame higher and found it written.

        Since the 6.2.0 chain carries PR 293 `canonicalize` reads the claim first through
        `_plain_value.plain_json`, the one copy rule, which refuses past the structural budget of 64
        levels; so the copy is measured here through the writer that uses it alone, and `canonicalize`
        through the budget. At the D4 head 7cc8fa0b `canonicalize` itself reached within two levels."""
        import rfc8785  # noqa: PLC0415
        from proofbundle.evalclaim import _jcs_bytes, _reject_non_jcs, canonicalize  # noqa: PLC0415

        def kopie_geschrieben(obj):
            kopie = canonical._plain_for_jcs(obj, EvalClaimError)
            _reject_non_jcs(kopie)                  # the walk `canonicalize` runs before the serializer
            return _jcs_bytes(kopie)

        def ergebnis(schreibe, tiefe, art):
            try:
                schreibe({"provenance": _geschachtelt(tiefe, art)})
                return "written"
            except EvalClaimError:
                return "EvalClaimError"
            except RecursionError:
                return "RecursionError"

        def tiefste(schreibe, art):
            unten, oben = 0, 3000
            while oben - unten > 1:
                mitte = (unten + oben) // 2
                if ergebnis(schreibe, mitte, art) == "written":
                    unten = mitte
                else:
                    oben = mitte
            return unten, ergebnis(schreibe, unten + 1, art)
        # UNDER A TRACER THE DISTANCE IS NOT THE LIBRARY'S. Measured 2026-09-28 on Python 3.12 under
        # coverage 7.15.1 (`sys.gettrace()` is its CTracer): the distance was 3, in CI run 36414971006
        # and locally; without a tracer it is within two on 3.10 to 3.14. The tracer moves the depth at
        # which the stack gives out, so the two-level claim is measured only where no tracer runs, and
        # said so where one does. The other assertions of this case hold under a tracer too.
        unter_tracer = sys.gettrace() is not None
        for art in ("list", "dict"):
            with self.subTest(art=art):
                (serialisierer, _), (kopie, danach) = (tiefste(rfc8785.dumps, art),
                                                       tiefste(kopie_geschrieben, art))
                self.assertGreater(kopie, 64)
                self.assertEqual(danach, "EvalClaimError")
            with self.subTest(art=art, abstand="to the serializer"):
                if unter_tracer:
                    self.skipTest("NOT MEASURED under a tracer (coverage): it moves the depth at which "
                                  f"the stack gives out; measured distance {serialisierer - kopie}")
                self.assertIn(serialisierer - kopie, (0, 1, 2))
            with self.subTest(art=art):
                kanonisch, danach = tiefste(canonicalize, art)
                self.assertLessEqual(kanonisch, 64)
                self.assertEqual(danach, "EvalClaimError")


# ---- round 8: lens run 6 at c8205c18 ------------------------------------------------------------------

_AUFRUFE: list = []


def _merke(name: str) -> None:
    _AUFRUFE.append(name)


class _MetaProtokoll(type):
    """A metaclass whose hooks record a call: the type's name, its equality with another type, and the
    two checks a metaclass can take over. `issubclass(typ, dict)` must not run any of them."""

    @property
    def __name__(cls):  # type: ignore[override]
        _merke("metaclass __name__")
        return type.__dict__["__name__"].__get__(cls)

    def __eq__(cls, other):
        _merke("metaclass __eq__")
        return type.__eq__(cls, other)

    __hash__ = type.__hash__

    def __instancecheck__(cls, obj):
        _merke("metaclass __instancecheck__")
        return type.__instancecheck__(cls, obj)

    def __subclasscheck__(cls, sub):
        _merke("metaclass __subclasscheck__")
        return type.__subclasscheck__(cls, sub)


#: Every method a reader could call on a caller's object. The recording classes below answer each as
#: their base type does, so an honest reading is undisturbed, and record it, so any reading is seen.
_LESEWEGE = ("__iter__", "__len__", "__contains__", "__getitem__", "__eq__", "__ne__", "__lt__",
             "__le__", "__gt__", "__ge__", "__hash__", "__bool__", "__repr__", "__str__",
             "__format__", "__int__", "__index__", "__float__", "__abs__", "__reversed__",
             "__length_hint__", "__copy__", "__deepcopy__", "__reduce_ex__", "__round__", "__trunc__",
             "__neg__", "__add__", "__mul__", "__mod__", "items", "keys", "values", "get", "encode",
             "lower", "upper", "strip", "split", "startswith", "copy", "bit_length", "to_bytes",
             "count", "index", "decode", "hex")


def _protokolliert(basis: type) -> type:
    """A subclass of `basis` that records every reading (its methods, `__getattribute__`, a
    `__class__` property, and the metaclass hooks) and otherwise behaves as `basis`."""
    ns: dict = {}
    for methode in _LESEWEGE:
        echt = getattr(basis, methode, None)
        if echt is None:
            continue

        def aufzeichnen(self, *args, _methode=methode, _echt=echt, **kwargs):
            _merke(_methode)
            return _echt(self, *args, **kwargs)
        ns[methode] = aufzeichnen
    if basis is bytes:
        # `bytes()` of a bytes subclass calls its `__bytes__`; bytes itself has none on 3.10.
        ns["__bytes__"] = lambda self: (_merke("__bytes__"), bytes.__getitem__(self, slice(None)))[1]

    def attribut(self, name, _basis=basis):
        _merke("attribute " + name)
        return _basis.__getattribute__(self, name)
    ns["__getattribute__"] = attribut
    ns["__class__"] = property(lambda self: (_merke("__class__"), type(self))[1])
    return _MetaProtokoll("Protokoll" + basis.__qualname__.title(), (basis,), ns)


P = {basis: _protokolliert(basis) for basis in (dict, list, tuple, str, int, float, frozenset, bytes)}


class _BehauptetDict(metaclass=_MetaProtokoll):
    """No JSON type, but its `__class__` says dict, and every reading of it is recorded."""

    @property
    def __class__(self):  # type: ignore[override]
        _merke("__class__")
        return dict

    def keys(self):
        _merke("keys")
        return ["idx"]

    def __getitem__(self, schluessel):
        _merke("__getitem__")
        return 5

    def __iter__(self):
        _merke("__iter__")
        return iter(["idx"])

    def __len__(self):
        _merke("__len__")
        return 1


class _BehauptetStr(metaclass=_MetaProtokoll):
    @property
    def __class__(self):  # type: ignore[override]
        _merke("__class__")
        return str

    def __str__(self):
        _merke("__str__")
        return "0.80"


class _BehauptetInt(metaclass=_MetaProtokoll):
    @property
    def __class__(self):  # type: ignore[override]
        _merke("__class__")
        return int

    def __int__(self):
        _merke("__int__")
        return 500

    __index__ = __int__


class _VersteckMeta(_MetaProtokoll):
    """`mro()` leaves the base out, so `issubclass(cls, dict)` is False, while the type keeps the C
    layout and flags of a dict, which `json.dumps` tests (PyDict_Check)."""

    def mro(cls):
        return [cls, object]


_VersteckterDict = _VersteckMeta("_VersteckterDict", (dict,), {
    "items": lambda self: (_merke("items"), [("fremd", 99)])[1],
    "keys": lambda self: (_merke("keys"), ["fremd"])[1],
    "__iter__": lambda self: (_merke("__iter__"), iter(["fremd"]))[1],
    "__contains__": lambda self, k: (_merke("__contains__"), True)[1],
})


def _versteckt(inhalt: dict):
    """A `_VersteckterDict` that stores `inhalt`. `dict.__setitem__` refuses the type (its own type
    check walks the MRO), so the items are stored through the C API, as the lens did."""
    wert = _VersteckterDict()
    setze = ctypes.pythonapi.PyDict_SetItem
    setze.argtypes = [ctypes.py_object, ctypes.py_object, ctypes.py_object]
    setze.restype = ctypes.c_int
    for schluessel, eintrag in inhalt.items():
        if setze(wert, schluessel, eintrag) != 0:
            raise AssertionError("PyDict_SetItem failed")
    return wert


def _gespeichert(wert) -> list:
    """What a `_VersteckterDict` stores, read through the C API (the premise of the F5 cases)."""
    lies = ctypes.pythonapi.PyDict_Items
    lies.argtypes = [ctypes.py_object]
    lies.restype = ctypes.py_object
    return lies(wert)


class _Ergebnis:
    checks = ()


class TestTheCopyRunsNoCodeOfTheCaller(_Basis):
    """THE PROOF of round 8. Lens run 6 at c8205c18 found caller code running inside the plain copy
    (its `isinstance` read `__class__`) and after it (rfc8785's `int()`, `float()` and `list()`,
    json's `items()`, the claim rule's `len`, `<=`, `set()`, `abs` and truthiness, the exporters'
    `get`, `==` and `__contains__`). Every public entry now takes one plain copy of every JSON-shaped
    argument first. Here each entry gets values whose every reading is recorded: subclasses of each
    JSON type holding honest values, the non-JSON types the copy refuses, objects whose `__class__`
    claims a JSON type, and a dict whose metaclass hides `dict` from its MRO. Every call must return
    or raise the entry's typed refusal, and not one recorded method may have run. Red at c8205c18."""

    def _pruefe(self, name, aufbau, aufruf, erlaubt):
        with self.subTest(weg=name):
            argumente = aufbau()
            _AUFRUFE.clear()
            try:
                aufruf(argumente)
            except erlaubt:
                pass
            finally:
                gesehen = list(_AUFRUFE)
                _AUFRUFE.clear()
            self.assertEqual(gesehen, [], f"{name}: the caller's code ran")

    def _anspruchs_wege(self):
        from proofbundle.errors import VerificationResult  # noqa: PLC0415
        from proofbundle.evalclaim import _jcs_bytes, canonicalize  # noqa: PLC0415
        ergebnis = VerificationResult()
        ergebnis.add("ed25519-signature", True, "")
        s = self.signer
        wege = {"canonicalize": (canonicalize, (EvalClaimError,)),
                "_jcs_bytes": (_jcs_bytes, (EvalClaimError,)),
                "emit_eval_receipt": (lambda c: emit_eval_receipt(c, s), (EvalClaimError,)),
                "svr_properties": (lambda c: intoto.svr_properties(ergebnis, c), (BundleFormatError,))}
        for name, erzeuge in _produzenten().items():
            wege[name] = (lambda c, e=erzeuge: e(c, s), (BundleFormatError,))
        return wege

    def _anspruchs_werte(self):
        b = self.basis
        return {
            "provenance of recording values": lambda: dict(b, provenance=P[dict]({
                "k": P[int](5), "s": P[str]("x"), "l": P[list]([P[int](1), P[tuple]((P[str]("a"),))]),
                "f": P[float](1.5), "d": P[dict]({"e": None, "t": True})})),
            "n": lambda: dict(b, n=P[int](500)),
            "suite": lambda: dict(b, suite=P[str]("safety-refusal")),
            "threshold": lambda: dict(b, threshold=P[str]("0.80")),
            "model_id_commit": lambda: dict(b, model_id_commit=P[str](b["model_id_commit"])),
            "passed as a recording int": lambda: dict(b, passed=P[int](1)),
            "ci95 list": lambda: dict(b, ci95=P[list]([P[str]("0.90"), P[str]("0.94")])),
            "ci95 tuple": lambda: dict(b, ci95=P[tuple]((P[str]("0.90"), P[str]("0.94")))),
            "the whole claim": lambda: P[dict](b),
            "a key": lambda: dict(b, provenance={P[str]("k"): 1}),
            "a frozenset": lambda: dict(b, provenance={"k": P[frozenset]({"a"})}),
            "bytes": lambda: dict(b, provenance={"k": P[bytes](b"x")}),
            "claims dict": lambda: dict(b, provenance={"k": _BehauptetDict()}),
            "threshold claims str": lambda: dict(b, threshold=_BehauptetStr()),
            "n claims int": lambda: dict(b, n=_BehauptetInt()),
            "hides dict": lambda: dict(b, provenance={"k": _versteckt({"a": 1})}),
            "the whole claim claims dict": lambda: _BehauptetDict(),
            "the whole claim hides dict": lambda: _versteckt(dict(b)),
        }

    def test_no_entry_that_takes_a_claim_runs_the_callers_code(self):
        for weg, (aufruf, erlaubt) in self._anspruchs_wege().items():
            for wert, aufbau in self._anspruchs_werte().items():
                self._pruefe(f"{weg}, {wert}", aufbau, aufruf, erlaubt)

    def test_no_statement_entry_runs_the_callers_code(self):
        erlaubt = (ProofBundleError, ValueError)
        voll = {"_type": "t", "subject": [], "predicateType": "p"}
        werte = {
            "predicate of recording values": lambda: dict(voll, predicate=P[dict]({
                "k": P[int](5), "f": P[float](1.5), "l": P[list]([P[tuple]((P[str]("a"),))])})),
            "the whole statement": lambda: P[dict](dict(voll, predicate={})),
            "a frozenset": lambda: dict(voll, predicate={"k": P[frozenset]({"a"})}),
            "claims dict": lambda: dict(voll, predicate=_BehauptetDict()),
            "hides dict": lambda: dict(voll, predicate=_versteckt({"a": 1})),
            "the whole statement claims dict": lambda: _BehauptetDict(),
            "recording bytes": lambda: P[bytes](b"{}"),
        }
        wege = {"canonicalize_statement": canonical.canonicalize_statement,
                "canonicalize_statement, shape guard":
                    lambda st: canonical.canonicalize_statement(st, require_statement_shape=True),
                "statement_content_root": canonical.statement_content_root}
        for weg, aufruf in wege.items():
            for wert, aufbau in werte.items():
                self._pruefe(f"{weg}, {wert}", aufbau, aufruf, erlaubt)

    def test_no_argument_of_issue_sd_jwt_runs_the_callers_code(self):
        werte = {
            "status": lambda: {"status": P[dict]({"status_list": P[dict]({
                "idx": P[int](7), "uri": P[str]("u")}), "x": P[list]([P[float](1.5)])})},
            "status hides dict": lambda: {"status": {"status_list": {"idx": 7}, "x": _versteckt({"a": 1})}},
            "status claims dict": lambda: {"status": _BehauptetDict()},
            "ci95": lambda: {"ci95": P[list]([P[str]("0.90"), P[str]("0.94")])},
            "ci95 tuple": lambda: {"ci95": P[tuple]((P[str]("0.90"), P[str]("0.94")))},
            "ci95 item claims str": lambda: {"ci95": [_BehauptetStr(), "0.94"]},
            "exact_score": lambda: {"exact_score": P[str]("0.92")},
            "exact_score claims str": lambda: {"exact_score": _BehauptetStr()},
            "vct": lambda: {"vct": P[str]("https://example.org/vct")},
            "root_b64": lambda: {"root_b64": P[str](ROOT_B64)},
            "root_b64 claims str": lambda: {"root_b64": _BehauptetStr()},
            "openings": lambda: {"model_id_opening": P[tuple]((P[str]("m"), P[str]("00"))),
                                 "dataset_id_opening": P[list]([P[str]("d"), P[str]("00")])},
            "an opening that is a frozenset": lambda: {"model_id_opening": P[frozenset]({"a"})},
        }
        for wert, aufbau in werte.items():
            self._pruefe(f"issue_sd_jwt, {wert}", aufbau,
                         lambda kw: issue_sd_jwt(self.basis, self.signer, **dict({"root_b64": ROOT_B64}, **kw)),
                         (BundleFormatError, ValueError))

    def test_no_other_argument_of_the_exporters_runs_the_callers_code(self):
        b, s = self.basis, self.signer
        jcs, alt = intoto.CONTENT_ROOT_ALG, intoto.LEGACY_CONTENT_ROOT_ALG

        def harness():
            return P[dict]({"name": P[str]("h"), "v": P[list]([P[int](1)])})
        faelle = {
            "to_intoto_statement": (lambda: dict(root_b64=P[str](ROOT_B64), harness=harness()),
                                    lambda kw: intoto.to_intoto_statement(b, **kw)),
            "to_test_result_statement": (
                lambda: dict(subject_digest=P[dict]({"sha256": P[str]("0" * 64)}), root_b64=P[str](ROOT_B64),
                             harness=harness(), url=P[str]("https://x"), content_root_alg=P[str](jcs)),
                lambda kw: intoto.to_test_result_statement(b, **kw)),
            "to_eval_result_predicate": (
                lambda: dict(root_b64=P[str](ROOT_B64), harness=harness(),
                             anchors=P[list]([P[dict]({"a": P[int](1)})]), subject_profile=P[str]("receipt")),
                lambda kw: intoto.to_eval_result_predicate(b, **kw)),
            "to_eval_result_statement": (
                lambda: dict(subject=P[list]([P[dict]({"name": P[str]("n"), "digest": P[dict](
                    {"sha256": P[str]("0" * 64)})})]), content_root_alg=P[str](jcs), harness=harness()),
                lambda kw: intoto.to_eval_result_statement(b, **kw)),
            "resolve_subject receipt": (
                lambda: dict(profil=P[str]("receipt"), root_b64=P[str](ROOT_B64)),
                lambda kw: intoto.resolve_subject(kw.pop("profil"), b, **kw)),
            "resolve_subject release-gate": (
                lambda: dict(profil=P[str]("release-gate"), subject_name=P[str]("m"),
                             subject_sha256=P[str]("AB" * 32)),
                lambda kw: intoto.resolve_subject(kw.pop("profil"), b, **kw)),
            # Round 9: a flag must be True or False, so these recording ints are refused, and the
            # proof is that the refusal reads them without running them. The refusal is PR 291's
            # SwitchTypeError since the 6.2.0 chain carries it (`_membership.require_switch`).
            "svr_properties flags": (
                lambda: dict(prereg_verified=P[int](1), anchor_verified=P[int](0)),
                lambda kw: intoto.svr_properties(_Ergebnis(), b, **kw)),
            "export_svr_dsse flags as recording ints": (
                lambda: dict(buendel=emit_eval_receipt(b, s), prereg_verified=P[int](1),
                             anchor_verified=P[int](0)),
                lambda kw: intoto.export_svr_dsse(kw.pop("buendel"), s, **kw)),
            "harness claims dict": (lambda: dict(harness=_BehauptetDict()),
                                    lambda kw: intoto.to_intoto_statement(b, **kw)),
            "harness hides dict": (lambda: dict(harness=_versteckt({"a": 1}), content_root_alg=alt),
                                   lambda kw: intoto.export_intoto_dsse(b, s, **kw)),
        }
        for alg in (jcs, alt):
            faelle[f"export_intoto_dsse {alg}"] = (
                lambda alg=alg: dict(root_b64=P[str](ROOT_B64), harness=harness(), url=P[str]("https://x"),
                                     keyid=P[str]("k"), content_root_alg=P[str](alg)),
                lambda kw: intoto.export_intoto_dsse(b, s, **kw))
            faelle[f"export_eval_result_dsse receipt {alg}"] = (
                lambda alg=alg: dict(subject_profile=P[str]("receipt"), root_b64=P[str](ROOT_B64),
                                     harness=harness(), anchors=P[list]([P[str]("a")]), keyid=P[str]("k"),
                                     content_root_alg=P[str](alg)),
                lambda kw: intoto.export_eval_result_dsse(b, s, **kw))
            faelle[f"export_eval_result_dsse release-gate {alg}"] = (
                lambda alg=alg: dict(subject_profile=P[str]("release-gate"), subject_name=P[str]("m"),
                                     subject_sha256=P[str]("ab" * 32), content_root_alg=P[str](alg)),
                lambda kw: intoto.export_eval_result_dsse(b, s, **kw))
            faelle[f"export_svr_dsse {alg}"] = (
                lambda alg=alg: dict(buendel=emit_eval_receipt(b, s), time_created=P[str]("2026-01-01T00:00:00Z"),
                                     policy=P[dict]({"uri": P[str]("u")}), prereg_verified=False,
                                     anchor_verified=False, keyid=P[str]("k"), content_root_alg=P[str](alg)),
                lambda kw: intoto.export_svr_dsse(kw.pop("buendel"), s, **kw))
        from proofbundle.errors import SwitchTypeError  # noqa: PLC0415
        for name, (aufbau, aufruf) in faelle.items():
            self._pruefe(name, aufbau, aufruf,
                         (BundleFormatError, SwitchTypeError) if "flags" in name else (BundleFormatError,))

    def test_control_a_recording_subclass_is_written_as_the_plain_value(self):
        """Green at c8205c18 too: the recording classes answer honestly, so every entry writes for them
        the bytes it writes for the plain values they hold. This keeps the proof above from passing
        over entries that refuse everything.

        The numbers are plain here since the 6.2.0 chain carries PR 293: a subclass of int or float is
        refused by the one copy rule (`_plain_value.plain_json`, and the JCS copy agrees), never
        written as the value it holds; the last lines hold that. At the D4 head 7cc8fa0b the recording
        ints were written as the ints they hold."""
        from proofbundle.evalclaim import canonicalize  # noqa: PLC0415
        b, s = self.basis, self.signer
        roh = {"k": 5, "s": "x", "l": [1, ["a"]], "d": {"e": None, "t": True}}
        aufgezeichnet = P[dict]({"k": 5, "s": P[str]("x"),
                                 "l": P[list]([1, P[tuple]((P[str]("a"),))]),
                                 "d": P[dict]({"e": None, "t": True})})
        self.assertEqual(canonicalize(dict(b, provenance=aufgezeichnet)), canonicalize(dict(b, provenance=roh)))
        self.assertEqual(emit_eval_receipt(dict(b, provenance=aufgezeichnet), s),
                         emit_eval_receipt(dict(b, provenance=roh), s))
        self.assertEqual(intoto.export_intoto_dsse(b, s, harness=aufgezeichnet),
                         intoto.export_intoto_dsse(b, s, harness=roh))
        status = {"status_list": {"idx": 7, "uri": "u"}, "x": roh}
        self.assertEqual(_immer_offen(issue_sd_jwt(b, s, root_b64=ROOT_B64, status=P[dict](
            {"status_list": P[dict]({"idx": 7, "uri": P[str]("u")}), "x": aufgezeichnet})))["status"],
            status)
        self.assertEqual(canonical.canonicalize_statement({"predicate": aufgezeichnet}),
                         canonical.canonicalize_statement({"predicate": roh}))
        for aufruf in (lambda z: canonicalize(dict(b, provenance={"k": z})),
                       lambda z: emit_eval_receipt(dict(b, n=z), s)):
            with self.assertRaises(EvalClaimError) as ctx:
                aufruf(P[int](5))
            self.assertIn("a subclass of int; a number must be an exact int or float", str(ctx.exception))


def _menge_die_spaeter_liste_sagt(tiefe: int) -> type:
    """F1 of lens run 6: an empty frozenset subclass whose first six `__class__` reads (the copy's at
    c8205c18) name its own type and every later one says `list`, and whose `__iter__` shows nested
    lists. rfc8785 reads `isinstance` and then `list()` of it."""
    class Menge(frozenset):
        gelesen = 0

        @property
        def __class__(self):  # type: ignore[override]
            Menge.gelesen += 1
            return Menge if Menge.gelesen <= 6 else list

        def __iter__(self):
            return iter([_geschachtelt(tiefe)])
    return Menge


class TestAValueOfNoJsonTypeIsRefusedNotPassedOn(_Basis):
    """F1 and F2 of lens run 6 at c8205c18. The copy passed every value that is not a JSON type
    through unchanged, after asking `isinstance` about it, which runs the value's `__class__`."""

    def test_f1_an_empty_frozenset_that_later_claims_list_is_refused(self):
        """At c8205c18 `canonicalize_statement` wrote 1035 bytes for 500 levels and raised a raw
        RecursionError for 3000; at 93b3c6f5 and on main it was a BundleFormatError."""
        for tiefe in (500, 3000):
            with self.subTest(tiefe=tiefe):
                Menge = _menge_die_spaeter_liste_sagt(tiefe)
                with self.assertRaises((ProofBundleError, ValueError)):
                    canonical.canonicalize_statement({"_type": "t", "predicate": {"m": Menge()}})
                self.assertEqual(Menge.gelesen, 0, "the value's __class__ ran")

    def test_f2_a_class_read_cannot_deepen_a_sibling_after_the_budget(self):
        """At c8205c18 the budget judged the statement, then the copy read `__class__`, which put 500
        nested lists into a sibling the copy had not reached, and the serializer wrote them past the
        depth bound of 64 (1074 bytes)."""
        ziel: list = []

        class Umbau(bytes):
            gelesen = 0

            @property
            def __class__(self):  # type: ignore[override]
                Umbau.gelesen += 1
                if not ziel:
                    ziel.append(_geschachtelt(500))
                return int if sys._getframe(1).f_code.co_name == "dump" else Umbau

        with self.assertRaises((ProofBundleError, ValueError)):
            canonical.canonicalize_statement({"_type": "t", "predicate": {"a": Umbau(b"5"), "z": ziel}})
        self.assertEqual((Umbau.gelesen, ziel), (0, []))

    def test_f2_a_recursion_error_of_the_caller_is_not_called_nesting(self):
        """The comment on the copy's `except RecursionError` said the copy runs no code of the
        caller. At c8205c18 a `__class__` that raised RecursionError was reported by `issue_sd_jwt`
        and by every producer as "the value nests too deep to serialize"."""
        class KlasseRekursion:
            gelesen = 0

            @property
            def __class__(self):  # type: ignore[override]
                KlasseRekursion.gelesen += 1
                raise RecursionError("raised by the caller's __class__")

        with self.assertRaises(ValueError) as ctx:
            issue_sd_jwt(self.basis, self.signer, root_b64=ROOT_B64,
                         status={"status_list": {"idx": 7, "uri": "u"}, "x": KlasseRekursion()})
        self.assertNotIn("nests too deep", str(ctx.exception))
        for name, erzeuge in _produzenten().items():
            with self.subTest(produzent=name):
                with self.assertRaises(BundleFormatError) as ctx:
                    erzeuge(dict(self.basis, provenance={"x": KlasseRekursion()}), self.signer)
                self.assertNotIn("nests too deep", str(ctx.exception))
        self.assertEqual(KlasseRekursion.gelesen, 0)


class _AbsWirft(int):
    def __abs__(self):
        raise KeyError("abs")


class _IntWirft(int):
    def __int__(self):
        raise KeyError("int")


class _VergleichWirft(int):
    def __le__(self, other):
        raise KeyError("le")

    def __ge__(self, other):
        raise KeyError("ge")

    def __lt__(self, other):
        raise KeyError("lt")

    def __gt__(self, other):
        raise KeyError("gt")


class _LaengeWirft(list):
    def __len__(self):
        raise KeyError("len")

    def __iter__(self):
        raise KeyError("iter")


class _IterWirft(dict):
    def __iter__(self):
        raise KeyError("iter")


class _WahrheitWirft(str):
    def __bool__(self):
        raise KeyError("bool")


class _GleichWirft(str):
    def __eq__(self, other):
        raise KeyError("eq")

    def __ne__(self, other):
        raise KeyError("ne")

    __hash__ = str.__hash__


class _KlasseWirft:
    @property
    def __class__(self):  # type: ignore[override]
        raise KeyError("__class__")


class TestNoMethodOfTheCallerRaisesThroughAnEntry(_Basis):
    """F3 of lens run 6 at c8205c18: raw exceptions from methods the caller overrides. Each value
    below holds an honest JSON value, or is no JSON value; each is written as what it holds or is
    the entry's typed refusal now."""

    def test_f3_the_claim_rule_and_the_serializer_read_the_stored_value(self):
        from proofbundle.evalclaim import canonicalize  # noqa: PLC0415
        s = self.signer

        def gelesen(claim):
            return decode_eval_claim(emit_eval_receipt(claim, s))
        import rfc8785  # noqa: PLC0415
        # A number subclass is the entry's typed refusal since the 6.2.0 chain carries PR 293 (the one
        # copy rule refuses it, and the JCS copy agrees); at the D4 head 7cc8fa0b each was written as the
        # number it holds. None of its methods runs either way.
        verweigert = (
            ("canonicalize, provenance abs raises", lambda: canonicalize(
                dict(self.basis, provenance={"k": _AbsWirft(5)})), EvalClaimError),
            ("emit, n abs raises", lambda: emit_eval_receipt(dict(self.basis, n=_AbsWirft(5)), s), EvalClaimError),
            ("canonicalize_statement, int() raises", lambda: canonical.canonicalize_statement(
                {"_type": "t", "predicate": {"k": _IntWirft(5)}}), rfc8785.CanonicalizationError),
            ("emit, n comparisons raise", lambda: emit_eval_receipt(dict(self.basis, n=_VergleichWirft(500)), s),
             EvalClaimError),
        )
        for name, lauf, fehler in verweigert:
            with self.subTest(fall=name):
                with self.assertRaises(fehler) as ctx:
                    lauf()
                self.assertIn("a number must be an exact int or float", str(ctx.exception))
        faelle = (
            ("emit, ci95 len and iter raise", lambda: gelesen(dict(
                self.basis, ci95=_LaengeWirft(["0.1", "0.2"])))["ci95"], ["0.1", "0.2"]),
            ("issue_sd_jwt, ci95 len and iter raise", lambda: _offenlegungen(issue_sd_jwt(
                self.basis, s, root_b64=ROOT_B64, ci95=_LaengeWirft(["0.1", "0.2"])))["ci95"], ["0.1", "0.2"]),
            ("emit, samples iteration raises", lambda: gelesen(dict(self.basis, samples=_IterWirft(
                root_b64=ROOT_B64, n=500, leaf_alg="sha256-rfc6962-sdjwt-v1")))["samples"]["n"], 500),
            ("emit, suite truthiness raises", lambda: gelesen(dict(
                self.basis, suite=_WahrheitWirft("safety-refusal")))["suite"], "safety-refusal"),
            ("to_eval_result_predicate, == raises", lambda: intoto.to_eval_result_predicate(dict(
                self.basis, suite=_GleichWirft("safety-refusal")))["suite"]["name"], "safety-refusal"),
        )
        for name, lauf, erwartet in faelle:
            with self.subTest(fall=name):
                self.assertEqual(lauf(), erwartet)

    def test_f3_issue_sd_jwt_refuses_its_arguments_by_type(self):
        """At c8205c18: a status holding an object whose `__class__` raises gave that KeyError, and a
        `vct` or `root_b64` that is no JSON value went into `json.dumps` and gave its TypeError."""
        for name, kwargs in (("status holds a raising __class__",
                              {"status": {"status_list": {"idx": 7, "uri": "u"}, "x": _KlasseWirft()}}),
                             ("vct is an object", {"vct": object()}),
                             ("root_b64 is an object", {"root_b64": object()})):
            with self.subTest(fall=name):
                with self.assertRaises(ValueError):
                    issue_sd_jwt(self.basis, self.signer, **dict({"root_b64": ROOT_B64}, **kwargs))


class _IntAnders(int):
    def __int__(self):
        return -1


class _FloatAnders(float):
    def __float__(self):
        return 2.0


class TestANumberIsWrittenAsWhatItHolds(_Basis):
    """F4 of lens run 6 at c8205c18: int and float subclasses passed the copy unchanged, the walks
    judged the stored value, and rfc8785 wrote the value of `int()` and `float()`. Round 8 wrote the
    stored value. Since the 6.2.0 chain carries PR 293 a subclass of int or float is refused by the one
    copy rule (`_plain_value.plain_json`) and by the JCS copy, which agrees with it (owner decision
    OA-c7d6ff7121): nothing writes the value of `int()` or `float()`, and nothing writes the stored one
    either."""

    def test_f4_a_number_subclass_is_refused(self):
        import rfc8785  # noqa: PLC0415
        from proofbundle.evalclaim import _jcs_bytes, canonicalize  # noqa: PLC0415
        faelle = (
            ("canonicalize", lambda: canonicalize(dict(self.basis, provenance={"k": _IntAnders(5)})),
             EvalClaimError),
            ("_jcs_bytes, float", lambda: _jcs_bytes(dict(self.basis, provenance={"k": _FloatAnders(1.5)})),
             EvalClaimError),
            ("canonicalize_statement", lambda: canonical.canonicalize_statement(
                {"i": _IntAnders(5), "f": _FloatAnders(1.5)}), rfc8785.CanonicalizationError),
            ("emit_eval_receipt", lambda: emit_eval_receipt(
                dict(self.basis, provenance={"k": _IntAnders(5)}), self.signer), EvalClaimError),
        )
        for name, lauf, fehler in faelle:
            with self.subTest(weg=name):
                with self.assertRaises(fehler) as ctx:
                    lauf()
                self.assertIn("a number must be an exact int or float", str(ctx.exception))
        self.assertEqual(canonical.canonicalize_statement({"i": 5, "f": 1.5}), b'{"f":1.5,"i":5}')


class TestATypeThatHidesItsBaseIsRefused(_Basis):
    """F5 of lens run 6 at c8205c18. A metaclass whose `mro()` returns `[cls, object]` makes
    `issubclass(cls, dict)` False while `json.dumps` treats the object as a dict through its C
    flags, and writes it through its own `items()`."""

    def test_f5_a_nested_status_value_is_refused(self):
        """At c8205c18 a status holding such a dict, stored {"a": 1}, was signed as {"fremd": 99}."""
        wert = _versteckt({"a": 1})
        self.assertEqual(_gespeichert(wert), [("a", 1)])                    # the premise
        self.assertFalse(issubclass(type(wert), dict))
        _AUFRUFE.clear()
        with self.assertRaises(ValueError):
            issue_sd_jwt(self.basis, self.signer, root_b64=ROOT_B64,
                         status={"status_list": {"idx": 7, "uri": "u"}, "x": wert})
        self.assertEqual(_AUFRUFE, [])

    def test_f5_a_status_that_is_such_a_dict_is_refused(self):
        """At c8205c18 such a status, which holds no `status_list` and whose `__class__` said dict
        to `isinstance`, was signed with the `status_list` its `items()` showed."""
        class Status(dict, metaclass=_VersteckMeta):
            @property
            def __class__(self):  # type: ignore[override]
                return Status if sys._getframe(1).f_code.co_name in ("_plain_value", "_plain_for_jcs") else dict

            def __contains__(self, schluessel):
                return True

            def items(self):
                return [("status_list", {"idx": 99, "uri": "https://example.org/other"})]
        status = Status()
        setze = ctypes.pythonapi.PyDict_SetItem
        setze.argtypes = [ctypes.py_object, ctypes.py_object, ctypes.py_object]
        setze.restype = ctypes.c_int
        self.assertEqual(setze(status, "x", 1), 0)
        with self.assertRaises(ValueError):
            issue_sd_jwt(self.basis, self.signer, root_b64=ROOT_B64, status=status)


class TestAClaimedClassIsATypedRefusalEverywhere(_Basis):
    """The wording finding of lens run 6: the round-7 message said objects whose `__class__` claims
    dict, str or int are typed refusals now. At c8205c18 that did not hold for `emit_eval_receipt`'s
    `threshold`,
    `model_id_commit` and `n` (the claim rule read them before the copy, and the decimal pattern or
    `<=` raised a raw TypeError) or for `issue_sd_jwt`'s `exact_score` and `ci95` items
    (`str.__str__` raised a raw TypeError)."""

    def test_emit_refuses_a_claimed_class_in_every_field(self):
        for feld, wert in (("threshold", _UnechterStr()), ("model_id_commit", _UnechterStr()),
                           ("n", _UnechteZahl())):
            with self.subTest(feld=feld):
                with self.assertRaises(EvalClaimError) as ctx:
                    emit_eval_receipt(dict(self.basis, **{feld: wert}), self.signer)
                self.assertIn(feld, str(ctx.exception))

    def test_issue_sd_jwt_refuses_a_claimed_class_in_the_withheld_numbers(self):
        for name, kwargs in (("exact_score", {"exact_score": _UnechterStr()}),
                             ("ci95", {"ci95": [_UnechterStr(), "0.2"]})):
            with self.subTest(argument=name):
                with self.assertRaises(BundleFormatError) as ctx:
                    issue_sd_jwt(self.basis, self.signer, root_b64=ROOT_B64, **kwargs)
                self.assertIn(name, str(ctx.exception))


class _ItemsZeigtFremdes(dict):
    def items(self):
        return [("fremd", 99)]


class _KleinZeigtAnderes(str):
    def lower(self):
        return "ab" * 32


class _BehauptetBytes:
    @property
    def __class__(self):  # type: ignore[override]
        return bytes

    def __bytes__(self):
        return b"x"


class _BytesZeigtAnderes(bytes):
    def __bytes__(self):
        return b"x"


class TestTheExportersReadTheirOtherArgumentsOnce(_Basis):
    """Siblings found in the sweep of round 8, beside the claim: arguments of the exporters that go
    into a signed statement or a digest, read at c8205c18 through methods the caller controls."""

    def test_the_legacy_serializer_writes_the_stored_harness(self):
        """At c8205c18 the legacy serializer (json.dumps) wrote a harness dict subclass through its
        own `items()`: the signed statement carried {"fremd": 99}."""
        env = intoto.export_intoto_dsse(self.basis, self.signer, harness=_ItemsZeigtFremdes(a=1),
                                        content_root_alg=intoto.LEGACY_CONTENT_ROOT_ALG)
        annotationen = _nutzlast(env)["predicate"]["configuration"][0]["annotations"]
        self.assertEqual(annotationen["harness"], {"a": 1})

    def test_a_release_gate_digest_is_its_stored_characters(self):
        """At c8205c18 `resolve_subject` built the subject digest from `subject_sha256.lower()`, the
        caller's method, and accepted a value whose stored characters are no sha256."""
        with self.assertRaises(BundleFormatError):
            intoto.resolve_subject("release-gate", self.basis, subject_name="m",
                                   subject_sha256=_KleinZeigtAnderes("not-a-digest"))

    def test_statement_content_root_chooses_its_path_by_the_type(self):
        """At c8205c18 `isinstance` read `__class__` and `bytes()` called `__bytes__`: an object that
        claims bytes was hashed as b"x", and so was a bytes subclass holding b"{}"."""
        import hashlib  # noqa: PLC0415
        with self.assertRaises(ProofBundleError):
            canonical.statement_content_root(_BehauptetBytes())
        self.assertEqual(canonical.statement_content_root(_BytesZeigtAnderes(b"{}")),
                         hashlib.sha256(b"{}").digest())


class _Zahl(enum.IntEnum):
    EINS = 1


class _Wort(str, enum.Enum):
    A = "a"


_Paar = collections.namedtuple("_Paar", "a b")


class TestPlainArgumentsKeepTheirBytes(_Basis):
    """Controls of round 8, green at c8205c18 as well. A value the copy reads as a JSON type is
    written as before: the subclasses the standard library ships (Counter, OrderedDict, defaultdict,
    IntEnum, a str Enum, a namedtuple), a tuple, a claim given to the emitter as a list of pairs,
    and the openings of an SD-JWT as a tuple, a list, a string or a JSON object."""

    def test_control_standard_library_subclasses_keep_their_bytes(self):
        """An IntEnum is a subclass of int, and since the 6.2.0 chain carries PR 293 the one copy rule
        refuses it (owner decision OA-c7d6ff7121); it stood among these controls at the D4 head 7cc8fa0b,
        and it is held as a refusal at the end now."""
        import rfc8785  # noqa: PLC0415
        from proofbundle.evalclaim import canonicalize  # noqa: PLC0415
        paare = (
            (collections.Counter(a=1), {"a": 1}), (collections.OrderedDict(b=2, a=1), {"a": 1, "b": 2}),
            (collections.defaultdict(int, a=1), {"a": 1}), (_Wort.A, "a"),
            (_Paar(1, "x"), [1, "x"]), ((1, "x"), [1, "x"]))
        for wert, roh in paare:
            with self.subTest(wert=type(wert).__name__):
                self.assertEqual(canonicalize(dict(self.basis, provenance={"k": wert})),
                                 canonicalize(dict(self.basis, provenance={"k": roh})))
                self.assertEqual(canonical.canonicalize_statement({"k": wert}),
                                 canonical.canonicalize_statement({"k": roh}))
                self.assertEqual(intoto.export_intoto_dsse(self.basis, self.signer, harness={"k": wert},
                                                           content_root_alg=intoto.LEGACY_CONTENT_ROOT_ALG),
                                 intoto.export_intoto_dsse(self.basis, self.signer, harness={"k": roh},
                                                           content_root_alg=intoto.LEGACY_CONTENT_ROOT_ALG))
                status = {"status_list": {"idx": 7}, "k": wert}
                self.assertEqual(_immer_offen(issue_sd_jwt(self.basis, self.signer, root_b64=ROOT_B64,
                                                           status=status))["status"],
                                 {"status_list": {"idx": 7}, "k": roh})
        with self.assertRaises(EvalClaimError):
            canonicalize(dict(self.basis, provenance={"k": _Zahl.EINS}))
        with self.assertRaises(rfc8785.CanonicalizationError):
            canonical.canonicalize_statement({"k": _Zahl.EINS})
        with self.assertRaises(BundleFormatError):
            intoto.export_intoto_dsse(self.basis, self.signer, harness={"k": _Zahl.EINS},
                                      content_root_alg=intoto.LEGACY_CONTENT_ROOT_ALG)
        with self.assertRaises(ValueError):
            issue_sd_jwt(self.basis, self.signer, root_b64=ROOT_B64,
                         status={"status_list": {"idx": 7}, "k": _Zahl.EINS})

    def test_control_plain_shapes_the_readers_accepted_are_read_as_before(self):
        paare = list(self.basis.items())
        self.assertEqual(emit_eval_receipt([list(p) for p in paare], self.signer),
                         emit_eval_receipt(self.basis, self.signer))
        for name, oeffnung, erwartet in (("tuple", ("m", "00"), ["m", "00"]), ("list", ["m", "00"], ["m", "00"]),
                                         ("string", "ab", ["a", "b"]), ("object", {"m": 1}, ["m"])):
            with self.subTest(oeffnung=name):
                compact = issue_sd_jwt(self.basis, self.signer, root_b64=ROOT_B64, model_id_opening=oeffnung)
                self.assertEqual(_offenlegungen(compact)["model_id_opening"], erwartet)


class _NurWahr:
    """No JSON value, only truthy, like a NumPy boolean."""

    def __bool__(self):
        return True


class TestTheChangesRoundEightNamesInReview(_Basis):
    """Behavior changes of round 8 that its first description left out, found when it was read.
    Each was accepted at c8205c18, or named ambiguously there."""

    def test_a_flag_that_is_no_json_value_is_refused(self):
        """PR 291's SwitchTypeError since the 6.2.0 chain carries it; a BundleFormatError at the D4 head
        7cc8fa0b."""
        from proofbundle.errors import SwitchTypeError  # noqa: PLC0415
        env = emit_eval_receipt(self.basis, self.signer)
        wege = (("svr_properties",
                 lambda f: intoto.svr_properties(_Ergebnis(), self.basis, prereg_verified=f)),
                ("export_svr_dsse", lambda f: intoto.export_svr_dsse(env, self.signer, anchor_verified=f)))
        for name, aufruf in wege:
            with self.subTest(weg=name):
                with self.assertRaises(SwitchTypeError):
                    aufruf(_NurWahr())

    def test_a_claim_given_as_an_iterator_of_pairs_is_refused(self):
        paare = list(self.basis.items())
        for name, claim in (("iterator", iter(paare)), ("generator", (p for p in paare)),
                            ("dict view", self.basis.items())):
            with self.subTest(form=name):
                with self.assertRaises(EvalClaimError):
                    emit_eval_receipt(claim, self.signer)

    def test_a_type_named_like_a_built_in_is_named_as_not_the_built_in(self):
        """At c8205c18 the refusal read "unsupported value type bool" for a type named `bool`."""
        fremd = type("bool", (), {})()
        with self.assertRaises(EvalClaimError) as ctx:
            emit_eval_receipt(dict(self.basis, provenance={"k": fremd}), self.signer)
        self.assertIn("bool (not the built-in bool)", str(ctx.exception))

    def test_control_a_tuple_of_pairs_is_read_as_before(self):
        paare = tuple(tuple(p) for p in self.basis.items())
        self.assertEqual(emit_eval_receipt(paare, self.signer), emit_eval_receipt(self.basis, self.signer))


# ---- round 9: lens run 7 at ee489403 ------------------------------------------------------------------

def _typ_ohne_type_im_mro():
    """F1, form A of lens run 7: an object whose type's metaclass leaves `type` out of its own MRO.
    `type.__dict__["__name__"].__get__` checks its argument against that MRO and raised TypeError."""
    class _OhneTypeMeta(type):
        def mro(cls):
            return [cls, object]

    class _OhneType(type, metaclass=_OhneTypeMeta):
        pass

    class _Anfang(type):
        pass

    class Wert(metaclass=_Anfang):
        pass
    wert = Wert()
    Wert.__class__ = _OhneType
    return wert


def _name_ohne_str_im_mro():
    """F1, form B: an ordinary class whose `__name__` is a `str` subclass whose metaclass leaves `str`
    out of its MRO. `str.__str__` checks against that MRO and raised TypeError. Its methods record."""
    class _OhneStrMeta(type):
        def mro(cls):
            return [cls, object]
    name = _OhneStrMeta("Name", (str,), {
        "__str__": lambda self: (_merke("name __str__"), "x")[1],
        "__repr__": lambda self: (_merke("name __repr__"), "x")[1],
        "__eq__": lambda self, other: (_merke("name __eq__"), False)[1],
        "__hash__": lambda self: (_merke("name __hash__"), 1)[1]})

    class Wert:
        pass
    Wert.__name__ = name("harmlos")
    return Wert()


def _verschoben(klasse=collections.OrderedDict):
    """An OrderedDict whose own order (salt_hex, identifier) is not its storage order."""
    od = klasse([("identifier", "acme/model-x"), ("salt_hex", "00ff")])
    od.move_to_end("identifier")
    return od


class _OdZeigtFremdes(collections.OrderedDict):
    """Its own methods show a key it does not hold; the copy reads the base type's order."""

    def __iter__(self):
        return iter(["fremd"])

    def keys(self):
        return ["fremd"]

    def items(self):
        return [("fremd", 99)]

    def __getitem__(self, schluessel):
        return 99


class _HashProtokoll(str):
    """A key whose hash is its own code, and records that it ran."""

    def __hash__(self):
        _merke("key __hash__")
        return str.__hash__(self)


class _GleichProtokoll(str):
    """A key with `str`'s own hash whose comparisons are its own code, and record that they ran."""

    def __eq__(self, other):
        _merke("key __eq__")
        return str.__eq__(self, other)

    def __ne__(self, other):
        _merke("key __ne__")
        return str.__ne__(self, other)

    __hash__ = str.__hash__


def _paare_in_reihenfolge(text: str) -> list:
    """The key order of every object in a JSON text, as the text writes it."""
    reihen: list = []

    def merken(paare):
        reihen.append([k for k, _ in paare])
        return dict(paare)
    json.loads(text, object_pairs_hook=merken)
    return reihen


class TestTheRefusalNamesEveryTypeWithoutRaising(_Basis):
    """F1 of lens run 7 at ee489403, a regression of 86490e3c at the verify boundary. `_type_name`
    raised a raw TypeError for the two forms below, so the refusal it was building escaped as that
    TypeError: from the emitter, every producer, the budget and `statement_content_root`, and from
    `verify_intoto_dsse`, where c8205c18 gave EvalClaimError and ok=False."""

    def test_f1_a_type_whose_name_cannot_be_read_is_named_and_refused(self):
        from proofbundle._strict_json import enforce_structural_budget  # noqa: PLC0415
        s = self.signer
        umschlag = intoto.export_intoto_dsse(self.basis, s)
        for form, bau in (("metaclass hides type", _typ_ohne_type_im_mro),
                          ("name hides str", _name_ohne_str_im_mro)):
            with self.subTest(form=form):
                _AUFRUFE.clear()
                with self.assertRaises(EvalClaimError) as ctx:
                    emit_eval_receipt(dict(self.basis, provenance={"k": bau()}), s)
                # The emitter reads the claim first through `_plain_value.plain_json` since the chain
                # carries PR 293; its refusal names the type through `_membership.type_name`, which
                # never raises either. At the D4 head 7cc8fa0b the JCS copy's words were
                # "a value of type <unnamed type> is not a JSON value".
                self.assertIn("is of type <unnamed type>; a JSON value is", str(ctx.exception))
                for name, erzeuge in _produzenten().items():
                    with self.assertRaises(BundleFormatError, msg=name):
                        erzeuge(dict(self.basis, provenance={"k": bau()}), s)
                with self.assertRaises(ValueError):
                    issue_sd_jwt(self.basis, s, root_b64=ROOT_B64,
                                 status={"status_list": {"idx": 7}, "x": bau()})
                with self.assertRaises(BundleFormatError):
                    enforce_structural_budget({"k": bau()})
                for aufruf in (canonical.statement_content_root,
                               lambda w: canonical.canonicalize_statement(w, require_statement_shape=True)):
                    with self.assertRaises(ProofBundleError) as ctx:
                        aufruf(bau())
                    self.assertIn("<unnamed type>", str(ctx.exception))
                with self.assertRaises(BundleFormatError):
                    dsse.verify_envelope(dict(umschlag, extra=bau()), self.pub)
                for verifiziere in (intoto.verify_intoto_dsse, intoto.verify_eval_result_dsse,
                                    intoto.verify_svr_dsse):
                    self.assertIs(verifiziere(dict(umschlag, extra=bau()), self.pub)["ok"], False)
                self.assertEqual(_AUFRUFE, [])


class TestTheSerializerAfterTheCopyGivesTheEntrysRefusal(_Basis):
    """F2 and F3 of lens run 7 at ee489403: the serializers that run after the copy raised their own
    errors. RecursionError in a band of depths just below the copy's limit (the disclosure's
    json.dumps, the legacy serializer), rfc8785's FloatDomainError and IntegerDomainError and the
    budget's BudgetExceeded under jcs, json's ValueError for 10**5000 under legacy, and `dict()`'s
    TypeError or ValueError for a `subject_digest` that is no object."""

    def _bandsuche(self, aufruf, erlaubt, art):
        """(deepest written, outcomes of the twelve depths after it and of 5000), from one frame."""
        def ergebnis(tiefe):
            try:
                aufruf(_geschachtelt(tiefe, art))
                return "written"
            except erlaubt:
                return "refused"
            except RecursionError:
                return "RecursionError"
        unten, oben = 1, 3000
        while oben - unten > 1:
            mitte = (unten + oben) // 2
            if ergebnis(mitte) == "written":
                unten = mitte
            else:
                oben = mitte
        return unten, [ergebnis(t) for t in list(range(unten + 1, unten + 13)) + [5000]]

    def test_f2_a_value_just_below_the_copys_limit_is_refused_not_raised(self):
        b, s = self.basis, self.signer
        alt = intoto.LEGACY_CONTENT_ROOT_ALG
        buendel = emit_eval_receipt(b, s)
        wege = {
            "issue_sd_jwt model_id_opening": (ValueError, lambda w: issue_sd_jwt(
                b, s, root_b64=ROOT_B64, model_id_opening=["m", w])),
            "issue_sd_jwt dataset_id_opening": (ValueError, lambda w: issue_sd_jwt(
                b, s, root_b64=ROOT_B64, dataset_id_opening=w)),
            "export_intoto_dsse legacy harness": (BundleFormatError, lambda w: intoto.export_intoto_dsse(
                b, s, harness={"h": w}, content_root_alg=alt)),
            "export_eval_result_dsse legacy harness": (BundleFormatError, lambda w: intoto.export_eval_result_dsse(
                b, s, harness={"h": w}, content_root_alg=alt)),
            "export_eval_result_dsse legacy anchors": (BundleFormatError, lambda w: intoto.export_eval_result_dsse(
                b, s, anchors=[w], content_root_alg=alt)),
            "export_svr_dsse legacy policy": (BundleFormatError, lambda w: intoto.export_svr_dsse(
                buendel, s, policy={"p": w}, content_root_alg=alt)),
        }
        for name, (erlaubt, aufruf) in wege.items():
            for art in ("list", "dict"):
                with self.subTest(weg=name, art=art):
                    tiefste, danach = self._bandsuche(aufruf, erlaubt, art)
                    self.assertGreater(tiefste, 64)
                    self.assertEqual(danach, ["refused"] * 13, tiefste)

    def test_f3_a_number_the_serializer_refuses_is_the_exporters_refusal(self):
        b, s = self.basis, self.signer
        alt = intoto.LEGACY_CONTENT_ROOT_ALG
        buendel = emit_eval_receipt(b, s)
        jcs_wege = {
            "export_intoto_dsse harness": lambda v: intoto.export_intoto_dsse(b, s, harness={"h": v}),
            "export_eval_result_dsse anchors": lambda v: intoto.export_eval_result_dsse(b, s, anchors=[v]),
            "export_svr_dsse policy": lambda v: intoto.export_svr_dsse(buendel, s, policy={"p": v}),
        }
        werte = (("nan", float("nan")), ("inf", float("inf")), ("2**53", 2 ** 53), ("2**64", 2 ** 64),
                 ("10**5000", 10 ** 5000))
        for name, aufruf in jcs_wege.items():
            for bezeichnung, wert in werte:
                with self.subTest(weg=name, wert=bezeichnung):
                    with self.assertRaises(BundleFormatError) as ctx:
                        aufruf(wert)
                    self.assertIn(name.split()[0], str(ctx.exception))
        with self.subTest(weg="export_intoto_dsse legacy harness", wert="10**5000"):
            with self.assertRaises(BundleFormatError):
                intoto.export_intoto_dsse(b, s, harness={"h": 10 ** 5000}, content_root_alg=alt)

    def test_f3_a_subject_digest_that_is_no_object_is_refused(self):
        for wert in (None, 5, "ab", [1], True):
            with self.subTest(subject_digest=wert):
                with self.assertRaises(BundleFormatError) as ctx:
                    intoto.to_test_result_statement(self.basis, subject_digest=wert)
                self.assertIn("subject_digest", str(ctx.exception))
        for wert, erwartet in (({"sha256": "00"}, {"sha256": "00"}), ([["sha256", "00"]], {"sha256": "00"})):
            with self.subTest(angenommen=wert):
                stmt = intoto.to_test_result_statement(self.basis, subject_digest=wert)
                self.assertEqual(stmt["subject"][0]["digest"], erwartet)


class TestAnArgumentThatMustBeAStringIsOne(_Basis):
    """The class of F3 at the string arguments, measured at ee489403 by a second lens: `_eigen` let
    any JSON value through where the argument must be a string. `root_b64` or `content_root_alg`
    of 10**5000 at `export_intoto_dsse`, `subject_profile=10**5000` at `export_eval_result_dsse`,
    `expected_predicate_type=10**5000` at the verifiers and `passed=10**5000` at `svr_properties` raised
    a raw ValueError from a message; a `url`, `keyid`, `root_b64`, `subject_name` or `subject_profile`
    of another type was written into the statement or the envelope."""

    def _wege(self):
        b, s = self.basis, self.signer
        buendel = emit_eval_receipt(b, s)
        umschlag = intoto.export_intoto_dsse(b, s)
        eval_umschlag = intoto.export_eval_result_dsse(b, s)
        svr_umschlag = intoto.export_svr_dsse(buendel, s)
        digest = {"sha256": "0" * 64}
        sha = "ab" * 32
        return {
            ("to_intoto_statement", "root_b64"): lambda v: intoto.to_intoto_statement(b, root_b64=v),
            ("to_test_result_statement", "root_b64"): lambda v: intoto.to_test_result_statement(
                b, subject_digest=digest, root_b64=v),
            ("to_test_result_statement", "url"): lambda v: intoto.to_test_result_statement(
                b, subject_digest=digest, url=v),
            ("to_test_result_statement", "content_root_alg"): lambda v: intoto.to_test_result_statement(
                b, subject_digest=digest, content_root_alg=v),
            ("export_intoto_dsse", "root_b64"): lambda v: intoto.export_intoto_dsse(b, s, root_b64=v),
            ("export_intoto_dsse", "url"): lambda v: intoto.export_intoto_dsse(b, s, url=v),
            ("export_intoto_dsse", "keyid"): lambda v: intoto.export_intoto_dsse(b, s, keyid=v),
            ("export_intoto_dsse", "content_root_alg"): lambda v: intoto.export_intoto_dsse(
                b, s, content_root_alg=v),
            ("resolve_subject", "profile"): lambda v: intoto.resolve_subject(v, b),
            ("resolve_subject", "root_b64"): lambda v: intoto.resolve_subject("receipt", b, root_b64=v),
            ("resolve_subject", "subject_name"): lambda v: intoto.resolve_subject(
                "public-model", b, subject_name=v, subject_sha256=sha),
            ("resolve_subject", "subject_sha256"): lambda v: intoto.resolve_subject(
                "release-gate", b, subject_name="m", subject_sha256=v),
            ("to_eval_result_predicate", "root_b64"): lambda v: intoto.to_eval_result_predicate(b, root_b64=v),
            ("to_eval_result_predicate", "subject_profile"): lambda v: intoto.to_eval_result_predicate(
                b, subject_profile=v),
            ("to_eval_result_statement", "content_root_alg"): lambda v: intoto.to_eval_result_statement(
                b, subject=[digest], content_root_alg=v),
            ("export_eval_result_dsse", "subject_profile"): lambda v: intoto.export_eval_result_dsse(
                b, s, subject_profile=v),
            ("export_eval_result_dsse", "subject_name"): lambda v: intoto.export_eval_result_dsse(
                b, s, subject_profile="public-model", subject_name=v, subject_sha256=sha),
            ("export_eval_result_dsse", "subject_sha256"): lambda v: intoto.export_eval_result_dsse(
                b, s, subject_profile="public-model", subject_name="m", subject_sha256=v),
            ("export_eval_result_dsse", "root_b64"): lambda v: intoto.export_eval_result_dsse(b, s, root_b64=v),
            ("export_eval_result_dsse", "keyid"): lambda v: intoto.export_eval_result_dsse(b, s, keyid=v),
            ("export_eval_result_dsse", "content_root_alg"): lambda v: intoto.export_eval_result_dsse(
                b, s, content_root_alg=v),
            ("export_svr_dsse", "time_created"): lambda v: intoto.export_svr_dsse(buendel, s, time_created=v),
            ("export_svr_dsse", "keyid"): lambda v: intoto.export_svr_dsse(buendel, s, keyid=v),
            ("export_svr_dsse", "content_root_alg"): lambda v: intoto.export_svr_dsse(
                buendel, s, content_root_alg=v),
            ("verify_intoto_dsse", "expected_predicate_type"): lambda v: intoto.verify_intoto_dsse(
                umschlag, self.pub, expected_predicate_type=v),
            ("verify_eval_result_dsse", "expected_predicate_type"): lambda v: intoto.verify_eval_result_dsse(
                eval_umschlag, self.pub, expected_predicate_type=v),
            ("verify_svr_dsse", "expected_predicate_type"): lambda v: intoto.verify_svr_dsse(
                svr_umschlag, self.pub, expected_predicate_type=v),
        }

    #: The arguments the 6.2.0 chain reads first through PR 293's `intoto._text_once` and `_alg_once`
    #: (read once from storage, before this module's own reading), with the refusal those give. At the
    #: D4 head 7cc8fa0b each was refused as "<entry>: <argument> must be a string".
    _ZUERST_293 = {"content_root_alg": "unknown contentRootAlg of type ",
                   "profile": "unknown subject profile of type ",
                   "subject_profile": "unknown subject profile of type ",
                   "subject_name": "subject_name must be text",
                   "subject_sha256": "subject_sha256 must be text"}
    #: `export_eval_result_dsse` reads these two itself before it hands them to `resolve_subject`.
    _D4_ZUERST = {("export_eval_result_dsse", "subject_name"), ("export_eval_result_dsse", "subject_sha256")}

    def test_an_argument_of_another_type_is_refused_by_name(self):
        for (weg, argument), aufruf in self._wege().items():
            for wert in (10 ** 5000, 5, [1], {"a": "b"}, True):
                with self.subTest(weg=weg, argument=argument, wert=type(wert).__name__):
                    with self.assertRaises(BundleFormatError) as ctx:
                        aufruf(wert)
                    erwartet = (f"{weg}: {argument} must be a string" if (weg, argument) in self._D4_ZUERST
                                else self._ZUERST_293.get(argument, f"{weg}: {argument} must be a string"))
                    self.assertIn(erwartet, str(ctx.exception))

    def test_a_passed_the_message_cannot_print_is_refused(self):
        with self.assertRaises(BundleFormatError) as ctx:
            intoto.svr_properties(_Ergebnis(), dict(self.basis, passed=10 ** 5000))
        self.assertIn("`passed` is int <int, 16610 bits>", str(ctx.exception))

    def test_control_a_string_argument_is_written_as_its_characters(self):
        """Green at ee489403 too: a `str` subclass is read as the characters it holds."""
        class Text(str):
            pass
        b, s = self.basis, self.signer
        self.assertEqual(intoto.export_intoto_dsse(b, s, root_b64=Text(ROOT_B64), url=Text("https://x"),
                                                   keyid=Text("k")),
                         intoto.export_intoto_dsse(b, s, root_b64=ROOT_B64, url="https://x", keyid="k"))
        self.assertEqual(intoto.resolve_subject(Text("release-gate"), b, subject_name=Text("m"),
                                                subject_sha256=Text("AB" * 32)),
                         [{"name": "m", "digest": {"sha256": "ab" * 32}}])


class TestACallerAttestedFlagIsABoolean(_Basis):
    """R-B4 at the caller-attested flags, P2, found outside the targets of lens run 7 and measured at
    ee489403 and on main 20e91c8e: `export_svr_dsse(env, signer, anchor_verified="false")` signed
    PROOFBUNDLE_ANCHOR_VALID. A flag was read by its truth.

    The refusal is PR 291's since the 6.2.0 chain carries it: `_membership.require_switch`, a
    SwitchTypeError (a TypeError and a ProofBundleError) naming the flag and the type. At the D4 head
    7cc8fa0b it was this module's BundleFormatError "<entry>: <flag> must be True or False"."""

    def test_a_flag_that_is_not_true_or_false_is_refused(self):
        from proofbundle.errors import SwitchTypeError  # noqa: PLC0415
        buendel = emit_eval_receipt(self.basis, self.signer)
        mit_prereg = dict(self.basis, prereg_sha256="a" * 64)
        for flagge in ("prereg_verified", "anchor_verified"):
            for wert in ("false", "true", "", 0, 1, None, [], {}):
                with self.subTest(flagge=flagge, wert=wert):
                    for aufruf in (lambda: intoto.svr_properties(_Ergebnis(), mit_prereg, **{flagge: wert}),
                                   lambda: intoto.export_svr_dsse(buendel, self.signer, **{flagge: wert})):
                        with self.assertRaises(SwitchTypeError) as ctx:
                            aufruf()
                        self.assertIn(f"{flagge} must be a bool (True or False), not a value of type "
                                      f"{type(wert).__name__}", str(ctx.exception))

    def test_control_true_and_false_attest_as_before(self):
        from _svr_binding import bound_svr_result  # type: ignore  # noqa: PLC0415
        buendel = emit_eval_receipt(self.basis, self.signer)
        mit_prereg = dict(self.basis, prereg_sha256="a" * 64)
        # Nachtrag 48/48b (F3): the caller-attested flags still ride on a result bound to exactly this claim.
        result, claim = bound_svr_result(mit_prereg, self.signer)
        for wert in (True, False):
            with self.subTest(wert=wert):
                props = intoto.svr_properties(result, claim, prereg_verified=wert,
                                              anchor_verified=wert)
                self.assertEqual("PROOFBUNDLE_PREREG_BOUND" in props, wert)
                self.assertEqual("PROOFBUNDLE_ANCHOR_VALID" in props, wert)
                signiert = _nutzlast(intoto.export_svr_dsse(buendel, self.signer, anchor_verified=wert))
                self.assertEqual("PROOFBUNDLE_ANCHOR_VALID" in signiert["predicate"]["properties"], wert)


class TestAnOrderedDictIsReadInItsOwnOrder(_Basis):
    """F4 of lens run 7 at ee489403, a regression of this round: the copy read an OrderedDict with
    `dict.items`, its storage order, which `move_to_end` does not change. `issue_sd_jwt` signed the
    opening ['identifier', 'salt_hex'] for an OrderedDict whose own order is the reverse, where
    c8205c18 and main signed ['salt_hex', 'identifier'], and `to_test_result_statement` built another
    subject digest. `status` read the storage order at c8205c18 too; it reads the own order now, as
    on main."""

    FORMEN = (("OrderedDict", lambda: _verschoben()),
              ("a subclass whose own methods show another key", lambda: _verschoben(_OdZeigtFremdes)))

    def test_every_order_sensitive_reader_sees_the_own_order(self):
        b, s = self.basis, self.signer
        for form, bau in self.FORMEN:
            with self.subTest(form=form):
                od = bau()
                self.assertEqual(list(collections.OrderedDict.__iter__(od)), ["salt_hex", "identifier"])
                self.assertEqual(list(dict.__iter__(od)), ["identifier", "salt_hex"])   # the premise
                offen = _offenlegungen(issue_sd_jwt(b, s, root_b64=ROOT_B64, model_id_opening=od,
                                                    dataset_id_opening=["d", od]))
                self.assertEqual(offen["model_id_opening"], ["salt_hex", "identifier"])
                self.assertEqual(list(offen["dataset_id_opening"][1]), ["salt_hex", "identifier"])
                self.assertEqual(intoto.to_test_result_statement(b, subject_digest=[od])["subject"][0]
                                 ["digest"], {"salt_hex": "identifier"})
                self.assertEqual(list(intoto.to_intoto_statement(b, harness=od)["predicate"]["harness"]),
                                 ["salt_hex", "identifier"])
                compact = issue_sd_jwt(b, s, root_b64=ROOT_B64,
                                       status={"status_list": {"idx": 7}, "x": od})
                teil = compact.split("~", 1)[0].split(".")[1]
                text = base64.urlsafe_b64decode(teil + "=" * (-len(teil) % 4)).decode("utf-8")
                self.assertIn(["salt_hex", "identifier"], _paare_in_reihenfolge(text))

    def test_an_ordered_dict_keeps_its_bytes_on_every_path(self):
        """What the CHANGELOG says of OrderedDict, as bytes: on every path an OrderedDict writes what
        the plain dict in its own order writes."""
        from proofbundle.evalclaim import canonicalize  # noqa: PLC0415
        b, s = self.basis, self.signer
        alt = intoto.LEGACY_CONTENT_ROOT_ALG
        for form, bau in self.FORMEN:
            od = bau()
            roh = {k: dict.__getitem__(od, k) for k in collections.OrderedDict.__iter__(od)}
            wege = {
                "canonicalize": lambda w: canonicalize(dict(b, provenance={"k": w})),
                "canonicalize_statement": lambda w: canonical.canonicalize_statement({"k": w}),
                "emit_eval_receipt": lambda w: emit_eval_receipt(dict(b, provenance={"k": w}), s),
                "export_intoto_dsse legacy": lambda w: intoto.export_intoto_dsse(
                    b, s, harness={"k": w}, content_root_alg=alt),
                "export_intoto_dsse jcs": lambda w: intoto.export_intoto_dsse(b, s, harness={"k": w}),
                "issue_sd_jwt status": lambda w: issue_sd_jwt(
                    b, s, root_b64=ROOT_B64, status={"status_list": {"idx": 7}, "k": w}).split("~", 1)[0],
                "issue_sd_jwt opening": lambda w: json.dumps(_offenlegungen(issue_sd_jwt(
                    b, s, root_b64=ROOT_B64, model_id_opening=w, dataset_id_opening=["d", w]))),
                "to_test_result_statement subject_digest": lambda w: json.dumps(
                    intoto.to_test_result_statement(b, subject_digest=[w])),
                "to_intoto_statement harness": lambda w: json.dumps(intoto.to_intoto_statement(b, harness=w)),
            }
            for weg, schreibe in wege.items():
                with self.subTest(form=form, weg=weg):
                    self.assertEqual(schreibe(od), schreibe(roh))

    def test_a_key_that_computes_its_own_hash_is_refused_without_running_it(self):
        """The base method hashes each key to find its node, and this key's hash is its own code. It
        is refused before the order is read, and its hash never runs. At ee489403 the copy read the
        storage order and signed it. Round 10 refuses every key that is not of type str itself, and
        the expected message changed with it (it was "computes its own hash")."""
        od = collections.OrderedDict([(_HashProtokoll("a"), 1), ("b", 2)])
        od.move_to_end("a")
        _AUFRUFE.clear()
        with self.assertRaises(EvalClaimError) as ctx:
            emit_eval_receipt(dict(self.basis, provenance={"k": od}), self.signer)
        self.assertIn("an OrderedDict key must be of type str, got _HashProtokoll", str(ctx.exception))
        with self.assertRaises(ValueError):
            issue_sd_jwt(self.basis, self.signer, root_b64=ROOT_B64, status={"status_list": {}, "k": od})
        self.assertEqual(_AUFRUFE, [])

    def test_control_the_copy_of_an_ordered_dict_runs_no_code_of_the_caller(self):
        """Green at ee489403 too, which read the storage order: a recording OrderedDict subclass, and
        keys that compare through their own `__eq__` with `str`'s hash, are read without a call.
        Since round 10 the second form is refused, as a key that is not of type str itself, and
        still without a call; the case accepts either outcome and asserts only the absence of one."""
        PO = _protokolliert(collections.OrderedDict)
        b, s = self.basis, self.signer

        def aufbau():
            od = PO([("identifier", "acme/model-x"), ("salt_hex", "00ff")])
            collections.OrderedDict.move_to_end(od, "identifier")
            return od

        def eigene_vergleiche():
            od = collections.OrderedDict([(_GleichProtokoll("a"), 1), (_GleichProtokoll("b"), 2)])
            od.move_to_end(next(iter(od)))
            return od
        for weg, aufruf in (
                ("emit provenance", lambda w: emit_eval_receipt(dict(b, provenance={"k": w}), s)),
                ("issue_sd_jwt status", lambda w: issue_sd_jwt(b, s, root_b64=ROOT_B64,
                                                               status={"status_list": {}, "k": w})),
                ("issue_sd_jwt opening", lambda w: issue_sd_jwt(b, s, root_b64=ROOT_B64, model_id_opening=w)),
                ("to_test_result_statement", lambda w: intoto.to_test_result_statement(
                    b, subject_digest=[w])),
                ("export_intoto_dsse legacy", lambda w: intoto.export_intoto_dsse(
                    b, s, harness=w, content_root_alg=intoto.LEGACY_CONTENT_ROOT_ALG))):
            for form, bau in (("recording OrderedDict", aufbau), ("keys that compare by their own code",
                                                                  eigene_vergleiche),
                              ("recording OrderedDict holding a recording key",
                               lambda: PO([(P[str]("k"), 1)]))):
                self._pruefe(f"{weg}, {form}", bau, aufruf, (ProofBundleError, ValueError))

    _pruefe = TestTheCopyRunsNoCodeOfTheCaller._pruefe


# ---- round 10: lens run 8 at 493c2f86 -----------------------------------------------------------------

#: Armed only while an entry runs: a caller function that raises or deepens a sibling does so there,
#: and not while its value is built (building an OrderedDict hashes each key once, in the test).
_SCHARF = [False]


def _alias_hash(self):
    """A `__hash__` bound under a class-dict key that only compares equal to the name."""
    _merke("alias __hash__")
    return str.__hash__(self)


def _alias_hash_wirft(self):
    _merke("alias __hash__")
    if _SCHARF[0]:
        raise ZeroDivisionError("the caller's __hash__")
    return str.__hash__(self)


class _NameGleich(str):
    """A key spelled "__hash__" that is a `str` subclass, so equal to the name and not of type str."""


class _NameBehauptet(str):
    """Other characters, whose `__eq__` and `__hash__` claim to be "__hash__"."""

    def __eq__(self, other):
        return True

    def __hash__(self):
        return hash("__hash__")


class _NameObjekt:
    """No string at all, whose `__eq__` and `__hash__` claim to be "__hash__"."""

    def __eq__(self, other):
        return other == "__hash__"

    def __hash__(self):
        return hash("__hash__")


def _alias_formen() -> dict:
    """The key types of lens run 8 (its p04, and the form that raises): each binds `__hash__` to the
    caller's function under a class-dict key that only compares equal to the name, which CPython's
    slot lookup accepts. Built at call time, so building them records nothing a case counts."""
    gesetzt = type("MitSetattr", (str,), {_NameGleich("__hash__"): str.__hash__})
    gesetzt.__hash__ = _alias_hash       # setattr keeps the existing key object
    basis = type("AliasBasis", (str,), {_NameGleich("__hash__"): _alias_hash})
    return {
        "a str subclass key spelled __hash__": type("Gleich", (str,), {_NameGleich("__hash__"): _alias_hash}),
        "a key of other characters claiming the name": type(
            "Behauptet", (str,), {_NameBehauptet("zzz"): _alias_hash}),
        "a key that is no string": type("Objekt", (str,), {_NameObjekt(): _alias_hash}),
        "setattr over an alias key": gesetzt,
        "the alias on a base before str": type("VonBasis", (basis,), {}),
        "an alias whose function raises": type("Wirft", (str,), {_NameGleich("__hash__"): _alias_hash_wirft}),
    }


class _KnotenProtokoll(str):
    """A key whose hash and comparison are its own code, and record that they ran."""

    def __hash__(self):
        _merke("node key __hash__")
        return str.__hash__(self)

    def __eq__(self, other):
        _merke("node key __eq__")
        return str.__eq__(self, other)

    __ne__ = str.__ne__


class _KnotenWirft(str):
    def __hash__(self):
        _merke("node key __hash__")
        if _SCHARF[0]:
            raise ZeroDivisionError("the node key's __hash__")
        return str.__hash__(self)


class _MetaHash(type):
    """A metaclass whose hash and equality record, for an OrderedDict class that is its own key."""

    def __hash__(cls):
        _merke("metaclass __hash__")
        return type.__hash__(cls)

    def __eq__(cls, other):
        _merke("metaclass __eq__")
        return type.__eq__(cls, other)


def _fremder_knoten_formen() -> dict:
    """OrderedDicts whose storage was written past their own methods (`dict.__delitem__`), so their
    own list keeps a key object the storage no longer holds. Every stored key is of type str, so the
    check of the stored keys alone passes them; the list is what the base method hashes."""
    od_typ = collections.OrderedDict

    def gleich():
        od = od_typ([(_KnotenProtokoll("a"), "1")])
        dict.__delitem__(od, "a")
        dict.__setitem__(od, "a", "1")
        return od

    def fort():
        od = od_typ([(_KnotenProtokoll("x"), "1"), ("b", "2")])
        dict.__delitem__(od, "x")
        return od

    def auch_als_wert():
        schluessel = _KnotenProtokoll("x")
        od = od_typ([(schluessel, "1"), ("b", "2")])
        dict.__delitem__(od, "x")
        dict.__setitem__(od, "v", schluessel)
        return od

    def eigene_klasse():
        klasse = _MetaHash("OdMitMeta", (od_typ,), {})
        od = klasse([("b", "2")])
        od[klasse] = "1"
        dict.__delitem__(od, klasse)
        return od

    def wirft():
        od = od_typ([(_KnotenWirft("x"), "1"), ("b", "2")])
        dict.__delitem__(od, "x")
        dict.__setitem__(od, "x", "1")
        return od
    return {"the list holds a key object whose characters are stored": gleich,
            "the list holds a key the storage lost": fort,
            "the list's key object is also a stored value": auch_als_wert,
            "the list holds the OrderedDict's own class": eigene_klasse,
            "the list holds a key whose hash raises": wirft}


class _WahrheitProtokoll:
    """Answers `wert` to a truth test, and records that it was asked."""

    def __init__(self, wert):
        self.wert = wert

    def __bool__(self):
        _merke("__bool__")
        return self.wert


class _WahrheitWirftProtokoll:
    def __bool__(self):
        _merke("__bool__")
        raise ZeroDivisionError("the caller's __bool__")


class TestAnOrderedDictIsReadOnlyWithKeysOfTypeStr(_Basis):
    """L8-A of lens run 8 at 493c2f86. `canonical._hasht_als_zeichen` decided whether hashing a `str`
    subclass key runs the caller's code by reading the class dicts of its MRO for an entry under a
    key of type str spelled "__hash__". CPython binds the hash slot by a lookup that compares keys by
    equality, so each form of `_alias_formen` hashed through the caller's function while that
    reading called it `str`'s own, and `OrderedDict.__iter__` hashed every key: the caller's code ran
    in 28 of 28 entry and argument pairs and raw exceptions escaped. An OrderedDict is read in its own
    order now only when every stored key is of type str itself and its own list holds nothing else;
    the second half is the sibling of `_fremder_knoten_formen`, measured at 493c2f86 and on main."""

    def _eintritte(self) -> dict:
        """The 28 entry and argument pairs of lens run 8 (its p02), name -> (call, typed refusals)."""
        from proofbundle.evalclaim import canonicalize  # noqa: PLC0415
        b, s = self.basis, self.signer
        zeit = "2026-01-01T00:00:00Z"
        buendel = emit_eval_receipt(b, s)
        tr = intoto.export_intoto_dsse(b, s)
        er = intoto.export_eval_result_dsse(b, s)
        svr = intoto.export_svr_dsse(buendel, s, time_created=zeit)
        kopie = (ProofBundleError, ValueError)
        bfe = (BundleFormatError,)
        sd = (BundleFormatError, ValueError)
        # A flag is a switch: PR 291's SwitchTypeError since the 6.2.0 chain carries it (a
        # BundleFormatError at the D4 head 7cc8fa0b).
        from proofbundle.errors import SwitchTypeError  # noqa: PLC0415
        schalter = (SwitchTypeError,)
        return {
            "canonicalize_statement": (lambda w: canonical.canonicalize_statement({"k": w}), kopie),
            "canonicalize_statement, shape guard": (lambda w: canonical.canonicalize_statement(
                {"_type": "t", "subject": [], "predicateType": "p", "predicate": w},
                require_statement_shape=True), kopie),
            "statement_content_root": (lambda w: canonical.statement_content_root({"k": w}), kopie),
            "canonicalize provenance": (lambda w: canonicalize(dict(b, provenance={"k": w})), (EvalClaimError,)),
            "emit_eval_receipt provenance": (
                lambda w: emit_eval_receipt(dict(b, provenance={"k": w}), s), (EvalClaimError,)),
            "to_intoto_statement harness": (lambda w: intoto.to_intoto_statement(b, harness=w), bfe),
            "to_intoto_statement root_b64": (lambda w: intoto.to_intoto_statement(b, root_b64=w), bfe),
            "to_test_result_statement subject_digest": (
                lambda w: intoto.to_test_result_statement(b, subject_digest=w), bfe),
            "to_test_result_statement url": (lambda w: intoto.to_test_result_statement(
                b, subject_digest={"sha256": "0" * 64}, url=w), bfe),
            "export_intoto_dsse harness": (lambda w: intoto.export_intoto_dsse(b, s, harness=w), bfe),
            "export_intoto_dsse keyid": (lambda w: intoto.export_intoto_dsse(b, s, keyid=w), bfe),
            "resolve_subject claim": (
                lambda w: intoto.resolve_subject("receipt", dict(b, provenance={"k": w})), bfe),
            "resolve_subject profile": (lambda w: intoto.resolve_subject(w, b), bfe),
            "to_eval_result_predicate anchors": (lambda w: intoto.to_eval_result_predicate(b, anchors=[w]), bfe),
            "to_eval_result_statement subject": (lambda w: intoto.to_eval_result_statement(b, subject=[w]), bfe),
            "export_eval_result_dsse harness": (lambda w: intoto.export_eval_result_dsse(b, s, harness=w), bfe),
            "export_eval_result_dsse subject_name": (
                lambda w: intoto.export_eval_result_dsse(b, s, subject_name=w), bfe),
            "svr_properties claim": (
                lambda w: intoto.svr_properties(_Ergebnis(), dict(b, provenance={"k": w})), bfe),
            "svr_properties flag": (lambda w: intoto.svr_properties(_Ergebnis(), b, anchor_verified=w),
                                    schalter),
            "export_svr_dsse policy": (
                lambda w: intoto.export_svr_dsse(buendel, s, policy=w, time_created=zeit), bfe),
            "export_svr_dsse anchor_verified": (
                lambda w: intoto.export_svr_dsse(buendel, s, anchor_verified=w), schalter),
            "issue_sd_jwt claim": (
                lambda w: issue_sd_jwt(dict(b, provenance={"k": w}), s, root_b64=ROOT_B64), sd),
            "issue_sd_jwt status": (lambda w: issue_sd_jwt(
                b, s, root_b64=ROOT_B64, status={"status_list": {}, "k": w}), sd),
            "issue_sd_jwt model_id_opening": (
                lambda w: issue_sd_jwt(b, s, root_b64=ROOT_B64, model_id_opening=w), sd),
            "issue_sd_jwt vct": (lambda w: issue_sd_jwt(b, s, root_b64=ROOT_B64, vct=w), sd),
            "verify_intoto_dsse expected_predicate_type": (
                lambda w: intoto.verify_intoto_dsse(tr, self.pub, expected_predicate_type=w), bfe),
            "verify_eval_result_dsse expected_predicate_type": (
                lambda w: intoto.verify_eval_result_dsse(er, self.pub, expected_predicate_type=w), bfe),
            "verify_svr_dsse expected_predicate_type": (
                lambda w: intoto.verify_svr_dsse(svr, self.pub, expected_predicate_type=w), bfe),
        }

    def _weist_ab(self, name, aufbau, aufruf, erlaubt):
        """The entry's typed refusal, and not one recorded call while the entry runs."""
        with self.subTest(weg=name):
            wert = aufbau()
            _AUFRUFE.clear()
            _SCHARF[0] = True
            try:
                with self.assertRaises(erlaubt):
                    aufruf(wert)
            finally:
                _SCHARF[0] = False
                gesehen = list(_AUFRUFE)
                _AUFRUFE.clear()
            self.assertEqual(gesehen, [], f"{name}: the caller's code ran")

    def test_every_alias_form_is_refused_at_every_entry_without_a_call(self):
        formen = _alias_formen()
        for name, typ in formen.items():
            _AUFRUFE.clear()
            hash(typ("x"))
            self.assertIn("alias __hash__", _AUFRUFE, f"the premise: {name} hashes through the caller")
        _AUFRUFE.clear()
        eintritte = self._eintritte()
        self.assertEqual(len(eintritte), 28)
        for weg, (aufruf, erlaubt) in eintritte.items():
            for name, typ in formen.items():
                self._weist_ab(f"{weg}, {name}", lambda typ=typ: collections.OrderedDict(
                    [(typ("a"), "1"), (typ("b"), "2")]), aufruf, erlaubt)

    def test_every_foreign_key_in_the_own_order_is_refused_at_every_entry_without_a_call(self):
        """The sibling: with every stored key of type str, the list of an OrderedDict written past its
        own methods still held a key object whose hash, `__eq__` or metaclass ran at 493c2f86, and a
        hash that raised escaped raw (on main 31816e08 too, as KeyError or the raised error)."""
        for weg, (aufruf, erlaubt) in self._eintritte().items():
            for name, bau in _fremder_knoten_formen().items():
                self._weist_ab(f"{weg}, {name}", bau, aufruf, erlaubt)

    def test_a_key_cannot_deepen_a_sibling_after_the_budget(self):
        """p03 of lens run 8: the budget judged the statement, then the copy hashed the OrderedDict's
        key through the caller's function, which deepened a sibling the copy had not reached yet. At
        493c2f86 `canonicalize_statement` returned output nested 502 deep for 500 levels against the
        depth bound of 64, and wrote 300000 list items against the bound of 200000 nodes."""
        for tiefe, breite in ((64, 0), (500, 0), (2000, 0), (0, 300_000)):
            with self.subTest(tiefe=tiefe, breite=breite):
                geschwister: list = []

                def vertiefe(selbst, tiefe=tiefe, breite=breite, geschwister=geschwister):
                    _merke("alias __hash__")
                    if _SCHARF[0] and not geschwister:
                        ende = geschwister
                        for _ in range(tiefe):
                            neu: list = []
                            ende.append(neu)
                            ende = neu
                        geschwister.extend(range(breite))
                    return str.__hash__(selbst)
                typ = type("Vertieft", (str,), {_NameGleich("__hash__"): vertiefe})
                od = collections.OrderedDict([(typ("a"), 1)])
                _AUFRUFE.clear()
                _SCHARF[0] = True
                try:
                    with self.assertRaises((ProofBundleError, ValueError)):
                        canonical.canonicalize_statement({"a": od, "b": geschwister})
                finally:
                    _SCHARF[0] = False
                    gesehen = list(_AUFRUFE)
                    _AUFRUFE.clear()
                self.assertEqual((gesehen, geschwister), ([], []))

    def test_control_an_ordered_dict_of_str_keys_is_read_in_its_own_order(self):
        """Green at 493c2f86 too: an OrderedDict with keys of type str, a subclass with an attribute
        or a slot holding a str, and one holding recording values keep their own order, and nothing
        of theirs runs."""
        class MitAttribut(collections.OrderedDict):
            pass

        class MitSlot(collections.OrderedDict):
            __slots__ = ("z",)

        def verschoben(klasse=collections.OrderedDict, werte=("acme/model-x", "00ff")):
            od = klasse([("identifier", werte[0]), ("salt_hex", werte[1])])
            collections.OrderedDict.move_to_end(od, "identifier")
            return od

        def mit_attribut():
            od = verschoben(MitAttribut)
            od.attr = P[str]("x")
            return od

        def mit_slot():
            od = verschoben(MitSlot)
            od.z = "s"
            return od
        formen = {"OrderedDict": verschoben, "a subclass with an attribute": mit_attribut,
                  "a subclass whose slot holds a str": mit_slot,
                  # the number plain: a recording int is refused by the one copy rule (PR 293)
                  "recording values": lambda: verschoben(werte=(P[dict]({"k": 1}),
                                                                P[list]([P[str]("x")])))}
        for name, bau in formen.items():
            with self.subTest(form=name):
                od = bau()
                _AUFRUFE.clear()
                kopie = canonical._plain_for_jcs(od, ValueError)
                gesehen = list(_AUFRUFE)
                _AUFRUFE.clear()
                self.assertEqual(list(kopie), ["salt_hex", "identifier"])
                self.assertEqual(gesehen, [])

    def test_control_a_plain_dict_with_str_subclass_keys_is_copied_as_before(self):
        """Green at 493c2f86 too: a plain dict is read through `dict.items`, which hashes nothing, so
        every alias form, a key with its own hash and a recording key are copied as their characters,
        in storage order, without a call."""
        formen = [typ for name, typ in _alias_formen().items() if "raises" not in name]
        schluessel = [typ(f"k{i}") for i, typ in enumerate(formen)] + [_HashProtokoll("h"), P[str]("p")]
        wert = {k: i for i, k in enumerate(schluessel)}
        erwartet = {str.__str__(k): i for i, k in enumerate(schluessel)}
        _AUFRUFE.clear()
        _SCHARF[0] = True
        try:
            kopie = canonical._plain_for_jcs(wert, ValueError)
            geschrieben = canonical.canonicalize_statement({"k": wert})
        finally:
            _SCHARF[0] = False
            gesehen = list(_AUFRUFE)
            _AUFRUFE.clear()
        self.assertEqual((kopie, list(kopie)), (erwartet, list(erwartet)))
        self.assertTrue(all(type(k) is str for k in kopie))
        self.assertEqual(geschrieben, canonical.canonicalize_statement({"k": erwartet}))
        self.assertEqual(gesehen, [])


class TestAFlagIsReadAsABoolean(_Basis):
    """L8-B of lens run 8 at 493c2f86 (on main too): `require_statement_shape` was read by its truth
    in `canonicalize_statement` and `statement_content_root`, so a caller object's `__bool__` ran,
    what it raised escaped raw, and the string "false" switched the guard on. And the sibling found by
    a second lens in `intoto.svr_properties`: the `ok` of a check of the caller's result was read by
    its truth, so "false" earned PROOFBUNDLE_SIGNATURE_VALID and PROOFBUNDLE_RECEIPT_UNCHANGED."""

    def test_require_statement_shape_must_be_true_or_false(self):
        bar = {"predicate": {}}
        wege = {"canonicalize_statement": lambda f: canonical.canonicalize_statement(
                    bar, require_statement_shape=f),
                "statement_content_root": lambda f: canonical.statement_content_root(
                    bar, require_statement_shape=f)}
        werte = {'"false"': lambda: "false", "0": lambda: 0, "1": lambda: 1, "None": lambda: None,
                 "a recording __bool__ answering True": lambda: _WahrheitProtokoll(True),
                 "a recording __bool__ answering False": lambda: _WahrheitProtokoll(False),
                 "a __bool__ that raises": _WahrheitWirftProtokoll}
        for weg, aufruf in wege.items():
            for name, bau in werte.items():
                with self.subTest(weg=weg, wert=name):
                    flagge = bau()
                    _AUFRUFE.clear()
                    try:
                        with self.assertRaises(ProofBundleError) as ctx:
                            aufruf(flagge)
                    finally:
                        gesehen = list(_AUFRUFE)
                        _AUFRUFE.clear()
                    # PR 291's refusal since the 6.2.0 chain carries it (`_membership.require_switch`,
                    # a SwitchTypeError); at the D4 head 7cc8fa0b it read
                    # "<entry>: require_statement_shape must be True or False".
                    self.assertIn("require_statement_shape must be a bool (True or False), not a value "
                                  "of type", str(ctx.exception))
                    self.assertEqual(gesehen, [])

    def test_the_bytes_path_refuses_a_flag_that_is_no_bool_too(self):
        """A change, not a defect of 493c2f86: the bytes path of `statement_content_root` ignored the
        flag there and ran none of its code. It is red there only because the refusal is new."""
        for name, flagge in (('"false"', "false"), ("0", 0), ("None", None)):
            with self.subTest(wert=name):
                with self.assertRaises(ProofBundleError) as ctx:
                    canonical.statement_content_root(b"{}", require_statement_shape=flagge)
                self.assertIn("require_statement_shape must be a bool (True or False), not a value of type",
                              str(ctx.exception))   # PR 291's refusal (see above)

    def test_control_true_and_false_select_the_guard_as_before(self):
        import hashlib  # noqa: PLC0415
        voll = {"_type": "t", "subject": [], "predicateType": "p", "predicate": {}}
        bar = {"predicate": {}}
        for weg, aufruf in (("canonicalize_statement", canonical.canonicalize_statement),
                            ("statement_content_root", canonical.statement_content_root)):
            with self.subTest(weg=weg):
                with self.assertRaises(ProofBundleError) as ctx:
                    aufruf(bar, require_statement_shape=True)
                self.assertIn("missing in-toto Statement key", str(ctx.exception))
                self.assertIsNotNone(aufruf(voll, require_statement_shape=True))
                self.assertEqual(aufruf(bar, require_statement_shape=False), aufruf(bar))
        self.assertEqual(canonical.statement_content_root(b"{}", require_statement_shape=True),
                         hashlib.sha256(b"{}").digest())

    def test_a_check_earns_its_property_only_when_its_ok_is_true(self):
        from proofbundle.errors import Check, VerificationResult  # noqa: PLC0415
        for name, bau in (('"false"', lambda: "false"), ("[0]", lambda: [0]), ("1", lambda: 1),
                          ('"true"', lambda: "true"),
                          ("a recording __bool__ answering True", lambda: _WahrheitProtokoll(True)),
                          ("a recording __bool__ answering False", lambda: _WahrheitProtokoll(False))):
            with self.subTest(ok=name):
                ok = bau()
                ergebnis = VerificationResult([Check("ed25519-signature", ok), Check("merkle-inclusion", ok)])
                _AUFRUFE.clear()
                props = intoto.svr_properties(ergebnis, self.basis)
                gesehen = list(_AUFRUFE)
                _AUFRUFE.clear()
                self.assertNotIn("PROOFBUNDLE_SIGNATURE_VALID", props)
                self.assertNotIn("PROOFBUNDLE_RECEIPT_UNCHANGED", props)
                self.assertEqual(gesehen, [])

    def test_control_true_earns_the_check_properties_and_false_and_zero_do_not(self):
        from proofbundle.errors import Check  # noqa: PLC0415
        from _svr_binding import bound_svr_result  # type: ignore  # noqa: PLC0415
        # Nachtrag 48/48b (F3), updated for Nachtrag 46c: start from a real result bound to this claim, set its
        # checks to the ok value under test, and RE-STAMP. The origin token now covers the checks (N46c), so a
        # result must be stamped over its FINAL checks for svr_properties to read each check's ok (True earns,
        # False/0 do not). Setting checks without re-stamping now invalidates the token — that is the N46c
        # counter-probe, tested in test_security_fix_620_bind_n46c.py.
        for ok, erwartet in ((True, ["PROOFBUNDLE_SIGNATURE_VALID", "PROOFBUNDLE_RECEIPT_UNCHANGED"]),
                             (False, []), (0, [])):
            with self.subTest(ok=ok):
                result, claim = bound_svr_result(self.basis, self.signer)
                result.checks = [Check("ed25519-signature", ok), Check("merkle-inclusion", ok)]
                result.stamp_origin()  # Nachtrag 46c: the token covers the checks, so re-stamp over the set checks
                props = intoto.svr_properties(result, claim)
                self.assertEqual([p for p in props if p in ("PROOFBUNDLE_SIGNATURE_VALID",
                                                            "PROOFBUNDLE_RECEIPT_UNCHANGED")], erwartet)


class _SagtUngleichNie(str):
    """Its `__ne__` answers False and its `__eq__` True, and both record."""

    def __ne__(self, other):
        _merke("__ne__")
        return False

    def __eq__(self, other):
        _merke("__eq__")
        return True

    def __hash__(self):
        _merke("__hash__")
        return hash(">=")


class _ObjektSagtUngleichNie:
    def __ne__(self, other):
        _merke("__ne__")
        return False

    def __eq__(self, other):
        _merke("__eq__")
        return True

    __hash__ = object.__hash__


class _KodiertAlsModell(str):
    """Holds other characters; its `encode` gives the committed identifier's bytes."""

    def encode(self, *args, **kwargs):
        _merke("encode")
        return b"acme/model-x"


class _StrGibt:
    """No string; its `__str__` gives `text`."""

    def __init__(self, text):
        self.text = text

    def __str__(self):
        _merke("__str__")
        return self.text


class TestAStringIsComparedByItsCharacters(_Basis):
    """The sibling lens run 8 named, and the sweep of its class over the entries of this branch: a
    string argument that a check compares was compared through the caller's own `__eq__`, `__ne__`,
    `__hash__`, `encode` or `__str__`. Measured at 493c2f86 and on main 31816e08:
    `decode_eval_claim(expected_context=...)` returned the claim of a receipt bound to another context,
    `build_eval_claim` passed a comparator and an assurance level that are none of its values,
    `verify_commitment` verified a wrong identifier and an object that is no commitment, and
    `check_binds_bundle` bound an SD-JWT to a root it does not carry."""

    def test_expected_context_is_compared_by_its_characters(self):
        from proofbundle.evalclaim import CLAIM_INVALID, classify_eval_claim  # noqa: PLC0415
        gebunden = emit_eval_receipt(dict(self.basis, context_binding="ctx-A"), self.signer)
        ungebunden = emit_eval_receipt(self.basis, self.signer)
        for name, bau, buendel in (
                ("a str subclass holding ctx-B", lambda: _SagtUngleichNie("ctx-B"), gebunden),
                ("an object of another type", _ObjektSagtUngleichNie, gebunden),
                ("a str subclass holding ctx-A, the receipt has no binding",
                 lambda: _SagtUngleichNie("ctx-A"), ungebunden)):
            with self.subTest(fall=name):
                erwartet = bau()
                _AUFRUFE.clear()
                ergebnis = (decode_eval_claim(buendel, expected_context=erwartet),
                            classify_eval_claim(buendel, expected_context=erwartet))
                gesehen = list(_AUFRUFE)
                _AUFRUFE.clear()
                self.assertEqual(ergebnis, (None, (CLAIM_INVALID, None)))
                self.assertEqual(gesehen, [])

    def test_the_swept_strings_are_compared_by_their_characters(self):
        from proofbundle.evalclaim import salted_commit, verify_commitment  # noqa: PLC0415
        from proofbundle.sdjwt_issue import check_binds_bundle  # noqa: PLC0415
        b, s = self.basis, self.signer
        salz = b"0" * 16
        zusage = salted_commit("acme/model-x", salz)
        compact = issue_sd_jwt(b, s, root_b64=ROOT_B64)
        kw = dict(suite="s", suite_version="v1", metric="m", threshold="0.80", score="0.50", n=5,
                  model_id="m", dataset_id="d", issuer=b["issuer"], timestamp="2026-01-01T00:00:00Z",
                  model_salt=b"0" * 16, dataset_salt=b"1" * 16)

        def gebaut(**werte):
            try:
                build_eval_claim(**dict(kw, **werte))
                return "built"
            except EvalClaimError:
                return "refused"
        faelle = (
            ("build_eval_claim comparator holding ==", lambda: gebaut(comparator=_SagtUngleichNie("==")),
             "refused"),
            ("build_eval_claim assurance_level holding bogus",
             lambda: gebaut(comparator=">=", assurance_level=_SagtUngleichNie("bogus")), "refused"),
            ("verify_commitment identifier holding other",
             lambda: verify_commitment(_KodiertAlsModell("other"), salz, zusage), False),
            ("verify_commitment commitment that is no string",
             lambda: verify_commitment("acme/model-x", salz, _StrGibt(zusage)), False),
            ("check_binds_bundle root_b64 holding another root",
             lambda: check_binds_bundle(compact, b, _SagtUngleichNie("d3Jvbmc=")), False),
            ("check_binds_bundle root_b64 that is no string",
             lambda: check_binds_bundle(compact, b, _ObjektSagtUngleichNie()), False))
        for name, lauf, erwartet in faelle:
            with self.subTest(fall=name):
                _AUFRUFE.clear()
                ergebnis = lauf()
                gesehen = list(_AUFRUFE)
                _AUFRUFE.clear()
                self.assertEqual(ergebnis, erwartet)
                self.assertEqual(gesehen, [])

    def test_control_plain_and_honest_strings_are_compared_as_before(self):
        """Green at 493c2f86 too: a plain string and a `str` subclass that compares as `str` give the
        verdict they gave there."""
        from proofbundle.evalclaim import salted_commit, verify_commitment  # noqa: PLC0415
        from proofbundle.sdjwt_issue import check_binds_bundle  # noqa: PLC0415

        class Text(str):
            pass
        b, s = self.basis, self.signer
        gebunden = emit_eval_receipt(dict(b, context_binding="ctx-A"), s)
        for wert, erwartet in (("ctx-A", True), (Text("ctx-A"), True), ("ctx-B", False), ("", False)):
            with self.subTest(expected_context=wert):
                self.assertEqual(decode_eval_claim(gebunden, expected_context=wert) is not None, erwartet)
        claim, _ = build_eval_claim(
            suite="s", suite_version="v1", metric="m", comparator=Text(">="), threshold="0.80",
            score="0.90", n=5, model_id="m", dataset_id="d", issuer=b["issuer"],
            timestamp="2026-01-01T00:00:00Z", assurance_level=Text("reproduced"),
            model_salt=b"0" * 16, dataset_salt=b"1" * 16)
        self.assertEqual((claim["comparator"], claim["assurance_level"], claim["passed"]),
                         (">=", "reproduced", True))
        salz = b"0" * 16
        zusage = salted_commit("acme/model-x", salz)
        for ident, salzwert, commit, erwartet in (
                ("acme/model-x", salz, zusage, True), (Text("acme/model-x"), bytearray(salz), Text(zusage), True),
                ("other", salz, zusage, False)):
            with self.subTest(identifier=ident, salt=type(salzwert).__name__):
                self.assertIs(verify_commitment(ident, salzwert, commit), erwartet)
        compact = issue_sd_jwt(b, s, root_b64=ROOT_B64)
        for wurzel, erwartet in ((ROOT_B64, True), (Text(ROOT_B64), True), ("d3Jvbmc=", False)):
            with self.subTest(root_b64=wurzel):
                self.assertIs(check_binds_bundle(compact, b, wurzel), erwartet)


class TestVerifyCommitmentAnswersABool(_Basis):
    """Written against 6b223d8e, the first commit of round 10, whose report named these two raises as
    not changed. `verify_commitment` checks a presented identifier and salt against a commitment and
    is documented to answer a bool. At 493c2f86, at 6b223d8e and on main 31816e08 a commitment
    holding a character outside ASCII raised a raw TypeError from `hmac.compare_digest`, and an
    identifier holding a lone surrogate raised a raw UnicodeEncodeError from `salted_commit`. Each is
    a fail-closed False now, and no method of the caller runs."""

    def test_an_input_that_cannot_be_encoded_is_false(self):
        from proofbundle.evalclaim import salted_commit, verify_commitment  # noqa: PLC0415
        salz = b"0" * 16
        zusage = salted_commit("acme/model-x", salz)
        akut, surrogat = chr(0xE9), chr(0xD800)
        faelle = (
            ("a commitment with a character outside ASCII", lambda: ("acme/model-x", "sha256:" + akut * 64)),
            ("a commitment with a lone surrogate", lambda: ("acme/model-x", "sha256:" + surrogat)),
            ("a recording str subclass commitment outside ASCII",
             lambda: ("acme/model-x", P[str]("sha256:" + akut * 64))),
            ("an identifier that is a lone surrogate", lambda: (surrogat, zusage)),
            ("an identifier holding a lone surrogate", lambda: ("acme/" + surrogat, zusage)),
            ("a recording str subclass identifier holding a lone surrogate",
             lambda: (P[str]("acme/" + surrogat), zusage)),
        )
        for name, bau in faelle:
            with self.subTest(fall=name):
                kennung, commit = bau()
                _AUFRUFE.clear()
                try:
                    ergebnis = verify_commitment(kennung, salz, commit)
                finally:
                    gesehen = list(_AUFRUFE)
                    _AUFRUFE.clear()
                self.assertIs(ergebnis, False)
                self.assertEqual(gesehen, [])

    def test_control_a_presented_opening_verifies_as_before(self):
        """Green at 6b223d8e too: the right opening is True, a wrong identifier or salt is False, and an
        identifier outside ASCII that UTF-8 can encode verifies against its own commitment."""
        from proofbundle.evalclaim import salted_commit, verify_commitment  # noqa: PLC0415
        salz = b"0" * 16
        zusage = salted_commit("acme/model-x", salz)
        cafe = "caf" + chr(0xE9)
        for name, kennung, salzwert, commit, erwartet in (
                ("right", "acme/model-x", salz, zusage, True),
                ("right, the salt a bytearray", "acme/model-x", bytearray(salz), zusage, True),
                ("wrong identifier", "other", salz, zusage, False),
                ("wrong salt", "acme/model-x", b"1" * 16, zusage, False),
                ("an identifier outside ASCII", cafe, salz, salted_commit(cafe, salz), True)):
            with self.subTest(fall=name):
                self.assertIs(verify_commitment(kennung, salzwert, commit), erwartet)


if __name__ == "__main__":
    unittest.main()
