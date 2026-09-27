"""A caller's resolver promotes a verdict only when it answers the exact ``True``.

The evidence ladder and the renewal anchor take a callable from the caller and used to promote on the
truthiness of its answer: ``bool(evidence_resolver(...))`` in ``classify_digest_evidence``,
``bool(res)`` in ``classify_receiver_corroboration``, and ``bool(verify_anchor(newest))`` in
``verify_sequence``. A resolver that answers ``1``, ``"true"``, ``"false"``, a non-empty list or an
object whose ``__bool__`` says True therefore reached CONTENT_RESOLVED, INDEPENDENTLY_ATTESTED or an
anchored newest ArchiveTimeStamp, although it never said True. The contract of all three is a bool.

Every surface is asked with the same values, directly and through the public verify functions that
pass the resolver on (``verify_decision_receipt``, ``verify_outcome_receipt``). Each such answer must
leave the level where it was, the detail must say why, and the answer's own ``__bool__`` must never run.
The controls show that the exact True still promotes, the exact False still does not, a raising
resolver still does not, and 32 bytes of key material still attest as before.

A fourth surface has the same shape: ``anchors.register_anchor_type`` is a public extension point, so a
registered anchor verifier is caller code, and ``verify_anchor`` read its result with
``bool(res.get("ok"))``, ``bool(res.get("warn"))`` and ``bool(res.get(flag))`` for the three provenance
flags, outside the try, so a result that is not a dict raised a raw AttributeError. It is asked the same
values, directly, through ``verify_anchors(require=...)`` and through
``verify_decision_receipt(anchors=...)``.

Round 2 closes the other half of the same rule: a TYPE CHECK THAT BELIEVES THE ANSWER. The 32-byte branch of
``classify_receiver_corroboration`` asked ``isinstance(res, (bytes, bytearray))``, which believes an object's
own ``__class__``, and then read the object with its own ``__len__`` and ``__bytes__``: an answer claiming to
be bytes, 32 long and ``b""`` reached INDEPENDENTLY_ATTESTED with zero bytes of key material, also through
``verify_outcome_receipt`` (``ok`` true), and a raising ``__len__`` or ``__class__`` or a ``__bytes__``
returning a str escaped both never-raise functions. A real ``bytes`` subclass was read the same way. Key
material now counts only as a plain ``bytes`` or ``bytearray`` object, the key ids only as a plain ``str``,
the expectation only as plain bytes, the digest object only as a plain ``dict`` holding a plain ``str`` (one
whose ``__class__`` raised escaped ``classify_digest_evidence``, which never raises), and the rollups
``evidence_ladder_best`` / ``evidence_ladder_summary`` take a level only as a plain ``int`` or ``EvidenceLevel``. The recording classes below show that none of the
caller's methods runs. The caller-built results and policy dicts of the same class are in
``tests/test_a_caller_verdict_counts_only_as_a_bool.py``.

Round 4 answers a review of 3a8074fc. ``classify_digest_evidence(applicable=)`` read its switch by its truth:
``None``, ``0``, ``""`` and ``[]`` made a weak field not applicable, and ``evidence_ladder_summary`` rose past
it. The switch now counts only as an exact bool; anything else is a ``SwitchTypeError`` (a ``TypeError`` and a
``ProofBundleError``) naming the parameter and the type. And the plain-type checks of round 2 refused an
honest subclass of the documented type: a registered anchor verifier returning an ``OrderedDict`` or a
``defaultdict`` with ``ok`` True was a failed anchor, an ``OrderedDict`` digest object was CLAIMED, and an
``OrderedDict`` field or a level from the caller's own ``IntEnum`` left the AND rollup, which then rose. Each
is now read by what it stores (``dict.get`` and ``int.__int__`` of the base type), so the subclass counts as
the dict or int it is and none of its own methods runs.
"""
from __future__ import annotations

import base64
import collections
import copy
import enum
import hashlib
import json
import types
import unittest
from pathlib import Path

from proofbundle import anchors, dsse
from proofbundle.assurance import (
    EvidenceLevel,
    classify_digest_evidence,
    classify_receiver_corroboration,
    evidence_ladder_best,
    evidence_ladder_summary,
)
from proofbundle.decision import emit_decision_receipt, verify_decision_receipt
from proofbundle.emit import generate_signer
from proofbundle.errors import ProofBundleError
from proofbundle.outcome import (
    emit_outcome_receipt,
    executor_trusted_by_role,
    pack_key_binds_signer,
    receiver_trusted_by_role,
    verify_outcome_receipt,
)
from proofbundle.renewal import build_initial_sequence, verify_sequence

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"
_DIGEST = {"sha256": "a" * 64}
_DATA = [hashlib.sha256(b"a").hexdigest(), hashlib.sha256(b"b").hexdigest()]
#: The words every refusal detail carries.
_WHY = "only the exact True"


class _Truthy:
    """An answer whose truthiness is True and which records every time something asks for it."""

    def __init__(self):
        self.asked = 0

    def __bool__(self):
        self.asked += 1
        return True


def _answers():
    """The answers that are not True, fresh for every use (the object counts its own calls)."""
    return [("int 1", 1), ("str 'true'", "true"), ("str 'false'", "false"),
            ("object with __bool__", _Truthy()), ("non-empty list", [0]), ("float 1.0", 1.0)]


def _keys():
    s = generate_signer()
    return s, s.public_key().public_bytes_raw()


def _outcome(**over) -> dict:
    p = {
        "schemaVersion": "0.1.0", "outcomeId": "outcome-0001", "decisionRef": {"sha256": "e" * 64},
        "executor": {"id": "executor:runner-7", "keyId": "kid-exec"},
        "requestedActionDigest": {"sha256": "b" * 64}, "status": "executed",
        "performedAt": "2026-07-14T10:00:00Z", "effectDigest": {"sha256": "c" * 64},
    }
    p.update(over)
    return p


def _check(result, name):
    return next((c for c in result.checks if c.name == name), None)


class TestTheDigestLadderPromotesOnlyOnTrue(unittest.TestCase):
    def test_an_answer_that_is_not_true_stays_well_formed_and_says_why(self):
        for label, answer in _answers():
            with self.subTest(answer=label):
                r = classify_digest_evidence(_DIGEST, evidence_resolver=lambda d, a=answer: a)
                self.assertEqual(r["level"], EvidenceLevel.REFERENCE_WELL_FORMED)
                self.assertIn(_WHY, r["detail"])
                if isinstance(answer, _Truthy):
                    self.assertEqual(answer.asked, 0, "the answer's own __bool__ ran")

    def test_control_true_promotes_false_and_raise_do_not(self):
        self.assertEqual(classify_digest_evidence(_DIGEST, evidence_resolver=lambda d: True)["level"],
                         EvidenceLevel.CONTENT_RESOLVED)
        r = classify_digest_evidence(_DIGEST, evidence_resolver=lambda d: False)
        self.assertEqual(r["level"], EvidenceLevel.REFERENCE_WELL_FORMED)
        self.assertNotIn(_WHY, r["detail"])

        def _boom(_d):
            raise RuntimeError("resolver failed")
        self.assertEqual(classify_digest_evidence(_DIGEST, evidence_resolver=_boom)["level"],
                         EvidenceLevel.REFERENCE_WELL_FORMED)


class TestTheReceiverLadderAttestsOnlyOnTrue(unittest.TestCase):
    _base = dict(executor_key_id="kid-exec", receiver_key_id="kid-recv")

    def test_an_attestation_answer_that_is_not_true_keeps_the_base_level_and_says_why(self):
        for label, answer in _answers():
            with self.subTest(answer=label):
                r = classify_receiver_corroboration(
                    _DIGEST, evidence_resolver=lambda d: True,
                    independent_attestation_resolver=lambda d, a=answer: a, **self._base)
                self.assertEqual(r["level"], EvidenceLevel.CONTENT_RESOLVED)
                self.assertIn(_WHY, r["detail"])
                if isinstance(answer, _Truthy):
                    self.assertEqual(answer.asked, 0, "the answer's own __bool__ ran")

    def test_an_evidence_answer_that_is_not_true_opens_no_step_above_it(self):
        for label, answer in _answers():
            with self.subTest(answer=label):
                r = classify_receiver_corroboration(
                    _DIGEST, evidence_resolver=lambda d, a=answer: a,
                    independent_attestation_resolver=lambda d: True, **self._base)
                self.assertEqual(r["level"], EvidenceLevel.REFERENCE_WELL_FORMED)
                self.assertIn(_WHY, r["detail"])

    def test_control_true_and_key_material_attest_false_and_raise_do_not(self):
        top = EvidenceLevel.INDEPENDENTLY_ATTESTED
        self.assertEqual(classify_receiver_corroboration(
            _DIGEST, evidence_resolver=lambda d: True, independent_attestation_resolver=lambda d: True,
            **self._base)["level"], top)
        self.assertEqual(classify_receiver_corroboration(
            _DIGEST, evidence_resolver=lambda d: True, independent_attestation_resolver=lambda d: b"k" * 32,
            **self._base)["level"], top)
        r = classify_receiver_corroboration(
            _DIGEST, evidence_resolver=lambda d: True, independent_attestation_resolver=lambda d: False,
            **self._base)
        self.assertEqual(r["level"], EvidenceLevel.CONTENT_RESOLVED)
        self.assertNotIn(_WHY, r["detail"])

        def _boom(_d):
            raise RuntimeError("resolver failed")
        self.assertEqual(classify_receiver_corroboration(
            _DIGEST, evidence_resolver=lambda d: True, independent_attestation_resolver=_boom,
            **self._base)["level"], EvidenceLevel.CONTENT_RESOLVED)


class TestTheRenewalAnchorHoldsOnlyOnTrue(unittest.TestCase):
    def setUp(self):
        self.seq = build_initial_sequence(_DATA, hash_alg="sha256", time=1000)

    def test_an_anchor_answer_that_is_not_true_is_not_anchored_and_says_why(self):
        for label, answer in _answers():
            with self.subTest(answer=label):
                r = verify_sequence(self.seq, _DATA, anchor_verifier=lambda a, x=answer: x)
                c = _check(r, "renewal:last_anchor")
                self.assertIsNotNone(c, [x.name for x in r.checks])
                self.assertIs(c.ok, False)
                self.assertIs(r.ok, False)
                self.assertIn(_WHY, c.detail)
                if isinstance(answer, _Truthy):
                    self.assertEqual(answer.asked, 0, "the answer's own __bool__ ran")

    def test_control_true_anchors_false_does_not(self):
        r = verify_sequence(self.seq, _DATA, anchor_verifier=lambda a: True)
        self.assertIs(_check(r, "renewal:last_anchor").ok, True)
        self.assertIs(r.ok, True)
        r = verify_sequence(self.seq, _DATA, anchor_verifier=lambda a: False)
        c = _check(r, "renewal:last_anchor")
        self.assertIs(c.ok, False)
        self.assertNotIn(_WHY, c.detail)


class TestThePublicVerifiersPassTheRuleOn(unittest.TestCase):
    """The resolvers reach the ladder only through these two functions; the CLI sets none."""

    def _decision(self):
        p = copy.deepcopy(json.loads((EXAMPLES / "decision_receipt_deny.json").read_text(encoding="utf-8")))
        p["evidenceRefs"] = [{"relation": "evalResult", "digest": {"sha256": "b" * 64}}]
        s, pub = _keys()
        return emit_decision_receipt(p, s, strict=True), pub

    def test_decision_evidence_refs(self):
        env, pub = self._decision()
        for label, answer in _answers():
            with self.subTest(answer=label):
                r = verify_decision_receipt(env, pub, strict=True, evidence_resolver=lambda d, a=answer: a)
                self.assertEqual(r["evidence_levels"]["evidenceRefs"]["level"],
                                 EvidenceLevel.REFERENCE_WELL_FORMED)
        r = verify_decision_receipt(env, pub, strict=True, evidence_resolver=lambda d: True)
        self.assertEqual(r["evidence_levels"]["evidenceRefs"]["level"], EvidenceLevel.CONTENT_RESOLVED)

    def test_outcome_effect_and_receiver(self):
        s, pub = _keys()
        env = emit_outcome_receipt(_outcome(receiverRefs=[
            {"relation": "receiverAck", "digest": {"sha256": "d" * 64}, "receiverKeyId": "kid-recv"}]), s)
        for label, answer in _answers():
            with self.subTest(answer=label, resolver="evidence"):
                r = verify_outcome_receipt(env, pub, evidence_resolver=lambda d, a=answer: a)
                self.assertEqual(r["evidence_levels"]["effect"]["level"], EvidenceLevel.REFERENCE_WELL_FORMED)
            with self.subTest(answer=label, resolver="receiver attestation"):
                r = verify_outcome_receipt(env, pub, evidence_resolver=lambda d: True,
                                           receiver_attestation_resolver=lambda d, a=answer: a)
                self.assertEqual(r["evidence_levels"]["receiverRefs"]["level"], EvidenceLevel.CONTENT_RESOLVED)
        r = verify_outcome_receipt(env, pub, evidence_resolver=lambda d: True,
                                   receiver_attestation_resolver=lambda d: True)
        self.assertEqual(r["evidence_levels"]["effect"]["level"], EvidenceLevel.CONTENT_RESOLVED)
        self.assertEqual(r["evidence_levels"]["receiverRefs"]["level"], EvidenceLevel.INDEPENDENTLY_ATTESTED)


class _LyingDict(dict):
    """A result that is a dict subclass whose own ``get`` answers True for every key."""

    def get(self, key, default=None):
        return True


class TestARegisteredAnchorVerifierCountsOnlyOnTrue(unittest.TestCase):
    """``register_anchor_type`` hands ``verify_anchor`` caller code; its answer counts only as the exact True."""

    _TYPE = "test-only-the-exact-true/v1"
    _FLAGS = ("rp_trusted", "needs_rp_trust", "frozenEvidence")

    def setUp(self):
        self.answer = None
        anchors.register_anchor_type(self._TYPE, lambda proof, root, *, frozen, now: self.answer)

    def tearDown(self):
        anchors._VERIFIERS.pop(self._TYPE, None)

    def _anchor(self, root: bytes, target: str = "statement") -> dict:
        return {"type": self._TYPE, "target": target, "canonicalRoot": base64.b64encode(root).decode("ascii"),
                "proof": base64.b64encode(b"proof").decode("ascii")}

    def _one(self, answer):
        self.answer = answer
        root = hashlib.sha256(b"statement").digest()
        return anchors.verify_anchor(self._anchor(root), target_roots={"statement": root})

    def _required(self, answer, *, allow_pending: bool):
        self.answer = answer
        root = hashlib.sha256(b"statement").digest()
        return anchors.verify_anchors([self._anchor(root)], target_roots={"statement": root}, require="any",
                                      allow_pending=allow_pending)

    def test_an_ok_that_is_not_true_is_not_verified_and_says_why(self):
        for label, value in _answers():
            with self.subTest(answer=label):
                out = self._one({"ok": value, "detail": "from the verifier"})
                self.assertIs(out["ok"], False)
                self.assertIs(out["warn"], False)
                self.assertEqual(out["status"], "fail")
                self.assertIn(_WHY, out["detail"])
                self.assertIs(self._required({"ok": value}, allow_pending=False)["require_met"], False)
                if isinstance(value, _Truthy):
                    self.assertEqual(value.asked, 0, "the answer's own __bool__ ran")

    def test_a_warn_that_is_not_true_does_not_turn_a_fail_into_pending(self):
        for label, value in _answers():
            with self.subTest(answer=label):
                out = self._one({"ok": False, "warn": value})
                self.assertIs(out["warn"], False)
                self.assertIn(_WHY, out["detail"])
                res = self._required({"ok": False, "warn": value}, allow_pending=True)
                self.assertIs(res["require_met"], False)
                self.assertEqual(res["status"], "FAIL")
                if isinstance(value, _Truthy):
                    self.assertEqual(value.asked, 0, "the answer's own __bool__ ran")

    def test_a_provenance_flag_that_is_not_true_is_false(self):
        for flag in self._FLAGS:
            for label, value in _answers():
                with self.subTest(flag=flag, answer=label):
                    out = self._one({"ok": False, flag: value})
                    self.assertIs(out[flag], False)
                    self.assertIn(_WHY, out["detail"])
                    if isinstance(value, _Truthy):
                        self.assertEqual(value.asked, 0, "the answer's own __bool__ ran")

    def test_a_result_that_is_not_a_dict_fails_closed_does_not_raise_and_names_its_type(self):
        calls: list = []

        class _ClaimsDict:
            """Not a dict, but its ``__class__`` says ``dict``; its ``get`` answers True for every key."""

            @property
            def __class__(self):
                calls.append("__class__")
                return dict

            def get(self, key, default=None):
                calls.append("get")
                return True

        for label, value, name in (("bool True", True, "bool"), ("None", None, "NoneType"),
                                   ("list of pairs", [("ok", True)], "list"), ("str 'ok'", "ok", "str"),
                                   ("int 1", 1, "int"),
                                   ("read-only mapping with ok True", types.MappingProxyType({"ok": True}),
                                    "mappingproxy"),
                                   ("__class__ says dict, get says True", _ClaimsDict(), "_ClaimsDict")):
            with self.subTest(result=label):
                calls.clear()
                out = self._one(value)
                self.assertIs(out["ok"], False)
                self.assertIs(out["warn"], False)
                self.assertEqual(out["status"], "fail")
                self.assertIn(f"returned a value of type {name}, which is not a dict", out["detail"])
                self.assertIs(self._required(value, allow_pending=True)["require_met"], False)
                self.assertEqual(calls, [], "the result's own methods ran")

    def test_a_dict_subclass_is_read_as_the_dict_it_is(self):
        """N5 (review of 3a8074fc): an OrderedDict or defaultdict with ok True was a failed anchor there,
        whose detail said the verifier returned no result object; main 31816e08 verified it."""

        class _PlainSubclass(dict):
            pass

        for label, make in (("OrderedDict", lambda **kw: collections.OrderedDict(**kw)),
                            ("defaultdict", lambda **kw: collections.defaultdict(str, **kw)),
                            ("a subclass with no method of its own", lambda **kw: _PlainSubclass(**kw))):
            with self.subTest(result=label):
                out = self._one(make(ok=True, status="pass", detail="verified"))
                self.assertIs(out["ok"], True)
                self.assertEqual((out["status"], out["detail"]), ("pass", "verified"))
                self.assertIs(self._required(make(ok=True), allow_pending=False)["require_met"], True)
                out = self._one(make(ok=False, warn=True, rp_trusted="false"))
                self.assertIs(out["ok"], False)
                self.assertIs(out["warn"], True)
                self.assertIs(out["rp_trusted"], False)
                self.assertIn(_WHY, out["detail"])
                self.assertIs(self._required(make(ok=False, warn=True), allow_pending=True)["require_met"], True)
                self.assertIs(self._required(make(ok=False, warn=True), allow_pending=False)["require_met"], False)

    def test_a_dict_subclasss_own_methods_never_decide(self):
        """The other direction: what the subclass STORES decides, and none of its own methods runs."""
        calls: list = []

        class _Lies(dict):
            def get(self, key, default=None):
                calls.append("get")
                return True

            def __getitem__(self, key):
                calls.append("__getitem__")
                return True

            def __contains__(self, key):
                calls.append("__contains__")
                return True

            def __missing__(self, key):
                calls.append("__missing__")
                return True

            def __iter__(self):
                calls.append("__iter__")
                return iter(["ok", "warn"])

            def keys(self):
                calls.append("keys")
                return ["ok", "warn"]

        for label, stored, verified in (("stores ok False", {"ok": False}, False),
                                        ("stores nothing", {}, False),
                                        ("stores ok 'true'", {"ok": "true"}, False),
                                        ("stores ok True", {"ok": True}, True)):
            with self.subTest(result=label):
                calls.clear()
                out = self._one(_Lies(stored))
                self.assertIs(out["ok"], verified)
                self.assertIs(out["warn"], False)
                self.assertIs(self._required(_Lies(stored), allow_pending=True)["require_met"], verified)
                self.assertEqual(calls, [], "the subclass's own methods ran")

    def test_control_exact_bools_behave_as_before(self):
        out = self._one({"ok": True, "detail": "verified"})
        self.assertIs(out["ok"], True)
        self.assertEqual(out["status"], "pass")
        self.assertEqual(out["detail"], "verified")
        self.assertIs(self._required({"ok": True}, allow_pending=False)["require_met"], True)
        out = self._one({"ok": False, "detail": "bad proof"})
        self.assertIs(out["ok"], False)
        self.assertEqual(out["detail"], "bad proof")
        self.assertNotIn(_WHY, out["detail"])
        out = self._one({"ok": False, "warn": True, "status": "pending"})
        self.assertIs(out["warn"], True)
        self.assertEqual(out["status"], "pending")
        self.assertIs(self._required({"ok": False, "warn": True}, allow_pending=True)["require_met"], True)
        self.assertIs(self._required({"ok": False, "warn": True}, allow_pending=False)["require_met"], False)
        out = self._one({"ok": True, "rp_trusted": True, "needs_rp_trust": False, "frozenEvidence": False})
        self.assertEqual((out["rp_trusted"], out["needs_rp_trust"], out["frozenEvidence"]), (True, False, False))
        self.assertNotIn(_WHY, out["detail"])

    def test_control_a_raising_verifier_is_a_failed_anchor(self):
        def _boom(proof, root, *, frozen, now):
            raise RuntimeError("verifier failed")
        anchors.register_anchor_type(self._TYPE, _boom)
        root = hashlib.sha256(b"statement").digest()
        out = anchors.verify_anchor(self._anchor(root), target_roots={"statement": root})
        self.assertIs(out["ok"], False)
        self.assertIs(out["warn"], False)
        self.assertEqual(out["status"], "fail")

    def _decision(self):
        p = copy.deepcopy(json.loads((EXAMPLES / "decision_receipt_deny.json").read_text(encoding="utf-8")))
        s, pub = _keys()
        env = emit_decision_receipt(p, s, strict=True)
        return env, pub, anchors.statement_content_root(dsse.load_payload(env))

    def test_decision_receipt_anchors_ok_only_on_true(self):
        env, pub, root = self._decision()
        for label, value in _answers():
            with self.subTest(answer=label, field="ok"):
                self.answer = {"ok": value}
                r = verify_decision_receipt(env, pub, strict=True, anchors=[self._anchor(root)])
                self.assertIs(r["anchors_ok"], False)
                self.assertIs(r["ok"], False)
        for label, value in (("bool True", True), ("None", None), ("dict subclass with its own get",
                                                                   _LyingDict(ok=False))):
            with self.subTest(result=label):
                self.answer = value
                r = verify_decision_receipt(env, pub, strict=True, anchors=[self._anchor(root)])
                self.assertIs(r["anchors_ok"], False)
                self.assertIs(r["ok"], False)
        self.answer = {"ok": True}
        r = verify_decision_receipt(env, pub, strict=True, anchors=[self._anchor(root)])
        self.assertIs(r["anchors_ok"], True)
        self.assertIs(r["ok"], True, "the refusals above must come from the anchor, not from elsewhere")
        self.answer = {"ok": False}
        r = verify_decision_receipt(env, pub, strict=True, anchors=[self._anchor(root)])
        self.assertIs(r["anchors_ok"], False)


# ── round 2: a type check that believes the answer ────────────────────────────────────────────────


class _ClaimsBytes:
    """Not bytes (``type()`` says so), but its ``__class__`` says ``bytes``. Every method records itself."""

    def __init__(self, calls: list, *, payload=b"", length: int = 32, raise_len: bool = False):
        self._calls, self._payload, self._length, self._raise_len = calls, payload, length, raise_len

    @property
    def __class__(self):
        self._calls.append("__class__")
        return bytes

    def __len__(self):
        self._calls.append("__len__")
        if self._raise_len:
            raise RuntimeError("the caller's __len__ raised")
        return self._length

    def __bytes__(self):
        self._calls.append("__bytes__")
        return self._payload

    def __bool__(self):
        self._calls.append("__bool__")
        return True


class _ClaimsStr:
    """Not a str, but its ``__class__`` says ``str``; its ``__eq__`` answers what it is told."""

    def __init__(self, calls: list, *, eq: bool):
        self._calls, self._eq = calls, eq

    @property
    def __class__(self):
        self._calls.append("__class__")
        return str

    def __eq__(self, other):
        self._calls.append("__eq__")
        return self._eq

    def __ne__(self, other):
        self._calls.append("__ne__")
        return not self._eq

    def __hash__(self):
        self._calls.append("__hash__")
        return 0


class _ClaimsInt:
    """Not an int, but its ``__class__`` says ``int``; every comparison says it is neither smaller nor larger."""

    def __init__(self, calls: list):
        self._calls = calls

    @property
    def __class__(self):
        self._calls.append("__class__")
        return int

    def __lt__(self, other):
        self._calls.append("__lt__")
        return False

    def __gt__(self, other):
        self._calls.append("__gt__")
        return False


class _RaisingClass:
    """An object whose ``__class__`` raises when anyone asks for it."""

    def __init__(self, calls: list):
        self._calls = calls

    @property
    def __class__(self):
        self._calls.append("__class__")
        raise RuntimeError("the caller's __class__ raised")


def _bytes_subclass(calls: list):
    class _BytesSubclass(bytes):
        """A real bytes subclass whose own ``__len__`` says 32 whatever it holds."""

        def __len__(self):
            calls.append("__len__")
            return 32
    return _BytesSubclass


def _not_key_material(calls: list, *, pack_key: bytes = b"r" * 32):
    """Answers that are not a plain bytes/bytearray object, each with what it did at 44e12b72."""
    sub = _bytes_subclass(calls)
    return [
        ("__class__ says bytes, 32 long, zero bytes (attested)", _ClaimsBytes(calls, payload=b"")),
        ("__class__ says bytes, carrying the pack key (attested and bound)", _ClaimsBytes(calls, payload=pack_key)),
        ("__class__ says bytes, __len__ raises (escaped)", _ClaimsBytes(calls, raise_len=True)),
        ("__class__ says bytes, __bytes__ returns a str (escaped)", _ClaimsBytes(calls, payload="not bytes")),
        ("__class__ raises (escaped)", _RaisingClass(calls)),
        ("bytes subclass whose __len__ says 32 over zero bytes (attested)", sub(b"")),
        ("bytes subclass carrying the pack key (attested and bound)", sub(pack_key)),
    ]


_RECV_KEY = b"r" * 32


class TestKeyMaterialCountsOnlyAsPlainBytes(unittest.TestCase):
    """An answer attests only as the exact True or as 32 bytes in a plain bytes/bytearray object."""

    _base = dict(executor_key_id="kid-exec", receiver_key_id="kid-recv")

    def _classify(self, answer, **kw):
        return classify_receiver_corroboration(_DIGEST, evidence_resolver=lambda d: True,
                                               independent_attestation_resolver=lambda d: answer,
                                               **self._base, **kw)

    def test_an_answer_that_only_claims_to_be_bytes_attests_nothing_and_runs_nothing(self):
        calls: list = []
        for label, answer in _not_key_material(calls):
            for expected in (None, _RECV_KEY):
                with self.subTest(answer=label, expectation=expected is not None):
                    calls.clear()
                    r = self._classify(answer, expected_receiver_public_key=expected)
                    self.assertEqual(r["level"], EvidenceLevel.CONTENT_RESOLVED)
                    if expected is None:
                        self.assertIn(_WHY, r["detail"])
                    self.assertEqual(calls, [], "the answer's own methods ran")

    def test_through_verify_outcome_receipt_nothing_escapes_and_nothing_binds(self):
        s, pub = _keys()
        env = emit_outcome_receipt(_outcome(receiverRefs=[
            {"relation": "receiverAck", "digest": {"sha256": "d" * 64}, "receiverKeyId": "kid-recv"}]), s)
        pack = {"roles": {"outcomeExecutors": {"keyIds": ["kid-exec"]}, "outcomeReceivers": {"keyIds": ["kid-recv"]}},
                "keys": {"kid-exec": {"publicKey": base64.b64encode(pub).decode("ascii")},
                         "kid-recv": {"publicKey": base64.b64encode(_RECV_KEY).decode("ascii")}}}
        calls: list = []
        for label, answer in _not_key_material(calls):
            for trust_pack in (None, pack):
                with self.subTest(answer=label, trust_pack=trust_pack is not None):
                    calls.clear()
                    r = verify_outcome_receipt(env, pub, evidence_resolver=lambda d: True,
                                               receiver_attestation_resolver=lambda d, a=answer: a,
                                               trust_pack=trust_pack)
                    self.assertEqual(r["evidence_levels"]["receiverRefs"]["level"], EvidenceLevel.CONTENT_RESOLVED)
                    self.assertIsNot(r["receiver_key_bound"], True)
                    self.assertIs(r["ok"], True, r["errors"])
                    self.assertEqual(calls, [], "the answer's own methods ran")

    def test_control_plain_key_material_attests_and_binds_as_before(self):
        for label, answer in (("bytes", _RECV_KEY), ("bytearray", bytearray(_RECV_KEY))):
            with self.subTest(answer=label):
                self.assertEqual(self._classify(answer)["level"], EvidenceLevel.INDEPENDENTLY_ATTESTED)
                self.assertEqual(self._classify(answer, expected_receiver_public_key=_RECV_KEY)["level"],
                                 EvidenceLevel.INDEPENDENTLY_ATTESTED)
                r = self._classify(answer, expected_receiver_public_key=b"x" * 32)
                self.assertEqual(r["level"], EvidenceLevel.CONTENT_RESOLVED)
                self.assertIn("KEY_ID_NOT_BOUND_TO_SIGNER", r["detail"])
        r = self._classify(b"k" * 31)
        self.assertEqual(r["level"], EvidenceLevel.CONTENT_RESOLVED)
        self.assertIn("not a 32-byte Ed25519 key", r["detail"])
        s, pub = _keys()
        env = emit_outcome_receipt(_outcome(receiverRefs=[
            {"relation": "receiverAck", "digest": {"sha256": "d" * 64}, "receiverKeyId": "kid-recv"}]), s)
        pack = {"roles": {"outcomeExecutors": {"keyIds": ["kid-exec"]}, "outcomeReceivers": {"keyIds": ["kid-recv"]}},
                "keys": {"kid-exec": {"publicKey": base64.b64encode(pub).decode("ascii")},
                         "kid-recv": {"publicKey": base64.b64encode(_RECV_KEY).decode("ascii")}}}
        r = verify_outcome_receipt(env, pub, evidence_resolver=lambda d: True,
                                   receiver_attestation_resolver=lambda d: _RECV_KEY, trust_pack=pack)
        self.assertEqual(r["evidence_levels"]["receiverRefs"]["level"], EvidenceLevel.INDEPENDENTLY_ATTESTED)
        self.assertIs(r["receiver_key_bound"], True)
        self.assertIs(r["receiver_role_trusted"], True)
        r = verify_outcome_receipt(env, pub, evidence_resolver=lambda d: True,
                                   receiver_attestation_resolver=lambda d: b"x" * 32, trust_pack=pack)
        self.assertIs(r["receiver_key_bound"], False)
        self.assertEqual(r["evidence_levels"]["receiverRefs"]["level"], EvidenceLevel.CONTENT_RESOLVED)

    def test_an_expectation_that_is_not_plain_bytes_refuses_and_does_not_raise(self):
        calls: list = []
        for label, expected in (("str 'abc' (raised TypeError)", "abc"),
                                ("__class__ says bytes, __bytes__ gives the answer's key (attested)",
                                 _ClaimsBytes(calls, payload=_RECV_KEY))):
            with self.subTest(expectation=label):
                calls.clear()
                r = self._classify(_RECV_KEY, expected_receiver_public_key=expected)
                self.assertEqual(r["level"], EvidenceLevel.CONTENT_RESOLVED)
                self.assertIn("expected_receiver_public_key is not a bytes", r["detail"])
                self.assertEqual(calls, [], "the expectation's own methods ran")


class TestTheKeyIdsCountOnlyAsPlainStr(unittest.TestCase):
    """Independence and role membership are decided on plain str key ids, never by a key id's own ``__eq__``."""

    def _classify(self, executor_key_id, receiver_key_id):
        return classify_receiver_corroboration(_DIGEST, evidence_resolver=lambda d: True,
                                               independent_attestation_resolver=lambda d: True,
                                               executor_key_id=executor_key_id, receiver_key_id=receiver_key_id)

    def test_a_key_id_that_only_claims_to_be_a_str_proves_no_independence(self):
        calls: list = []
        for label, ex, rc in (("receiver key id, __eq__ says False", "kid-exec", _ClaimsStr(calls, eq=False)),
                              ("executor key id, __eq__ says False", _ClaimsStr(calls, eq=False), "kid-recv"),
                              ("receiver key id whose __class__ raises", "kid-exec", _RaisingClass(calls))):
            with self.subTest(key_id=label):
                calls.clear()
                r = self._classify(ex, rc)
                self.assertEqual(r["level"], EvidenceLevel.CONTENT_RESOLVED)
                self.assertIn("independence not provable", r["detail"])
                self.assertEqual(calls, [], "the key id's own methods ran")

    def test_a_role_member_by_a_key_ids_own_eq_is_no_member(self):
        calls: list = []
        pack = {"roles": {"outcomeExecutors": {"keyIds": ["someone-else"]},
                          "outcomeReceivers": {"keyIds": ["someone-else"]}}}
        with self.subTest(surface="receiver_trusted_by_role"):
            calls.clear()
            self.assertIs(receiver_trusted_by_role(_ClaimsStr(calls, eq=True), pack), False)
            self.assertEqual(calls, [])
        with self.subTest(surface="executor_trusted_by_role"):
            calls.clear()
            self.assertIs(executor_trusted_by_role({"keyId": _ClaimsStr(calls, eq=True)}, pack), False)
            self.assertEqual(calls, [])

    def test_pack_key_binds_signer_takes_only_plain_bytes(self):
        calls: list = []
        pack = {"keys": {"kid-recv": {"publicKey": base64.b64encode(_RECV_KEY).decode("ascii")}}}
        for label, key in (("__class__ says bytes, __bytes__ returns a str (raised TypeError)",
                            _ClaimsBytes(calls, payload="not bytes")),
                           ("__class__ says bytes, __bytes__ gives the pack key (bound)",
                            _ClaimsBytes(calls, payload=_RECV_KEY))):
            with self.subTest(public_key=label):
                calls.clear()
                self.assertIs(pack_key_binds_signer("kid-recv", pack, key), False)
                self.assertEqual(calls, [])

    def test_control_plain_key_ids_behave_as_before(self):
        self.assertEqual(self._classify("kid-exec", "kid-recv")["level"], EvidenceLevel.INDEPENDENTLY_ATTESTED)
        self.assertEqual(self._classify("kid-exec", "kid-exec")["level"], EvidenceLevel.CONTENT_RESOLVED)
        self.assertEqual(self._classify("kid-exec", ["kid-exec"])["level"], EvidenceLevel.CONTENT_RESOLVED)
        pack = {"roles": {"outcomeExecutors": {"keyIds": ["kid-exec"]}, "outcomeReceivers": {"keyIds": ["kid-recv"]}},
                "keys": {"kid-recv": {"publicKey": base64.b64encode(_RECV_KEY).decode("ascii")}}}
        self.assertIs(receiver_trusted_by_role("kid-recv", pack), True)
        self.assertIs(receiver_trusted_by_role("kid-other", pack), False)
        self.assertIs(executor_trusted_by_role({"keyId": "kid-exec"}, pack), True)
        self.assertIs(executor_trusted_by_role({"keyId": "kid-other"}, pack), False)
        self.assertIs(pack_key_binds_signer("kid-recv", pack, _RECV_KEY), True)
        self.assertIs(pack_key_binds_signer("kid-recv", pack, bytearray(_RECV_KEY)), True)
        self.assertIs(pack_key_binds_signer("kid-recv", pack, b"x" * 32), False)


class TestTheLadderRollupsTakeOnlyPlainLevels(unittest.TestCase):
    """``evidence_ladder_best`` / ``evidence_ladder_summary`` take a level only as a plain int or EvidenceLevel."""

    def test_a_level_that_only_claims_to_be_an_int_decides_nothing(self):
        calls: list = []
        plain = {"level": EvidenceLevel.CONTENT_RESOLVED, "level_name": "CONTENT_RESOLVED"}
        for name, rollup in (("best", evidence_ladder_best), ("summary", evidence_ladder_summary)):
            for label, field in (("level whose __class__ says int", {"level": _ClaimsInt(calls), "level_name": "X"}),
                                 ("level whose __class__ raises", {"level": _RaisingClass(calls), "level_name": "X"}),
                                 ("field whose __class__ raises", _RaisingClass(calls))):
                with self.subTest(rollup=name, field=label):
                    calls.clear()
                    r = rollup(field, plain)
                    self.assertEqual(r["level"], EvidenceLevel.CONTENT_RESOLVED)
                    self.assertEqual(r["level_name"], "CONTENT_RESOLVED")
                    self.assertEqual(calls, [], "the field's own methods ran")

    def test_a_digest_object_that_only_claims_to_be_a_dict_is_no_digest(self):
        calls: list = []

        class _ClaimsDict:
            @property
            def __class__(self):
                calls.append("__class__")
                return dict

            def get(self, key, default=None):
                calls.append("get")
                return "a" * 64

        for label, digest in (("__class__ says dict, get gives 64 hex (was REFERENCE_WELL_FORMED)", _ClaimsDict()),
                              ("__class__ raises (escaped)", _RaisingClass(calls))):
            for name, classify in (("classify_digest_evidence", lambda d: classify_digest_evidence(
                    d, evidence_resolver=lambda x: True)),
                                   ("classify_receiver_corroboration", lambda d: classify_receiver_corroboration(
                                       d, evidence_resolver=lambda x: True,
                                       independent_attestation_resolver=lambda x: True,
                                       executor_key_id="kid-exec", receiver_key_id="kid-recv"))):
                with self.subTest(digest=label, surface=name):
                    calls.clear()
                    self.assertEqual(classify(digest)["level"], EvidenceLevel.CLAIMED)
                    self.assertEqual(calls, [], "the digest object's own methods ran")

    def test_control_plain_digest_objects_classify_as_before(self):
        self.assertEqual(classify_digest_evidence(_DIGEST)["level"], EvidenceLevel.REFERENCE_WELL_FORMED)
        self.assertEqual(classify_digest_evidence(_DIGEST, evidence_resolver=lambda d: True)["level"],
                         EvidenceLevel.CONTENT_RESOLVED)
        for bad in ({"sha256": "A" * 64}, {"sha256": "a" * 63}, {"sha256": 5}, {}, None, "a" * 64):
            with self.subTest(digest=repr(bad)[:20]):
                self.assertEqual(classify_digest_evidence(bad)["level"], EvidenceLevel.CLAIMED)

    def test_control_plain_levels_roll_up_as_before(self):
        a = {"level": EvidenceLevel.REFERENCE_WELL_FORMED, "level_name": "REFERENCE_WELL_FORMED"}
        b = {"level": 2, "level_name": "CONTENT_RESOLVED"}
        self.assertEqual(evidence_ladder_best(a, b)["level_name"], "CONTENT_RESOLVED")
        self.assertEqual(evidence_ladder_summary(a, b)["level_name"], "REFERENCE_WELL_FORMED")
        self.assertIsNone(evidence_ladder_summary({"level": True}, {"level": None}, 5)["level"])


# ── round 4: the applicable switch, and an honest subclass of the documented type ─────────────────────


def _assert_refused_as_a_switch(test: unittest.TestCase, cm, name: str, type_label: str) -> None:
    """A switch refusal: a TypeError and a ProofBundleError whose message names the parameter and the type."""
    exc = cm.exception
    test.assertIsInstance(exc, TypeError)
    test.assertIsInstance(exc, ProofBundleError)
    test.assertIn(f"{name} must be a bool", str(exc))
    test.assertIn(f"not a value of type {type_label}", str(exc))


class TestApplicableCountsOnlyAsABool(unittest.TestCase):
    """N1 (review of 3a8074fc): ``if not applicable`` read the switch by its truth. ``None``, ``0``, ``""`` and
    ``[]`` made a weak field not applicable, ``evidence_ladder_summary`` ignored it, and the summary of a CLAIMED
    and a CONTENT_RESOLVED field rose to CONTENT_RESOLVED. The switch is now refused unless it is a bool."""

    _WEAK = {"sha256": "not-hex"}

    def _surfaces(self):
        return (("classify_digest_evidence", lambda v: classify_digest_evidence(self._WEAK, applicable=v)),
                ("classify_receiver_corroboration", lambda v: classify_receiver_corroboration(
                    self._WEAK, applicable=v, evidence_resolver=lambda d: True,
                    independent_attestation_resolver=lambda d: True, executor_key_id="kid-exec",
                    receiver_key_id="kid-recv")))

    def test_a_falsy_value_that_is_not_a_bool_is_refused_and_no_weak_field_drops_out(self):
        for label, value, type_label in (("None", None, "NoneType"), ("int 0", 0, "int"), ("str ''", "", "str"),
                                         ("empty list", [], "list")):
            for name, classify in self._surfaces():
                with self.subTest(applicable=label, surface=name):
                    with self.assertRaises(TypeError) as cm:
                        classify(value)
                    _assert_refused_as_a_switch(self, cm, "applicable", type_label)

    def test_a_truthy_value_that_is_not_a_bool_is_refused_and_never_asked(self):
        for label, value in (("str 'false'", "false"), ("str 'no'", "no"), ("int 1", 1), ("list [0]", [0]),
                             ("object with __bool__", _Truthy())):
            for name, classify in self._surfaces():
                with self.subTest(applicable=label, surface=name):
                    with self.assertRaises(TypeError) as cm:
                        classify(value)
                    _assert_refused_as_a_switch(self, cm, "applicable", type(value).__name__)
                    if isinstance(value, _Truthy):
                        self.assertEqual(value.asked, 0, "the switch's own __bool__ ran")

    def test_control_exact_bools_classify_and_roll_up_as_before(self):
        strong = classify_digest_evidence(_DIGEST, evidence_resolver=lambda d: True)
        weak = classify_digest_evidence(self._WEAK, applicable=True)
        self.assertEqual(weak["level"], EvidenceLevel.CLAIMED)
        self.assertEqual(evidence_ladder_summary(weak, strong)["level_name"], "CLAIMED")
        off = classify_digest_evidence(self._WEAK, applicable=False)
        self.assertEqual((off["level"], off["detail"]), (None, "not applicable"))
        self.assertEqual(evidence_ladder_summary(off, strong)["level_name"], "CONTENT_RESOLVED")
        self.assertIsNone(classify_receiver_corroboration(_DIGEST, applicable=False)["level"])
        self.assertEqual(classify_digest_evidence(_DIGEST)["level"], EvidenceLevel.REFERENCE_WELL_FORMED)


class _CallerLevel(enum.IntEnum):
    """A caller's own level scale, an int subclass like EvidenceLevel."""

    LOW = 0
    HIGH = 5


class TestTheLadderReadsAnHonestSubclassAsWhatItStores(unittest.TestCase):
    """At 3a8074fc the rollups and the digest check asked ``type(x) is dict`` and ``type(level) in (int,
    EvidenceLevel)``. An OrderedDict field and a level from the caller's own IntEnum were skipped as not
    applicable, so the AND rollup rose past a CLAIMED field (main 31816e08 said CLAIMED), and an OrderedDict
    digest object was CLAIMED where main said REFERENCE_WELL_FORMED."""

    _STRONG = {"level": EvidenceLevel.CONTENT_RESOLVED, "level_name": "CONTENT_RESOLVED"}

    def test_an_ordered_dict_field_and_a_callers_int_enum_level_count_in_the_rollups(self):
        for label, field, name in (
                ("OrderedDict field, CLAIMED", collections.OrderedDict(level=EvidenceLevel.CLAIMED,
                                                                       level_name="CLAIMED"), "CLAIMED"),
                ("defaultdict field, CLAIMED", collections.defaultdict(str, level=EvidenceLevel.CLAIMED,
                                                                       level_name="CLAIMED"), "CLAIMED"),
                ("level from the caller's IntEnum", {"level": _CallerLevel.LOW, "level_name": "LOW"}, "LOW")):
            with self.subTest(field=label):
                self.assertEqual(evidence_ladder_summary(field, self._STRONG)["level_name"], name)
                self.assertEqual(evidence_ladder_best(field)["level_name"], name)
                self.assertEqual(evidence_ladder_best(field, self._STRONG)["level_name"], "CONTENT_RESOLVED")

    def test_a_subclasss_own_methods_never_decide_the_rollup(self):
        calls: list = []

        class _Lies(dict):
            def get(self, key, default=None):
                calls.append("get")
                return EvidenceLevel.EFFECT_OBSERVED if key == "level" else "EFFECT_OBSERVED"

            def __getitem__(self, key):
                calls.append("__getitem__")
                return EvidenceLevel.EFFECT_OBSERVED

        class _LyingInt(int):
            def __lt__(self, other):
                calls.append("__lt__")
                return False

            def __gt__(self, other):
                calls.append("__gt__")
                return True

            def __int__(self):
                calls.append("__int__")
                return 6

        weak = _Lies(level=EvidenceLevel.CLAIMED, level_name="CLAIMED")
        r = evidence_ladder_summary(weak, self._STRONG)
        self.assertEqual((r["level"], r["level_name"]), (EvidenceLevel.CLAIMED, "CLAIMED"))
        low = {"level": _LyingInt(0), "level_name": "ZERO"}
        self.assertEqual(evidence_ladder_summary(low, self._STRONG)["level_name"], "ZERO")
        self.assertEqual(evidence_ladder_best(low, self._STRONG)["level_name"], "CONTENT_RESOLVED")
        self.assertEqual(calls, [], "the subclass's own methods ran")

    def test_an_ordered_dict_digest_object_is_well_formed_and_runs_nothing(self):
        calls: list = []

        class _Str(str):
            def __eq__(self, other):
                calls.append("__eq__")
                return True

            __hash__ = str.__hash__

        class _LiesAboutTheDigest(dict):
            def get(self, key, default=None):
                calls.append("get")
                return "a" * 64

        for label, digest, level in (
                ("OrderedDict", collections.OrderedDict(sha256="a" * 64), EvidenceLevel.REFERENCE_WELL_FORMED),
                ("a str subclass value", {"sha256": _Str("a" * 64)}, EvidenceLevel.REFERENCE_WELL_FORMED),
                ("a subclass whose get lies over a bad value", _LiesAboutTheDigest(sha256="nope"),
                 EvidenceLevel.CLAIMED)):
            with self.subTest(digest=label):
                calls.clear()
                self.assertEqual(classify_digest_evidence(digest)["level"], level)
                self.assertEqual(calls, [], "the digest object's own methods ran")


if __name__ == "__main__":
    unittest.main()
