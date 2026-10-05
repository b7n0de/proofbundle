"""One reading of the caller's object at every public verify and emit surface (D4 round 12).

SOURCE. Lens run 11 at cd5d39f431ea0cc4732cf64d2d6f23bdc08b1508 found the class of round 11 at
surfaces round 11 did not touch: F1 to F3 (P0), F4 to F7 (P1), and outside its targets O1 (an
expected value compared through the caller's own `__ne__`) and O2 (a switch read by its truth). The
cases F1 to F7 below rebuild the lens's probes (/mnt/bigstore/claude_scratch/lens-d4r11/probe, not
shipped) as tests. The other cases are this round's sweep of the public verify and emit surfaces.

THE PROPERTY. A public verify or emit surface reads the caller's object once, by what it stores,
into a plain copy of exact built-in types, and every check, parse, signature check and write uses
only that copy. No method the caller's object defines runs: not `get`, `__getitem__`, `items` or
`__iter__` of a dict or list subclass, not `encode`, `split`, `__eq__`, `__ne__`, `__hash__`,
`__len__` or a slice of a `str` subclass, not `__bytes__` or `__radd__` of a `bytes` subclass, not
`__eq__` or `__index__` of an `int` subclass. A value that cannot be copied so is refused with the
surface's documented typed error or fail-closed verdict.

Every case in this file was measured RED at cd5d39f4 and GREEN at the head that adds it, on Python
3.10 to 3.14, except `ABytesLikeValueIsReadWhereItWasReadBefore`: that class guards that the copy
narrowed nothing a surface took before, so it is GREEN at both.
"""
from __future__ import annotations

import base64
import copy
import json
import pathlib
import unittest

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from proofbundle import evalclaim as ec
from proofbundle.errors import BundleFormatError, ProofBundleError

# Nachtrag 48/48b: evaluate_decision_policy now binds the result to the statement + signer it judges; the
# decision-policy verdict surface below passes a result stand-in bound to exactly that statement + signer.
from _decision_result_binding import bound_decision_result  # type: ignore  # noqa: E402

_WURZEL = pathlib.Path(__file__).resolve().parents[1]

# Literal seeds: tests/test_sdist_ohne_signierwerkzeug.py allows `from_private_bytes` in a shipped test
# only over a seed written out in the source.
_T = Ed25519PrivateKey.from_private_bytes(b"\x07" * 32)
_E = Ed25519PrivateKey.from_private_bytes(b"\x09" * 32)
_A = Ed25519PrivateKey.from_private_bytes(b"\x0a" * 32)
_W1 = Ed25519PrivateKey.from_private_bytes(b"\x0b" * 32)


def _raw(k) -> bytes:
    return k.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _b64pub(k) -> str:
    return base64.b64encode(_raw(k)).decode("ascii")


def _claim(threshold: str) -> dict:
    claim, _ = ec.build_eval_claim(
        suite="real-suite", suite_version="1", metric="acc", comparator=">=", threshold=threshold,
        score="0.5", n=100, model_id="m", dataset_id="d", issuer="x",
        timestamp="2026-07-09T10:00:00Z", model_salt=b"0" * 16, dataset_salt=b"1" * 16)
    return claim


class _SwapAfter(dict):
    """A dict that stores `source`, and whose own `__getitem__` and `get` answer `forged[field]`
    from read number `after + 1` of that field on. The stored contents never change."""

    def __init__(self, source: dict, forged: dict, after: int = 0) -> None:
        super().__init__(source)
        self.forged, self.after, self.reads = forged, after, {k: 0 for k in forged}

    def __getitem__(self, key):
        if key in self.forged:
            self.reads[key] += 1
            if self.reads[key] > self.after:
                return self.forged[key]
        return dict.__getitem__(self, key)

    def get(self, key, default=None):
        if key in self.forged and dict.__contains__(self, key):
            return self[key]
        return dict.get(self, key, default)


class _EncodesAfter(str):
    """A str that holds `text` and whose own `encode` answers `forged` from call `after + 1` on."""

    def __new__(cls, text: str, forged: str, after: int = 0) -> "_EncodesAfter":
        obj = super().__new__(cls, text)
        obj.forged, obj.after, obj.calls = forged, after, 0
        return obj

    def encode(self, *args, **kwargs):  # type: ignore[override]
        self.calls += 1
        return (str.__str__(self) if self.calls <= self.after else self.forged).encode(*args, **kwargs)


# ─────────────────────────────────────────────────────────────────────────────────────────────────
# The lens's findings F1 to F7 at cd5d39f4.
# ─────────────────────────────────────────────────────────────────────────────────────────────────


def _eval_policy(trusted_roots=None):
    from proofbundle.policy import load_policy  # noqa: PLC0415
    merkle = {"required_hash_alg": "sha256-rfc6962"}
    if trusted_roots is not None:
        merkle["trusted_roots"] = trusted_roots
    return load_policy({"schema": "proofbundle/trust-policy/v0.1", "policy_id": "p",
                        "allowed_schema_versions": ["proofbundle/v0.1"],
                        "allowed_issuers": [{"issuer": "T", "public_key_b64": _b64pub(_T), "kid": "t"}],
                        "signature": {"allowed_algs": ["ed25519"], "require_expected_signer": True},
                        "merkle": merkle, "assurance": {"minimum_level": "self_attested"}})


class F1ThePolicyJudgesTheBundleThatWasVerified(unittest.TestCase):
    """PROPERTY: `evaluate_policy` judges the signer and the root of the bundle `verify_bundle`
    verified. P0 (lens run 11, F1). At cd5d39f4 the signer pin (policy.py:802, :850) and the stated
    root (:942) were read through the caller's own `get`, while `verify_bundle` read what the bundle
    stores: a bundle signed by E, which the policy does not trust, passed a policy that trusts only T."""

    def setUp(self) -> None:
        self.bundle = ec.emit_eval_receipt(_claim("0.10"), _E)

    def _urteil(self, bundle, policy):
        from proofbundle.bundle import verify_bundle  # noqa: PLC0415
        from proofbundle.policy import evaluate_policy  # noqa: PLC0415
        return evaluate_policy(bundle, verify_bundle(bundle), policy)

    def test_a_dict_subclass_naming_the_trusted_key_in_its_own_get(self) -> None:
        # Controls: the plain bundle signed by E fails the policy, one signed by T passes it.
        self.assertIs(self._urteil(copy.deepcopy(self.bundle), _eval_policy())["policy_ok"], False)
        self.assertIs(self._urteil(ec.emit_eval_receipt(_claim("0.10"), _T), _eval_policy())["policy_ok"], True)
        signatur = dict(self.bundle["signature"], public_key_b64=_b64pub(_T))
        traeger = _SwapAfter(copy.deepcopy(self.bundle), {"signature": signatur})
        self.assertIsNot(self._urteil(traeger, _eval_policy())["policy_ok"], True,
                         "policy_ok True for a bundle the trusted key never signed")

    def test_a_key_string_whose_own_eq_and_hash_claim_the_trusted_key(self) -> None:
        t_b64 = _b64pub(_T)

        class _BehauptetGleich(str):
            def __eq__(self, other):
                return True if other == t_b64 else str.__eq__(self, other)

            def __hash__(self):
                return hash(t_b64)

        traeger = copy.deepcopy(self.bundle)
        traeger["signature"] = dict(traeger["signature"])
        traeger["signature"]["public_key_b64"] = _BehauptetGleich(self.bundle["signature"]["public_key_b64"])
        self.assertIsNot(self._urteil(traeger, _eval_policy())["policy_ok"], True,
                         "policy_ok True for a key string that only claims to be the trusted key")

    def test_a_dict_subclass_answering_a_trusted_root_in_its_own_get(self) -> None:
        x = ec.emit_eval_receipt(_claim("0.10"), _T)
        y = ec.emit_eval_receipt(dict(_claim("0.20"), suite="other-suite"), _T)
        policy = _eval_policy(trusted_roots=[x["merkle"]["root_b64"]])
        self.assertIs(self._urteil(copy.deepcopy(y), policy)["policy_ok"], False)
        traeger = _SwapAfter(copy.deepcopy(y), {"merkle": x["merkle"]})
        urteil = self._urteil(traeger, policy)
        self.assertIsNot(urteil["policy_ok"], True, "policy_ok True for a root the policy does not trust")
        self.assertIsNot(urteil["root_authenticated"], True)


def _agt_receipt() -> dict:
    from proofbundle.adapters import agt_receipt as agt  # noqa: PLC0415
    r = {"agent_did": "did:x", "args_hash": "a" * 64, "cedar_decision": "allow", "cedar_policy_id": "p",
         "receipt_id": "r1", "timestamp": 2000, "tool_name": "t", "assurance_level": "externally_authorized",
         "authorizer_id": "auth", "authorization_expires_at": 1500, "authorization_nonce": "n",
         "authorizer_public_key": _raw(_A).hex(), "signer_public_key": _raw(_T).hex()}
    r["signature"] = _T.sign(agt.canonical_payload(r)).hex()
    r["authorization_signature"] = _A.sign(agt.canonical_authorization_payload(r)).hex()
    return r


class F2TheAgtExpiryIsJudgedAtTheSignedTimestamp(unittest.TestCase):
    """PROPERTY: `verify_agt_receipt` judges the expiry at the timestamp the signature covers. P0
    (lens run 11, F2). At cd5d39f4 the signature covered `receipt[f]` and the expiry was judged at
    `receipt.get("timestamp")`: an externally authorized receipt expired at its own signed timestamp
    gave ok True for a dict subclass whose own `get` answered an earlier instant."""

    def test_an_expired_authorization_stays_expired(self) -> None:
        from proofbundle.adapters.agt_receipt import verify_agt_receipt  # noqa: PLC0415
        r = _agt_receipt()
        vertraut = [_raw(_A).hex()]
        self.assertIs(verify_agt_receipt(copy.deepcopy(r), trusted_authorizer_keys=vertraut).ok, False)

        class _FrueherePunkt(dict):
            def get(self, key, default=None):
                return 1000 if key == "timestamp" else dict.get(self, key, default)

        self.assertIs(verify_agt_receipt(_FrueherePunkt(copy.deepcopy(r)),
                                         trusted_authorizer_keys=vertraut).ok, False,
                      "ok True for an authorization that expired before the signed timestamp")


class F3TheCheckpointFieldsComeFromTheSignedText(unittest.TestCase):
    """PROPERTY: `verify_checkpoint` returns the fields of the text the signature covers. P0 (lens
    run 11, F3; re-measured by the coordinator). At cd5d39f4 the note text was the caller's own slice
    (`_split_signed_note`: `signed_note[:split+1]`): the signature was checked over its `encode()`
    and the fields parsed from its characters, and a str subclass gave ok True with tree size 999 for
    a note signed with tree size 5."""

    def test_a_str_subclass_cannot_hand_out_another_text(self) -> None:
        from proofbundle import checkpoint as cp  # noqa: PLC0415
        origin = "example.org/log"
        echt = cp.sign_checkpoint(origin, 5, b"\x11" * 32, _T, origin)
        vk = cp.vkey(origin, _raw(_T))
        signiert = echt[:echt.rfind("\n\n") + 1]
        falsch = cp.checkpoint_note(origin, 999, b"\x22" * 32)
        self.assertEqual(cp.verify_checkpoint(echt, vk)["tree_size"], 5)
        self.assertIs(cp.verify_checkpoint(falsch + echt[len(signiert):], vk)["ok"], False)

        class _Gefaelscht(str):
            def encode(self, *a, **k):  # type: ignore[override]
                return str.encode(signiert, *a, **k)

        class _Traeger(str):
            def __getitem__(self, i):
                teil = str.__getitem__(self, i)
                if isinstance(i, slice) and teil == signiert:
                    return _Gefaelscht(falsch)
                return teil

        try:
            res = cp.verify_checkpoint(_Traeger(echt), vk)
        except BundleFormatError:
            return
        if res["ok"]:
            self.assertEqual((res["tree_size"], res["root"]), (5, b"\x11" * 32),
                             "ok True with fields of a text the signature does not cover")


class F4ThePublishedValueIsCheckedAgainstTheVerifiedPayload(unittest.TestCase):
    """PROPERTY: `to_eval_results_entry` decides whether the payload is an eval claim from the payload
    it verified. P1 (lens run 11, F4). At cd5d39f4 hf_evals.py:274 read `bundle["payload_b64"]` a
    third time through the caller's object, and an eval claim that does not decode was published with
    a value the signed verdict contradicts when that read answered a payload that is no eval claim."""

    def setUp(self) -> None:
        from proofbundle.emit import emit_bundle  # noqa: PLC0415
        anderer = Ed25519PrivateKey.from_private_bytes(b"\x08" * 32)
        claim = dict(_claim("0.80"), issuer="ed25519:" + _b64pub(anderer))   # does not decode
        self.bundle = emit_bundle(ec.canonicalize(claim), _T)
        self.fremd = base64.b64encode(b'{"x": 1}').decode("ascii")

    def _baue(self, bundle):
        from proofbundle import hf_evals  # noqa: PLC0415
        return hf_evals.to_eval_results_entry(bundle, dataset_id="d", task_id="t", value=0.95)

    def test_a_dict_subclass(self) -> None:
        with self.assertRaises(BundleFormatError):   # control: the plain bundle is refused
            self._baue(copy.deepcopy(self.bundle))
        for after in range(3):
            with self.subTest(after=after):
                with self.assertRaises(BundleFormatError):
                    self._baue(_SwapAfter(copy.deepcopy(self.bundle), {"payload_b64": self.fremd}, after))

    def test_a_str_subclass_in_the_payload(self) -> None:
        for after in range(3):
            with self.subTest(after=after):
                b = copy.deepcopy(self.bundle)
                b["payload_b64"] = _EncodesAfter(self.bundle["payload_b64"], self.fremd, after)
                with self.assertRaises(BundleFormatError):
                    self._baue(b)


class F5TheWrittenTokenIsTheBundleThatWasJudged(unittest.TestCase):
    """PROPERTY: the `verifyToken` an entry carries holds the bundle that was verified and judged. P1
    (lens run 11, F5). At cd5d39f4 `receipt_token` serialized through `json.dumps`, which reads a dict
    subclass through its own `items()`, and wrote another receipt than the one judged."""

    def test_the_token_holds_the_verified_bundle(self) -> None:
        from proofbundle import hf_evals  # noqa: PLC0415
        a = ec.emit_eval_receipt(_claim("0.10"), _T)
        signiert = ec.decode_eval_claim(a)
        b = dict(a, payload_b64=base64.b64encode(ec.canonicalize(dict(signiert, suite="forged-suite"))).decode())

        class _ItemsLuegt(dict):
            def items(self):
                return dict.items(b)

        for name, eingabe in (("plain", copy.deepcopy(a)), ("dict subclass", _ItemsLuegt(copy.deepcopy(a)))):
            with self.subTest(carrier=name):
                try:
                    e = hf_evals.to_eval_results_entry(eingabe, dataset_id="d", task_id="t", value=0.95)
                except ProofBundleError:
                    continue
                _, token_bundle = hf_evals.verify_receipt_token(e["verifyToken"])
                self.assertEqual(token_bundle, a, "the token holds another bundle than the one judged")


class F6TheChainOrderComesFromTheVerifiedPayload(unittest.TestCase):
    """PROPERTY: `resolve_receipt_chain` orders the receipts by the claims of the payload whose digest
    the caller verified. P1 (lens run 11, F6; named P1 by the lens branch's review at 7753961d, 6.2).
    At cd5d39f4 the digest came from one read of the caller's envelope and the supersession claims
    from another."""

    def setUp(self) -> None:
        from proofbundle import agent_review as ar  # noqa: PLC0415
        pfad = (_WURZEL / "conformance" / "agent_review"
                / "agent-review-positive-control-supersession-names-the-current-receipt" / "chain.json")
        self.e1, self.e2 = json.loads(pfad.read_text(encoding="utf-8"))["envelopes"]
        self.d1, self.d2 = ar.receipt_digest(self.e1), ar.receipt_digest(self.e2)

        def neu(env, sup):
            st = json.loads(base64.b64decode(env["payload"]))
            if sup is None:
                st["predicate"].pop("supersession", None)
            else:
                st["predicate"]["supersession"] = sup
            return base64.b64encode(json.dumps(st, sort_keys=True, separators=(",", ":")).encode()).decode()

        self.f1 = neu(self.e1, {"supersedes": [{"priorDigest": {"sha256": self.d2}, "reason": "unsigned"}]})
        self.f2 = neu(self.e2, None)

    def test_dict_and_str_subclasses(self) -> None:
        from proofbundle import agent_review as ar  # noqa: PLC0415
        res = ar.resolve_receipt_chain([copy.deepcopy(self.e1), copy.deepcopy(self.e2)],
                                       verified={self.d1, self.d2})
        self.assertEqual(res["current"], self.d2)   # control: the plain chain names E2 current
        a = copy.deepcopy(self.e1)
        b = copy.deepcopy(self.e2)
        a["payload"] = _EncodesAfter(self.e1["payload"], self.f1, 1)
        b["payload"] = _EncodesAfter(self.e2["payload"], self.f2, 1)
        for name, kette in (("dict subclass", [_SwapAfter(self.e1, {"payload": self.f1}, 1),
                                               _SwapAfter(self.e2, {"payload": self.f2}, 1)]),
                            ("str subclass", [a, b])):
            with self.subTest(carrier=name):
                res = ar.resolve_receipt_chain(kette, verified={self.d1, self.d2})
                self.assertEqual(res["current"], self.d2, "the order follows a claim nobody signed")
                self.assertNotIn(self.d2, res["corrected"])


class F7TheTokenCapBoundsWhatIsDecoded(unittest.TestCase):
    """PROPERTY: `verify_receipt_token` measures and decodes the same characters, and runs no method
    of the caller's string. P1 (lens run 11, F7). At cd5d39f4 the pre-decode cap counted the caller's
    own `len()` and the decode read the caller's own slice: a str subclass reporting 12 characters
    handed out 64 MiB to decode."""

    def test_no_method_of_the_callers_token_runs(self) -> None:
        from proofbundle import hf_evals  # noqa: PLC0415
        aufrufe: list = []

        class _Token(str):
            def __len__(self):
                aufrufe.append("__len__")
                return 12

            def __getitem__(self, i):
                aufrufe.append("__getitem__")
                return "A" * 4096 if isinstance(i, slice) else str.__getitem__(self, i)

            def startswith(self, *a):  # type: ignore[override]
                aufrufe.append("startswith")
                return str.startswith(self, *a)

        with self.assertRaises(BundleFormatError):
            hf_evals.verify_receipt_token(_Token("pb1.AAAA"))
        self.assertEqual(aufrufe, [], "the cap and the decode read the caller's own methods")


# ─────────────────────────────────────────────────────────────────────────────────────────────────
# O1 and its siblings: an expected value the caller supplies is compared by its characters.
# ─────────────────────────────────────────────────────────────────────────────────────────────────


def _luegt_gleich(wahr: str):
    """A str holding `wahr`, whose own `__eq__` and `__ne__` claim equality with every string."""

    class _Luegt(str):
        def __eq__(self, other):
            return True

        def __ne__(self, other):
            return False

        def __hash__(self):
            return str.__hash__(self)

    return _Luegt(wahr)


class O1AnExpectedValueIsComparedByItsCharacters(unittest.TestCase):
    """PROPERTY (round 10, `canonical._zeichen_von`): an expected value the caller supplies is compared
    by the characters it holds, so its own `__eq__` and `__ne__` never decide a binding. Lens run 11,
    O1 and the siblings it named by reading; each case gave the binding for another value at cd5d39f4."""

    def test_agent_review_expected_subject_digest(self) -> None:
        from proofbundle import agent_review as ar  # noqa: PLC0415
        pfad = (_WURZEL / "conformance" / "agent_review"
                / "agent-review-v02-positive-control-current-v02-is-marked-current" / "envelope.json")
        praedikat = json.loads(base64.b64decode(json.loads(pfad.read_text(encoding="utf-8"))["payload"]))["predicate"]
        umschlag = ar.emit_agent_review(praedikat, _T)
        res = ar.verify_agent_review_v02(umschlag, _raw(_T), expected_subject_digest=_luegt_gleich("f" * 64))
        self.assertNotEqual(res["expected_subject_match"], "MATCH")
        self.assertIs(res["ok"], False)

    def _decision(self):
        from proofbundle.decision import emit_decision_receipt  # noqa: PLC0415
        praedikat = json.loads((_WURZEL / "examples" / "decision_receipt_allow.json").read_text(encoding="utf-8"))
        return emit_decision_receipt(praedikat, _T)

    def test_decision_expected_nonce_and_audience(self) -> None:
        from proofbundle.decision import verify_decision_receipt  # noqa: PLC0415
        umschlag = self._decision()
        res = verify_decision_receipt(umschlag, _raw(_T), expected_nonce=_luegt_gleich("another-nonce"))
        self.assertIs(res["nonce_ok"], False)
        res = verify_decision_receipt(umschlag, _raw(_T), expected_audience=_luegt_gleich("another-rp"))
        self.assertIs(res["audience_ok"], False)

    def test_outcome_expected_decision_ref(self) -> None:
        from proofbundle.outcome import emit_outcome_receipt, verify_outcome_receipt  # noqa: PLC0415
        praedikat = {"schemaVersion": "0.1.0", "outcomeId": "outcome-0001", "decisionRef": {"sha256": "a" * 64},
                     "executor": {"id": "executor:runner-7", "keyId": "kid-exec"},
                     "requestedActionDigest": {"sha256": "c" * 64}, "status": "executed",
                     "performedAt": "2026-07-14T10:00:00Z", "effectDigest": {"sha256": "c" * 64}}
        umschlag = emit_outcome_receipt(praedikat, _T)
        res = verify_outcome_receipt(umschlag, _raw(_T), expected_decision_ref=_luegt_gleich("b" * 64))
        self.assertIs(res["decision_bound"], False)

    def test_statuslist_expected_uri(self) -> None:
        from proofbundle.statuslist import issue_status_list_token, verify_status_snapshot  # noqa: PLC0415
        token = issue_status_list_token([0, 1], uri="https://example.org/list/1", signer=_T, iat=1000)
        res = verify_status_snapshot(token, expected_uri=_luegt_gleich("https://example.org/other"), index=0,
                                     issuer_pubkey=_raw(_T))
        self.assertIs(res["ok"], False)

    def test_checkpoint_expected_origin(self) -> None:
        from proofbundle import checkpoint as cp  # noqa: PLC0415
        origin = "example.org/log"
        note = cp.sign_checkpoint(origin, 5, b"\x11" * 32, _T, origin)
        note = cp.cosign_checkpoint(note, _W1, "witness.example", 1000)
        res = cp.verify_witnessed_checkpoint(note, cp.vkey(origin, _raw(_T)),
                                             [cp.cosign_vkey("witness.example", _raw(_W1))],
                                             expected_origin=_luegt_gleich("another.example/log"))
        self.assertIs(res["log_ok"], False)

    def test_public_transparency_expected_root(self) -> None:
        from proofbundle import checkpoint as cp  # noqa: PLC0415
        from proofbundle.public_transparency import evaluate_public_transparency  # noqa: PLC0415
        origin = "example.org/log"
        note = cp.sign_checkpoint(origin, 5, b"\x11" * 32, _T, origin)
        res = evaluate_public_transparency(note, {"requireSignedCheckpoint": True}, log_vkey=cp.vkey(origin, _raw(_T)),
                                           expected_root_b64=_luegt_gleich(base64.b64encode(b"\x22" * 32).decode()))
        self.assertEqual(res["statuses"]["ROOT_BYTES_AUTHENTICITY"], "FAIL")


class O2ADecisionPolicySwitchIsABool(unittest.TestCase):
    """PROPERTY (`canonical._flagge`): `decision_receipt.allow_pending` is True or False. Lens run 11,
    O2: at cd5d39f4 `evaluate_decision_policy` read it by its truth when the policy skipped
    `load_policy`, so "false" let a pending anchor satisfy `require_external_anchor`."""

    def test_the_string_false_does_not_accept_a_pending_anchor(self) -> None:
        from proofbundle.policy import evaluate_decision_policy  # noqa: PLC0415
        praedikat = json.loads((_WURZEL / "examples" / "decision_receipt_allow.json").read_text(encoding="utf-8"))
        statement = {"predicate": praedikat, "predicateType": "x"}
        # Nachtrag 48/48b: evaluate_decision_policy binds the result to the statement + signer; pass one bound to
        # exactly this statement and signer "x" so the allow_pending/anchor rule under test is still reached.
        bound = bound_decision_result(statement, "x")
        for wert, erwartet in ((False, False), (True, True)):
            policy = {"schema": "proofbundle/trust-policy/v0.2", "policy_id": "p",
                      "decision_receipt": {"require_external_anchor": True, "allow_pending": wert}}
            res = evaluate_decision_policy(statement, bound, policy, signer_public_key_b64="x", anchor_status="WARN")
            self.assertIs(res["policy_ok"], erwartet)
        for wert in ("false", "no", 1, [0]):
            with self.subTest(allow_pending=wert):
                policy = {"schema": "proofbundle/trust-policy/v0.2", "policy_id": "p",
                          "decision_receipt": {"require_external_anchor": True, "allow_pending": wert}}
                res = evaluate_decision_policy(statement, bound, policy, signer_public_key_b64="x",
                                               anchor_status="WARN")
                self.assertIs(res["policy_ok"], False)



# ─────────────────────────────────────────────────────────────────────────────────────────────────
# The sweep's verdict-level cases: what a reading through the caller's own methods changed.
# ─────────────────────────────────────────────────────────────────────────────────────────────────


class APinnedKeyIsTheKeyTheRuleJudged(unittest.TestCase):
    """PROPERTY: `verify_ed25519_pinned` checks the signature under the key its trust-anchor rule
    judged. At cd5d39f4 the rule and the check each called `bytes()` of the caller's key, and a
    `bytes` subclass whose own `__bytes__` answered a sound key to the rule and the identity point to
    the check verified the signature (R = identity, S = 0) that verifies under the identity point for
    every message, with no private key."""

    def test_the_identity_point_cannot_hide_behind_a_sound_key(self) -> None:
        from proofbundle.signature import verify_ed25519_pinned  # noqa: PLC0415
        identitaet = b"\x01" + b"\x00" * 31
        faelschung = identitaet + b"\x00" * 32
        self.assertIs(verify_ed25519_pinned(identitaet, faelschung, b"any message"), False)
        solide = _raw(_T)

        class _Wechselt(bytes):
            def __new__(cls):
                obj = super().__new__(cls, solide)
                obj.aufrufe = 0
                return obj

            def __bytes__(self):
                self.aufrufe += 1
                return solide if self.aufrufe == 1 else identitaet

        self.assertIs(verify_ed25519_pinned(_Wechselt(), faelschung, b"any message"), False,
                      "a signature made with no private key verified under a pinned key")


class AWitnessQuorumCountsKeysByWhatTheVkeyHolds(unittest.TestCase):
    """PROPERTY: `witness_quorum` counts distinct witness KEY MATERIAL as the vkey holds it. At cd5d39f4
    the key material was read through the roster entry's own `split`, so one witness listed twice as a
    `str` subclass answering another key there counted as two and met a threshold of 2."""

    def test_one_witness_is_one_witness(self) -> None:
        import inspect  # noqa: PLC0415

        from proofbundle import checkpoint as cp  # noqa: PLC0415
        origin = "example.org/log"
        note = cp.sign_checkpoint(origin, 5, b"\x11" * 32, _T, origin)
        note = cp.cosign_checkpoint(note, _W1, "witness.example", 1000)
        echt = cp.cosign_vkey("witness.example", _raw(_W1))
        self.assertEqual(cp.witness_quorum(note, [echt, echt], 2, log_key_material=None)[0], False)

        class _Anderes(str):
            def split(self, *a, **k):  # type: ignore[override]
                teile = str.split(self, *a, **k)
                if inspect.currentframe().f_back.f_code.co_name == "_witness_key_material":
                    return teile[:2] + [base64.b64encode(bytes([4]) + bytes([self.nummer]) * 32).decode()]
                return teile

        a, b = _Anderes(echt), _Anderes(echt)
        a.nummer, b.nummer = 1, 2
        self.assertIs(cp.witness_quorum(note, [a, b], 2, log_key_material=None)[0], False,
                      "one witness met a quorum of two")


class TheEvidencePackBudgetBoundsTheProofThatIsDecoded(unittest.TestCase):
    """PROPERTY: `verify_evidence_pack` decodes the proof the structural budget bounded. At cd5d39f4
    the budget walked what the pack stores and `pack["proof"]` then read the pack's own `__getitem__`,
    so a proof the budget never saw was decoded and judged."""

    def test_the_proof_judged_is_the_proof_stored(self) -> None:
        if not _ots_vorhanden():
            self.skipTest("needs proofbundle[anchors] (opentimestamps) — NOT MEASURABLE here, did NOT run")
        import hashlib  # noqa: PLC0415

        from opentimestamps.core.notary import PendingAttestation  # noqa: PLC0415
        from opentimestamps.core.op import OpSHA256  # noqa: PLC0415
        from opentimestamps.core.serialize import BytesSerializationContext  # noqa: PLC0415
        from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp  # noqa: PLC0415

        from proofbundle.evidence_pack import build_evidence_pack, verify_evidence_pack  # noqa: PLC0415

        wurzel = hashlib.sha256(b"one-reading-pack-root").digest()
        ts = Timestamp(wurzel)
        ts.attestations.add(PendingAttestation("https://alice.btc.calendar.opentimestamps.org"))
        ctx = BytesSerializationContext()
        DetachedTimestampFile(OpSHA256(), ts).serialize(ctx)
        pack = build_evidence_pack(wurzel, ctx.getbytes())
        erwartet = verify_evidence_pack(copy.deepcopy(pack))
        riesig = base64.b64encode(b"\x00" * (6 * 1024 * 1024)).decode()
        gesehen = verify_evidence_pack(_SwapAfter(copy.deepcopy(pack), {"proof": riesig}))
        self.assertEqual(gesehen["status"], erwartet["status"],
                         "the pack judged a proof its budget never bounded")


# ─────────────────────────────────────────────────────────────────────────────────────────────────
# A class claim is no type: an object that is NOT a str, dict, list, bytes or int claims to be one
# through `__class__`. `isinstance` reads that claim and accepts it, so a guard written with it let
# the object through to its own methods after the copy had passed it on unread. Measured on this
# round's tree before the guards read `type()`: F7's cap was bypassed again (64 MiB decoded), and 26
# of the 86 sweep surfaces ran methods of such an object (a probe; the sweep's clock argument then
# stopped `check_freshness` before it read the claim). At cd5d39f4 the sweep below fails for 56
# surfaces on Python 3.10 and 3.11 and for 57 on 3.12 to 3.14, where `emit_bundle` also hashed the
# claimed bytes through their own `__buffer__`.
# ─────────────────────────────────────────────────────────────────────────────────────────────────

_BEHAUPTUNGEN: list = []

_LUEGEN_METHODEN = ("__getitem__", "__iter__", "__len__", "__contains__", "__eq__", "__ne__", "__hash__",
                    "__str__", "__repr__", "__format__", "__bytes__", "__index__", "__int__", "__float__",
                    "__add__", "__radd__", "__lt__", "__le__", "__gt__", "__ge__", "__bool__", "__buffer__",
                    "__mod__", "__mul__", "__and__", "__rshift__", "__lshift__", "__sub__", "__rsub__")


def _behauptet(wert):
    """An object that is not of `wert`'s type but claims it through `__class__`, and answers every
    method from `wert`, recording `<claimed type>.<method>` for each that runs. Values of any other
    type are returned as they are."""
    typ = type(wert)
    if typ not in (dict, list, tuple, str, bytes, int, float):
        return wert
    echt = copy.deepcopy(wert)

    def mache(name):
        def methode(self, *args, **kwargs):
            _BEHAUPTUNGEN.append(f"{typ.__name__}.{name}")
            return getattr(echt, name)(*args, **kwargs)
        return methode

    namensraum = {name: mache(name) for name in _LUEGEN_METHODEN if hasattr(typ, name)}
    namensraum["__class__"] = property(lambda self: typ)

    def __getattr__(self, name):
        _BEHAUPTUNGEN.append(f"{typ.__name__}.{name}")
        return getattr(echt, name)

    namensraum["__getattr__"] = __getattr__
    return type("_Behauptet", (), namensraum)()


class AClassClaimIsNoType(unittest.TestCase):
    """PROPERTY: an object that claims a JSON type through `__class__` without being one is refused
    by its own type, and no method of it runs at a verify or emit surface. The one exception is an
    argument documented as any iterable (a receipt chain, prior leaves, a witness roster): it is read
    once through its own iteration, the only reading such a value has."""

    def test_f7_through_a_class_claim(self) -> None:
        from proofbundle import hf_evals  # noqa: PLC0415
        koerper = "pb1." + "A" * (4 * 1024 * 1024)

        class _Token:
            @property
            def __class__(self):  # noqa: D401 - the claim under test
                return str

            def startswith(self, prefix):
                _BEHAUPTUNGEN.append("str.startswith")
                return koerper.startswith(prefix)

            def __len__(self):
                _BEHAUPTUNGEN.append("str.__len__")
                return 12

            def __getitem__(self, stelle):
                _BEHAUPTUNGEN.append("str.__getitem__")
                return koerper[stelle]

        _BEHAUPTUNGEN.clear()
        with self.assertRaises(BundleFormatError) as fall:
            hf_evals.verify_receipt_token(_Token())
        self.assertIn("not a proofbundle receipt token", str(fall.exception))
        self.assertEqual(_BEHAUPTUNGEN, [], "the cap and the decode read the claim's own methods")

    def test_no_surface_reads_an_object_that_claims_a_type(self) -> None:
        # One iteration of an argument documented as any iterable, at exactly the three surfaces of the
        # sweep that take one (measured: no other surface iterates a claimed list).
        iteration = {"list.__iter__", "list.__len__"}
        erlaubt = {"agent_review.resolve_receipt_chain": iteration,   # the receipts
                   "public_transparency.evaluate_public_transparency": iteration,   # the witness roster
                   "emit.emit_bundle": iteration,   # the prior leaves
                   # the relying party's trusted_authorizer_keys, documented as any iterable read once
                   # through its own iterator by PR 293 (`agt_receipt._vertrauensliste`), which the 6.2.0
                   # chain carries
                   "adapters.agt_receipt.verify_agt_receipt": iteration,
                   "adapters.agt_receipt.verify_agt_receipt_chain": iteration}
        flaechen, aufraeumen = _flaechen()
        self.addCleanup(aufraeumen)
        for name, aufruf in flaechen:
            with self.subTest(surface=name):
                _BEHAUPTUNGEN.clear()
                try:
                    aufruf(_behauptet)
                except Exception:  # noqa: BLE001, S110 - a refusal is a correct answer here
                    pass
                gelaufen = sorted(set(_BEHAUPTUNGEN) - erlaubt.get(name, set()))
                _BEHAUPTUNGEN.clear()
                self.assertEqual(gelaufen, [], f"{name} ran methods of an object that claims a type")


class ABytesLikeValueIsReadWhereItWasReadBefore(unittest.TestCase):
    """PARITY, green at cd5d39f4 and here: a plain copy must not narrow what a surface accepts. The
    Merkle hashes, the DSSE body, the emitted payload, a witness quorum's log key and a relying
    party's expected receiver key took a `memoryview` before (through `b"\\x00" + x` or `==`), and
    take it now as the bytes it views (`canonical._puffer_von`). Measured on this round's tree before
    that helper: the Merkle and DSSE surfaces and `emit_bundle` refused a `memoryview`. Read in the
    same tree, not measured: the quorum and the receiver classifier dropped the key comparison for one
    (fail-open), and a uri that is no string matched a token without `sub`."""

    def test_the_merkle_dsse_and_emit_surfaces(self) -> None:
        from proofbundle import bundle as bm, dsse, emit, merkle  # noqa: PLC0415
        blaetter = [b"a", b"b", b"c"]
        wurzel = merkle.merkle_tree_hash(blaetter)
        beweis = merkle.inclusion_proof(blaetter, 1)
        self.assertEqual(merkle.leaf_hash(memoryview(b"a")), merkle.leaf_hash(b"a"))
        self.assertEqual(merkle.merkle_tree_hash([memoryview(b) for b in blaetter]), wurzel)
        self.assertTrue(merkle.verify_inclusion(memoryview(b"b"), 1, 3, [memoryview(p) for p in beweis], wurzel))
        self.assertEqual(dsse.pae("t", memoryview(b"x")), dsse.pae("t", b"x"))
        umschlag = dsse.sign_envelope(memoryview(b"x"), _T, payload_type="t")
        self.assertTrue(dsse.verify_envelope(umschlag, _raw(_T)))
        self.assertTrue(bm.verify_bundle(emit.emit_bundle(memoryview(b"x"), _T)).ok)

    def test_the_log_key_of_a_witness_quorum(self) -> None:
        import hashlib  # noqa: PLC0415

        from proofbundle import checkpoint as cp  # noqa: PLC0415
        origin = "example.com/one-reading"
        note = cp.sign_checkpoint(origin, 2, hashlib.sha256(b"r").digest(), _T, origin)
        mit_logschluessel = cp.cosign_checkpoint(note, _T, "w.example", 1)
        zeuge = cp.cosign_vkey("w.example", _raw(_T))
        for material in (_raw(_T), memoryview(_raw(_T))):
            with self.subTest(material=type(material).__name__):
                ok, zeugen = cp.witness_quorum(mit_logschluessel, [zeuge], 1, log_key_material=material)
                self.assertFalse(ok, "the log's own key counted as a witness")

    def test_the_expected_receiver_key(self) -> None:
        """Not a parity case any more: since the 6.2.0 chain carries PR 291, key material counts only as
        a plain bytes or bytearray object (`assurance._is_key_material`), the expectation included, so a
        `memoryview` expectation is refused and never compared, and nothing is promoted over it. At the
        D4 head 7cc8fa0b it was compared as the bytes it views (`canonical._puffer_von`). The plain
        bytes are the control."""
        from proofbundle.assurance import EvidenceLevel, classify_receiver_corroboration  # noqa: PLC0415
        empfaenger = Ed25519PrivateKey.from_private_bytes(b"\x0c" * 32)
        basis = dict(digest_obj={"sha256": "d" * 64}, evidence_resolver=lambda d: True,
                     executor_key_id="e", receiver_key_id="r")
        for antwort in (lambda d: _raw(empfaenger), lambda d: _raw(_T), lambda d: True):
            with self.subTest(antwort=antwort):
                res = classify_receiver_corroboration(
                    independent_attestation_resolver=antwort,
                    expected_receiver_public_key=memoryview(_raw(empfaenger)), **basis)
                self.assertEqual(res["level"], EvidenceLevel.CONTENT_RESOLVED)
        gut = classify_receiver_corroboration(
            independent_attestation_resolver=lambda d: _raw(empfaenger),
            expected_receiver_public_key=_raw(empfaenger), **basis)
        self.assertEqual(gut["level"], EvidenceLevel.INDEPENDENTLY_ATTESTED)
        falsch = classify_receiver_corroboration(
            independent_attestation_resolver=lambda d: _raw(_T),
            expected_receiver_public_key=_raw(empfaenger), **basis)
        self.assertEqual(falsch["level"], EvidenceLevel.CONTENT_RESOLVED)

    def test_a_uri_that_is_no_string_never_matches(self) -> None:
        import zlib  # noqa: PLC0415

        from proofbundle import statuslist  # noqa: PLC0415

        def b64url(roh: bytes) -> str:
            return base64.urlsafe_b64encode(roh).rstrip(b"=").decode("ascii")

        kopf = {"alg": "EdDSA", "typ": statuslist.TYP}
        inhalt = {"iat": 1, "status_list": {"bits": 1, "lst": b64url(zlib.compress(b"\x00", 9))}}   # no `sub`
        eingabe = b64url(json.dumps(kopf).encode()) + "." + b64url(json.dumps(inhalt).encode())
        token = eingabe + "." + b64url(_T.sign(eingabe.encode("ascii")))
        res = statuslist.verify_status_snapshot(token, expected_uri=5, index=0, issuer_pubkey=_raw(_T))
        self.assertFalse(res["ok"])
        self.assertIn("sub does not match", res["detail"])


class AKeyThatIsNoBytesNeverBinds(unittest.TestCase):
    """PROPERTY: a relying party's expected receiver key that is no bytes-like value keeps the key
    binding required and never matches. At cd5d39f4 `bytes()` of a str key raised a raw TypeError out
    of a classifier that promises never to raise. Read in this round's tree before the fix, not
    measured: the key was dropped, and a resolver answering True promoted the receiver (fail-open)."""

    def test_a_str_key(self) -> None:
        from proofbundle.assurance import EvidenceLevel, classify_receiver_corroboration  # noqa: PLC0415
        empfaenger = Ed25519PrivateKey.from_private_bytes(b"\x0c" * 32)
        basis = dict(digest_obj={"sha256": "d" * 64}, evidence_resolver=lambda d: True,
                     executor_key_id="e", receiver_key_id="r", expected_receiver_public_key=_b64pub(empfaenger))
        for resolver in (lambda d: _raw(empfaenger), lambda d: True):
            with self.subTest(resolver=resolver):
                res = classify_receiver_corroboration(independent_attestation_resolver=resolver, **basis)
                self.assertEqual(res["level"], EvidenceLevel.CONTENT_RESOLVED)


# ─────────────────────────────────────────────────────────────────────────────────────────────────
# THE SWEEP: every public verify and emit surface, fed the caller's objects as recording subclasses.
# ─────────────────────────────────────────────────────────────────────────────────────────────────

_AUFRUFE: list = []
_PAUSE: list = []


def _merke(art: str, name: str) -> None:
    if not _PAUSE:
        _AUFRUFE.append(f"{art}.{name}")


def _aufzeichnend(basis, art: str, spezial: tuple):
    """A subclass of `basis` that records every attribute read through `__getattribute__` and every
    call of the special methods in `spezial`, then answers as `basis` would. What it answers is always
    what it stores, so a surface that runs its methods still sees the right values; the case measures
    whether the methods run at all."""

    def mache(name):
        def methode(self, *args, **kwargs):
            _merke(art, name)
            return getattr(basis, name)(self, *args, **kwargs)
        methode.__name__ = name
        return methode

    def __getattribute__(self, name):
        _merke(art, name)
        return basis.__getattribute__(self, name)

    namensraum = {"__getattribute__": __getattribute__}
    for name in spezial:
        if hasattr(basis, name):
            namensraum[name] = mache(name)
    return type(f"_Aufzeichnend{basis.__name__.title()}", (basis,), namensraum)


_VERGLEICHE = ("__eq__", "__ne__", "__lt__", "__le__", "__gt__", "__ge__", "__hash__")
_RDict = _aufzeichnend(dict, "dict", ("__getitem__", "__iter__", "__len__", "__contains__", "__reversed__",
                                      "__or__", "__eq__", "__ne__"))
_RList = _aufzeichnend(list, "list", ("__getitem__", "__iter__", "__len__", "__contains__", "__reversed__",
                                      "__add__", "__mul__", "__eq__", "__ne__"))
_RStr = _aufzeichnend(str, "str", ("__getitem__", "__iter__", "__len__", "__contains__", "__add__",
                                   "__radd__", "__mul__", "__mod__", "__format__", "__str__", "__repr__")
                      + _VERGLEICHE)
_RBytes = _aufzeichnend(bytes, "bytes", ("__getitem__", "__iter__", "__len__", "__contains__", "__add__",
                                         "__radd__", "__mul__", "__bytes__", "__buffer__", "__format__",
                                         "__str__", "__repr__") + _VERGLEICHE)
_RInt = _aufzeichnend(int, "int", ("__index__", "__int__", "__float__", "__add__", "__radd__", "__sub__",
                                   "__rsub__", "__mul__", "__rmul__", "__floordiv__", "__rfloordiv__",
                                   "__mod__", "__divmod__", "__and__", "__rand__", "__or__", "__rshift__",
                                   "__lshift__", "__neg__", "__abs__", "__bool__", "__format__", "__str__",
                                   "__repr__") + _VERGLEICHE)
_RFloat = _aufzeichnend(float, "float", ("__float__", "__int__", "__add__", "__radd__", "__sub__",
                                         "__rsub__", "__mul__", "__rmul__", "__bool__", "__format__",
                                         "__str__", "__repr__") + _VERGLEICHE)


def _aufgezeichnet(wert):
    """`wert` rebuilt from recording subclasses: every dict, list, tuple, string, bytes, int and float
    of it (a tuple becomes a recording list, the array JSON writes for it). Building it records
    nothing: the dict keys it hashes on the way are the test's own reads, not the surface's."""
    _PAUSE.append(1)
    try:
        return _baue(wert)
    finally:
        _PAUSE.pop()


def _baue(wert):
    typ = type(wert)
    if typ is dict:
        return _RDict({_baue(k): _baue(v) for k, v in wert.items()})
    if typ is list or typ is tuple:
        return _RList(_baue(v) for v in wert)
    if typ is str:
        return _RStr(wert)
    if typ is bytes:
        return _RBytes(wert)
    # A number stays plain since the 6.2.0 chain carries PR 293: the one copy rule refuses a subclass of
    # int or float (owner decision OA-c7d6ff7121), so a recording number is a refusal at every surface
    # that copies, not a value read by what it holds. `_RInt` and `_RFloat` measured that reading at
    # the D4 head 7cc8fa0b.
    return wert


def _klare_schluessel(wert):
    """`wert`, a dict of the reader's type, with its keys as plain `str`. PR 291, which the 6.2.0 chain
    carries, counts a key of a digest object on the evidence ladder only when it is of type str itself
    (`_membership.stored_str_items`), so a recording key would be no key there and the answer would
    differ by design; the recording values and the recording dict are kept."""
    _PAUSE.append(1)
    try:
        return type(wert)({str.__str__(k): v for k, v in dict.items(wert)})
    finally:
        _PAUSE.pop()


def _klar(wert):
    """A comparable plain form of a surface's result (recording values are read by what they hold)."""
    from proofbundle.errors import VerificationResult  # noqa: PLC0415
    if isinstance(wert, VerificationResult):
        return [(c.name, c.ok, c.detail) for c in wert.checks]
    if issubclass(type(wert), dict):
        return {_klar(k): _klar(v) for k, v in dict.items(wert)}
    if issubclass(type(wert), (list, tuple)):
        return [_klar(v) for v in list.__iter__(list(tuple.__iter__(tuple(wert))))]
    if issubclass(type(wert), str):
        return str.__str__(wert)
    if issubclass(type(wert), bytes):
        return bytes.__getitem__(wert, slice(None))
    if type(wert) is not bool and issubclass(type(wert), int):
        return int.__index__(wert)
    return wert


def _praedikattyp(umschlag) -> str:
    """The predicateType a DSSE in-toto envelope of this package carries (the legitimate expectation)."""
    return json.loads(base64.b64decode(umschlag["payload"]))["predicateType"]


def _flaechen():
    """(name, call): each call takes `w`, the reader of the caller's values (a deep copy, or the
    recording rebuild), and runs one public surface on a LEGITIMATE input built from this package's
    own emitters and fixtures. Keys are signers, not caller values, and are passed unwrapped."""
    from datetime import datetime, timezone  # noqa: PLC0415

    from cryptography.hazmat.primitives.asymmetric import ec as _ec  # noqa: PLC0415

    from proofbundle import (agent_review as ar, anchors, bundle as bm, checkpoint as cp, decision,  # noqa: PLC0415
                             dsse, hf_evals, intoto, kbjwt, merkle, outcome, policy as pol,
                             public_transparency as pt, relation_statement as rs, run_ledger as rl,
                             sdjwt, sdjwt_issue, sdjwt_vc, signature, statuslist, tlogproof, trust_pack as tp,
                             verification_summary as vs)
    from proofbundle.adapters import agt_receipt as agt  # noqa: PLC0415

    pub = _raw(_T)
    ev_bundle = ec.emit_eval_receipt(_claim("0.10"), _T)
    halter = Ed25519PrivateKey.from_private_bytes(b"\x05" * 32)
    kompakt = sdjwt_issue.issue_sd_jwt(ec.decode_eval_claim(ev_bundle), _T, root_b64=ev_bundle["merkle"]["root_b64"],
                                       holder_public_key=_raw(halter))
    praesentiert = sdjwt_issue.present_with_key_binding(kompakt, halter, aud="v", nonce="n", iat=1_780_000_000)
    sd_bundle = ec.emit_eval_receipt(_claim("0.10"), _T, sd_jwt={"compact": praesentiert, "issuer_public_key_b64": _b64pub(_T)})

    intoto_env = intoto.export_intoto_dsse(_claim("0.80"), _T)
    eval_env = intoto.export_eval_result_dsse(_claim("0.80"), _T)
    svr_env = intoto.export_svr_dsse(ev_bundle, _T)

    dec_pred = json.loads((_WURZEL / "examples" / "decision_receipt_allow.json").read_text(encoding="utf-8"))
    dec_env = decision.emit_decision_receipt(dec_pred, _T)
    dec_validity = dec_pred.get("validity") or {}
    # Nachtrag 48/48b: the evaluate_decision_policy verdict surface judges this statement under the signer _T;
    # the result it is handed must be bound to exactly that statement + signer (a passing verify stamps it so).
    dec_policy_stmt = {"predicate": dec_pred, "predicateType": decision.DECISION_RECEIPT_PREDICATE_TYPE}
    dec_policy_result = bound_decision_result(dec_policy_stmt, _b64pub(_T))
    out_pred = {"schemaVersion": "0.1.0", "outcomeId": "outcome-0001", "decisionRef": {"sha256": "a" * 64},
                "executor": {"id": "executor:runner-7", "keyId": "root-0"},
                "requestedActionDigest": {"sha256": "c" * 64}, "status": "executed",
                "performedAt": "2026-07-14T10:00:00Z", "effectDigest": {"sha256": "c" * 64}}
    out_env = outcome.emit_outcome_receipt(out_pred, _T)
    rl_pred = {"schemaVersion": "0.1.0", "studyId": "study-0001", "runBudget": 5,
               "runs": rl.link_runs(["1" * 64, "2" * 64, "3" * 64], ["completed", "aborted", "completed"]),
               "selectedSeq": 3, "nonClaims": ["does not prove the selected run is representative"]}
    vs_pred = {"schemaVersion": "0.1.0", "summaryId": "summary-0001", "producedAt": "2026-07-14T10:00:00Z",
               "producer": {"id": "verifier://example/summarizer"},
               "levels": [{"kind": "eval", "receiptRef": {"sha256": "a" * 64}, "status": "VERIFIED",
                           "evidenceClass": "authorship_integrity", "checks": ["crypto", "merkle"]}],
               "nonClaims": ["does not prove the eval number is true"]}
    rs_pred = {"schemaVersion": "0.1.0", "statementId": "urn:uuid:s-1",
               "relationships": [{"relation": "retracts", "targetReceiptDigest": {
                   "digestAlgorithm": "jcs-sha256-v1", "digest": "a" * 64}}]}
    ar_pfad = (_WURZEL / "conformance" / "agent_review"
               / "agent-review-v02-positive-control-current-v02-is-marked-current" / "envelope.json")
    ar_pred = json.loads(base64.b64decode(json.loads(ar_pfad.read_text(encoding="utf-8"))["payload"]))["predicate"]
    ar_env = ar.emit_agent_review(ar_pred, _T)
    ar_subjekt = json.loads(base64.b64decode(ar_env["payload"]))["subject"][0]["digest"]["sha256"]
    kette_pfad = (_WURZEL / "conformance" / "agent_review"
                  / "agent-review-positive-control-supersession-names-the-current-receipt" / "chain.json")
    kette = json.loads(kette_pfad.read_text(encoding="utf-8"))["envelopes"]

    wurzeln = (Ed25519PrivateKey.from_private_bytes(b"\x01" * 32),
               Ed25519PrivateKey.from_private_bytes(b"\x02" * 32),
               Ed25519PrivateKey.from_private_bytes(b"\x03" * 32))
    tp_keys = {f"root-{i}": {"publicKey": _b64pub(k), "scheme": "ed25519"} for i, k in enumerate(wurzeln)}
    tp_pred = {"schemaVersion": "0.1.0", "trustPackId": "tp-0001", "version": 1,
               "expires": "2027-01-01T00:00:00Z", "prevVersionDigest": None,
               "roles": {"root": {"keyIds": list(tp_keys), "threshold": 2},
                         "outcomeExecutors": {"keyIds": ["root-0"], "threshold": 1}},
               "keys": tp_keys, "nonClaims": ["names which keys hold which role, not that the holders are honest"]}
    tp_env = tp.sign_trust_pack(tp_pred, {"root-0": wurzeln[0], "root-1": wurzeln[1]})
    jetzt = datetime(2026, 7, 14, 12, 0, 0, tzinfo=timezone.utc)

    policy = _eval_policy()
    dec_policy = {"schema": "proofbundle/trust-policy/v0.2", "policy_id": "p",
                  "decision_receipt": {"require_external_anchor": True, "allow_pending": False,
                                       "trusted_decision_makers": [{"public_key_b64": _b64pub(_T)}]}}

    origin = "example.org/log"
    blaetter = [b"leaf-0", b"leaf-1", b"leaf-2"]
    wurzel3 = merkle.merkle_tree_hash(blaetter)
    note = cp.sign_checkpoint(origin, 3, wurzel3, _T, origin)
    note = cp.cosign_checkpoint(note, _W1, "witness.example", 1000)
    log_vkey = cp.vkey(origin, pub)
    zeuge = cp.cosign_vkey("witness.example", _raw(_W1))
    tlog_text = tlogproof.format_tlog_proof(1, merkle.inclusion_proof(blaetter, 1), note)

    token = statuslist.issue_status_list_token([0, 1, 0], uri="https://example.org/list/1", signer=_T,
                                               iat=1000, exp=5000)
    vc_policy = {"vctAllowlist": [sdjwt_issue.DEFAULT_VCT], "requireKeyBinding": True,
                 "requireIssuerSignature": True}
    agt_r = _agt_receipt()
    agt_r = dict(agt_r, authorization_expires_at=3000)
    agt_r["authorization_signature"] = _A.sign(agt.canonical_authorization_payload(agt_r)).hex()
    agt_kind = {"agent_did": "did:x", "args_hash": "b" * 64, "cedar_decision": "deny", "cedar_policy_id": "p",
                "receipt_id": "r2", "timestamp": 2001, "tool_name": "t", "signer_public_key": pub.hex(),
                "parent_receipt_hash": agt.payload_hash(agt_r)}
    agt_kind["signature"] = _T.sign(agt.canonical_payload(agt_kind)).hex()
    p256 = _ec.derive_private_key(12345, _ec.SECP256R1())
    p256_pub = p256.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    from cryptography.hazmat.primitives import hashes as _hashes  # noqa: PLC0415
    from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature  # noqa: PLC0415
    _r, _s = decode_dss_signature(p256.sign(b"message", _ec.ECDSA(_hashes.SHA256())))
    p256_sig = _r.to_bytes(32, "big") + _s.to_bytes(32, "big")

    saved = dict(anchors._VERIFIERS)
    anchors.register_anchor_type("sweep-anchor/v1", lambda proof, r, *, frozen, now: {
        "ok": True, "warn": False, "status": "confirmed", "detail": "sweep"})
    anker = [{"type": "sweep-anchor/v1", "target": "receipt", "canonicalRoot": base64.b64encode(b"\xaa" * 32).decode(),
              "proof": base64.b64encode(b"p").decode(), "anchoredAt": "2026-07-05T12:00:00Z"}]
    # The arguments the sweep did not pass before the deep gate of 6.2.0 at 2348f0a7 (L4-620-01, L3-620-02):
    # a policy with a relations section, an attached target map and detached anchors over the statement.
    dec_wurzel = anchors.statement_content_root(dsse.load_payload(dec_env))
    dec_anker = [{"type": "sweep-anchor/v1", "target": "statement",
                  "canonicalRoot": base64.b64encode(dec_wurzel).decode(), "proof": base64.b64encode(b"p").decode()}]
    relationen = {"reject_superseded": True, "require_relation_resolution": ["retracts"]}
    dec_policy_relationen = dict(dec_policy, relations=relationen)
    verwandt = {"e" * 64: {"verified": True, "relationships": [], "verified_under": _b64pub(_T),
                           "subject_digest": None, "subject_digest_state": "absent"}}

    f = [
        # verify surfaces
        ("bundle.verify_bundle", lambda w: bm.verify_bundle(
            w(sd_bundle), expected_aud=w("v"), expected_nonce=w("n"),
            expected_root_b64=w(sd_bundle["merkle"]["root_b64"]), expected_tree_size=w(1),
            sd_jwt_issuer_key_pin=w("ed25519:" + _b64pub(_T)))),
        ("evalclaim.decode_eval_claim", lambda w: ec.decode_eval_claim(w(ev_bundle), expected_context=w("sweep"))),
        ("evalclaim.classify_eval_claim", lambda w: ec.classify_eval_claim(w(ev_bundle), expected_context=w("sweep"))),
        ("dsse.verify_envelope", lambda w: dsse.verify_envelope(w(dec_env), w(pub), payload_type=w(
            "application/vnd.in-toto+json"))),
        ("dsse.load_payload", lambda w: dsse.load_payload(w(dec_env))),
        ("intoto.verify_intoto_dsse", lambda w: intoto.verify_intoto_dsse(
            w(intoto_env), w(pub), expected_predicate_type=w(_praedikattyp(intoto_env)))),
        ("intoto.verify_eval_result_dsse", lambda w: intoto.verify_eval_result_dsse(
            w(eval_env), w(pub), expected_predicate_type=w(_praedikattyp(eval_env)))),
        ("intoto.verify_svr_dsse", lambda w: intoto.verify_svr_dsse(
            w(svr_env), w(pub), expected_predicate_type=w(_praedikattyp(svr_env)))),
        ("decision.verify_decision_receipt", lambda w: decision.verify_decision_receipt(
            w(dec_env), w(pub), expected_audience=w((dec_validity.get("audience") or ["x"])[0]),
            expected_nonce=w(dec_validity.get("nonce") or "n"), policy=w(dec_policy_relationen),
            anchors=w(dec_anker), related=w(verwandt), rp_trust=w({}))),
        ("outcome.verify_outcome_receipt", lambda w: outcome.verify_outcome_receipt(
            w(out_env), w(pub), expected_decision_ref=w("a" * 64), trust_pack=w(tp_pred),
            decision_maker_id=w("maker:x"), expected_audience=w("rp"), expected_nonce=w("n"),
            policy=w({"relations": relationen}), related=w(verwandt))),
        ("run_ledger.verify_run_ledger", lambda w: rl.verify_run_ledger(w(rl.emit_run_ledger(rl_pred, _T)), w(pub))),
        ("verification_summary.verify_verification_summary", lambda w: vs.verify_verification_summary(
            w(vs.emit_verification_summary(vs_pred, _T)), w(pub))),
        ("relation_statement.verify_relation_statement", lambda w: rs.verify_relation_statement(
            w(rs.emit_relation_statement(rs_pred, _T)), w(pub),
            policy=w({"relations": dict(relationen, reject_retracted=True)}), related=w(verwandt))),
        ("agent_review.verify_agent_review_v02", lambda w: ar.verify_agent_review_v02(
            w(ar_env), w(pub), expected_subject_digest=w(ar_subjekt), observed_body=w("the observed body"),
            policy=w(dict(ar.load_policy())))),
        ("agent_review.verify_agent_review_any", lambda w: ar.verify_agent_review_any(
            w(ar_env), w(pub), expected_subject_digest=w(ar_subjekt))),
        ("agent_review.resolve_receipt_chain", lambda w: ar.resolve_receipt_chain(
            w(kette), verified=w([ar.receipt_digest(e) for e in kette]))),
        ("agent_review.receipt_digest", lambda w: ar.receipt_digest(w(ar_env))),
        ("trust_pack.verify_trust_pack", lambda w: tp.verify_trust_pack(
            w(tp_env), now=jetzt, prev_version_digest=w("a" * 64), prev_root_keys=w(dict(tp_keys)),
            prev_version=w(1), prev_root_threshold=w(2))),
        ("policy.evaluate_policy", lambda w: pol.evaluate_policy(
            w(ev_bundle), bm.verify_bundle(ev_bundle), w(policy))),
        ("policy.evaluate_decision_policy", lambda w: pol.evaluate_decision_policy(
            w(dec_policy_stmt), dec_policy_result, w(dec_policy),
            signer_public_key_b64=w(_b64pub(_T)), anchor_status="PASS")),
        ("policy.load_policy", lambda w: pol.load_policy(w(policy))),
        ("hf_evals.verify_receipt_token", lambda w: hf_evals.verify_receipt_token(
            w(hf_evals.receipt_token(ev_bundle)))),
        ("hf_evals.verify_eval_results_entry", lambda w: hf_evals.verify_eval_results_entry(w(
            hf_evals.to_eval_results_entry(ev_bundle, dataset_id="d", task_id="t", value=0.95)))),
        ("checkpoint.verify_checkpoint", lambda w: cp.verify_checkpoint(w(note), w(log_vkey))),
        ("checkpoint.verify_cosignature", lambda w: cp.verify_cosignature(w(note), w(zeuge))),
        ("checkpoint.verify_witnessed_checkpoint", lambda w: cp.verify_witnessed_checkpoint(
            w(note), w(log_vkey), w([zeuge]), threshold=w(1), expected_origin=w(origin))),
        ("checkpoint.witness_quorum", lambda w: cp.witness_quorum(
            w(note), w([zeuge]), w(1), log_key_material=w(pub))),
        ("tlogproof.parse_tlog_proof", lambda w: tlogproof.parse_tlog_proof(w(tlog_text))),
        ("tlogproof.verify_tlog_proof", lambda w: tlogproof.verify_tlog_proof(
            w(tlog_text), w(b"leaf-1"), w(log_vkey), w([zeuge]), threshold=w(1), expected_origin=w(origin))),
        # `rp_trust` is passed here: the decision verifier reached it through verify_anchors before the anchors
        # were read at its entry (deep gate at 7409b123, L1-620v2-T3-01), and now calls the judging step itself.
        ("anchors.verify_anchors", lambda w: anchors.verify_anchors(
            w(anker), target_roots=w({"receipt": b"\xaa" * 32}), require=w("any"), require_target=w("receipt"),
            now=w(1_780_000_000), rp_trust=w({"bitcoin_block_headers": {}}))),
        ("sdjwt.verify_sd_jwt", lambda w: sdjwt.verify_sd_jwt(w(praesentiert), w(pub))),
        ("kbjwt.verify_key_binding", lambda w: kbjwt.verify_key_binding(
            w(praesentiert), expected_aud=w("v"), expected_nonce=w("n"))),
        ("kbjwt.split_key_binding", lambda w: kbjwt.split_key_binding(w(praesentiert))),
        ("sdjwt_issue.check_binds_bundle", lambda w: sdjwt_issue.check_binds_bundle(
            w(kompakt), w(ec.decode_eval_claim(ev_bundle)), w(ev_bundle["merkle"]["root_b64"]))),
        ("statuslist.verify_status_snapshot", lambda w: statuslist.verify_status_snapshot(
            w(token), expected_uri=w("https://example.org/list/1"), index=w(1), issuer_pubkey=w(pub),
            now=w(2000), receipt_issuer_pubkey=w(pub))),
        ("sdjwt_vc.verify_sdjwt_vc", lambda w: sdjwt_vc.verify_sdjwt_vc(
            w(praesentiert), w(vc_policy), issuer_pubkey=w(pub), expected_aud=w("v"), expected_nonce=w("n"),
            holder_pubkey=w(_raw(halter)), offline_metadata=w({}))),
        ("adapters.agt_receipt.verify_agt_receipt", lambda w: agt.verify_agt_receipt(
            w(agt_r), trusted_authorizer_keys=w([_raw(_A).hex()]), now=w(2000.5))),
        ("adapters.agt_receipt.verify_agt_receipt_chain", lambda w: agt.verify_agt_receipt_chain(
            w([agt_r, agt_kind]), trusted_authorizer_keys=w([_raw(_A).hex()]), now=w(2000.5))),
        ("public_transparency.evaluate_public_transparency", lambda w: pt.evaluate_public_transparency(
            w(note), w({"requireSignedCheckpoint": True, "trustedLogOrigins": [origin], "witnessQuorum": {"threshold": 1}}),
            log_vkey=w(log_vkey), witness_vkeys=w([zeuge]), expected_root_b64=w(base64.b64encode(wurzel3).decode()),
            expected_tree_size=w(3))),
        ("merkle.verify_inclusion", lambda w: merkle.verify_inclusion(
            w(b"leaf-1"), w(1), w(3), w(merkle.inclusion_proof(blaetter, 1)), w(wurzel3))),
        ("merkle.verify_consistency", lambda w: merkle.verify_consistency(
            w(1), w(3), w(merkle.consistency_proof(blaetter, 1)), w(merkle.merkle_tree_hash(blaetter[:1])),
            w(wurzel3))),
        ("signature.verify_ed25519_pinned", lambda w: signature.verify_ed25519_pinned(
            w(pub), w(_T.sign(b"message")), w(b"message"))),
        ("signature.verify_ecdsa_p256", lambda w: signature.verify_ecdsa_p256(w(p256_pub), w(p256_sig), w(b"message"))),
        # emit surfaces
        ("evalclaim.emit_eval_receipt", lambda w: ec.emit_eval_receipt(w(_claim("0.10")), _T)),
        ("decision.emit_decision_receipt", lambda w: decision.emit_decision_receipt(w(dec_pred), _T)),
        ("outcome.emit_outcome_receipt", lambda w: outcome.emit_outcome_receipt(w(out_pred), _T)),
        ("run_ledger.emit_run_ledger", lambda w: rl.emit_run_ledger(w(rl_pred), _T)),
        ("verification_summary.emit_verification_summary", lambda w: vs.emit_verification_summary(w(vs_pred), _T)),
        ("relation_statement.emit_relation_statement", lambda w: rs.emit_relation_statement(w(rs_pred), _T)),
        ("agent_review.emit_agent_review", lambda w: ar.emit_agent_review(w(ar_pred), _T)),
        ("trust_pack.sign_trust_pack", lambda w: tp.sign_trust_pack(
            w(tp_pred), _baue_signer(w, {"root-0": wurzeln[0], "root-1": wurzeln[1]}))),
        ("intoto.export_intoto_dsse", lambda w: intoto.export_intoto_dsse(w(_claim("0.80")), _T)),
        ("intoto.export_eval_result_dsse", lambda w: intoto.export_eval_result_dsse(w(_claim("0.80")), _T)),
        # A FIXED time_created (hermetic-cleanroom at 6cab813e, run 37167336188): without it the surface reads the clock
        # in seconds, and the sweep calls it twice, so a second boundary between the calls made the outputs differ.
        ("intoto.export_svr_dsse", lambda w: intoto.export_svr_dsse(w(ev_bundle), _T,
                                                                    time_created=w("2026-10-04T00:00:00Z"))),
        ("dsse.sign_envelope", lambda w: dsse.sign_envelope(w(b"body"), _T, payload_type=w("text/plain"),
                                                            keyid=w("k1"))),
        ("checkpoint.sign_checkpoint", lambda w: cp.sign_checkpoint(w(origin), w(3), w(wurzel3), _T, w(origin))),
        ("checkpoint.cosign_checkpoint", lambda w: cp.cosign_checkpoint(
            w(cp.sign_checkpoint(origin, 3, wurzel3, _T, origin)), _W1, w("witness.example"), w(1000))),
        ("checkpoint.vkey", lambda w: cp.vkey(w(origin), w(pub))),
        ("tlogproof.format_tlog_proof", lambda w: tlogproof.format_tlog_proof(
            w(1), w(merkle.inclusion_proof(blaetter, 1)), w(note), extra=w(b"x"))),
        ("statuslist.issue_status_list_token", lambda w: statuslist.issue_status_list_token(
            w([0, 1, 0]), uri=w("https://example.org/list/1"), signer=_T, iat=w(1000), exp=w(5000))),
        ("hf_evals.receipt_token", lambda w: hf_evals.receipt_token(w(ev_bundle))),
        ("hf_evals.to_eval_results_entry", lambda w: hf_evals.to_eval_results_entry(
            w(ev_bundle), dataset_id="d", task_id="t", value=w(0.95))),
        ("sdjwt_issue.present_with_key_binding", lambda w: sdjwt_issue.present_with_key_binding(
            w(kompakt), halter, aud="v", nonce="n", iat=w(1_780_000_000))),
    ]
    f += _flaechen_zwei(ev_bundle, dec_pred, out_pred, policy, tp_pred)
    import shutil  # noqa: PLC0415
    import tempfile  # noqa: PLC0415
    ablage = tempfile.mkdtemp(prefix="one-reading-sweep-")
    f += _flaechen_drei(pathlib.Path(ablage))
    return f, (lambda: (anchors._VERIFIERS.clear(), anchors._VERIFIERS.update(saved),
                        shutil.rmtree(ablage, ignore_errors=True)))


def _flaechen_drei(ablage):
    """The third part of the sweep: the exported verify and evaluate surfaces the first two parts did not
    list (deep gate 6.2.0 at 2348f0a7, L1-620-T3-02 and L2-620-RENEWAL-*). A document path is an operating
    system path, not a value a check compares, and is passed unwrapped like the keys above; the claim, the
    sequence, the data digests, the authority keys and the remembered digest are the caller's values."""
    import hashlib  # noqa: PLC0415

    from proofbundle import evalcard, pqsig, prereg, renewal  # noqa: PLC0415
    from proofbundle import RenewalPolicy, build_initial_sequence, renew_timestamp  # noqa: PLC0415
    from proofbundle.renewal import anchor_proof_digest  # noqa: PLC0415

    dokument = ablage / "protocol.txt"
    dokument.write_bytes(b"the protocol of the sweep\n")
    wert = hashlib.sha256(b"the protocol of the sweep\n").hexdigest()
    daten = ["ab" * 32, "cd" * 32]
    folge = renew_timestamp(build_initial_sequence(daten, hash_alg="sha256", time=5, sig_alg="ed25519",
                                                   signers={"ed25519": _T}),
                            time=7, signers={"ed25519": _T})
    zuletzt = anchor_proof_digest(folge[-1][-1])
    return [
        ("prereg.verify_prereg", lambda w: prereg.verify_prereg(str(dokument), w({"prereg_sha256": wert}))),
        ("evalcard.verify_evaluation_card", lambda w: evalcard.verify_evaluation_card(
            str(dokument), w({"evaluation_card_sha256": wert}))),
        ("renewal.verify_sequence", lambda w: renewal.verify_sequence(
            w(folge), w(daten), authority_keys=w({"ed25519": _raw(_T)}), known_newest_token_digest=w(zuletzt),
            rp_trust=w({}))),
        ("renewal.evaluate_renewal_policy", lambda w: renewal.evaluate_renewal_policy(
            w(folge), policy=RenewalPolicy(deprecated_algs=frozenset({"sha1"}), max_ats_age=10, strictness="fail"),
            now=w(12))),
        # The three post-quantum verifiers: the sweep measures that they read the caller's bytes by what
        # they store whether the optional backend is installed or not (without it both runs raise the same
        # PQUnavailable, which the sweep compares like any other outcome).
        ("pqsig.verify_mldsa", lambda w: pqsig.verify_mldsa(w(b"\x01" * 1952), w(b"\x02" * 3309), w(b"message"),
                                                      level=w("mldsa65"))),
        ("pqsig.verify_slhdsa", lambda w: pqsig.verify_slhdsa(w(b"\x01" * 32), w(b"\x02" * 7856), w(b"message"),
                                                        level=w("slhdsa-sha2-128s"))),
        ("pqsig.verify_hybrid", lambda w: pqsig.verify_hybrid(
            classical_pub=w(_raw(_T)), classical_sig=w(_T.sign(b"message")), pq_pub=w(b"\x01" * 1952),
            pq_sig=w(b"\x02" * 3309), message=w(b"message"), pq_level=w("mldsa65"))),
    ]


def _flaechen_zwei(ev_bundle, dec_pred, out_pred, policy, tp_pred):
    """The second part of the sweep: the verify and classify surfaces beside the receipts' own."""
    import hashlib  # noqa: PLC0415
    from datetime import datetime, timezone  # noqa: PLC0415

    from proofbundle import (agent_review as ar, assurance, decision, emit, hashalg, intoto, outcome,  # noqa: PLC0415
                             persample, policy as pol, relation, subject_binding, trust_pack as tp)

    baum = persample.build_sample_tree([{"id": "a", "epoch": 1, "input": "x", "target": "y", "score": 1},
                                        {"id": "b", "epoch": 1, "input": "x", "target": "y", "score": 0}],
                                       b"\x33" * 32)
    oeffnung = persample.sample_opening(baum["disclosures"], 1)
    daten = b"artifact bytes"
    digests = {"sha256": hashlib.sha256(daten).hexdigest(), "sha3-256": hashlib.sha3_256(daten).hexdigest()}
    claim, oeffnungen = ec.build_eval_claim(
        suite="real-suite", suite_version="1", metric="acc", comparator=">=", threshold="0.10",
        score="0.5", n=100, model_id="m", dataset_id="d", issuer="x",
        timestamp="2026-07-09T10:00:00Z", model_salt=b"0" * 16, dataset_salt=b"1" * 16)
    ar_pfad = (_WURZEL / "conformance" / "agent_review"
               / "agent-review-v02-positive-control-current-v02-is-marked-current" / "envelope.json")
    ar_pred = json.loads(base64.b64decode(json.loads(ar_pfad.read_text(encoding="utf-8"))["payload"]))["predicate"]
    evidenz = b'{"evidence": 1}'
    ref = {"relation": "input", "digest": {"sha256": hashlib.sha256(evidenz).hexdigest()}}
    signiert = intoto.export_intoto_dsse(_claim("0.80"), _T)
    statement = json.loads(base64.b64decode(signiert["payload"]))
    return [
        ("persample.verify_sample_opening", lambda w: persample.verify_sample_opening(
            w(oeffnung), w(baum["root_b64"]), w(baum["n"]))),
        ("hashalg.verify_dual_hash", lambda w: hashalg.verify_dual_hash(w(daten), w(digests))),
        ("hashalg.compute_digest", lambda w: hashalg.compute_digest(w(daten), w("sha256"))),
        ("evalclaim.verify_commitment", lambda w: ec.verify_commitment(
            w("m"), w(oeffnungen["model_salt"]), w(claim["model_id_commit"]))),
        # `now` is the relying party's clock, a datetime: an int there stopped both runs at the same
        # early refusal, before the claim was read at all.
        ("evalclaim.check_freshness", lambda w: ec.check_freshness(
            w(claim), max_age_seconds=w(10**9), now=datetime(2026, 9, 1, tzinfo=timezone.utc))),
        ("emit.emit_bundle", lambda w: emit.emit_bundle(w(b"payload"), _T, prior_leaves=w([b"a", b"b"]))),
        ("decision.resolve_evidence_ref", lambda w: decision.resolve_evidence_ref(
            w(ref), evidence_payload=w(evidenz))),
        ("outcome.resolve_receiver_ref", lambda w: outcome.resolve_receiver_ref(
            w(dict(ref, relation="receiver")), receiver_payload=w(evidenz))),
        ("relation.verify_relationship_edges", lambda w: relation.verify_relationship_edges(
            w([{"relation": "retracts", "targetReceiptDigest": {"digestAlgorithm": "jcs-sha256-v1",
                                                                 "digest": "a" * 64}}]), None,
            subject_hex=w("b" * 64), max_depth=w(8))),
        ("assurance.classify_digest_evidence", lambda w: assurance.classify_digest_evidence(
            _klare_schluessel(w({"sha256": "a" * 64})))),
        ("subject_binding.classify_subject", lambda w: subject_binding.classify_subject(w(statement))),
        ("intoto.classify_svr_predicate_shape", lambda w: intoto.classify_svr_predicate_shape(
            w(json.loads(base64.b64decode(intoto.export_svr_dsse(ev_bundle, _T)["payload"]))))),
        ("intoto.svr_properties", lambda w: intoto.svr_properties(
            __import__("proofbundle.bundle", fromlist=["x"]).verify_bundle(ev_bundle),
            w(ec.decode_eval_claim(ev_bundle)))),
        ("policy.lint_policy", lambda w: pol.lint_policy(w(policy))),
        ("policy.explain_policy", lambda w: pol.explain_policy(w(policy))),
        ("trust_pack.validate_trust_pack_predicate", lambda w: tp.validate_trust_pack_predicate(w(tp_pred))),
        ("decision.validate_decision_predicate", lambda w: decision.validate_decision_predicate(w(dec_pred))),
        ("outcome.validate_outcome_predicate", lambda w: outcome.validate_outcome_predicate(w(out_pred))),
        ("agent_review.evaluate_time_policy", lambda w: ar.evaluate_time_policy(
            w({"external_time_status": "EXTERNALLY_ANCHORED"}), w({"kind": "existence"}))),
        ("agent_review.evaluate_limitation_policy", lambda w: ar.evaluate_limitation_policy(
            w(ar_pred), w(dict(ar.load_policy())))),
        ("relation.evaluate_relations_policy", lambda w: relation.evaluate_relations_policy(
            w({"require_relation_resolution": ["retracts"], "reject_superseded": True}),
            w({"edges": [{"relation": "retracts", "resolution": "VERIFIED"}], "supersededByAttached": None}),
            successor_key_b64=w(_b64pub(_T)))),
    ] + _flaechen_mit_ots()


#: The surfaces `_flaechen_mit_ots` adds, by name. Without OpenTimestamps they are not in the sweep, and
#: `EveryArgumentOfAVerifySurfaceIsInTheSweep` names them as not measured instead of reading their absence
#: as a gap (the hermetic cleanroom job installs no extras).
_OTS_FLAECHEN = ("evidence_pack.verify_evidence_pack", "anchors_rootcommit.verify_rootcommit_v1")


def _ots_vorhanden() -> bool:
    """Whether OpenTimestamps (proofbundle[anchors]) is installed. Only its absence counts as absence: no module
    spec to find. A module that is found and fails while importing, ``ImportError`` included, is a broken
    install, and its failure is raised, so a regression stays red instead of reading as not measured (Codex
    thread 4163240548 at dd079791; until then every ``ImportError`` counted as absence)."""
    import importlib.util  # noqa: PLC0415
    if importlib.util.find_spec("opentimestamps") is None:
        return False
    import opentimestamps  # noqa: F401, PLC0415
    return True


def _flaechen_mit_ots():
    """The two surfaces whose legitimate input needs OpenTimestamps (proofbundle[anchors]); absent that
    extra they are not in the sweep, which the case then does not claim to cover."""
    if not _ots_vorhanden():
        return []
    import hashlib  # noqa: PLC0415

    from opentimestamps.core.notary import PendingAttestation  # noqa: PLC0415
    from opentimestamps.core.op import OpSHA256  # noqa: PLC0415
    from opentimestamps.core.serialize import BytesSerializationContext  # noqa: PLC0415
    from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp  # noqa: PLC0415

    from proofbundle import anchors_rootcommit as rc  # noqa: PLC0415
    from proofbundle import evidence_pack as ep  # noqa: PLC0415

    wurzel = hashlib.sha256(b"one-reading-pack-root").digest()
    ts = Timestamp(wurzel)
    ts.attestations.add(PendingAttestation("https://alice.btc.calendar.opentimestamps.org"))
    ctx = BytesSerializationContext()
    DetachedTimestampFile(OpSHA256(), ts).serialize(ctx)
    pack = ep.build_evidence_pack(wurzel, ctx.getbytes())
    vektor = (_WURZEL / "tests" / "fixtures" / "anchors" / "tlog_bitcoin_anchor" / "rootcommit" / "vectors"
              / "rootcommit-01-valid.txt").read_text()
    flaechen = [
        ("evidence_pack.verify_evidence_pack", lambda w: ep.verify_evidence_pack(
            w(pack), rp_trust=w({}), now=w(1_780_000_000))),
        ("anchors_rootcommit.verify_rootcommit_v1", lambda w: rc.verify_rootcommit_v1(
            w(vektor), frozen=w({}), rp_trust=w({}))),
    ]
    assert tuple(name for name, _ in flaechen) == _OTS_FLAECHEN, "_OTS_FLAECHEN names another list"
    return flaechen


def _baue_signer(w, signers: dict):
    """The signer map of `sign_trust_pack`: for the recording run a recording dict with recording key
    ids (the private keys are the caller's signers, not values a check reads)."""
    if w is not _aufgezeichnet:
        return dict(signers)
    _PAUSE.append(1)
    try:
        return _RDict({_RStr(k): v for k, v in signers.items()})
    finally:
        _PAUSE.pop()


class EverySurfaceReadsTheCallersObjectsByWhatTheyStore(unittest.TestCase):
    """PROPERTY (the class, measured at every surface of the sweep): fed every caller value as a
    recording subclass that answers exactly what it stores, a public verify or emit surface runs none
    of its methods and returns what it returns for the plain values. RED at cd5d39f4 where a surface
    read a caller value through a method the caller defines; the list of those surfaces and of the
    ones that already held is in the round's commit message."""

    def test_no_surface_runs_a_method_of_the_callers_values(self) -> None:
        # PR 293, which the 6.2.0 chain carries, documents the relying party's trusted_authorizer_keys as
        # any iterable, read once through its own iterator after `isinstance` has asked whether it is one
        # key (`agt_receipt._vertrauensliste`): those two reads are that contract, not a second reading.
        vertrauensliste = {"list.__class__", "list.__iter__"}
        erlaubt = {"adapters.agt_receipt.verify_agt_receipt": vertrauensliste,
                   "adapters.agt_receipt.verify_agt_receipt_chain": vertrauensliste}
        flaechen, aufraeumen = _flaechen()
        self.addCleanup(aufraeumen)
        for name, aufruf in flaechen:
            with self.subTest(surface=name):
                try:
                    erwartet = aufruf(copy.deepcopy)
                except Exception as exc:  # noqa: BLE001 - the plain call's outcome is the oracle
                    erwartet = ("raised", type(exc).__name__)
                _AUFRUFE.clear()
                try:
                    gesehen = aufruf(_aufgezeichnet)
                except Exception as exc:  # noqa: BLE001
                    gesehen = ("raised", type(exc).__name__)
                aufrufe = sorted(set(_AUFRUFE) - erlaubt.get(name, set()))
                _AUFRUFE.clear()
                self.assertEqual(aufrufe, [], f"{name} ran methods of the caller's values")
                self.assertEqual(_klar(gesehen), _klar(erwartet), f"{name} answered differently")


#: The arguments of a verify or evaluate surface that the sweep does NOT pass, each with its reason. Every
#: other argument of such a surface must be passed by the sweep, measured, so an argument added later is red
#: here until it is passed or named. Two rule-based groups are not listed one by one and are NOT measured
#: by this sweep: a switch (an argument whose default is a bool; judged by `_membership.require_switch` or
#: by the exact True where a switch widens a verdict) and a callback (its name holds `resolver` or
#: `verifier`; the rewrite-during-a-callback property is measured for the receipt verifiers in
#: tests/test_one_reading_reaches_every_argument.py, and not for the other callbacks).
_NICHT_IM_SWEEP = {
    "public_transparency.evaluate_public_transparency": {
        "consistency_confirmed": "a bool or None the relying party computed; a bool cannot be subclassed",
        "consistency_result": "an object of this package's own ConsistencyVerificationResult type, no JSON value",
    },
    "policy.evaluate_policy": {"now": "an aware datetime, no JSON value; the sweep's readers rebuild JSON values. "
                               "Read once (canonical._zeitpunkt_von); a datetime subclass is held by "
                               "tests/test_one_reading_reaches_every_argument.py"},
    "trust_pack.verify_trust_pack": {"now": "an aware datetime, no JSON value; the sweep's readers rebuild JSON "
                                     "values. Read once (canonical._zeitpunkt_von); a datetime subclass is held "
                                     "by tests/test_one_reading_reaches_every_argument.py"},
    "hf_evals.verify_receipt_token": {"sd_jwt_issuer_key_pin": "the relying-party SD-JWT issuer-trust pin "
                                      "(Nachtrag 38, Z309); forwarded verbatim to bundle.verify_bundle, where its "
                                      "one reading (canonical._zeichen_von) is measured by the entry above"},
    "hf_evals.verify_eval_results_entry": {"sd_jwt_issuer_key_pin": "the relying-party SD-JWT issuer-trust pin "
                                           "(Nachtrag 38, Z309); forwarded verbatim through verify_receipt_token to "
                                           "bundle.verify_bundle, where its one reading is measured by the entry above"},
}


class EveryArgumentOfAVerifySurfaceIsInTheSweep(unittest.TestCase):
    """GENERATOR for the sweep itself (deep gate 6.2.0 at 2348f0a7). The eight P1 findings of that gate sat
    in arguments the sweep never passed (`policy`, `related` and `anchors` of the receipt verifiers) and in
    exported surfaces it never listed (`verify_prereg`, `verify_evaluation_card`, `verify_sequence`,
    `evaluate_renewal_policy`). A list of cases cannot see what it does not list, so this measures the
    list: every name that `proofbundle` exports as `verify_*` or `evaluate_*` is a surface of the sweep,
    and every argument of every verify or evaluate surface of the sweep is passed by it, read from the
    calls the sweep actually makes, or named in `_NICHT_IM_SWEEP`, or a switch or a callback (see there).

    GREEN at 2074d814 and at the head that adds it: it measures this file, not the package. It is RED for a
    planted gap, measured when it was added: with `anchors=` taken out of the decision call it names
    `decision.verify_decision_receipt(anchors)`, and with the `verify_prereg` entry taken out it names
    `verify_prereg (prereg.verify_prereg)`."""

    def _gerufen(self):
        import importlib  # noqa: PLC0415
        import inspect  # noqa: PLC0415
        flaechen, aufraeumen = _flaechen()
        self.addCleanup(aufraeumen)
        gesehen: dict = {}
        original = []
        for name, _ in flaechen:
            modul = importlib.import_module("proofbundle." + name.rsplit(".", 1)[0])
            attr = name.rsplit(".", 1)[1]
            fn = getattr(modul, attr)

            def huelle(*a, _fn=fn, _name=name, _sig=inspect.signature(fn), **k):
                gesehen.setdefault(_name, set()).update(_sig.bind(*a, **k).arguments)
                return _fn(*a, **k)

            original.append((modul, attr, fn))
            setattr(modul, attr, huelle)
        try:
            for _name, aufruf in flaechen:
                try:
                    aufruf(copy.deepcopy)
                except Exception:  # noqa: BLE001, S110 - the outcome is measured elsewhere; here only the arguments
                    pass
        finally:
            for modul, attr, fn in original:
                setattr(modul, attr, fn)
        return flaechen, gesehen

    def test_every_exported_verify_surface_is_in_the_sweep(self) -> None:
        import proofbundle  # noqa: PLC0415
        flaechen, _ = self._gerufen()
        namen = {name for name, _ in flaechen}
        fehlt = []
        for export in sorted(dir(proofbundle)):
            if not export.startswith(("verify_", "evaluate_")):
                continue
            objekt = getattr(proofbundle, export)
            name = f"{objekt.__module__.removeprefix('proofbundle.')}.{objekt.__name__}"
            if name not in namen:
                fehlt.append((f"{export} ({name})", name))
        # Without the [anchors] extra the OpenTimestamps surfaces are not in the sweep by design: they are
        # named as not measured here, never read as covered, and every other gap stays red.
        ungemessen = [text for text, name in fehlt if name in _OTS_FLAECHEN and not _ots_vorhanden()]
        self.assertEqual([text for text, name in fehlt if text not in ungemessen], [],
                         "exported verify surfaces that the sweep does not call")
        if ungemessen:
            self.skipTest(f"NOT MEASURED without OpenTimestamps (proofbundle[anchors]): {ungemessen}")

    def test_every_argument_of_a_verify_surface_is_passed(self) -> None:
        import importlib  # noqa: PLC0415
        import inspect  # noqa: PLC0415
        flaechen, gesehen = self._gerufen()
        offen = []
        for name, _ in flaechen:
            attr = name.rsplit(".", 1)[1]
            if not attr.startswith(("verify_", "evaluate_")):
                continue
            fn = getattr(importlib.import_module("proofbundle." + name.rsplit(".", 1)[0]), attr)
            for argument, parameter in inspect.signature(fn).parameters.items():
                if (argument.startswith("_") or argument in gesehen.get(name, set())
                        or argument in _NICHT_IM_SWEEP.get(name, {})
                        or type(parameter.default) is bool
                        or "resolver" in argument or "verifier" in argument):
                    continue
                offen.append(f"{name}({argument})")
        self.assertEqual(offen, [], "arguments of verify surfaces the sweep does not pass and that are not named")


def _zahlen_aufgezeichnet(wert):
    """`wert` with every int (not bool) and float rebuilt as a recording subclass, and everything else as
    it is. The sweep above keeps numbers plain on the premise that every surface reads a number by the one
    rule (`_plain_value.plain_int`) and refuses a subclass; this reading tests that premise."""
    _PAUSE.append(1)
    try:
        return _zahlen(wert)
    finally:
        _PAUSE.pop()


def _zahlen(wert):
    typ = type(wert)
    if typ is int:
        return _RInt(wert)
    if typ is float:
        return _RFloat(wert)
    if typ is dict:
        return {k: _zahlen(v) for k, v in wert.items()}
    if typ is list or typ is tuple:
        return typ(_zahlen(v) for v in wert)
    return wert


class EveryNumberIsReadByTheOneRule(unittest.TestCase):
    """PROPERTY (the number axis of the class, deep gate 6.2.0 at 2348f0a7): a surface reads a number the
    caller hands it as an exact int or float, and refuses a subclass, or runs none of its methods. The
    premise of the sweep above did not hold everywhere: `evaluate_renewal_policy` subtracted a `now` through
    its own `__sub__` (L2-620-RENEWAL-POLICY-NOW-INTSUB), and `verify_trust_pack` compared `prev_version` and
    `prev_root_threshold` through their own reflected comparisons. A refusal is a correct answer here; a
    method of the caller's number that runs is not. RED at 2074d814 for `trust_pack.verify_trust_pack` and
    `renewal.evaluate_renewal_policy`, GREEN at the head that adds it."""

    def test_no_surface_runs_a_method_of_a_callers_number(self) -> None:
        flaechen, aufraeumen = _flaechen()
        self.addCleanup(aufraeumen)
        for name, aufruf in flaechen:
            with self.subTest(surface=name):
                _AUFRUFE.clear()
                try:
                    aufruf(_zahlen_aufgezeichnet)
                except Exception:  # noqa: BLE001, S110 - a refusal is a correct answer here
                    pass
                gelaufen = sorted(set(_AUFRUFE))
                _AUFRUFE.clear()
                self.assertEqual(gelaufen, [], f"{name} ran methods of a caller's number")


class ALineageResultWithoutAPlainCopyIsReadByWhatItStores(unittest.TestCase):
    """Review of the 6.2.0 chain (PR 300 carrying PR 291): `relation.evaluate_relations_policy` judges a
    lineage result that holds a value that is no JSON value as it stands (PR 291's rule), and the
    fallback that did so handed on the caller's object. The rules then read it through its own `get`,
    and a stored field that is no JSON value reached `_keys_equal`, whose `isinstance` reads the
    value's own `__class__`. RED at the adaptation of D4 to the heads before it, where both ran; GREEN
    when the fallback reads what the result stores (`relation._lineage_as_stored`)."""

    def _lauf(self, section, linie):
        from proofbundle import relation  # noqa: PLC0415
        return [x["code"] for x in relation.evaluate_relations_policy(section, linie,
                                                                      successor_key_b64=_b64pub(_T))]

    def test_the_callers_get_does_not_choose_the_edges(self) -> None:
        gelaufen: list = []

        class _KeinJsonWert:
            pass

        class _EigenesGet(dict):
            def get(self, key, default=None):
                gelaufen.append(f"get {key}")
                return [] if key == "edges" else default

        kante = {"relation": "supersedes", "resolution": "DECLARED_UNRESOLVED", "targetDigest": "a" * 64}
        codes = self._lauf({"require_relation_resolution": ["supersedes"]},
                           _EigenesGet(edges=[kante], extra=_KeinJsonWert()))
        self.assertEqual(codes, ["LINEAGE_REQUIREMENT_FAILED"])
        self.assertEqual(gelaufen, [], "the lineage result's own get ran")

    def test_a_stored_field_that_is_no_json_value_runs_none_of_its_code(self) -> None:
        gelaufen: list = []

        class _BehauptetText:
            @property
            def __class__(self):
                gelaufen.append("__class__")
                return str

        kante = {"relation": "supersedes", "resolution": "VERIFIED", "verified_under": _BehauptetText()}
        codes = self._lauf({"relation_signer": {"supersedes": {"mode": "same-key"}}}, {"edges": [kante]})
        self.assertEqual(codes, ["RELATION_SIGNER_UNAUTHORIZED"])
        self.assertEqual(gelaufen, [], "the stored value's own __class__ ran")

    def test_control_a_plain_lineage_result_is_judged_as_before(self) -> None:
        verifiziert = {"relation": "supersedes", "resolution": "VERIFIED", "targetDigest": "b" * 64,
                       "verified_under": _b64pub(_T)}
        self.assertEqual(self._lauf({"require_relation_resolution": ["supersedes"]}, {"edges": [verifiziert]}),
                         [])
        # Nachtrag 48/48b (F2): same-key is satisfied only for a lineage bound to the verified successor receipt;
        # stamp it for _T (the _lauf successor key), as a passing verify does.
        from _lineage_binding import bound_lineage  # type: ignore  # noqa: PLC0415
        self.assertEqual(self._lauf({"relation_signer": {"supersedes": {"mode": "same-key"}}},
                                    bound_lineage({"edges": [verifiziert]}, _b64pub(_T))), [])
        self.assertEqual(self._lauf({"reject_superseded": True}, {"edges": [], "supersededByAttached": "by X"}),
                         ["LINEAGE_REQUIREMENT_FAILED"])


if __name__ == "__main__":
    unittest.main()
