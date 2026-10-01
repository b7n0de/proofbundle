"""A public function reads a caller's values once, at its call, as one state, and its verdict is the verdict over
that one reading.

WHERE THIS COMES FROM. Deep gate run 5 at d388ed3d, finding L4-620v5-T5-SECOND-READING-01, two of three jurors P1.
`verify_decision_receipt` and `verify_outcome_receipt` read the caller's `related` map in
`verify_relationship_edges` and again in `successor_warning`, and recorded the second reading's
`supersededByAttached`. A gc callback of the caller that emptied its own map between the two readings gave `ok` True
under a policy that refuses the full map and the empty map alike.

WHY THE READING SITS AT THE CALL. The first fix (6d674973) read each such value once where the body read it and
paused the collector during that reading. The verify lanes on that commit found the class where no single reading
of one parameter shows it: a loop over nine rules each reading the document (`check_cap1_document`), chains or
receipts copied one at a time (`renewal.verify_sequence`, `verify_agt_receipt_chain`, `resolve_receipt_chain`), two
parameters each read once but at two times (the policy and `related`, the block and the statement), a budget that
read one state and a copy another, an entry read before and after a token check (`verify_eval_results_entry`), a
Mapping or an object read through its own methods at several places, and the pause itself undone by a second
thread. So every public function of the package, and every public classmethod and staticmethod of a public class,
reads all of its arguments in ONE reading at its call (`canonical._ein_stand`, the copy `canonical._stand`), before
its body reads any of them, and the body reads only that private copy; a value a caller's callable returns into a
verdict is read the same way where it is returned, and the callable runs as the caller's code (`canonical._draussen`).

WHY THE READING IS READ TWICE. The reading of 8f2fa980 paused the collector for the whole process while it read. The
verify lanes V5 and V6 on that commit found what a switch of the process costs: the collector starved under threads, a
thread that collected made calls refuse, a fork or an exception at the wrong line left it off. And the reading left
out what it did not copy: the dataclasses of this package and a dict keyed by a `str` subclass. So the reading now reads
every container twice and keeps the first reading when the second found the same objects (the double collect of the
atomic snapshot, `canonical._stand`), touching nothing of the process, and copies those values too.

THE PROPERTY, measured with the caller's own gc callback rather than with a list of known readers. Each case hands
the function a value in a first state, and at the k-th start of a garbage collection during the call the caller's
callback rewrites that value, in place, into a second state. The verdict must be the verdict over the first state
or the verdict over the second, for every k from the first collection of the call to past its last one. Section 1
opens with the planted control (a function that reads twice is caught by the same sweep) and holds the surfaces
the gate and the verify lanes measured, each with a sweep of its own but the two the CHANGELOG entry names. Section 2 counts the readings of the `related` map, section 3 holds the
neighbours that are a split in reader (a subclass read through its own methods and by what it stores). Section 4
holds the guard: every public function of a public module, and every public classmethod and staticmethod of a public
class there, carries the reading at its call, once; every call of a caller's callable is named, and each whose answer
enters a verdict runs as the caller's code. Section 5 holds the one reading itself: a private copy of one state,
sharing none of the containers it copies with the caller, running no method of the caller, copying this package's
dataclasses and a key of a `str` subclass, in linear time, and a sweep over the copy that falls when the second collect
is taken away. Section 6 holds the second collect: a change between the two collects is seen and the value read again,
three readings before a refusal, and nothing of the process is touched. Section 7 holds what the verify lanes V7 and V8
on 085869313 found: the reader of a Mapping is part of both collects, a deque, an array and a view of a dict are copied,
a RecursionError is no change, a Mapping that builds or parses its values anew is read, and each edge a planted
defect of the lanes V7 and V10 showed untested (the second collect of each kind, the depth after an exception, the
warning's frame, the prefix of a module name) has a test that falls on that plant; the lane V12 on d1c39ae3 found 24
rules of the same value that no test held, and the lane V13 on 95c9f82a 18 more; each of these has a case now that
falls without it (the guard against a circle by a hang of the ring case). The lane V14 on 6723bf24 found 33 further
single defects of these rules that no case catches (RESTRISIKO_620.md, R620-V14-3). A Codex review of 110cdad9 (pull
request 311, thread 4151141239) found the second collect blind to a container's class: section 1 sweeps that finding at
`root_authenticity_summary`, and section 7 changes the class of every kind `_lies` reads and of every pair of this
package's dataclasses whose layouts let one become the other; both fall without the comparison of the type.

WHAT THIS DOES NOT SEE. A value of the caller's own class that is no built-in container and no dataclass of this
package (an object, a Mapping that is no dict) is read through its own methods; where a function reads one, a named
reader reads it before the first collect and after the second, and the two answers must be the same
(`canonical._abbild_stand`, `public_transparency._konsistenz_stand`); any other such object is handed on as the caller's
object. The public instance methods of this package's classes are not read at their call. A dict with a key that is no
str, int, float, bool, bytes or None, no subclass of str or bytes and no tuple or frozenset of exact such values stays
the caller's object (its hash can be the caller's code), and so do a dict whose keys meet as one in the copy, an
OrderedDict whose own order cannot be read without hashing, a keys, values or items view of an OrderedDict, the items of a frozenset, an iterator or a generator
(it cannot be read twice, and the body reads it when it reads it), and a memoryview whose format a view of private
bytes cannot take (read by both collects, then read by the body as the caller's view) or that is not C-contiguous (not
read at all). A value of a type the comparison of a reader's two answers does not read (`canonical._derselbe` names
them), built anew on each read, is a change, and the call is refused. A change that is made and undone between the two
reads of one container is not seen. And the sweep reaches a window only where a
tracked object is allocated in it.
"""
from __future__ import annotations

import ast
import base64
import copy
import gc
import hashlib
import json
import sys
import unittest
from pathlib import Path
from collections.abc import Mapping
from typing import Any, Callable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

REPO = Path(__file__).resolve().parents[1]
for _p in (str(REPO), str(REPO / "src"), str(REPO / "tests")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from _lastdeckel import KOSTEN_JE_ELEMENT, gedeckelt  # noqa: E402  (LAUF11-L3: a load built from a budget is capped)
from tests.test_a_producer_reads_a_callers_key_once import _not_shipped  # noqa: E402

_ALG = "jcs-sha256-v1"
_A, _R = "8" * 64, "7" * 64
#: Refuses the full map (the attached retraction) and the empty one (the derivedFrom edge unresolved).
_POLICY = {"schema": "proofbundle/trust-policy/v0.2", "policy_id": "t/read-once",
           "relations": {"reject_superseded": True, "require_relation_resolution": ["derivedFrom"]}}


def _raw(sk: Ed25519PrivateKey) -> bytes:
    return sk.public_key().public_bytes_raw()


def _edge(target: str, relation: str) -> dict:
    return {"relation": relation, "targetReceiptDigest": {"digestAlgorithm": _ALG, "digest": target}}


# ── the sweep ───────────────────────────────────────────────────────────────────────────────────

def _run(call: Callable[[Any], Any], value: Any, k: int, change: Callable[[Any], None], pad: int = 0,
         drain: "bool | str" = False) -> "tuple[Any, int]":
    """One call with the caller's gc callback armed to change `value` at the k-th collection start;
    returns the call's result and how many collections started. ``drain`` empties the free list of lists first, so the
    next list the call makes is a fresh allocation, and ``pad`` shifts the count of the collector by that many lists: a
    window between two readings is reached only where an allocation starts a collection in it (verify lane V5 on
    8f2fa980 found `RenewalPolicy.from_dict` and `exit_code` only this way). ``drain="v5"`` is the lane's own phase:
    drained, collected, and one tracked object of a new class made, so the collector counts one (verify lane V7 on
    085869313: without it the sweep of `from_dict` did not reach the window at 8f2fa980, where the method was open).

    Every object that exists before the call is frozen for its length (`gc.freeze`), so a collection the sweep starts
    walks only what the call allocates. Measured in the full suite on 2026-09-30: without it each collection walked the
    whole heap of the suite process, and one test of this file ran past ten minutes that takes seconds on its own. The
    collections start where they started, and the callback runs at each."""
    seen = {"n": 0}
    gc.freeze()
    try:
        keep: list = [[] for _ in range(100)] if drain else []
        if drain or pad:
            gc.collect()
            keep.extend([[] for _ in range(pad)])
        if drain == "v5":
            keep.append(object.__new__(type("T", (), {})))

        def callback(phase, info):
            if phase != "start":
                return
            if seen["n"] == k:
                change(value)
            seen["n"] += 1
        old = gc.get_threshold()
        gc.callbacks.append(callback)
        gc.set_threshold(1, 1, 1)
        try:
            out = call(value)
        finally:
            gc.set_threshold(*old)
            gc.callbacks.remove(callback)
    finally:
        gc.unfreeze()
    return out, seen["n"]


def sweep(call: Callable[[Any], Any], make: Callable[[], Any], change: Callable[[Any], None],
          verdict: Callable[[Any], Any], *, phasen: bool = False) -> "tuple[Any, Any, list, int]":
    """(verdict over the first state, verdict over the second, the mixed verdicts, calls swept). With ``phasen`` the
    sweep runs once for each allocator phase, the free list drained or not and 0 to 3 lists of padding, and once in the
    phase of verify lane V5 (`_run`): nine phases."""
    first = verdict(call(make()))
    second_state = make()
    change(second_state)
    second = verdict(call(second_state))
    mixed = []
    gesamt = 0
    phasenliste: list = [(d, p) for d in (False, True) for p in range(4)] + [("v5", 0)]
    for drain, pad in (phasenliste if phasen else [(False, 0)]):
        _, n = _run(call, make(), 1 << 60, change, pad, drain)
        for k in range(n + n // 4 + 16):
            out, _ = _run(call, make(), k, change, pad, drain)
            gesamt += 1
            v = verdict(out)
            if v not in (first, second):
                mixed.append((k, v) if not phasen else (drain, pad, k, v))
    return first, second, mixed, gesamt


# ── the fixtures ────────────────────────────────────────────────────────────────────────────────

class _Fx:
    def __init__(self):
        from proofbundle import dsse, pqsig
        from proofbundle import statuslist as sl
        from proofbundle import verifier_block as vb
        from proofbundle.anchors import statement_content_root
        from proofbundle.outcome import emit_outcome_receipt
        from proofbundle.relation_statement import emit_relation_statement
        self.sk = Ed25519PrivateKey.generate()
        self.pub = _raw(self.sk)
        self.subject = {}
        rel = [_edge(_A, "derivedFrom")]
        if not _not_shipped("examples/decision_receipt_allow.json"):
            pred = json.loads((REPO / "examples" / "decision_receipt_allow.json").read_text(encoding="utf-8"))
            pred["relationships"] = rel
            from proofbundle.decision import emit_decision_receipt
            self.decision = emit_decision_receipt(pred, self.sk, strict=False)
        else:
            self.decision = None
        self.outcome = emit_outcome_receipt(
            {"schemaVersion": "0.1.0", "outcomeId": "outcome-once", "decisionRef": {"sha256": "e" * 64},
             "executor": {"id": "executor:x", "keyId": "kid"}, "requestedActionDigest": {"sha256": "1" * 64},
             "status": "executed", "performedAt": "2026-09-29T00:00:00Z", "effectDigest": {"sha256": "2" * 64},
             "relationships": rel}, self.sk)
        self.statement = emit_relation_statement(
            {"schemaVersion": "0.1.0", "statementId": "urn:uuid:read-once", "relationships": rel}, self.sk)
        for name in ("decision", "outcome", "statement"):
            env = getattr(self, name)
            if env is not None:
                self.subject[name] = statement_content_root(dsse.load_payload(env)).hex()
        # the status list: signed by `status_signer`, the receipt by `self.sk`
        self.status_signer = Ed25519PrivateKey.generate()
        self.status_uri = "https://example.org/status/1"
        self.status_token = sl.issue_status_list_token([0, 1], uri=self.status_uri, signer=self.status_signer,
                                                       iat=1_780_000_000)
        # the hybrid: Ed25519 over one message, ML-DSA over another of the same length
        self.m1, self.m2 = b"the first message", b"the other message"
        try:
            ml = pqsig.generate_mldsa("mldsa65")
            self.hybrid = {"classical_pub": self.pub, "classical_sig": self.sk.sign(self.m1),
                           "pq_pub": ml.public_key().public_bytes_raw(),
                           "pq_sig": pqsig.sign_mldsa(ml, self.m2), "pq_level": "mldsa65"}
        except pqsig.PQUnavailable:
            self.hybrid = None
        # the join: a valid statement S0, and S2, invalid, whose digest the block cites
        build = {"digest": {"sha256": "1" * 64}, "source": "source-tree", "files": 7}
        vset = {"name": "proofbundle.conformance.manifest.v1", "digest": {"sha256": "2" * 64}, "cases": 2}
        self.s0 = vb.build_test_result_statement(
            build=build, vector_set=vset, version="6.2.0",
            results=[{"caseId": "a", "ok": True, "scope": "full"}, {"caseId": "b", "ok": True, "scope": "full"}])
        s2 = copy.deepcopy(self.s0)
        s2["predicate"]["url"] = ""
        assert vb.validate_test_result_statement(s2), "S2 must be invalid"
        tr = {"predicateType": vb.TEST_RESULT_PREDICATE_TYPE, "result": self.s0["predicate"]["result"]}
        self.block_for_s2 = vb.build_verifier_block(
            build=build, version="6.2.0", vector_set=vset,
            test_result=dict(tr, statementDigest={"sha256": vb.statement_digest(s2)}))
        self.block_other = vb.build_verifier_block(
            build=build, version="6.2.0", vector_set=vset, test_result=dict(tr, statementDigest={"sha256": "0" * 64}))
        self.s0_digest = vb.statement_digest(self.s0)


_FX: "_Fx | None" = None


def fx() -> _Fx:
    global _FX
    if _FX is None:
        _FX = _Fx()
    return _FX


def _related_full(subject_hex: str) -> dict:
    e = {"verified": True, "verified_under": "k", "subject_digest": None, "subject_digest_state": "absent"}
    return {_A: dict(e, relationships=None), _R: dict(e, relationships=[_edge(subject_hex, "retracts")])}


def _lineage_verdict(r: dict) -> tuple:
    return (r.get("ok"), r.get("policy_ok"), (r.get("automation") or {}).get("safeForAutomation"))


# ── 1. the property: every verdict is the verdict over one state ────────────────────────────────

class EveryVerdictIsTheVerdictOverOneState(unittest.TestCase):

    def _assert_one_state(self, name, call, make, change, verdict, *, first=None, second=None, phasen=False):
        v1, v2, mixed, upto = sweep(call, make, change, verdict, phasen=phasen)
        if first is not None:
            self.assertEqual(v1, first, f"{name}: the first state is not judged as the case assumes")
        if second is not None:
            self.assertEqual(v2, second, f"{name}: the second state is not judged as the case assumes")
        self.assertEqual(mixed, [], f"{name}: a verdict neither state gives, at these gc starts of {upto}")
        return v1, v2

    def test_the_planted_control_is_caught(self):
        """THE SWEEP CAN FAIL. A verdict read twice from one map, with work between the readings as a
        verifier does, is caught; the same verdict read once is not."""
        # `dict.copy` reads the map in one C call, so a callback cannot change it in the middle of a reading (an
        # iteration raised "dictionary changed size during iteration" once, verify lane V4 on 8f2fa980).
        def twice(m):
            first = dict.copy(m)
            _ = [[i] for i in range(400)]
            second = dict.copy(m)
            return "A" in first and "R" not in second

        def once(m):
            only = dict.copy(m)
            _ = [[i] for i in range(400)]
            return "A" in only and "R" not in only
        make = lambda: {"A": 1, "R": 1}  # noqa: E731
        v1, v2, mixed, _ = sweep(twice, make, dict.clear, bool)
        self.assertEqual((v1, v2), (False, False))
        self.assertTrue(mixed, "the sweep did not catch a verdict read twice")
        self.assertEqual(sweep(once, make, dict.clear, bool)[2], [])

    def _lineage(self, name, verify):
        """Two changes of the caller's map. The lens's own: the map is emptied. And two entries at once: the
        parent stops verifying and the retraction is withdrawn, so a reading that takes the parent from
        before and the retraction from after passes, where the map held no such state. Both states of
        each change are refused by the policy, so a mixed verdict that passes shows."""
        f = fx()
        if name not in f.subject:
            self.skipTest("not shipped: examples/decision_receipt_allow.json")
        sh = f.subject[name]

        def two_entries(m):
            m[_A]["verified"] = False
            m[_R]["relationships"] = None
        for label, change in (("emptied", dict.clear), ("two entries at once", two_entries)):
            with self.subTest(change=label):
                v1, v2 = self._assert_one_state(f"{name}, {label}", verify, lambda: _related_full(sh), change,
                                                _lineage_verdict)
                self.assertEqual((v1[0], v1[1], v2[0], v2[1]), (False, False, False, False))

    def test_the_decision_verifier_reads_related_once(self):
        from proofbundle.decision import verify_decision_receipt
        self._lineage("decision", lambda rel: verify_decision_receipt(fx().decision, fx().pub, related=rel,
                                                                      policy=_POLICY))

    def test_the_outcome_verifier_reads_related_once(self):
        from proofbundle.outcome import verify_outcome_receipt
        self._lineage("outcome", lambda rel: verify_outcome_receipt(fx().outcome, fx().pub, related=rel,
                                                                    policy=_POLICY))

    def test_the_relation_statement_verifier_reads_related_once(self):
        from proofbundle.relation_statement import verify_relation_statement
        self._lineage("statement", lambda rel: verify_relation_statement(fx().statement, fx().pub, related=rel,
                                                                         policy=_POLICY))

    def test_the_status_list_issuer_key_is_read_once(self):
        """`self_issued` and the signature check read the key twice; the mixed verdict is a list signed
        by another key reported as self-issued and valid."""
        from proofbundle.statuslist import verify_status_snapshot
        f = fx()

        def call(key):
            return verify_status_snapshot(f.status_token, expected_uri=f.status_uri, index=0, issuer_pubkey=key,
                                          receipt_issuer_pubkey=f.pub)

        def change(key):
            key[:] = _raw(f.status_signer)
        self._assert_one_state("verify_status_snapshot", call, lambda: bytearray(f.pub), change,
                               lambda r: (r["ok"], r["self_issued"]), first=(False, True), second=(True, False))

    def test_the_hybrid_message_is_read_once(self):
        from proofbundle.pqsig import verify_hybrid
        f = fx()
        if f.hybrid is None:
            self.skipTest("NOT MEASURABLE: this build of cryptography has no ML-DSA")

        def change(m):
            m[:] = f.m2
        self._assert_one_state("verify_hybrid", lambda m: verify_hybrid(message=m, **f.hybrid),
                               lambda: bytearray(f.m1), change, bool, first=False, second=False)

    def test_the_join_reads_the_statement_once(self):
        """Validated in one state and digested in the other: a valid statement that the block does not
        cite, then the invalid one it does."""
        from proofbundle.verifier_block import join_test_result
        f = fx()

        def change(s):
            s["predicate"]["url"] = ""
        self._assert_one_state("join_test_result statement", lambda s: join_test_result(f.block_for_s2, s),
                               lambda: copy.deepcopy(f.s0), change, lambda r: r["ok"], first=False,
                               second=False)

    def test_the_join_reads_the_block_once(self):
        from proofbundle.verifier_block import join_test_result
        f = fx()

        def change(b):
            b["testResult"]["statementDigest"]["sha256"] = f.s0_digest
            b["assurance"] = "observedByRunner"
        self._assert_one_state("join_test_result block", lambda b: join_test_result(b, f.s0),
                               lambda: copy.deepcopy(f.block_other), change, lambda r: r["ok"], first=False,
                               second=False)

    def test_the_anchor_list_is_read_as_one_state(self):
        """Two entries changed at once: the first stops matching its root while the second's type becomes one
        a verifier is registered for. Each state FAILs (an unbound anchor, an unknown type); a reading that
        takes the first entry from before and the second from after PASSes."""
        from proofbundle import anchors
        name = "test-read-once/v1"
        root = hashlib.sha256(b"a statement").digest()
        good = {"type": name, "target": "statement", "canonicalRoot": base64.b64encode(root).decode(),
                "proof": base64.b64encode(b"a proof").decode()}

        def change(lst):
            lst[0]["canonicalRoot"] = base64.b64encode(b"\x00" * 32).decode()
            lst[1]["type"] = name
        anchors.register_anchor_type(name, lambda proof, canonical_root, *, frozen, now: {
            "ok": True, "warn": False, "status": "pass", "detail": "registered for this test"})
        try:
            self._assert_one_state(
                "verify_anchors", lambda lst: anchors.verify_anchors(lst, target_roots={"statement": root}),
                lambda: [dict(good), dict(good, type="unregistered-type/v1")], change, lambda r: r["status"],
                first="FAIL", second="FAIL")
        finally:
            anchors._VERIFIERS.pop(name, None)

    def test_the_provider_evidence_is_read_once(self):
        """Untampered in one state and bound to this request in the other."""
        from proofbundle.experimental import attested_inference as ai
        nonce = "nonce-0123456789"
        req, res = b"the request", b"the response"
        e1 = {"request_hash": hashlib.sha256(req).hexdigest(), "response_hash": hashlib.sha256(res).hexdigest(),
              "route": "route-1", "binding": "none-given-for-this-one"}
        expected = ai.evidence_digest(e1)

        def call(e):
            return ai.check_on_receipt(e, provider="p", nonce=nonce, request_bytes=req, response_bytes=res,
                                       planned_route="route-1", expected_evidence_digest=expected)

        def change(e):
            e["binding"] = nonce
        self._assert_one_state("check_on_receipt", call, lambda: copy.deepcopy(e1), change,
                               lambda r: r["outcome"], first=ai.OUTCOME_ATTESTATION_FAILURE,
                               second=ai.OUTCOME_ATTESTATION_FAILURE)

    # ── the surfaces the verify lanes on 6d674973 found (V1, V2, V3), each read at its call now ─────────

    def test_an_eval_results_entry_is_read_as_one_state(self):
        """V1 F1, V2 F1: the token was read, verified, and the value read after it; 22 of 112 starts gave `ok` True
        where both states are refused."""
        from proofbundle.evalclaim import build_eval_claim, emit_eval_receipt
        from proofbundle.hf_evals import to_eval_results_entry, verify_eval_results_entry
        from proofbundle import generate_signer

        def token(score):
            claim, _ = build_eval_claim(suite="s", suite_version="1", metric="acc", comparator=">=", threshold="0.8",
                                        score=score, n=10, model_id="m", dataset_id="d", issuer="Lab",
                                        timestamp="2026-07-02T00:00:00Z")
            return to_eval_results_entry(emit_eval_receipt(claim, generate_signer()), dataset_id="d", task_id="t",
                                         value=float(score))["verifyToken"]
        bestanden, durchgefallen = token("0.9"), token("0.5")

        def change(e):
            e["verifyToken"] = durchgefallen
            e["value"] = 0.9
        self._assert_one_state("verify_eval_results_entry", verify_eval_results_entry,
                               lambda: {"verifyToken": bestanden, "value": 0.5}, change,
                               lambda r: (r["ok"], r["crypto_ok"], r["value_consistent"]),
                               first=(False, True, False), second=(False, True, False))

    def test_the_target_roots_of_an_anchor_list_are_read_as_one_state(self):
        """V2 F2, V3 F1: the roots were read one target at a time, after the anchor list."""
        from proofbundle import anchors
        name = "test-read-once-roots/v1"
        r1, r2 = hashlib.sha256(b"receipt root").digest(), hashlib.sha256(b"statement root").digest()
        w1, w2 = hashlib.sha256(b"wrong receipt").digest(), hashlib.sha256(b"wrong statement").digest()

        def eintrag(ziel, wurzel):
            return {"type": name, "target": ziel, "canonicalRoot": base64.b64encode(wurzel).decode(),
                    "proof": base64.b64encode(b"p").decode()}
        liste = [eintrag("receipt", r1), eintrag("statement", r2)]

        def change(m):
            m["receipt"] = w1
            m["statement"] = r2
        anchors.register_anchor_type(name, lambda proof, canonical_root, *, frozen, now: {
            "ok": True, "warn": False, "status": "pass", "detail": "registered for this test"})
        try:
            self._assert_one_state(
                "verify_anchors target_roots", lambda m: anchors.verify_anchors(copy.deepcopy(liste), target_roots=m),
                lambda: {"receipt": r1, "statement": w2}, change, lambda r: r["status"], first="FAIL", second="FAIL")
        finally:
            anchors._VERIFIERS.pop(name, None)

    def test_a_renewal_sequence_is_read_as_one_state(self):
        """V2 F3: each chain was copied at its own time; 6 of 73 starts gave `ok` True for a sequence neither state
        holds."""
        import dataclasses
        from proofbundle.renewal import build_initial_sequence, renew_hashtree, verify_sequence
        daten = ["a" * 64, "b" * 64, "c" * 64]
        gut = renew_hashtree(build_initial_sequence(daten, hash_alg="sha256", time=1000), daten,
                             new_hash_alg="sha512", time=2000)
        g0, g1 = list(gut[0]), list(gut[1])

        def kaputt(kette):
            return [dataclasses.replace(kette[0], covered_digest="0" * 64)] + list(kette[1:])
        b0, b1 = kaputt(g0), kaputt(g1)

        def change(seq):
            seq[0][:] = b0
            seq[1][:] = g1
        self._assert_one_state(
            "verify_sequence", lambda seq: verify_sequence(seq, daten, allow_unauthenticated_anchor=True),
            lambda: [list(g0), list(b1)], change, lambda r: r.ok, first=False, second=False)

    def test_an_agt_receipt_chain_is_read_as_one_state(self):
        """V2 F4: one receipt was read at a time; 8 of 78 starts gave a chain neither state holds."""
        from proofbundle.adapters.agt_receipt import verify_agt_receipt_chain
        vektoren = REPO / "tests" / "vektoren" / "agt_receipts"
        if not (vektoren / "01_allow.json").is_file():
            self.skipTest("NOT MEASURABLE: tests/vektoren/agt_receipts is not in this tree")
        r1 = json.loads((vektoren / "01_allow.json").read_text(encoding="utf-8"))
        r2 = json.loads((vektoren / "02_deny.json").read_text(encoding="utf-8"))
        r1_falsch = dict(r1, cedar_decision="deny" if r1["cedar_decision"] == "allow" else "allow")
        r2_falsch = dict(r2, cedar_decision="allow" if r2["cedar_decision"] == "deny" else "deny")

        def change(seq):
            seq[0].clear()
            seq[0].update(copy.deepcopy(r1_falsch))
            seq[1].clear()
            seq[1].update(copy.deepcopy(r2))
        self._assert_one_state("verify_agt_receipt_chain", verify_agt_receipt_chain,
                               lambda: [copy.deepcopy(r1), copy.deepcopy(r2_falsch)], change, lambda r: r.ok,
                               first=False, second=False)

    def test_a_cap1_document_is_read_as_one_state(self):
        """V2 F5: nine rules each read the document at their own time; 12 of 58 starts judged it conformant."""
        from proofbundle import cap1
        vektoren = REPO / "conformance" / "cap1" / "vectors"
        if not (vektoren / "NC-07.json").is_file():
            self.skipTest("NOT MEASURABLE: conformance/cap1/vectors is not in this tree")
        a = json.loads((vektoren / "NC-07.json").read_text(encoding="utf-8"))
        b = json.loads((vektoren / "NC-02.json").read_text(encoding="utf-8"))

        def change(d):
            d.clear()
            d.update(copy.deepcopy(b))
        v1, v2 = self._assert_one_state("check_cap1_document", cap1.check_cap1_document, lambda: copy.deepcopy(a),
                                        change, lambda r: tuple(sorted({e["rule"] for e in r})))
        self.assertTrue(v1 and v2, "the case needs two documents that are each refused")

    def test_the_policy_and_the_related_map_are_read_as_one_state(self):
        """V2 F6: each argument was read once, at its own time; a callback that changed both gave `ok` True under a
        pair neither state holds (246 of 603 starts at decision)."""
        from proofbundle.decision import verify_decision_receipt
        from proofbundle.outcome import verify_outcome_receipt
        from proofbundle.relation_statement import verify_relation_statement
        f = fx()

        def p0():
            return {"schema": "proofbundle/trust-policy/v0.2", "policy_id": "t/x", "relations": {"reject_superseded": True}}

        def change(st):
            st[0]["relations"] = {"reject_superseded": True, "require_relation_resolution": ["derivedFrom"]}
            st[1].clear()
        for name, pruefer in (("decision", verify_decision_receipt), ("outcome", verify_outcome_receipt),
                              ("statement", verify_relation_statement)):
            if name not in f.subject:
                continue
            umschlag, sh = getattr(f, name), f.subject[name]
            with self.subTest(verifier=name):
                v1, v2 = self._assert_one_state(
                    f"{name}, policy and related", lambda st: pruefer(umschlag, f.pub, policy=st[0], related=st[1]),
                    lambda: (p0(), _related_full(sh)), change, _lineage_verdict)
                self.assertEqual((v1[0], v2[0]), (False, False))

    def test_the_block_and_the_statement_of_a_join_are_read_as_one_state(self):
        """V2 F6: block and statement changed together gave `ok` True for a pair neither state holds."""
        from proofbundle import verifier_block as vb
        f = fx()
        s1 = vb.build_test_result_statement(
            build={"digest": {"sha256": "1" * 64}, "source": "source-tree", "files": 7}, version="6.2.1",
            vector_set={"name": "proofbundle.conformance.manifest.v1", "digest": {"sha256": "2" * 64}, "cases": 2},
            results=[{"caseId": "a", "ok": True, "scope": "full"}, {"caseId": "b", "ok": True, "scope": "full"}])
        block_gut = vb.build_verifier_block(
            build={"digest": {"sha256": "1" * 64}, "source": "source-tree", "files": 7}, version="6.2.0",
            vector_set={"name": "proofbundle.conformance.manifest.v1", "digest": {"sha256": "2" * 64}, "cases": 2},
            test_result={"predicateType": vb.TEST_RESULT_PREDICATE_TYPE, "result": f.s0["predicate"]["result"],
                         "statementDigest": {"sha256": f.s0_digest}})

        def change(st):
            st[0].clear()
            st[0].update(copy.deepcopy(f.block_other))
            st[1].clear()
            st[1].update(copy.deepcopy(f.s0))
        self._assert_one_state("join_test_result, block and statement", lambda st: vb.join_test_result(st[0], st[1]),
                               lambda: (copy.deepcopy(block_gut), copy.deepcopy(s1)), change, lambda r: r["ok"],
                               first=False, second=False)

    def test_a_proof_over_the_budget_is_judged_in_the_state_the_budget_saw(self):
        """V2 F7: the budget read one state and the copy another; a proof whose second state is over the budget was
        accepted (`verify_offline_merkle` 1 of 31, new with 6d674973)."""
        from proofbundle.anchors_chia import verify_offline_merkle
        from proofbundle.budget import DEFAULT_BUDGET
        wurzel = hashlib.sha256(b"a root").digest()
        kc = hashlib.sha256(b"\x01" + wurzel).digest()
        vc = hashlib.sha256(b"\x01" + b"\xab").digest()
        blatt = hashlib.sha256(b"\x02" + kc + vc).digest()
        gut = {"key": wurzel.hex(), "value": "ab", "key_clvm_hash": kc.hex(), "value_clvm_hash": vc.hex(),
               "published_root": blatt.hex(), "inclusion_layers": []}
        polster = "x" * (gedeckelt(DEFAULT_BUDGET.string_len, bytes_je_element=KOSTEN_JE_ELEMENT["string_len"]) + 100_000)

        def change(p):
            p["key"] = gut["key"]
            p["pad"] = polster
        self._assert_one_state("verify_offline_merkle, budget and copy", lambda p: verify_offline_merkle(p, wurzel),
                               lambda: dict(gut, key=hashlib.sha256(b"other").digest().hex()), change,
                               lambda r: r["ok"], first=False, second=False)

    def test_a_receipt_chain_of_agent_reviews_is_resolved_over_one_state(self):
        """V2 F10: each envelope was read at its own time (a name outside the five scanned prefixes)."""
        from proofbundle.agent_review import resolve_receipt_chain

        def kodiert(o):
            return base64.b64encode(json.dumps(o, sort_keys=True).encode()).decode()

        def digest(o):
            return hashlib.sha256(json.dumps(o, sort_keys=True).encode()).hexdigest()
        a1, a2 = {"predicate": {"n": 1}}, {"predicate": {"n": 2}}
        b1 = {"predicate": {"supersession": {"corrects": [{"priorDigest": {"sha256": digest(a1)}}]}}}
        b2 = {"predicate": {"supersession": {"corrects": [{"priorDigest": {"sha256": digest(a2)}}]}}}
        geprueft = {digest(b1), digest(b2)}

        def change(envs):
            envs[0]["payload"] = kodiert(a2)
            envs[1]["payload"] = kodiert(b2)
        self._assert_one_state(
            "resolve_receipt_chain", lambda envs: resolve_receipt_chain(envs, verified=geprueft),
            lambda: [{"payload": kodiert(a1), "payloadType": "x"}, {"payload": kodiert(b1), "payloadType": "x"}],
            change, lambda r: (r["current"], r["ambiguous"], r["integrity_ok"], tuple(r["corrected"])))

    def test_a_mapping_the_caller_reads_through_its_own_methods_is_read_once_at_the_call(self):
        """V2 F12 and F9: `automation_summary` read a Mapping at eight places, `verify_rfc3161` a relying party's
        Mapping through its own `items()` after the call began. The boundary reads a Mapping that is no dict once,
        with the other arguments."""
        from collections.abc import Mapping as _Mapping
        from proofbundle.automation_verdict import automation_summary

        class _Buchung:   # an instance with a __dict__ is tracked by the collector; a bare object() is not
            pass

        class Sicht(_Mapping):
            def __init__(self, d):
                self._d = d

            def __getitem__(self, k):
                v = self._d[k]
                _ = [_Buchung(), _Buchung(), _Buchung()]
                return v

            def __iter__(self):
                return iter(list(self._d))

            def __len__(self):
                return len(self._d)
        pruefungen = {"crypto": "crypto_ok", "structure": "structure_ok", "policy": "policy_ok",
                      "references": ["evidence_bound"]}
        a = {"crypto_ok": True, "structure_ok": False, "policy_ok": True, "evidence_bound": True, "ok": True}
        b = {"crypto_ok": False, "structure_ok": True, "policy_ok": True, "evidence_bound": True, "ok": True}

        def mache():
            d = dict(a)
            return (Sicht(d), d)

        def change(st):
            st[1].clear()
            st[1].update(b)
        self._assert_one_state("automation_summary over a Mapping view",
                               lambda st: automation_summary(st[0], required_checks=pruefungen), mache, change,
                               lambda s: s["safeForAutomation"], first=False, second=False)

    def test_a_result_object_is_read_once_at_the_call(self):
        """V2 F11: `evaluate_public_transparency` read a result object at five places; one whose fields are computed
        on each access passed with a root and a confirmation from two states."""
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        from proofbundle import checkpoint as cp, emit_bundle, generate_signer
        from proofbundle.public_transparency import ConsistencyVerificationResult as Cvr
        from proofbundle.public_transparency import evaluate_public_transparency
        herkunft = "example.com/demo-log"
        log = generate_signer()
        buendel = emit_bundle(b'{"x":1}', log, prior_leaves=[b"e1", b"e2"])
        wurzel, groesse = buendel["merkle"]["root_b64"], buendel["merkle"]["tree_size"]
        notiz = cp.sign_checkpoint(herkunft, groesse, base64.b64decode(wurzel), log, herkunft)
        schluessel = cp.vkey(herkunft, log.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
        politik = {"requireSignedCheckpoint": True, "requireConsistencyProof": True}
        felder = list(Cvr.__dataclass_fields__)

        def satz(neu, bestaetigt):
            c = Cvr(old_origin=herkunft, old_tree_size=1, old_root_b64="A" * 44, new_origin=herkunft,
                    new_tree_size=groesse, new_root_b64=neu, proof_digest="d", verifier_version="v",
                    policy_digest="p", confirmed=bestaetigt)
            return {f: getattr(c, f) for f in felder}

        class Sicht:
            def __init__(self, rec):
                self._rec = rec

            def __getattr__(self, name):
                if name in felder:
                    return dict(self._rec)[name]
                raise AttributeError(name)

            def validate(self):
                return Cvr.validate(self)

        def change(v):
            v._rec.update(new_root_b64="B" * 44, confirmed=True)
        self._assert_one_state(
            "evaluate_public_transparency over a view-style result",
            lambda v: evaluate_public_transparency(notiz, politik, log_vkey=schluessel, consistency_result=v),
            lambda: Sicht(satz(wurzel, False)), change, lambda r: r["statuses"]["CONSISTENCY"],
            first="FAIL", second="FAIL")

    def test_a_markovian_root_is_read_as_one_state(self):
        """V1 F3 on 6d674973: the envelope bound one reading of the target root and the Bitcoin proof was checked against
        another (at d388ed3d `confirmed` at 29 of 51 starts, where neither state confirms); an earlier text of this file
        said no collection starts between those readings. With a real OpenTimestamps proof, as the lane measured it."""
        try:
            from opentimestamps.core.notary import BitcoinBlockHeaderAttestation
            from opentimestamps.core.op import OpAppend, OpSHA256
            from opentimestamps.core.serialize import BytesSerializationContext
            from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp
        except ImportError:
            self.skipTest("NOT MEASURABLE: the [anchors] extra (opentimestamps) is not installed")
        from proofbundle.anchors_markovian import verify_markovian

        def aufgewertet(nachricht, hoehe=850000):
            ts = Timestamp(nachricht)
            blatt = ts.ops.add(OpAppend(b"\x00")).ops.add(OpSHA256())
            blatt.attestations.add(BitcoinBlockHeaderAttestation(hoehe))
            ctx = BytesSerializationContext()
            DetachedTimestampFile(OpSHA256(), ts).serialize(ctx)
            return ctx.getbytes()
        r1, r2 = hashlib.sha256(b"root one").digest(), hashlib.sha256(b"root two").digest()
        salz, wallet = "00112233445566778899aabbccddeeff", "1MKVtestWa11etAAAAAAAAAAAAAAAAAAAA"
        mr = hashlib.sha256(f"{r1.hex()}:{salz}:{wallet}".encode()).hexdigest()
        umschlag = json.dumps({"schema": "markovian-provenance/v1", "data_hash": r1.hex(), "salt": salz,
                               "wallet": wallet, "merkle_root": mr, "block_height": 77810,
                               "ots": base64.b64encode(aufgewertet(r2)).decode()}).encode()
        rp = {"bitcoin_block_headers": {"850000": hashlib.sha256(r2 + b"\x00").hexdigest()}}

        def change(w):
            w[:] = r2
        v1, v2 = self._assert_one_state(
            "verify_markovian", lambda w: verify_markovian(umschlag, w, frozen={}, rp_trust=rp)["status"],
            lambda: bytearray(r1), change, lambda s: s)
        self.assertNotIn("confirmed", (v1, v2), "the case needs two states in which the anchor does not confirm")

    def test_a_relying_partys_hybrid_keys_are_read_as_one_state(self):
        """The neighbour of `verify_hybrid` in `renewal`: both authority keys were read at their own time
        (measured at d388ed3d: 1 of 63 starts gave `ok` True for two keys of two states)."""
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as _Ed
        from proofbundle import pqsig, renewal
        try:
            ml, ml2 = pqsig.generate_mldsa("mldsa65"), pqsig.generate_mldsa("mldsa65")
        except pqsig.PQUnavailable:
            self.skipTest("NOT MEASURABLE: this build of cryptography has no ML-DSA")
        ed, ed2 = _Ed.generate(), _Ed.generate()
        daten = ["a" * 64]
        folge = renewal.build_initial_sequence(daten, hash_alg="sha256", time=1_780_000_000,
                                               sig_alg="hybrid-ed25519-mldsa65",
                                               signers={"ed25519": ed, "mldsa65": ml})
        eg, mg = ed.public_key().public_bytes_raw(), ml.public_key().public_bytes_raw()
        eb, mb = ed2.public_key().public_bytes_raw(), ml2.public_key().public_bytes_raw()

        def change(d):
            d["ed25519"] = eb
            d["mldsa65"] = mg
        self._assert_one_state("verify_sequence authority keys",
                               lambda k: renewal.verify_sequence(folge, daten, authority_keys=k),
                               lambda: {"ed25519": eg, "mldsa65": mb}, change, lambda r: r.ok,
                               first=False, second=False)

    def test_a_mapping_of_digests_is_refused_as_before(self):
        """V4 F3 on 8f2fa980: a reader at the call turned a Mapping of digests into a dict, and `verify_dual_hash`,
        which refused it at both tags and at d388ed3d (the structural budget refuses every non-dict Mapping),
        accepted it. The digests are handed on as the caller's Mapping, read once in the body."""
        from collections import UserDict
        from types import MappingProxyType
        from proofbundle.hashalg import verify_dual_hash
        daten = b"the data"
        d = {"sha256": hashlib.sha256(daten).hexdigest()}
        self.assertTrue(verify_dual_hash(daten, dict(d)).ok)
        for sicht in (UserDict(d), MappingProxyType(d), _Sicht(d)):
            with self.subTest(mapping=type(sicht).__name__):
                self.assertFalse(verify_dual_hash(daten, sicht).ok)

    def test_a_relying_partys_mapping_at_an_rfc3161_anchor_is_read_as_one_state(self):
        """V2 F9 on 6d674973: `verify_rfc3161` read a Mapping `rp_trust` through its own `items()` after the call
        began, and a status came out that neither state gives."""
        from proofbundle.anchors_rfc3161 import verify_rfc3161
        a = {"trusted_tsa_roots": ["QUJD"], "trusted_tsa_policy_oids": "not-a-list"}
        b = {"trusted_tsa_roots": [], "trusted_tsa_policy_oids": ["1.2.3"]}

        def mache():
            d = dict(a)
            return (_Sicht(d), d)

        def change(st):
            st[1].clear()
            st[1].update(b)
        self._assert_one_state(
            "verify_rfc3161 rp_trust", lambda st: verify_rfc3161(b"proof", b"root", frozen={}, rp_trust=st[0]),
            mache, change, lambda r: (r.get("ok"), r.get("status")))

    def test_a_bundle_over_the_budget_is_judged_in_the_state_the_budget_saw(self):
        """V2 F7 on 6d674973: `verify_bundle` bounded one reading and copied another; a bundle whose second state
        is over the budget was verified."""
        from proofbundle import emit_bundle, generate_signer, verify_bundle
        from proofbundle.budget import DEFAULT_BUDGET
        sk = generate_signer()
        klein = emit_bundle(b'{"x": 1}', sk)
        gross = emit_bundle(b"y" * (gedeckelt(DEFAULT_BUDGET.string_len, bytes_je_element=KOSTEN_JE_ELEMENT["string_len"])
                                    * 3 // 4 + 1000), sk)
        falsch = copy.deepcopy(klein)
        falsch["payload_b64"] = gross["payload_b64"][:16]

        def aufruf(b):
            try:
                r = verify_bundle(b)
                return "ok" if r.ok else "not ok"
            except Exception as exc:  # noqa: BLE001 - a refusal of the budget is a verdict here
                return type(exc).__name__

        def change(b):
            b.clear()
            b.update(copy.deepcopy(gross))
        v1, v2 = self._assert_one_state("verify_bundle budget and copy", aufruf, lambda: copy.deepcopy(falsch),
                                        change, lambda v: v)
        self.assertNotIn("ok", (v1, v2), "the case needs two states that are both refused")

    def test_the_edges_over_the_budget_are_judged_in_the_state_the_budget_saw(self):
        """V2 F7 on 6d674973: `verify_relationship_edges` bounded one reading of the edges and copied another."""
        from proofbundle.budget import DEFAULT_BUDGET
        from proofbundle.relation import verify_relationship_edges
        x, y = "8" * 64, "7" * 64
        polster = "x" * (gedeckelt(DEFAULT_BUDGET.string_len, bytes_je_element=KOSTEN_JE_ELEMENT["string_len"]) + 1000)
        verwandt = {y: {"verified": True, "verified_under": "k", "subject_digest": None,
                        "subject_digest_state": "absent", "relationships": None}}

        def change(lst):
            lst[0] = dict(_edge(y, "derivedFrom"), reason=polster)
        v1, v2 = self._assert_one_state(
            "verify_relationship_edges budget and copy", lambda lst: verify_relationship_edges(lst, verwandt)["lineage"],
            lambda: [_edge(x, "derivedFrom")], change, lambda v: v)
        self.assertNotIn("VERIFIED", (v1, v2))

    # ── the surfaces verify lane V5 on 8f2fa980 found ────────────────────────────────────────────────

    def test_a_renewal_policy_is_read_as_one_state_at_its_classmethod(self):
        """V5-01: `RenewalPolicy.from_dict`, a public classmethod, read the caller's dict three times; a policy neither
        state holds passed `evaluate_renewal_policy`, where both states fail."""
        from proofbundle.renewal import RenewalPolicy, build_initial_sequence, evaluate_renewal_policy
        folge = build_initial_sequence(["a" * 64], hash_alg="sha256", time=1000)

        def change(d):
            d["max_ats_age"] = 1
            d["deprecated_algs"] = []
        self._assert_one_state(
            "RenewalPolicy.from_dict", RenewalPolicy.from_dict,
            lambda: {"strictness": "fail", "max_ats_age": 1_000_000, "deprecated_algs": ["sha256"]}, change,
            lambda p: evaluate_renewal_policy(folge, policy=p, now=1100).ok, first=False, second=False, phasen=True)

    def test_a_result_object_of_this_package_is_read_as_one_state(self):
        """V5-02: a `VerificationResult` and its `Check` objects were handed on as the caller's objects;
        `root_authenticity_summary`, `evaluate_policy` and `exit_code` read them at several times."""
        from proofbundle import emit_bundle, generate_signer, verify_bundle
        from proofbundle.adapters.agt_receipt import exit_code
        from proofbundle.bundle import root_authenticity_summary
        from proofbundle.errors import Check, VerificationResult
        from proofbundle.policy import evaluate_policy

        def ersetzt(neu):
            def change(r):
                r.checks[:] = neu()
            return change
        with self.subTest(surface="root_authenticity_summary"):
            self._assert_one_state(
                "root_authenticity_summary",
                lambda r: root_authenticity_summary(r, policy_ok=True, signer_trusted=True,
                                                    tree_context_authenticated=True, checkpoint_authenticity="PASS"),
                lambda: VerificationResult([Check("ed25519-signature", True), Check("root-authenticity", True),
                                            Check("merkle-inclusion", False)]),
                ersetzt(lambda: [Check("ed25519-signature", True), Check("merkle-inclusion", True)]),
                lambda d: (d["safeForAutomation"], tuple(d["automationBlockers"])), phasen=True)
        with self.subTest(surface="exit_code"):
            self._assert_one_state("exit_code", exit_code, lambda: VerificationResult([Check("chain-link", False)]),
                                   ersetzt(lambda: [Check("readable", False)]), lambda x: x, first=1, second=2,
                                   phasen=True)
        with self.subTest(surface="evaluate_policy"):
            buendel = emit_bundle(b'{"x":1}', generate_signer())
            echt = verify_bundle(buendel)
            erste = echt.checks[0].name
            politik = {"schema": "proofbundle/trust-policy/v0.1", "policy_id": "t/x",
                       "merkle": {"require_authenticated_root": True}}
            self._assert_one_state(
                "evaluate_policy", lambda r: evaluate_policy(buendel, r, politik),
                lambda: VerificationResult([Check(c.name, True, c.detail) for c in echt.checks
                                            if c.name != "root-authenticity"]),
                ersetzt(lambda: [Check(c.name, c.name != erste, "") for c in echt.checks
                                 if c.name != "root-authenticity"] + [Check("root-authenticity", True, "")]),
                lambda d: d["policy_ok"], phasen=True)

    def test_a_result_object_that_changes_its_class_is_read_as_one_state(self):
        """Codex review of pull request 311 (thread 4151141239, P1): the second collect compared what each container
        holds but not its type, and a dataclass of this package is copied as the type the first collect read. A callback
        that made a `VerificationResult` a `Check` between the two collects and put a passing check into its list gave a
        copy of a `VerificationResult` holding the passing check, a state the value never held: `safeForAutomation` True
        in 3 of 299 runs at 6b02d9f7, where both states give False."""
        from proofbundle.bundle import root_authenticity_summary
        from proofbundle.errors import Check, VerificationResult

        def change(r):
            r.__class__ = Check
            r.checks[0] = Check("root-authenticity", True)
        self._assert_one_state(
            "root_authenticity_summary, a change of class",
            lambda r: root_authenticity_summary(r, policy_authenticated_root=True, policy_ok=True, signer_trusted=True,
                                                tree_context_authenticated=True),
            lambda: VerificationResult([Check("root-authenticity", False)]), change,
            lambda d: d["safeForAutomation"], first=False, second=False, phasen=True)

    def test_the_signatures_of_an_archive_timestamp_are_read_as_one_state(self):
        """V5-03: an `ArchiveTimeStamp` kept its `signatures` list as the caller's object; `verify_sequence` read it
        for the rollback digest and again for the authority signature, and passed an ATS whose two states each fail.
        From the refused signature to the valid one: the other direction never gave ok True at 8f2fa980, where the
        class was open, so a sweep in it could not fall (verify lane V7 on 085869313; this one gave 18 of 157)."""
        import dataclasses
        from proofbundle.renewal import anchor_proof_digest, build_initial_sequence, verify_sequence
        schluessel = Ed25519PrivateKey.generate()
        daten = ["a" * 64]
        ats0 = build_initial_sequence(daten, hash_alg="sha256", time=1000, sig_alg="ed25519",
                                      signers={"ed25519": schluessel})[0][0]
        gueltig = dict(ats0.signatures)["ed25519"]
        falsch = base64.b64encode(b"\x00" * 64).decode()
        erinnert = anchor_proof_digest(dataclasses.replace(ats0, signatures=(("ed25519", falsch),)))

        def change(a):
            a.signatures[:] = [("ed25519", gueltig)]
        self._assert_one_state(
            "verify_sequence signatures",
            lambda a: verify_sequence([[a]], daten, authority_keys={"ed25519": _raw(schluessel)},
                                      known_newest_token_digest=erinnert),
            lambda: dataclasses.replace(ats0, signatures=[("ed25519", falsch)]), change, lambda r: r.ok,
            first=False, second=False)

    def test_the_size_cap_of_an_opentimestamps_token_holds_for_the_bytes_handed_on(self):
        """V5-03: the `external_token` bytearray of an ATS stayed the caller's object and was handed from the package's
        own frame to `verify_opentimestamps`, whose reading at the call was skipped; its size was checked on one state
        and the library was handed another, four times the cap."""
        import dataclasses
        try:
            from opentimestamps.core import serialize
        except ImportError:
            self.skipTest("NOT MEASURABLE: the [anchors] extra (opentimestamps) is not installed")
        from proofbundle import anchors_ots
        from proofbundle.renewal import build_initial_sequence, verify_sequence
        grenze = anchors_ots._MAX_OTS_PROOF_BYTES
        gereicht: list = []
        original = serialize.BytesDeserializationContext.__init__

        def spion(self_, buf):
            gereicht.append(len(buf))
            return original(self_, buf)
        daten = ["a" * 64]
        ats = build_initial_sequence(daten, hash_alg="sha256", time=1000)[0][0]

        def change(a):
            a.external_token[:] = b"\x00" * (grenze * 4)

        def aufruf(a):
            gereicht.clear()
            verify_sequence([[a]], daten, allow_unauthenticated_anchor=True, rp_trust={})
            return max(gereicht, default=0) <= grenze
        serialize.BytesDeserializationContext.__init__ = spion
        try:
            self._assert_one_state(
                "verify_sequence external token", aufruf,
                lambda: dataclasses.replace(ats, external_token_type="opentimestamps",
                                            external_token=bytearray(b"\x00" * 100)),
                change, lambda v: v, first=True, second=True, phasen=True)
        finally:
            serialize.BytesDeserializationContext.__init__ = original

    def test_a_map_keyed_by_a_str_subclass_is_read_as_one_state(self):
        """V5-04: a dict with a key of a `str` subclass that overrides nothing stayed the caller's object, so the reading
        at the call did not cover it: `verify_decision_receipt` ok True in 291 of 618 runs where both states give False,
        a level of `evidence_ladder_summary` neither state holds, and a raw RuntimeError out of `statement_content_root`."""
        from proofbundle.assurance import EvidenceLevel, evidence_ladder_summary
        from proofbundle.canonical import statement_content_root
        from proofbundle.decision import verify_decision_receipt
        from proofbundle.outcome import verify_outcome_receipt

        class K(str):
            pass
        f = fx()

        def change(st):
            st[0]["relations"] = {"reject_superseded": True, "require_relation_resolution": ["derivedFrom"]}
            st[1].clear()
        for name, pruefer in (("decision", verify_decision_receipt), ("outcome", verify_outcome_receipt)):
            if name not in f.subject:
                continue
            umschlag, sh = getattr(f, name), f.subject[name]
            with self.subTest(surface=name):
                self._assert_one_state(
                    f"{name}, related keyed by a str subclass",
                    lambda st: pruefer(umschlag, f.pub, policy=st[0], related=st[1]),
                    lambda: ({"schema": "proofbundle/trust-policy/v0.2", "policy_id": "t/x",
                              "relations": {"reject_superseded": True}},
                             {K(k): v for k, v in _related_full(sh).items()}),
                    change, _lineage_verdict)
        stufe = EvidenceLevel

        def feld(level):
            return {"level": level, "level_name": level.name, K("note"): "x"}

        def stufen(fs):
            fs[0]["level"], fs[0]["level_name"] = stufe.CONTENT_RESOLVED, stufe.CONTENT_RESOLVED.name
            fs[1]["level"], fs[1]["level_name"] = stufe.REFERENCE_WELL_FORMED, stufe.REFERENCE_WELL_FORMED.name
        with self.subTest(surface="evidence_ladder_summary"):
            self._assert_one_state("evidence_ladder_summary", lambda fs: evidence_ladder_summary(*fs),
                                   lambda: [feld(stufe.CLAIMED), feld(stufe.CONTENT_RESOLVED)], stufen,
                                   lambda r: r["level_name"], phasen=True)

        def aussage():
            return {"_type": "https://in-toto.io/Statement/v1",
                    "subject": [{"name": "x", "digest": {"sha256": "a" * 64}}],
                    "predicateType": "https://example.org/p",
                    "predicate": {"n%d" % i: [i, {"a": i}] for i in range(30)}, K("extra"): 1}

        def wurzel(d):
            try:
                return statement_content_root(d, require_statement_shape=True).hex()
            except Exception as exc:  # noqa: BLE001 - a raw exception is the finding
                return type(exc).__name__
        with self.subTest(surface="statement_content_root"):
            self._assert_one_state("statement_content_root", wurzel, aussage,
                                   lambda d: d.__setitem__("added", [1, 2, 3]), lambda v: v, phasen=True)


# ── 2. the `related` map is read once, counted ──────────────────────────────────────────────────

class TheRelatedMapIsReadOnce(unittest.TestCase):

    def test_one_reading_per_verifier_call(self):
        from proofbundle import relation
        from proofbundle.decision import verify_decision_receipt
        from proofbundle.outcome import verify_outcome_receipt
        from proofbundle.relation_statement import verify_relation_statement
        f = fx()
        cases = {"outcome": lambda rel: verify_outcome_receipt(f.outcome, f.pub, related=rel, policy=_POLICY),
                 "statement": lambda rel: verify_relation_statement(f.statement, f.pub, related=rel,
                                                                    policy=_POLICY)}
        if f.decision is not None:
            cases["decision"] = lambda rel: verify_decision_receipt(f.decision, f.pub, related=rel, policy=_POLICY)
        original = relation._read_attached_entries
        for name, call in cases.items():
            count = {"n": 0}

            def counting(related, _count=count):
                _count["n"] += 1
                return original(related)
            relation._read_attached_entries = counting
            try:
                r = call(_related_full(f.subject[name]))
            finally:
                relation._read_attached_entries = original
            with self.subTest(verifier=name):
                self.assertEqual(count["n"], 1, f"{name} read the caller's map {count['n']} times")
                self.assertFalse(r["ok"], "the attached retraction must refuse")
                self.assertTrue(r["lineage"]["supersededByAttached"])


# ── 3. one reading by what the value stores, not through its own methods ────────────────────────

class OneReadingByWhatItStores(unittest.TestCase):

    def test_an_eat_whose_own_methods_disagree_is_read_as_its_text(self):
        """At d388ed3d a `str` subclass whose `count` answered 2 and whose `split` gave four parts escaped
        `verify_enclave_attestation` as a raw ValueError (measured)."""
        from proofbundle.experimental.enclave import verify_enclave_attestation

        class Token(str):
            def count(self, x, *a):
                return 2

            def split(self, *a, **k):
                return ["a", "b", "c", "d"]
        r = verify_enclave_attestation(Token("x.y"), verifier_pubkey=b"\x01" * 32, expected_binding="b" * 43)
        self.assertFalse(r["ok"])
        self.assertEqual(r["detail"], "not a compact JWS")

    def test_evidence_is_copied_without_running_a_key_of_the_caller(self):
        """A key whose own `__str__` rewrites two members of the evidence while the one reading copies it. At 6d674973
        the copy took the request hash from before and the binding from after, and without an expected digest the
        answer was ACCEPTED, where the evidence before is not bound to this request and the evidence after names
        another request. The copy reads keys by their characters now, so the key's own method never runs."""
        from proofbundle.experimental import attested_inference as ai
        nonce = "nonce-0123456789"
        req, res = b"the request", b"the response"
        vorher = {"request_hash": hashlib.sha256(req).hexdigest(), "response_hash": hashlib.sha256(res).hexdigest(),
                  "route": "route-1", "note": "x", "binding": "none-given-for-this-one"}
        nachher = dict(vorher, request_hash="0" * 64, binding=nonce)

        def call(e):
            return ai.check_on_receipt(e, provider="p", nonce=nonce, request_bytes=req, response_bytes=res,
                                       planned_route="route-1")["outcome"]
        evidence: dict = {}

        class Key(str):
            def __str__(self):
                evidence["request_hash"] = nachher["request_hash"]
                evidence["binding"] = nachher["binding"]
                return str.__str__(self)
        for k, v in vorher.items():
            evidence[Key(k) if k == "note" else k] = v
        staende = {call(dict(vorher)), call(dict(nachher))}
        self.assertNotIn(ai.OUTCOME_ACCEPTED, staende, "the case needs two states that are both refused")
        self.assertIn(call(evidence), staende)

    def test_a_datalayer_proof_is_read_as_the_bytes_it_stores(self):
        from proofbundle.anchors_chia import verify_chia_datalayer
        root = hashlib.sha256(b"a root").digest()
        key_clvm = hashlib.sha256(b"\x01" + root).digest()
        value_clvm = hashlib.sha256(b"\x01" + b"\xab").digest()
        leaf = hashlib.sha256(b"\x02" + key_clvm + value_clvm).digest()
        stored = json.dumps({"key": root.hex(), "value": "ab", "key_clvm_hash": key_clvm.hex(),
                             "value_clvm_hash": value_clvm.hex(), "published_root": leaf.hex(),
                             "inclusion_layers": []}).encode()

        class Proof(bytes):
            def __bytes__(self):
                return b"{}"

            def __len__(self):
                return 1
        plain = verify_chia_datalayer(stored, root)
        self.assertTrue(plain["ok"])
        self.assertEqual(verify_chia_datalayer(Proof(stored), root), plain)


# ── 4. the guard: every public function reads its arguments as one state at its call ────────────

#: Modules whose public functions hand no caller's value to a verdict: the command line reads files and argparse
#: values, the demo builds its own data, and the two framework hooks hand the framework's objects on.
_AUSSERHALB = {
    "proofbundle.cli": "the command line: it reads files and argparse strings, and calls the public functions",
    "proofbundle.demo": "the demo builds every value it passes itself",
    "proofbundle.pytest_plugin": "pytest hooks: the framework's own objects, not a caller's value to judge",
    "proofbundle.inspect_hook": "an inspect_ai hook: the framework's own objects, not a caller's value to judge",
}

#: Public functions that do not read their arguments at their call, each with its reason.
_OHNE_STAND = {
    ("proofbundle.verifier_block", "attach"): ("fills the caller's predicate in place by contract (\"Returns the same "
                                               "predicate object\"); it judges nothing, and the block it attaches is "
                                               "read once (`_block_once`) and validated as that one copy"),
}



def _dekorname(d: ast.AST) -> str:
    ziel = d.func if isinstance(d, ast.Call) else d
    return ziel.id if isinstance(ziel, ast.Name) else ziel.attr if isinstance(ziel, ast.Attribute) else "?"


def _ohne_stand(quelle: str) -> "list[str]":
    """Every public top-level function of `quelle` that does not read its arguments at its call once: `_ein_stand` is
    not its outermost decorator, or it stands there twice (verify lane V6 on 8f2fa980: two functions carried it twice
    and paid the wrapper twice). Outermost, because a decorator above it would read the arguments before the reading,
    and because `_ein_stand` asks the frame that calls it whether the call comes from inside the package. And every
    public classmethod and staticmethod of a public top-level class, named ``Klasse.methode``, whose decorators are not
    `classmethod` or `staticmethod` and then `_ein_stand` (verify lane V5 on 8f2fa980: `RenewalPolicy.from_dict` read
    the caller's dict three times, and this guard read only top-level functions)."""
    fehlt = []
    koerper = ast.parse(quelle).body
    for f in _modulfunktionen(koerper):
        if f.name.startswith("_"):
            continue
        namen = [_dekorname(d) for d in f.decorator_list]
        if not namen or namen[0] != "_ein_stand" or namen.count("_ein_stand") != 1:
            fehlt.append(f.name)
    for klasse in _modulklassen(koerper):
        if klasse.name.startswith("_"):
            continue
        for f in klasse.body:
            if not isinstance(f, (ast.FunctionDef, ast.AsyncFunctionDef)) or f.name.startswith("_"):
                continue
            namen = [_dekorname(d) for d in f.decorator_list]
            if namen[:1] not in (["classmethod"], ["staticmethod"]):
                continue
            if namen[1:2] != ["_ein_stand"] or namen.count("_ein_stand") != 1:
                fehlt.append(f"{klasse.name}.{f.name}")
    return fehlt


def _modulklassen(koerper: list) -> list:
    """Every class a module defines at its top level, also inside an `if`, a `try` or a `with` there."""
    gefunden = []
    for knoten in koerper:
        if isinstance(knoten, ast.ClassDef):
            gefunden.append(knoten)
        elif isinstance(knoten, (ast.If, ast.Try, ast.With, ast.For, ast.While)):
            for feld in ("body", "orelse", "finalbody"):
                gefunden += _modulklassen(getattr(knoten, feld, []))
            for zweig in getattr(knoten, "handlers", []):
                gefunden += _modulklassen(zweig.body)
    return gefunden


def _modulfunktionen(koerper: list) -> list:
    """Every function a module defines at its top level, also inside an `if`, a `try` or a `with` there (verify lane
    V4 on 8f2fa980: a public def inside a top-level try escaped the guard). A method of a class is not one; the
    limits of the reading name public methods."""
    gefunden = []
    for knoten in koerper:
        if isinstance(knoten, (ast.FunctionDef, ast.AsyncFunctionDef)):
            gefunden.append(knoten)
        elif isinstance(knoten, (ast.If, ast.Try, ast.With, ast.For, ast.While)):
            for feld in ("body", "orelse", "finalbody"):
                gefunden += _modulfunktionen(getattr(knoten, feld, []))
            for zweig in getattr(knoten, "handlers", []):
                gefunden += _modulfunktionen(zweig.body)
    return gefunden


def _oeffentliche_module() -> "dict[str, Path]":
    paket = REPO / "src" / "proofbundle"
    module = {}
    for pfad in sorted(paket.rglob("*.py")):
        rel = pfad.relative_to(paket)
        if any(t.startswith("_") for t in rel.parts):
            continue
        module[".".join(("proofbundle",) + rel.with_suffix("").parts)] = pfad
    return module


class _Sicht(Mapping):
    """A caller's Mapping that is no dict, reading through a record it holds; each access allocates tracked objects."""

    def __init__(self, d):
        self._d = d

    def __getitem__(self, k):
        v = self._d[k]
        _ = [_Spur(), _Spur(), _Spur()]
        return v

    def __iter__(self):
        return iter(list(self._d))

    def __len__(self):
        return len(self._d)


class _Spur:   # an instance with a __dict__ is tracked by the collector
    pass


def verify_relationship_edges_from_the_caller(wert: dict) -> Any:
    """A caller's code that calls a public function of the package: this module is the caller."""
    from proofbundle.hashalg import verify_dual_hash
    return verify_dual_hash(b"x", wert)


def _aliasse(fn: ast.AST, namen: "set[str]") -> "dict[str, str]":
    """Each name ``fn`` (or a function nested in it) binds to one of ``namen`` or to such a name, by an assignment whose
    value is that name, or a conditional or ``or`` over it, mapped to the parameter it stands for (verify lane V8 on
    085869313, F5: `renewal.verify_sequence` called its ``anchor_verifier`` as ``verify_anchor``, and the scans, which
    looked for the parameter's own name, did not see the call)."""
    def quellen(wert: "ast.AST | None") -> list:
        if isinstance(wert, ast.Name):
            return [wert.id]
        if isinstance(wert, ast.IfExp):
            return quellen(wert.body) + quellen(wert.orelse)
        if isinstance(wert, ast.BoolOp):
            return [q for v in wert.values for q in quellen(v)]
        return []
    aliasse: "dict[str, str]" = {}
    while True:
        vorher = dict(aliasse)
        for n in ast.walk(fn):
            if isinstance(n, ast.Assign):
                ziele, wert = n.targets, n.value
            elif isinstance(n, (ast.AnnAssign, ast.NamedExpr)) and n.value is not None:
                ziele, wert = [n.target], n.value
            else:
                continue
            for q in quellen(wert):
                herkunft = q if q in namen else aliasse.get(q)
                if herkunft is None:
                    continue
                for z in ziele:
                    if isinstance(z, ast.Name) and z.id not in namen:
                        aliasse.setdefault(z.id, herkunft)
        if aliasse == vorher:
            return aliasse


def _ausserhalb_von_draussen(quelle: str, funktion: str, parameter: str) -> "list[str]":
    """``funktion:zeile`` for every call of ``parameter`` in ``funktion`` (or a function nested in it), under its own
    name or a name bound to it (`_aliasse`), that stands in no ``with _draussen():``."""
    baum = ast.parse(quelle)
    eltern = {kind: knoten for knoten in ast.walk(baum) for kind in ast.iter_child_nodes(knoten)}
    offen = []
    for fn in ast.walk(baum):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)) or fn.name != funktion:
            continue
        gerufen = {parameter} | {a for a, p in _aliasse(fn, {parameter}).items() if p == parameter}
        for n in ast.walk(fn):
            if not (isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in gerufen):
                continue
            k, drin = n, False
            while k in eltern and not drin:
                k = eltern[k]
                drin = isinstance(k, ast.With) and any(
                    isinstance(i.context_expr, ast.Call) and _dekorname(i.context_expr) == "_draussen" for i in k.items)
            if not drin:
                offen.append(f"{funktion}:{n.lineno}")
    return offen


class EveryPublicFunctionReadsItsArgumentsAtItsCall(unittest.TestCase):

    def test_every_public_function_carries_the_reading(self):
        ohne = set()
        for modul, pfad in _oeffentliche_module().items():
            if modul not in _AUSSERHALB:
                ohne |= {(modul, f) for f in _ohne_stand(pfad.read_text(encoding="utf-8"))}
        self.assertEqual(sorted(ohne - set(_OHNE_STAND)), [],
                         "a public function reads its arguments without `canonical._ein_stand`")
        self.assertEqual(sorted(set(_OHNE_STAND) - ohne), [], "a named exception carries the reading now")

    def test_every_module_named_outside_exists(self):
        self.assertEqual(sorted(set(_AUSSERHALB) - set(_oeffentliche_module())), [])

    def test_control_the_guard_finds_a_function_without_the_reading(self):
        gepflanzt = ("@_ein_stand\ndef verify_a(x):\n    return x\n"
                     "def verify_b(x):\n    return x\n"
                     "@_never_raise_verdict('n')\n@_ein_stand\ndef verify_c(x):\n    return x\n"
                     "@_ein_stand(rp_trust=_abbild_stand)\n@_never_raise_verdict('n')\ndef verify_d(x, rp_trust=None):\n"
                     "    return x\n"
                     "def _privat(x):\n    return x\n"
                     "try:\n    def verify_e(x):\n        return x\nexcept ImportError:\n    pass\n"
                     "if True:\n    @_ein_stand\n    def verify_f(x):\n        return x\n"
                     "@_ein_stand\n@_ein_stand\ndef verify_g(x):\n    return x\n"
                     "class Politik:\n"
                     "    @classmethod\n    def aus(cls, d):\n        return d\n"
                     "    @classmethod\n    @_ein_stand\n    def von(cls, d):\n        return d\n"
                     "    @staticmethod\n    def lies(d):\n        return d\n"
                     "    def methode(self, d):\n        return d\n"
                     "    @classmethod\n    def _privat(cls, d):\n        return d\n"
                     "class _Intern:\n    @classmethod\n    def aus(cls, d):\n        return d\n")
        self.assertEqual(_ohne_stand(gepflanzt), ["verify_b", "verify_c", "verify_e", "verify_g", "Politik.aus",
                                                  "Politik.lies"])

    def test_a_call_from_inside_the_package_is_not_read_again_and_a_call_from_the_caller_is(self):
        """The cost bound of the reading: a public function that the package's own code calls from inside the body
        of another reads nothing again (measured without it: `verify_decision_receipt` took twice its time). A
        caller's callable that calls a public function from inside that body is the caller's code, and its call is
        read as every call is."""
        from proofbundle import canonical
        from proofbundle.assurance import classify_digest_evidence
        from proofbundle.decision import verify_decision_receipt
        f = fx()
        if f.decision is None:
            self.skipTest("not shipped: examples/decision_receipt_allow.json")
        gezaehlt = []
        original = canonical._stand

        def zaehlend(wurzel, leser=None):
            gezaehlt.append(1)
            return original(wurzel, leser)
        canonical._stand = zaehlend
        try:
            verify_decision_receipt(f.decision, f.pub, related=_related_full(f.subject["decision"]), policy=_POLICY)
            eine = len(gezaehlt)
            gezaehlt.clear()
            innen = []

            def resolver(d):
                innen.append(d)
                return verify_relationship_edges_from_the_caller({"k": [1]})
            classify_digest_evidence({"sha256": "a" * 64}, evidence_resolver=resolver)
        finally:
            canonical._stand = original
        self.assertEqual(eine, 1, "a public function called from inside the package read its arguments again")
        self.assertTrue(innen, "the resolver did not run")
        self.assertEqual(len(gezaehlt), 2, "the call the caller's resolver made was not read (or the outer call was not)")

    def test_a_partial_of_a_public_function_as_a_resolver_is_read(self):
        """V5-09 on 8f2fa980: a resolver that is a `functools.partial` of a public function is called from this
        package's frame, so the skip of a call from inside read nothing for it. The resolver runs as the caller's code
        now (`canonical._draussen`), and its call is read."""
        import functools
        from proofbundle import canonical
        from proofbundle.assurance import classify_digest_evidence
        from proofbundle.hashalg import verify_dual_hash
        gezaehlt = []
        original = canonical._stand

        def zaehlend(wurzel, leser=None):
            gezaehlt.append(1)
            return original(wurzel, leser)
        canonical._stand = zaehlend
        try:
            classify_digest_evidence({"sha256": "a" * 64}, evidence_resolver=functools.partial(verify_dual_hash, b"x"))
        finally:
            canonical._stand = original
        self.assertEqual(len(gezaehlt), 2, "the call the partial made was not read")

    def test_every_callable_whose_answer_enters_a_verdict_runs_as_the_callers_code(self):
        """Every call of a caller's callable whose answer a verdict reads stands inside `with _draussen():`."""
        paket = REPO / "src" / "proofbundle"
        offen = []
        for (datei, funktion, parameter), grund in _AUFRUFE_VON_PARAMETERN.items():
            if grund is _EINE_ANTWORT or grund is _NUR_WAHR or (datei, funktion) == ("anchors.py", "_call_verifier"):
                offen += _ausserhalb_von_draussen((paket / datei).read_text(encoding="utf-8"), funktion, parameter)
        self.assertEqual(offen, [])

    def test_control_the_draussen_scan_sees_a_call_outside(self):
        gepflanzt = ("def verify_x(resolver, d):\n"
                     "    with _draussen():\n        a = resolver(d)\n"
                     "    b = resolver(d)\n    return a, b\n")
        self.assertEqual(_ausserhalb_von_draussen(gepflanzt, "verify_x", "resolver"), ["verify_x:4"])
        unter_anderem_namen = ("def verify_y(anchor_verifier, d):\n"
                               "    if d:\n        pruefe = anchor_verifier\n    else:\n        pruefe = None\n"
                               "    zweit = pruefe or d\n"
                               "    return pruefe(d), zweit(d)\n")
        self.assertEqual(_ausserhalb_von_draussen(unter_anderem_namen, "verify_y", "anchor_verifier"),
                         ["verify_y:7", "verify_y:7"])

    def test_a_reader_is_bound_to_a_parameter_the_function_has(self):
        """Found before the push: with `_ein_stand` outermost, the names of a function wrapped by another decorator were
        read from that wrapper's `*args, **kwargs`, so the readers of `rp_trust` and `frozen` did nothing on four
        functions, and nothing said so. The names come from the innermost function now, and a reader bound to a name
        the function does not have fails where the function is defined."""
        from proofbundle.canonical import _abbild_stand, _ein_stand
        with self.assertRaises(TypeError):
            _ein_stand(nicht_da=_abbild_stand)(lambda wert: wert)

        def huelle(f):
            import functools

            @functools.wraps(f)
            def innen(*args, **kwargs):
                return f(*args, **kwargs)
            return innen

        @_ein_stand(rp_trust=_abbild_stand)
        @huelle
        def pruefer(x, *, rp_trust=None):
            return rp_trust
        self.assertIs(type(pruefer(1, rp_trust=_Sicht({"a": 1}))), dict, "the reader did not run through the wrapper")

    def test_a_mapping_that_restarts_the_collector_never_passes_an_anchor(self):
        """The reader of `rp_trust` at `verify_anchors`, below `_refuse_unreadable_input`: a Mapping whose own
        `__getitem__` starts the collector again is either read as one state or refused (`_StandGestoert`), never
        read as a mix. At the first form of this commit the reader did nothing there, and a sweep gave PASS at two
        collection starts where both states FAIL (the verify lane's own script, measured)."""
        from proofbundle import anchors
        from proofbundle.canonical import _StandGestoert
        name = "test-read-once-rp/v1"
        wurzel = hashlib.sha256(b"stmt").digest()
        liste = [{"type": name, "target": "statement", "canonicalRoot": base64.b64encode(wurzel).decode(),
                  "proof": base64.b64encode(b"p").decode()}]
        anchors.register_anchor_type(name, lambda proof, canonical_root, *, frozen, now, rp_trust=None: {
            "ok": rp_trust["a"] == rp_trust["b"], "warn": False, "status": "pass", "detail": "a==b"})

        class Neustart(_Sicht):
            def __getitem__(self, k):
                gc.enable()
                return super().__getitem__(k)

        def aufruf(st):
            try:
                return anchors.verify_anchors(copy.deepcopy(liste), target_roots={"statement": wurzel},
                                              rp_trust=st[0])["status"]
            except _StandGestoert:
                return "refused: the value changed during every reading"

        def mache():
            d = {"a": 1, "b": 2}
            return (Neustart(d), d)

        def change(st):
            st[1].clear()
            st[1].update({"a": 2, "b": 1})
        war = gc.isenabled()
        try:
            v1, v2, gemischt, _ = sweep(aufruf, mache, change, lambda v: v)
        finally:
            anchors._VERIFIERS.pop(name, None)
            gc.enable() if war else gc.disable()
        verdikte = {v for _, v in gemischt} | {v1, v2}
        self.assertNotIn("PASS", verdikte, "a mix of two states passed the anchor")

    def test_the_reading_is_what_the_decorator_does_at_run_time(self):
        """The flag the guard reads is the code that runs: a public function's body sees a private copy."""
        from proofbundle.relation import verify_relationship_edges
        gesehen = []
        from proofbundle import relation
        original = relation._related_lesen

        def spion(related):
            gesehen.append(related)
            return original(related)
        wert = {_A: {"verified": True, "verified_under": "k", "subject_digest": None,
                     "subject_digest_state": "absent", "relationships": None}}
        relation._related_lesen = spion
        try:
            verify_relationship_edges([_edge(_A, "derivedFrom")], wert)
        finally:
            relation._related_lesen = original
        self.assertTrue(gesehen)
        self.assertIsNot(gesehen[0], wert, "the body read the caller's own map, not the copy of it")
        self.assertEqual(gesehen[0], wert)


# ── 5. the one reading itself: a private copy of one state, and no code of the caller runs ──────

def _knoten(wert: Any, gesehen: "set[int] | None" = None) -> "list[int]":
    """The ids of every built-in container reachable from `wert`, read by what each stores."""
    gesehen = set() if gesehen is None else gesehen
    stapel, ids = [wert], []
    while stapel:
        w = stapel.pop()
        t = type(w)
        if id(w) in gesehen:
            continue
        if issubclass(t, dict):
            gesehen.add(id(w))
            ids.append(id(w))
            stapel.extend(v for _, v in list(dict.items(w)))
        elif issubclass(t, (list, tuple)):
            gesehen.add(id(w))
            ids.append(id(w))
            stapel.extend(list(list.__iter__(w)) if issubclass(t, list) else list(tuple.__iter__(w)))
        elif issubclass(t, (set, bytearray)):
            gesehen.add(id(w))
            ids.append(id(w))
    return ids


class _Aufgezeichnet:
    """Records every method of the caller's classes that runs."""
    aufrufe: "list[str]" = []


#: Methods a recording subclass leaves alone: the ones the interpreter needs to make, name and pickle the object.
_NICHT_AUFZEICHNEN = frozenset({"__new__", "__init__", "__getattribute__", "__setattr__", "__delattr__",
                                "__init_subclass__", "__subclasshook__", "__class__", "__dir__", "__sizeof__",
                                "__reduce__", "__reduce_ex__", "__getstate__", "__class_getitem__"})


def _aufzeichnend(basis: type) -> type:
    """A subclass of `basis` that records a call of EVERY instance method `basis` has (verify lane V4 on 8f2fa980:
    a list of chosen names left `count`, `split`, `__str__` and `lower` of a str unrecorded)."""
    import types

    def melde(name):
        def methode(self, *a, **k):
            _Aufgezeichnet.aufrufe.append(f"{basis.__name__}.{name}")
            return getattr(basis, name)(self, *a, **k)
        return methode
    namen = []
    for n in dir(basis):
        if n in _NICHT_AUFZEICHNEN:
            continue
        roh = next((k.__dict__[n] for k in basis.__mro__ if n in k.__dict__), None)
        if isinstance(roh, (types.MethodDescriptorType, types.WrapperDescriptorType)):
            namen.append(n)
    return type(f"Aufgezeichnet{basis.__name__.capitalize()}", (basis,), {n: melde(n) for n in namen})


class TheReadingAtTheCallIsOneState(unittest.TestCase):

    def _werte(self):
        from collections import OrderedDict, defaultdict
        D, L, T, B = _aufzeichnend(dict), _aufzeichnend(list), _aufzeichnend(tuple), _aufzeichnend(bytearray)
        S, K = _aufzeichnend(set), _aufzeichnend(str)
        geteilt = [1, {"x": bytearray(b"ab")}]
        ring: list = [1]
        ring.append(ring)
        od = OrderedDict([("b", 1), ("a", [2])])
        od.move_to_end("b")
        return [
            {"a": [1, 2, {"b": (3, [4])}], "c": bytearray(b"xyz"), "d": {5, 6}, "e": memoryview(b"mv")},
            D(a=L([1, D(b=B(b"q"))]), c=T((1, L([2])))),
            {"k": K("wert"), "j": S({1, 2})},
            [geteilt, geteilt, {"g": geteilt}],
            ring,
            {"od": od, "dd": defaultdict(list, {"q": [1]})},
            ((1, 2), [(3, [4])], frozenset({7})),
        ]

    def test_the_copy_holds_what_the_value_stores(self):
        from proofbundle.canonical import _stand
        for i, wert in enumerate(self._werte()):
            with self.subTest(value=i):
                kopie = _stand(wert)
                self.assertEqual(repr(_plain_view(kopie)), repr(_plain_view(wert)))

    def test_the_copy_shares_no_container_with_the_caller(self):
        from proofbundle.canonical import _stand
        for i, wert in enumerate(self._werte()):
            with self.subTest(value=i):
                self.assertEqual(set(_knoten(_stand(wert))) & set(_knoten(wert)), set())

    def test_a_shared_part_stays_shared_and_a_circle_stays_a_circle(self):
        from proofbundle.canonical import _stand
        geteilt = [1]
        kopie = _stand({"a": geteilt, "b": geteilt})
        self.assertIs(kopie["a"], kopie["b"])
        ring: list = [1]
        ring.append(ring)
        k = _stand(ring)
        self.assertIs(k[1], k)
        self.assertIsNot(k, ring)

    def test_no_method_of_the_caller_runs(self):
        from proofbundle.canonical import _stand
        werte = self._werte()   # built first: building a dict with a recording key hashes it
        _Aufgezeichnet.aufrufe.clear()
        for wert in werte:
            _stand(wert)
        self.assertEqual(_Aufgezeichnet.aufrufe, [])

    def test_a_str_subclass_key_is_copied_as_its_characters_in_a_class_of_this_package(self):
        """V5-04 on 8f2fa980: such a dict stayed the caller's object. Its key becomes what it stores, in `_FremderText`
        (`_FremdeBytes` for a `bytes` subclass), which hashes and compares as the base type and is no exact `str`
        either, so a reader that counts only an exact `str` as a key is not promoted by the copy (`assurance`: a digest
        keyed by a `str` subclass spelled "sha256" is CLAIMED, and a copy keyed by "sha256" was CONTENT_RESOLVED)."""
        from proofbundle import canonical
        from proofbundle.assurance import EvidenceLevel, classify_digest_evidence
        K, B = _aufzeichnend(str), _aufzeichnend(bytes)
        werte = {K("sha256"): "a" * 64}
        roh = {B(b"k"): 1}
        _Aufgezeichnet.aufrufe.clear()
        kopie = canonical._stand({"digest": werte, "roh": roh})
        self.assertEqual(_Aufgezeichnet.aufrufe, [])
        self.assertIsNot(kopie["digest"], werte)
        (schluessel,) = list(kopie["digest"])
        self.assertIs(type(schluessel), canonical._FremderText)
        self.assertEqual(str.__str__(schluessel), "sha256")
        self.assertIs(type(next(iter(kopie["roh"]))), canonical._FremdeBytes)
        self.assertEqual(classify_digest_evidence(werte)["level"], EvidenceLevel.CLAIMED)

    def test_keys_that_meet_in_the_copy_and_a_key_of_another_class_stay_the_callers_objects(self):
        """The named limit: a `str` subclass beside the `str` it spells would be one key in the copy, and a key of any
        other class cannot enter a copy without its own hash. Neither dict is copied, and no method of the keys runs."""
        from proofbundle.canonical import _stand
        gerufen = []

        class Anders(str):
            def __hash__(self):
                gerufen.append("__hash__")
                return 7

            def __eq__(self, other):
                gerufen.append("__eq__")
                return self is other

        class Zahl(int):
            def __hash__(self):
                gerufen.append("__hash__")
                return int.__hash__(self)
        begegnen = {"a": 1, Anders("a"): 2}
        fremd = {Zahl(5): 1}
        gerufen.clear()
        kopie = _stand({"begegnen": begegnen, "fremd": fremd, "liste": [1]})
        self.assertEqual(gerufen, [])
        self.assertIs(kopie["begegnen"], begegnen)
        self.assertIs(kopie["fremd"], fremd)

    def test_a_dataclass_of_this_package_is_copied_field_by_field(self):
        """V5-02 and V5-03 on 8f2fa980: a `VerificationResult` with its `Check` objects, and an `ArchiveTimeStamp` whose
        `signatures` is a list, were handed on as the caller's objects. They are new objects of the same class now,
        holding copies of what they store; an object of a caller's subclass stays the caller's object."""
        import dataclasses
        from proofbundle.canonical import _stand
        from proofbundle.errors import Check, VerificationResult
        from proofbundle.renewal import build_initial_sequence
        ergebnis = VerificationResult([Check("a", True, "d"), Check("b", False)])
        kopie = _stand(ergebnis)
        self.assertIs(type(kopie), VerificationResult)
        self.assertIsNot(kopie, ergebnis)
        self.assertIsNot(kopie.checks, ergebnis.checks)
        self.assertTrue(all(k is not e for k, e in zip(kopie.checks, ergebnis.checks)))
        self.assertEqual(kopie, ergebnis)
        ats = dataclasses.replace(build_initial_sequence(["a" * 64], hash_alg="sha256", time=1000)[0][0],
                                  signatures=[("ed25519", "x")], external_token=bytearray(b"t"))
        a = _stand(ats)
        self.assertIsNot(a, ats)
        self.assertIsNot(a.signatures, ats.signatures)
        self.assertIsNot(a.external_token, ats.external_token)
        self.assertEqual(a, ats)

        class Eigen(VerificationResult):
            pass
        eigen = Eigen([Check("a", True)])
        self.assertIs(_stand(eigen), eigen)

    def test_a_tuple_of_tuples_is_copied_in_linear_time(self):
        """V6-F3 on 8f2fa980: the parts of a tuple were scanned again after each part was built, and a tuple of 16000
        tuples took 55 s. Measured as CPU time of two sizes: sixteen times the tuples may cost at most 64 times."""
        import time
        from proofbundle.canonical import _stand

        def kosten(n):
            wert = tuple((i,) for i in range(n))
            beste = None
            for _ in range(3):
                t0 = time.process_time()
                _stand(wert)
                t = time.process_time() - t0
                beste = t if beste is None else min(beste, t)
            return max(beste, 1e-4)
        klein, gross = kosten(2000), kosten(32000)
        self.assertLess(gross / klein, 64, f"{klein:.4f} s for 2000 tuples, {gross:.4f} s for 32000")

    def test_a_subclass_becomes_its_base_type_and_an_ordered_dict_keeps_its_order(self):
        from collections import OrderedDict
        from proofbundle.canonical import _stand
        D = _aufzeichnend(dict)
        k = _stand(D(a=1))
        self.assertIs(type(k), dict)
        od = OrderedDict([("b", 1), ("a", 2)])
        od.move_to_end("b")
        self.assertEqual(list(_stand(od)), ["a", "b"])

    def test_a_gc_callback_during_the_reading_cannot_mix_two_states(self):
        """The sweep over `_stand` itself: at every collection start the caller rewrites two nested parts at once;
        the copy is one of the two states. And the control: without the second collect the same sweep finds a copy
        that holds one part from before and one from after."""
        from proofbundle import canonical

        def mache():
            return {"a": [{"n": i} for i in range(40)], "b": [{"n": -i} for i in range(40)]}

        def change(w):
            w["a"][0]["n"] = "x"
            w["b"][0]["n"] = "x"

        def urteil(k):
            return json.dumps(_plain_view(k), sort_keys=True)
        v1, v2, gemischt, _ = sweep(canonical._stand, mache, change, urteil)
        self.assertNotEqual(v1, v2)
        self.assertEqual(gemischt, [])
        original = canonical._gleich_gelesen
        canonical._gleich_gelesen = lambda gelesen: True
        try:
            _, _, gemischt_ohne, _ = sweep(canonical._stand, mache, change, urteil)
        finally:
            canonical._gleich_gelesen = original
        self.assertTrue(gemischt_ohne, "the sweep cannot fall on `_stand`, so its green says nothing")


def _plain_view(w: Any, tiefe: int = 0) -> Any:
    """What a value stores, as plain JSON-like data, for a comparison that reads no method of the caller."""
    if tiefe > 50:
        return "<deep>"
    t = type(w)
    if issubclass(t, dict):   # by key, so a dict's order is compared where a test asks for it, not here
        return sorted([str.__str__(k) if issubclass(type(k), str) else repr(k), _plain_view(v, tiefe + 1)]
                      for k, v in list(dict.items(w)))
    if issubclass(t, list):
        return ["<circle>" if v is w else _plain_view(v, tiefe + 1) for v in list(list.__iter__(w))]
    if issubclass(t, tuple):
        return ["tuple"] + [_plain_view(v, tiefe + 1) for v in list(tuple.__iter__(w))]
    if issubclass(t, (set, frozenset)):
        return sorted(repr(x) for x in (list(set.__iter__(w)) if issubclass(t, set) else list(frozenset.__iter__(w))))
    if issubclass(t, bytearray):
        return ["bytes", bytes(bytearray.__getitem__(w, slice(None))).hex()]
    if t is memoryview:
        return ["bytes", w.tobytes().hex()]
    if issubclass(t, str):
        return str.__str__(w)
    return repr(w)


# ── 6. the second collect: a change is seen, and nothing of the process is touched ───────────────

class TheSecondCollectSeesAChange(unittest.TestCase):

    def _mit_aenderung(self, wie_oft):
        """`_stand` over a dict whose list gains an item after the first collect, ``wie_oft`` times."""
        from proofbundle import canonical
        wert = {"a": [1]}
        original = canonical._gleich_gelesen
        aufrufe = []

        def spion(gelesen):
            aufrufe.append(1)
            if len(aufrufe) <= wie_oft:
                wert["a"].append(len(aufrufe) + 1)
            return original(gelesen)
        canonical._gleich_gelesen = spion
        try:
            return canonical._stand(wert), wert, aufrufe
        finally:
            canonical._gleich_gelesen = original

    def test_a_change_between_the_two_collects_is_seen_and_the_value_read_again(self):
        kopie, wert, aufrufe = self._mit_aenderung(1)
        self.assertEqual(len(aufrufe), 2)
        self.assertEqual(kopie, {"a": [1, 2]})
        self.assertEqual(kopie, wert)

    def test_three_readings_before_a_refusal(self):
        """The texts say three; the number is the code's, pinned here (verify lane V4 on 8f2fa980)."""
        from proofbundle import canonical
        self.assertEqual(canonical._VERSUCHE, 3)
        with self.assertRaises(canonical._StandGestoert):
            self._mit_aenderung(3)
        kopie, _, aufrufe = self._mit_aenderung(2)
        self.assertEqual(len(aufrufe), 3)
        self.assertEqual(kopie, {"a": [1, 2, 3]})

    def test_a_dict_that_changes_its_size_while_it_is_read_is_read_again(self):
        """A gc callback that adds a key while a dict is listed makes the listing raise RuntimeError; the reading is
        made again, and no RuntimeError leaves `_stand` (V5-04 measured one out of `statement_content_root`)."""
        from proofbundle import canonical

        def mache():
            return {f"k{i}": [i] for i in range(60)}

        def urteil(k):
            return tuple(sorted(k))
        v1, v2, gemischt, _ = sweep(canonical._stand, mache, lambda d: d.__setitem__("neu", [0]), urteil, phasen=True)
        self.assertNotEqual(v1, v2)
        self.assertEqual(gemischt, [])

    def test_a_mapping_read_through_its_own_methods_is_read_in_both_collects(self):
        """The reader of a Mapping that is no dict runs before the first collect and after the second, and the two
        answers must be the same (`canonical._stand`, `canonical._derselbe`): a value that changes each time is
        refused, and one that builds equal values anew each time is read."""
        from proofbundle.canonical import _StandGestoert, _abbild_stand, _stand
        d = {"a": 1, "b": 2}
        self.assertEqual(_stand(_Sicht(d), _abbild_stand), d)
        zaehler = [0]

        class Wandelnd(_Sicht):
            def __getitem__(self, k):
                zaehler[0] += 1
                return [zaehler[0]] if k == "a" else super().__getitem__(k)
        with self.assertRaises(_StandGestoert):
            _stand(Wandelnd(d), _abbild_stand)
        import os
        self.assertEqual(_stand(os.environ, _abbild_stand), dict(os.environ), "a mapping that builds its text anew")

    def test_nothing_of_the_process_is_touched(self):
        """V5-06, V5-07, V5-08 and V6-F4 on 8f2fa980: the reading switched the collector of the process off and on,
        and kept a callback in `gc.callbacks`. It touches neither now: a reader inside it sees the collector as the
        caller left it, and the callbacks are those of the caller."""
        from proofbundle.canonical import _stand
        war = gc.isenabled()
        vorher = list(gc.callbacks)
        gesehen = []

        def leser(w):
            gesehen.append(gc.isenabled())
            return w
        try:
            for an in (True, False):
                gc.enable() if an else gc.disable()
                _stand({"a": [1, {"b": (2, [3])}]}, leser)
                self.assertEqual(gc.isenabled(), an)
        finally:
            gc.enable() if war else gc.disable()
        self.assertEqual(gesehen[0], True)
        self.assertEqual(gesehen[-1], False)
        self.assertEqual(gc.callbacks, vorher)

    def test_no_code_of_the_package_switches_the_collector(self):
        """The guard over the class: no module of the package switches the collector, sets its thresholds or adds a
        callback to it, so no reading can leave it switched for the process. The package reads the module only as
        ``gc.get_referents`` (`_gc_zugriffe`)."""
        paket = REPO / "src" / "proofbundle"
        gefunden = []
        for pfad in sorted(paket.rglob("*.py")):
            gefunden += [f"{pfad.relative_to(paket)}:{z}" for z in _gc_zugriffe(pfad.read_text(encoding="utf-8"))]
        self.assertEqual(gefunden, [])

    def test_control_the_gc_guard_sees_an_alias_an_import_and_a_getattr(self):
        """Verify lane V7 on 085869313 planted three forms the list of attribute names missed: the module bound to
        another name, a name imported from it, and ``getattr`` over it. Each is caught, and the one read the package
        makes is not."""
        gepflanzt = {
            "alias": "import gc\ndef f():\n    g = gc\n    g.disable()\n",
            "from": "from gc import disable\n",
            "getattr": "import gc\ndef f():\n    getattr(gc, 'set_debug')(0)\n",
            "import as": "import gc as sammler\nsammler.disable()\n",
            "attribute": "import gc\ngc.callbacks.append(print)\n",
        }
        for name, quelle in gepflanzt.items():
            with self.subTest(form=name):
                self.assertTrue(_gc_zugriffe(quelle), f"the guard missed {name}")
        self.assertEqual(_gc_zugriffe("import gc\ndef f(x):\n    return gc.get_referents(x)\n"), [])

    def test_a_thread_that_collects_all_the_time_makes_no_call_refuse(self):
        """V5-07 on 8f2fa980: a thread that ran `gc.collect()` every 100 ms made 46 of 60 calls refuse. A collection
        changes no value, so no reading is read again for it."""
        import threading
        from proofbundle.canonical import _stand
        stopp = threading.Event()

        def sammler():
            while not stopp.is_set():
                gc.collect()
        gc.freeze()   # the heap of a full suite would make each collection walk all of it (`_run`)
        t = threading.Thread(target=sammler)
        t.start()
        try:
            wert = {f"k{i}": [i, {"x": i}] for i in range(3000)}
            for _ in range(20):
                self.assertEqual(_stand(wert), wert)
        finally:
            stopp.set()
            t.join(10)
            gc.unfreeze()

    def test_another_thread_that_changes_its_callbacks_breaks_no_reading(self):
        """V4 F2 on 8f2fa980: a thread that added and removed its own gc callback made a reading raise IndexError and
        left the collector off. The reading keeps no callback now."""
        import threading
        from proofbundle import canonical
        war = gc.isenabled()
        gc.enable()
        stopp, fehler = threading.Event(), []

        def fremd(phase, info):
            return None

        def rauscher():
            while not stopp.is_set():
                gc.callbacks.insert(0, fremd)
                try:
                    gc.callbacks.remove(fremd)
                except ValueError:
                    pass
        t = threading.Thread(target=rauscher)
        t.start()
        try:
            for _ in range(20000):
                try:
                    canonical._stand({"a": [1, 2], "b": (3, [4])})
                except Exception as exc:  # noqa: BLE001 - any escape is the finding
                    fehler.append(type(exc).__name__)
                    break
        finally:
            stopp.set()
            t.join(10)
            eingeschaltet = gc.isenabled()
            gc.enable() if war else gc.disable()
        self.assertEqual(fehler, [])
        self.assertTrue(eingeschaltet, "the collector stayed off after the readings ended")


def _gc_zugriffe(quelle: str) -> "list[str]":
    """``zeile: form`` for every use of the module ``gc`` in ``quelle`` other than ``gc.get_referents``: an attribute
    of it, the name handed on or bound to another, a ``from gc import``, an ``import gc as``."""
    baum = ast.parse(quelle)
    eltern = {kind: knoten for knoten in ast.walk(baum) for kind in ast.iter_child_nodes(knoten)}
    gefunden = []
    for n in ast.walk(baum):
        if isinstance(n, ast.ImportFrom) and n.module == "gc":
            gefunden.append(f"{n.lineno}: from gc import")
        elif isinstance(n, ast.Import):
            gefunden += [f"{n.lineno}: import gc as {a.asname}" for a in n.names if a.name == "gc" and a.asname]
        elif isinstance(n, ast.Name) and n.id == "gc":
            oben = eltern.get(n)
            if not (isinstance(oben, ast.Attribute) and oben.value is n and oben.attr == "get_referents"):
                gefunden.append(f"{n.lineno}: gc" + (f".{oben.attr}" if isinstance(oben, ast.Attribute) else ""))
    return gefunden


#: Every call in src/ of a function's own parameter, with why its answer is not a caller's value read twice, or
#: where it is read as one state. A value a caller's callable returns into a verdict is a caller's value too.
_EINE_ANTWORT = "the caller's callable: its answer is read as one state where it returns (`canonical._stand`)"
_NUR_WAHR = ("the caller's anchor verifier: only the exact True it returns anchors, compared by identity, so nothing of "
             "its answer is read")
_AUFRUFE_VON_PARAMETERN = {
    ("anchors.py", "_call_verifier", "fn"): ("a registered anchor verifier, the caller's code: `verify_anchor` hands it "
                                             "its own copy of `frozen` and `rp_trust` and reads its result as one "
                                             "state (`canonical._stand`)"),
    ("assurance.py", "classify_digest_evidence", "evidence_resolver"): _EINE_ANTWORT,
    ("assurance.py", "classify_receiver_corroboration", "independent_attestation_resolver"): _EINE_ANTWORT,
    ("outcome.py", "verify_outcome_receipt", "receiver_attestation_resolver"): _EINE_ANTWORT,
    ("_plain_value.py", "plain_json", "error"): "the error type its callers in this package pass",
    ("canonical.py", "_plain_for_jcs", "key_error"): "the error type its callers in this package pass",
    ("canonical.py", "_eine_kopie", "fehler"): "the error type its callers in this package pass",
    ("sdjwt_issue.py", "_fehler", "art"): "the error type its callers in this package pass",
    ("canonical.py", "_stand", "leser"): ("a boundary reader of this package (`_abbild_stand`, `_konsistenz_stand`), "
                                          "run before the first collect and after the second and compared"),
    ("renewal.py", "verify_sequence", "anchor_verifier"): _NUR_WAHR,
    ("canonical.py", "verpacken", "f"): "the decorated function of this package itself",
    ("anchors.py", "_refuse_unreadable_input", "surface"): "the decorated function of this package itself",
    ("renewal.py", "deco", "fn"): "the decorated function of this package itself",
    ("renewal.py", "from_dict", "cls"): "the class of a classmethod of this package",
    ("cap1.py", "_r0_shape", "f"): "the finding recorder `check_cap1_document` passes",
    ("cap1.py", "_r1_no_silent_remainder", "f"): "the finding recorder `check_cap1_document` passes",
    ("cap1.py", "_r2_closed_disposition", "f"): "the finding recorder `check_cap1_document` passes",
    ("cap1.py", "_r3_withholding_digest_bound", "f"): "the finding recorder `check_cap1_document` passes",
    ("cap1.py", "_r4_denominator_basis", "f"): "the finding recorder `check_cap1_document` passes",
    ("cap1.py", "_r5_counts_well_formed", "f"): "the finding recorder `check_cap1_document` passes",
    ("cap1.py", "_r6_absence_is_scoped", "f"): "the finding recorder `check_cap1_document` passes",
    ("cap1.py", "_r7_incomplete_not_clean", "f"): "the finding recorder `check_cap1_document` passes",
    ("cap1.py", "_r8_supports_bounds_citation", "f"): "the finding recorder `check_cap1_document` passes",
    ("intoto.py", "_judge_claim_fields", "felder_von"): "a field reader of this package its two callers pass",
    ("merkle.py", "_hashes_of", "lesen"): "a byte reader of this package (`_bytes_von`, `_puffer_von`)",
}


def _aufrufe_von_parametern(quelle: str) -> "set[tuple[str, str]]":
    """(function, parameter) for every call of a parameter as a function, in the function or a function nested in it."""
    gefunden = set()
    for fn in ast.walk(ast.parse(quelle)):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        namen = {a.arg for a in fn.args.posonlyargs + fn.args.args + fn.args.kwonlyargs}
        for extra in (fn.args.vararg, fn.args.kwarg):
            if extra is not None:
                namen.add(extra.arg)
        aliasse = _aliasse(fn, namen)
        for n in ast.walk(fn):
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name):
                if n.func.id in namen:
                    gefunden.add((fn.name, n.func.id))
                elif n.func.id in aliasse:
                    gefunden.add((fn.name, aliasse[n.func.id]))
    return gefunden


class EveryCallOfACallersCallableIsNamed(unittest.TestCase):

    def test_the_calls_and_the_list_agree_in_both_directions(self):
        paket = REPO / "src" / "proofbundle"
        gefunden = set()
        for pfad in sorted(paket.rglob("*.py")):
            rel = pfad.relative_to(paket).as_posix()
            gefunden |= {(rel, f, p) for f, p in _aufrufe_von_parametern(pfad.read_text(encoding="utf-8"))}
        self.assertEqual(sorted(gefunden - set(_AUFRUFE_VON_PARAMETERN)), [], "a parameter is called, unnamed")
        self.assertEqual(sorted(set(_AUFRUFE_VON_PARAMETERN) - gefunden), [], "a named call is gone")

    def test_control_the_scan_sees_a_planted_call(self):
        gepflanzt = ("def verify_x(resolver, wert):\n"
                     "    def innen(d):\n        return resolver(d)\n"
                     "    return innen(wert), len(wert)\n")
        self.assertEqual(_aufrufe_von_parametern(gepflanzt), {("verify_x", "resolver")})
        alias = ("def verify_y(anchor_verifier, wert):\n"
                 "    pruefe = anchor_verifier if wert else None\n"
                 "    weiter = pruefe\n"
                 "    return weiter(wert)\n")
        self.assertEqual(_aufrufe_von_parametern(alias), {("verify_y", "anchor_verifier")})


# ── 7. what the verify lanes V7 and V8 on 085869313 found ────────────────────────────────────────

class _Abbild(Mapping):
    """A caller's Mapping that is no dict, over a dict the caller swaps whole (verify lane V8, E1)."""

    def __init__(self, d):
        self.d = d

    def __getitem__(self, k):
        return self.d[k]

    def __iter__(self):
        return iter(self.d)

    def __len__(self):
        return len(self.d)


class _NeuGebaut(Mapping):
    """A caller's Mapping that builds a new, equal value on each read and never changes (verify lanes V7 F2, V8 F4)."""

    def __init__(self, d):
        self._d = d

    def __getitem__(self, k):
        return copy.deepcopy(self._d[k])

    def __iter__(self):
        return iter(list(self._d))

    def __len__(self):
        return len(self._d)


class TheReaderIsPartOfBothCollects(unittest.TestCase):

    def test_two_mappings_changed_together_are_read_as_one_state(self):
        """V8 F1: the reader ran once, before the collects, so a callback that swapped both Mappings after it ran gave
        `automation_summary` the result of one state and the required checks of the other: safe in 171 of 1080 runs
        at 085869313, where each state is refused."""
        from proofbundle.automation_verdict import automation_summary
        r0 = {"crypto_ok": True, "alt": False, "structure_ok": True}
        c0 = {"crypto": "alt", "structure": "structure_ok"}
        r1 = {"crypto_ok": False, "alt": True, "structure_ok": True}
        c1 = {"crypto": "crypto_ok", "structure": "structure_ok"}

        def change(st):
            st[0].d = dict(r1)
            st[1].d = dict(c1)
        EveryVerdictIsTheVerdictOverOneState._assert_one_state(
            self, "automation_summary, two Mappings", lambda st: automation_summary(st[0], required_checks=st[1]),
            lambda: (_Abbild(dict(r0)), _Abbild(dict(c0))), change, lambda r: r["safeForAutomation"],
            first=False, second=False, phasen=True)

    def test_the_reader_runs_again_after_the_second_collect(self):
        """The reader's second answer comes after the second collect, and a change between the two answers reads the
        value again. The change here is made when the second collect ends, so a reader read only before the collects
        (the form of 085869313) returns the first state beside nothing it can compare, and this fails."""
        from proofbundle import canonical
        d = {"a": [1]}
        wert = _Abbild(d)
        leser_gerufen = []
        original = canonical._gleich_gelesen

        def leser(w):
            leser_gerufen.append(1)
            return canonical._abbild_stand(w)

        def spion(gelesen):
            ergebnis = original(gelesen)
            if len(leser_gerufen) == 1:
                wert.d = {"a": [2]}
            return ergebnis
        canonical._gleich_gelesen = spion
        try:
            kopie = canonical._stand(wert, leser)
        finally:
            canonical._gleich_gelesen = original
        self.assertEqual(kopie, {"a": [2]}, "a reading whose reader answered two states was kept")
        self.assertEqual(len(leser_gerufen), 4, "the reader did not run before and after both collects, twice")

    def test_a_mapping_that_builds_its_values_anew_gives_a_verdict(self):
        """V7 F2 and V8 F4: a Mapping that is never changed but builds a new value on each read was refused as changed
        at `verify_anchors`, `verify_rfc3161` and `automation_summary`, where every earlier tree gave a verdict."""
        from proofbundle.anchors_rfc3161 import verify_rfc3161
        from proofbundle.automation_verdict import automation_summary
        import array
        import datetime
        from collections import OrderedDict, defaultdict, deque
        ergebnis = {"crypto_ok": True, "structure_ok": True, "policy_ok": True,
                    "extra": {"n": [1.5, None], "b": bytearray(b"x"), "s": {1, "a"}, "q": deque([1], 4),
                              "od": OrderedDict([("z", 1), ("a", 2)]), "dd": defaultdict(list, {"x": [1]}),
                              "arr": array.array("d", [float("nan")]), "tag": datetime.date(2026, 9, 30),
                              "dauer": datetime.timedelta(seconds=5)}}
        r = automation_summary(_NeuGebaut(ergebnis), required_checks=_NeuGebaut({"crypto": "crypto_ok"}))
        self.assertIs(r["cryptoValid"], True)
        # A verdict, not a refusal as changed: the reading of `rp_trust` happens at the call and before the import
        # guard, so it runs with and without the [anchors] extra; only the verdict differs (the import guard's
        # `ok` False without it, a failed chain with it), and both carry `ok`, where `status` exists only past the guard.
        v = verify_rfc3161(b"proof", b"root", frozen={}, rp_trust=_NeuGebaut({"trusted_tsa_roots": ["QUJD"]}))
        self.assertIs(v["ok"], False)

    def test_a_mapping_that_parses_its_values_anew_gives_a_verdict(self):
        """V12 F1: a Mapping that is never changed but parses its values anew on each read, as a configuration read with
        ``json.loads(..., parse_float=Decimal, object_pairs_hook=OrderedDict)`` does, was refused as changed at
        `automation_summary` for a frozenset, a set of floats or tuples, a complex, a range, a Decimal, a Counter or a
        dict with float or tuple keys in another order, where 8f2fa980 gave a verdict; V13 F1 on 95c9f82a: a dict keyed
        by a date, a NaN or a tuple holding a date. Each run of the reader builds every value anew, and the runs list
        the pairs in turn in one order and in the other (V13 F6: the first form of this test turned the order per
        call of the Mapping, and the reader's calls fell so that the value was read twice in one order)."""
        import datetime
        import json
        from collections import Counter, OrderedDict, defaultdict
        from decimal import Decimal
        from proofbundle.automation_verdict import automation_summary
        geteilt = _Spur()
        gelesen = [0]
        richtungen: list = []

        def bauen(umgekehrt):
            def reihe(liste):
                return liste[::-1] if umgekehrt else liste
            paare = [("x", 1.5), ("y", 2.5)]
            # The text in one order: an OrderedDict's own order is part of its value, so the other would be a change.
            text = json.dumps(dict(paare))
            tag = datetime.date.fromisoformat("2026-09-30")
            werte = {
                "json": json.loads(text, parse_float=Decimal, object_pairs_hook=OrderedDict),
                "fs": frozenset({"".join(["a", "b"]), float("1.5"), (1, "".join(["x"]))}),
                "menge": {float("0.5"), (2, "".join(["y", "z"]))},
                "c": complex(1.5, -2.5),
                "r": range(0, 7, 2),
                "d": Decimal("12.50"),
                "zaehler": Counter(dict(reihe(paare))),
                "dd": defaultdict(list, dict(reihe(paare))),
                "fk": {float(k): v for k, v in reihe([(1.5, "a"), (2.5, "b")])},
                "tk": {tuple(k): v for k, v in reihe([((1,), "a"), ((2, 3), "b")])},
                "datum": {k: v for k, v in reihe([(tag, 1), ((tag, 1), 2), (float("nan"), 3)])},
                "geteilt": {geteilt},
            }
            return {"crypto_ok": True, "structure_ok": True, "policy_ok": True, "extra": werte}

        class Parsend(Mapping):
            def __getitem__(self, k):
                umgekehrt = gelesen[0] % 2 == 0
                if k == "extra":
                    richtungen.append(umgekehrt)
                return bauen(umgekehrt)[k]

            def __iter__(self):
                gelesen[0] += 1
                return iter(list(bauen(False)))

            def __len__(self):
                return len(bauen(False))
        r = automation_summary(Parsend(), required_checks={"crypto": "crypto_ok"})
        self.assertIs(r["cryptoValid"], True)
        self.assertGreater(gelesen[0], 1, "the Mapping was not read before the first collect and after the second")
        self.assertIn(True, richtungen)
        self.assertIn(False, richtungen, "the value was not read in both orders")

    def test_same_value_tells_types_and_the_bits_of_a_float_apart(self):
        """Rules of `canonical._derselbe` on values built anew (verify lane V10 on d58be0b8, F4: without the rule
        for bytes, for int, for the length or the keys of a dict, or for `_Unlesbar`, no test fell)."""
        from collections import deque
        from proofbundle.canonical import _Unlesbar, _derselbe
        roh = b"abc" * 10
        neu_roh = bytes(bytearray(roh))
        gross = 10 ** 30
        neu_gross = int("1" + "0" * 30)
        self.assertIsNot(roh, neu_roh)
        self.assertIsNot(gross, neu_gross)
        self.assertTrue(_derselbe(roh, neu_roh))
        self.assertTrue(_derselbe(gross, neu_gross))
        self.assertFalse(_derselbe(gross, gross + 1))
        self.assertFalse(_derselbe({"a": 1}, {"a": 1, "b": 2}))
        self.assertFalse(_derselbe({"a": 1, "b": 2}, {"a": 1}))
        self.assertFalse(_derselbe({"a": 1}, {"b": 1}))
        self.assertTrue(_derselbe(_Unlesbar(), _Unlesbar()))
        self.assertTrue(_derselbe(bytearray(b"ab"), bytearray(b"ab")))
        self.assertFalse(_derselbe(bytearray(b"ab"), bytearray(b"ac")))
        self.assertTrue(_derselbe({1, "a", b"b", None}, {1, "a", b"b", None}))
        self.assertFalse(_derselbe({1}, {2}))
        self.assertTrue(_derselbe(frozenset({float("1.5")}), frozenset({float("1.5")})),
                        "a float in a set is met by its value and compared by its bits (V12 F3)")
        self.assertTrue(_derselbe(deque([1, [2]], 3), deque([1, [2]], 3)))
        self.assertFalse(_derselbe(deque([1], 3), deque([1], 4)))
        # V11 F1: judged by the reading the copy is built from, so these count too.
        import array
        import datetime
        import types
        from collections import OrderedDict, defaultdict
        self.assertTrue(_derselbe({"a": 1, "b": [2]}, {"b": [2], "a": 1}), "a plain dict in another order")
        self.assertTrue(_derselbe(OrderedDict([("a", 1), ("b", 2)]), OrderedDict([("a", 1), ("b", 2)])))
        self.assertFalse(_derselbe(OrderedDict([("a", 1), ("b", 2)]), OrderedDict([("b", 2), ("a", 1)])),
                         "an OrderedDict's own order is part of its value")
        self.assertTrue(_derselbe(defaultdict(list, {"a": [1]}), defaultdict(list, {"a": [1]})))
        self.assertTrue(_derselbe(array.array("d", [float("nan")]), array.array("d", [float("nan")])))
        self.assertFalse(_derselbe(array.array("b", [1]), array.array("B", [1])), "another type code")
        self.assertTrue(_derselbe(datetime.date(2026, 9, 30), datetime.date(2026, 9, 30)))
        self.assertTrue(_derselbe(datetime.timedelta(1), datetime.timedelta(1)))
        utc = datetime.timezone.utc
        self.assertFalse(_derselbe(datetime.datetime(2026, 9, 30, tzinfo=utc), datetime.datetime(2026, 9, 30, tzinfo=utc)),
                         "a tzinfo answers through its own methods")
        self.assertTrue(_derselbe({"a": 1}.keys(), {"a": 1}.keys()))
        self.assertFalse(_derselbe(types.MappingProxyType({"a": 1}), types.MappingProxyType({"a": 2})))

        class Eigen(dict):
            pass
        self.assertTrue(_derselbe(Eigen(a=1), Eigen(a=1)), "a dict subclass is copied as what it stores")
        self.assertFalse(_derselbe(1, True))
        self.assertFalse(_derselbe(1, 1.0))
        self.assertFalse(_derselbe(0.0, -0.0))
        self.assertTrue(_derselbe(float("nan"), float("nan")))
        self.assertTrue(_derselbe({"a": [1, (2, "x")]}, {"a": [1, (2, "x")]}))
        self.assertTrue(_derselbe({"a": 1, "b": 2}, {"b": 2, "a": 1}),
                        "a plain dict with exact keys in another order is one value (V11 F1); an OrderedDict is not")
        ring_a: list = [1]
        ring_a.append(ring_a)
        ring_b: list = [1]
        ring_b.append(ring_b)
        self.assertTrue(_derselbe(ring_a, ring_b))

        class Eigen:
            pass
        self.assertFalse(_derselbe(Eigen(), Eigen()), "an object of the caller is the same only as itself")

    def test_each_rule_of_same_value_has_a_case_that_falls_without_it(self):
        """Verify lane V12 on d1c39ae3, F2: with one of 24 rules of `canonical._derselbe` planted away (a length, a key
        check, the bytes of an array or a memoryview, the date rule for a datetime or a time, the check of a tzinfo,
        the art or the extra of a reading, the recursion into a deque), no test fell. Each case here is built before
        the comparison, the answer is judged, and no method of the caller's objects may run while it is judged. The
        name holds for the rules the lanes V12 and V13 named: the lane V14 on 6723bf24 planted 33 further single
        defects of these rules that no case here catches (RESTRISIKO_620.md, R620-V14-3)."""
        import array
        import datetime
        import struct
        import types
        from collections import Counter, OrderedDict, defaultdict, deque
        from decimal import Decimal
        from proofbundle.canonical import _derselbe
        from proofbundle.errors import Check

        class Merkend:
            def __hash__(self):
                _Aufgezeichnet.aufrufe.append("Merkend.__hash__")
                return 1

            def __eq__(self, other):
                _Aufgezeichnet.aufrufe.append("Merkend.__eq__")
                return self is other

        class Zone(datetime.tzinfo):
            def utcoffset(self, dt):
                _Aufgezeichnet.aufrufe.append("Zone.utcoffset")
                return datetime.timedelta(0)

            def dst(self, dt):
                _Aufgezeichnet.aufrufe.append("Zone.dst")
                return datetime.timedelta(0)

            def tzname(self, dt):
                _Aufgezeichnet.aufrufe.append("Zone.tzname")
                return "Z"

        class Geschlitzt(OrderedDict):
            __slots__ = ("x",)

        class Zehntel(Decimal):
            pass

        def tag():
            return datetime.date.fromisoformat("2026-09-30")

        def tief():
            wert: tuple = ()
            for _ in range(2000):
                wert = (wert,)
            return wert

        def umgedreht(objekt):
            eigen = object.__getattribute__(objekt, "__dict__")
            paare = list(eigen.items())
            eigen.clear()
            eigen.update(reversed(paare))
            return objekt
        Tupel = _aufzeichnend(tuple)
        geteilt_l = [1]
        zweiter = Merkend()
        geteilt_nan = float("nan")

        def bits(muster):
            return struct.unpack("<d", struct.pack("<Q", muster))[0]
        Text = _aufzeichnend(str)
        geteilt = Merkend()
        lebend = Geschlitzt(a=1)
        lebend.x = object()
        frei = memoryview(bytearray(b"ab"))
        frei.release()
        od_a, od_b = OrderedDict(a=1), OrderedDict(a=1)
        abbild = _Sicht({"a": 1})
        dt = datetime.datetime
        faelle = [
            ("str built anew", True, "".join(["ab", "c"]), "".join(["a", "bc"])),
            ("str", False, "abc", "abd"),
            ("bool", False, True, False),
            ("the sign of a NaN", False, bits(0x7FF8000000000000), bits(0xFFF8000000000000)),
            ("the payload of a NaN", False, bits(0x7FF8000000000000), bits(0x7FF8000000000001)),
            ("complex built anew", True, complex(1.5, 2.5), complex("1.5+2.5j")),
            ("complex, the sign of a zero", False, complex(0.0, 0.0), complex(0.0, -0.0)),
            ("complex, the real part", False, complex(-0.0, 1.0), complex(0.0, 1.0)),
            ("range built anew", True, range(3), range(0, 3)),
            ("range", False, range(0, 3), range(0, 3, 2)),
            ("range, its start", False, range(0, 3), range(5, 8)),
            ("range, its start beside one step", False, range(0, 4, 2), range(1, 4, 2)),
            ("range, its stop", False, range(0, 4), range(0, 5)),
            ("two ranges equal by ==, stored otherwise", False, range(0, 3, 5), range(0, 1)),
            ("Decimal, its exponent alone", False, Decimal("1E+2"), Decimal("1E+3")),
            ("Decimal built anew", True, Decimal("1.0"), Decimal("1.0")),
            ("Decimal, its exponent", False, Decimal("1.0"), Decimal("1.00")),
            ("Decimal, the sign of a zero", False, Decimal("0"), Decimal("-0")),
            ("Decimal, the payload of a NaN", False, Decimal("NaN1"), Decimal("NaN2")),
            ("a Decimal subclass", False, Zehntel("1.0"), Zehntel("1.0")),
            ("date built anew", True, datetime.date(2026, 9, 30), datetime.date.fromisoformat("2026-09-30")),
            ("date", False, datetime.date(2026, 9, 30), datetime.date(2026, 10, 1)),
            ("timedelta built anew", True, datetime.timedelta(1), datetime.timedelta(hours=24)),
            ("timedelta", False, datetime.timedelta(1), datetime.timedelta(2)),
            ("datetime built anew", True, dt(2026, 9, 30, 12), dt.fromisoformat("2026-09-30T12:00")),
            ("datetime", False, dt(2026, 9, 30, 12), dt(2026, 9, 30, 12, 0, 1)),
            ("datetime, fold", False, dt(2026, 10, 25, 2, 30), dt(2026, 10, 25, 2, 30, fold=1)),
            ("time built anew", True, datetime.time(12, 30), datetime.time.fromisoformat("12:30")),
            ("time", False, datetime.time(12, 30), datetime.time(12, 31)),
            ("time, fold", False, datetime.time(2, 30), datetime.time(2, 30, fold=1)),
            ("two datetimes with a tzinfo", False, dt(2026, 9, 30, tzinfo=Zone()), dt(2026, 9, 30, tzinfo=Zone())),
            ("a naive and an aware datetime", False, dt(2026, 9, 30), dt(2026, 9, 30, tzinfo=Zone())),
            ("an aware and a naive datetime", False, dt(2026, 9, 30, tzinfo=Zone()), dt(2026, 9, 30)),
            ("a naive and an aware time", False, datetime.time(1), datetime.time(1, tzinfo=Zone())),
            ("an aware and a naive time", False, datetime.time(1, tzinfo=Zone()), datetime.time(1)),
            ("frozenset built anew", True, frozenset({"".join(["a", "b"]), float("1.5"), (1, "x")}),
             frozenset({"".join(["ab"]), float("1.5"), (1, "x")})),
            ("frozenset, 1 and True", False, frozenset({1}), frozenset({True})),
            ("frozenset, 0.0 and -0.0", False, frozenset({0.0}), frozenset({-0.0})),
            ("frozenset, its length", False, frozenset({1}), frozenset({1, 2})),
            ("frozenset of one caller object", True, frozenset({geteilt}), frozenset({geteilt})),
            ("frozenset of two caller objects", False, frozenset({Merkend()}), frozenset({Merkend()})),
            ("dict, a value", False, {"a": 1}, {"a": 2}),
            ("dict, 1 and True", False, {1: "x"}, {True: "x"}),
            ("dict, 0.0 and -0.0", False, {0.0: "x"}, {-0.0: "x"}),
            ("dict, float keys in another order", True, {float("1.5"): "x", float("2.5"): "y"},
             {float("2.5"): "y", float("1.5"): "x"}),
            ("dict, tuple keys in another order", True, {(1, "a"): 1, (2,): 2}, {(2,): 2, (1, "a"): 1}),
            ("dict, a caller key and another order", True, {geteilt: 1, "a": 2}, {"a": 2, geteilt: 1}),
            ("dict, two caller keys", False, {Merkend(): 1}, {Merkend(): 1}),
            ("dict, a caller key on one side", False, {"a": 1}, {Merkend(): 1}),
            ("dict, a caller key on the other side", False, {Merkend(): 1}, {"a": 1}),
            ("dict, a str subclass key", False, {Text("a"): 1}, {Text("a"): 1}),
            ("dict, keys of a date, a NaN and a tuple of a date in another order", True,
             {tag(): 1, (tag(), 1): 2, float("nan"): 3}, {float("nan"): 3, (tag(), 1): 2, tag(): 1}),
            # Built at run time: a tuple written out is a constant of the code object, and both answers would hold
            # the same object, which meets itself without the rule under test.
            ("dict, tuple keys holding a bool in another order", True, {tuple([True]): 1, tuple([False]): 2},
             {tuple([False]): 2, tuple([True]): 1}),
            ("dict, tuple keys holding None in another order", True, {tuple([None, 1]): 1, tuple([None, 2]): 2},
             {tuple([None, 2]): 2, tuple([None, 1]): 1}),
            ("dict, tuple keys holding bytes in another order", True, {tuple([b"a"]): 1, tuple([b"b"]): 2},
             {tuple([b"b"]): 2, tuple([b"a"]): 1}),
            ("dict, tuple keys holding a frozenset in another order", True,
             {(frozenset({1}),): 1, (frozenset({2}),): 2}, {(frozenset({2}),): 2, (frozenset({1}),): 1}),
            ("dict, a key nested 2000 deep", True, {tief(): 1}, {tief(): 1}),
            ("dict, tuple keys holding a caller object", False, {(1, Merkend()): 1}, {(1, Merkend()): 1}),
            ("dict, a key of a tuple subclass", True, {Tupel((1,)): 1}, {Tupel((1,)): 1}),
            ("dict, a str key and a bytes key", False, {"a": 1}, {b"a": 1}),
            ("Counter in another order", True, Counter(a=1, b=2), Counter(b=2, a=1)),
            ("defaultdict in another order", True, defaultdict(list, a=[1], b=[2]), defaultdict(list, b=[2], a=[1])),
            ("dataclass of this package, its fields in another order", True, Check("a", True),
             umgedreht(Check("a", True))),
            ("an item shared on the first side", False, [geteilt_l, geteilt_l], [[2], [1]]),
            ("dict, two shared caller keys in another order", True, {geteilt: 1, zweiter: 2}, {zweiter: 2, geteilt: 1}),
            ("dict, two NaN keys of the same bits", True, {float("nan"): 1, float("nan"): 2},
             {float("nan"): 1, float("nan"): 2}),
            ("dict, a shared NaN key beside a fresh one", True, {float("nan"): 1, geteilt_nan: 2},
             {geteilt_nan: 1, float("nan"): 2}),
            ("dict, NaN keys of two signs in another order", True,
             {bits(0x7FF8000000000000): 1, bits(0xFFF8000000000000): 2},
             {bits(0xFFF8000000000000): 2, bits(0x7FF8000000000000): 1}),
            ("dict, complex keys in another order", True, {complex(1, 2): 1, complex(3, 4): 2},
             {complex(3, 4): 2, complex(1, 2): 1}),
            ("dict, Decimal keys in another order", True, {Decimal("1.0"): 1, Decimal("2.50"): 2},
             {Decimal("2.50"): 2, Decimal("1.0"): 1}),
            ("dict, range keys in another order", True, {range(3): 1, range(1, 4): 2}, {range(1, 4): 2, range(3): 1}),
            ("dict, timedelta keys in another order", True, {datetime.timedelta(1): 1, datetime.timedelta(2): 2},
             {datetime.timedelta(2): 2, datetime.timedelta(1): 1}),
            ("dict, datetime keys in another order", True, {dt(2026, 1, 1): 1, dt(2026, 1, 2): 2},
             {dt(2026, 1, 2): 2, dt(2026, 1, 1): 1}),
            ("dict, time keys in another order", True, {datetime.time(1): 1, datetime.time(2): 2},
             {datetime.time(2): 2, datetime.time(1): 1}),
            ("an item shared on the second side", False, [[2], [1]], [geteilt_l, geteilt_l]),
            ("OrderedDict built anew", True, OrderedDict(a=1, b=[2]), OrderedDict(a=1, b=[2])),
            ("OrderedDict, its length", False, OrderedDict(a=1), OrderedDict(a=1, b=2)),
            ("OrderedDict, a key", False, OrderedDict(a=1), OrderedDict(b=1)),
            ("OrderedDict, a value", False, OrderedDict(a=1), OrderedDict(a=2)),
            ("OrderedDict, read and left live", False, lebend, Geschlitzt(a=1)),
            ("set built anew", True, {"".join(["a", "b"]), 10 ** 30, True, None},
             {"".join(["ab"]), int("1" + "0" * 30), True, None}),
            ("set, 1 and True", False, {1}, {True}),
            ("set, 0.0 and -0.0", False, {0.0}, {-0.0}),
            ("set, a longer one", False, {1}, {1, 2}),
            ("set, a shorter one", False, {1, 2}, {1}),
            ("set of one caller object", True, {geteilt, 1}, {1, geteilt}),
            ("set of two caller objects", False, {Merkend()}, {Merkend()}),
            ("set of a str subclass", False, {Text("a")}, {Text("a")}),
            ("deque, an item", False, deque([1]), deque([2])),
            ("deque, its length", False, deque([1]), deque([1, 2])),
            ("tuple, an item", False, (1,), (2,)),
            ("tuple, its length", False, (1,), (1, 2)),
            ("tuple built anew", True, (1, [2]), (1, [2])),
            ("list, an item", False, [1], [2]),
            ("list, its length", False, [1], [1, 2]),
            ("array, its bytes", False, array.array("b", [1]), array.array("b", [2])),
            ("memoryview built anew", True, memoryview(bytes(4)), memoryview(bytearray(4))),
            ("memoryview, its bytes", False, memoryview(b"ab"), memoryview(b"ac")),
            ("memoryview, its format", False, memoryview(b"abcd").cast("H"), memoryview(b"abcd")),
            ("memoryview, its shape", False, memoryview(bytes(6)).cast("B", (2, 3)),
             memoryview(bytes(6)).cast("B", (3, 2))),
            ("a live and a released memoryview", False, memoryview(b"ab"), frei),
            ("a released and a live memoryview", False, frei, memoryview(b"ab")),
            ("a view of a dict and of an OrderedDict", False, {"a": 1}.keys(), dict.keys(od_a)),
            ("two views of OrderedDicts", False, dict.keys(od_a), dict.keys(od_b)),
            ("a proxy of a dict and of a Mapping", False, types.MappingProxyType({"a": 1}),
             types.MappingProxyType(_Sicht({"a": 1}))),
            ("two proxies of one Mapping", False, types.MappingProxyType(abbild), types.MappingProxyType(abbild)),
            ("dataclass of this package built anew", True, Check("a", True), Check("a", True)),
            ("dataclass of this package", False, Check("a", True), Check("a", False)),
        ]
        for name, erwartet, a, b in faelle:
            with self.subTest(case=name):
                self.assertIsNot(a, b)
                _Aufgezeichnet.aufrufe.clear()
                try:
                    antwort = _derselbe(a, b)
                finally:
                    gerufen = list(_Aufgezeichnet.aufrufe)
                self.assertIs(antwort, erwartet)
                self.assertEqual(gerufen, [], "a method of the caller's object ran while it was judged")

    def test_the_reading_hands_on_what_its_copy_cannot_hold_as_it_is(self):
        """Verify lane V12 on d1c39ae3, F4 and the plant of the memoryview shape: `dict.keys(od)` lists the storage
        order and was copied as a view of the OrderedDict's copy, which lists its own order; a memoryview of two
        dimensions must keep them."""
        import types
        from collections import OrderedDict
        from proofbundle.canonical import _stand
        od = OrderedDict([("b", 1), ("a", 2)])
        od.move_to_end("b")
        sicht = dict.keys(od)
        self.assertEqual(list(sicht), ["b", "a"])
        self.assertIs(_stand([sicht])[0], sicht)

        class Nachfahr(OrderedDict):
            pass
        nachfahr = Nachfahr([("b", 1), ("a", 2)])
        nachfahr.move_to_end("b")
        for weitergereicht in (dict.values(od), dict.items(od), dict.keys(nachfahr), dict.items(nachfahr)):
            with self.subTest(view=type(weitergereicht).__name__):
                self.assertIs(_stand([weitergereicht])[0], weitergereicht)
        gesprungen = memoryview(b"abcd")[::2]
        self.assertFalse(gesprungen.contiguous)
        self.assertIs(_stand([gesprungen])[0], gesprungen, "a view that is not C-contiguous is not read at all")
        proxy = types.MappingProxyType(od)
        kopie_proxy = _stand([proxy])[0]
        self.assertIsNot(kopie_proxy, proxy, "a proxy reads the OrderedDict through its own order, as its copy does")
        self.assertEqual(list(kopie_proxy), ["a", "b"])
        flaeche = memoryview(bytearray(range(6))).cast("B", (2, 3))
        kopie = _stand([flaeche])[0]
        self.assertIsNot(kopie, flaeche)
        self.assertEqual((kopie.format, kopie.shape, kopie.tobytes()), ("B", (2, 3), bytes(range(6))))

    def test_a_str_key_and_a_bytes_key_are_never_compared(self):
        """V13 F7: ``hash("a") == hash(b"a")``, so looking a key of one answer up among the other's compared a str with
        bytes, and under ``python -bb`` a BytesWarning escaped where the two answers are simply different."""
        import subprocess
        programm = (
            "from proofbundle.canonical import _derselbe\n"
            "print(_derselbe({'a': 1}, {b'a': 1}), _derselbe(frozenset({'a'}), frozenset({b'a'})),\n"
            "      _derselbe({('a',): 1}, {(b'a',): 1}), _derselbe({'a'}, {b'a'}))\n")
        lauf = subprocess.run([sys.executable, "-bb", "-c", programm], capture_output=True, text=True, timeout=120,
                              env={**__import__("os").environ, "PYTHONPATH": str(REPO / "src")})
        self.assertEqual(lauf.returncode, 0, lauf.stderr[-400:])
        self.assertEqual(lauf.stdout.split(), ["False", "False", "False", "False"])

    def test_a_recursion_error_in_a_reader_is_raised(self):
        """V10 F3: the readers caught a RecursionError as a Mapping that cannot list its pairs, and `automation_summary`
        answered a valid Mapping a few frames below the limit as unreadable."""
        from proofbundle import canonical
        from proofbundle.public_transparency import _konsistenz_stand

        class Tief(_Sicht):
            def items(self):
                raise RecursionError("maximum recursion depth exceeded")

        class TiefesErgebnis:
            def validate(self):
                raise RecursionError("maximum recursion depth exceeded")
        with self.assertRaises(RecursionError):
            canonical._stand(Tief({"a": 1}), canonical._abbild_stand)
        with self.assertRaises(RecursionError):
            _konsistenz_stand(TiefesErgebnis())

    def test_the_collection_of_package_classes_lets_a_recursion_error_through(self):
        """V10 plant q07b: with the collection of this package's dataclasses catching a RecursionError as another
        thread's import, no test fell; an unknown class would then be judged no class of the package."""
        from proofbundle import canonical

        class Tief:
            def __get__(self, obj, typ=None):
                raise RecursionError("maximum recursion depth exceeded")
        original, stand = canonical._MODULNAME, canonical._PAKETKLASSEN_BEI[0]
        canonical._MODULNAME = Tief()
        canonical._PAKETKLASSEN_BEI[0] = -2
        try:
            with self.assertRaises(RecursionError):
                canonical._paketklasse(type("Unbekannt", (), {}))
        finally:
            canonical._MODULNAME = original
            canonical._PAKETKLASSEN_BEI[0] = stand

    def test_a_recursion_error_is_no_change(self):
        """V7 F1 and V8 F4: the retry caught RecursionError as a RuntimeError, and a valid input a few frames below the
        limit was refused as "changed while it was read"."""
        from proofbundle import canonical
        original = canonical._lesen_einmal

        def tief(wurzel):
            raise RecursionError("maximum recursion depth exceeded")
        canonical._lesen_einmal = tief
        try:
            with self.assertRaises(RecursionError):
                canonical._stand([1])
        finally:
            canonical._lesen_einmal = original


class TheReadingCopiesEachKindAndSeesEachChange(unittest.TestCase):

    def test_the_second_collect_sees_a_change_of_each_kind_at_its_length(self):
        """Verify lane V7 on 085869313: with the second collect of a set, a bytearray, a memoryview, a dataclass of this
        package or a kept OrderedDict left out, or a list or set compared by its length, no test fell. Each kind is
        changed here without changing its length."""
        from collections import OrderedDict, deque
        import array
        from proofbundle import canonical
        from proofbundle.errors import Check, VerificationResult

        class K(str):
            pass
        puffer = bytearray(b"ab")
        faelle = {
            "dict value": ({"a": [1]}, lambda w: w.__setitem__("a", [1])),
            "dict key": ({"a": 1}, lambda w: (w.pop("a"), w.__setitem__("b", 1))),
            "list": ([[1], [2]], lambda w: w.__setitem__(0, [1])),
            "set": ({1, 2}, lambda w: (w.discard(1), w.add(3))),
            "bytearray": (bytearray(b"ab"), lambda w: w.__setitem__(0, 122)),
            "memoryview": (memoryview(puffer), lambda w: puffer.__setitem__(0, 122)),
            "dataclass": (VerificationResult([Check("a", True)]),
                          lambda w: setattr(w, "checks", [Check("a", True)])),
            "kept OrderedDict": (OrderedDict([(K("a"), [1])]),
                                 lambda w: dict.__setitem__(w, next(iter(dict.keys(w))), [1])),
            "deque": (deque([[1], [2]]), lambda w: w.__setitem__(0, [1])),
            "array": (array.array("b", [1, 2]), lambda w: w.__setitem__(0, 5)),
            "view": ({"a": [1]}.keys(), None),
        }
        for name, (wert, aendern) in faelle.items():
            with self.subTest(kind=name):
                if name == "view":
                    d = {"a": [1]}
                    wert = d.keys()

                    def aendern(_w, d=d):
                        d["a"] = [1]
                gelesen = canonical._lesen_einmal([wert])
                self.assertTrue(canonical._gleich_gelesen(gelesen), "an unchanged value read as changed")
                aendern(wert)
                self.assertFalse(canonical._gleich_gelesen(gelesen), f"a change of the {name} was not seen")

    def test_the_second_collect_sees_a_change_of_class_of_each_kind(self):
        """Codex review of pull request 311 (thread 4151141239, P1): the second collect did not compare a container's
        type, and a dataclass of this package is copied as the type the first collect read. Over every kind `_lies`
        reads, taken from its own source: a kind whose class the caller can assign is read again when its class changes
        and nothing it holds does; for a tuple, a view and a memoryview the interpreter refuses the assignment, which is
        why the second collect leaves their class alone. And over every pair of this package's dataclasses whose layouts
        let one become the other, the frozen ones assigned past their own `__setattr__`."""
        import array
        import importlib
        import inspect
        import pkgutil
        import types
        from collections import OrderedDict, deque
        import proofbundle
        from proofbundle import canonical
        from proofbundle.errors import Check, VerificationResult

        arten = {k.value for r in ast.walk(ast.parse(inspect.getsource(canonical._lies))) if isinstance(r, ast.Return)
                 and isinstance(r.value, ast.Tuple) for k in r.value.elts[:1] if isinstance(k, ast.Constant)}
        gedeckt: set = set()

        def gesehen(wert, ziel):
            gelesen = canonical._lesen_einmal([wert])
            self.assertTrue(canonical._gleich_gelesen(gelesen), "an unchanged value read as changed")
            gedeckt.add(canonical._lies(wert)[0])
            object.__setattr__(wert, "__class__", ziel)
            return canonical._gleich_gelesen(gelesen)

        class K(str):
            pass
        bauen = {"dict": (dict, lambda t: t(a=[1])), "OrderedDict": (OrderedDict, lambda t: t(a=[1])),
                 "kept OrderedDict": (OrderedDict, lambda t: t([(K("a"), [1])])), "list": (list, lambda t: t([[1]])),
                 "set": (set, lambda t: t({1})), "bytearray": (bytearray, lambda t: t(b"ab")),
                 "deque": (deque, lambda t: t([[1]], 3)), "array": (array.array, lambda t: t("b", [1]))}
        for name, (basis, mache) in bauen.items():
            with self.subTest(kind=name):
                eins, zwei = type("Eins", (basis,), {}), type("Zwei", (basis,), {})
                self.assertFalse(gesehen(mache(eins), zwei), f"a change of class of a {name} was not seen")
        d = {"a": [1]}
        fest = {"tuple": (type("Eins", (tuple,), {})((1,)), type("Zwei", (tuple,), {})),
                "view": (d.keys(), type(d.values())), "proxy": (types.MappingProxyType(d), dict),
                "memoryview": (memoryview(bytearray(b"ab")), bytearray)}
        for name, (wert, ziel) in fest.items():
            with self.subTest(kind=name):
                gedeckt.add(canonical._lies(wert)[0])
                with self.assertRaises(TypeError):
                    object.__setattr__(wert, "__class__", ziel)

        for info in pkgutil.walk_packages(proofbundle.__path__, "proofbundle."):
            if info.name.rsplit(".", 1)[-1] == "__main__":
                continue   # importing it would run the command line
            try:
                importlib.import_module(info.name)
            except (Exception, SystemExit):  # noqa: BLE001 - a module whose extra is missing defines no class here
                pass
        canonical._paketklasse(type("Unbekannt", (), {}))   # collects the classes of every module loaded now
        klassen = []
        for k in list(canonical._PAKETKLASSEN.values()):
            try:
                satz = canonical._lies(object.__new__(k))
            except TypeError:   # a class `object.__new__` cannot make
                continue
            if satz is not None and satz[0] == "daten":
                klassen.append(k)
        paare, blind = [], []
        for a in klassen:
            for b in klassen:
                if a is b:
                    continue
                wert = object.__new__(a)
                gelesen = canonical._lesen_einmal([wert])
                try:
                    object.__setattr__(wert, "__class__", b)
                except TypeError:
                    continue
                paare.append((a, b))
                gedeckt.add("daten")
                if canonical._gleich_gelesen(gelesen):
                    blind.append(f"{a.__qualname__} -> {b.__qualname__}")
        self.assertIn((VerificationResult, Check), paare, "the generator did not reach the measured pair")
        self.assertEqual(blind, [], f"a change of class unseen, of {len(paare)} pairs")
        self.assertEqual(arten - gedeckt, set(), "a kind `_lies` reads has no case here")

    def test_a_deque_an_array_and_a_view_are_copied(self):
        """V8 F3: a deque, an array and a view of a dict were handed on as the caller's objects, and the body read
        them after the other arguments were copied. They are copies of the same type now, and none of their methods
        runs (`_aufzeichnend`)."""
        import array
        import types
        from collections import deque
        from proofbundle.canonical import _stand
        Q, A = _aufzeichnend(deque), _aufzeichnend(array.array)
        teil = [1]
        q = Q([teil, 2], 5)
        a = A("d", [float("nan"), 2.0])
        d = {"x": teil}
        werte = (q, a, d.keys(), d.values(), d.items(), types.MappingProxyType(d))
        _Aufgezeichnet.aufrufe.clear()
        kopie = _stand(werte)
        self.assertEqual(_Aufgezeichnet.aufrufe, [])
        self.assertIs(type(kopie[0]), deque)
        self.assertEqual(kopie[0].maxlen, 5)
        self.assertIsNot(kopie[0][0], teil)
        self.assertIs(type(kopie[1]), array.array)
        self.assertEqual((kopie[1].typecode, kopie[1].tobytes()), ("d", array.array.tobytes(a)))
        self.assertEqual([type(x).__name__ for x in kopie[2:]], ["dict_keys", "dict_values", "dict_items", "mappingproxy"])
        for sicht in kopie[3:6]:
            self.assertNotIn(id(teil), [id(v) for v in (sicht.values() if isinstance(sicht, Mapping) else
                                                       [p if not isinstance(p, tuple) else p[1] for p in sicht])])
        teil.append(9)
        self.assertEqual(list(kopie[3]), [[1]])

    def test_a_deque_of_witness_keys_is_read_as_one_state(self):
        """V8 F3 at `evaluate_public_transparency`: the policy was copied at the call and the witness keys, in a deque,
        read by the body; 194 of 814 runs passed where each state fails."""
        from collections import deque
        from proofbundle import checkpoint as cp
        from proofbundle.public_transparency import evaluate_public_transparency
        log = Ed25519PrivateKey.from_private_bytes(b"\x07" * 32)
        zeuge = Ed25519PrivateKey.from_private_bytes(b"\x09" * 32)
        notiz = cp.sign_checkpoint("example.org/log", 10, b"\x42" * 32, log, "example.org/log")
        notiz = cp.cosign_checkpoint(notiz, zeuge, "witness-1", 1700000000)
        schluessel = cp.cosign_vkey("witness-1", zeuge.public_key().public_bytes_raw())

        def change(st):
            st[0]["witnessQuorum"]["threshold"] = 2
            st[1].append(schluessel)
        EveryVerdictIsTheVerdictOverOneState._assert_one_state(
            self, "evaluate_public_transparency, a deque of witness keys",
            lambda st: evaluate_public_transparency(notiz, st[0], witness_vkeys=st[1])["PUBLIC_TRANSPARENCY"],
            lambda: ({"witnessQuorum": {"threshold": 1}}, deque()), change, lambda v: v,
            first="FAIL", second="FAIL", phasen=True)

    def test_a_deque_of_prior_leaves_is_signed_over_one_state(self):
        """V8 F3 at `emit_bundle`: the payload was copied at the call and the prior leaves, in a deque, read by the
        body, so the signed tree held the payload of one state over the leaves of the other (99 of 521 runs)."""
        from collections import deque
        from proofbundle.emit import emit_bundle
        sk = Ed25519PrivateKey.from_private_bytes(b"\x05" * 32)

        def change(st):
            st[0][:] = b"payload-state-1"
            st[1].clear()
            st[1].extend([b"leaf-a1", b"leaf-b1"])
        EveryVerdictIsTheVerdictOverOneState._assert_one_state(
            self, "emit_bundle, a deque of prior leaves",
            lambda st: emit_bundle(st[0], sk, prior_leaves=st[1]),
            lambda: (bytearray(b"payload-state-0"), deque([b"leaf-a0", b"leaf-b0"])), change,
            lambda b: (b["payload_b64"], b["merkle"]["root_b64"]), phasen=True)

    def test_a_memoryview_the_copy_cannot_rebuild_stays_the_callers_view(self):
        """The named limit (V8 F2): a view whose format no view of private bytes can take (``<H`` of a ctypes array)
        stays the caller's view, read by both collects. A copy in format ``B`` would be another value to a reader that
        judges a buffer by its format (`adapters.agt_receipt._puffer`). Pinned, so a change of it is seen."""
        import ctypes
        from proofbundle.canonical import _stand
        sicht = memoryview((ctypes.c_uint16 * 2)(1, 2))
        self.assertEqual(sicht.format, "<H")
        self.assertIs(_stand([sicht])[0], sicht)
        self.assertIsNot(_stand([memoryview(bytearray(b"ab"))])[0].obj, None)

    def test_a_set_whose_items_meet_in_the_copy_stays_the_callers_object(self):
        """V7 plant p05b: with the check that two items meet as one taken out for a set, no test fell."""
        from proofbundle.canonical import _stand
        gerufen = []

        class K(str):
            def __hash__(self):
                gerufen.append("__hash__")
                return 7

            def __eq__(self, other):
                gerufen.append("__eq__")
                return self is other
        menge = {K("a"), "a"}
        self.assertEqual(len(menge), 2)
        gerufen.clear()
        self.assertIs(_stand([menge])[0], menge)
        self.assertEqual(gerufen, [])

    def test_an_object_of_this_package_with_an_attribute_name_that_is_no_str_stays_the_callers(self):
        """V7 plant p26: with the check of an attribute name taken out, a dataclass of this package was copied with a
        name of the caller's class in its instance dict, and no test fell."""
        from proofbundle.canonical import _stand
        from proofbundle.errors import Check, VerificationResult

        class K(str):
            pass
        ergebnis = VerificationResult([Check("a", True)])
        object.__getattribute__(ergebnis, "__dict__")[K("fremd")] = 1
        self.assertIs(_stand([ergebnis])[0], ergebnis)


class TheEdgesOfTheReadingAtTheCall(unittest.TestCase):

    def _zaehlend(self):
        from proofbundle import canonical
        gezaehlt: list = []
        original = canonical._stand

        def zaehlend(wurzel, leser=None):
            gezaehlt.append(1)
            return original(wurzel, leser)
        return canonical, original, zaehlend, gezaehlt

    def test_a_call_from_the_callers_frame_inside_a_body_is_read(self):
        """V7 plant p10: with the skip taken for every call inside a body, whatever frame makes it, no test fell. A call
        from this file while the depth says "inside a body" is the caller's, and is read."""
        from proofbundle.hashalg import verify_dual_hash
        canonical, original, zaehlend, gezaehlt = self._zaehlend()
        war = getattr(canonical._INNEN, "tiefe", 0)
        canonical._stand = zaehlend
        canonical._INNEN.tiefe = 1
        try:
            verify_dual_hash(b"x", {"sha256": [1]})
        finally:
            canonical._INNEN.tiefe = war
            canonical._stand = original
        self.assertEqual(len(gezaehlt), 1)

    def test_the_depth_is_restored_after_a_body_raises_and_after_draussen(self):
        """V7 plants p16 and p17: with the depth left where the body or `_draussen` set it, no test fell. A later call
        from inside the package would then be read or skipped by a depth that is no longer true."""
        from proofbundle import canonical
        from proofbundle.canonical import _draussen, canonicalize_statement
        war = getattr(canonical._INNEN, "tiefe", 0)
        try:
            canonical._INNEN.tiefe = 3
            with _draussen():
                self.assertEqual(canonical._INNEN.tiefe, 0)
            self.assertEqual(canonical._INNEN.tiefe, 3)
            canonical._INNEN.tiefe = 0
            with self.assertRaises(Exception):
                canonicalize_statement({"a": [1]}, require_statement_shape="yes")
            self.assertEqual(canonical._INNEN.tiefe, 0, "the depth stayed where the body set it")
        finally:
            canonical._INNEN.tiefe = war

    def test_a_deprecation_warning_names_the_callers_line(self):
        """V7 plant p15: with the warning's ``stacklevel`` at 3 again, it named canonical.py, and no test fell."""
        import warnings
        from proofbundle.agent_review import build_agent_review_statement
        with warnings.catch_warnings(record=True) as gesehen:
            warnings.simplefilter("always")
            try:
                build_agent_review_statement({}, v02=True)
            except Exception:  # noqa: BLE001 - only the warning is judged here
                pass
        veraltet = [w for w in gesehen if issubclass(w.category, DeprecationWarning)]
        self.assertTrue(veraltet)
        self.assertEqual(Path(veraltet[0].filename).resolve(), Path(__file__).resolve())

    def test_only_this_package_is_this_package(self):
        """V7 plants p47 and p48: with a module name read by its prefix, a module named ``proofbundlex`` counted as this
        package, for the skip of a call from inside and for the copy of a dataclass, and no test fell."""
        import dataclasses
        import types
        from proofbundle import canonical
        rahmen = {}
        for name in ("proofbundlex", "proofbundle.innen", "proofbundle"):
            g = {"__name__": name, "sys": sys}
            exec("r = sys._getframe()", g)  # noqa: S102 - a frame whose module has this name
            rahmen[name] = g["r"]
        self.assertFalse(canonical._aus_dem_paket(rahmen["proofbundlex"]))
        self.assertTrue(canonical._aus_dem_paket(rahmen["proofbundle.innen"]))
        self.assertTrue(canonical._aus_dem_paket(rahmen["proofbundle"]))

        @dataclasses.dataclass
        class Fremd:
            a: int = 1
        Fremd.__module__ = "proofbundlex"
        modul = types.ModuleType("proofbundle._test_fremd_heimat")
        modul.Fremd = Fremd  # type: ignore[attr-defined]
        sys.modules[modul.__name__] = modul
        try:
            self.assertFalse(canonical._paketklasse(Fremd))
        finally:
            del sys.modules[modul.__name__]
            canonical._PAKETKLASSEN.pop(id(Fremd), None)

    def test_a_tuple_argument_is_read(self):
        """V7 plant p51: with a tuple taken as a value that cannot change, a list inside it was the caller's, and no
        test fell."""
        from proofbundle.canonical import _gelesen
        liste = [1]
        args, _ = _gelesen((("x",), ("x",)), {}, ((1, liste),), {})
        self.assertIsNot(args[0][1], liste)
        self.assertEqual(args[0][1], liste)

    def test_a_partial_as_an_anchor_verifier_is_read(self):
        """V8 F5: `verify_sequence` called its ``anchor_verifier`` under another name, outside `_draussen`, so a
        `functools.partial` of a public function handed in there read nothing. It runs as the caller's code now."""
        import functools
        from proofbundle.hashalg import verify_dual_hash
        from proofbundle.renewal import build_initial_sequence, verify_sequence
        folge = build_initial_sequence(["a" * 64], hash_alg="sha256", time=1000)
        canonical, original, zaehlend, gezaehlt = self._zaehlend()
        canonical._stand = zaehlend
        try:
            verify_sequence(folge, ["a" * 64], anchor_verifier=functools.partial(verify_dual_hash, b"x"))
        finally:
            canonical._stand = original
        self.assertEqual(len(gezaehlt), 2, "the call the partial made was not read")


if __name__ == "__main__":
    unittest.main()
