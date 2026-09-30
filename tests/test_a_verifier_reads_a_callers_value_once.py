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
thread. So every public function of the package reads all of its arguments in ONE reading at its call
(`canonical._ein_stand`, the copy `canonical._stand`), before its body reads any of them, and the body reads only
that private copy; a value a caller's callable returns into a verdict is read the same way where it is returned.

THE PROPERTY, measured with the caller's own gc callback rather than with a list of known readers. Each case hands
the function a value in a first state, and at the k-th start of a garbage collection during the call the caller's
callback rewrites that value, in place, into a second state. The verdict must be the verdict over the first state
or the verdict over the second, for every k from the first collection of the call to past its last one. Section 1
opens with the planted control (a function that reads twice is caught by the same sweep) and holds every surface
the gate and the verify lanes measured. Section 2 counts the readings of the `related` map, section 3 holds the
neighbours that are a split in reader (a subclass read through its own methods and by what it stores). Section 4
holds the guard: every public function of a public module carries the reading at its call, and every call of a
caller's callable is named. Section 5 holds the one reading itself: a private copy of one state, sharing no
container with the caller, running no method of the caller, and a sweep over the copy that falls when the pause is
taken away. Section 6 holds the pause: one for the whole process, and a collection that runs during a reading
anyway is seen and the value read again.

WHAT THIS DOES NOT SEE. A value of the caller's own class that is no built-in container (an object, a Mapping that
is no dict) is read through its own methods; where a function reads one, a named reader reads it once at the call
(`canonical._abbild_stand`, `public_transparency._konsistenz_stand`), and any other such object is handed on as the
caller's object. A dict with a key that is no exact str, number, bytes or None stays the caller's object (its hash
can be the caller's code, and keying the copy by the text a str subclass stores would promote it), and so does an
OrderedDict whose own order cannot be read without hashing. A value another thread writes WITHOUT a collection is a
race of the caller's own threads. And the sweep reaches a window only where a tracked object is allocated in it.
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
for _p in (str(REPO), str(REPO / "src")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

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

def _run(call: Callable[[Any], Any], value: Any, k: int, change: Callable[[Any], None]) -> "tuple[Any, int]":
    """One call with the caller's gc callback armed to change `value` at the k-th collection start;
    returns the call's result and how many collections started."""
    seen = {"n": 0}

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
    return out, seen["n"]


def sweep(call: Callable[[Any], Any], make: Callable[[], Any], change: Callable[[Any], None],
          verdict: Callable[[Any], Any]) -> "tuple[Any, Any, list, int]":
    """(verdict over the first state, verdict over the second, the mixed verdicts, collections swept)."""
    first = verdict(call(make()))
    second_state = make()
    change(second_state)
    second = verdict(call(second_state))
    _, n = _run(call, make(), 1 << 60, change)
    upto = n + n // 4 + 16
    mixed = []
    for k in range(upto):
        out, _ = _run(call, make(), k, change)
        v = verdict(out)
        if v not in (first, second):
            mixed.append((k, v))
    return first, second, mixed, upto


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

    def _assert_one_state(self, name, call, make, change, verdict, *, first=None, second=None):
        v1, v2, mixed, upto = sweep(call, make, change, verdict)
        if first is not None:
            self.assertEqual(v1, first, f"{name}: the first state is not judged as the case assumes")
        if second is not None:
            self.assertEqual(v2, second, f"{name}: the second state is not judged as the case assumes")
        self.assertEqual(mixed, [], f"{name}: a verdict neither state gives, at these gc starts of {upto}")
        return v1, v2

    def test_the_planted_control_is_caught(self):
        """THE SWEEP CAN FAIL. A verdict read twice from one map, with work between the readings as a
        verifier does, is caught; the same verdict read once is not."""
        def twice(m):
            first = dict(dict.items(m))
            _ = [[i] for i in range(400)]
            second = dict(dict.items(m))
            return "A" in first and "R" not in second

        def once(m):
            only = dict(dict.items(m))
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
        polster = "x" * (DEFAULT_BUDGET.string_len + 100_000)

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
    """Every public top-level function of `quelle` that does not read its arguments at its call: `_ein_stand` is not
    its outermost decorator. Outermost, because a decorator above it would read the arguments before the reading,
    and because `_ein_stand` asks the frame that calls it whether the call comes from inside the package."""
    fehlt = []
    for f in ast.parse(quelle).body:
        if not isinstance(f, (ast.FunctionDef, ast.AsyncFunctionDef)) or f.name.startswith("_"):
            continue
        namen = [_dekorname(d) for d in f.decorator_list]
        if not namen or namen[0] != "_ein_stand":
            fehlt.append(f.name)
    return fehlt


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
                     "def _privat(x):\n    return x\n")
        self.assertEqual(_ohne_stand(gepflanzt), ["verify_b", "verify_c"])

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


def _aufzeichnend(basis: type) -> type:
    def melde(name):
        def methode(self, *a, **k):
            _Aufgezeichnet.aufrufe.append(f"{basis.__name__}.{name}")
            return getattr(basis, name)(self, *a, **k)
        return methode
    namen = [n for n in ("__iter__", "__len__", "__getitem__", "__contains__", "__eq__", "__hash__", "__bytes__",
                         "__index__", "items", "keys", "values", "get", "copy", "__reduce_ex__", "__deepcopy__")
             if hasattr(basis, n)]
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

    def test_a_dict_with_a_key_of_the_callers_class_stays_the_callers_object(self):
        """The named limit: such a key cannot enter a copy without its own hash, and replacing it by the text it stores
        would promote it where a reader counts only an exact str as a key (`assurance`: a digest keyed by a str
        subclass spelled "sha256" is CLAIMED, and a copy keyed by "sha256" was CONTENT_RESOLVED)."""
        from proofbundle.canonical import _stand
        K = _aufzeichnend(str)
        werte = {K("sha256"): "a" * 64}
        _Aufgezeichnet.aufrufe.clear()
        kopie = _stand({"digest": werte, "liste": [1]})
        self.assertIs(kopie["digest"], werte)
        self.assertEqual(_Aufgezeichnet.aufrufe, [])

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
        the copy is one of the two states. And the control: without the pause the same sweep finds a copy that
        holds one part from before and one from after."""
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

        class _OhnePause:
            gestoert = False

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return None
        original = canonical._in_einem_zug
        canonical._in_einem_zug = _OhnePause
        try:
            _, _, gemischt_ohne, _ = sweep(canonical._stand, mache, change, urteil)
        finally:
            canonical._in_einem_zug = original
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


# ── 6. one pause for the whole process, and a collection during a reading is seen ───────────────

class OnePauseForTheWholeProcess(unittest.TestCase):

    def test_a_reading_that_ends_in_another_thread_does_not_restart_the_collector(self):
        """V3 F3 on 6d674973: a second reading found the collector off, paused nothing, and the first reading's end
        switched it on in the middle of the second."""
        import threading
        from proofbundle.canonical import _in_einem_zug
        war = gc.isenabled()
        gc.enable()
        try:
            drinnen, weiter, gesehen = threading.Event(), threading.Event(), []

            def zweite():
                with _in_einem_zug():
                    drinnen.set()
                    weiter.wait(10)
                    gesehen.append(gc.isenabled())
            with _in_einem_zug():
                t = threading.Thread(target=zweite)
                t.start()
                drinnen.wait(10)
            weiter.set()
            t.join(10)
            self.assertEqual(gesehen, [False], "the first reading's end restarted the collector under the second")
            self.assertTrue(gc.isenabled(), "the last reading did not restart the collector it paused")
        finally:
            gc.enable() if war else gc.disable()

    def test_a_caller_that_runs_with_the_collector_off_keeps_it_off(self):
        from proofbundle.canonical import _in_einem_zug
        war = gc.isenabled()
        gc.disable()
        try:
            with _in_einem_zug():
                with _in_einem_zug():
                    pass
            self.assertFalse(gc.isenabled())
        finally:
            gc.enable() if war else gc.disable()

    def test_a_collection_during_a_reading_is_seen_and_the_value_read_again(self):
        """Code of the caller inside a reading (a Mapping's own `items`) that collects: the reading says so, and
        `_stand` reads again."""
        from proofbundle.canonical import _stand
        aufrufe = []

        def leser(w):
            aufrufe.append(1)
            if len(aufrufe) == 1:
                gc.collect()
            return w
        self.assertEqual(_stand({"a": [1]}, leser), {"a": [1]})
        self.assertEqual(len(aufrufe), 2)

    def test_a_value_changed_in_every_reading_is_refused(self):
        from proofbundle.canonical import _StandGestoert, _stand

        def leser(w):
            gc.enable()
            gc.collect()
            return w
        war = gc.isenabled()
        try:
            with self.assertRaises(_StandGestoert):
                _stand({"a": [1]}, leser)
        finally:
            gc.enable() if war else gc.disable()


#: Every call in src/ of a function's own parameter, with why its answer is not a caller's value read twice, or
#: where it is read as one state. A value a caller's callable returns into a verdict is a caller's value too.
_EINE_ANTWORT = "the caller's callable: its answer is read as one state where it returns (`canonical._stand`)"
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
    ("canonical.py", "_stand", "leser"): "a boundary reader of this package (`_abbild_stand`, `_konsistenz_stand`)",
    ("canonical.py", "verpacken", "f"): "the decorated function of this package itself",
    ("canonical.py", "_gelesen_rufen", "f"): "the decorated function of this package itself",
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
        for n in ast.walk(fn):
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name) and n.func.id in namen:
                gefunden.add((fn.name, n.func.id))
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


if __name__ == "__main__":
    unittest.main()
