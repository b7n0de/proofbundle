"""A verifier reads a caller's value once, and its verdict is the verdict over that one reading.

WHERE THIS COMES FROM. Deep gate run 5 at d388ed3d, finding L4-620v5-T5-SECOND-READING-01, two of three
jurors P1. `verify_decision_receipt` and `verify_outcome_receipt` read the caller's `related` map in
`verify_relationship_edges` and again in `successor_warning`, and recorded the second reading's
`supersededByAttached`. A gc callback of the caller that emptied its own map between the two readings
gave `ok` True under a policy that refuses the full map and the empty map alike. The producer side has
its own contract (`tests/test_a_producer_reads_a_callers_value_once.py`), and that contract names
exactly this split as the one it does not see: two storage reads of one value the caller changes
between them.

THE PROPERTY, measured with the caller's own gc callback rather than with a list of known readers.
Each case hands the verifier a value in a first state, and at the k-th start of a garbage collection
during the call the caller's callback rewrites that value, in place, into a second state. The verdict
must be the verdict over the first state or the verdict over the second, for every k from the first
collection of the call to past its last one. A verdict that is neither was assembled from two
readings. The states are chosen so that a mixed verdict differs from both, and section 1 opens with
the planted control: a function that reads twice, as the verifiers did at d388ed3d, is caught by the
same sweep, and one that reads once is not.

Section 2 counts the readings of the `related` map (a counting reader on the one function that reads
it). Section 3 holds the two neighbours that are not a split in time but a split in reader: a `str` or
`bytes` subclass read once through its own methods and once by what it stores. Section 4 names every
public verdict function under src/ whose body still hands one parameter to more than one reading, with
why that is not this class; the scan checks that list in both directions.

A split this contract does NOT see: a value reached THROUGH a parameter (a nested container, a local
derived from it), and a parameter the function rebinds before it reads it again. The scan follows
parameters by name; the sweep covers the cases section 1 names. And the sweep reaches a window between
two readings only if a tracked object is allocated in it: `verify_offline_merkle` read its root and its
key, and `verify_markovian` its target root, twice at d388ed3d, and no collection starts between those
readings, so the sweep could not fall there (measured). Both read once now; the scan of section 4 holds
them, because a second reading of the parameter would be unnamed there.
"""
from __future__ import annotations

import ast
import base64
import copy
import gc
import hashlib
import json
import re
import sys
import unittest
from pathlib import Path
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


# ── 4. every verdict function that still reads a parameter more than once is named ──────────────

_VERDICT_NAME = re.compile(r"^(verify|evaluate|check|classify|join)(_|$)")
#: Calls that ask only a value's type, or that are a typing no-op, and read nothing it stores.
_TYPE_ONLY = frozenset({"type", "isinstance", "issubclass", "id", "callable", "type_name", "_type_name",
                        "_typname", "cast"})

_STR_CHARS = ("not this class: a str's characters cannot change between two readings, and each reader reads "
              "them by `_zeichen_von`")
_EXACT_INT = "not this class: an exact int (`type(...) is int` is required first), which cannot change"
_RESOLVER = "not this class: a callable is called once per digest, not a container that is read"
_POLICY_FALLBACK = ("not this class: `_richtlinie_von` makes the one copy that every gate reads; `_abschnitt_von` "
                    "reads the caller's policy again only when that copy failed, and then the policy is refused "
                    "whatever the second reading says (`policy_ok` False), so it can only name the relations "
                    "gate's own refusal")

_SWEEP = {
    ("src/proofbundle/agent_review.py", "verify_agent_review_any", "public_key"):
        "not this class: the three calls stand in three branches that each return; one runs per call",
    ("src/proofbundle/anchors.py", "verify_anchors", "allow_pending"):
        "not this class: `require_switch` refuses anything but an exact bool, which cannot change",
    ("src/proofbundle/assurance.py", "classify_receiver_corroboration", "expected_receiver_public_key"):
        "not this class: `_is_key_material` asks only the type, and `bytes()` of that plain bytes or "
        "bytearray is the one reading, on the same line, before either resolver runs",
    ("src/proofbundle/checkpoint.py", "verify_witnessed_checkpoint", "log_vkey"): _STR_CHARS,
    ("src/proofbundle/checkpoint.py", "verify_witnessed_checkpoint", "expected_origin"): _STR_CHARS,
    ("src/proofbundle/decision.py", "verify_decision_receipt", "policy"): _POLICY_FALLBACK,
    ("src/proofbundle/decision.py", "verify_decision_receipt", "evidence_resolver"): _RESOLVER,
    ("src/proofbundle/hashalg.py", "verify_dual_hash", "digests"):
        "not this class: the pairs are read once (`paare`) and judged; the second reading is the structural "
        "budget, a bound on work that can only refuse",
    ("src/proofbundle/hf_evals.py", "verify_eval_results_entry", "entry"):
        "not this class: two different fields, each read once by what the entry stores; no content is read "
        "twice",
    ("src/proofbundle/outcome.py", "verify_outcome_receipt", "evidence_resolver"): _RESOLVER,
    ("src/proofbundle/outcome.py", "verify_outcome_receipt", "policy"): _POLICY_FALLBACK,
    ("src/proofbundle/public_transparency.py", "evaluate_public_transparency", "consistency_result"):
        "not this class: a typed result object asked to validate itself, by design, not a container",
    ("src/proofbundle/relation_statement.py", "verify_relation_statement", "policy"): _POLICY_FALLBACK,
    ("src/proofbundle/renewal.py", "evaluate_renewal_policy", "now"): _EXACT_INT,
    ("src/proofbundle/tlogproof.py", "verify_tlog_proof", "log_vkey"): _STR_CHARS,
    ("src/proofbundle/tlogproof.py", "verify_tlog_proof", "expected_origin"): _STR_CHARS,
    ("src/proofbundle/trust_pack.py", "verify_trust_pack", "prev_version"): _EXACT_INT,
    ("src/proofbundle/trust_pack.py", "verify_trust_pack", "prev_root_threshold"): _EXACT_INT,
}


def _name_of(func: ast.AST) -> "str | None":
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return None


def _is(node: ast.AST, param: str) -> bool:
    return isinstance(node, ast.Name) and node.id == param


def _readings(fn: ast.AST, param: str) -> "set[tuple[int, str]]":
    """Where the body reads `param`: as an argument of a call that reads more than its type, as the
    receiver of a method, subscripted, as the container of `in`, as an operand of a comparison other
    than `is`, and as what a loop iterates."""
    out: set = set()
    for n in ast.walk(fn):
        if isinstance(n, ast.Call):
            if _name_of(n.func) not in _TYPE_ONLY and any(
                    _is(a, param) for a in list(n.args) + [k.value for k in n.keywords]):
                out.add((n.lineno, f"call {_name_of(n.func)}"))
            if isinstance(n.func, ast.Attribute) and _is(n.func.value, param):
                out.add((n.lineno, f"method {n.func.attr}"))
        elif isinstance(n, ast.Subscript) and _is(n.value, param):
            out.add((n.lineno, "subscript"))
        elif isinstance(n, ast.Compare) and any(_is(c, param) for c in [n.left] + n.comparators) and not all(
                isinstance(o, (ast.Is, ast.IsNot)) for o in n.ops):
            out.add((n.lineno, "compare"))
        elif isinstance(n, (ast.For, ast.comprehension)) and _is(n.iter, param):
            out.add((getattr(n, "lineno", 0), "iter"))
    return out


def _twice_read(source: str) -> "set[tuple[str, str]]":
    """(function, parameter) of every public verdict function in `source` that reads a parameter it does
    not rebind at more than one place."""
    found = set()
    for fn in ast.parse(source).body:
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)) or fn.name.startswith("_") \
                or not _VERDICT_NAME.match(fn.name):
            continue
        rebound = {n.id for n in ast.walk(fn) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)}
        for a in fn.args.posonlyargs + fn.args.args + fn.args.kwonlyargs:
            if a.arg not in rebound and len(_readings(fn, a.arg)) >= 2:
                found.add((fn.name, a.arg))
    return found


def _scan() -> "set[tuple[str, str, str]]":
    found = set()
    for path in sorted((REPO / "src" / "proofbundle").rglob("*.py")):
        rel = path.relative_to(REPO).as_posix()
        for fn, param in _twice_read(path.read_text(encoding="utf-8")):
            found.add((rel, fn, param))
    return found


class EveryDoubleReadingIsNamed(unittest.TestCase):

    def test_the_scan_and_the_list_agree_in_both_directions(self):
        found, listed = _scan(), set(_SWEEP)
        self.assertEqual(sorted(found - listed), [], "a verdict function reads a parameter twice, unnamed")
        self.assertEqual(sorted(listed - found), [], "a named double reading that is no longer there")

    def test_the_scan_sees_the_form_it_is_for(self):
        """Planted: the form of d388ed3d is found, the one reading is not, and neither is a rebound one."""
        twice = ("def verify_x(related, other):\n"
                 "    a = verify_relationship_edges(None, related)\n"
                 "    b = successor_warning(None, related)\n"
                 "    return a, b, other\n")
        once = ("def verify_x(related):\n"
                "    gelesen = _related_lesen(related)\n"
                "    return _kanten_urteil(None, gelesen), gelesen\n")
        rebound = ("def verify_x(key):\n"
                   "    key = _bytes_von(key)\n"
                   "    return check(key), compare(key)\n")
        self.assertEqual(_twice_read(twice), {("verify_x", "related")})
        self.assertEqual(_twice_read(once), set())
        self.assertEqual(_twice_read(rebound), set())


if __name__ == "__main__":
    unittest.main()
