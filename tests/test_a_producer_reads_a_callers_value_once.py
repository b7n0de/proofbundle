"""A producer reads a caller's value once, and what it checks is what it writes.

WHERE THIS COMES FROM. Lens run 8 at fddc00f4, findings A, B and D. Round 8 made every producer read a
caller's KEY once (`tests/test_a_producer_reads_a_callers_key_once.py`); the lens then measured the
same split on the other values a producer both checks and writes:

* A: `checkpoint.vkey` checked a name's stored text, hashed `keyname.encode()` into the key ID and
  wrote `f"{keyname}+…"`, the caller's `__format__`. A `str` subclass name wrote a whole vkey line for
  the identity point in front of the real one; v6.0.0 and v6.1.0 accept that line and verify a
  checkpoint signed by nobody under it. The same split stood at all seven name and origin sites.
* B: `sign_trust_pack` checked `for kid in signers` and signed `signers.items()`; the three `assemble`
  steps checked a body through `items()` or `__getitem__` and copied its storage; `instantiate_template`
  checked an overlay through `__iter__` and a policy_id through `__eq__`; `issue_sd_jwt` checked a status
  through `__contains__`.
* D: `trust_pack._read_once` read numbers through the caller's `__float__` and `__int__`: a float
  subclass storing 1.5 whose `__float__` answers 1.0 was signed as version 1, `numpy.float64(1.0)` too.

THE PROPERTY, measured with a TRAP rather than with a list of known tricks. Every value a producer
checks and writes is handed in as a subclass of its built-in type that holds the legitimate value in
its storage and overrides every method a producer could read it through. Each override records that it
ran and then answers exactly what the base type would, so a trapped call behaves like the plain call;
the only thing the trap can show is WHERE the producer read. For every producer of the sweep list:

1. no override ran (the value was read from its storage, through `_plain_value` or `signature`);
2. the output is exactly the output of the plain call (nothing legitimate changed);
3. the output holds no object of a trapped type (what is written is a plain value, not the caller's).

A number handed in as a subclass of `int` or `float` (and `numpy.float64`) is refused with the
producer's typed error: its only reads are the caller's methods. Section 2 then runs the lens's own
counter-examples, section 3 the numbers, and section 4 names every public producer under `src/` and
`scripts/` with how it is covered or why it is not affected; the scan checks that list both ways.

A split this contract does NOT see: two reads of one value where both reads are storage reads of a
value the caller mutates between them. No producer here lets caller code run between its reads.
"""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
import re
import subprocess
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

#: A fixed time for the artefacts built here; any past instant does.
_T = "2026-09-26T00:00:00Z"

# ── the traps ─────────────────────────────────────────────────────────────────────────────────────

CALLS: list = []


def _hook(base: type, name: str) -> Callable:
    original = getattr(base, name)

    def method(self, *args, **kwargs):
        CALLS.append(f"{base.__name__}.{name}")
        return original(self, *args, **kwargs)
    method.__name__ = name
    return method


def _truth(base: type) -> Callable:
    def __bool__(self):
        CALLS.append(f"{base.__name__}.__bool__")
        return base.__len__(self) > 0
    return __bool__


def _radd(base: type) -> Callable:
    def __radd__(self, other):
        CALLS.append(f"{base.__name__}.__radd__")
        return other + (str.__str__(self) if base is str else bytes(base.__getitem__(self, slice(None))))
    return __radd__


_STR = ("__str__", "__repr__", "__format__", "encode", "__getitem__", "__iter__", "__len__", "__contains__",
        "__eq__", "__ne__", "__lt__", "__le__", "__gt__", "__ge__", "__hash__", "__add__", "__mul__",
        "__rmul__", "__mod__", "startswith", "endswith", "isascii", "isprintable", "isdigit", "isalnum",
        "isalpha", "isspace", "isdecimal", "isnumeric", "islower", "isupper", "lower", "upper",
        "casefold", "strip", "lstrip", "rstrip", "split", "rsplit", "splitlines", "partition",
        "rpartition", "replace", "count", "find", "rfind", "index", "rindex", "join", "format",
        "format_map", "removeprefix", "removesuffix", "zfill", "translate")
_DICT = ("__getitem__", "get", "items", "keys", "values", "__iter__", "__len__", "__contains__", "__eq__",
         "__ne__", "copy", "setdefault", "pop", "popitem", "__or__", "__ror__", "__reversed__", "__repr__")
_LIST = ("__getitem__", "__iter__", "__len__", "__contains__", "__eq__", "__ne__", "__lt__", "__gt__",
         "__add__", "__mul__", "__rmul__", "index", "count", "copy", "__reversed__", "__repr__")
_BYTES = ("__bytes__", "__buffer__", "__len__", "__getitem__", "__iter__", "__add__", "__contains__",
          "__eq__", "__ne__", "__lt__", "__hash__", "hex", "decode", "startswith", "endswith", "find",
          "count", "split", "strip", "__mod__", "__mul__", "__repr__")
_NUMBER = ("__int__", "__index__", "__float__", "__lt__", "__le__", "__gt__", "__ge__", "__eq__", "__ne__",
           "__hash__", "__format__", "__str__", "__repr__", "__add__", "__radd__", "__sub__", "__rsub__",
           "__mul__", "__rmul__", "__neg__", "__abs__", "__round__", "__trunc__", "__floor__", "__ceil__",
           "to_bytes", "bit_length", "is_integer", "as_integer_ratio", "hex")


def _trap_class(base: type, names: "tuple[str, ...]") -> type:
    ns: dict = {n: _hook(base, n) for n in names if hasattr(base, n)}
    if base in (str, bytes, bytearray, dict, list, tuple):
        ns["__bool__"] = _truth(base)
    if base in (str, bytes):
        ns["__radd__"] = _radd(base)
    if base is tuple:
        ns["__hash__"] = _hook(tuple, "__hash__")
    return type(f"Trap{base.__name__.capitalize()}", (base,), ns)


TrapStr = _trap_class(str, _STR)
TrapDict = _trap_class(dict, _DICT)
TrapList = _trap_class(list, _LIST)
TrapTuple = _trap_class(tuple, _LIST)
TrapBytes = _trap_class(bytes, _BYTES)
TrapBytearray = _trap_class(bytearray, _BYTES)
TrapInt = _trap_class(int, _NUMBER)
TrapFloat = _trap_class(float, _NUMBER)
_TRAP_TYPES = (TrapStr, TrapDict, TrapList, TrapTuple, TrapBytes, TrapBytearray, TrapInt, TrapFloat)


def trapped(value: Any) -> Any:
    """The value, every container, text and byte string of it replaced by a trap holding the same
    storage. Numbers stay plain here; section 3 hands them in trapped."""
    t = type(value)
    if t is dict:
        return TrapDict({trapped(k): trapped(v) for k, v in value.items()})
    if t is list:
        return TrapList([trapped(v) for v in value])
    if t is tuple:
        return TrapTuple(tuple(trapped(v) for v in value))
    if t is str:
        return TrapStr(value)
    if t is bytes:
        return TrapBytes(value)
    if t is bytearray:
        return TrapBytearray(value)
    return value


def _holds_a_trap(value: Any, seen: "set | None" = None) -> bool:
    """Whether an output still carries a trapped object anywhere (the caller's object, written out).
    Walked through the base types' own methods, so the walk itself trips no trap."""
    seen = set() if seen is None else seen
    if isinstance(value, _TRAP_TYPES):
        return True
    if id(value) in seen:
        return False
    seen.add(id(value))
    if isinstance(value, dict):
        return any(_holds_a_trap(k, seen) or _holds_a_trap(v, seen) for k, v in dict.items(value))
    if isinstance(value, list):
        return any(_holds_a_trap(v, seen) for v in list.__iter__(value))
    if isinstance(value, tuple):
        return any(_holds_a_trap(v, seen) for v in tuple.__iter__(value))
    if hasattr(value, "__dataclass_fields__"):
        return any(_holds_a_trap(getattr(value, f), seen) for f in value.__dataclass_fields__)
    slots = getattr(type(value), "__slots__", ())
    if slots:                            # a result object with slots (e.g. an audit request)
        slots = (slots,) if isinstance(slots, str) else slots
        return any(_holds_a_trap(getattr(value, s, None), seen) for s in slots)
    return False


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _raw(sk: Ed25519PrivateKey) -> bytes:
    return sk.public_key().public_bytes_raw()


# ── the fixtures every case builds on ─────────────────────────────────────────────────────────────

class _Fx:
    """Plain, legitimate inputs, built once per process."""

    def __init__(self):
        from proofbundle import checkpoint as cp
        from proofbundle import evalclaim as ec
        self.sk = Ed25519PrivateKey.generate()
        self.witness = Ed25519PrivateKey.generate()
        self.holder = Ed25519PrivateKey.generate()
        self.owner = Ed25519PrivateKey.generate()
        self.root = hashlib.sha256(b"a merkle root").digest()
        self.note = cp.sign_checkpoint("example.org/log", 5, self.root, self.sk, "log")
        self.mldsa_pub = hashlib.shake_256(b"an ML-DSA-44 key").digest(1312)
        claim, _ = ec.build_eval_claim(
            suite="s", suite_version="1", metric="acc", comparator=">=", threshold="0.80", score="0.90",
            n=10, model_id="m", dataset_id="d", issuer=ec.issuer_fingerprint(self.sk), timestamp=_T,
            model_salt=b"0" * 16, dataset_salt=b"1" * 16)
        self.claim_in = claim
        self.bundle = ec.emit_eval_receipt(claim, self.sk)
        self.claim = ec.decode_eval_claim(self.bundle)
        self.pack = {"schemaVersion": "0.1.0", "trustPackId": "tp", "version": 1,
                     "expires": "2099-01-01T00:00:00Z", "prevVersionDigest": None,
                     "roles": {"root": {"keyIds": ["o"], "threshold": 1}},
                     "keys": {"o": {"publicKey": _b64(_raw(self.owner))}},
                     "nonClaims": ["does not assert the key holders are honest"]}


_FX: "_Fx | None" = None


def fx() -> _Fx:
    global _FX
    if _FX is None:
        _FX = _Fx()
    return _FX


# ── 1. every producer of the sweep list, handed trapped values ────────────────────────────────────

def _json(v: Any) -> str:
    return json.dumps(v, sort_keys=True,
                      default=lambda o: o.hex() if isinstance(o, (bytes, bytearray)) else repr(o))


def _tokens(seq) -> list:
    return [[(a.token(), a.anchor_status) for a in chain] for chain in seq]


def _decision_pred():
    if _not_shipped("examples/decision_receipt_deny.json"):
        raise unittest.SkipTest("not shipped: examples/decision_receipt_deny.json")
    return json.loads((REPO / "examples" / "decision_receipt_deny.json").read_text(encoding="utf-8"))


def _outcome_pred():
    return {"schemaVersion": "0.1.0", "outcomeId": "outcome-0001", "decisionRef": {"sha256": "a" * 64},
            "executor": {"id": "executor:runner-7", "keyId": "kid-exec"},
            "requestedActionDigest": {"sha256": "b" * 64}, "status": "executed",
            "performedAt": "2026-07-14T10:00:00Z", "effectDigest": {"sha256": "b" * 64}}


def _relation_pred():
    return {"schemaVersion": "0.1.0", "statementId": "urn:uuid:s-1",
            "relationships": [{"relation": "retracts", "targetReceiptDigest": {
                "digestAlgorithm": "jcs-sha256-v1", "digest": "c" * 64}}]}


def _ledger_pred():
    from proofbundle.run_ledger import link_runs
    return {"schemaVersion": "0.1.0", "studyId": "study-0001", "runBudget": 5,
            "runs": link_runs(["1" * 64, "2" * 64, "3" * 64], ["completed", "aborted", "completed"]),
            "selectedSeq": 3, "nonClaims": ["does not prove the selected run is representative"]}


def _summary_pred():
    return {"schemaVersion": "0.1.0", "summaryId": "summary-0001", "producedAt": "2026-07-14T10:00:00Z",
            "producer": {"id": "verifier://example/summarizer"},
            "levels": [{"kind": "eval", "receiptRef": {"sha256": "a" * 64}, "status": "VERIFIED",
                        "evidenceClass": "authorship_integrity", "checks": ["crypto", "merkle"]}],
            "nonClaims": ["does not prove the eval number is true"]}


def _review_pred():
    return {"schemaVersion": "0.1.0", "reviewId": "r",
            "subjectContext": {"kind": "githubPullRequest", "forge": "g", "repositoryId": "R",
                               "pullRequestNodeId": "P", "headSha": "a" * 40, "baseSha": "b" * 40,
                               "reviewedDiffDigest": "c" * 64, "bodyCoreDigest": "d" * 64},
            "declaration": {"authoring": [{"assurance": "selfDeclared", "assertedBy": "x"}],
                            "reviewRuns": [], "findings": [], "findingsTotal": 0, "nonClaims": ["n"]},
            "coverage": {"status": "UNKNOWN"}, "times": {"declaredAt": "2026-08-31T17:00:00Z"},
            "limitations": ["l"]}


def _block():
    from proofbundle import verifier_block as vb
    return {"build": {"digest": {"sha256": "1" * 64}, "source": "source-tree", "files": 77},
            "vector_set": {"name": "proofbundle.conformance.manifest.v1", "digest": {"sha256": "2" * 64},
                           "cases": 110},
            "test_result": {"predicateType": vb.TEST_RESULT_PREDICATE_TYPE, "result": "PASSED",
                            "statementDigest": {"sha256": "3" * 64}},
            "version": "6.1.0"}


def _results():
    return [{"caseId": "a", "ok": True, "scope": "full"}, {"caseId": "b", "ok": True, "scope": "full"}]


def _body():
    from proofbundle import agent_review as ar
    return f"intro\n\n{ar.DISCLOSURE_BEGIN}\n- **Receipt:** x\n{ar.DISCLOSURE_END}\n\noutro\n"


class _Stubbed:
    """Replaces module attributes for one call and restores them."""

    def __init__(self, pairs):
        self.pairs = pairs

    def __enter__(self):
        self.saved = [(m, n, getattr(m, n)) for m, n, _ in self.pairs]
        for m, n, v in self.pairs:
            setattr(m, n, v)

    def __exit__(self, *exc):
        for m, n, v in self.saved:
            setattr(m, n, v)


def _chia_export(root, value):
    """`export_anchor` with the RPC and the offline check stubbed: what root was checked, what written."""
    from proofbundle import anchors_chia_add as chia
    seen = {}

    def rpc(service, method, params, timeout=30):
        if method == "get_proof":
            return {"proof": {"store_proofs": {"proofs": [{"key_clvm_hash": "k", "value_clvm_hash": "v",
                                                          "node_hash": "n", "layers": []}]},
                              "coin_id": None, "inner_puzzle_hash": "i"}}
        return {"hash": "0x" + "ab" * 32}

    def verify(proof_obj, canonical_root):
        seen["checked"] = canonical_root.hex() if type(canonical_root) is bytes else "NOT PLAIN"
        return {"ok": True}
    with _Stubbed([(chia, "_rpc", rpc), (chia, "verify_offline_merkle", verify)]):
        out = chia.export_anchor("store", canonical_root=root, value=value)
    return {"out": out, "checked": seen["checked"]}


def _chia_add(root_hex, value_hex):
    """`anchor_add` with the RPC and the export stubbed: what went into the changelist."""
    from proofbundle import anchors_chia_add as chia
    seen = {}

    def rpc(service, method, params, timeout=30):
        if method == "batch_update":
            seen["changelist"] = json.dumps(params["changelist"])
            return {"success": True}
        return {"hash": "0x" + "cd" * 32}

    def export(store_id, *, canonical_root, target, network, value):
        return {"root": canonical_root.hex(), "value": value, "plain": type(value) is str}
    with _Stubbed([(chia, "_rpc", rpc), (chia, "export_anchor", export)]):
        out = chia.anchor_add(root_hex, store_id="store", value_digest_hex=value_hex, wait=False)
    return {"out": out, "changelist": seen["changelist"]}


def _rfc3161_create(root):
    """`create_rfc3161_anchor` with the TSA client, the network and the check stubbed."""
    import types
    import urllib.request
    from proofbundle import anchors_rfc3161 as tsa
    seen = {}

    class _Req:
        def as_bytes(self):
            return b"request"

    class _Builder:
        def data(self, d):
            seen["stamped"] = d.hex() if type(d) is bytes else "NOT PLAIN"
            return self

        def cert_request(self):
            return self

        def build(self):
            return _Req()

    class _Resp:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return b"a token"

    fake = types.ModuleType("rfc3161_client")
    fake.TimestampRequestBuilder = _Builder

    def verify(token, canonical_root, *, frozen, rp_trust):
        seen["checked"] = canonical_root.hex() if type(canonical_root) is bytes else "NOT PLAIN"
        return {"ok": True}
    saved = sys.modules.get("rfc3161_client")
    sys.modules["rfc3161_client"] = fake
    try:
        with _Stubbed([(urllib.request, "urlopen", lambda *a, **k: _Resp()), (tsa, "verify_rfc3161", verify)]):
            out = tsa.create_rfc3161_anchor(root, "receipt", tsa_url="https://tsa.invalid",
                                            root_certs_der=[b"cert"], anchored_at=_T)
    finally:
        if saved is None:
            sys.modules.pop("rfc3161_client", None)
        else:
            sys.modules["rfc3161_client"] = saved
    return {"out": out, "stamped": seen["stamped"], "checked": seen["checked"]}


def _cases() -> "list[tuple[str, Callable, dict, tuple, Callable]]":
    """(name, producer, plain keyword arguments, the arguments handed in trapped, output normaliser)."""
    from proofbundle import agent_review as ar
    from proofbundle import anchors, beacon, hashalg
    from proofbundle import checkpoint as cp
    from proofbundle import decision, evalclaim as ec, evidence_pack as ep, hf_evals as hf
    from proofbundle import intoto, outcome, persample, relation_statement as rs, renewal
    from proofbundle import run_ledger, statuslist as sl, tlogproof, trust_pack as tp
    from proofbundle import verification_summary as vs, verifier_block as vb
    from proofbundle.adapters import eee
    from proofbundle.policy_profiles import instantiate_template
    from proofbundle.sdjwt_issue import issue_sd_jwt, present_with_key_binding
    f = fx()

    def ident(o):
        return o
    seq = renewal.build_initial_sequence(["a" * 64], hash_alg="sha256", time=1_780_000_000)
    compact = issue_sd_jwt(f.claim_in, f.sk, root_b64=_b64(f.root))
    entry = hf.to_eval_results_entry(f.bundle, dataset_id="d", task_id="t", value=0.9, include_token=False)
    mk = f.bundle["merkle"]
    note_for_bundle = cp.sign_checkpoint("example.org/log", mk["tree_size"],
                                         base64.b64decode(mk["root_b64"]), f.sk, "log")
    stmt = vb.build_test_result_statement(build=_block()["build"], vector_set=_block()["vector_set"],
                                          results=_results(), version="6.1.0")
    eee_path = REPO / "tests" / "fixtures" / "eee_arc_easy.json"
    disclosures = persample.build_sample_tree([{"id": 1, "score": "1"}, {"id": 2, "score": "0"}],
                                              b"s" * 32)["disclosures"]
    c = [
        ("checkpoint.vkey", cp.vkey, {"keyname": "log", "pubkey": _raw(f.sk)}, ("keyname", "pubkey"), ident),
        ("checkpoint.key_id", cp.key_id, {"keyname": "log", "pubkey": _raw(f.sk)}, ("keyname", "pubkey"), ident),
        ("checkpoint.cosign_vkey", cp.cosign_vkey, {"witness_name": "w", "pubkey": _raw(f.witness)},
         ("witness_name", "pubkey"), ident),
        ("checkpoint.cosign_key_id", cp.cosign_key_id, {"witness_name": "w", "pubkey": _raw(f.witness)},
         ("witness_name", "pubkey"), ident),
        ("checkpoint.cosign_vkey_mldsa", cp.cosign_vkey_mldsa, {"witness_name": "w", "pubkey": f.mldsa_pub},
         ("witness_name", "pubkey"), ident),
        ("checkpoint.cosign_key_id_mldsa", cp.cosign_key_id_mldsa,
         {"witness_name": "w", "pubkey": f.mldsa_pub}, ("witness_name", "pubkey"), ident),
        ("checkpoint.checkpoint_note", cp.checkpoint_note,
         {"origin": "example.org/log", "tree_size": 5, "root": f.root}, ("origin", "root"), ident),
        ("checkpoint.sign_checkpoint", cp.sign_checkpoint,
         {"origin": "example.org/log", "tree_size": 5, "root": f.root, "signer": f.sk, "keyname": "log"},
         ("origin", "root", "keyname"), ident),
        ("checkpoint.cosign_checkpoint", cp.cosign_checkpoint,
         {"signed_note": f.note, "witness_signer": f.witness, "witness_name": "w", "timestamp": 1_780_000_000},
         ("signed_note", "witness_name"), ident),
        ("trust_pack.sign_trust_pack", tp.sign_trust_pack, {"predicate": f.pack, "signers": {"o": f.owner}},
         ("predicate", "signers"), _json),
        ("trust_pack.build_trust_pack_statement", tp.build_trust_pack_statement, {"predicate": f.pack},
         ("predicate",), _json),
        ("policy_profiles.instantiate_template", instantiate_template,
         {"template": "strict-eval-template-v1", "issuer_keys": [_b64(_raw(f.sk))], "policy_id": "org/x",
          "valid_until": "2099-01-01T00:00:00Z", "overlay": {"valid_from": "2020-01-01T00:00:00Z"}},
         ("template", "issuer_keys", "policy_id", "valid_until", "overlay"), _json),
        ("policy_profiles.instantiate_template, expected_root", instantiate_template,
         {"template": "strict-eval-authenticated-root-template-v1", "issuer_keys": (_b64(_raw(f.sk)),),
          "policy_id": "org/x", "expected_root": _b64(f.root)},
         ("template", "issuer_keys", "policy_id", "expected_root"), _json),
        ("sdjwt_issue.issue_sd_jwt", issue_sd_jwt,
         {"claim": f.claim_in, "signer": f.sk, "root_b64": _b64(f.root),
          "status": sl.status_claim("https://example.org/list", 3)}, ("status",), ident),
        ("sdjwt_issue.present_with_key_binding", present_with_key_binding,
         {"compact": compact, "holder_signer": f.holder, "aud": "v", "nonce": "n", "iat": 1_780_000_000},
         ("compact",), ident),
        ("statuslist.status_claim", sl.status_claim, {"uri": "https://example.org/list", "idx": 3}, ("uri",), _json),
        ("statuslist.issue_status_list_token", sl.issue_status_list_token,
         {"statuses": [0, 1, 0, 1], "uri": "https://example.org/list", "signer": f.sk, "iat": 1_780_000_000},
         ("statuses",), ident),
        ("decision.emit_decision_receipt", decision.emit_decision_receipt,
         {"predicate": _decision_pred, "signer": f.sk}, ("predicate",), _json),
        ("decision.build_decision_statement", decision.build_decision_statement,
         {"predicate": _decision_pred}, ("predicate",), _json),
        ("outcome.emit_outcome_receipt", outcome.emit_outcome_receipt,
         {"predicate": _outcome_pred(), "signer": f.sk}, ("predicate",), _json),
        ("outcome.build_outcome_statement", outcome.build_outcome_statement,
         {"predicate": _outcome_pred()}, ("predicate",), _json),
        ("relation_statement.emit_relation_statement", rs.emit_relation_statement,
         {"predicate": _relation_pred(), "signer": f.sk}, ("predicate",), _json),
        ("relation_statement.build_relation_statement", rs.build_relation_statement,
         {"predicate": _relation_pred()}, ("predicate",), _json),
        ("run_ledger.emit_run_ledger", run_ledger.emit_run_ledger,
         {"predicate": _ledger_pred(), "signer": f.sk}, ("predicate",), _json),
        ("run_ledger.build_run_ledger_statement", run_ledger.build_run_ledger_statement,
         {"predicate": _ledger_pred()}, ("predicate",), _json),
        ("verification_summary.emit_verification_summary", vs.emit_verification_summary,
         {"predicate": _summary_pred(), "signer": f.sk}, ("predicate",), _json),
        ("verification_summary.build_summary_statement", vs.build_summary_statement,
         {"predicate": _summary_pred()}, ("predicate",), _json),
        ("agent_review.emit_agent_review", ar.emit_agent_review,
         {"predicate": _review_pred(), "signer": f.sk, "legacy_v01": True}, ("predicate",), _json),
        ("agent_review.build_agent_review_statement", ar.build_agent_review_statement,
         {"predicate": _review_pred(), "legacy_v01": True}, ("predicate",), _json),
        ("agent_review.render_disclosure_block", ar.render_disclosure_block,
         {"predicate": _review_pred(), "receipt_digest": "e" * 64, "legacy_v01": True}, ("predicate",), ident),
        ("agent_review.render_disclosure_line", ar.render_disclosure_line,
         {"predicate": _review_pred(), "receipt_digest": "e" * 64, "receipt_url": "https://example.org/r",
          "legacy_v01": True}, ("predicate", "receipt_digest"), ident),
        ("agent_review.body_core_bytes", ar.body_core_bytes, {"body": _body()}, ("body",), ident),
        ("agent_review.disclosure_core_bytes", ar.disclosure_core_bytes, {"body": _body()}, ("body",), ident),
        ("agent_review.prepare_body_for_disclosure", ar.prepare_body_for_disclosure,
         {"body": "intro\n\n## Review\n\noutro\n", "anchor": "## Review"}, ("body", "anchor"), ident),
        ("agent_review.replace_disclosure_block", ar.replace_disclosure_block,
         {"body": _body(), "block": f"{ar.DISCLOSURE_BEGIN}\n- new\n{ar.DISCLOSURE_END}"}, ("body", "block"),
         ident),
        ("verifier_block.build_verifier_block", vb.build_verifier_block, _block(),
         ("build", "vector_set", "test_result", "version"), _json),
        ("verifier_block.attach", lambda block: vb.attach(_review_pred(), block),
         {"block": vb.build_verifier_block(**_block())}, ("block",), _json),
        ("verifier_block.build_test_result_statement", vb.build_test_result_statement,
         {"build": _block()["build"], "vector_set": _block()["vector_set"], "results": _results(),
          "version": "6.1.0"}, ("build", "vector_set", "results", "version"), _json),
        ("verifier_block.test_result_ref", vb.test_result_ref, {"statement": stmt}, ("statement",), _json),
        ("verifier_block.sign_test_result_statement", vb.sign_test_result_statement,
         {"statement": stmt, "signer": f.sk}, ("statement",), _json),
        ("intoto.to_intoto_statement", intoto.to_intoto_statement,
         {"claim": f.claim, "root_b64": _b64(f.root)}, ("claim",), _json),
        ("intoto.to_test_result_statement", intoto.to_test_result_statement,
         {"claim": f.claim, "subject_digest": {"sha256": "a" * 64}}, ("claim",), _json),
        ("intoto.export_intoto_dsse", intoto.export_intoto_dsse, {"claim": f.claim, "signer": f.sk},
         ("claim",), _json),
        ("intoto.to_eval_result_predicate", intoto.to_eval_result_predicate,
         {"claim": f.claim, "subject_profile": "receipt"}, ("claim", "subject_profile"), _json),
        ("intoto.to_eval_result_statement", intoto.to_eval_result_statement,
         {"claim": f.claim, "subject": [{"name": "s", "digest": {"sha256": "a" * 64}}]}, ("claim",), _json),
        ("intoto.export_eval_result_dsse", intoto.export_eval_result_dsse,
         {"claim": f.claim, "signer": f.sk, "subject_profile": "receipt"}, ("claim", "subject_profile"), _json),
        ("intoto.to_eval_result_v02_predicate", intoto.to_eval_result_v02_predicate,
         {"claim": f.claim, "evaluator_id": "https://example.org/evaluator"}, ("claim", "evaluator_id"), _json),
        ("intoto.to_eval_result_v02_statement", intoto.to_eval_result_v02_statement,
         {"claim": f.claim, "subject": [{"name": "s", "digest": {"sha256": "a" * 64}}],
          "evaluator_id": "https://example.org/evaluator"}, ("claim", "subject", "evaluator_id"), _json),
        ("intoto.export_eval_result_v02_dsse", intoto.export_eval_result_v02_dsse,
         {"claim": f.claim, "signer": f.sk, "evaluator_id": "https://example.org/evaluator",
          "subject_profile": "receipt", "root_b64": _b64(f.root)}, ("claim", "evaluator_id", "subject_profile"),
         _json),
        ("intoto.resolve_subject", intoto.resolve_subject,
         {"profile": "receipt", "claim": f.claim, "root_b64": _b64(f.root)}, ("profile", "claim"), _json),
        ("intoto.export_svr_dsse", intoto.export_svr_dsse,
         {"bundle": f.bundle, "signer": f.sk, "time_created": _T}, ("bundle",), _json),
        ("evalclaim.build_eval_claim", ec.build_eval_claim,
         {"suite": "s", "suite_version": "1", "metric": "acc", "comparator": ">=", "threshold": "0.80",
          "score": "0.90", "n": 10, "model_id": "m", "dataset_id": "d", "issuer": ec.issuer_fingerprint(f.sk),
          "timestamp": _T, "ci95": ["0.85", "0.95"], "provenance": {"harness": "h", "runs": [1, 2]},
          "model_salt": b"0" * 16, "dataset_salt": b"1" * 16},
         ("suite", "comparator", "threshold", "score", "issuer", "timestamp", "ci95", "provenance",
          "model_salt", "dataset_salt"), _json),
        ("evalclaim.emit_eval_receipt", ec.emit_eval_receipt, {"claim": f.claim_in, "signer": f.sk},
         ("claim",), _json),
        ("evalclaim.salted_commit", ec.salted_commit, {"identifier": "m", "salt": b"0" * 16},
         ("identifier", "salt"), ident),
        ("persample.derive_leaf_salt", persample.derive_leaf_salt,
         {"tree_secret": b"s" * 32, "sample_id": "a", "epoch": 1}, ("tree_secret",), ident),
        ("persample.make_disclosure", persample.make_disclosure,
         {"record": {"idx": 0, "id": "a", "score": "1"}, "salt": b"s" * 16}, ("record", "salt"), ident),
        ("persample.build_sample_tree", persample.build_sample_tree,
         {"records": [{"id": 1, "score": "1"}, {"id": 2, "score": "0"}], "tree_secret": b"s" * 32},
         ("records", "tree_secret"), _json),
        ("evidence_pack.build_evidence_pack", ep.build_evidence_pack,
         {"canonical_root": f.root, "proof": b"not an ots proof", "bundled_headers": {"800000": "a" * 64},
          "declared_calendars": ["https://a.example.org"]}, ("proof", "bundled_headers"), _json),
        ("renewal.build_initial_sequence", renewal.build_initial_sequence,
         {"data_digests": ["a" * 64, "b" * 64], "hash_alg": "sha256", "time": 1_780_000_000,
          "anchor_status": "confirmed"}, ("data_digests", "hash_alg", "anchor_status"), _tokens),
        ("renewal.renew_timestamp", renewal.renew_timestamp,
         {"sequence": seq, "time": 1_780_000_001, "anchor_status": "confirmed"}, ("sequence", "anchor_status"),
         _tokens),
        ("renewal.renew_hashtree", renewal.renew_hashtree,
         {"sequence": seq, "data_digests": ["a" * 64], "new_hash_alg": "sha512", "time": 1_780_000_002},
         ("sequence", "data_digests", "new_hash_alg"), _tokens),
        ("hf_evals.to_eval_results_entry", hf.to_eval_results_entry,
         {"bundle": f.bundle, "dataset_id": "d", "task_id": "t", "value": 0.9, "notes": "n"},
         ("bundle", "dataset_id", "task_id", "notes"), _json),
        ("hf_evals.eval_results_yaml", hf.eval_results_yaml, {"entries": [entry]}, ("entries",), ident),
        ("hf_evals.receipt_token", hf.receipt_token, {"bundle": f.bundle}, ("bundle",), ident),
        ("tlogproof.format_tlog_proof", tlogproof.format_tlog_proof,
         {"index": 0, "inclusion_proof": [hashlib.sha256(b"h").digest()], "signed_checkpoint": f.note,
          "extra": b"x"}, ("inclusion_proof", "signed_checkpoint", "extra"), ident),
        ("tlogproof.tlog_proof_for_bundle", tlogproof.tlog_proof_for_bundle,
         {"bundle": f.bundle, "signed_checkpoint": note_for_bundle}, ("bundle", "signed_checkpoint"), ident),
        ("anchors_chia_add.export_anchor", _chia_export, {"root": f.root, "value": "ab" * 32},
         ("root", "value"), _json),
        ("anchors_chia_add.anchor_add", _chia_add, {"root_hex": f.root.hex(), "value_hex": "cd" * 32},
         ("root_hex", "value_hex"), _json),
        ("anchors_rfc3161.create_rfc3161_anchor", _rfc3161_create, {"root": f.root}, ("root",), _json),
        ("anchors.prereg_canonical_root", anchors.prereg_canonical_root, {"prereg_sha256_hex": "a" * 64},
         ("prereg_sha256_hex",), ident),
        ("beacon.beacon_nonce", beacon.beacon_nonce,
         {"pulse_randomness": b"p" * 32, "beacon": "drand-quicknet", "round_": 7},
         ("pulse_randomness", "beacon"), ident),
        # through `as_dict`, so that a caller's object the request carries is seen in the output
        ("beacon.beacon_audit_challenge", lambda **kw: beacon.beacon_audit_challenge(**kw).as_dict(),
         {"root": f.root, "n": 10, "k": 3, "pulse_randomness": b"p" * 32, "beacon": "drand-quicknet",
          "round_": 7}, ("root", "pulse_randomness", "beacon"), _json),
        ("persample.audit_challenge", persample.audit_challenge,
         {"root": f.root, "n": 10, "k": 3, "nonce": b"n" * 16}, ("root", "nonce"), ident),
        ("persample.audit_challenge, base64 root", persample.audit_challenge,
         {"root": _b64(f.root), "n": 10, "k": 3, "nonce": bytearray(b"n" * 16)}, ("root", "nonce"), ident),
        ("persample.sample_opening", persample.sample_opening, {"disclosures": disclosures, "index": 1},
         ("disclosures",), _json),
        ("hashalg.compute_dual_hash", hashalg.compute_dual_hash,
         {"data": b"the data", "alg_ids": ["sha256", "sha512"]}, ("data",), _json),
        ("run_ledger.link_runs", run_ledger.link_runs,
         {"result_digests": ["a" * 64, "b" * 64], "statuses": ["completed", "failed"]},
         ("result_digests", "statuses"), _json),
        ("run_ledger.link_runs, default statuses", run_ledger.link_runs,
         {"result_digests": ("a" * 64,)}, ("result_digests",), _json),
        ("evalclaim.canonicalize", ec.canonicalize, {"claim": f.claim_in}, ("claim",), ident),
    ]
    if eee_path.is_file():
        c.append(("adapters.eee.from_eee_dataset", eee.from_eee_dataset,
                  {"source": json.loads(eee_path.read_text(encoding="utf-8")), "comparator": ">=",
                   "threshold": "0.5", "timestamp": _T, "model_salt": b"0" * 16, "dataset_salt": b"1" * 16,
                   "validate": False}, ("source",), _json))
    return c


def _mldsa_signer():
    try:
        from cryptography.hazmat.primitives.asymmetric import mldsa
        return mldsa.MLDSA44PrivateKey.generate()
    except Exception:  # noqa: BLE001 — a build without FIPS 204 has no ML-DSA-44 signer
        return None


class EveryProducerReadsItsValuesOnce(unittest.TestCase):

    def _check(self, name, producer, kwargs, trap_names, normalise):
        kwargs = {k: (v() if k == "predicate" and callable(v) else v) for k, v in kwargs.items()}
        plain = normalise(producer(**kwargs))
        handed = {k: (trapped(v) if k in trap_names else v) for k, v in kwargs.items()}
        CALLS.clear()
        out = producer(**handed)
        ran = sorted(set(CALLS))
        self.assertEqual(ran, [], f"{name}: the producer read a caller's value through its own methods")
        self.assertFalse(_holds_a_trap(out), f"{name}: the output carries the caller's object")
        self.assertEqual(normalise(out), plain, f"{name}: a legitimate value was written differently")

    def test_every_producer(self):
        for name, producer, kwargs, trap_names, normalise in _cases():
            with self.subTest(producer=name):
                self._check(name, producer, kwargs, trap_names, normalise)

    def test_the_ml_dsa_cosignature(self):
        """ML-DSA signatures are randomised, so the lines are compared without their signature."""
        from proofbundle import checkpoint as cp
        signer = _mldsa_signer()
        if signer is None:
            self.skipTest("NOT MEASURABLE: this build of cryptography has no ML-DSA-44")
        note = fx().note

        def shape(out):
            line = out.rsplit("\n", 2)[-2]
            name, blob = line.split(" ")[1:3]
            return out[:len(note)], name, base64.b64decode(blob)[:12]
        plain = shape(cp.cosign_checkpoint_mldsa(note, signer, "w", 1_780_000_000))
        CALLS.clear()
        out = cp.cosign_checkpoint_mldsa(trapped(note), signer, trapped("w"), 1_780_000_000)
        self.assertEqual(sorted(set(CALLS)), [])
        self.assertEqual(shape(out), plain)


# ── the three `assemble` steps under scripts/, in a process of their own ──────────────────────────

_PRODUCERS = {
    "gen_findings_register": ("scripts/gen_findings_register.py", "assemble", "gen_findings_register"),
    "sign_readiness_artifact": ("scripts/sign_readiness_artifact.py", "assemble", "sign_readiness_artifact"),
    "pre_tag_receipt": ("scripts/pre_tag_receipt.py", "assemble_receipt", "pre_tag_receipt_lib"),
}
_BODIES = {
    "gen_findings_register": {"schema": "proofbundle.findings_register.v1", "version": "9.9.9",
                              "generated_at": _T, "findings": [{"id": "F1", "open": True}]},
    "sign_readiness_artifact": {"schema": "x", "signer_role": "release-runner", "produced_at": _T,
                                "counts": [1, 2]},
    "pre_tag_receipt": {"version": "9.9.9", "subject_tree_digest": "a" * 64, "gate_source_digest": "b" * 64,
                        "audit_command": "nobody ran this", "audit_exit_code": 0,
                        "audit_output_digest": "c" * 64, "runner_identity": "nobody", "produced_at": _T},
}

#: The trap of section 1 and the lens's own forms of finding B, in the driver process. Mode "trap": the
#: body handed in trapped, the output compared with the plain call's. Mode "lens": a dict subclass that
#: stores body B and answers body A through `items()` (through `__getitem__` and `__contains__` for the
#: receipt), with a real signature over A. The step must refuse, since what it holds is B.
_DRIVER = r'''
import base64, importlib.util, json, sys
sys.path.insert(0, sys.argv[7])
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import tests.test_a_producer_reads_a_callers_value_once as T

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

class ItemsBody(dict):
    def items(self):
        return self.answer.items()

class GetitemBody(dict):
    def __getitem__(self, k):
        return self.answer[k]
    def __contains__(self, k):
        return k in self.answer

path, fn_name, lib_path, body, mode, receipt = sys.argv[1:7]
mod = load("producer", path)
fn, body = getattr(mod, fn_name), json.loads(body)
lib = mod if lib_path == path else load("lib", lib_path)
if hasattr(lib, "RECEIPT_SCHEMA"):
    body = dict(body, schema=lib.RECEIPT_SCHEMA)
k = Ed25519PrivateKey.generate()
pub = base64.b64encode(k.public_key().public_bytes_raw()).decode()
if mode == "trap":
    sig = base64.b64encode(k.sign(lib.canonical_bytes(body))).decode()
    plain = json.dumps(fn(dict(body), sig, pub), sort_keys=True)
    handed = T.trapped(body)
    T.CALLS.clear()
    out = fn(handed, T.trapped(sig), T.trapped(pub))
    print(json.dumps({"ran": sorted(set(T.CALLS)), "trap_in_output": T._holds_a_trap(out),
                      "same": json.dumps(out, sort_keys=True) == plain}))
else:
    answer = body
    stored = dict(body, version="6.6.6", runner_identity="someone-else", signer_role="someone-else")
    sig = base64.b64encode(k.sign(lib.canonical_bytes(answer))).decode()
    hostile = (GetitemBody if receipt == "1" else ItemsBody)(stored)
    hostile.answer = answer
    try:
        out = fn(hostile, sig, pub)
        print(json.dumps({"refused": False, "written_version": json.loads(json.dumps(out)).get("version")}))
    except SystemExit as exc:
        print(json.dumps({"refused": True, "why": str(exc.code)[:200]}))
'''


class TheAssembleSteps(unittest.TestCase):

    def _run(self, producer: str, mode: str) -> dict:
        path, fn, lib = _PRODUCERS[producer]
        for rel in (path, f"scripts/{lib}.py"):
            if _not_shipped(rel):
                self.skipTest(f"not shipped: {rel} is not in this distribution, so its `assemble` step is "
                              "N/A outside a git checkout")
        env = dict(os.environ, PYTHONPATH=str(REPO / "src"), PYTHONDONTWRITEBYTECODE="1")
        r = subprocess.run([sys.executable, "-B", "-c", _DRIVER, str(REPO / path), fn,
                            str(REPO / "scripts" / f"{lib}.py"), json.dumps(_BODIES[producer]), mode,
                            "1" if producer == "pre_tag_receipt" else "0", str(REPO)],
                           capture_output=True, text=True, timeout=300, env=env)
        if r.returncode != 0:
            raise AssertionError(f"driver for {producer} failed: {r.stderr[-1500:]}")
        return json.loads(r.stdout.strip().splitlines()[-1])

    def test_the_body_is_read_once(self):
        for producer in _PRODUCERS:
            with self.subTest(producer=producer):
                res = self._run(producer, "trap")
                self.assertEqual(res["ran"], [], f"{producer} read the body through the caller's methods")
                self.assertFalse(res["trap_in_output"])
                self.assertTrue(res["same"], "a legitimate body was written differently")

    def test_the_lens_form_is_refused(self):
        """Finding B: a body that stores B and answers A, with a real signature over A. At fddc00f4
        each step verified A and wrote B."""
        for producer in _PRODUCERS:
            with self.subTest(producer=producer):
                res = self._run(producer, "lens")
                self.assertTrue(res["refused"], f"{producer} wrote {res}")


# ── 2. the lens's counter-examples, as it ran them ────────────────────────────────────────────────

class TheLensCounterExamples(unittest.TestCase):

    def test_a_the_name_of_a_vkey_is_the_text_it_holds(self):
        """Finding A: `Name("log")` whose `__format__` answers a whole vkey line for the identity point,
        a newline and `log`. The vkey is now the one for `log`, and nothing stands in front of it."""
        from proofbundle import checkpoint as cp
        i1 = b"\x01" + b"\x00" * 31
        key = _raw(Ed25519PrivateKey.generate())

        class Name(str):
            inject = ""

            def __format__(self, spec):
                return self.inject

        for writer, stored, sig_type in ((cp.vkey, "log", 0x01), (cp.cosign_vkey, "w", 0x04)):
            kid = hashlib.sha256(b"evil\n" + bytes([sig_type]) + i1).digest()[:4]
            n = Name(stored)
            n.inject = f"evil+{kid.hex()}+{_b64(bytes([sig_type]) + i1)}\n{stored}"
            with self.subTest(writer=writer.__name__):
                out = writer(n, key)
                self.assertEqual(out, writer(stored, key))
                self.assertNotIn("\n", out)

    def test_a_all_seven_name_and_origin_sites(self):
        """The siblings: a `str` subclass whose storage is clean and whose `__format__` answers a text
        with '+', a space and a newline. At fddc00f4 all seven wrote it; now each writes the storage."""
        from proofbundle import checkpoint as cp
        sk, w = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
        bad = "bad+name with space\nsecond line"
        root = hashlib.sha256(b"r").digest()

        class T(str):
            def __format__(self, spec):
                return bad

        note = cp.sign_checkpoint("example.org/log", 5, root, sk, "log")
        ml = hashlib.shake_256(b"k").digest(1312)
        sites = {
            "vkey name": (lambda: cp.vkey(T("log"), _raw(sk)), lambda: cp.vkey("log", _raw(sk))),
            "cosign_vkey name": (lambda: cp.cosign_vkey(T("w"), _raw(w)), lambda: cp.cosign_vkey("w", _raw(w))),
            "cosign_vkey_mldsa name": (lambda: cp.cosign_vkey_mldsa(T("w"), ml),
                                       lambda: cp.cosign_vkey_mldsa("w", ml)),
            "checkpoint_note origin": (lambda: cp.checkpoint_note(T("example.org/log"), 5, root),
                                       lambda: cp.checkpoint_note("example.org/log", 5, root)),
            "sign_checkpoint origin": (lambda: cp.sign_checkpoint(T("example.org/log"), 5, root, sk, "log"),
                                       lambda: cp.sign_checkpoint("example.org/log", 5, root, sk, "log")),
            "sign_checkpoint keyname": (lambda: cp.sign_checkpoint("example.org/log", 5, root, sk, T("log")),
                                        lambda: cp.sign_checkpoint("example.org/log", 5, root, sk, "log")),
            "cosign_checkpoint witness_name": (lambda: cp.cosign_checkpoint(note, w, T("w"), 1_780_000_000),
                                               lambda: cp.cosign_checkpoint(note, w, "w", 1_780_000_000)),
        }
        for site, (hostile, plain) in sites.items():
            with self.subTest(site=site):
                out = hostile()
                self.assertNotIn(bad, out)
                self.assertEqual(out, plain())

    def test_b_the_signers_map_of_a_trust_pack(self):
        """Finding B: a signers dict whose `__iter__` names a declared keyId and whose `items()` names
        another, and a `str` subclass keyId whose text is undeclared while it hashes as a declared one."""
        from proofbundle import trust_pack as tp
        f = fx()
        other = Ed25519PrivateKey.generate()

        class Signers(dict):
            def __iter__(self):
                return iter(["o"])

            def items(self):
                return [("evil", other)]

        class Label(str):
            def __hash__(self):
                return hash("o")

            def __eq__(self, x):
                return x == "o"

        with self.subTest(form="dict subclass, storage 'o', items() 'evil'"):
            env = tp.sign_trust_pack(f.pack, Signers({"o": f.owner}))
            self.assertEqual([s["keyid"] for s in env["signatures"]], ["o"])
            self.assertTrue(tp.verify_trust_pack(json.loads(json.dumps(env)))["ok"])
        for label, signers in (("dict subclass, storage 'evil'", Signers({"evil": other})),
                               ("str subclass keyId, text 'evil'", {Label("evil"): other})):
            with self.subTest(form=label):
                with self.assertRaises(tp.TrustPackError):
                    tp.sign_trust_pack(f.pack, signers)

    def test_b_the_overlay_the_policy_id_and_the_status(self):
        from proofbundle.policy import PolicyError, load_policy
        from proofbundle.policy_profiles import instantiate_template, profile_path
        from proofbundle.sdjwt_issue import issue_sd_jwt
        f = fx()
        k = _b64(_raw(f.sk))

        class Overlay(dict):
            def __iter__(self):
                return iter([])

        with self.subTest(form="overlay whose __iter__ yields nothing"):
            with self.assertRaises(PolicyError):
                instantiate_template("strict-eval-template-v1", issuer_keys=[k], policy_id="org/x",
                                     overlay=Overlay(generatedFromTemplate="forged", policyPurpose="decision"))
        tpl_id = load_policy(profile_path("strict-eval-template-v1"))["policy_id"]

        class Id(str):
            def __eq__(self, x):
                return False
            __hash__ = str.__hash__

        with self.subTest(form="policy_id whose __eq__ answers False, text = the template's"):
            with self.assertRaises(PolicyError):
                instantiate_template("strict-eval-template-v1", issuer_keys=[k], policy_id=Id(tpl_id))

        class St(dict):
            def __contains__(self, key):
                return True

        with self.subTest(form="status whose __contains__ answers True, without status_list"):
            with self.assertRaises(ValueError):
                issue_sd_jwt(f.claim_in, f.sk, root_b64=_b64(f.root), status=St(idx=1))

    def test_d_a_number_is_what_it_stores(self):
        """Finding D: a float subclass storing 1.5 whose `__float__` answers 1.0, a plain float subclass
        storing 1.0, an int subclass and `numpy.float64(1.0)`, as `version` and as a role's `threshold`:
        refused, as at 75c3aa48 and on main. A plain 1.0 still signs as 1 (round 8's decision)."""
        from proofbundle import trust_pack as tp
        f = fx()

        class Lying(float):
            def __float__(self):
                return 1.0

        class F(float):
            pass

        forms = {"Lying(1.5)": Lying(1.5), "F(1.0)": F(1.0), "int subclass 1": TrapInt(1)}
        try:
            import numpy
            forms["numpy.float64(1.0)"] = numpy.float64(1.0)
        except ImportError:
            pass
        for label, v in forms.items():
            for field in ("version", "threshold"):
                pred = json.loads(json.dumps(f.pack))
                if field == "version":
                    pred["version"] = v
                else:
                    pred["roles"]["root"]["threshold"] = v
                for producer in (lambda p: tp.sign_trust_pack(p, {"o": f.owner}),
                                 tp.build_trust_pack_statement):
                    with self.subTest(form=label, field=field):
                        with self.assertRaises(tp.TrustPackError):
                            producer(pred)
        with self.subTest(form="plain 1.0 signs as 1"):
            self.assertEqual(tp.sign_trust_pack(dict(f.pack, version=1.0), {"o": f.owner})["payload"],
                             tp.sign_trust_pack(f.pack, {"o": f.owner})["payload"])


# ── 3. a number a producer checks and writes is an exact int or float ─────────────────────────────

class ANumberIsExact(unittest.TestCase):
    """A subclass of `int` or `float` has no storage read but its own methods: its comparison, its
    `__format__`, its `to_bytes` and its `__int__`/`__float__` are the caller's, and the producers
    checked through one and wrote through another. Each refuses it, with its own typed error."""

    def test_each_number_site_refuses_a_subclass(self):
        from proofbundle import beacon, checkpoint as cp, evalclaim as ec, hf_evals as hf, persample, renewal
        from proofbundle import run_ledger, statuslist as sl, tlogproof
        from proofbundle.errors import BundleFormatError
        from proofbundle.sdjwt_issue import issue_sd_jwt, present_with_key_binding
        f = fx()
        compact = issue_sd_jwt(f.claim_in, f.sk, root_b64=_b64(f.root))
        ledger = _ledger_pred()
        ledger["runBudget"] = TrapInt(5)
        seq = renewal.build_initial_sequence(["a" * 64], hash_alg="sha256", time=1_780_000_000)
        sites = {
            "checkpoint_note tree_size": (lambda: cp.checkpoint_note("example.org/log", TrapInt(5), f.root),
                                          BundleFormatError),
            "cosign_checkpoint timestamp": (lambda: cp.cosign_checkpoint(f.note, f.witness, "w",
                                                                         TrapInt(1_780_000_000)),
                                            BundleFormatError),
            "status_claim idx": (lambda: sl.status_claim("https://example.org/l", TrapInt(3)), BundleFormatError),
            "issue_status_list_token bits": (lambda: sl.issue_status_list_token(
                [0, 1], uri="u", signer=f.sk, iat=1_780_000_000, bits=TrapInt(1)), BundleFormatError),
            "issue_status_list_token statuses": (lambda: sl.issue_status_list_token(
                [0, TrapInt(1)], uri="u", signer=f.sk, iat=1_780_000_000), BundleFormatError),
            "present_with_key_binding iat": (lambda: present_with_key_binding(
                compact, f.holder, aud="v", nonce="n", iat=TrapInt(1_780_000_000)), ValueError),
            "build_eval_claim n": (lambda: ec.build_eval_claim(
                suite="s", suite_version="1", metric="acc", comparator=">=", threshold="0.8", score="0.9",
                n=TrapInt(10), model_id="m", dataset_id="d", issuer="x", timestamp=_T,
                model_salt=b"0" * 16, dataset_salt=b"1" * 16), ec.EvalClaimError),
            "emit_run_ledger runBudget": (lambda: run_ledger.emit_run_ledger(ledger, f.sk),
                                          run_ledger.RunLedgerError),
            "renew_timestamp time": (lambda: renewal.renew_timestamp(seq, time=TrapInt(1_780_000_001)),
                                     renewal.RenewalError),
            "build_initial_sequence time": (lambda: renewal.build_initial_sequence(
                ["a" * 64], hash_alg="sha256", time=TrapInt(1_780_000_000)), renewal.RenewalError),
            "format_tlog_proof index": (lambda: tlogproof.format_tlog_proof(TrapInt(0), [], f.note),
                                        BundleFormatError),
            "derive_leaf_salt epoch": (lambda: persample.derive_leaf_salt(b"s" * 32, "a", TrapInt(1)),
                                       BundleFormatError),
            "build_sample_tree record epoch": (lambda: persample.build_sample_tree(
                [{"id": 1, "epoch": TrapInt(1)}], b"s" * 32), BundleFormatError),
            "to_eval_results_entry value": (lambda: hf.to_eval_results_entry(
                f.bundle, dataset_id="d", task_id="t", value=TrapFloat(0.9)), BundleFormatError),
            "beacon_nonce round": (lambda: beacon.beacon_nonce(b"p" * 32, "drand", TrapInt(7)),
                                   BundleFormatError),
            "beacon_audit_challenge round": (lambda: beacon.beacon_audit_challenge(
                f.root, 10, 3, pulse_randomness=b"p" * 32, beacon="drand", round_=TrapInt(7)),
                BundleFormatError),
            "audit_challenge n": (lambda: persample.audit_challenge(f.root, TrapInt(10), 3, b"n" * 16),
                                  BundleFormatError),
            "audit_challenge k": (lambda: persample.audit_challenge(f.root, 10, TrapInt(3), b"n" * 16),
                                  BundleFormatError),
            "sample_opening index": (lambda: persample.sample_opening(["a", "b"], TrapInt(1)),
                                     BundleFormatError),
            "evalclaim.canonicalize an int": (lambda: ec.canonicalize({"n": TrapInt(10)}), ec.EvalClaimError),
        }
        for site, (call, error) in sites.items():
            with self.subTest(site=site):
                with self.assertRaises(error):
                    call()


# ── 4. every public producer under src/ and scripts/ is named, with how it is covered ─────────────

#: A public function whose name marks it as something that builds, signs, writes, renders or derives
#: an artefact from what it is handed. The scan finds each; the list below says what it does with a
#: caller's value and where the contract holds it.
_PRODUCER_NAME = re.compile(
    r"^(emit|sign|build|issue|export|instantiate|assemble|cosign|present|create|make|format|render|to|from|"
    r"prepare|replace|derive|attach|resolve|anchor_add|tlog_proof|status_claim|checkpoint_note|vkey|key_id|"
    r"salted_commit|receipt_token|eval_results_yaml|test_result_ref|body_core|disclosure_core|"
    # widened in the same round, from a read of every public function the first pattern missed: the
    # verbs of a function that forms, hashes, links, measures or renews something from its arguments
    r"renew|add|bind|link|compute|beacon|sample_opening|audit_challenge|merkle_tree_hash|inclusion_proof|"
    r"consistency_proof|prereg_canonical_root|receipt_canonical_root|statement_content_root|canonicalize|"
    r"canonical|normalise|evidence_digest|pae|save|generate|findings_root|receipt_digest|statement_digest|"
    r"config_hash|payload_hash|leaf|clvm|apply|measure|join)(_|$)")

_COVERED = "read once; section 1 case"


def _c(name: str) -> str:
    return f"{_COVERED} {name}"


_PRIVATE_PROVENANCE = ("not affected: a helper of a private module, called only by the adapters with "
                       "values they parsed from a file (the EEE adapter with its copy read once)")


_SWEEP = {
    ("src/proofbundle/_integration.py", "emit_enabled"): "not affected: reads the environment, writes nothing",
    ("src/proofbundle/_integration.py", "emit_config"): "not affected: reads the environment, writes nothing",
    ("src/proofbundle/_integration.py", "emit_claim_receipt"): "read once by emit_eval_receipt, which it calls",
    ("src/proofbundle/adapters/eee.py", "from_eee_dataset"): _c("adapters.eee.from_eee_dataset"),
    ("src/proofbundle/adapters/inspect_ai.py", "from_inspect_ai_log"): "not affected: parses a log file; its "
        "arguments go to build_eval_claim, which reads them once",
    ("src/proofbundle/adapters/lm_eval.py", "from_lm_eval_results"): "not affected: parses a results file; "
        "its arguments go to build_eval_claim",
    ("src/proofbundle/adapters/promptfoo.py", "from_promptfoo_results"): "not affected: parses a results "
        "file; its arguments go to build_eval_claim",
    ("src/proofbundle/agent_review.py", "body_core_bytes"): _c("agent_review.body_core_bytes"),
    ("src/proofbundle/agent_review.py", "prepare_body_for_disclosure"): _c("agent_review.prepare_body_for_disclosure"),
    ("src/proofbundle/agent_review.py", "replace_disclosure_block"): _c("agent_review.replace_disclosure_block"),
    ("src/proofbundle/agent_review.py", "body_core_digest"): "hashes body_core_bytes, which reads once",
    ("src/proofbundle/agent_review.py", "disclosure_core_bytes"): _c("agent_review.disclosure_core_bytes"),
    ("src/proofbundle/agent_review.py", "disclosure_core_digest"): "hashes disclosure_core_bytes, which reads once",
    ("src/proofbundle/agent_review.py", "derive_limitation_codes"): "not affected: derives codes, writes no "
        "value it checked",
    ("src/proofbundle/agent_review.py", "resolve_receipt_chain"): "not a producer: judges envelopes (verify side)",
    ("src/proofbundle/agent_review.py", "render_disclosure_block"): _c("agent_review.render_disclosure_block"),
    ("src/proofbundle/agent_review.py", "render_disclosure_line"): _c("agent_review.render_disclosure_line"),
    ("src/proofbundle/agent_review.py", "build_agent_review_statement"): _c("agent_review.build_agent_review_statement"),
    ("src/proofbundle/agent_review.py", "emit_agent_review"): _c("agent_review.emit_agent_review"),
    ("src/proofbundle/anchors_chia_add.py", "export_anchor"): _c("anchors_chia_add.export_anchor"),
    ("src/proofbundle/anchors_chia_add.py", "anchor_add"): _c("anchors_chia_add.anchor_add"),
    ("src/proofbundle/anchors_rfc3161.py", "create_rfc3161_anchor"): _c("anchors_rfc3161.create_rfc3161_anchor"),
    ("src/proofbundle/anchors_rootcommit.py", "build_preimage"): "not affected: formats its arguments, checks none",
    ("src/proofbundle/budget.py", "render_safe"): "not a producer: renders a diagnostic",
    ("src/proofbundle/budget.py", "render_keys_safe"): "not a producer: renders a diagnostic",
    ("src/proofbundle/checkpoint.py", "checkpoint_note"): _c("checkpoint.checkpoint_note"),
    ("src/proofbundle/checkpoint.py", "key_id"): _c("checkpoint.key_id"),
    ("src/proofbundle/checkpoint.py", "vkey"): _c("checkpoint.vkey"),
    ("src/proofbundle/checkpoint.py", "sign_checkpoint"): _c("checkpoint.sign_checkpoint"),
    ("src/proofbundle/checkpoint.py", "cosign_key_id"): _c("checkpoint.cosign_key_id"),
    ("src/proofbundle/checkpoint.py", "cosign_vkey"): _c("checkpoint.cosign_vkey"),
    ("src/proofbundle/checkpoint.py", "cosign_checkpoint"): _c("checkpoint.cosign_checkpoint"),
    ("src/proofbundle/checkpoint.py", "cosign_key_id_mldsa"): _c("checkpoint.cosign_key_id_mldsa"),
    ("src/proofbundle/checkpoint.py", "cosign_vkey_mldsa"): _c("checkpoint.cosign_vkey_mldsa"),
    ("src/proofbundle/checkpoint.py", "cosign_checkpoint_mldsa"): "read once; test_the_ml_dsa_cosignature",
    ("src/proofbundle/cli.py", "build_parser"): "not a producer: builds the argument parser",
    ("src/proofbundle/decision.py", "resolve_evidence_ref"): "not a producer: judges evidence (verify side)",
    ("src/proofbundle/decision.py", "build_decision_statement"): _c("decision.build_decision_statement"),
    ("src/proofbundle/decision.py", "emit_decision_receipt"): _c("decision.emit_decision_receipt"),
    ("src/proofbundle/dsse.py", "sign_envelope"): "not affected: checks nothing; a body signed and written "
        "through two reads gives an envelope its verifier refuses",
    ("src/proofbundle/emit.py", "emit_bundle"): "not affected: checks nothing; the payload is signed and "
        "written, sd_jwt_vc passed on verbatim",
    ("src/proofbundle/evalclaim.py", "salted_commit"): _c("evalclaim.salted_commit"),
    ("src/proofbundle/evalclaim.py", "build_eval_claim"): _c("evalclaim.build_eval_claim"),
    ("src/proofbundle/evalclaim.py", "emit_eval_receipt"): _c("evalclaim.emit_eval_receipt"),
    ("src/proofbundle/evidence_pack.py", "build_evidence_pack"): _c("evidence_pack.build_evidence_pack"),
    ("src/proofbundle/experimental/enclave.py", "issue_enclave_attestation"): "not affected: a test helper "
        "that checks nothing",
    ("src/proofbundle/hashalg.py", "resolve_hash_alg"): "not a producer: a registry lookup",
    ("src/proofbundle/hf_evals.py", "receipt_token"): _c("hf_evals.receipt_token"),
    ("src/proofbundle/hf_evals.py", "receipt_token_identity"): "not a producer: judges a token (verify side)",
    ("src/proofbundle/hf_evals.py", "to_eval_results_entry"): _c("hf_evals.to_eval_results_entry"),
    ("src/proofbundle/hf_evals.py", "eval_results_yaml"): _c("hf_evals.eval_results_yaml"),
    ("src/proofbundle/intoto.py", "to_intoto_statement"): _c("intoto.to_intoto_statement"),
    ("src/proofbundle/intoto.py", "to_test_result_statement"): _c("intoto.to_test_result_statement"),
    ("src/proofbundle/intoto.py", "export_intoto_dsse"): _c("intoto.export_intoto_dsse"),
    ("src/proofbundle/intoto.py", "resolve_subject"): _c("intoto.resolve_subject"),
    ("src/proofbundle/intoto.py", "to_eval_result_predicate"): _c("intoto.to_eval_result_predicate"),
    ("src/proofbundle/intoto.py", "to_eval_result_statement"): _c("intoto.to_eval_result_statement"),
    ("src/proofbundle/intoto.py", "export_eval_result_dsse"): _c("intoto.export_eval_result_dsse"),
    ("src/proofbundle/intoto.py", "to_eval_result_v02_predicate"): _c("intoto.to_eval_result_v02_predicate"),
    ("src/proofbundle/intoto.py", "to_eval_result_v02_statement"): _c("intoto.to_eval_result_v02_statement"),
    ("src/proofbundle/intoto.py", "export_eval_result_v02_dsse"): _c("intoto.export_eval_result_v02_dsse"),
    ("src/proofbundle/intoto.py", "export_svr_dsse"): _c("intoto.export_svr_dsse"),
    ("src/proofbundle/outcome.py", "resolve_receiver_ref"): "not a producer: judges evidence (verify side)",
    ("src/proofbundle/outcome.py", "build_outcome_statement"): _c("outcome.build_outcome_statement"),
    ("src/proofbundle/outcome.py", "emit_outcome_receipt"): _c("outcome.emit_outcome_receipt"),
    ("src/proofbundle/persample.py", "derive_leaf_salt"): _c("persample.derive_leaf_salt"),
    ("src/proofbundle/persample.py", "make_disclosure"): _c("persample.make_disclosure"),
    ("src/proofbundle/persample.py", "build_sample_tree"): _c("persample.build_sample_tree"),
    ("src/proofbundle/policy_profiles.py", "resolve_policy_source"): "not a producer: resolves a path",
    ("src/proofbundle/policy_profiles.py", "instantiate_template"): _c("policy_profiles.instantiate_template"),
    ("src/proofbundle/pqsig.py", "sign_mldsa"): "not affected: signs, checks nothing",
    ("src/proofbundle/relation_statement.py", "build_relation_statement"): _c("relation_statement.build_relation_statement"),
    ("src/proofbundle/relation_statement.py", "emit_relation_statement"): _c("relation_statement.emit_relation_statement"),
    ("src/proofbundle/renewal.py", "build_initial_sequence"): _c("renewal.build_initial_sequence"),
    ("src/proofbundle/run_ledger.py", "build_run_ledger_statement"): _c("run_ledger.build_run_ledger_statement"),
    ("src/proofbundle/run_ledger.py", "emit_run_ledger"): _c("run_ledger.emit_run_ledger"),
    ("src/proofbundle/sdjwt_issue.py", "issue_sd_jwt"): _c("sdjwt_issue.issue_sd_jwt"),
    ("src/proofbundle/sdjwt_issue.py", "present_with_key_binding"): _c("sdjwt_issue.present_with_key_binding"),
    ("src/proofbundle/statuslist.py", "status_claim"): _c("statuslist.status_claim"),
    ("src/proofbundle/statuslist.py", "issue_status_list_token"): _c("statuslist.issue_status_list_token"),
    ("src/proofbundle/subject_binding.py", "derive_subject_digest"): "not affected: hashes, checks nothing",
    ("src/proofbundle/tlogproof.py", "format_tlog_proof"): _c("tlogproof.format_tlog_proof"),
    ("src/proofbundle/tlogproof.py", "tlog_proof_for_bundle"): _c("tlogproof.tlog_proof_for_bundle"),
    ("src/proofbundle/trust_pack.py", "build_trust_pack_statement"): _c("trust_pack.build_trust_pack_statement"),
    ("src/proofbundle/trust_pack.py", "sign_trust_pack"): _c("trust_pack.sign_trust_pack"),
    ("src/proofbundle/verification_summary.py", "build_summary_statement"): _c("verification_summary.build_summary_statement"),
    ("src/proofbundle/verification_summary.py", "emit_verification_summary"): _c("verification_summary.emit_verification_summary"),
    ("src/proofbundle/verifier_block.py", "build_verifier_block"): _c("verifier_block.build_verifier_block"),
    ("src/proofbundle/verifier_block.py", "attach"): _c("verifier_block.attach"),
    ("src/proofbundle/verifier_block.py", "build_test_result_statement"): _c("verifier_block.build_test_result_statement"),
    ("src/proofbundle/verifier_block.py", "test_result_ref"): _c("verifier_block.test_result_ref"),
    ("src/proofbundle/verifier_block.py", "sign_test_result_statement"): _c("verifier_block.sign_test_result_statement"),
    ("src/proofbundle/adapters/_provenance.py", "config_hash"): _PRIVATE_PROVENANCE,
    ("src/proofbundle/adapters/_provenance.py", "add_provenance"): _PRIVATE_PROVENANCE,
    ("src/proofbundle/adapters/_provenance.py", "bind_reported_version"): _PRIVATE_PROVENANCE,
    ("src/proofbundle/adapters/agt_receipt.py", "canonical_payload"): "not a producer: the bytes an AGT "
        "receipt's signature covers, formed for its verifier (verify side)",
    ("src/proofbundle/adapters/agt_receipt.py", "payload_hash"): "not a producer: hashes canonical_payload "
        "(verify side)",
    ("src/proofbundle/adapters/agt_receipt.py", "canonical_authorization_payload"): "not a producer: the "
        "bytes an external authorizer's signature covers, formed for the verifier (verify side)",
    ("src/proofbundle/agent_review.py", "findings_root"): "not affected: checks nothing; canonicalises each "
        "finding once and hashes it",
    ("src/proofbundle/agent_review.py", "receipt_digest"): "not a producer: digests a received envelope "
        "(verify side)",
    ("src/proofbundle/agent_review.py", "apply_time_evidence"): "not a producer: it checks `verified` and "
        "`kind` and writes constants; it reads the evidence once, as the plain copy of what it stores "
        "(pull request 312, where its own `get` had lifted both axes)",
    ("src/proofbundle/anchors.py", "receipt_canonical_root"): "not affected: checks only the structural "
        "budget, a bound on its own work, and writes only a hash",
    ("src/proofbundle/anchors.py", "prereg_canonical_root"): _c("anchors.prereg_canonical_root"),
    ("src/proofbundle/anchors.py", "statement_content_root"): "not affected: checks only the type and "
        "hashes the bytes",
    ("src/proofbundle/anchors_chia.py", "clvm_atom_hash"): "not affected: hashes, checks nothing",
    ("src/proofbundle/anchors_chia.py", "leaf_node_hash"): "not affected: hashes, checks nothing",
    ("src/proofbundle/beacon.py", "beacon_nonce"): _c("beacon.beacon_nonce"),
    ("src/proofbundle/beacon.py", "beacon_audit_challenge"): _c("beacon.beacon_audit_challenge"),
    ("src/proofbundle/canonical.py", "canonicalize_statement"): "not affected: a canonicaliser that checks "
        "only the structural budget and, when asked, the Statement shape (no caller in src/ or scripts/ "
        "asks); every producer that signs its output hands it a copy read once",
    ("src/proofbundle/canonical.py", "statement_content_root"): "not affected: hashes the canonical form "
        "or the bytes; checks only the type",
    ("src/proofbundle/dsse.py", "pae"): "not affected: checks nothing (see sign_envelope)",
    ("src/proofbundle/emit.py", "generate_signer"): "not affected: takes no argument",
    ("src/proofbundle/emit.py", "save_signer"): "not affected: writes a key to a path; the path is "
        "written into no artefact",
    ("src/proofbundle/evalclaim.py", "canonicalize"): _c("evalclaim.canonicalize"),
    ("src/proofbundle/experimental/attested_inference.py", "evidence_digest"): "not a producer: part of "
        "judging a provider's evidence for a relying party (verify side, experimental)",
    ("src/proofbundle/experimental/attested_inference.py", "normalise_provider_evidence"): "not a producer: "
        "the record of check_on_receipt, which judges a provider's evidence (verify side, experimental)",
    ("src/proofbundle/hashalg.py", "compute_digest"): "not affected: checks only the algorithm and reads "
        "the data once",
    ("src/proofbundle/hashalg.py", "compute_dual_hash"): _c("hashalg.compute_dual_hash"),
    ("src/proofbundle/merkle.py", "leaf_hash"): "not affected: hashes, checks nothing",
    ("src/proofbundle/merkle.py", "merkle_tree_hash"): "not affected: checks nothing it writes; its "
        "producers (emit_bundle, build_sample_tree, sample_opening) hand it a list they built",
    ("src/proofbundle/merkle.py", "inclusion_proof"): "not affected: checks only that the index can be "
        "used and writes no value it checked; its producers hand it a list they built",
    ("src/proofbundle/merkle.py", "consistency_proof"): "not affected: checks only that the size can be "
        "used and writes no value it checked",
    ("src/proofbundle/persample.py", "sample_opening"): _c("persample.sample_opening"),
    ("src/proofbundle/persample.py", "audit_challenge"): _c("persample.audit_challenge"),
    ("src/proofbundle/policy_profiles.py", "canonical_profile_name"): "not a producer: a lookup",
    ("src/proofbundle/pqsig.py", "generate_mldsa"): "not affected: generates a key; the level is a lookup",
    ("src/proofbundle/renewal.py", "renew_timestamp"): _c("renewal.renew_timestamp"),
    ("src/proofbundle/renewal.py", "renew_hashtree"): _c("renewal.renew_hashtree"),
    ("src/proofbundle/run_ledger.py", "link_runs"): _c("run_ledger.link_runs"),
    ("src/proofbundle/sdjwt.py", "canonical_sd_jwt_compact"): "not a producer: the identity form of a "
        "received credential (verify side)",
    ("src/proofbundle/signature.py", "canonical_es256_signature"): "not a producer: the identity form of a "
        "received signature (verify side)",
    ("src/proofbundle/verifier_block.py", "measure_build"): "not affected: measures the package files",
    ("src/proofbundle/verifier_block.py", "measure_vector_set"): "not affected: measures the corpus files",
    ("src/proofbundle/verifier_block.py", "measure_verifier_block"): "not affected: measures; its statement "
        "goes to test_result_ref, which reads it once",
    ("src/proofbundle/verifier_block.py", "statement_digest"): "not affected: checks nothing; hashes the "
        "canonical form once",
    ("src/proofbundle/verifier_block.py", "join_test_result"): "not a producer: judges a statement against "
        "a block (verify side)",
    ("scripts/build_reproducible.py", "measure_reproducible"): "not affected: builds and measures from the tree",
    ("scripts/build_reproducible.py", "measure_wheel_from_sdist"): "not affected: builds and measures from "
        "the tree",
    ("scripts/codex_threads_check.py", "measure"): "not affected: reports a verdict over review data; writes "
        "no value it checked",
    ("scripts/codex_threads_check.py", "measure_at_origin"): "not affected: queries a remote and reports",
    ("scripts/gen_findings_register.py", "canonical_bytes"): "not affected: the canonical form; `assemble` "
        "hands it the copy read once, the verify side a parsed file",
    ("scripts/pre_tag_receipt_lib.py", "canonical_bytes"): "not affected: the canonical form; "
        "`assemble_receipt` hands it the copy read once, the verify side a parsed file",
    ("scripts/readiness_pack_manifest.py", "compute_manifest"): "not affected: takes no argument",
    ("scripts/readiness_pack_manifest.py", "generate"): "not affected: takes no argument",
    ("scripts/sign_readiness_artifact.py", "canonical_bytes"): "not affected: the canonical form; `assemble` "
        "hands it the copy read once, the verify side a parsed file",
    ("scripts/verify_pre_tag_receipt.py", "measure"): "not a producer: measures for the verifier (verify side)",
    ("scripts/build_reproducible.py", "build_normalized_wheel"): "not affected: builds from the tree",
    ("scripts/build_reproducible.py", "build_normalized"): "not affected: builds from the tree",
    ("scripts/gen_findings_register.py", "build_register"): "not affected: writes its own register constant",
    ("scripts/gen_findings_register.py", "assemble"): "read once; TheAssembleSteps",
    ("scripts/gen_synthetic_ots_fixture.py", "build"): "not affected: takes no argument",
    ("scripts/interop/cedulon_leaked_refusal_adapter.py", "build_decision_predicate"): "not affected: "
        "converts a parsed fixture file",
    ("scripts/interop/cedulon_leaked_refusal_adapter.py", "build_outcome_predicate"): "not affected: "
        "converts a parsed fixture file",
    ("scripts/pre_tag_attestation.py", "build_statement"): "read once; test_pre_tag_attestation_fields",
    ("scripts/pre_tag_attestation.py", "sign_statement"): "not affected: signs, checks nothing",
    ("scripts/pre_tag_receipt.py", "build_context"): "not affected: builds from its own measurement",
    ("scripts/pre_tag_receipt.py", "build_and_sign"): "not affected: signs what build_context built",
    ("scripts/pre_tag_receipt.py", "assemble_receipt"): "read once; TheAssembleSteps",
    ("scripts/render_site_data.py", "build"): "not affected: reads files, takes no caller value",
    ("scripts/rust_parity_gate.py", "resolve_surface"): "not a producer: a lookup",
    ("scripts/sign_readiness_artifact.py", "build_body"): "not affected: copies a parsed measurement, checks "
        "no value it writes",
    ("scripts/sign_readiness_artifact.py", "assemble"): "read once; TheAssembleSteps",
}


def _producers_found() -> "set[tuple[str, str]]":
    import ast
    found = set()
    for root in ("src/proofbundle", "scripts"):
        for path in sorted((REPO / root).rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in tree.body:
                if (isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and not node.name.startswith("_")
                        and _PRODUCER_NAME.match(node.name)):
                    found.add((path.relative_to(REPO).as_posix(), node.name))
    return found


class EveryProducerIsNamed(unittest.TestCase):

    def test_the_scan_and_the_list_agree_in_both_directions(self):
        found = _producers_found()
        listed = {k for k in _SWEEP if not _not_shipped(k[0])}
        self.assertEqual(sorted(found - listed), [], "a producer no one has read and named")
        self.assertEqual(sorted(listed - found), [], "a named producer that is no longer there")

    def test_every_covered_producer_has_its_case(self):
        names = {c[0] for c in _cases()}
        for where, how in _SWEEP.items():
            if how.startswith(_COVERED):
                with self.subTest(producer=where):
                    self.assertIn(how[len(_COVERED) + 1:], names)

    def test_pre_tag_attestation_fields(self):
        """`build_statement` checked the result, the commit and the version through a `str` subclass's
        `__eq__` and pattern reads; each is read once as its text."""
        rel = "scripts/pre_tag_attestation.py"
        if _not_shipped(rel):
            self.skipTest(f"not shipped: {rel}")
        spec = importlib.util.spec_from_file_location("_pta_once", REPO / rel)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        kw = {"commit": "a" * 40, "version": "6.2.0", "verifier_id": "v", "time_verified": "t",
              "policy_uri": "u", "result": "PASSED"}
        plain = json.dumps(mod.build_statement(**kw), sort_keys=True)
        CALLS.clear()
        out = mod.build_statement(**{k: (trapped(v) if k in ("commit", "version", "result") else v)
                                     for k, v in kw.items()})
        self.assertEqual(sorted(set(CALLS)), [])
        self.assertEqual(json.dumps(out, sort_keys=True), plain)


if __name__ == "__main__":
    unittest.main()
