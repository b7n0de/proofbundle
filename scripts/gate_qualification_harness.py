#!/usr/bin/env python3
"""Gate Qualification Harness (makellose-500 Spur 1). Evaluates the GATES, not the product: each of the
15 mandatory counter-proof classes is SEEDED as a known defect and the responsible gate must DETECT it.
Acceptance is 15/15 detected WITH a green positive control per gate (a guard that rejects everything is
not a gate). One surviving preregistered counter-proof strips that gate of its release power.

Maps the 15 classes to the three reconstructed gates:
  type_confusion_gate (F1/F3/F4/F5): empty population, vanished/parser/import surface, nested-leaf,
    string|path on a dict|str primary, shared-payload mutation, comment-as-coverage, inventory disagreement.
  pre_tag_audit_gate  (F6): copied/bare attestation line, wrong subject digest, unsigned/untrusted receipt.
  audit_candidate_matrix (F2/F7): PENDING_JUSTIFIED, DATA_BLOCKED, unknown verdict, negated-keyword decoy.

Spur-2 Linse A note: cc01/cc02 now OBSERVE gate.evaluate() (they were vacuous re-transcriptions of the
rule), and class 15 is a distinct inventory-disagreement counter-example (it duplicated cc10).
"""
from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))
sys.path.insert(0, str(REPO / "scripts"))

import type_confusion_gate as tcg  # noqa: E402
import audit_candidate_matrix as acm  # noqa: E402
from pre_tag_receipt_lib import RECEIPT_SCHEMA, canonical_bytes, verify_receipt  # noqa: E402
from proofbundle.errors import BundleFormatError  # noqa: E402


def _kp():
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    p = Ed25519PrivateKey.generate()
    return p, base64.b64encode(p.public_key().public_bytes_raw()).decode()


# ---- type_confusion_gate counter-examples (a gate helper must CATCH a seeded raw crash / gap) --------
def cc01_empty_population():
    # OBSERVE the gate, never re-transcribe its rule (Spur-2 Linse A: cc01/cc02 were vacuous — they
    # recomputed `0>0` and Python's own ast.parse without touching the gate). Seed an empty inventory and
    # confirm evaluate() ITSELF computes population_complete=False; a future regression that drops the
    # population>0 guard turns THIS red.
    orig_disc, orig_rt = tcg.discover_python_verify_functions, tcg._runtime_inventory
    tcg.discover_python_verify_functions = lambda: {}
    tcg._runtime_inventory = lambda: (set(), [])
    try:
        r = tcg.evaluate()
    finally:
        tcg.discover_python_verify_functions, tcg._runtime_inventory = orig_disc, orig_rt
    detected = r["population_complete"] is False and r["population_size"] == 0
    return detected, f"gate.evaluate() on an empty population -> population_complete={r['population_complete']} (fail-closed)"


def cc02_vanished_or_parser_surface():
    # OBSERVE the gate's OWN parse-skip detection on a seeded unparseable file under the scanned root,
    # THEN confirm evaluate() propagates it to population_complete=False (the `and not parse_skips` clause).
    # discover silently skips a SyntaxError file (its verify_* vanish) — the gate must FAIL, not skip.
    import tempfile
    orig_src = tcg.SRC
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "seeded_broken.py").write_text("def broken(:\n")  # a real SyntaxError source
        tcg.SRC = Path(d)
        try:
            skips = tcg._parse_skips()
        finally:
            tcg.SRC = orig_src
    detected_scan = any("seeded_broken.py" in x for x in skips)
    orig_ps = tcg._parse_skips
    tcg._parse_skips = lambda: ["seeded_broken.py: SyntaxError: seeded"]
    try:
        r = tcg.evaluate()
    finally:
        tcg._parse_skips = orig_ps
    detected = detected_scan and r["population_complete"] is False
    return detected, f"gate._parse_skips detects the seeded file ({detected_scan}) -> evaluate.complete={r['population_complete']}"


def cc03_import_error_surface():
    info = tcg._classify("proofbundle.does_not_exist.verify_ghost")
    return info["status"] == "IMPORT_ERROR", f"unresolvable surface -> {info['status']} (counted, --strict fails)"


def cc04_nested_leaf_crash():
    def victim(x):  # a form-valid outer object whose inner 'status' leaf is hashed unguarded
        if not isinstance(x, dict):
            raise BundleFormatError("shape")
        return x["status"] in {"ok", "bad"}  # unhashable leaf -> raw TypeError
    tcg._FIELD_CACHE["__hq__"] = ["status"]
    try:
        victim.__module__ = "__hq__"
        viol, _n, _t = tcg._exercise_nested(victim, {}, "x", False)
    finally:
        tcg._FIELD_CACHE.pop("__hq__", None)
    return bool(viol), f"nested-leaf matrix caught {len(viol)} raw crash(es) on a form-valid outer object"


def cc05_string_on_dict_or_str_primary():
    def victim(x):  # a dict|str primary that raw-OSErrors on a string (the F5 'correct API' fallacy)
        if isinstance(x, str):
            raise OSError("bad path")
        return False
    viol, _ = tcg._exercise(victim, {}, tcg._COMPACT_STR_PAYLOADS, "x", False)
    return bool(viol), f"string matrix caught {len(viol)} raw OSError(s) on a dict|str primary"


def cc06_shared_payload_mutation():
    # a mutating verifier must not corrupt the shared payload for a later one (deepcopy per call).
    seen = {}

    def mutator(x):
        if isinstance(x, dict):
            x["poisoned"] = True
        return False

    def victim(x):
        seen["poisoned"] = isinstance(x, dict) and x.get("poisoned")
        return False
    payloads = [{"a": 1}]
    tcg._exercise(mutator, {}, payloads, "x", False)
    tcg._exercise(victim, {}, payloads, "x", False)
    # if deepcopy works, victim never sees the mutation AND the shared list is unchanged
    detected = not seen.get("poisoned") and payloads == [{"a": 1}]
    return detected, "deepcopy per call: a mutating verifier cannot poison a later one's payload"


def cc07_comment_as_coverage():
    # a NON_JSON surface is EXERCISED, not delegated by a comment. Detection = it is not silently skipped.
    info = tcg._classify("proofbundle.merkle.verify_inclusion")
    return "fn" in info and info["status"] == "NON_JSON", "NON_JSON surface is resolved+exercised, no comment-delegation"


# ---- pre_tag_audit_gate counter-examples --------------------------------------------------------------
_TREE, _GATE, _VER = "a" * 40, "b" * 64, "5.0.0"


def _receipt(priv, pub, **over):
    r = {"schema": RECEIPT_SCHEMA, "version": _VER, "subject_tree_digest": _TREE,
         "gate_source_digest": _GATE, "audit_command": "c", "audit_exit_code": 0,
         "audit_output_digest": "d" * 64, "runner_identity": "ci", "produced_at": "t"}
    r.update(over)
    r["signature"] = base64.b64encode(priv.sign(canonical_bytes(r))).decode()
    r["signer_pubkey"] = pub
    return r


def _v(receipt, trusted):
    ok, _ = verify_receipt(receipt, trusted_pubkeys=trusted, expected_version=_VER,
                           subject_tree_digest=_TREE, gate_source_digest=_GATE)
    return ok


def cc08_bare_or_copied_attestation_line():
    ok = _v("pre-tag-adversarial-audit: RUN | version=5.0.0", ["x"])  # a bare prose line is not a receipt
    return not ok, "a bare/copied prose attestation line does not grant the pass (P6)"


def cc09_wrong_subject_digest():
    priv, pub = _kp()
    r = _receipt(priv, pub, subject_tree_digest="f" * 40)
    r["signature"] = base64.b64encode(priv.sign(canonical_bytes(r))).decode()
    return not _v(r, [pub]), "a receipt bound to another tree cannot attest this one"


def cc10_unsigned_or_untrusted_receipt():
    priv, pub = _kp()
    return not _v(_receipt(priv, pub), []), "no trusted key pinned -> fail-closed (unbound substitute check)"


# ---- audit_candidate_matrix counter-examples --------------------------------------------------------
def _acm_ready(rows, pin="bound"):
    reg = [(cid, 1, cid, (lambda v=v: (v, "s"))) for cid, v in rows]
    orig_c, orig_p = acm.CHECKS, acm.version_pin_binding
    acm.CHECKS = reg
    acm.version_pin_binding = lambda _v: {"state": pin, "detail": "t"}
    try:
        return acm.evaluate()["audit_candidate_ready"]
    finally:
        acm.CHECKS, acm.version_pin_binding = orig_c, orig_p


def cc11_pending_justified_internal():
    return not _acm_ready([("C2.1", acm.PASS), ("C7.3", acm.PENDING), ("EXT.1", acm.EXTERNAL)]), \
        "internal PENDING_JUSTIFIED withholds readiness"


def cc12_data_blocked_internal():
    return not _acm_ready([("C2.1", acm.PASS), ("C6.3", acm.DATA_BLOCKED), ("EXT.1", acm.EXTERNAL)]), \
        "internal DATA_BLOCKED withholds readiness"


def cc13_unknown_verdict():
    return not _acm_ready([("C2.1", acm.PASS), ("C3.1", "WEIRD"), ("EXT.1", acm.EXTERNAL)]), \
        "an unknown verdict withholds readiness"


def cc14_negated_keyword_decoy():
    # the lexical checks are INFORMATIVE: a decoy PASS on them (incl. a negated-keyword sentence) plus a
    # single DATA_BLOCKED deciding check must still withhold readiness.
    rows = [(cid, acm.PASS) for cid in acm._INFORMATIVE_CHECKS] + [("C6.3", acm.DATA_BLOCKED), ("EXT.1", acm.EXTERNAL)]
    return not _acm_ready(rows), "lexical decoys are informative -> cannot grant readiness"


def cc15_inventory_disagreement():
    # Spur-2 Linse A made class 15 DISTINCT (it was a duplicate of cc10). OBSERVE the two-independent-
    # inventory invariant: seed a runtime inventory carrying a phantom surface the AST inventory lacks, and
    # confirm evaluate() withholds completeness via inventories_agree=False. The reviewer's "two inventories,
    # equality enforced" rule — distinct from cc01 (empty), cc02 (parse-skip), cc03 (import error).
    orig_rt = tcg._runtime_inventory
    tcg._runtime_inventory = lambda: ({"proofbundle.phantom.verify_nonexistent"}, [])
    try:
        r = tcg.evaluate()
    finally:
        tcg._runtime_inventory = orig_rt
    detected = r["population_complete"] is False and r["inventories_agree"] is False
    return detected, f"seeded inventory disagreement -> inventories_agree={r['inventories_agree']}, complete={r['population_complete']}"


CLASSES = [
    ("01_empty_population", "type_confusion", cc01_empty_population),
    ("02_vanished_or_parser_surface", "type_confusion", cc02_vanished_or_parser_surface),
    ("03_import_error_surface", "type_confusion", cc03_import_error_surface),
    ("04_nested_leaf", "type_confusion", cc04_nested_leaf_crash),
    ("05_string_on_dict_or_str", "type_confusion", cc05_string_on_dict_or_str_primary),
    ("06_shared_payload_mutation", "type_confusion", cc06_shared_payload_mutation),
    ("07_comment_as_coverage", "type_confusion", cc07_comment_as_coverage),
    ("08_bare_copied_attestation", "pre_tag", cc08_bare_or_copied_attestation_line),
    ("09_wrong_subject_digest", "pre_tag", cc09_wrong_subject_digest),
    ("10_unsigned_unbound_receipt", "pre_tag", cc10_unsigned_or_untrusted_receipt),
    ("11_pending_justified", "audit_candidate", cc11_pending_justified_internal),
    ("12_data_blocked", "audit_candidate", cc12_data_blocked_internal),
    ("13_unknown_verdict", "audit_candidate", cc13_unknown_verdict),
    ("14_negated_keyword_decoy", "audit_candidate", cc14_negated_keyword_decoy),
    ("15_inventory_disagreement", "type_confusion", cc15_inventory_disagreement),
]


def _positive_controls():
    # each gate must ACCEPT a clean input (not a constant reject).
    out = []
    priv, pub = _kp()
    out.append(("pre_tag_clean_receipt", _v(_receipt(priv, pub), [pub])))
    out.append(("audit_candidate_all_pass", _acm_ready([("C2.1", acm.PASS), ("EXT.1", acm.EXTERNAL)])))
    # type_confusion: a defended verifier produces NO violation (returns a verdict, not a raw crash)
    viol, ret = tcg._exercise(lambda x: False, {}, [None, {}, "s", 5], "x", False)
    out.append(("type_confusion_defended_clean", (not viol) and ret > 0))
    # the REAL gate must ACCEPT the clean subject tree (population_complete True) — proves the 15 detections
    # above are a discriminating gate, not a constant reject (green positive control per gate).
    out.append(("type_confusion_real_population_complete", tcg.evaluate()["population_complete"] is True))
    return out


def run() -> dict:
    results = []
    for cid, gate, fn in CLASSES:
        try:
            detected, detail = fn()
        except Exception as e:  # noqa: BLE001
            detected, detail = False, f"harness error: {type(e).__name__}: {e}"
        results.append({"class": cid, "gate": gate, "detected": bool(detected), "detail": detail})
    pos = [{"control": c, "passed": bool(p)} for c, p in _positive_controls()]
    detected_n = sum(1 for r in results if r["detected"])
    return {
        "schema": "b7n0de.makellose500.gate_qualification.v1",
        "classes_total": len(results),
        "classes_detected": detected_n,
        "detection_rate": f"{detected_n}/{len(results)}",
        "acceptance_15_15": detected_n == len(results) == 15,
        "positive_controls": pos,
        "positive_controls_all_green": all(p["passed"] for p in pos),
        "results": results,
    }


def main(argv=None) -> int:
    r = run()
    print(json.dumps(r, indent=2, ensure_ascii=False))
    ok = r["acceptance_15_15"] and r["positive_controls_all_green"]
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
