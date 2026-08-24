"""The action-chain content-root vectors (Phase 1 / R51) — and the proof that their gate bites.

Three layers, mirroring the corpus rules:

1. every `content_root_vector` case in the manifest passes against the real primitive;
2. CATCH PROOF (a gate that never fires is indistinguishable from a broken gate): a tampered
   copy of a case — one flipped hex character in the pinned root, one mutated payload byte,
   an under-declared expected block — must FAIL the same handler;
3. the properties the vectors exist for hold across cases: an unknown top-level field CHANGES
   the root (silent dropping would collide two different statements), and the algorithm-confusion
   payload is rejected while the identical bytes verify under the named legacy algorithm.

All tampering happens on COPIES under tmp — the accepted corpus bytes are never edited in place
(conformance/README.md rule: a fixture change is a new case, never an in-place edit).
"""
from __future__ import annotations

import importlib.util
import json
import pathlib
import shutil
import sys

REPO = pathlib.Path(__file__).resolve().parents[1]
CONF = REPO / "conformance"
VECTORS = CONF / "action_chain_content_roots"

_spec = importlib.util.spec_from_file_location("_run_conf", CONF / "run_conformance.py")
RC = importlib.util.module_from_spec(_spec)
sys.modules.setdefault("_run_conf", RC)
_spec.loader.exec_module(RC)


def _cases() -> list[tuple[str, dict, pathlib.Path]]:
    manifest = json.loads((CONF / "manifest.json").read_text())
    out = []
    for rel in manifest["cases"]:
        case_dir = CONF / rel
        case = json.loads((case_dir / "case.json").read_text())
        if case.get("kind") == "content_root_vector":
            out.append((rel, case, case_dir))
    return out


def test_vector_set_is_present_and_covers_all_four_modes():
    """Anti-tautology floor: without cases every green claim below would be vacuous."""
    cases = _cases()
    assert len(cases) >= 9, f"expected >= 9 content_root_vector cases, found {len(cases)}"
    modes = {c.get("mode") for _, c, _ in cases}
    assert modes == {"canonical", "pair_reference", "binding", "envelope_invariance"}, modes


def test_every_vector_passes_against_the_real_primitive():
    for rel, case, case_dir in _cases():
        res = RC._check_content_root_vector(case, case_dir)
        assert res["ok"], f"{rel}: {res['detail']}"


def test_catch_proof_flipped_root_pin_fails(tmp_path):
    """Flip ONE hex character of the pinned root -> the handler must fail. This is the direct
    proof that the pin is load-bearing and not decorative."""
    src = VECTORS / "key-order"
    dst = tmp_path / "key-order"
    shutil.copytree(src, dst)
    case = json.loads((dst / "case.json").read_text())
    root = case["expected"]["contentRoot"]
    case["expected"]["contentRoot"] = ("0" if root[0] != "0" else "1") + root[1:]
    res = RC._check_content_root_vector(case, dst)
    assert not res["ok"]
    assert "pinned" in res["detail"]


def test_catch_proof_mutated_jcs_byte_fails(tmp_path):
    """Mutate one byte of the pinned canonical bytes -> byte-identity check must fail."""
    src = VECTORS / "unicode"
    dst = tmp_path / "unicode"
    shutil.copytree(src, dst)
    raw = bytearray((dst / "statement.jcs").read_bytes())
    raw[-2] ^= 0x01
    (dst / "statement.jcs").write_bytes(bytes(raw))
    case = json.loads((dst / "case.json").read_text())
    res = RC._check_content_root_vector(case, dst)
    assert not res["ok"]
    assert "byte-identical" in res["detail"] or "root" in res["detail"]


def test_catch_proof_under_declared_case_fails(tmp_path):
    """Remove a required expectation key -> fail-closed floor must reject, never pass green by
    asserting nothing (the F3 class from the card-logic round: vacuous truth over a silent skip)."""
    src = VECTORS / "negative-alg-confusion"
    dst = tmp_path / "neg"
    shutil.copytree(src, dst)
    case = json.loads((dst / "case.json").read_text())
    del case["expected"]["bindingOk"]
    res = RC._check_content_root_vector(case, dst)
    assert not res["ok"]
    assert "under-declared" in res["detail"]


def test_catch_proof_unknown_mode_fails():
    case = {"caseId": "x", "kind": "content_root_vector", "mode": "does_not_exist", "expected": {"a": 1}}
    res = RC._check_content_root_vector(case, VECTORS / "key-order")
    assert not res["ok"]
    assert "unknown content_root_vector mode" in res["detail"]


def test_property_unknown_top_field_changes_the_root():
    """The reason the unknown-top-field vector exists: silently dropping an unknown Statement
    property would make two DIFFERENT statements share a root."""
    base = json.loads((VECTORS / "key-order" / "case.json").read_text())["expected"]["contentRoot"]
    extended = json.loads((VECTORS / "unknown-top-field" / "case.json").read_text())["expected"]["contentRoot"]
    assert base != extended


def test_property_confusion_rejected_legacy_accepted():
    """The same serialization (json.dumps sort_keys) is REJECTED when offered as jcs-sha256-v1 and
    ACCEPTED when undeclared (named legacy wire) — the declared-algorithm gate, exercised as data."""
    from proofbundle.intoto import _content_root_binding

    neg = (VECTORS / "negative-alg-confusion" / "payload.bytes").read_bytes()
    ok_neg, alg_neg, _ = _content_root_binding(json.loads(neg.decode()), neg)
    assert ok_neg is False and alg_neg == "jcs-sha256-v1"

    leg = (VECTORS / "legacy-absent-verifies" / "payload.bytes").read_bytes()
    ok_leg, alg_leg, _ = _content_root_binding(json.loads(leg.decode()), leg)
    assert ok_leg is True and alg_leg == "legacy-sortkeys-json-v0"


def test_schema_and_fallback_share_one_kind_source():
    """The class fix behind the drift found while adding this kind: the dependency-free fallback
    in cross_format.py used to carry its OWN literal copy of the kind enum and had already drifted
    (relation_statement was missing). The fallback now reads the schema's enum — one source. This
    test pins the property, not the implementation detail: every kind used in the manifest is
    accepted by the fallback validator."""
    spec = importlib.util.spec_from_file_location("_cross_fmt", CONF / "cross_format.py")
    cf = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("_cross_fmt", cf)
    spec.loader.exec_module(cf)
    schema_kinds = json.loads((CONF / "vector_schema.json").read_text())["properties"]["kind"]["enum"]
    for kind in schema_kinds:
        probe = {"caseId": "probe", "kind": kind, "expected": {"pinned": True}}
        errs = cf._structural_validate(probe)
        assert not any("unknown kind" in e for e in errs), (kind, errs)
    errs = cf._structural_validate({"caseId": "probe", "kind": "not-a-kind", "expected": {"a": 1}})
    assert any("unknown kind" in e for e in errs)
