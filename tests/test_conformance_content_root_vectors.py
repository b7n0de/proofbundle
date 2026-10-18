"""The action-chain content-root vectors (Phase 1 / R51) — and the proof that their gate bites.

Three layers, mirroring the corpus rules:

1. every `content_root_vector` case in the manifest passes against the real primitive;
2. CATCH PROOF (a gate that never fires is indistinguishable from a broken gate): a tampered
   copy of a case — one flipped hex character in the pinned root, one mutated payload byte,
   an under-declared expected block — must FAIL the same handler;
3. the properties the vectors exist for hold across cases: an unknown top-level field CHANGES
   the root (silent dropping would collide two different statements), and the algorithm-confusion
   payload is rejected while the same sort-keys body, declared as the named legacy algorithm,
   verifies (the two payloads differ only in their `contentRootAlg` field).

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
    assert len(cases) >= 10, f"expected >= 10 content_root_vector cases, found {len(cases)}"
    modes = {c.get("mode") for _, c, _ in cases}
    assert modes == {"canonical", "pair_reference", "binding", "envelope_invariance"}, modes


def test_every_vector_passes_against_the_real_primitive():
    """Its own floor, since a loop over no case passes: measured on main 570dd164 on 2026-10-18, where
    the kind does not exist, this test passed while every other test of this file failed."""
    cases = _cases()
    assert len(cases) >= 10, f"expected >= 10 content_root_vector cases, found {len(cases)}"
    for rel, case, case_dir in cases:
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


# ─────────── Iteration-2 catch proofs (the deep-gate lens findings, each now bites) ───────────

def test_catch_proof_bare_predicate_fails(tmp_path):
    """Lens-2 P2: a bare predicate (no _type/subject/predicateType) passed green in iteration 1 —
    this vector kind pins STATEMENT roots, so the full-Statement shape guard is now mandatory
    (ADR 0002 §2). The handler either fails the case or raises (the runner's per-case try maps a
    raise to a per-case FAIL — both are a caught defect, never a green)."""
    import hashlib

    from proofbundle.canonical import canonicalize_statement
    from proofbundle.errors import ProofBundleError

    d = tmp_path / "bare"
    d.mkdir()
    bare = {"verdict": "ALLOW", "decidedAt": "2026-08-24T00:00:00Z"}
    jcs = canonicalize_statement(bare)   # deliberately WITHOUT the shape guard: build the fixture
    (d / "statement.json").write_text(json.dumps(bare), encoding="utf-8")
    (d / "statement.jcs").write_bytes(jcs)
    case = {"caseId": "probe-bare", "kind": "content_root_vector", "mode": "canonical",
            "input": "statement.json",
            "expected": {"jcsFile": "statement.jcs",
                         "contentRoot": hashlib.sha256(jcs).hexdigest(),
                         "objectAndBytesAgree": True}}
    try:
        res = RC._check_content_root_vector(case, d)
        assert not res["ok"], "bare predicate must never pass as a statement content-root vector"
    except ProofBundleError as exc:
        assert "Statement" in str(exc)


def test_catch_proof_binding_payload_that_is_no_statement_fails(tmp_path):
    """Codex 4305349124 on 96564b19: the binding mode called the binding gate without the
    full-Statement guard of the canonical and pair modes, so a payload `{}` with bindingOk true
    under the legacy algorithm passed green with scope FULL. Measured there, it does not now."""
    d = tmp_path / "binding"
    d.mkdir()
    (d / "payload.bytes").write_bytes(b"{}")
    case = {"caseId": "probe-binding-not-a-statement", "kind": "content_root_vector", "mode": "binding",
            "expected": {"bindingOk": True, "alg": "legacy-sortkeys-json-v0"}}
    res = RC._check_content_root_vector(case, d)
    assert not res["ok"], res
    assert "no in-toto Statement" in res["detail"], res


def test_catch_proof_envelope_payload_that_is_no_statement_fails(tmp_path):
    """Codex 4305349124, the sibling: two envelopes carrying the same arbitrary bytes under
    different signature blocks passed the envelope mode green with the SHA-256 of those bytes as
    the pin. The payload is read strictly and must be a full Statement now."""
    import base64
    import hashlib

    d = tmp_path / "envelope"
    d.mkdir()
    roh = b"not a statement at all"
    for name, sig in (("envelope_a.json", "AA"), ("envelope_b.json", "BB")):
        (d / name).write_text(json.dumps({"payload": base64.b64encode(roh).decode(), "payloadType": "x",
                                          "signatures": [{"sig": sig}]}), encoding="utf-8")
    case = {"caseId": "probe-envelope-not-a-statement", "kind": "content_root_vector",
            "mode": "envelope_invariance",
            "expected": {"contentRoot": hashlib.sha256(roh).hexdigest(), "secondEnvelope": "envelope_b.json"}}
    res = RC._check_content_root_vector(case, d)
    assert not res["ok"], res
    assert "no in-toto Statement" in res["detail"], res


def test_catch_proof_nonbinding_pair_fails(tmp_path):
    """Lens-2 P1: a pair case declaring evidenceRefBindsRoot:false passed green with a detail line
    CLAIMING a binding. The binding is now an unconditional floor: a false declaration fails, and
    a pair whose decision does NOT bind the evidence root fails even when everything else is
    consistent."""
    import hashlib

    from proofbundle.canonical import canonicalize_statement

    src = VECTORS / "cross-predicate-ref"
    d = tmp_path / "pair"
    shutil.copytree(src, d)
    case = json.loads((d / "case.json").read_text())

    # (a) the switch-off itself fails
    case_false = json.loads(json.dumps(case))
    case_false["expected"]["evidenceRefBindsRoot"] = False
    res = RC._check_content_root_vector(case_false, d)
    assert not res["ok"] and "literally true" in res["detail"]

    # (b) a consistent-but-non-binding pair fails on the unconditional floor
    dec = json.loads((d / "decision.json").read_text())
    dec["predicate"]["evidenceRefs"][0]["digest"]["sha256"] = "de" * 32
    jcs = canonicalize_statement(dec, require_statement_shape=True)
    (d / "decision.json").write_text(json.dumps(dec), encoding="utf-8")
    (d / "decision.jcs").write_bytes(jcs)
    case_nb = json.loads(json.dumps(case))
    case_nb["expected"]["decisionRoot"] = hashlib.sha256(jcs).hexdigest()
    res = RC._check_content_root_vector(case_nb, d)
    assert not res["ok"]
    assert "does not bind" in res["detail"]


def test_catch_proof_string_false_is_not_a_boolean(tmp_path):
    """Lens-3 F5: bool("false") is True — a JSON-string expectation must never satisfy a boolean
    axis. All three boolean axes now demand real booleans (canonical/pair: literally true)."""
    src = VECTORS / "key-order"
    d = tmp_path / "ko"
    shutil.copytree(src, d)
    case = json.loads((d / "case.json").read_text())
    case["expected"]["objectAndBytesAgree"] = "false"
    res = RC._check_content_root_vector(case, d)
    assert not res["ok"] and "literally true" in res["detail"]

    src_b = VECTORS / "negative-alg-confusion"
    db = tmp_path / "neg"
    shutil.copytree(src_b, db)
    case_b = json.loads((db / "case.json").read_text())
    case_b["expected"]["bindingOk"] = "false"
    res_b = RC._check_content_root_vector(case_b, db)
    assert not res_b["ok"] and "JSON boolean" in res_b["detail"]


def test_property_utf16_order_vector_discriminates():
    """Lens-2 F3c gap: no vector exercised RFC 8785 §3.2.3's actual hard part (UTF-16 code-unit
    ordering). The iteration-2 vector pins it: the astral key (U+1F512) precedes the BMP key
    (U+FF00) in the canonical bytes — code-point or UTF-8-byte ordering would reverse them."""
    d = VECTORS / "utf16-order"
    jcs = (d / "statement.jcs").read_bytes()
    i_astral = jcs.find("\U0001F512key".encode())
    i_bmp = jcs.find("＀key".encode())
    assert i_astral != -1 and i_bmp != -1
    assert i_astral < i_bmp, "UTF-16 code-unit order puts the astral key first; anything else diverges"
    # Python's own order is by code point, the reverse: a canonicalizer that sorted with it would fail here.
    assert sorted(["\U0001F512key", "＀key"])[0] == "＀key"


def test_property_receipt_root_delegates_to_the_one_canonicalizer(monkeypatch):
    """Lens-2 F3a-2: anchors.receipt_canonical_root was a second inline rfc8785+budget copy (the
    duplication had already cost a double fix). It now routes through canonical.canonicalize_statement
    — measured by a call-spy, and the output stays byte-stable."""
    import hashlib

    from proofbundle import anchors, canonical

    calls = []
    echt = canonical.canonicalize_statement

    def spion(obj, **kw):
        calls.append(1)
        return echt(obj, **kw)

    monkeypatch.setattr(canonical, "canonicalize_statement", spion)
    bundle = {"schema": "probe", "n": 1.0, "u": "ü"}
    root = anchors.receipt_canonical_root(bundle)
    assert calls, "receipt_canonical_root no longer delegates to the one canonicalizer"
    assert root == hashlib.sha256(echt(bundle)).digest()


def test_schema_and_fallback_share_one_kind_source():
    """The kinds of a case stand in `common_vocabulary.CASE_KINDS`, which the runner and the
    dependency-free fallback in cross_format.py read (tests/test_korpus_arten_haben_eine_quelle.py).
    The enum of vector_schema.json is a third list of the same kinds. In August the fallback carried
    its own copy and had drifted; main fixed that by the vocabulary. This pins the schema to the same
    set, so a kind added to one and not the other fails here, and the fallback accepts every kind the
    schema names and refuses one it does not."""
    sys.path.insert(0, str(CONF))
    from common_vocabulary import CASE_KINDS
    spec = importlib.util.spec_from_file_location("_cross_fmt", CONF / "cross_format.py")
    cf = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("_cross_fmt", cf)
    spec.loader.exec_module(cf)
    schema_kinds = json.loads((CONF / "vector_schema.json").read_text())["properties"]["kind"]["enum"]
    assert set(schema_kinds) == set(CASE_KINDS), (sorted(set(schema_kinds) ^ set(CASE_KINDS)))
    assert "content_root_vector" in CASE_KINDS
    for kind in schema_kinds:
        probe = {"caseId": "probe", "kind": kind, "expected": {"pinned": True}}
        errs = cf._structural_validate(probe)
        assert not any("unknown kind" in e for e in errs), (kind, errs)
    errs = cf._structural_validate({"caseId": "probe", "kind": "not-a-kind", "expected": {"a": 1}})
    assert any("unknown kind" in e for e in errs)
