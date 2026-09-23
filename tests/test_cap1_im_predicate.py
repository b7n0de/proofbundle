"""CAP-1 part B, block 2: the coverage of an agent-review/v0.2 predicate in the language of
draft-hillier-coverage-attestation-00 — checked with the rules from `proofbundle.cap1`, measured
against the author's fifteen vectors (Certisyn-Inc/certisyn-drafts, commit 0980d32), not against
self-built fixtures.

Every rule gets its own reason code in the predicate (`COVERAGE_CAP1_*`); the status is DERIVED from
`integrity.complete`, and a status set in contradiction to it fails. v0.1 does not know the three
fields and rejects them as unknown. Three planted defects (the build plan's gate meta-test) have to
go red: complete=true beside a failed unit, an alias without an expiry note in COMPATIBILITY.md, and
a document with a duplicate name.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from proofbundle import agent_review as ar
from proofbundle import cap1
from proofbundle._strict_json import loads_strict
from proofbundle.errors import BundleFormatError

REPO = Path(__file__).resolve().parents[1]
KORPUS = REPO / "conformance" / "agent_review"
VEKTOREN = REPO / "conformance" / "cap1" / "vectors"
SK = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
PK = SK.public_key().public_bytes_raw()

#: Rule id -> qualified code in the predicate. The mapping is built in `_cap1_abdeckung` as a chain
#: of literals; this mirror checks that it is COMPLETE (every rule from cap1.RULES).
CODE_JE_REGEL = {
    "R0-shape": "COVERAGE_CAP1_SHAPE",
    "R1-no-silent-remainder": "COVERAGE_CAP1_SILENT_REMAINDER",
    "R2-closed-disposition": "COVERAGE_CAP1_DISPOSITION_NOT_CLOSED",
    "R3-withholding-digest-bound": "COVERAGE_CAP1_WITHHELD_WITHOUT_DIGEST",
    "R4-denominator-basis": "COVERAGE_CAP1_BASIS_MISSING",
    "R5-counts-well-formed": "COVERAGE_CAP1_COUNTS_MALFORMED",
    "R6-absence-is-scoped": "COVERAGE_CAP1_ABSENCE_UNSCOPED",
    "R7-incomplete-not-clean": "COVERAGE_CAP1_INCOMPLETE_CLAIMED_CLEAN",
    "R8-supports-bounds-citation": "COVERAGE_CAP1_SUPPORTS_MISSING",
}


def _v02() -> dict:
    return json.loads((KORPUS / "agent-review-v02-positive-control-default-policy-decides-accept"
                       / "predicate.json").read_text(encoding="utf-8"))


def _vektor(vid: str) -> dict:
    return json.loads((VEKTOREN / f"{vid}.json").read_text(encoding="utf-8"))


def _erwartung() -> dict:
    """The EXACT rule set per vector from the author's recorded run — the same source as
    tests/test_cap1_regeln.py (`results[].rules`)."""
    lauf = json.loads((VEKTOREN / "_author_conformance_run.json").read_text(encoding="utf-8"))
    return {r["id"]: set(r.get("rules") or []) for r in lauf["results"]}


def _mit_cap1(vid: str, *, status: str | None = None) -> dict:
    """A real v0.2 predicate whose coverage carries the CAP-1 vector."""
    v = _vektor(vid)
    p = copy.deepcopy(_v02())
    integ = v.get("integrity") if isinstance(v.get("integrity"), dict) else {}
    abgeleitet = "COMPLETE" if integ.get("complete") is True else "PARTIAL"
    cov: dict = {"status": status or abgeleitet}
    if "strata" in v:
        cov["strata"] = v["strata"]
    if "integrity" in v:
        cov["integrity"] = v["integrity"]
    if "absence_assertions" in v:
        cov["absenceAssertions"] = v["absence_assertions"]
    p["coverage"] = cov
    p["limitationCodes"] = ar.derive_limitation_codes(p)
    return p


def _codes(errs) -> set[str]:
    return {getattr(e, "code", None) for e in errs} - {None}


# ── the mapping is complete ────────────────────────────────────────────────────────────────────────

def test_jede_regel_aus_cap1_hat_ihren_code_im_predicate():
    assert set(CODE_JE_REGEL) == set(cap1.RULE_IDS), (
        "cap1.RULES and the literal chain in _cap1_abdeckung have drifted apart: a rule without its "
        "own code would be reported as CAP1_RULE_UNMAPPED — not lost, but unnamed")


def test_eine_unbekannte_regel_wird_gemeldet_nicht_verschluckt(monkeypatch):
    def _r99(doc, f):
        f("R99-erfunden", "a rule the mapping does not know")
    monkeypatch.setitem(cap1.RULES, "R99-erfunden", _r99)
    errs = ar.validate_agent_review_v02_predicate(_mit_cap1("PV-01"))
    assert "COVERAGE_CAP1_RULE_UNMAPPED" in _codes(errs), _codes(errs)


# ── the author's vectors inside the predicate ──────────────────────────────────────────────────────

@pytest.mark.parametrize("vid", ["PV-01", "PV-02", "PV-03", "PV-04", "PV-05"])
def test_positive_vektoren_sind_im_predicate_gueltig(vid):
    errs = ar.validate_agent_review_v02_predicate(_mit_cap1(vid))
    assert errs == [], errs


@pytest.mark.parametrize("vid", [f"NC-{i:02d}" for i in range(1, 11)])
def test_negative_vektoren_tragen_genau_die_codes_ihrer_regeln(vid):
    erwartet = {CODE_JE_REGEL[r] for r in _erwartung()[vid]}
    assert erwartet, f"{vid}: the author's run names no rule — then the vector is no counter-proof"
    codes = _codes(ar.validate_agent_review_v02_predicate(_mit_cap1(vid)))
    cap1_codes = {c for c in codes if c.startswith("COVERAGE_CAP1_") and c != "COVERAGE_CAP1_STATUS_CONTRADICTS_STRATA"}
    assert cap1_codes == erwartet, f"{vid}: {cap1_codes} != {erwartet}"


def test_der_status_wird_abgeleitet_und_ein_widerspruch_faellt():
    p = _mit_cap1("PV-01", status="PARTIAL")  # PV-01 is complete=true -> COMPLETE
    codes = _codes(ar.validate_agent_review_v02_predicate(p))
    assert "COVERAGE_CAP1_STATUS_CONTRADICTS_STRATA" in codes, codes
    assert ar.validate_agent_review_v02_predicate(_mit_cap1("PV-01", status="COMPLETE")) == []


def test_ein_unbekannter_status_bleibt_eine_legacy_meldung_kein_widerspruch():
    p = _mit_cap1("PV-01", status="VIELLEICHT")
    errs = ar.validate_agent_review_v02_predicate(p)
    assert any("status must be one of" in str(e) for e in errs), errs
    assert "COVERAGE_CAP1_STATUS_CONTRADICTS_STRATA" not in _codes(errs)


# ── v0.1 does not know the fields ──────────────────────────────────────────────────────────────────

def test_v01_weist_die_drei_felder_als_unbekannt_ab():
    p = _mit_cap1("PV-01")
    errs = ar.validate_agent_review_predicate(p)
    unbekannt = {e for e in errs if "unknown field" in str(e)}
    assert any("'strata'" in str(e) for e in unbekannt), errs
    assert any("'integrity'" in str(e) for e in unbekannt), errs
    assert any("'absenceAssertions'" in str(e) for e in unbekannt), errs
    assert not {c for c in _codes(errs) if c.startswith("COVERAGE_CAP1_")}, "v0.1 runs no CAP-1 rules"


# ── end to end: issue, read, policy ────────────────────────────────────────────────────────────────

def test_ein_receipt_mit_strata_wird_ausgestellt_und_gelesen():
    p = _mit_cap1("PV-01")
    env = ar.emit_agent_review(p, SK)
    r = ar.verify_agent_review_v02(env, PK, expected_subject_digest=ar._subject_digest(p),
                                   policy=ar.load_policy())
    assert r["ok"] is True, r["errors"][:3]
    assert r["policy_decision"] == "accept"
    assert "COVERAGE_LEGACY_FIELDS" not in (r.get("advisory_codes") or [])
    assert "COVERAGE_PARTIAL" not in p["limitationCodes"], "PV-01 is COMPLETE"


def test_ein_receipt_ohne_strata_traegt_den_hinweiscode_und_bleibt_gueltig():
    p = _v02()
    env = ar.emit_agent_review(p, SK)
    r = ar.verify_agent_review_v02(env, PK, expected_subject_digest=ar._subject_digest(p),
                                   policy=ar.load_policy())
    assert r["ok"] is True, r["errors"][:3]
    assert "COVERAGE_LEGACY_FIELDS" in r["advisory_codes"]
    assert "COVERAGE_LEGACY_FIELDS" not in (r.get("reason_codes") or []), "advisory is not a reason"


def test_partial_mit_strata_leitet_coverage_partial_ab():
    """MEASURED across the five positive vectors: only PV-03 carries complete=false (capped_to
    'indeterminate'); the first version of this test assumed PV-02 and failed — an assumption about
    a fixture is not a measurement."""
    p = _mit_cap1("PV-03")
    assert p["coverage"]["integrity"]["complete"] is False
    assert p["coverage"]["status"] == "PARTIAL", p["coverage"]["integrity"]
    assert "COVERAGE_PARTIAL" in ar.derive_limitation_codes(p)
    assert ar.validate_agent_review_v02_predicate(p) == []


# ── gate meta-test: the build plan's three planted defects ─────────────────────────────────────────

def test_gate_meta_1_complete_neben_einer_failed_einheit_wird_rot():
    p = _mit_cap1("PV-01")
    s0 = p["coverage"]["strata"][0]
    s0["unexamined"] = list(s0.get("unexamined") or []) + [{"unit": "planted-defect", "disposition": "failed"}]
    s0["eligible"] = int(s0["eligible"]) + 1
    p["coverage"]["integrity"]["complete"] = True
    p["coverage"]["status"] = "COMPLETE"
    codes = _codes(ar.validate_agent_review_v02_predicate(p))
    assert "COVERAGE_CAP1_INCOMPLETE_CLAIMED_CLEAN" in codes, codes


def test_gate_meta_2_jeder_alias_traegt_seinen_verfallsvermerk():
    text = (REPO / "COMPATIBILITY.md").read_text(encoding="utf-8")
    absatz = text[text.index("Coverage aliases"):]
    for feld in ("observedRuns", "expectedRuns", "knownGaps", "collectionMethod"):
        assert f"`{feld}`" in absatz, f"{feld} is missing from the alias paragraph of COMPATIBILITY.md"
    assert "next MAJOR" in absatz, "the expiry names no boundary"


def test_gate_meta_3_ein_dokument_mit_doppeltem_namen_wird_vom_leser_abgewiesen():
    p = _mit_cap1("PV-01")
    roh = json.dumps(p)
    doppelt = roh.replace('"status": "COMPLETE"', '"status": "COMPLETE", "status": "PARTIAL"', 1)
    assert doppelt != roh, "the planting did not change the text"
    assert json.loads(doppelt)["coverage"]["status"] == "PARTIAL", "control: the standard reader takes the LAST value"
    with pytest.raises(BundleFormatError):
        loads_strict(doppelt)
    with pytest.raises(BundleFormatError):
        cap1.load_cap1_document(doppelt)


# ── the fuzz guard sees the new surface ────────────────────────────────────────────────────────────

@pytest.mark.parametrize("kaputt", [None, 42, "strata", [], [42], [{"id": 3}], {"a": 1}])
def test_kaputte_strata_werden_beurteilt_nicht_geworfen(kaputt):
    p = copy.deepcopy(_v02())
    p["coverage"] = {"status": "PARTIAL", "knownGaps": ["x"], "strata": kaputt}
    errs = ar.validate_agent_review_v02_predicate(p)
    assert errs, "broken strata have to carry a message"
    assert "COVERAGE_CAP1_SHAPE" in _codes(errs), _codes(errs)
