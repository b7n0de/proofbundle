"""A number too long to write in decimal is rendered bounded by every validator and every renderer.

THE CLASS, stated as the violated assumption: *a value that reaches a message can be written in
decimal.* It cannot. CPython caps int->str conversion at 4300 digits (CVE-2020-10735), so a message
that interpolates `10**5000` raises ValueError instead of explaining the refusal, out of a validator
whose contract is "returns a list of errors, never raises". The strict parser refuses such a literal
and the verifiers run the structural budget, so no signed payload carries one; the validators and the
two agent-review renderers take a dict directly and run no budget.

MEASURED ON d5747000, first by the lens (run 8): `render_disclosure_block` and `render_disclosure_line`
raised "Exceeds the limit (4300) for integer string conversion" for `findingsTotal = 10**5000`, a
predicate `validate_agent_review_v02_predicate` accepts, and with the validator taken away for
`assertedBy` and `coverage.status` of that value. Then with the generator below, which puts
`10**5000` and `-10**5000` at every value and `10**5000` as an extra key of every object of thirteen
seed predicates and calls every validator and renderer that takes them: 351 raw raises in 5,411
calls, at 42 source lines of nine modules (agent_review, verifier_block, subject_binding, outcome,
run_ledger, verification_summary, trust_pack, relation_statement, relation), and 9 more at caller
arguments and policy fields (`validate_statement_shape`, `evaluate_time_policy`, the policy form,
`evaluate_relations_policy`, `build_test_result_statement`, `verify_trust_pack`'s `prev_version` and
`prev_root_threshold`). Every message site renders through `budget.render_safe` now, which describes
such an integer as `<int, 16610 bits>` and renders an ordinary value as `repr()` did. The same
generator finds 0. Measured with this file against the source of d5747000: 51 of its 64 cases fail
there. The 13 that pass are the anti-parity pin and the twelve generator cases of
`derive_limitation_codes` and `evaluate_limitation_policy`, which render nothing from the predicate
and stand beside the others as anti-parity.
"""
from __future__ import annotations

import base64
import copy
import json
from pathlib import Path

import pytest

from proofbundle import (agent_review as AR, decision, outcome, relation, relation_statement,
                         run_ledger, trust_pack, verification_summary, verifier_block)
from proofbundle.errors import ProofBundleError

REPO = Path(__file__).resolve().parents[1]
RIESE = 10**5000
H = lambda c: c * 64  # noqa: E731 - a 64-hex digest of one repeated character
T = "2026-09-26T00:00:00Z"


def _conformance(name: str) -> dict:
    return json.loads((REPO / "conformance" / "agent_review" / name / "predicate.json")
                      .read_text(encoding="utf-8"))


def _v02() -> dict:
    return _conformance("agent-review-v02-positive-control-fixcommit-full-sha-is-accepted")


def _v01() -> dict:
    p = _v02()
    del p["limitationCodes"]
    p["subjectContext"].pop("disclosureCoreDigest")
    p["coverage"] = {"status": "COMPLETE", "observedRuns": 1, "expectedRuns": 1, "sources": ["s"],
                     "window": "w", "collectionMethod": "m"}
    return p


def _v03() -> dict:
    return _conformance("agent-review-v03-positive-control-verifier-block-is-accepted")


def _v01_supersession() -> dict:
    p = _v01()
    p["supersession"] = {"supersedes": [{"priorDigest": {"sha256": H("e")}, "reason": "r"}]}
    return p


def _v02_time_claims() -> dict:
    p = _v02()
    p["declaration"]["timeClaims"] = [{"kind": "reviewCompleted", "value": T, "assertedBy": "x",
                                       "assurance": "selfDeclared"}]
    return p


def _v02_strata() -> dict:
    cap = json.loads((REPO / "conformance" / "cap1" / "cap1-positive-control-pv-01-complete-run-catalogued-basis"
                      / "document.json").read_text(encoding="utf-8"))
    p = _v02()
    p["coverage"] = {"status": "COMPLETE", "strata": cap["strata"], "integrity": cap.get("integrity", {}),
                     "absenceAssertions": cap.get("absence_assertions", [])}
    return p


AGENT_REVIEW_SEEDS = {"v0.1": _v01, "v0.2": _v02, "v0.3": _v03, "v0.1 with supersession": _v01_supersession,
                      "v0.2 with time claims": _v02_time_claims, "v0.2 with strata": _v02_strata}


def _agent_review_surfaces() -> dict:
    pol = AR.load_policy()
    return {
        "validate_agent_review_predicate": AR.validate_agent_review_predicate,
        "validate_agent_review_v02_predicate": AR.validate_agent_review_v02_predicate,
        "validate_agent_review_v03_predicate": AR.validate_agent_review_v03_predicate,
        "render_disclosure_block": AR.render_disclosure_block,
        "render_disclosure_line": lambda p: AR.render_disclosure_line(p, receipt_digest="0" * 64, receipt_url="u"),
        "derive_limitation_codes": AR.derive_limitation_codes,
        "evaluate_limitation_policy": lambda p: AR.evaluate_limitation_policy(p, pol),
    }


def _other_seeds() -> dict:
    edge = {"relation": "supersedes", "targetReceiptDigest": {"digestAlgorithm": "jcs-sha256-v1", "digest": H("c")},
            "targetSubjectDigest": {"digestAlgorithm": "jcs-sha256-v1", "digest": H("d")}, "reason": "r",
            "reasonCode": "correction", "declaredAt": T}
    return {
        "decision.validate_decision_predicate": (
            decision.validate_decision_predicate,
            lambda: json.loads((REPO / "examples" / "decision_receipt_deny.json").read_text(encoding="utf-8"))),
        "outcome.validate_outcome_predicate": (
            outcome.validate_outcome_predicate,
            lambda: {"schemaVersion": "0.1.0", "outcomeId": "o", "decisionRef": {"sha256": H("1")},
                     "executor": {"id": "e", "keyId": "k"}, "requestedActionDigest": {"sha256": H("2")},
                     "status": "executed", "performedAt": T, "limitations": ["l"], "policyPurpose": "outcome",
                     "sequence": {"runId": "r", "seq": 1}}),
        "run_ledger.validate_run_ledger_predicate": (
            run_ledger.validate_run_ledger_predicate,
            lambda: {"schemaVersion": "0.1.0", "studyId": "s", "runBudget": 3, "nonClaims": ["n"],
                     "selectedSeq": 1, "runs": [{"seq": 1, "status": "completed",
                                                 "resultDigest": {"sha256": H("1")}, "prevDigest": None}]}),
        "verification_summary.validate_summary_predicate": (
            verification_summary.validate_summary_predicate,
            lambda: {"schemaVersion": "0.1.0", "summaryId": "v", "producedAt": T, "nonClaims": ["n"],
                     "producer": {"id": "p"},
                     "levels": [{"kind": "decision", "receiptRef": {"sha256": H("8")}, "status": "VERIFIED",
                                 "evidenceClass": "decision_claim", "checks": ["c"]}]}),
        "trust_pack.validate_trust_pack_predicate": (
            trust_pack.validate_trust_pack_predicate,
            lambda: {"schemaVersion": "0.1.0", "trustPackId": "t", "version": 1,
                     "expires": "2099-01-01T00:00:00Z", "prevVersionDigest": None,
                     "roles": {"root": {"keyIds": ["k1"], "threshold": 1}},
                     "keys": {"k1": {"publicKey": base64.b64encode(b"\x01" * 32).decode()}},
                     "nonClaims": ["n"], "revoked": []}),
        "relation_statement.validate_relation_statement_predicate": (
            relation_statement.validate_relation_statement_predicate,
            lambda: {"schemaVersion": "0.1.0", "statementId": "s", "relationships": [copy.deepcopy(edge)]}),
        "verifier_block.validate_verifier_block": (
            verifier_block.validate_verifier_block, lambda: _v03()["producer"]["verifier"]),
    }


def _paths(o, pfad=()):
    yield pfad
    if isinstance(o, dict):
        for k, v in o.items():
            yield from _paths(v, pfad + (k,))
    elif isinstance(o, list):
        for i, v in enumerate(o):
            yield from _paths(v, pfad + (i,))


def _mutants(seed: dict):
    """`10**5000` and `-10**5000` at every value, and `10**5000` as an extra key of every object."""
    for pfad in list(_paths(seed)):
        for wert in (RIESE, -RIESE):
            m = copy.deepcopy(seed)
            if not pfad:
                m = wert
            else:
                ziel = m
                for k in pfad[:-1]:
                    ziel = ziel[k]
                ziel[pfad[-1]] = wert
            yield m
        ziel = seed
        for k in pfad:
            ziel = ziel[k]
        if isinstance(ziel, dict):
            m = copy.deepcopy(seed)
            ziel = m
            for k in pfad:
                ziel = ziel[k]
            ziel[RIESE] = 1
            yield m


def _raw_raises(fn, seed: dict) -> tuple[int, list]:
    calls, roh = 0, []
    for m in _mutants(seed):
        calls += 1
        try:
            fn(m)
        except ProofBundleError:
            pass
        except Exception as exc:  # noqa: BLE001 - the finding is the exception that is not the package's
            roh.append(f"{type(exc).__name__}: {str(exc)[:60]}")
    return calls, roh


# ── the generator, one case per surface and seed ─────────────────────────────────────────────
@pytest.mark.parametrize("seed", sorted(AGENT_REVIEW_SEEDS))
@pytest.mark.parametrize("surface", sorted(_agent_review_surfaces()))
def test_every_agent_review_validator_and_renderer_renders_a_huge_number_bounded(surface, seed):
    calls, roh = _raw_raises(_agent_review_surfaces()[surface], AGENT_REVIEW_SEEDS[seed]())
    assert calls > 50, "the generator reached nothing"
    assert roh == [], roh[:5]


@pytest.mark.parametrize("surface", sorted(_other_seeds()))
def test_every_other_validator_renders_a_huge_number_bounded(surface):
    fn, seed = _other_seeds()[surface]
    calls, roh = _raw_raises(fn, seed())
    assert calls > 20, "the generator reached nothing"
    assert roh == [], roh[:5]


# ── the lens's reproduction, and what the renderers now say ─────────────────────────────────
def test_a_valid_predicate_with_a_huge_findings_total_renders():
    """`findingsTotal = 10**5000` is valid (a non-negative integer, not below the list, with the
    unlisted findings named as a known gap). Both renderers answer and name the count bounded."""
    p = _v02()
    p["declaration"]["findingsTotal"] = RIESE
    assert AR.validate_agent_review_v02_predicate(p) == []
    n = len(p["declaration"]["findings"])
    block = AR.render_disclosure_block(p)
    line = AR.render_disclosure_line(p, receipt_digest="0" * 64, receipt_url="u")
    assert f"{n} listed of <int, 16610 bits> recorded" in block
    assert f"{n} listed of <int, 16610 bits> recorded findings" in line


@pytest.mark.parametrize("feld", ["assertedBy", "coverage.status", "findingsTotal"])
def test_the_renderers_read_a_huge_number_where_a_string_or_a_count_belongs(feld, monkeypatch):
    """With the validator in front taken away: `assertedBy` and `coverage.status` must be strings, so
    a number there is unreadable and read as absent; a count is rendered bounded."""
    monkeypatch.setattr(AR, "require_valid_agent_review_predicate_any", lambda *_a, **_k: None)
    p = _v02()
    if feld == "assertedBy":
        for eintrag in p["declaration"]["authoring"]:
            eintrag["assertedBy"] = RIESE
    elif feld == "coverage.status":
        p["coverage"]["status"] = RIESE
    else:
        p["declaration"]["findingsTotal"] = RIESE
    block = AR.render_disclosure_block(p)
    AR.render_disclosure_line(p, receipt_digest="0" * 64, receipt_url="u")
    erwartet = {"assertedBy": "- **Involvement:** not stated\n", "coverage.status": "coverage UNKNOWN\n",
                "findingsTotal": "<int, 16610 bits> recorded"}[feld]
    assert erwartet in block, block


def test_a_boolean_findings_total_is_no_count(monkeypatch):
    """`true` is an int in Python and no count; beside an empty list it was rendered "0 listed of
    True recorded"."""
    monkeypatch.setattr(AR, "require_valid_agent_review_predicate_any", lambda *_a, **_k: None)
    p = _v02()
    p["declaration"]["findings"] = []
    p["declaration"]["findingsTotal"] = True
    assert "- **Findings:** 0 total (" in AR.render_disclosure_block(p)
    assert "- 0 findings" not in AR.render_disclosure_line(p, receipt_digest="0" * 64, receipt_url="u")
    assert " · 0 findings · " in AR.render_disclosure_line(p, receipt_digest="0" * 64, receipt_url="u")


# ── caller arguments and policy fields the seeds do not reach ──────────────────────────────
def _single_cases() -> dict:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: PLC0415
    sk = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
    tp = {"schemaVersion": "0.1.0", "trustPackId": "t", "version": 1, "expires": "2099-01-01T00:00:00Z",
          "prevVersionDigest": None, "roles": {"root": {"keyIds": ["k1"], "threshold": 1}},
          "keys": {"k1": {"publicKey": base64.b64encode(sk.public_key().public_bytes_raw()).decode()}},
          "nonClaims": ["n"]}
    env = trust_pack.sign_trust_pack(tp, {"k1": sk})
    return {
        "agent_review.validate_statement_shape _type": lambda: AR.validate_statement_shape(
            {"_type": RIESE, "subject": [{"name": "x", "digest": {"sha256": H("0")}}]}, None),
        "agent_review.validate_statement_shape extra key": lambda: AR.validate_statement_shape(
            {"_type": AR.INTOTO_STATEMENT_TYPE, "subject": [{"name": "x", "digest": {"sha256": H("0")}}],
             RIESE: 1}, None),
        "agent_review.evaluate_time_policy kind": lambda: AR.evaluate_time_policy({}, {"kind": RIESE}),
        "agent_review.evaluate_limitation_policy policy.time": lambda: AR.evaluate_limitation_policy(
            {}, {"time": RIESE}),
        "relation.evaluate_relations_policy resolution": lambda: relation.evaluate_relations_policy(
            {"require_relation_resolution": ["supersedes"]},
            {"edges": [{"relation": "supersedes", "resolution": RIESE}]}, successor_key_b64=None),
        "relation.evaluate_relations_policy targetDigest": lambda: relation.evaluate_relations_policy(
            {"require_relation_target": {"supersedes": [H("a")]}},
            {"edges": [{"relation": "supersedes", "resolution": "VERIFIED", "targetDigest": RIESE}]},
            successor_key_b64=None),
        "verifier_block.build_test_result_statement results": lambda: verifier_block.build_test_result_statement(
            build={"digest": {"sha256": H("1")}, "source": "source-tree"},
            vector_set={"name": "n", "digest": {"sha256": H("2")}, "cases": 1}, results=[RIESE],
            version="6.1.0"),
        "trust_pack.verify_trust_pack prev_version": lambda: trust_pack.verify_trust_pack(env, prev_version=RIESE),
        "trust_pack.verify_trust_pack prev_root_threshold": lambda: trust_pack.verify_trust_pack(
            env, prev_root_keys={}, prev_root_threshold=RIESE),
    }


@pytest.mark.parametrize("name", sorted(_single_cases()))
def test_a_huge_number_in_a_caller_argument_or_a_policy_field_is_rendered_bounded(name):
    """Each answers with its verdict or its module's typed error, never a raw ValueError."""
    try:
        _single_cases()[name]()
    except ProofBundleError:
        pass


# ── anti-parity: an ordinary value renders as it always did ───────────────────────────────
def test_an_ordinary_value_renders_byte_identically():
    """The pins below held on d5747000 too: `render_safe` is `repr()` for a short string, a small int
    and a short tuple, and `str()` with `quote=False`."""
    p = _v01()
    p["sneaky"] = 1
    p["coverage"]["observedRuns"] = -3
    fehler = AR.validate_agent_review_predicate(p)
    assert "unknown field 'sneaky' (additionalProperties:false)" in fehler
    assert any(str(e).startswith("coverage: observedRuns must not be negative, got -3 ") for e in fehler)
    oc = outcome.validate_outcome_predicate({"status": "done", "executor": {"id": "e", "extra": 1}})
    assert "status must be one of ['executed', 'failed', 'partial', 'refused'], got 'done'" in oc
    assert "executor.extra is not an allowed field" in oc
    tp = trust_pack.validate_trust_pack_predicate({"keys": {"k1": {"publicKey": "AA==", "bogus": 1}}})
    assert "keys['k1'].bogus is not an allowed field" in tp
