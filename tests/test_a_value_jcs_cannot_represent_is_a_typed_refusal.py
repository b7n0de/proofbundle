"""A value RFC 8785 cannot represent is a typed refusal, never a defect of the verifier.

THE CLASS, stated as the violated assumption: *what the strict parser admits, the canonicalizer can
represent.* It cannot. `loads_strict` reads an integer outside +-(2**53 - 1), NaN and Infinity, and
`rfc8785.dumps` refuses each with IntegerDomainError or FloatDomainError, both ValueError. The
in-toto verifiers and `anchors.receipt_canonical_root` already mapped that refusal to their own
typed answer; the agent-review module and seven other wrappers of the canonicalizer did not.

MEASURED ON 8ecb6edf (lens run 7, then a sweep that signs a statement with one such value at every
node of a seed predicate and calls every public surface): a correctly signed agent-review receipt
(v0.1, v0.2, v0.3) with `2**53` in a finding or in `subjectContext` made `verify_agent_review`,
`verify_agent_review_v02`, `verify_agent_review_v03` and `verify_agent_review_any` answer
`reason_code=internal_error`, "a defect in the verifier"; `emit_agent_review` raised the bare
IntegerDomainError for `subjectContext.humanRef = 2**53` after the validator had passed the
predicate; `subject_binding.classify_subject`, `require_derived_subject` and
`derive_subject_digest`, `verifier_block.join_test_result` and `test_result_ref`, and the decision,
outcome and run ledger emitters raised it too. The sweep found 29 distinct findings in 22,590 calls
there and 4 after the fix, all four at the two primitives of `canonical`, which pass the refusal on
by their documented contract. Measured with this file against the source of 8ecb6edf: 119 of its 122
cases fail there. The three that pass are the anti-parity case, the premise about the strict parser,
and the inventory of call sites, which reads the source of the tree it sits in.
"""
from __future__ import annotations

import ast
import copy
import json
import math
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from proofbundle import agent_review as AR
from proofbundle import dsse

REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "src" / "proofbundle"
SK = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
PK = SK.public_key().public_bytes_raw()

#: What the strict parser admits and RFC 8785 refuses.
OUTSIDE_JCS = [2**53, -(2**53) - 5, float("nan"), float("inf")]


def _conformance(name: str) -> dict:
    return json.loads((REPO / "conformance" / "agent_review" / name / "predicate.json")
                      .read_text(encoding="utf-8"))


def _v02() -> dict:
    return _conformance("agent-review-v02-positive-control-fixcommit-full-sha-is-accepted")


def _v03() -> dict:
    p = _conformance("agent-review-v03-positive-control-verifier-block-is-accepted")
    fuer = _v02()["declaration"]
    p["declaration"]["findings"] = copy.deepcopy(fuer["findings"])
    p["declaration"]["findingsRoot"] = fuer["findingsRoot"]
    p["declaration"]["findingsTotal"] = len(fuer["findings"])
    return p


def _v01() -> dict:
    p = _v02()
    del p["limitationCodes"]
    p["subjectContext"].pop("disclosureCoreDigest")
    return p


VERSIONS = {
    "v0.1": (_v01, AR.AGENT_REVIEW_PREDICATE_TYPE, AR.verify_agent_review),
    "v0.2": (_v02, AR.AGENT_REVIEW_PREDICATE_TYPE_V02, AR.verify_agent_review_v02),
    "v0.3": (_v03, AR.AGENT_REVIEW_PREDICATE_TYPE_V03, AR.verify_agent_review_v03),
}

#: The nodes the lens named: a finding, a string in a finding, and two strings of `subjectContext`,
#: one the validator types (`forge`) and one it does not (`humanRef`).
PATHS = [("declaration", "findings", 0), ("declaration", "findings", 0, "id"),
         ("subjectContext", "forge"), ("subjectContext", "humanRef")]


def _set(p: dict, pfad: tuple, wert) -> dict:
    ziel = p
    for k in pfad[:-1]:
        ziel = ziel[k]
    ziel[pfad[-1]] = wert
    return p


def _signed_as_sent(predicate: dict, predicate_type: str) -> dict:
    """Signed over the bytes a producer would send: JCS cannot write them, so plain JSON does, and
    the verifier reads exactly those bytes. The subject names the predicate's own subject, so the
    statement's shape holds and the verifier reaches its binding code."""
    st = {"_type": AR.STATEMENT_TYPE,
          "subject": [{"name": AR._subject_name(predicate), "digest": {"sha256": "0" * 64}}],
          "predicateType": predicate_type, "predicate": predicate}
    body = json.dumps(st, sort_keys=True, separators=(",", ":")).encode()
    return dsse.sign_envelope(body, SK, payload_type=AR.INTOTO_STATEMENT_PAYLOAD_TYPE)


def _no_internal_error(r: dict) -> None:
    assert r["reason_code"] != "internal_error", r["errors"]
    assert "internal_error" not in r["reason_codes"], r["errors"]
    assert not any("defect in the verifier" in str(e) for e in r["errors"]), r["errors"]


# ── the verifiers ─────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("version", sorted(VERSIONS))
@pytest.mark.parametrize("through_any", [False, True], ids=["direct", "any"])
@pytest.mark.parametrize("pfad", PATHS, ids=lambda p: ".".join(map(str, p)))
@pytest.mark.parametrize("wert", OUTSIDE_JCS, ids=repr)
def test_a_signed_receipt_with_such_a_value_is_refused_by_type(version, through_any, pfad, wert):
    """The signature verifies, the receipt is refused, and the reason is a code about the receipt:
    STATEMENT_NOT_CANONICALIZABLE. At 8ecb6edf all 96 of these calls answered `internal_error`."""
    bauen, typ, verify = VERSIONS[version]
    env = _signed_as_sent(_set(bauen(), pfad, wert), typ)
    r = AR.verify_agent_review_any(env, PK) if through_any else verify(env, PK)
    _no_internal_error(r)
    assert r["crypto_ok"] is True and r["ok"] is False
    assert "STATEMENT_NOT_CANONICALIZABLE" in r["reason_codes"], r["errors"]


@pytest.mark.parametrize("version", sorted(VERSIONS))
def test_where_the_validator_passes_the_top_reason_names_the_missing_canonical_form(version):
    """`subjectContext.humanRef` is typed nowhere, so the validator passes `2**53` there, and the
    missing canonical form is the receipt's first and only reason."""
    bauen, typ, verify = VERSIONS[version]
    r = verify(_signed_as_sent(_set(bauen(), ("subjectContext", "humanRef"), 2**53), typ), PK)
    assert r["reason_code"] == "STATEMENT_NOT_CANONICALIZABLE", (r["reason_codes"], r["errors"])


def test_a_canonical_payload_that_is_merely_not_canonical_keeps_its_sentence():
    """Anti-parity: a payload that HAS a canonical form and is not in it is refused as before,
    with the sentence it always had and no new code."""
    p = _v02()
    st = {"_type": AR.STATEMENT_TYPE,
          "subject": [{"name": AR._subject_name(p), "digest": {"sha256": AR._subject_digest(p)}}],
          "predicateType": AR.AGENT_REVIEW_PREDICATE_TYPE_V02, "predicate": p}
    env = dsse.sign_envelope(json.dumps(st, indent=1).encode(), SK,
                             payload_type=AR.INTOTO_STATEMENT_PAYLOAD_TYPE)
    r = AR.verify_agent_review_v02(env, PK, expected_subject_digest=AR._subject_digest(p))
    assert r["ok"] is False and "STATEMENT_NOT_CANONICALIZABLE" not in r["reason_codes"]
    assert "payload is not RFC-8785 canonical (hash_binding fail-closed)" in r["errors"]


# ── the producers of this module ──────────────────────────────────────────────────────────────
@pytest.mark.parametrize("wert", OUTSIDE_JCS, ids=repr)
def test_findings_root_raises_the_modules_typed_error(wert):
    finding = {"id": wert, "severity": "low", "title": "t", "disposition": "open"}
    with pytest.raises(AR.AgentReviewError) as info:
        AR.findings_root([finding])
    assert "findings[0]" in str(info.value)


@pytest.mark.parametrize("wert", OUTSIDE_JCS, ids=repr)
def test_the_emitter_refuses_such_a_value_by_type(wert):
    """The validator passes `humanRef = 2**53`; the canonical form is where it fails, and the
    failure is the module's own error, not the canonicalizer's."""
    p = _set(_v02(), ("subjectContext", "humanRef"), wert)
    assert AR.validate_agent_review_v02_predicate(p) == []
    with pytest.raises(AR.AgentReviewError):
        AR.emit_agent_review(p, SK)
    with pytest.raises(AR.AgentReviewError):
        AR.build_agent_review_statement(p)


# ── every other wrapper of the canonicalizer ──────────────────────────────────────────────────
def _wrappers() -> dict:
    """(module, function) -> (call with one value, what it answers). One entry for every function
    under src/proofbundle that calls the canonicalizer itself; the inventory test holds the list
    complete."""
    from proofbundle import (anchors, canonical, decision, evalclaim, intoto, outcome,  # noqa: PLC0415
                             relation_statement, run_ledger, subject_binding, trust_pack,
                             verification_summary, verifier_block)
    from proofbundle._statement_payload import load_statement_strict  # noqa: PLC0415
    from proofbundle.adapters import _provenance, eee  # noqa: PLC0415
    from proofbundle.errors import BundleFormatError  # noqa: PLC0415
    return {
        ("agent_review", "_rfc8785_bytes"): (AR._rfc8785_bytes, AR.AgentReviewError),
        ("decision", "_rfc8785_bytes"): (decision._rfc8785_bytes, decision.DecisionReceiptError),
        ("outcome", "_rfc8785_bytes"): (outcome._rfc8785_bytes, outcome.OutcomeReceiptError),
        ("run_ledger", "_rfc8785_bytes"): (run_ledger._rfc8785_bytes, run_ledger.RunLedgerError),
        ("relation_statement", "_rfc8785_bytes"): (relation_statement._rfc8785_bytes,
                                                   relation_statement.RelationStatementError),
        ("trust_pack", "_rfc8785_bytes"): (trust_pack._rfc8785_bytes, trust_pack.TrustPackError),
        ("verification_summary", "_rfc8785_bytes"): (verification_summary._rfc8785_bytes,
                                                     verification_summary.VerificationSummaryError),
        ("subject_binding", "_rfc8785_bytes"): (subject_binding._rfc8785_bytes,
                                                subject_binding.SubjectBindingError),
        ("verifier_block", "_rfc8785_bytes"): (verifier_block._rfc8785_bytes,
                                               verifier_block.VerifierBlockError),
        ("intoto", "_serialize_statement"): (
            lambda o: intoto._serialize_statement(o, intoto.CONTENT_ROOT_ALG), BundleFormatError),
        ("anchors", "receipt_canonical_root"): (anchors.receipt_canonical_root, BundleFormatError),
        ("evalclaim", "canonicalize"): (evalclaim.canonicalize, evalclaim.EvalClaimError),
        ("_statement_payload", "load_statement_strict"): (
            lambda o: load_statement_strict(json.dumps(o).encode(), require_canonical=True),
            BundleFormatError),
        # A producer helper that labels its fallback instead of refusing: the answer is a string.
        ("adapters._provenance", "config_hash"): (_provenance.config_hash, "sha256-sortkeys:"),
        ("adapters.eee", "_record_digest"): (eee._record_digest, "sha256-sortkeys:"),
        # The primitives pass the canonicalizer's refusal on unchanged: that is their documented
        # contract (canonical.canonicalize_statement), and every caller above maps it.
        ("canonical", "canonicalize_statement"): (canonical.canonicalize_statement, ValueError),
        ("canonical", "statement_content_root"): (canonical.statement_content_root, ValueError),
    }


@pytest.mark.parametrize("wert", OUTSIDE_JCS, ids=repr)
def test_every_wrapper_answers_such_a_value_with_its_own_typed_error(wert):
    """At 8ecb6edf nine of these raised the canonicalizer's bare ValueError (agent_review,
    decision, outcome, run_ledger, relation_statement, trust_pack, verification_summary,
    subject_binding, verifier_block) and a tenth, intoto, on its export paths."""
    for (modul, name), (aufruf, antwort) in _wrappers().items():
        objekt = {"x": wert}
        if isinstance(antwort, str):
            assert aufruf(objekt).startswith(antwort), (modul, name)
            continue
        with pytest.raises(Exception) as info:
            aufruf(objekt)
        assert isinstance(info.value, antwort), (modul, name, type(info.value).__name__)
        if antwort is not ValueError:
            assert type(info.value).__module__.startswith("proofbundle"), (
                modul, name, f"the canonicalizer's own {type(info.value).__name__} escaped")


def _direct_canonicalizer_calls() -> set:
    """(module, function) for every function under src/proofbundle whose body calls
    `rfc8785.dumps` or `canonicalize_statement` itself."""
    gefunden = set()
    for datei in sorted(SRC.rglob("*.py")):
        if "__pycache__" in datei.parts:
            continue
        modul = datei.relative_to(SRC).with_suffix("").as_posix().replace("/", ".")
        baum = ast.parse(datei.read_text(encoding="utf-8"))
        for fn in ast.walk(baum):
            if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for k in ast.walk(fn):
                if not isinstance(k, ast.Call):
                    continue
                f = k.func
                if ((isinstance(f, ast.Name) and f.id == "canonicalize_statement")
                        or (isinstance(f, ast.Attribute) and f.attr == "canonicalize_statement")
                        or (isinstance(f, ast.Attribute) and f.attr == "dumps"
                            and isinstance(f.value, ast.Name) and f.value.id == "rfc8785")):
                    gefunden.add((modul, fn.name))
    return gefunden


def test_every_call_of_the_canonicalizer_is_in_the_table():
    """A new function that calls the canonicalizer itself turns this red until its answer to such
    a value is in `_wrappers`; one that is gone has to leave it."""
    assert _direct_canonicalizer_calls() == set(_wrappers()), (
        sorted(_direct_canonicalizer_calls() ^ set(_wrappers())))


# ── the public surfaces behind those wrappers ─────────────────────────────────────────────────
@pytest.mark.parametrize("wert", OUTSIDE_JCS, ids=repr)
def test_subject_binding_refuses_by_type(wert):
    from proofbundle import subject_binding as SB  # noqa: PLC0415
    st = {"subject": [{"name": "x", "digest": {"sha256": "0" * 64}}], "predicate": {"x": wert}}
    for aufruf in (SB.classify_subject, SB.require_derived_subject,
                   lambda s: SB.derive_subject_digest(s["predicate"])):
        with pytest.raises(SB.SubjectBindingError):
            aufruf(st)


@pytest.mark.parametrize("wert", OUTSIDE_JCS, ids=repr)
def test_the_verifier_block_join_answers_instead_of_raising(wert):
    """`join_test_result` is a relying party's check. A statement without a canonical form has no
    digest to compare: the join says so and does not match; `test_result_ref` refuses by type."""
    from proofbundle import verifier_block as VB  # noqa: PLC0415
    block = _conformance("agent-review-v03-positive-control-verifier-block-is-accepted")["producer"]["verifier"]
    st = {"_type": VB.STATEMENT_TYPE, "subject": [{"name": "x", "digest": dict(block["build"]["digest"])}],
          "predicateType": VB.TEST_RESULT_PREDICATE_TYPE,
          "predicate": {"result": "PASSED",
                        "configuration": [{"name": "v", "digest": {"sha256": "a" * 64},
                                           "annotations": {"cases": 1, "n": wert}}],
                        "passedTests": ["a"], "warnedTests": [], "failedTests": []}}
    j = VB.join_test_result(dict(block, testResult={"predicateType": VB.TEST_RESULT_PREDICATE_TYPE,
                                                    "result": "PASSED",
                                                    "statementDigest": {"sha256": "a" * 64}}), st)
    assert j["ok"] is False and j["digest_matches"] is False
    assert any("no canonical digest" in e for e in j["errors"]), j["errors"]
    with pytest.raises(VB.VerifierBlockError):
        VB.test_result_ref(st)


def test_the_values_are_what_the_strict_parser_admits():
    """The premise, measured rather than assumed: each value survives the strict parser, so each
    reaches a verifier inside a correctly signed payload."""
    from proofbundle._strict_json import loads_strict  # noqa: PLC0415
    for wert in OUTSIDE_JCS:
        gelesen = loads_strict(json.dumps({"x": wert}))["x"]
        assert gelesen == wert or (math.isnan(wert) and math.isnan(gelesen))
