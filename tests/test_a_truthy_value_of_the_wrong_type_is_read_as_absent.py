"""A truthy value of the wrong type is read as absent, never as the type the next line expects.

THE CLASS, stated as the violated assumption: *`(x or [])` and `(x or {})` make a value of parsed JSON
safe to use as a list or a dict.* They replace a FALSY value only. A truthy value of another type, a
dict where a list belongs, a number, a string, `true`, passes the `or` and reaches the `+`, the `for`,
the `.get` or the `len` behind it.

MEASURED ON c3bd89a4, first by the lens: a correctly signed agent-review receipt whose
`declaration.authoring` is `{"a": []}` made `verify_agent_review`, `verify_agent_review_v02`,
`verify_agent_review_v03` and `verify_agent_review_any` answer `reason_code=internal_error`, "a defect
in the verifier", because `(dec.get("authoring") or []) + (dec.get("reviewRuns") or [])` became
`dict + list`; the validator beside it had already said `declaration: authoring must be an array`.
Then with a generator that replaces every node of four seed predicates by a value of each JSON type
and calls every public agent-review surface: 51,654 calls, 44 findings at nine source lines of
`agent_review.py` (the three `+` sites in the verifiers and `derive_limitation_codes`, the `findings`
loop of the v0.2 validator, `findings_root` over a non-list, two reads in `resolve_receipt_chain`,
and two hashing neighbours: the assurance set in `derive_limitation_codes` and the value set in
`_zeitachsen`). After the fix the same run finds 0. The sweep found two more sites of the class
outside this module, `evalclaim.sd_jwt_hidden_count` and `cap1._r2_closed_disposition`; both are
here too. Every test in this file fails at c3bd89a4.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from proofbundle import agent_review as AR
from proofbundle import canonical, cap1, dsse
from proofbundle.evalclaim import sd_jwt_hidden_count

REPO = Path(__file__).resolve().parents[1]
SK = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
PK = SK.public_key().public_bytes_raw()

#: Every JSON type in a form that survives `or`; the falsy forms, which always did; and lists whose
#: items are no objects, which the item filters beside the `+` hold. Each test runs through all of
#: them in one function, so every test function has a case that is red at c3bd89a4 and the others
#: stand beside it as anti-parity.
TRUTHY_WRONG = [{"a": []}, "x", 5, 1.5, True]
FALSY = [{}, "", 0, False, None]
ODD_LISTS = [[[1]], [{}], ["x"]]


def _v01() -> dict:
    return {
        "schemaVersion": "0.1.0", "reviewId": "r",
        "subjectContext": {"kind": "githubPullRequest", "forge": "g", "repositoryId": "R",
                           "pullRequestNodeId": "P", "headSha": "a" * 40, "baseSha": "b" * 40,
                           "reviewedDiffDigest": "c" * 64, "bodyCoreDigest": "d" * 64},
        "declaration": {"authoring": [{"assurance": "selfDeclared", "assertedBy": "x"}],
                        "reviewRuns": [], "findings": [], "findingsTotal": 0, "nonClaims": ["n"]},
        "coverage": {"status": "UNKNOWN"},
        "times": {"declaredAt": "2026-08-31T17:00:00Z"},
        "limitations": ["l"],
    }


def _conformance(name: str) -> dict:
    return json.loads((REPO / "conformance" / "agent_review" / name / "predicate.json")
                      .read_text(encoding="utf-8"))


def _v02() -> dict:
    return _conformance("agent-review-v02-positive-control-emitter-default-is-v02")


def _v03() -> dict:
    return _conformance("agent-review-v03-positive-control-verifier-block-is-accepted")


VERSIONS = {
    "v0.1": (_v01, AR.AGENT_REVIEW_PREDICATE_TYPE, AR.verify_agent_review),
    "v0.2": (_v02, AR.AGENT_REVIEW_PREDICATE_TYPE_V02, AR.verify_agent_review_v02),
    "v0.3": (_v03, AR.AGENT_REVIEW_PREDICATE_TYPE_V03, AR.verify_agent_review_v03),
}


def _signed(predicate: dict, predicate_type: str) -> dict:
    st = {"_type": AR.STATEMENT_TYPE,
          "subject": [{"name": AR._subject_name(predicate),
                       "digest": {"sha256": AR._subject_digest(predicate)}}],
          "predicateType": predicate_type, "predicate": predicate}
    return dsse.sign_envelope(canonical.canonicalize_statement(st), SK,
                              payload_type=AR.INTOTO_STATEMENT_PAYLOAD_TYPE)


def _no_internal_error(r: dict) -> None:
    assert r["reason_code"] != "internal_error", r["errors"]
    assert "internal_error" not in r["reason_codes"], r["errors"]
    assert not any("defect in the verifier" in str(e) for e in r["errors"]), r["errors"]


# ── the live finding, as the lens measured it ──────────────────────────────────────────────────
@pytest.mark.parametrize("version", sorted(VERSIONS))
@pytest.mark.parametrize("through_any", [False, True], ids=["direct", "any"])
def test_a_signed_receipt_whose_authoring_is_an_object_fails_on_its_structure(version, through_any):
    """The signature verifies, the structure fails with the validator's own sentence, and nothing
    says "defect in the verifier". At c3bd89a4 all six calls answered `internal_error`."""
    bauen, typ, verify = VERSIONS[version]
    p = bauen()
    p["declaration"]["authoring"] = {"a": []}
    env = _signed(p, typ)
    kw = {"expected_subject_digest": AR._subject_digest(p)}
    r = AR.verify_agent_review_any(env, PK, **kw) if through_any else verify(env, PK, **kw)
    _no_internal_error(r)
    assert r["crypto_ok"] is True
    assert r["structure_ok"] is False and r["ok"] is False
    assert any("authoring must be an array" in str(e) for e in r["errors"]), r["errors"]


@pytest.mark.parametrize("version", ["v0.2", "v0.3"])
def test_the_policy_is_evaluated_for_such_a_receipt_not_given_up(version):
    """With a policy the v0.2 path reaches `derive_limitation_codes`; at c3bd89a4 the receipt died
    before it, and with a list as a rung the policy answer was "policy could not be evaluated:
    unhashable type"."""
    bauen, typ, verify = VERSIONS[version]
    for pfad, wert in ((("declaration", "authoring"), {"a": []}),
                       (("declaration", "authoring", 0, "assurance"), [])):
        p = bauen()
        ziel = p
        for k in pfad[:-1]:
            ziel = ziel[k]
        ziel[pfad[-1]] = wert
        r = verify(_signed(p, typ), PK, expected_subject_digest=AR._subject_digest(p),
                   policy=AR.load_policy())
        _no_internal_error(r)
        assert "POLICY_NOT_EVALUABLE" not in r["reason_codes"], (pfad, r["errors"])
        assert r["policy_decision"] in ("accept", "reject", "insufficient_evidence")


# ── a generator over the four instances the task named, and the fifth ─────────────────────────
@pytest.mark.parametrize("feld", ["authoring", "reviewRuns"])
def test_derive_limitation_codes_never_raises(feld):
    """`agent_review.py:664` on c3bd89a4. `derive_limitation_codes` is a never-raise surface."""
    for bauen in (_v01, _v02, _v03):
        for wert in TRUTHY_WRONG + FALSY + ODD_LISTS:
            p = bauen()
            p["declaration"][feld] = copy.deepcopy(wert)
            codes = AR.derive_limitation_codes(p)
            assert "NOT_QUALITY_ATTESTATION" in codes and "IDENTITY_UNBOUND" in codes, (wert, codes)


@pytest.mark.parametrize("feld", ["authoring", "reviewRuns"])
def test_the_renderers_hold_without_the_validator_in_front(feld, monkeypatch):
    """`agent_review.py:1219` and `:1259` on c3bd89a4. The validator in front of the renderers
    refuses these values, so the public call raises `AgentReviewError` either way; the idiom behind
    it must not be what holds them, so the validator is taken away here and the renderer's own read
    is what is measured."""
    monkeypatch.setattr(AR, "require_valid_agent_review_predicate_any", lambda *_a, **_k: None)
    for wert in TRUTHY_WRONG + FALSY:
        p = _v02()
        p["declaration"][feld] = copy.deepcopy(wert)
        block = AR.render_disclosure_block(p)
        line = AR.render_disclosure_line(p, receipt_digest="0" * 64, receipt_url="u")
        assert "selfDeclared" in block and "selfDeclared" in line, wert


#: Entries of the right list with the wrong inside: no object, and a rung or disposition that cannot
#: be hashed or is no string.
ODD_ENTRIES = [5, "x", [1], {"assurance": []}, {"assurance": {"a": 1}, "assertedBy": "x"},
               {"assurance": 5}, {"disposition": []}, {"disposition": {"a": 1}}]


@pytest.mark.parametrize("feld", ["authoring", "reviewRuns", "findings"])
def test_the_renderers_hold_entries_of_the_wrong_type_without_the_validator(feld, monkeypatch):
    """Lens run 7 on this branch (qwen, 234g): the renderers' rung sets hashed `assurance` from every
    entry unfiltered, where `derive_limitation_codes` reads strings only. The public call raises
    `AgentReviewError` from the validator in front either way; with the validator taken away, an
    entry `{"assurance": []}` raised `TypeError` and an entry `5` raised `AttributeError` at
    f6d7cd7f. The renderer's own read is what is measured here, and a wrong entry names nothing."""
    monkeypatch.setattr(AR, "require_valid_agent_review_predicate_any", lambda *_a, **_k: None)
    for eintrag in ODD_ENTRIES:
        p = _v02()
        p["declaration"][feld] = p["declaration"].get(feld, []) + [copy.deepcopy(eintrag)]
        block = AR.render_disclosure_block(p)
        line = AR.render_disclosure_line(p, receipt_digest="0" * 64, receipt_url="u")
        assert "selfDeclared" in block and "selfDeclared" in line, eintrag


@pytest.mark.parametrize("version", sorted(VERSIONS))
@pytest.mark.parametrize("feld", ["authoring", "reviewRuns"])
def test_the_verifiers_never_answer_internal_error(version, feld):
    """`agent_review.py:2458` (v0.1) and `:2829` (v0.2 and v0.3) on c3bd89a4."""
    bauen, typ, verify = VERSIONS[version]
    for wert in TRUTHY_WRONG + ODD_LISTS:
        p = bauen()
        p["declaration"][feld] = copy.deepcopy(wert)
        r = verify(_signed(p, typ), PK, expected_subject_digest=AR._subject_digest(p))
        _no_internal_error(r)
        assert r["crypto_ok"] is True and r["ok"] is False, wert


# ── the other sites the generator found at c3bd89a4 ───────────────────────────────────────────
@pytest.mark.parametrize("version", sorted(VERSIONS))
def test_a_non_list_findings_list_is_a_structural_error(version):
    """`agent_review.py:2034`: `findings: 5` made the v0.2 VALIDATOR raise `TypeError`, and with it
    both v0.2/v0.3 verifiers and both renderers. `:2435` and `:2817`: beside a `findingsRoot` the
    same value reached the loop in `findings_root`, `:315`, and v0.1 answered `internal_error`."""
    bauen, typ, verify = VERSIONS[version]
    for wert in TRUTHY_WRONG:
        p = bauen()
        p["declaration"]["findings"] = copy.deepcopy(wert)
        p["declaration"]["findingsRoot"] = "0" * 64
        fehler = (AR.validate_agent_review_predicate(p) + AR.validate_agent_review_v02_predicate(p)
                  + AR.validate_agent_review_v03_predicate(p))
        assert any("findings must be an array" in str(e) for e in fehler), fehler
        r = verify(_signed(p, typ), PK, expected_subject_digest=AR._subject_digest(p))
        _no_internal_error(r)
        assert r["crypto_ok"] is True and r["ok"] is False
        with pytest.raises(AR.AgentReviewError):
            AR.render_disclosure_block(p)


@pytest.mark.parametrize("wert", [[], {}, [[1]], {"a": []}], ids=repr)
def test_a_review_time_that_does_not_hash_is_counted_not_hashed(wert):
    """`agent_review.py:2131`: the set of `reviewCompleted` values hashed each value, and a signed
    v0.2 receipt with `value: []` answered `internal_error`."""
    for version in ("v0.2", "v0.3"):
        bauen, typ, verify = VERSIONS[version]
        p = bauen()
        p["declaration"]["timeClaims"] = [{"kind": "reviewCompleted", "value": copy.deepcopy(wert),
                                           "assertedBy": "x", "assurance": "selfDeclared"}]
        r = verify(_signed(p, typ), PK, expected_subject_digest=AR._subject_digest(p))
        _no_internal_error(r)
        assert r["event_time_status"] == "SELF_DECLARED"


def test_two_different_review_times_still_conflict():
    """Anti-parity for the count above: the list compares by equality, as the set did, so two
    different hashable values are still a CONFLICT and two equal ones are not."""
    for werte, erwartet in ((["2026-09-01T00:00:00Z", "2026-09-02T00:00:00Z"], "CONFLICT"),
                            (["2026-09-01T00:00:00Z", "2026-09-01T00:00:00Z"], "SELF_DECLARED"),
                            (["2026-09-01T00:00:00Z", []], "CONFLICT")):
        p = _v02()
        p["declaration"]["timeClaims"] = [{"kind": "reviewCompleted", "value": w, "assertedBy": "x",
                                           "assurance": "selfDeclared"} for w in werte]
        assert AR._zeitachsen(p)["event_time_status"] == erwartet, werte


@pytest.mark.parametrize("pfad", [("supersession",), ("supersession", "supersedes"),
                                  ("supersession", "supersedes", 0, "priorDigest")], ids=repr)
def test_the_chain_resolver_orders_nothing_it_cannot_read(pfad):
    """`agent_review.py:1080` and `:1083`: with the envelope's digest named as verified, a
    `supersession` or a relation list or a `priorDigest` of the wrong type raised out of
    `resolve_receipt_chain`. Read as absent, the relation corrects nothing: the envelope stays the
    one candidate and no predecessor is invented."""
    for wert in TRUTHY_WRONG + ODD_LISTS:
        p = _v01()
        p["supersession"] = {"supersedes": [{"priorDigest": {"sha256": "e" * 64}, "reason": "r"}]}
        ziel = p
        for k in pfad[:-1]:
            ziel = ziel[k]
        ziel[pfad[-1]] = copy.deepcopy(wert)
        env = _signed(p, AR.AGENT_REVIEW_PREDICATE_TYPE)
        d = AR.receipt_digest(env)
        r = AR.resolve_receipt_chain([env], verified={d})
        assert r["current"] == d and r["corrected"] == [] and r["missing_predecessors"] == [], wert


def test_a_missing_rung_leaves_identity_unbound():
    """The rung set of `derive_limitation_codes` reads strings only now. Before, an entry without
    `assurance` put `None` into the set, `{None} <= {"selfDeclared"}` is false, and IDENTITY_UNBOUND
    was dropped for a declaration that names no rung at all. A string rung above selfDeclared still
    lifts it (anti-parity)."""
    p = _v02()
    p["declaration"]["authoring"] = [{"assertedBy": "x"}]
    assert "IDENTITY_UNBOUND" in AR.derive_limitation_codes(p)
    p["declaration"]["authoring"] = [{"assertedBy": "x", "assurance": "runnerObserved"}]
    assert "IDENTITY_UNBOUND" not in AR.derive_limitation_codes(p)


@pytest.mark.parametrize("wert", [[1], 5, True, 1.5], ids=repr)
def test_sd_jwt_hidden_count_reads_a_non_object_as_no_sd_jwt(wert):
    """`evalclaim.py:678`: a truthy `sd_jwt_vc` that is neither a string nor an object passed
    `if not sd` and raised AttributeError at `.get`, out of a never-raise surface."""
    assert sd_jwt_hidden_count({"sd_jwt_vc": wert}) is None


@pytest.mark.parametrize("wert", [5, True, "x", {"a": []}], ids=repr)
def test_cap1_rule_r2_reads_only_a_list(wert):
    """`cap1.py:162`: `unexamined: 5` or `true` made R2 raise inside `check_cap1_document`, which
    reported the rule as one it could not evaluate; `"x"` was read as one entry per character.
    R1 names the non-list, and R2 says nothing about a list that is not there."""
    vektor = REPO / "conformance" / "cap1" / "cap1-positive-control-pv-01-complete-run-catalogued-basis"
    doc = json.loads((vektor / "document.json").read_text(encoding="utf-8"))
    for s in doc["strata"]:
        s["unexamined"] = copy.deepcopy(wert)
    befunde = cap1.check_cap1_document(doc)
    assert not any("ausgewertet" in b["reason"] for b in befunde), befunde
    assert not any(b["rule"] == "R2-closed-disposition" for b in befunde), befunde
    assert any(b["rule"] == "R1-no-silent-remainder" and "keine Liste" in b["reason"] for b in befunde)


def test_as_list_is_a_list_and_nothing_else():
    """The helper the fix routes through: the same list for a list, a fresh empty one for anything
    else, a tuple included (the validators call an array a list, and `list + tuple` raises)."""
    from proofbundle._membership import as_list  # noqa: PLC0415 - absent at c3bd89a4
    xs = [1]
    assert as_list(xs) is xs
    for wert in ({"a": []}, (1,), "x", 5, None, True):
        assert as_list(wert) == [], wert
