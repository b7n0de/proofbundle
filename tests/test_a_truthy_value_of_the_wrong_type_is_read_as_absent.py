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
here too. Every test in this file up to the last section fails at c3bd89a4.

The last section follows lens run 7 on 8ecb6edf: the policy call held a predicate that is no object
against the policy as `{}`, and the renderers, with the validator in front taken away, raised on
`limitations` and on a predicate, `declaration` or `coverage` that is no object. Its 37 cases fail at
8ecb6edf; the byte-identity pin beside them passes there, because it holds what 8ecb6edf rendered.
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


# ── lens run 7 on 8ecb6edf: the policy call, and the renderers without the validator ─────────
@pytest.mark.parametrize("version", ["v0.2", "v0.3"])
@pytest.mark.parametrize("praed", [[1], "x", 5, [], 0, None, "ABSENT"], ids=repr)
def test_a_predicate_that_is_no_object_is_not_held_against_the_policy(version, praed):
    """`agent_review.py:2902` on 8ecb6edf, `evaluate_limitation_policy(_praed or {}, policy)`. A
    signed receipt whose predicate is `[1]`, `"x"` or `5` answered POLICY_NOT_EVALUABLE as its only
    code, a sentence about the policy; `[]`, `0`, null or no predicate at all was held against the
    policy as `{}`. Now the first reason names the shape, and nothing is evaluated."""
    _bauen, typ, verify = VERSIONS[version]
    st = {"_type": AR.STATEMENT_TYPE, "subject": [{"name": "x", "digest": {"sha256": "0" * 64}}],
          "predicateType": typ}
    if praed != "ABSENT":
        st["predicate"] = praed
    env = dsse.sign_envelope(canonical.canonicalize_statement(st), SK,
                             payload_type=AR.INTOTO_STATEMENT_PAYLOAD_TYPE)
    r = verify(env, PK, policy=AR.load_policy())
    _no_internal_error(r)
    assert r["reason_code"] == "PREDICATE_NOT_OBJECT", (r["reason_codes"], r["errors"])
    assert "POLICY_NOT_EVALUABLE" in r["reason_codes"]
    assert r["policy_decision"] == "insufficient_evidence" and r["ok"] is False
    assert "limitation_codes" not in (r.get("policy_reason") or {}), "a non-object was evaluated"
    assert any("not an object, so there is nothing to hold against the policy" in str(e)
               for e in r["errors"]), r["errors"]


def test_the_v01_verifier_names_the_shape_too():
    """The code comes from the validator all three versions share, so v0.1 names it as well; at
    8ecb6edf its verdict for such a receipt carried no reason code at all."""
    st = {"_type": AR.STATEMENT_TYPE, "subject": [{"name": "x", "digest": {"sha256": "0" * 64}}],
          "predicateType": AR.AGENT_REVIEW_PREDICATE_TYPE, "predicate": [1]}
    env = dsse.sign_envelope(canonical.canonicalize_statement(st), SK,
                             payload_type=AR.INTOTO_STATEMENT_PAYLOAD_TYPE)
    assert AR.verify_agent_review(env, PK)["reason_code"] == "PREDICATE_NOT_OBJECT"


@pytest.mark.parametrize("wert, erwartet", [(5, ""), (True, ""), ([5], ""), ([[1]], ""),
                                            ("x", ""), ({"a": 1}, ""), (["l1", 5, "l2"], "l1; l2")],
                         ids=repr)
def test_the_renderers_read_limitations_as_a_list_of_strings(wert, erwartet, monkeypatch):
    """`agent_review.py:1259` on 8ecb6edf, `"; ".join(predicate.get("limitations") or [])`, the
    idiom the reads two lines above had already left: `5` and `true` passed the `or`, `[5]` and
    `[[1]]` reached the join, each a TypeError, and a string or an object was joined per character
    or per key. With the validator in front taken away, a list is read and of it the strings."""
    monkeypatch.setattr(AR, "require_valid_agent_review_predicate_any", lambda *_a, **_k: None)
    p = _v02()
    p["limitations"] = copy.deepcopy(wert)
    block = AR.render_disclosure_block(p)
    AR.render_disclosure_line(p, receipt_digest="0" * 64, receipt_url="u")
    assert f"- **Limits:** {erwartet}\n" in block, block


@pytest.mark.parametrize("wo", ["predicate", "declaration", "coverage"])
@pytest.mark.parametrize("wert", [[1], "x", 5, None, "ABSENT"], ids=repr)
def test_the_renderers_read_a_section_that_is_no_object_as_absent(wo, wert, monkeypatch):
    """`agent_review.py:1226`, `:1230`, `:1256`, `:1282` and `:1283` on 8ecb6edf: with the validator
    taken away, a predicate, `declaration` or `coverage` that is no object raised TypeError, KeyError
    or AttributeError in the renderers. Read as absent, as the verifiers read it."""
    monkeypatch.setattr(AR, "require_valid_agent_review_predicate_any", lambda *_a, **_k: None)
    if wo == "predicate":
        p = {} if wert == "ABSENT" else copy.deepcopy(wert)
    else:
        p = _v02()
        if wert == "ABSENT":
            del p[wo]
        else:
            p[wo] = copy.deepcopy(wert)
    block = AR.render_disclosure_block(p)
    line = AR.render_disclosure_line(p, receipt_digest="0" * 64, receipt_url="u")
    assert "selfDeclared" in block and "selfDeclared" in line


#: sha256[:16] over `block + "\n" + line` for every valid predicate of the conformance corpus and
#: every published receipt, measured with the renderers of 8ecb6edf (block with receipt digest
#: "a"*64; line with receipt digest "a"*64, receipt url "u", leaf url "l"). The renderers after lens
#: run 7 give the same bytes for all 19. The lens's own render dump, 64 valid predicates of the corpus,
#: the receipts and its synthetic variants, was byte-identical between 8ecb6edf and this change too.
_RENDER_PINS = {
    "conformance/agent_review/agent-review-positive-control-emit-verify-roundtrip/predicate.json": "16e4e18ff57438db",
    "conformance/agent_review/agent-review-v02-counter-proof-blocking-policy-rejects/predicate.json": "65e50377901203cb",
    "conformance/agent_review/agent-review-v02-counter-proof-unknown-coverage-is-insufficient-evidence/predicate.json": "3c2572d60c6d7c42",
    "conformance/agent_review/agent-review-v02-counter-proof-without-policy-nothing-is-decided/predicate.json": "65e50377901203cb",
    "conformance/agent_review/agent-review-v02-positive-control-default-policy-decides-accept/predicate.json": "65e50377901203cb",
    "conformance/agent_review/agent-review-v02-positive-control-emitter-default-is-v02/predicate.json": "65e50377901203cb",
    "conformance/agent_review/agent-review-v02-positive-control-fixcommit-full-sha-is-accepted/predicate.json": "c4135f0e77726c1d",
    "conformance/agent_review/agent-review-v03-positive-control-verifier-block-is-accepted/predicate.json": "65e50377901203cb",
    "receipts/agent_review/inspect_ai_5141.r2.receipt.json": "c293685f153d34de",
    "receipts/agent_review/inspect_ai_5141.r3.receipt.json": "bbbd94dbacecd9a1",
    "receipts/agent_review/inspect_ai_5141.receipt.json": "6c2d979a1f652160",
    "receipts/agent_review/proofbundle_147_comment.r2.receipt.json": "5a6cd55a4b9bf60b",
    "receipts/agent_review/proofbundle_147_comment.receipt.json": "5a6cd55a4b9bf60b",
    "receipts/agent_review/proofbundle_162.receipt.json": "b9b411052f5f7a4e",
    "receipts/agent_review/proofbundle_185.r2.receipt.json": "a8523b586dbeea96",
    "receipts/agent_review/proofbundle_185.receipt.json": "5042897b733d87c0",
    "receipts/agent_review/proofbundle_224.r1.receipt.json": "da429cac82e32f5a",
    "receipts/agent_review/proofbundle_225.r1.receipt.json": "0afd18dcb99730f2",
    "receipts/agent_review/proofbundle_231_comment.receipt.json": "fce86b0faed878f2",
}


def test_valid_predicates_render_byte_identically():
    """The fixes above change what the renderers do with a value the validator refuses, and nothing
    else: every pinned predicate renders the bytes 8ecb6edf rendered."""
    import base64  # noqa: PLC0415
    import hashlib  # noqa: PLC0415
    for name, pin in _RENDER_PINS.items():
        roh = json.loads((REPO / name).read_text(encoding="utf-8"))
        p = roh if name.endswith("predicate.json") else json.loads(base64.b64decode(roh["payload"]))["predicate"]
        block = AR.render_disclosure_block(p, receipt_digest="a" * 64)
        line = AR.render_disclosure_line(p, receipt_digest="a" * 64, receipt_url="u", leaf_url="l")
        assert hashlib.sha256((block + "\n" + line).encode()).hexdigest()[:16] == pin, name
