"""Standalone lineage profile ``relation-statement/v0.1`` — EXPERIMENTAL (3.5.0).

A relation-statement is an INDEPENDENT, DSSE-signed statement ABOUT a target receipt: a
retroactive retraction / supersession / amendment that carries EXACTLY ONE typed relationship
edge and NO outcome/decision payload of its own — the statement IS the relation. It never
touches the target's bytes (append-only status precedent: W3C Bitstring Status List v1.0,
CT/OCSP revocation, SCITT protected-object-binding).

Honesty boundary (verbatim, enforced by claims-hygiene): a relation statement proves the
ISSUER DECLARED the relation over exact bytes; it does NOT retract the target's cryptographic
validity, and whether the issuer MAY declare it is a relying-party policy decision. The target
receipt stays valid for its bytes forever — a ``retracts`` statement sets a visible state
BESIDE it, it never invalidates crypto (lattice monotonicity: ``lineage``/policy never feed
``cryptoValid``).

Reuse, not re-implementation (SPEC §8.1): the edge is validated by
:func:`relation.validate_relationships`, resolved by :func:`relation.verify_relationship_edges`,
and gated by :func:`relation.evaluate_relations_policy` — the SAME functions the decision and
outcome paths call, and the SAME functions the independent Rust verifier mirrors. Only the
standalone predicate shape and the ``reject_retracted``/``reject_superseded`` self-assertion gate
live here.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any

from ._strict_json import loads_strict
from .errors import ProofBundleError

RELATION_STATEMENT_PREDICATE_TYPE = "https://b7n0de.com/proofbundle/predicates/relation-statement/v0.1"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
INTOTO_STATEMENT_PAYLOAD_TYPE = "application/vnd.in-toto+json"

_SEMVER_0_1_X = re.compile(r"^0\.1\.\d+$")

_REQUIRED = ("schemaVersion", "statementId", "relationships")
_ALLOWED_TOP = set(_REQUIRED)


class RelationStatementError(ProofBundleError):
    """A relation-statement/v0.1 predicate is malformed (fail-closed)."""


def validate_relation_statement_predicate(predicate: Any) -> list[str]:
    """Return a list of fail-closed errors (empty == valid). RETURNS, never raises — do NOT wrap
    in try/except (a caller that treats "no exception" as valid would report a malformed predicate
    as valid). Fail-closed: an unknown top-level field, a bad schemaVersion, an empty statementId,
    or anything other than EXACTLY ONE well-formed edge is an error."""
    from .relation import validate_relationships  # noqa: PLC0415

    errors: list[str] = []
    if not isinstance(predicate, dict):
        return ["predicate must be a JSON object"]

    for k in predicate:
        if k not in _ALLOWED_TOP:
            errors.append(f"unknown field {k!r} (additionalProperties:false)")
    for req in _REQUIRED:
        if req not in predicate:
            errors.append(f"missing required field {req!r}")

    sv = predicate.get("schemaVersion")
    if "schemaVersion" in predicate and not (isinstance(sv, str) and _SEMVER_0_1_X.match(sv)):
        errors.append("schemaVersion must match 0.1.x")

    sid = predicate.get("statementId")
    if "statementId" in predicate and not (isinstance(sid, str) and sid):
        errors.append("statementId must be a non-empty string")

    rels = predicate.get("relationships")
    if "relationships" in predicate:
        # A relation-statement carries EXACTLY ONE edge — it IS a single typed assertion over one
        # target (SPEC §2 WP-A1). The edge itself reuses the in-receipt edge schema verbatim.
        errors.extend(validate_relationships(rels))
        if isinstance(rels, list) and len(rels) != 1:
            errors.append(
                f"a relation-statement must carry EXACTLY ONE relationship edge, got {len(rels)}")
    return errors


def require_valid_relation_statement_predicate(predicate: Any) -> None:
    """Raise :class:`RelationStatementError` if the predicate is invalid; return None if valid."""
    errs = validate_relation_statement_predicate(predicate)
    if errs:
        raise RelationStatementError("invalid relation-statement predicate: " + "; ".join(errs))


# ── Emit (DSSE in-toto Statement) ──────────────────────────────────────────────
def _rfc8785_bytes(obj: Any) -> bytes:
    from . import canonical  # noqa: PLC0415
    try:
        return canonical.canonicalize_statement(obj)
    except canonical.CanonicalizerUnavailable as exc:
        raise RelationStatementError(
            "relation statements need the RFC 8785 (JCS) canonicalizer — install proofbundle[eval]") from exc


def _rfc8785_available() -> bool:
    try:
        import rfc8785  # noqa: F401, PLC0415
        return True
    except Exception:
        return False


def build_relation_statement(predicate: dict, *, subject_name: str | None = None,
                             subject_sha256: str | None = None) -> dict:
    """Build a STANDARD in-toto Statement v1 whose predicate is the relation-statement. The subject
    is by DEFAULT a commitment to the predicate (sha256 over its RFC-8785 canonical form). A
    caller-supplied override is self-attested and NOT cross-checked (No-Overclaim)."""
    errs = validate_relation_statement_predicate(predicate)
    if errs:
        raise RelationStatementError("invalid relation-statement predicate: " + "; ".join(errs))
    name = subject_name or f"relation-statement:{predicate.get('statementId', '')}"
    sha = subject_sha256 or hashlib.sha256(_rfc8785_bytes(predicate)).hexdigest()
    return {
        "_type": STATEMENT_TYPE,
        "subject": [{"name": name, "digest": {"sha256": sha}}],
        "predicateType": RELATION_STATEMENT_PREDICATE_TYPE,
        "predicate": predicate,
    }


def emit_relation_statement(predicate: dict, signer, *, subject_name: str | None = None,
                            subject_sha256: str | None = None, keyid: str | None = None) -> dict:
    """Sign a relation-statement as a DSSE-signed in-toto Statement. Emission is RFC-8785 canonical.
    Fail-closed: an invalid predicate raises before signing."""
    from . import dsse  # noqa: PLC0415
    errs = validate_relation_statement_predicate(predicate)
    if errs:
        raise RelationStatementError("invalid relation-statement predicate: " + "; ".join(errs))
    statement = build_relation_statement(predicate, subject_name=subject_name,
                                         subject_sha256=subject_sha256)
    body = _rfc8785_bytes(statement)
    return dsse.sign_envelope(body, signer, payload_type=INTOTO_STATEMENT_PAYLOAD_TYPE, keyid=keyid)


# ── Verify (pure, offline, fail-closed) ────────────────────────────────────────
# Stable standalone policy code, exit-3 class (mirrors relation.CODE_LINEAGE_REQUIREMENT_FAILED —
# the same code the decision/outcome paths use, so a relying party sees one vocabulary).
_SELF_ASSERTED_RETRACTORS = frozenset({"retracts"})


def _empty_result() -> dict:
    return {
        "ok": None, "crypto_ok": None, "structure_ok": None, "predicate_type_ok": None,
        "subject_binding": None, "subject_derived_ok": None,
        "lineage": None, "lineage_ok": None,
        "policy_ok": None, "relations_policy_failed": None,
        "relations_policy_codes": None, "warnings": [], "errors": [],
    }


def _finalize_failclosed(r: dict) -> dict:
    """RE-GATE never-raise (REGATE-BUDGET-01 / RE-TCE-01): a crypto/budget/parse failure over untrusted
    input yields ok=False — a fail-closed verdict dict, never a raw exception out of this dict-returning
    verify surface (mirrors decision/outcome). relation-statement carries no separate automation field."""
    r["ok"] = False
    return r


def verify_relation_statement(envelope: dict, public_key: bytes, *, strict: bool = False,
                              require_derived_subject: bool = False,
                              related: dict | None = None, policy: dict | None = None) -> dict:
    """Verify a DSSE-signed relation-statement. Crypto FIRST, then structure over the EXACT signed
    bytes, then the (pure, offline) lineage + relations-policy evaluation — reusing the shared
    relation engine, never re-implementing it.

    Fail-closed. Never raises on a malformed relations block (a fail-closed RESULT instead). A
    duplicate-JSON-key / non-JSON payload raises :class:`BundleFormatError` exactly like the other
    verify paths. Read ``ok`` (or ``crypto_ok``) — never an individual ``*_ok`` alone; on a forged
    envelope every trust-derived field stays None.

    Lattice monotonicity (INVARIANT): neither ``lineage`` nor the relations policy ever raises
    ``crypto_ok``. A ``retracts`` statement over a VERIFIED target does NOT make the target
    crypto-invalid — it is a visible declared state; ``reject_retracted``/``reject_superseded``
    turn a relying party's continued automated use of the target into an exit-3 policy block, never
    a crypto kill.
    """
    from . import anchors as _anchors  # noqa: PLC0415
    from . import dsse  # noqa: PLC0415
    from .budget import DEFAULT_BUDGET  # noqa: PLC0415
    from .relation import (  # noqa: PLC0415
        CODE_LINEAGE_REQUIREMENT_FAILED,
        LINEAGE_FAIL,
        LINEAGE_VERIFIED,
        SUCCESSOR_RELATIONS,
        evaluate_relations_policy,
        verify_relationship_edges,
    )
    r = _empty_result()
    related = related if isinstance(related, dict) else None

    try:
        # RE-GATE never-raise (REGATE-BUDGET-01 / RE-TCE-01): crypto verify + body load + input_bytes budget
        # + strict parse inside the never-raise try; the except catches ProofBundleError so an oversized/wide/
        # malformed untrusted envelope yields a fail-closed verdict, never a raw uncaught BudgetExceeded (a
        # ProofBundleError sibling of BundleFormatError the old narrow except let escape) out of this
        # dict-returning verify surface (mirrors decision/outcome).
        r["crypto_ok"] = bool(dsse.verify_envelope(
            envelope, public_key, payload_type=INTOTO_STATEMENT_PAYLOAD_TYPE))
        if not r["crypto_ok"]:
            r["errors"].append("DSSE signature verification failed — payload is unauthenticated")
        body = dsse.load_payload(envelope)
        DEFAULT_BUDGET.check("input_bytes", len(body))
        statement = loads_strict(body.decode("utf-8"))
    except (ProofBundleError, ValueError, UnicodeDecodeError) as exc:
        r["structure_ok"] = False
        r["errors"].append(f"DSSE payload is not a well-formed in-toto Statement: {exc}")
        return _finalize_failclosed(r)

    ptype = statement.get("predicateType") if isinstance(statement, dict) else None
    r["predicate_type_ok"] = ptype == RELATION_STATEMENT_PREDICATE_TYPE
    if not r["predicate_type_ok"]:
        r["errors"].append(
            f"predicateType is {ptype!r}, expected relation-statement/v0.1 (confusion attack?)")

    predicate = statement.get("predicate") if isinstance(statement, dict) else None
    struct_errs = validate_relation_statement_predicate(predicate)
    r["errors"].extend(struct_errs)

    canonical_ok = None
    if _rfc8785_available():
        try:
            canonical_ok = _rfc8785_bytes(statement) == body
        except Exception:  # noqa: BLE001
            canonical_ok = False
        if canonical_ok is False:
            r["errors"].append("payload is not RFC-8785 canonical (hash_binding fail-closed)")
    else:
        # PB06-RELSTMT-CANON-FAILOPEN (rfc8785 is now a declared CORE dependency): an absent canonicalizer is
        # a broken install, not a lenient mode — fail closed REGARDLESS of strict (mirrors decision.py). The
        # old `canonical_ok is None and not strict` branch let a payload whose canonicality could not be
        # verified pass with ok=True in default mode (a False Accept the decision sibling already closed).
        r["errors"].append(
            "RFC-8785 (JCS) canonicalizer unavailable — proofbundle requires rfc8785 (core dependency); "
            "hash_binding fail-closed, cannot verify canonicality")
    canonicality_ok = canonical_ok is True  # absent (None) or non-canonical (False) never passes (fail-closed)
    r["structure_ok"] = (not struct_errs) and bool(r["predicate_type_ok"]) and canonicality_ok

    if isinstance(predicate, dict) and r["crypto_ok"]:
        try:
            _subject_hex = _anchors.statement_content_root(body).hex()
        except Exception:  # noqa: BLE001
            _subject_hex = None
        # Reuse the SHARED engine — the statement's single edge is resolved exactly like an in-receipt
        # edge (target attached + verified + digest names it -> VERIFIED; absent -> DECLARED_UNRESOLVED;
        # cycle/depth/attached-but-wrong/subject-mismatch -> FAIL).
        r["lineage"] = verify_relationship_edges(
            predicate.get("relationships"), related, subject_hex=_subject_hex)
        if r["lineage"]["lineage"] == LINEAGE_FAIL:
            r["errors"].extend(r["lineage"]["errors"] or ["relation: lineage verification FAILED"])
        r["lineage_ok"] = False if r["lineage"]["lineage"] == LINEAGE_FAIL else None

        # Subject binding (mirrors decision/outcome): warn on an EXTERNAL_ATTESTED subject; a hard fail
        # only under require_derived_subject.
        if _rfc8785_available():
            from . import subject_binding as _sb  # noqa: PLC0415
            try:
                _cls = _sb.classify_subject(statement)
            except Exception:  # noqa: BLE001
                _cls = None
            if _cls is not None:
                r["subject_binding"] = {"mode": _cls["mode"], "matches": _cls["matches"]}
                if not _cls["matches"]:
                    r["warnings"].append(
                        "subject is EXTERNAL_ATTESTED — it does not commit to this predicate "
                        "(subject-rehang); trust it only via a policy that pins the external attester")
                if require_derived_subject:
                    r["subject_derived_ok"] = _cls["matches"]
                    if not _cls["matches"]:
                        r["errors"].append(
                            "require_derived_subject: subject is not a DERIVED commitment to the "
                            "predicate (fail-closed)")
            elif require_derived_subject:
                r["subject_derived_ok"] = False
                r["errors"].append(
                    "require_derived_subject: could not classify the subject binding "
                    "(canonicalization raised) — fail-closed")
        elif require_derived_subject:
            r["subject_derived_ok"] = False
            r["errors"].append(
                "require_derived_subject but RFC-8785 canonicalizer unavailable — cannot verify "
                "subject derivation (install proofbundle[eval]), fail-closed")

    # Relations trust-policy gate — REUSED identically to the decision/outcome path
    # (require_relation_resolution / relation_signer / require_relation_target). The successor issuer
    # key is the STATEMENT's own signing key (--pub). Plus the ONE standalone extension:
    # reject_retracted / reject_superseded fire on the statement's OWN verified assertion.
    if policy is not None and not isinstance(policy, dict):
        # RE-GATE never-raise (REGATE-CRYPTO-RELSTMT-POLICY / mirror decision.py + outcome.py): a caller-
        # supplied non-dict `policy` (a JSON scalar or list) must be a fail-closed policy verdict, not a raw
        # AttributeError from policy.get('relations'). A requested-but-malformed policy is never a silent pass.
        r["policy_ok"] = False
        r["errors"].append("trust policy must be a JSON object — malformed policy argument (fail-closed)")
    elif isinstance(policy, dict) and isinstance(policy.get("relations"), dict) and r["crypto_ok"]:
        import base64 as _b64  # noqa: PLC0415
        relations = policy["relations"]
        _viol = evaluate_relations_policy(
            relations, r.get("lineage") or {},
            successor_key_b64=_b64.b64encode(public_key).decode())
        # Standalone self-assertion gate (SPEC §2.5): a VERIFIED retracts/supersedes statement of a
        # (pinned/authorized) signer is a LIVE blocker for a relying party who asks "is my target still
        # safe for automation?". reject_retracted covers `retracts`; reject_superseded covers the
        # successor relations (supersedes/revises/corrects) — the same visible-state-not-crypto-kill
        # semantics as the in-receipt retracts-then-use vector.
        edges = (r.get("lineage") or {}).get("edges") or []
        edge0 = edges[0] if edges else {}
        rel0 = edge0.get("relation")
        resolved = edge0.get("resolution") == LINEAGE_VERIFIED
        if resolved and relations.get("reject_retracted") and rel0 in _SELF_ASSERTED_RETRACTORS:
            _viol = list(_viol) + [{
                "code": CODE_LINEAGE_REQUIREMENT_FAILED,
                "message": ("reject_retracted: a verified relation-statement RETRACTS the target; "
                            "the target stays crypto-valid for its bytes but is no longer safe for "
                            "automated use under this policy")}]
        if resolved and relations.get("reject_superseded") and rel0 in SUCCESSOR_RELATIONS:
            _viol = list(_viol) + [{
                "code": CODE_LINEAGE_REQUIREMENT_FAILED,
                "message": (f"reject_superseded: a verified relation-statement declares {rel0!r} over "
                            "the target; continued automated use of the target is blocked by this "
                            "policy (the target's crypto is untouched)")}]
        r["policy_ok"] = not _viol
        if _viol:
            r["relations_policy_failed"] = True
            for v in _viol:
                r["errors"].append(f"{v['code']}: {v['message']}")
            r["relations_policy_codes"] = sorted({v["code"] for v in _viol})

    r["ok"] = bool(
        r["crypto_ok"] and r["structure_ok"] and r["predicate_type_ok"]
        and r["subject_derived_ok"] is not False
        and r["lineage_ok"] is not False
        and r["policy_ok"] is not False)
    return r
