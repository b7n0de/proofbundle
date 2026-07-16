"""Decision Receipt predicate `decision-receipt/v0.1` — hand-rolled, fail-closed validation.

Vendored predicate under the b7n0de namespace (ADR 0001, Phase D / 2.1.0). This module validates the
`predicate` object of a Decision Receipt in-toto Statement. Like the rest of proofbundle it does NOT depend on
a runtime jsonschema library; `schemas/decision-receipt-v0.1.schema.json` is the external/docs schema, this
module is the enforced one. Fail-closed: unknown fields, missing required fields, bad enums, non-RFC3339-`Z`
timestamps and malformed digests are errors, never silently accepted.

Field names are lowerCamelCase (ITE-9); only the proofbundle-local trust policy is snake_case.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any, Callable

from ._strict_json import loads_strict
from .errors import BundleFormatError, ProofBundleError
from .subject_binding import nested_closure_violations

DECISION_RECEIPT_PREDICATE_TYPE = "https://b7n0de.com/proofbundle/predicates/decision-receipt/v0.1"
DECISION_SCHEMA_VERSION = "0.1.0"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
INTOTO_STATEMENT_PAYLOAD_TYPE = "application/vnd.in-toto+json"

# RFC3339 with a mandatory trailing Z (no generic timestamps, no offset forms).
_RFC3339_Z = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$")
_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
_SEMVER_0_1_X = re.compile(r"^0\.1\.\d+$")

_DECISION_TYPES = {"preActionAuthorization", "postHocReview", "humanEscalation", "policySimulation"}
_VERDICTS = {"ALLOW", "DENY", "REFUSE", "ESCALATE", "DEFER", "OBSERVE"}
_OUTCOME_STATUS = {"notAttempted", "blocked", "refused", "attempted", "executed", "failed", "unknown"}

# Top-level predicate fields required regardless of mode.
_REQUIRED_ALWAYS = (
    "schemaVersion", "decisionId", "decisionType", "decidedAt", "decisionMaker", "agent", "principal",
    "proposedAction", "inputSnapshot", "policyBoundary", "evidenceRefs", "decision",
)
# Additionally required in strict mode (§5.5: notChecked / decisionChangeConditions / privacy).
_REQUIRED_STRICT = _REQUIRED_ALWAYS + ("notChecked", "decisionChangeConditions", "privacy")
# Everything else that MAY appear (additionalProperties:false is enforced against this union).
# NOTE (Fix 2, proofbundle#7 self-reference resolution): `anchors` is DELIBERATELY NOT a predicate field.
# A decision anchor commits the content root = sha256 over the canonical Statement bytes — which would
# CONTAIN an in-predicate `anchors` field (chicken-and-egg, only resolvable by forbidden subset
# canonicalization). Anchor evidence for the statement's OWN root is carried DETACHED (a sibling of the
# DSSE envelope), verified against the content root. FOREIGN anchors (e.g. an evidence statement's own
# prereg anchor) are referenced indirectly via `evidenceRefs`. An `anchors` field inside the predicate is
# therefore a fail-closed unknown-field error.
_OPTIONAL = ("recordedAt", "delegationRefs", "actionOutcome", "traceContext", "validity",
             "notChecked", "decisionChangeConditions", "privacy", "relationships")
_ALLOWED_TOP = set(_REQUIRED_ALWAYS) | set(_OPTIONAL)

# Time-bearing paths that, if present, MUST be RFC3339-Z.
_TIME_PATHS = ("decidedAt", "recordedAt")

# Nested schema closure (Finding 04 / subject_binding.nested_closure_violations): a top-level
# additionalProperties:false does NOT, by itself, close these nested objects — an undeclared key inside one
# of them (e.g. `decision: {..., "sneaky": 1}`) previously rode along silently. Every path here was verified
# against the golden examples (examples/decision_receipt_{allow,deny,escalate}.json,
# decision_receipt_with_eval_ref.intoto.json) AND the `decision init` CLI template so this closure can never
# reject the repo's own reference material. `decisionMaker.version` is DELIBERATELY left undeclared — it is
# the versioned extensions container the module's own docstring describes as "the ONLY way to add fields".
_NESTED_ALLOWED: dict[str, tuple[str, ...]] = {
    "decisionMaker": ("id", "version"),
    "agent": ("id", "version", "configurationDigest"),
    "principal": ("id", "authnContextRef"),
    "principal.authnContextRef": ("uri", "digest"),
    "proposedAction": ("actionType", "target", "method", "parametersDigest", "parametersRef",
                       "parametersSchemaRef"),
    "proposedAction.target": ("name", "uri", "digest"),
    "proposedAction.parametersSchemaRef": ("uri", "digest"),
    "policyBoundary": ("policyEngine", "policyId", "policyDigest", "decisionPath", "bundleRevision",
                       "validFrom", "validUntil"),
    "evidenceRefs[]": ("relation", "digest", "artifactDigest", "uri", "predicateType"),
    "decision": ("verdict", "reasonCodes", "humanReadableSummary", "obligations", "allowedScope"),
    "notChecked[]": ("field", "reason", "impact"),
    "decisionChangeConditions[]": ("conditionType", "description", "requiredEvidenceType"),
    "actionOutcome": ("status", "performedAt", "outcomeRef"),
    "actionOutcome.outcomeRef": ("uri", "digest"),
    "privacy": ("rawInputsIncluded", "redactionProfile", "erased", "masked"),
    "validity": ("audience", "nonce", "expiresAt"),
    "inputSnapshot[]": ("name", "uri", "digest", "mediaType"),
}


class DecisionReceiptError(ProofBundleError):
    """A Decision Receipt predicate is malformed (fail-closed)."""


def _is_digest(obj: Any) -> bool:
    return isinstance(obj, dict) and isinstance(obj.get("sha256"), str) and bool(_SHA256_HEX.match(obj["sha256"]))


def validate_decision_predicate(predicate: Any, *, strict: bool = False) -> list[str]:
    """Return a list of human-readable errors; **empty list == valid**. Fail-closed.

    This function RETURNS its findings, it does NOT raise. Do NOT wrap it in
    ``try/except`` — a caller that treats "no exception" as "valid" will report a
    malformed predicate as valid (an empty ``except`` clause never fires because
    nothing is raised). Check the returned list instead::

        errors = validate_decision_predicate(pred)
        if errors:            # non-empty == invalid
            ...

    If you want an exception on the first invalid predicate, use
    :func:`require_valid_decision_predicate`, which raises ``DecisionReceiptError``.

    strict=True enforces the strict-v0.1 requirements (notChecked / decisionChangeConditions / privacy present,
    policyBoundary.policyDigest present, and — when `validity` is present — audience+nonce).
    """
    errors: list[str] = []
    if not isinstance(predicate, dict):
        return ["predicate must be a JSON object"]

    # additionalProperties: false — unknown top-level fields are rejected, never ignored.
    unknown = sorted(set(predicate) - _ALLOWED_TOP)
    if unknown:
        errors.append(f"unknown top-level field(s) {unknown} (decision receipt is fail-closed)")
    if "timestamp" in predicate:
        errors.append("generic 'timestamp' field is forbidden; use decidedAt/recordedAt/performedAt")

    required = _REQUIRED_STRICT if strict else _REQUIRED_ALWAYS
    for field in required:
        if field not in predicate:
            errors.append(f"missing required field '{field}'" + (" (strict)" if field not in _REQUIRED_ALWAYS else ""))

    # schemaVersion
    sv = predicate.get("schemaVersion")
    if sv is not None and (not isinstance(sv, str) or not _SEMVER_0_1_X.match(sv)):
        errors.append(f"schemaVersion must be a 0.1.x string, got {sv!r}")

    # decisionId (Finding 04, analogous to trustPackId in trust_pack.py): the required-field loop above only
    # checks PRESENCE — an int, a bool or an empty string previously satisfied "decisionId in predicate" and
    # passed silently.
    did = predicate.get("decisionId")
    if "decisionId" in predicate and not (isinstance(did, str) and did):
        errors.append(f"decisionId must be a non-empty string, got {did!r}")

    # decisionType enum
    dt = predicate.get("decisionType")
    if dt is not None and (not isinstance(dt, str) or dt not in _DECISION_TYPES):
        errors.append(f"decisionType must be one of {sorted(_DECISION_TYPES)}, got {dt!r}")

    # RFC3339-Z time fields
    for path in _TIME_PATHS:
        v = predicate.get(path)
        if v is not None and (not isinstance(v, str) or not _RFC3339_Z.match(v)):
            errors.append(f"{path} must be RFC3339 with trailing Z, got {v!r}")

    # decision.verdict + reasonCodes
    dec = predicate.get("decision")
    if isinstance(dec, dict):
        vd = dec.get("verdict")
        if not isinstance(vd, str) or vd not in _VERDICTS:
            errors.append(f"decision.verdict must be one of {sorted(_VERDICTS)}, got {vd!r}")
        rc = dec.get("reasonCodes")
        if not isinstance(rc, list) or not rc or not all(isinstance(x, str) for x in rc):
            errors.append("decision.reasonCodes must be a non-empty list of strings")
    elif "decision" in predicate:
        errors.append("decision must be a JSON object")

    # policyBoundary + strict policyDigest
    pb = predicate.get("policyBoundary")
    if isinstance(pb, dict):
        for k in ("policyEngine", "policyId", "decisionPath"):
            if not isinstance(pb.get(k), str) or not pb.get(k):
                errors.append(f"policyBoundary.{k} must be a non-empty string")
        if strict and not _is_digest(pb.get("policyDigest")):
            errors.append("policyBoundary.policyDigest with a sha256 is required in strict mode")
    elif "policyBoundary" in predicate:
        errors.append("policyBoundary must be a JSON object")

    # proposedAction inner shape (§6.2): actionType required + a digest OR a non-empty ref for the
    # parameters. Finding 04: a bare `{}` parametersRef previously satisfied `isinstance(..., dict)`
    # vacuously — `{}` is a dict but carries no actual reference.
    pa = predicate.get("proposedAction")
    if isinstance(pa, dict):
        if not isinstance(pa.get("actionType"), str) or not pa.get("actionType"):
            errors.append("proposedAction.actionType must be a non-empty string")
        pref = pa.get("parametersRef")
        pref_ok = isinstance(pref, dict) and bool(pref)
        if "parametersRef" in pa and not pref_ok:
            errors.append("proposedAction.parametersRef, when present, must be a non-empty object")
        if not (_is_digest(pa.get("parametersDigest")) or pref_ok):
            errors.append("proposedAction needs a sha256 parametersDigest or a non-empty parametersRef")
    elif "proposedAction" in predicate:
        errors.append("proposedAction must be a JSON object")

    # identity fields carry an id string each (matched to the DSSE signer via Trust Policy, never trusted
    # on the JSON claim alone — see policy.evaluate_decision_policy).
    for fld in ("decisionMaker", "agent", "principal"):
        obj = predicate.get(fld)
        if isinstance(obj, dict):
            if not isinstance(obj.get("id"), str) or not obj.get("id"):
                errors.append(f"{fld}.id must be a non-empty string")
        elif fld in predicate:
            errors.append(f"{fld} must be a JSON object")

    # inputSnapshot: a list of descriptors, each digest-bound (may also carry a uri/name/mediaType).
    isnap = predicate.get("inputSnapshot")
    if isinstance(isnap, list):
        for i, item in enumerate(isnap):
            if not isinstance(item, dict) or not _is_digest(item.get("digest")):
                errors.append(f"inputSnapshot[{i}] needs a sha256 'digest'")
    elif "inputSnapshot" in predicate:
        errors.append("inputSnapshot must be a list")

    # evidenceRefs (may be empty). Each ref is CONTENT-bound: `digest` is the content root of the referenced
    # evidence STATEMENT — sha256 over its RFC-8785 canonical statement bytes (the same rule as an anchor
    # root), NOT the enclosing envelope/file hash and NOT the bare predicate hash. Binding the content root
    # binds the claim's identity (incl. its subject + predicateType) and survives counter-signing / key
    # rotation of the evidence; WHO signed the evidence is a separate Trust-Policy question. Optional
    # `artifactDigest` pins an exact stored blob/envelope for retrieval. (proofbundle#7 consensus 2026-07-10.)
    ev = predicate.get("evidenceRefs")
    if isinstance(ev, list):
        for i, ref in enumerate(ev):
            if not isinstance(ref, dict) or not isinstance(ref.get("relation"), str) or not _is_digest(ref.get("digest")):
                errors.append(f"evidenceRefs[{i}] needs a string 'relation' and a sha256 content-root 'digest'")
            elif "artifactDigest" in ref and not _is_digest(ref.get("artifactDigest")):
                errors.append(f"evidenceRefs[{i}].artifactDigest, when present, must be a sha256 digest")
    elif "evidenceRefs" in predicate:
        errors.append("evidenceRefs must be a list")

    # actionOutcome (optional) — must be an object; status enum. Finding 04: a scalar (e.g. the bare
    # string "executed") previously skipped every check silently (the `isinstance(ao, dict)` guard simply
    # never entered the block, and nothing else objected to the wrong shape).
    ao = predicate.get("actionOutcome")
    if isinstance(ao, dict):
        st = ao.get("status")
        if not isinstance(st, str) or st not in _OUTCOME_STATUS:
            errors.append(f"actionOutcome.status must be one of {sorted(_OUTCOME_STATUS)}, got {st!r}")
    elif "actionOutcome" in predicate:
        errors.append("actionOutcome must be a JSON object")

    # validity — must be an object; strict interactive mode additionally requires audience + nonce when
    # present. Finding 04: a scalar validity previously passed the same way actionOutcome did.
    val = predicate.get("validity")
    if isinstance(val, dict):
        if strict:
            if not (isinstance(val.get("audience"), list) and val["audience"]):
                errors.append("validity.audience (non-empty list) is required in strict mode when validity is present")
            if not isinstance(val.get("nonce"), str) or not val.get("nonce"):
                errors.append("validity.nonce is required in strict mode when validity is present")
    elif "validity" in predicate:
        errors.append("validity must be a JSON object")

    # privacy inner shape: a bare {} must not pass strict — rawInputsIncluded is the field the policy's
    # allow_raw_inputs gate reads, so it MUST be an explicit boolean (§5.5 privacy).
    priv = predicate.get("privacy")
    if priv is not None and not isinstance(priv, dict):
        errors.append("privacy must be a JSON object")
    elif strict and isinstance(priv, dict) and not isinstance(priv.get("rawInputsIncluded"), bool):
        errors.append("privacy.rawInputsIncluded (boolean) is required in strict mode")

    # relationships (optional, relation/v0.1 EXPERIMENTAL): typed, SIGNED lineage edges to earlier
    # receipts — inside the predicate so the existing DSSE signature covers them (unlike detached
    # `anchors`). Edge closure/enums/digest shape are enforced by relation.validate_relationships
    # (fail-closed, incl. per-edge additionalProperties:false), so the block is NOT walked by the
    # generic nested-closure below.
    if "relationships" in predicate:
        from .relation import validate_relationships
        errors.extend(f"relationships: {e}" if not e.startswith("relationships") else e
                      for e in validate_relationships(predicate.get("relationships")))

    # Nested schema closure (Finding 04): additionalProperties:false at the TOP level does not, by itself,
    # close these nested objects — an undeclared key inside decision/policyBoundary/proposedAction/
    # decisionMaker/evidenceRefs[] (and their sub-objects) previously rode along silently.
    errors.extend(nested_closure_violations(predicate, _NESTED_ALLOWED))

    return errors


def require_valid_decision_predicate(predicate: Any, *, strict: bool = False) -> None:
    """Raise ``DecisionReceiptError`` if the predicate is invalid; return ``None`` if valid.

    A raising counterpart to :func:`validate_decision_predicate` for callers that prefer
    exception control flow. This exists because the list-returning validator is easy to
    misuse (``try: validate(...) ; except: ...`` silently passes every predicate, valid or
    not); use this wrapper when you want a real exception, or check the returned list
    directly — never wrap the list-returning form in ``try/except``.
    """
    errors = validate_decision_predicate(predicate, strict=strict)
    if errors:
        raise DecisionReceiptError(
            f"decision predicate has {len(errors)} finding(s): " + "; ".join(errors)
        )


def action_outcome_proven(predicate: Any) -> bool | None:
    """Whether `actionOutcome.status == executed` is backed by a signed/digest-bound outcomeRef.

    Returns None when there is no actionOutcome or the status is not 'executed' (not applicable), True when an
    executed outcome carries a sha256 outcomeRef, False when executed is self-asserted (the honesty limit)."""
    ao = predicate.get("actionOutcome") if isinstance(predicate, dict) else None
    if not isinstance(ao, dict) or ao.get("status") != "executed":
        return None
    ref = ao.get("outcomeRef")
    return isinstance(ref, dict) and _is_digest(ref.get("digest"))


def resolve_evidence_ref(ref: dict, *, evidence_payload: bytes | None = None,
                         artifact_bytes: bytes | None = None) -> dict:
    """Offline check of one ``evidenceRefs[]`` entry against resolved evidence (no network).

    ``evidence_payload`` is the EXACT DSSE payload bytes of the referenced evidence Statement — its content
    root is ``sha256`` over exactly these bytes, so the check is invariant under counter-signing / key
    rotation of the evidence (the payload does not change) and fails only when the evidence CONTENT changes.
    ``artifact_bytes`` is a fetched blob checked against the optional ``artifactDigest`` (exact retrieval
    pinning, a DIFFERENT question from claim identity). Returns ``{content_root_ok, artifact_ok, detail}``;
    a check that was not requested is ``None``. WHO signed the evidence is a Trust-Policy question, not this."""
    from . import anchors as _anchors_mod  # noqa: PLC0415
    out: dict[str, Any] = {"content_root_ok": None, "artifact_ok": None, "detail": ""}
    want = (ref.get("digest") or {}).get("sha256") if isinstance(ref, dict) else None
    if evidence_payload is not None:
        got = _anchors_mod.statement_content_root(evidence_payload).hex()
        out["content_root_ok"] = (got == want)
        if out["content_root_ok"] is False:
            out["detail"] = "evidence content root != evidenceRefs[].digest (evidence content changed?)"
    if artifact_bytes is not None and isinstance(ref, dict) and "artifactDigest" in ref:
        got_a = hashlib.sha256(artifact_bytes).hexdigest()
        out["artifact_ok"] = (got_a == (ref.get("artifactDigest") or {}).get("sha256"))
        if out["artifact_ok"] is False:
            out["detail"] = (out["detail"] + "; " if out["detail"] else "") + "artifactDigest != fetched blob"
    return out


# ── Emit / verify (DSSE in-toto Statement) ──────────────────────────────────
def _rfc8785_bytes(obj: Any) -> bytes:
    """RFC-8785 (JCS) canonical bytes of an in-toto Statement / predicate.

    Delegates to the shared ``canonical.canonicalize_statement`` primitive (ADR 0002) so decision.py,
    anchors.py and canonical.py compute the content root from ONE definition. A decision receipt's *content
    root* is defined over the RFC-8785 (JCS) canonical form (Fix 3 / proofbundle#7 consensus), so both emit
    and the hash_binding check use a REAL JCS canonicalizer rather than the bundle path's
    ``json.dumps(sort_keys=True)`` — which is not full JCS (it does not normalize number formatting or string
    escaping) and so cannot carry a stable content root. The canonicalizer (``rfc8785``, the ``[eval]`` extra)
    is imported lazily inside the shared primitive, so the base install and the plain no-anchor verify path
    stay dependency-free; a missing extra surfaces there as ``CanonicalizerUnavailable`` which we re-raise as
    the predicate-local ``DecisionReceiptError`` with the SAME message (never a raw ImportError — no
    behaviour change)."""
    from . import canonical  # noqa: PLC0415 — lazy: only the canonical/emit path pulls the JCS dependency
    try:
        return canonical.canonicalize_statement(obj)
    except canonical.CanonicalizerUnavailable as exc:
        raise DecisionReceiptError(
            "decision receipts need the RFC 8785 (JCS) canonicalizer — install proofbundle[eval]") from exc


def _rfc8785_available() -> bool:
    try:
        import rfc8785  # noqa: F401, PLC0415
        return True
    except Exception:
        return False


def build_decision_statement(predicate: dict, *, subject_name: str | None = None,
                             subject_sha256: str | None = None) -> dict:
    """Build a STANDARD in-toto Statement v1 whose predicate is the Decision Receipt. The subject is a
    commitment to the decision: by DEFAULT sha256 over the RFC-8785 canonical predicate.

    **Caller-attested override (No-Overclaim, 6-lens review):** a caller-supplied `subject_sha256` /
    `subject_name` is placed into `subject` verbatim and is NOT cross-checked against the predicate here;
    `verify_decision_receipt` likewise does not re-derive it. So a caller that overrides `subject_sha256`
    is self-attesting what the statement applies to — a generic in-toto consumer that matches by
    `subject.digest` (rather than re-hashing the predicate) trusts that value. Omit the override to keep
    the subject a true commitment to the signed predicate."""
    errs = validate_decision_predicate(predicate, strict=False)
    if errs:
        raise DecisionReceiptError("invalid decision predicate: " + "; ".join(errs))
    name = subject_name or f"decision:{predicate.get('decisionId', '')}"
    sha = subject_sha256 or hashlib.sha256(_rfc8785_bytes(predicate)).hexdigest()
    return {
        "_type": STATEMENT_TYPE,
        "subject": [{"name": name, "digest": {"sha256": sha}}],
        "predicateType": DECISION_RECEIPT_PREDICATE_TYPE,
        "predicate": predicate,
    }


def emit_decision_receipt(predicate: dict, signer, *, subject_name: str | None = None,
                          subject_sha256: str | None = None, keyid: str | None = None,
                          strict: bool = True) -> dict:
    """Sign a Decision Receipt as a DSSE-signed in-toto Statement. EMISSION is RFC-8785 canonical (Addendum
    §2.2). Fail-closed: an invalid predicate raises before signing."""
    from . import dsse  # noqa: PLC0415
    errs = validate_decision_predicate(predicate, strict=strict)
    if errs:
        raise DecisionReceiptError("invalid decision predicate: " + "; ".join(errs))
    statement = build_decision_statement(predicate, subject_name=subject_name, subject_sha256=subject_sha256)
    body = _rfc8785_bytes(statement)  # RFC-8785 emission
    return dsse.sign_envelope(body, signer, payload_type=INTOTO_STATEMENT_PAYLOAD_TYPE, keyid=keyid)


def _empty_result() -> dict:
    return {
        "ok": None, "structure_ok": None, "crypto_ok": None, "signer_trusted": None,
        "predicate_type_ok": None, "policy_ok": None, "evidence_bound": None, "audience_ok": None,
        "nonce_ok": None, "freshness_ok": None, "anchors_ok": None, "action_outcome_proven": None,
        "subject_binding": None, "subject_derived_ok": None,
        # Finding 01 / Finding 03 (2026-07 verify-layer hardening, additive): a uniform automation-safety
        # verdict (automation_verdict.automation_summary) and a per-digest EvidenceLevel classification
        # (assurance.classify_digest_evidence) computed at the end of verify — never gate anything on
        # these two here, the old ok/*_proven/evidence_bound fields above are UNCHANGED for compat.
        "automation": None, "evidence_levels": None,
        # relation/v0.1 (EXPERIMENTAL, additive): lineage verdict over the predicate's OPTIONAL
        # relationships edges — None until computed over AUTHENTICATED bytes; never gates `ok`.
        "lineage": None,
        "warnings": [], "errors": [],
    }


def verify_decision_receipt(envelope: dict, public_key: bytes, *, strict: bool = False,
                            expected_audience: str | None = None, expected_nonce: str | None = None,
                            policy: dict | None = None, anchors: list | None = None,
                            rp_trust: dict | None = None, require_derived_subject: bool = False,
                            evidence_resolver: Callable[[dict], bool] | None = None,
                            related: dict | None = None) -> dict:
    """Verify a DSSE-signed Decision Receipt. Crypto first, then structure over the EXACT signed bytes (never
    re-serialized). Returns the snake_case structured result; each check independent, non-applicable = None.

    **Read `ok` (or `crypto_ok`) — never an individual `*_ok` field alone.** `ok` is the aggregate
    verdict (crypto AND structure AND predicate-type AND every applicable trust check). The individual
    fields describe the payload only AFTER authentication: when `crypto_ok` is False the bytes are
    unauthenticated, so the trust-derived fields (`audience_ok`, `nonce_ok`, `evidence_bound`,
    `signer_trusted`, `policy_ok`, `action_outcome_proven`, `subject_derived_ok`) stay None — and
    `anchors_ok` is None, or False when anchors were supplied — and an error is recorded, so a consumer
    that reads e.g. `audience_ok` without checking `crypto_ok`/`ok` cannot read a claim about bytes nobody
    signed. The CLI gates its exit code on `crypto_ok` first (and reports `ok`).

    hash_binding (§7.1): the received payload MUST equal its own RFC-8785 canonicalization; a deviation is a
    fail-closed error (only checked when rfc8785 is importable, so plain verify stays dependency-free).

    Subject binding (Finding 05, mirrors outcome.py): `build_decision_statement` allows a caller to
    OVERRIDE `subject_sha256`, self-attested and NOT cross-checked there. This verify path now classifies
    the binding via `subject_binding.classify_subject` so a subject-rehang is never a ZERO-signal event: an
    `EXTERNAL_ATTESTED` subject is ALWAYS warned (`subject_binding`/`warnings`); `require_derived_subject`
    (opt-in, default False, preserving the documented override use) makes it a hard fail-closed error via
    `subject_derived_ok`.

    Detached anchors (Fix 2 / proofbundle#7): `anchors` is the DETACHED anchor evidence for the decision
    statement's OWN content root (sha256 over the exact signed payload bytes). It is NOT part of the signed
    predicate — an anchor cannot live inside the bytes whose hash it commits. It is verified against the
    content root via the shared anchors layer; `anchors_ok` is True (a full verifying anchor), False (a
    broken / root-mismatched / unknown-type anchor), or None (none supplied, pending-only, or crypto not
    established). Policy evaluation itself is `policy.evaluate_decision_policy` (WP5).

    `evidence_resolver` (Finding 03, additive, default None): an optional callable `f(digest_obj) -> bool`
    that checks a digest-bound field (`actionOutcome.outcomeRef`, each `evidenceRefs[]` entry) against
    ACTUALLY RESOLVED content — the missing wiring for `resolve_evidence_ref`, which existed but was never
    called from verify. When supplied, the corresponding `evidence_levels` entries reach
    `assurance.EvidenceLevel.CONTENT_RESOLVED` instead of stopping at `REFERENCE_WELL_FORMED` (a
    syntactically valid digest, attacker-choosable content). Never changes `action_outcome_proven` /
    `evidence_bound` (unchanged, additive) or the aggregate `ok`.

    `automation` (Finding 01, additive): a uniform `automationVerdict.automation_summary` verdict —
    `automation["safeForAutomation"]` requires `policy_ok IS True` (never merely `is not False`, unlike the
    permissive `ok` aggregate above) — see `automation_verdict.py`."""
    from . import dsse  # noqa: PLC0415
    from .budget import DEFAULT_BUDGET  # noqa: PLC0415
    r = _empty_result()

    r["crypto_ok"] = bool(dsse.verify_envelope(envelope, public_key, payload_type=INTOTO_STATEMENT_PAYLOAD_TYPE))
    if not r["crypto_ok"]:
        # errors[] must never be empty on a forged envelope — a consumer scanning errors[] for problems
        # would otherwise see none. The trust-derived fields below are also left None when crypto failed.
        r["errors"].append("DSSE signature verification failed — payload is unauthenticated")
    body = dsse.load_payload(envelope)  # EXACT bytes as signed — never re-serialize
    # Finding 15b: refuse an absurdly oversized payload BEFORE any JSON parsing/canonicalization work runs
    # (mirrors anchors_chia.py / hf_evals.py / statuslist.py's "cap before the expensive work" pattern).
    DEFAULT_BUDGET.check("input_bytes", len(body))
    try:
        # WP-C1: strict parse — a duplicated key (e.g. two `decision` objects) is rejected with a
        # clear fail-closed error instead of last-wins; the canonicality check would also catch it,
        # but only when the rfc8785 extra is installed.
        statement = loads_strict(body.decode("utf-8"))
    except BundleFormatError:
        r["structure_ok"] = False
        r["errors"].append("DSSE payload rejected (duplicate JSON key or malformed)")
        raise
    except (ValueError, UnicodeDecodeError) as exc:
        r["structure_ok"] = False
        r["errors"].append("DSSE payload is not a JSON in-toto Statement")
        raise BundleFormatError("DSSE payload is not a JSON in-toto Statement") from exc

    ptype = statement.get("predicateType") if isinstance(statement, dict) else None
    r["predicate_type_ok"] = ptype == DECISION_RECEIPT_PREDICATE_TYPE
    if not r["predicate_type_ok"]:
        r["errors"].append(f"predicateType is {ptype!r}, expected decision-receipt/v0.1 (confusion attack?)")

    predicate = statement.get("predicate") if isinstance(statement, dict) else None
    struct_errs = validate_decision_predicate(predicate, strict=strict)
    r["errors"].extend(struct_errs)

    # hash_binding: received bytes must BE their own RFC-8785 canonicalization (verify never re-canonicalizes).
    # Canonicality IS the core guarantee behind the content root, so in strict mode an absent canonicalizer is
    # fail-closed (structure_ok=False) — never a silent pass over possibly non-canonical bytes (the research
    # gap: without the extra the whole content-root invariant would be unenforced).
    canonical_ok = None
    if _rfc8785_available():
        try:
            canonical_ok = _rfc8785_bytes(statement) == body
        except Exception:
            canonical_ok = False
        if canonical_ok is False:
            r["errors"].append("payload is not RFC-8785 canonical (hash_binding fail-closed)")
    elif strict:
        r["errors"].append(
            "cannot verify RFC-8785 canonicality (install proofbundle[eval]); fail-closed in strict mode")
    else:
        r["warnings"].append("rfc8785 not installed: hash_binding canonicality not checked")

    canonicality_ok = canonical_ok is True or (canonical_ok is None and not strict)
    r["structure_ok"] = (not struct_errs) and bool(r["predicate_type_ok"]) and canonicality_ok

    # The predicate-derived fields describe AUTHENTICATED bytes only — never compute them over a payload
    # whose signature failed (mirrors the anchors/policy gates below). On a forged envelope they all stay
    # None, so a consumer can never read e.g. audience_ok=True or action_outcome_proven=True on bytes
    # nobody signed (fix-review: action_outcome_proven was computed pre-auth before).
    if isinstance(predicate, dict) and r["crypto_ok"]:
        r["action_outcome_proven"] = action_outcome_proven(predicate)
        if r["action_outcome_proven"] is False:
            r["warnings"].append("actionOutcome.status=executed is self-asserted (no signed outcomeRef)")
        ev = predicate.get("evidenceRefs")
        # None (not vacuous True) when there is nothing to bind — `all([])` is True, but "there are no
        # evidence refs" is not "the evidence is bound". Only digest-SHAPE is checked here; content
        # confirmation is a separate step (resolve_evidence_ref), never implied by evidence_bound.
        if isinstance(ev, list) and ev:
            r["evidence_bound"] = all(isinstance(x, dict) and _is_digest(x.get("digest")) for x in ev)

        # Finding 03 (additive): classify the SAME two digest-bound surfaces onto the EvidenceLevel ladder.
        # Never changes action_outcome_proven / evidence_bound above (those stay pure digest-presence
        # booleans for compat) — this is a STRICTER, more precise parallel view.
        from . import assurance as _assurance  # noqa: PLC0415
        ao = predicate.get("actionOutcome") if isinstance(predicate.get("actionOutcome"), dict) else None
        _ao_applicable = isinstance(ao, dict) and ao.get("status") == "executed"
        _outcome_level = _assurance.classify_digest_evidence(
            (ao or {}).get("outcomeRef"), applicable=_ao_applicable, evidence_resolver=evidence_resolver)
        _evref_levels = None
        if isinstance(ev, list) and ev:
            _evref_levels = _assurance.evidence_ladder_summary(*[
                _assurance.classify_digest_evidence(x.get("digest") if isinstance(x, dict) else None,
                                                    evidence_resolver=evidence_resolver)
                for x in ev
            ])
        r["evidence_levels"] = {
            "actionOutcome.outcomeRef": _outcome_level,
            "evidenceRefs": _evref_levels,
        }

        # relation/v0.1 (EXPERIMENTAL, additive): evaluate the OPTIONAL relationships edges against
        # caller-attached targets (`related`, offline — the CLI's --with-related). Computed ONLY over
        # authenticated bytes (this block), NEVER feeds `ok`/crypto (lattice monotonicity); a lineage
        # FAIL surfaces via errors[] and the policy layer, not by flipping the crypto verdict.
        if "relationships" in predicate or related:
            from . import anchors as _anchors_for_rel  # noqa: PLC0415
            from .relation import successor_warning, verify_relationship_edges  # noqa: PLC0415
            try:
                _subject_hex = _anchors_for_rel.statement_content_root(body).hex()
            except Exception:
                _subject_hex = None
            r["lineage"] = verify_relationship_edges(
                predicate.get("relationships"), related, subject_hex=_subject_hex)
            # Advisory by default; the policy's reject_superseded turns it into a blocker below.
            _sw = successor_warning(predicate.get("relationships"), related, subject_hex=_subject_hex)
            r["lineage"]["supersededByAttached"] = _sw
            if _sw:
                r["warnings"].append(f"lineage: {_sw}")
            if r["lineage"]["lineage"] == "FAIL":
                r["errors"].extend(r["lineage"]["errors"] or ["relation: lineage verification FAILED"])
        # 3.1.2 fail-closed fix (audit 2026-07-13, sibling of the eval-path F4 hardening and the decision
        # template/expiry gates): a relying party who supplies expected_audience/expected_nonce is ASKING for
        # RFC-9901-§7.3-style replay/audience binding. If the receipt carries NO validity object (or a
        # non-dict one), the previous `if isinstance(val, dict):` guard SKIPPED the checks entirely →
        # audience_ok/nonce_ok stayed None → the CLI exit gate (None is not False) let it pass exit 0: a
        # requested binding silently unenforced (fail-OPEN downgrade). Evaluate against {} instead, so an
        # absent validity/audience/nonce is a FAIL (fail-closed), never a silent pass.
        _val = predicate.get("validity")
        _validity = _val if isinstance(_val, dict) else {}
        if expected_audience is not None:
            # audience MUST be a real JSON array: with a STRING value Python's `in` degrades to
            # SUBSTRING matching ("rp.example" in "rp.example" is True) — a wrong-TYPE audience
            # would satisfy the binding (found by the 3.1.3 regression corpus, fail-closed now).
            _aud = _validity.get("audience")
            r["audience_ok"] = isinstance(_aud, list) and expected_audience in _aud
            if not r["audience_ok"]:
                r["errors"].append(
                    "audience mismatch or absent validity.audience — requested audience binding cannot be "
                    "enforced (cross-audience replay?, fail-closed)")
        if expected_nonce is not None:
            r["nonce_ok"] = _validity.get("nonce") == expected_nonce
            if not r["nonce_ok"]:
                r["errors"].append(
                    "nonce mismatch or absent validity.nonce — requested replay binding cannot be enforced "
                    "(replay?, fail-closed)")

    # Subject binding (Finding 05, release-review #4 parity with outcome.py): classify whether the subject
    # genuinely commits to the predicate so a consumer never gets ZERO signal on a subject-rehang override.
    # An EXTERNAL_ATTESTED subject is ALWAYS warned; require_derived_subject makes it a hard fail-closed
    # error (opt-in, preserves the documented build_decision_statement override use).
    if isinstance(statement, dict) and r["crypto_ok"]:
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
                        "subject is EXTERNAL_ATTESTED — it does not commit to this predicate (subject-rehang); "
                        "trust it only via a policy that pins the external attester")
                if require_derived_subject:
                    r["subject_derived_ok"] = _cls["matches"]
                    if not _cls["matches"]:
                        r["errors"].append(
                            "require_derived_subject: subject is not a DERIVED commitment to the predicate "
                            "(fail-closed)")
            elif require_derived_subject:
                # classify_subject raised (e.g. a predicate the JCS canonicalizer rejects). Do NOT silently
                # pass the gate on a coincidence elsewhere — make the fail-closed explicit.
                r["subject_derived_ok"] = False
                r["errors"].append(
                    "require_derived_subject: could not classify the subject binding (canonicalization raised) "
                    "— fail-closed")
        elif require_derived_subject:
            r["subject_derived_ok"] = False
            r["errors"].append(
                "require_derived_subject but RFC-8785 canonicalizer unavailable — cannot verify subject "
                "derivation (install proofbundle[eval]), fail-closed")

    # Detached anchors (Fix 2): verify anchor evidence for the statement's OWN content root — sha256 over the
    # EXACT signed payload bytes (never re-canonicalized), computed only once the bytes are authentic+canonical.
    _dr_section = policy.get("decision_receipt") if isinstance(policy, dict) else None
    _wants_anchor = isinstance(_dr_section, dict) and bool(_dr_section.get("require_external_anchor"))
    anchor_status = None
    if anchors is not None or _wants_anchor:
        if not (r["crypto_ok"] and canonical_ok is not False):
            anchor_status = "FAIL"
            r["anchors_ok"] = False
            r["errors"].append(
                "cannot verify anchors: payload is not authentic + RFC-8785 canonical (fail-closed)")
        else:
            from . import anchors as _anchors_mod  # noqa: PLC0415
            content_root = _anchors_mod.statement_content_root(body)
            # WP-A1: thread the relying-party trust material so a real OTS/rfc3161 statement anchor can
            # confirm here (the bundle's frozen material is never trust). Without it a time anchor is
            # needs_rp_trust — fail-closed, not a silent frozen pass.
            ar = _anchors_mod.verify_anchors(anchors or [], target_roots={"statement": content_root},
                                             rp_trust=rp_trust)
            # Per-anchor, not the aggregate: a broken/unknown anchor is fail-closed (a tamper signal), but a
            # FULL verifying anchor satisfies the obligation even when bundled with a pending one — the
            # aggregate WARN would otherwise wrongly reject a receipt that DOES carry a full time anchor.
            _results = ar.get("results") or []
            _has_fail = any(not x["ok"] and not x["warn"] for x in _results)
            _has_full = any(x["ok"] and not x["warn"] for x in _results)
            _has_pending = any(x["warn"] for x in _results)
            anchor_status = ("FAIL" if _has_fail else "PASS" if _has_full
                             else "WARN" if _has_pending else ar["status"])
            r["anchors_ok"] = (True if anchor_status == "PASS"
                               else False if anchor_status == "FAIL" else None)
            if anchor_status == "WARN":
                r["warnings"].append(
                    f"anchor(s) pending / inclusion-only — not a full time anchor: {ar['detail']}")
            elif anchor_status == "FAIL":
                r["errors"].append(f"anchor verification failed: {ar['detail']}")

    # Trust policy (v0.2 decision_receipt section) over the CRYPTO-VERIFIED statement. WP5. A policy is NEVER
    # evaluated on unverified bytes (fail-open fix, mirrors the eval path): if crypto did not pass, policy_ok
    # and signer_trusted stay None — a policy is never a reason to trust bytes whose signature failed.
    if policy is not None and isinstance(predicate, dict):
        if not r["crypto_ok"]:
            r["warnings"].append("crypto verification did not pass — trust policy not evaluated")
        else:
            import base64  # noqa: PLC0415
            from .policy import evaluate_decision_policy  # noqa: PLC0415
            pe = evaluate_decision_policy(statement, r, policy,
                                          signer_public_key_b64=base64.b64encode(public_key).decode(),
                                          anchor_status=anchor_status)
            r["policy_ok"] = pe["policy_ok"]
            r["signer_trusted"] = pe["signer_trusted"]
            r["errors"].extend(pe["errors"])
            # Honesty warning — a decision policy that constrains the verdict/type but pins NO
            # trusted_decision_makers means POLICY: OK proves integrity by an UNKNOWN signer.
            # DECISION-SPECIFIC (fix-review): the shared policy_warnings()/_attributes_to_nobody also
            # counts allowed_issuers / signature.require_expected_signer as "pins a signer" — but those
            # are EVAL-bundle concepts that evaluate_decision_policy never reads, so an orthogonal
            # allowed_issuers block in a v0.2 policy would wrongly suppress this warning for a decision
            # receipt signed by anyone. Gate solely on decision_receipt.trusted_decision_makers here.
            _dr = policy.get("decision_receipt")
            if isinstance(_dr, dict) and not _dr.get("trusted_decision_makers"):
                r["warnings"].append(
                    "attributes to nobody: the policy pins no decision maker (no "
                    "decision_receipt.trusted_decision_makers) — POLICY: OK then proves integrity by an "
                    "UNKNOWN signer. Pin the expected decision-maker key(s).")

    # relation/v0.1 policy gate (relations section, LIVE): a violation fails policy_ok (exit-3 class)
    # and raises the dedicated automation blocker LINEAGE_REQUIREMENT_FAILED below — it NEVER touches
    # the crypto verdict (lattice monotonicity). require_relation_resolution is conditional on
    # presence: a named relation that appears as an edge MUST be VERIFIED (attached + standalone-
    # verified); an absent relation is no violation.
    if policy is not None and isinstance(policy.get("relations"), dict) and r["crypto_ok"]:
        _rel_pol = policy["relations"]
        _lin = r.get("lineage") or {}
        _viol = []
        _req = _rel_pol.get("require_relation_resolution") or []
        for _e in (_lin.get("edges") or []):
            if _e.get("relation") in _req and _e.get("resolution") != "VERIFIED":
                _viol.append(f"relation {_e.get('relation')!r} must resolve (target attached and "
                             f"verified), got {_e.get('resolution')}")
        if _rel_pol.get("reject_superseded") and _lin.get("supersededByAttached"):
            _viol.append(f"reject_superseded: {_lin['supersededByAttached']}")
        if _viol:
            r["policy_ok"] = False
            r["lineage_requirement_failed"] = True
            r["errors"].extend("LINEAGE_REQUIREMENT_FAILED: " + v for v in _viol)

    # Aggregate verdict: authenticated AND well-structured AND no applicable trust check FAILED.
    # None means not-applicable (passes); only an explicit False fails the aggregate.
    r["ok"] = bool(
        r["crypto_ok"] and r["structure_ok"] and r["predicate_type_ok"]
        and r["policy_ok"] is not False and r["signer_trusted"] is not False
        and r["audience_ok"] is not False and r["nonce_ok"] is not False
        and r["evidence_bound"] is not False and r["anchors_ok"] is not False
        and r["subject_derived_ok"] is not False)

    # Finding 01 (additive): the STRICTER automation-safety verdict — policy_ok must be True, never merely
    # "not False" — never changes `ok` above.
    from .automation_verdict import automation_summary  # noqa: PLC0415
    r["automation"] = automation_summary(r, required_checks={
        "crypto": "crypto_ok", "structure": "structure_ok", "policy": "policy_ok",
        "references": ["evidence_bound", "audience_ok", "nonce_ok", "anchors_ok", "subject_derived_ok"],
    })
    # relation/v0.1: the dedicated blocker name (LIVE, not dormant) — POLICY_FAILED already fires via
    # policy_ok=False above; this names the REASON so a consumer can distinguish a lineage gate from
    # any other policy failure. Only ever ADDS a blocker (never turns safeForAutomation true).
    if r.get("lineage_requirement_failed") and isinstance(r.get("automation"), dict):
        blockers = r["automation"].setdefault("automationBlockers", [])
        if "LINEAGE_REQUIREMENT_FAILED" not in blockers:
            blockers.append("LINEAGE_REQUIREMENT_FAILED")
        r["automation"]["safeForAutomation"] = False
    return r
