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
import json
import re
from typing import Any

from .errors import BundleFormatError, ProofBundleError

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
_OPTIONAL = ("recordedAt", "delegationRefs", "actionOutcome", "traceContext", "validity", "anchors",
             "notChecked", "decisionChangeConditions", "privacy")
_ALLOWED_TOP = set(_REQUIRED_ALWAYS) | set(_OPTIONAL)

# Time-bearing paths that, if present, MUST be RFC3339-Z.
_TIME_PATHS = ("decidedAt", "recordedAt")


class DecisionReceiptError(ProofBundleError):
    """A Decision Receipt predicate is malformed (fail-closed)."""


def _is_digest(obj: Any) -> bool:
    return isinstance(obj, dict) and isinstance(obj.get("sha256"), str) and bool(_SHA256_HEX.match(obj["sha256"]))


def validate_decision_predicate(predicate: Any, *, strict: bool = False) -> list[str]:
    """Return a list of human-readable errors; empty list == valid. Fail-closed.

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

    # decisionType enum
    dt = predicate.get("decisionType")
    if dt is not None and dt not in _DECISION_TYPES:
        errors.append(f"decisionType must be one of {sorted(_DECISION_TYPES)}, got {dt!r}")

    # RFC3339-Z time fields
    for path in _TIME_PATHS:
        v = predicate.get(path)
        if v is not None and (not isinstance(v, str) or not _RFC3339_Z.match(v)):
            errors.append(f"{path} must be RFC3339 with trailing Z, got {v!r}")

    # decision.verdict + reasonCodes
    dec = predicate.get("decision")
    if isinstance(dec, dict):
        if dec.get("verdict") not in _VERDICTS:
            errors.append(f"decision.verdict must be one of {sorted(_VERDICTS)}, got {dec.get('verdict')!r}")
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

    # evidenceRefs list (may be empty; each ref digest-bound)
    ev = predicate.get("evidenceRefs")
    if isinstance(ev, list):
        for i, ref in enumerate(ev):
            if not isinstance(ref, dict) or not isinstance(ref.get("relation"), str) or not _is_digest(ref.get("digest")):
                errors.append(f"evidenceRefs[{i}] needs a string 'relation' and a sha256 'digest'")
    elif "evidenceRefs" in predicate:
        errors.append("evidenceRefs must be a list")

    # actionOutcome (optional) — status enum
    ao = predicate.get("actionOutcome")
    if isinstance(ao, dict) and ao.get("status") not in _OUTCOME_STATUS:
        errors.append(f"actionOutcome.status must be one of {sorted(_OUTCOME_STATUS)}, got {ao.get('status')!r}")

    # validity — strict interactive requires audience + nonce when present
    val = predicate.get("validity")
    if isinstance(val, dict) and strict:
        if not (isinstance(val.get("audience"), list) and val["audience"]):
            errors.append("validity.audience (non-empty list) is required in strict mode when validity is present")
        if not isinstance(val.get("nonce"), str) or not val.get("nonce"):
            errors.append("validity.nonce is required in strict mode when validity is present")

    return errors


def action_outcome_proven(predicate: Any) -> bool | None:
    """Whether `actionOutcome.status == executed` is backed by a signed/digest-bound outcomeRef.

    Returns None when there is no actionOutcome or the status is not 'executed' (not applicable), True when an
    executed outcome carries a sha256 outcomeRef, False when executed is self-asserted (the honesty limit)."""
    ao = predicate.get("actionOutcome") if isinstance(predicate, dict) else None
    if not isinstance(ao, dict) or ao.get("status") != "executed":
        return None
    ref = ao.get("outcomeRef")
    return isinstance(ref, dict) and _is_digest(ref.get("digest"))


# ── Emit / verify (DSSE in-toto Statement) ──────────────────────────────────
def _rfc8785_bytes(obj: Any) -> bytes:
    """RFC-8785 (JCS) canonical bytes. Addendum §2.2: decision receipts emit in RFC-8785 canonical form (the
    eval-result path uses sort_keys; decision emit deliberately diverges). rfc8785 lives in the `[eval]` extra,
    so this is imported lazily — the plain verify core stays dependency-free."""
    import rfc8785  # noqa: PLC0415
    return rfc8785.dumps(obj)


def _rfc8785_available() -> bool:
    try:
        import rfc8785  # noqa: F401, PLC0415
        return True
    except Exception:
        return False


def build_decision_statement(predicate: dict, *, subject_name: str | None = None,
                             subject_sha256: str | None = None) -> dict:
    """Build a STANDARD in-toto Statement v1 whose predicate is the Decision Receipt. The subject is a
    commitment to the decision (default: sha256 over the RFC-8785 canonical predicate)."""
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
        "structure_ok": None, "crypto_ok": None, "signer_trusted": None, "predicate_type_ok": None,
        "policy_ok": None, "evidence_bound": None, "audience_ok": None, "nonce_ok": None,
        "freshness_ok": None, "anchors_ok": None, "action_outcome_proven": None,
        "warnings": [], "errors": [],
    }


def verify_decision_receipt(envelope: dict, public_key: bytes, *, strict: bool = False,
                            expected_audience: str | None = None, expected_nonce: str | None = None,
                            policy: dict | None = None) -> dict:
    """Verify a DSSE-signed Decision Receipt. Crypto first, then structure over the EXACT signed bytes (never
    re-serialized). Returns the snake_case structured result; each check independent, non-applicable = None.

    hash_binding (§7.1): the received payload MUST equal its own RFC-8785 canonicalization; a deviation is a
    fail-closed error (only checked when rfc8785 is importable, so plain verify stays dependency-free).
    Policy evaluation is not done here (WP5: `policy.evaluate_decision_policy`)."""
    from . import dsse  # noqa: PLC0415
    r = _empty_result()

    r["crypto_ok"] = bool(dsse.verify_envelope(envelope, public_key, payload_type=INTOTO_STATEMENT_PAYLOAD_TYPE))
    body = dsse.load_payload(envelope)  # EXACT bytes as signed — never re-serialize
    try:
        statement = json.loads(body.decode("utf-8"))
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
    canonical_ok = None
    if _rfc8785_available():
        try:
            canonical_ok = _rfc8785_bytes(statement) == body
        except Exception:
            canonical_ok = False
        if canonical_ok is False:
            r["errors"].append("payload is not RFC-8785 canonical (hash_binding fail-closed)")
    else:
        r["warnings"].append("rfc8785 not installed: hash_binding canonicality not checked")

    r["structure_ok"] = (not struct_errs) and bool(r["predicate_type_ok"]) and (canonical_ok is not False)

    if isinstance(predicate, dict):
        ev = predicate.get("evidenceRefs")
        r["evidence_bound"] = isinstance(ev, list) and all(
            isinstance(x, dict) and _is_digest(x.get("digest")) for x in ev)
        r["action_outcome_proven"] = action_outcome_proven(predicate)
        if r["action_outcome_proven"] is False:
            r["warnings"].append("actionOutcome.status=executed is self-asserted (no signed outcomeRef)")
        val = predicate.get("validity")
        if isinstance(val, dict):
            if expected_audience is not None:
                r["audience_ok"] = expected_audience in (val.get("audience") or [])
                if not r["audience_ok"]:
                    r["errors"].append("audience mismatch (cross-audience replay?)")
            if expected_nonce is not None:
                r["nonce_ok"] = val.get("nonce") == expected_nonce
                if not r["nonce_ok"]:
                    r["errors"].append("nonce mismatch (replay?)")

    # Trust policy (v0.2 decision_receipt section) over the crypto-verified statement. WP5.
    if policy is not None and isinstance(predicate, dict):
        import base64  # noqa: PLC0415
        from .policy import evaluate_decision_policy  # noqa: PLC0415
        pe = evaluate_decision_policy(statement, r, policy,
                                      signer_public_key_b64=base64.b64encode(public_key).decode())
        r["policy_ok"] = pe["policy_ok"]
        r["signer_trusted"] = pe["signer_trusted"]
        r["errors"].extend(pe["errors"])

    return r
