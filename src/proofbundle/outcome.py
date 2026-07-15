"""Action Outcome Receipt predicate `action-outcome/v0.1` — hand-rolled, fail-closed validation.

The core of proofbundle 3.2.0 (EXPERIMENTAL). Third link of the receipt chain
``eval-result → decision-receipt → action-outcome``: an EXECUTOR (a policy role distinct from the
decisionMaker) signs what was actually done, bound by digest to a Decision Receipt (``decisionRef``).

Like the rest of proofbundle it does NOT depend on a runtime jsonschema library;
``schemas/action-outcome-v0.1.schema.json`` is the external/docs schema, this module is the enforced one.
Fail-closed: unknown fields, missing required fields, bad enums, non-RFC3339-``Z`` timestamps and malformed
digests are errors, never silently accepted.

No-Overclaim (§1.4): ``status == executed`` attests only WHO signed WHAT happened, never that the effect was
good, correct or desired. Role separation (executor ≠ decisionMaker) is ENFORCED at verify time when the
bound decision's maker id is supplied, not merely recommended.

Field names are lowerCamelCase (ITE-9).
"""
from __future__ import annotations

import hashlib
import re
from typing import Any

from ._strict_json import loads_strict
from .errors import BundleFormatError, ProofBundleError
from .subject_binding import nested_closure_violations

ACTION_OUTCOME_PREDICATE_TYPE = "https://b7n0de.com/proofbundle/predicates/action-outcome/v0.1"
OUTCOME_SCHEMA_VERSION = "0.1.0"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
INTOTO_STATEMENT_PAYLOAD_TYPE = "application/vnd.in-toto+json"

_RFC3339_Z = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$")
_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
_SEMVER_0_1_X = re.compile(r"^0\.1\.\d+$")

_OUTCOME_STATUS = {"executed", "refused", "failed", "partial"}
_OUTCOME_POLICY_PURPOSE = "outcome"

_REQUIRED_ALWAYS = (
    "schemaVersion", "outcomeId", "decisionRef", "executor", "requestedActionDigest",
    "status", "performedAt",
)
_OPTIONAL = ("actualActionDigest", "responseDigest", "effectDigest", "recordedAt", "policyPurpose",
             "traceContext", "limitations", "validity")
_ALLOWED_TOP = set(_REQUIRED_ALWAYS) | set(_OPTIONAL)

_DIGEST_FIELDS = ("requestedActionDigest", "actualActionDigest", "responseDigest", "effectDigest")
_TIME_PATHS = ("performedAt", "recordedAt")

# Nested schema closure (Finding 04 / subject_binding.nested_closure_violations): a top-level
# additionalProperties:false does NOT, by itself, close traceContext/validity — an undeclared key inside
# one of them previously rode along silently. Verified against `outcome init`'s CLI template
# (traceContext={"traceparent": ""}) and tests/test_outcome_verify.py's validity={"audience", "nonce"}.
_NESTED_ALLOWED: dict[str, tuple[str, ...]] = {
    "traceContext": ("traceparent",),
    "validity": ("audience", "nonce"),
}


class OutcomeReceiptError(ProofBundleError):
    """An Action Outcome Receipt predicate is malformed (fail-closed)."""


def _is_digest(obj: Any) -> bool:
    return isinstance(obj, dict) and isinstance(obj.get("sha256"), str) and bool(_SHA256_HEX.match(obj["sha256"]))


def validate_outcome_predicate(predicate: Any, *, strict: bool = False) -> list[str]:
    """Return a list of fail-closed errors for an ``action-outcome/v0.1`` predicate (empty = valid).

    strict currently adds no extra required fields beyond _REQUIRED_ALWAYS (the outcome predicate is small and
    fully required by default); the flag is kept for signature parity with decision.py and future §-gates."""
    errors: list[str] = []
    if not isinstance(predicate, dict):
        return ["predicate must be a JSON object"]

    # additionalProperties:false — any unknown top-level key is fail-closed.
    for k in predicate:
        if k not in _ALLOWED_TOP:
            errors.append(f"unknown field {k!r} (additionalProperties:false)")

    for req in _REQUIRED_ALWAYS:
        if req not in predicate:
            errors.append(f"missing required field {req!r}")

    sv = predicate.get("schemaVersion")
    if "schemaVersion" in predicate and not (isinstance(sv, str) and _SEMVER_0_1_X.match(sv)):
        errors.append("schemaVersion must match 0.1.x")

    oid = predicate.get("outcomeId")
    if "outcomeId" in predicate and not (isinstance(oid, str) and oid):
        errors.append("outcomeId must be a non-empty string")

    # decisionRef binds to the Decision Receipt content root (a sha256 digest object).
    if "decisionRef" in predicate and not _is_digest(predicate.get("decisionRef")):
        errors.append("decisionRef must be a sha256 digest object (content root of the bound decision)")

    ex = predicate.get("executor")
    if "executor" in predicate:
        if not isinstance(ex, dict) or not isinstance(ex.get("id"), str) or not ex.get("id"):
            errors.append("executor must be an object with a non-empty string 'id'")
        else:
            for k in ex:
                if k not in ("id", "keyId"):
                    errors.append(f"executor.{k} is not an allowed field")
            if "keyId" in ex and not isinstance(ex.get("keyId"), str):
                errors.append("executor.keyId, when present, must be a string")

    for df in _DIGEST_FIELDS:
        if df in predicate and not _is_digest(predicate.get(df)):
            errors.append(f"{df}, when present, must be a sha256 digest object")

    st = predicate.get("status")
    if "status" in predicate and st not in _OUTCOME_STATUS:
        errors.append(f"status must be one of {sorted(_OUTCOME_STATUS)}, got {st!r}")

    for tp in _TIME_PATHS:
        v = predicate.get(tp)
        if tp in predicate and not (isinstance(v, str) and _RFC3339_Z.match(v)):
            errors.append(f"{tp} must be an RFC3339 UTC 'Z' timestamp")

    # policyPurpose (optional): when present it MUST be exactly 'outcome' — a wrong purpose is a
    # confusion/misrouting signal, fail-closed (the CLI maps this to exit 3).
    if "policyPurpose" in predicate and predicate.get("policyPurpose") != _OUTCOME_POLICY_PURPOSE:
        errors.append(
            f"policyPurpose must be {_OUTCOME_POLICY_PURPOSE!r} for an outcome receipt, "
            f"got {predicate.get('policyPurpose')!r}")

    lim = predicate.get("limitations")
    if "limitations" in predicate and not (isinstance(lim, list) and all(isinstance(x, str) for x in lim)):
        errors.append("limitations must be a list of strings")

    tc = predicate.get("traceContext")
    if "traceContext" in predicate and not isinstance(tc, dict):
        errors.append("traceContext must be an object")

    # validity (Finding 04): previously had NO structural check at all — a scalar validity (e.g. the bare
    # string "n-1") silently reached verify_outcome_receipt, which only guards with
    # `_val if isinstance(_val, dict) else {}` and so treated it as an absent validity object without ever
    # flagging the malformed shape.
    val = predicate.get("validity")
    if "validity" in predicate and not isinstance(val, dict):
        errors.append("validity must be an object")

    # Nested schema closure (Finding 04): additionalProperties:false at the TOP level does not, by itself,
    # close traceContext/validity — an undeclared key inside either previously rode along silently.
    errors.extend(nested_closure_violations(predicate, _NESTED_ALLOWED))

    return errors


def require_valid_outcome_predicate(predicate: Any, *, strict: bool = False) -> None:
    """Raise :class:`OutcomeReceiptError` if the predicate is invalid; return ``None`` if valid."""
    errs = validate_outcome_predicate(predicate, strict=strict)
    if errs:
        raise OutcomeReceiptError("invalid action-outcome predicate: " + "; ".join(errs))


def outcome_execution_proven(predicate: Any) -> bool | None:
    """Whether ``status == executed`` is backed by a digest of what was actually done/effected.

    Returns None when status is not 'executed' (not applicable), True when an executed outcome carries an
    ``effectDigest`` or ``actualActionDigest`` (a digest of the real effect/action), False when 'executed' is
    self-asserted with no such digest (the honesty limit — a signed claim, not proof of the effect)."""
    if not isinstance(predicate, dict) or predicate.get("status") != "executed":
        return None
    return _is_digest(predicate.get("effectDigest")) or _is_digest(predicate.get("actualActionDigest"))


# ── Emit / verify (DSSE in-toto Statement) ──────────────────────────────────
def _rfc8785_bytes(obj: Any) -> bytes:
    """RFC-8785 (JCS) canonical bytes — shared ``canonical.canonicalize_statement`` primitive (ADR 0002), so
    the content root is computed from ONE definition. A missing ``[eval]`` extra surfaces as the predicate-
    local :class:`OutcomeReceiptError` (never a raw ImportError)."""
    from . import canonical  # noqa: PLC0415
    try:
        return canonical.canonicalize_statement(obj)
    except canonical.CanonicalizerUnavailable as exc:
        raise OutcomeReceiptError(
            "outcome receipts need the RFC 8785 (JCS) canonicalizer — install proofbundle[eval]") from exc


def _rfc8785_available() -> bool:
    try:
        import rfc8785  # noqa: F401, PLC0415
        return True
    except Exception:
        return False


def build_outcome_statement(predicate: dict, *, subject_name: str | None = None,
                            subject_sha256: str | None = None) -> dict:
    """Build a STANDARD in-toto Statement v1 whose predicate is the Outcome Receipt. The subject is by DEFAULT
    a commitment to the predicate: sha256 over its RFC-8785 canonical form. A caller-supplied override is
    self-attested and NOT cross-checked (No-Overclaim, same discipline as build_decision_statement)."""
    errs = validate_outcome_predicate(predicate, strict=False)
    if errs:
        raise OutcomeReceiptError("invalid action-outcome predicate: " + "; ".join(errs))
    name = subject_name or f"outcome:{predicate.get('outcomeId', '')}"
    sha = subject_sha256 or hashlib.sha256(_rfc8785_bytes(predicate)).hexdigest()
    return {
        "_type": STATEMENT_TYPE,
        "subject": [{"name": name, "digest": {"sha256": sha}}],
        "predicateType": ACTION_OUTCOME_PREDICATE_TYPE,
        "predicate": predicate,
    }


def emit_outcome_receipt(predicate: dict, signer, *, subject_name: str | None = None,
                         subject_sha256: str | None = None, keyid: str | None = None,
                         strict: bool = True) -> dict:
    """Sign an Outcome Receipt as a DSSE-signed in-toto Statement. Emission is RFC-8785 canonical. Fail-closed:
    an invalid predicate raises before signing."""
    from . import dsse  # noqa: PLC0415
    errs = validate_outcome_predicate(predicate, strict=strict)
    if errs:
        raise OutcomeReceiptError("invalid action-outcome predicate: " + "; ".join(errs))
    statement = build_outcome_statement(predicate, subject_name=subject_name, subject_sha256=subject_sha256)
    body = _rfc8785_bytes(statement)
    return dsse.sign_envelope(body, signer, payload_type=INTOTO_STATEMENT_PAYLOAD_TYPE, keyid=keyid)


def _empty_result() -> dict:
    return {
        "ok": None, "structure_ok": None, "crypto_ok": None,
        "predicate_type_ok": None, "decision_bound": None, "role_separation_ok": None,
        "execution_proven": None, "audience_ok": None, "nonce_ok": None,
        "subject_binding": None, "subject_derived_ok": None,
        "warnings": [], "errors": [],
    }


def verify_outcome_receipt(envelope: dict, public_key: bytes, *, strict: bool = False,
                           expected_decision_ref: str | None = None, decision_maker_id: str | None = None,
                           expected_audience: str | None = None, expected_nonce: str | None = None,
                           require_derived_subject: bool = False) -> dict:
    """Verify a DSSE-signed Outcome Receipt. Crypto first, then structure over the EXACT signed bytes.

    Outcome-specific fail-closed checks (each applies only after crypto passes; non-applicable = None):

    - ``decision_bound`` — when ``expected_decision_ref`` is supplied, the predicate's ``decisionRef.sha256``
      MUST equal it. Replay of an outcome against a DIFFERENT decision fails (False + error).
    - ``role_separation_ok`` — when ``decision_maker_id`` is supplied, the executor's id MUST differ from it.
      An executor witnessing their own decision fails (False + error).
    - ``execution_proven`` — status=executed with a real effect/action digest is True; self-asserted executed
      is False + a No-Overclaim warning (not a hard aggregate fail — it is an honest limit, not tampering).

    Read ``ok`` (or ``crypto_ok``) — never an individual ``*_ok`` alone. On a forged envelope every trust-
    derived field stays None and an error is recorded, so a consumer cannot read a claim about unsigned bytes.
    """
    from . import dsse  # noqa: PLC0415
    r = _empty_result()

    r["crypto_ok"] = bool(dsse.verify_envelope(envelope, public_key, payload_type=INTOTO_STATEMENT_PAYLOAD_TYPE))
    if not r["crypto_ok"]:
        r["errors"].append("DSSE signature verification failed — payload is unauthenticated")
    body = dsse.load_payload(envelope)
    try:
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
    r["predicate_type_ok"] = ptype == ACTION_OUTCOME_PREDICATE_TYPE
    if not r["predicate_type_ok"]:
        r["errors"].append(f"predicateType is {ptype!r}, expected action-outcome/v0.1 (confusion attack?)")

    predicate = statement.get("predicate") if isinstance(statement, dict) else None
    struct_errs = validate_outcome_predicate(predicate, strict=strict)
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
    elif strict:
        r["errors"].append(
            "cannot verify RFC-8785 canonicality (install proofbundle[eval]); fail-closed in strict mode")
    else:
        r["warnings"].append("rfc8785 not installed: hash_binding canonicality not checked")

    canonicality_ok = canonical_ok is True or (canonical_ok is None and not strict)
    r["structure_ok"] = (not struct_errs) and bool(r["predicate_type_ok"]) and canonicality_ok

    if isinstance(predicate, dict) and r["crypto_ok"]:
        # decisionRef binding (replay against another decision fails).
        _dref = (predicate.get("decisionRef") or {}).get("sha256") if isinstance(predicate.get("decisionRef"), dict) else None
        if expected_decision_ref is not None:
            r["decision_bound"] = _dref == expected_decision_ref
            if not r["decision_bound"]:
                r["errors"].append(
                    "decisionRef mismatch — this outcome is bound to a DIFFERENT decision than expected "
                    "(replay across decisions?, fail-closed)")

        # role separation (executor must differ from the decision maker).
        _exid = (predicate.get("executor") or {}).get("id") if isinstance(predicate.get("executor"), dict) else None
        if decision_maker_id is not None:
            r["role_separation_ok"] = bool(_exid) and _exid != decision_maker_id
            if not r["role_separation_ok"]:
                r["errors"].append(
                    "role separation violated — executor.id equals the decisionMaker id; whoever decides "
                    "must not witness their own execution (fail-closed)")

        # execution proof (honesty limit, warning not hard-fail).
        r["execution_proven"] = outcome_execution_proven(predicate)
        if r["execution_proven"] is False:
            r["warnings"].append(
                "status=executed is self-asserted (no effectDigest/actualActionDigest) — a signed claim, "
                "not proof the effect occurred")

        # replay/audience binding (fail-closed when requested), mirrors decision.py.
        _val = predicate.get("validity")
        _validity = _val if isinstance(_val, dict) else {}
        if expected_audience is not None:
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

    # Subject binding (release-review #4): classify whether the subject genuinely commits to the predicate so a
    # consumer never gets ZERO signal on a subject-rehang. An EXTERNAL_ATTESTED subject is ALWAYS warned;
    # require_derived_subject makes it a hard fail-closed error (opt-in, preserves the documented override use).
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
                # classify_subject raised (e.g. a predicate the JCS canonicalizer rejects). Do NOT silently pass
                # the gate on a coincidence elsewhere — make the fail-closed explicit (release-review #4 hardening).
                r["subject_derived_ok"] = False
                r["errors"].append(
                    "require_derived_subject: could not classify the subject binding (canonicalization raised) "
                    "— fail-closed")
        elif require_derived_subject:
            r["subject_derived_ok"] = False
            r["errors"].append(
                "require_derived_subject but RFC-8785 canonicalizer unavailable — cannot verify subject "
                "derivation (install proofbundle[eval]), fail-closed")

    r["ok"] = bool(
        r["crypto_ok"] and r["structure_ok"] and r["predicate_type_ok"]
        and r["decision_bound"] is not False and r["role_separation_ok"] is not False
        and r["audience_ok"] is not False and r["nonce_ok"] is not False
        and r["subject_derived_ok"] is not False)
    return r
