"""Verification Summary predicate `verification-summary/v0.1` — hand-rolled, fail-closed validation.

proofbundle 3.2.0 O4 (EXPERIMENTAL). A signed, machine-readable summary of what was verified across the
receipt chain (eval → decision → outcome): per level the verified receipt's content root, its verdict status
and evidence class, plus an EXPLICIT non-claims block. Emitted as its own DSSE-signed in-toto Statement.

No-Overclaim: a summary states which checks passed for which receipts. It never asserts the underlying claim
is true, the decision correct, the effect real, or coverage complete — that is what the ``nonClaims`` block
records verbatim. Like the rest of proofbundle this module is the enforced validator; the JSON schema is docs.

Field names are lowerCamelCase (ITE-9).
"""
from __future__ import annotations

import hashlib
import re
from typing import Any

from ._strict_json import loads_strict
from .errors import ProofBundleError

VERIFICATION_SUMMARY_PREDICATE_TYPE = "https://b7n0de.com/proofbundle/predicates/verification-summary/v0.1"
SUMMARY_SCHEMA_VERSION = "0.1.0"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
INTOTO_STATEMENT_PAYLOAD_TYPE = "application/vnd.in-toto+json"

_RFC3339_Z = re.compile(r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z\Z")  # \A..\Z (not ^..$): $ matches before a trailing newline
_SHA256_HEX = re.compile(r"\A[0-9a-f]{64}\Z")  # \A..\Z (not ^..$): $ matches before a trailing newline
_SEMVER_0_1_X = re.compile(r"\A0\.1\.\d+\Z")  # \A..\Z (not ^..$): $ matches before a trailing newline

_LEVEL_KINDS = {"eval", "decision", "outcome"}
_STATUS = {"VERIFIED", "FAILED", "NOT_EVALUATED"}
_EVIDENCE_CLASS = {"authorship_integrity", "decision_claim", "outcome_claim"}

_REQUIRED_ALWAYS = ("schemaVersion", "summaryId", "producedAt", "levels", "nonClaims")
_OPTIONAL = ("producer", "chainRef")
_ALLOWED_TOP = set(_REQUIRED_ALWAYS) | set(_OPTIONAL)
# receiptRef is NOT structurally required (a NOT_EVALUATED level legitimately references no receipt); the
# verify-time levels_consistent check enforces it specifically for status=VERIFIED (a real, testable rule that
# validate alone cannot express — No-Fake: not a check that can never fail).
_LEVEL_REQUIRED = ("kind", "status", "evidenceClass")
_LEVEL_ALLOWED = set(_LEVEL_REQUIRED) | {"receiptRef", "checks"}


class VerificationSummaryError(ProofBundleError):
    """A Verification Summary predicate is malformed (fail-closed)."""


def _is_digest(obj: Any) -> bool:
    return isinstance(obj, dict) and isinstance(obj.get("sha256"), str) and bool(_SHA256_HEX.match(obj["sha256"]))


def validate_summary_predicate(predicate: Any, *, strict: bool = False) -> list[str]:
    """Return fail-closed errors for a ``verification-summary/v0.1`` predicate (empty = valid)."""
    errors: list[str] = []
    if not isinstance(predicate, dict):
        return ["predicate must be a JSON object"]

    for k in predicate:
        if k not in _ALLOWED_TOP:
            errors.append(f"unknown field {k!r} (additionalProperties:false)")
    for req in _REQUIRED_ALWAYS:
        if req not in predicate:
            errors.append(f"missing required field {req!r}")

    sv = predicate.get("schemaVersion")
    if "schemaVersion" in predicate and not (isinstance(sv, str) and _SEMVER_0_1_X.match(sv)):
        errors.append("schemaVersion must match 0.1.x")

    sid = predicate.get("summaryId")
    if "summaryId" in predicate and not (isinstance(sid, str) and sid):
        errors.append("summaryId must be a non-empty string")

    pa = predicate.get("producedAt")
    if "producedAt" in predicate and not (isinstance(pa, str) and _RFC3339_Z.match(pa)):
        errors.append("producedAt must be an RFC3339 UTC 'Z' timestamp")

    pr = predicate.get("producer")
    if "producer" in predicate:
        if not isinstance(pr, dict):
            errors.append("producer must be an object")
        else:
            for k in pr:
                if k not in ("id", "keyId"):
                    errors.append(f"producer.{k} is not an allowed field")
                elif not isinstance(pr[k], str):
                    errors.append(f"producer.{k} must be a string")

    if "chainRef" in predicate and not _is_digest(predicate.get("chainRef")):
        errors.append("chainRef, when present, must be a sha256 digest object")

    lv = predicate.get("levels")
    if "levels" in predicate:
        if not isinstance(lv, list) or not lv:
            errors.append("levels must be a non-empty array")
        else:
            for i, lvl in enumerate(lv):
                errors.extend(f"levels[{i}]: {e}" for e in _validate_level(lvl))

    nc = predicate.get("nonClaims")
    if "nonClaims" in predicate and not (isinstance(nc, list) and nc and all(isinstance(x, str) for x in nc)):
        errors.append("nonClaims must be a non-empty array of strings (No-Overclaim block is mandatory)")

    return errors


def _validate_level(lvl: Any) -> list[str]:
    errs: list[str] = []
    if not isinstance(lvl, dict):
        return ["must be an object"]
    for k in lvl:
        if k not in _LEVEL_ALLOWED:
            errs.append(f"unknown field {k!r}")
    for req in _LEVEL_REQUIRED:
        if req not in lvl:
            errs.append(f"missing {req!r}")
    if "kind" in lvl and lvl.get("kind") not in _LEVEL_KINDS:
        errs.append(f"kind must be one of {sorted(_LEVEL_KINDS)}")
    if "receiptRef" in lvl and not _is_digest(lvl.get("receiptRef")):
        errs.append("receiptRef must be a sha256 digest object")
    if "status" in lvl and lvl.get("status") not in _STATUS:
        errs.append(f"status must be one of {sorted(_STATUS)}")
    if "evidenceClass" in lvl and lvl.get("evidenceClass") not in _EVIDENCE_CLASS:
        errs.append(f"evidenceClass must be one of {sorted(_EVIDENCE_CLASS)}")
    ch = lvl.get("checks")
    if "checks" in lvl and not (isinstance(ch, list) and all(isinstance(x, str) for x in ch)):
        errs.append("checks must be a list of strings")
    return errs


def require_valid_summary_predicate(predicate: Any, *, strict: bool = False) -> None:
    errs = validate_summary_predicate(predicate, strict=strict)
    if errs:
        raise VerificationSummaryError("invalid verification-summary predicate: " + "; ".join(errs))


# ── Emit / verify ───────────────────────────────────────────────────────────
def _rfc8785_bytes(obj: Any) -> bytes:
    from . import canonical  # noqa: PLC0415
    try:
        return canonical.canonicalize_statement(obj)
    except canonical.CanonicalizerUnavailable as exc:
        raise VerificationSummaryError(
            "verification summaries need the RFC 8785 (JCS) canonicalizer — install proofbundle[eval]") from exc


def _rfc8785_available() -> bool:
    try:
        import rfc8785  # noqa: F401, PLC0415
        return True
    except Exception:
        return False


def build_summary_statement(predicate: dict, *, subject_name: str | None = None,
                            subject_sha256: str | None = None) -> dict:
    errs = validate_summary_predicate(predicate, strict=False)
    if errs:
        raise VerificationSummaryError("invalid verification-summary predicate: " + "; ".join(errs))
    name = subject_name or f"verification-summary:{predicate.get('summaryId', '')}"
    sha = subject_sha256 or hashlib.sha256(_rfc8785_bytes(predicate)).hexdigest()
    return {
        "_type": STATEMENT_TYPE,
        "subject": [{"name": name, "digest": {"sha256": sha}}],
        "predicateType": VERIFICATION_SUMMARY_PREDICATE_TYPE,
        "predicate": predicate,
    }


def emit_verification_summary(predicate: dict, signer, *, subject_name: str | None = None,
                              subject_sha256: str | None = None, keyid: str | None = None,
                              strict: bool = True) -> dict:
    from . import dsse  # noqa: PLC0415
    errs = validate_summary_predicate(predicate, strict=strict)
    if errs:
        raise VerificationSummaryError("invalid verification-summary predicate: " + "; ".join(errs))
    statement = build_summary_statement(predicate, subject_name=subject_name, subject_sha256=subject_sha256)
    body = _rfc8785_bytes(statement)
    return dsse.sign_envelope(body, signer, payload_type=INTOTO_STATEMENT_PAYLOAD_TYPE, keyid=keyid)


def _empty_result() -> dict:
    return {"ok": None, "structure_ok": None, "crypto_ok": None, "predicate_type_ok": None,
            "levels_consistent": None,
            # Finding 01 (2026-07 verify-layer hardening, additive): a uniform automation-safety verdict,
            # computed at the end of verify — never gates anything above, `ok` is unchanged.
            "automation": None,
            "warnings": [], "errors": []}


def _finalize_failclosed(r: dict) -> dict:
    """RE-GATE never-raise: a crypto/budget/parse failure over untrusted input yields ok=False plus a
    consistent automation verdict (safeForAutomation=False) — the SAME shape as a full run, never a raw
    exception out of this dict-returning verify surface. Mirrors decision._finalize_failclosed."""
    from .automation_verdict import automation_summary  # noqa: PLC0415
    r["ok"] = False
    r["automation"] = automation_summary(r, required_checks={
        "crypto": "crypto_ok", "structure": "structure_ok", "policy": None,
        "references": ["levels_consistent"]})
    return r


def verify_verification_summary(envelope: dict, public_key: bytes, *, strict: bool = False) -> dict:
    """Verify a DSSE-signed Verification Summary. Crypto first, then structure over the EXACT signed bytes.

    ``levels_consistent`` is a No-Fake honesty check on the summary's OWN claims: a level marked
    ``status = VERIFIED`` must carry a real ``receiptRef`` digest (you cannot summarize a receipt you did not
    reference). It does NOT re-run the underlying receipt verification — a summary attests what the producer
    verified, and ``nonClaims`` records that limit verbatim. Read ``ok`` (or ``crypto_ok``) — never an
    individual field alone; on a crypto fail every derived field stays None."""
    from . import dsse  # noqa: PLC0415
    from .budget import DEFAULT_BUDGET  # noqa: PLC0415
    r = _empty_result()
    try:
        # RE-GATE never-raise (budget-parity, sibling of REGATE-BUDGET-02): crypto verify + body load +
        # input_bytes budget + strict parse inside the never-raise try; the except catches ProofBundleError so
        # an oversized/wide/malformed untrusted envelope yields a fail-closed verdict, never a raw uncaught
        # exception out of this dict-returning verify surface (mirrors decision/outcome).
        r["crypto_ok"] = bool(dsse.verify_envelope(envelope, public_key, payload_type=INTOTO_STATEMENT_PAYLOAD_TYPE))
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
    r["predicate_type_ok"] = ptype == VERIFICATION_SUMMARY_PREDICATE_TYPE
    if not r["predicate_type_ok"]:
        r["errors"].append(f"predicateType is {ptype!r}, expected verification-summary/v0.1 (confusion attack?)")

    predicate = statement.get("predicate") if isinstance(statement, dict) else None
    struct_errs = validate_summary_predicate(predicate, strict=strict)
    r["errors"].extend(struct_errs)

    canonical_ok = None
    if _rfc8785_available():
        try:
            canonical_ok = _rfc8785_bytes(statement) == body
        except Exception:
            canonical_ok = False
        if canonical_ok is False:
            r["errors"].append("payload is not RFC-8785 canonical (hash_binding fail-closed)")
    else:
        # PB-06 parity (rfc8785 is now a declared CORE dependency): an absent canonicalizer is a broken
        # install, not a lenient mode — fail closed REGARDLESS of strict (mirrors decision.py).
        r["errors"].append(
            "RFC-8785 (JCS) canonicalizer unavailable — proofbundle requires rfc8785 (core dependency); "
            "hash_binding fail-closed, cannot verify canonicality")

    canonicality_ok = canonical_ok is True  # absent (None) or non-canonical (False) never passes (fail-closed)
    r["structure_ok"] = (not struct_errs) and bool(r["predicate_type_ok"]) and canonicality_ok

    if isinstance(predicate, dict) and r["crypto_ok"]:
        levels = predicate.get("levels")
        if isinstance(levels, list):
            bad = [i for i, lv in enumerate(levels)
                   if isinstance(lv, dict) and lv.get("status") == "VERIFIED" and not _is_digest(lv.get("receiptRef"))]
            r["levels_consistent"] = not bad
            if bad:
                r["errors"].append(
                    f"levels {bad} claim status=VERIFIED without a receiptRef digest (cannot summarize an "
                    "unreferenced receipt, fail-closed)")

    r["ok"] = bool(
        r["crypto_ok"] and r["structure_ok"] and r["predicate_type_ok"]
        and r["levels_consistent"] is not False)

    # Finding 01 (additive): a uniform automation-safety verdict — never changes `ok` above. A verification
    # summary carries no separate policy/authorization layer of its own ("policy" not applicable).
    from .automation_verdict import automation_summary  # noqa: PLC0415
    r["automation"] = automation_summary(r, required_checks={
        "crypto": "crypto_ok", "structure": "structure_ok", "policy": None,
        "references": ["levels_consistent"],
    })
    return r
