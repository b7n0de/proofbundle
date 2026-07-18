"""Run Ledger predicate `run-ledger/v0.1` — hand-rolled, fail-closed validation.

proofbundle 3.2.0 O5 (EXPERIMENTAL). A signed ledger of ALL runs of a study, against best-of-many
cherry-picking: a monotone ``seq`` sequence with a ``prevDigest`` chain (each run links the previous run's
result), aborted/failed runs kept VISIBLE (never dropped), a ``runBudget`` declared up front, and an explicit
``nonClaims`` block. Emitted as its own DSSE-signed in-toto Statement.

No-Overclaim: the ledger records which runs happened and their order. It does NOT assert the selected run is
representative, that the study was unbiased, or that no run outside the ledger exists — ``nonClaims`` records
those limits verbatim, and the digest chain only makes SILENT omission (dropping a run mid-chain) detectable.

Field names are lowerCamelCase (ITE-9).
"""
from __future__ import annotations

import hashlib
import re
from typing import Any

from ._strict_json import loads_strict
from .errors import ProofBundleError

RUN_LEDGER_PREDICATE_TYPE = "https://b7n0de.com/proofbundle/predicates/run-ledger/v0.1"
RUN_LEDGER_SCHEMA_VERSION = "0.1.0"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
INTOTO_STATEMENT_PAYLOAD_TYPE = "application/vnd.in-toto+json"

_RFC3339_Z = re.compile(r"\A\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z\Z")  # \A..\Z (not ^..$): $ matches before a trailing newline
_SHA256_HEX = re.compile(r"\A[0-9a-f]{64}\Z")  # \A..\Z (not ^..$): $ matches before a trailing newline
_SEMVER_0_1_X = re.compile(r"\A0\.1\.\d+\Z")  # \A..\Z (not ^..$): $ matches before a trailing newline

_RUN_STATUS = {"completed", "aborted", "failed"}
_REQUIRED_ALWAYS = ("schemaVersion", "studyId", "runBudget", "runs", "nonClaims")
_OPTIONAL = ("externalRandomnessRef", "selectedSeq")
_ALLOWED_TOP = set(_REQUIRED_ALWAYS) | set(_OPTIONAL)
_RUN_REQUIRED = ("seq", "status", "resultDigest", "prevDigest")
_RUN_ALLOWED = set(_RUN_REQUIRED) | {"startedAt", "note"}


class RunLedgerError(ProofBundleError):
    """A Run Ledger predicate is malformed (fail-closed)."""


def _is_digest(obj: Any) -> bool:
    return isinstance(obj, dict) and isinstance(obj.get("sha256"), str) and bool(_SHA256_HEX.match(obj["sha256"]))


def _digest_hex(obj: Any) -> str | None:
    return obj["sha256"] if _is_digest(obj) else None


def validate_run_ledger_predicate(predicate: Any, *, strict: bool = False) -> list[str]:
    """Return fail-closed errors for a ``run-ledger/v0.1`` predicate (empty = valid).

    Beyond per-field shape this enforces the ledger INVARIANTS: seq starts at 1 and is strictly monotone with
    no gaps; the first run's prevDigest is null; every later run's prevDigest equals the previous run's
    resultDigest (the chain — a silently dropped run breaks it); and runs never exceed runBudget."""
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

    sid = predicate.get("studyId")
    if "studyId" in predicate and not (isinstance(sid, str) and sid):
        errors.append("studyId must be a non-empty string")

    budget = predicate.get("runBudget")
    budget_ok = isinstance(budget, int) and not isinstance(budget, bool) and budget >= 1
    if "runBudget" in predicate and not budget_ok:
        errors.append("runBudget must be an integer >= 1 (declared before the study)")

    if "externalRandomnessRef" in predicate and not _is_digest(predicate.get("externalRandomnessRef")):
        errors.append("externalRandomnessRef, when present, must be a sha256 digest object")

    nc = predicate.get("nonClaims")
    if "nonClaims" in predicate and not (isinstance(nc, list) and nc and all(isinstance(x, str) for x in nc)):
        errors.append("nonClaims must be a non-empty array of strings (No-Overclaim block is mandatory)")

    runs = predicate.get("runs")
    if "runs" not in predicate:
        return errors
    if not isinstance(runs, list) or not runs:
        errors.append("runs must be a non-empty array")
        return errors

    # Per-run shape.
    for i, run in enumerate(runs):
        for e in _validate_run_shape(run):
            errors.append(f"runs[{i}]: {e}")
    # If any run is mis-shaped, the invariant checks below would be noise — report shape first.
    if errors and any(e.startswith("runs[") for e in errors):
        return errors

    # Ledger invariants (monotone seq, no gaps, digest chain, budget).
    prev_result: str | None = None
    for i, run in enumerate(runs):
        seq = run.get("seq")
        if seq != i + 1:
            errors.append(f"runs[{i}].seq must be {i + 1} (strictly monotone from 1, no gaps), got {seq!r}")
        prev = run.get("prevDigest")
        if i == 0:
            if prev is not None:
                errors.append("runs[0].prevDigest must be null (first run has no predecessor)")
        else:
            prev_hex = _digest_hex(prev)
            if prev_hex != prev_result:
                errors.append(
                    f"runs[{i}].prevDigest does not equal runs[{i - 1}].resultDigest — the run chain is "
                    "broken (a run was dropped or reordered, fail-closed)")
        prev_result = _digest_hex(run.get("resultDigest"))

    if budget_ok and isinstance(budget, int) and len(runs) > budget:
        errors.append(f"runs ({len(runs)}) exceed the declared runBudget ({budget})")

    sel = predicate.get("selectedSeq")
    if "selectedSeq" in predicate:
        if not (isinstance(sel, int) and not isinstance(sel, bool) and 1 <= sel <= len(runs)):
            errors.append(f"selectedSeq must be an integer in 1..{len(runs)} (an existing run)")

    return errors


def _validate_run_shape(run: Any) -> list[str]:
    errs: list[str] = []
    if not isinstance(run, dict):
        return ["must be an object"]
    for k in run:
        if k not in _RUN_ALLOWED:
            errs.append(f"unknown field {k!r}")
    for req in _RUN_REQUIRED:
        if req not in run:
            errs.append(f"missing {req!r}")
    seq = run.get("seq")
    if "seq" in run and not (isinstance(seq, int) and not isinstance(seq, bool) and seq >= 1):
        errs.append("seq must be an integer >= 1")
    if "status" in run and run.get("status") not in _RUN_STATUS:
        errs.append(f"status must be one of {sorted(_RUN_STATUS)}")
    if "resultDigest" in run and not _is_digest(run.get("resultDigest")):
        errs.append("resultDigest must be a sha256 digest object")
    if "prevDigest" in run and run.get("prevDigest") is not None and not _is_digest(run.get("prevDigest")):
        errs.append("prevDigest must be a sha256 digest object or null")
    if "startedAt" in run and not (isinstance(run.get("startedAt"), str) and _RFC3339_Z.match(run["startedAt"])):
        errs.append("startedAt must be an RFC3339 UTC 'Z' timestamp")
    if "note" in run and not isinstance(run.get("note"), str):
        errs.append("note must be a string")
    return errs


def require_valid_run_ledger_predicate(predicate: Any, *, strict: bool = False) -> None:
    errs = validate_run_ledger_predicate(predicate, strict=strict)
    if errs:
        raise RunLedgerError("invalid run-ledger predicate: " + "; ".join(errs))


def link_runs(result_digests: list[str], statuses: list[str] | None = None) -> list[dict]:
    """Helper: build a well-formed, chained ``runs`` list from an ordered list of result-digest hexes.

    ``statuses`` defaults to all ``completed``. seq is 1-based; prevDigest chains each run to the previous
    result; the first prevDigest is null. Fail-closed: a non-64-hex digest raises ``RunLedgerError`` (the
    ledger never carries a malformed chain link)."""
    statuses = statuses or ["completed"] * len(result_digests)
    if len(statuses) != len(result_digests):
        raise RunLedgerError("statuses length must match result_digests length")
    runs: list[dict] = []
    prev: dict | None = None
    for i, (rd, st) in enumerate(zip(result_digests, statuses)):
        if not (isinstance(rd, str) and _SHA256_HEX.match(rd)):
            raise RunLedgerError(f"result_digests[{i}] is not a 64-hex sha256")
        if st not in _RUN_STATUS:
            raise RunLedgerError(f"statuses[{i}] must be one of {sorted(_RUN_STATUS)}")
        runs.append({"seq": i + 1, "status": st, "resultDigest": {"sha256": rd}, "prevDigest": prev})
        prev = {"sha256": rd}
    return runs


# ── Emit / verify ───────────────────────────────────────────────────────────
def _rfc8785_bytes(obj: Any) -> bytes:
    from . import canonical  # noqa: PLC0415
    try:
        return canonical.canonicalize_statement(obj)
    except canonical.CanonicalizerUnavailable as exc:
        raise RunLedgerError(
            "run ledgers need the RFC 8785 (JCS) canonicalizer — install proofbundle[eval]") from exc


def _rfc8785_available() -> bool:
    try:
        import rfc8785  # noqa: F401, PLC0415
        return True
    except Exception:
        return False


def build_run_ledger_statement(predicate: dict, *, subject_name: str | None = None,
                               subject_sha256: str | None = None) -> dict:
    errs = validate_run_ledger_predicate(predicate, strict=False)
    if errs:
        raise RunLedgerError("invalid run-ledger predicate: " + "; ".join(errs))
    name = subject_name or f"run-ledger:{predicate.get('studyId', '')}"
    sha = subject_sha256 or hashlib.sha256(_rfc8785_bytes(predicate)).hexdigest()
    return {
        "_type": STATEMENT_TYPE,
        "subject": [{"name": name, "digest": {"sha256": sha}}],
        "predicateType": RUN_LEDGER_PREDICATE_TYPE,
        "predicate": predicate,
    }


def emit_run_ledger(predicate: dict, signer, *, subject_name: str | None = None,
                    subject_sha256: str | None = None, keyid: str | None = None,
                    strict: bool = True) -> dict:
    from . import dsse  # noqa: PLC0415
    errs = validate_run_ledger_predicate(predicate, strict=strict)
    if errs:
        raise RunLedgerError("invalid run-ledger predicate: " + "; ".join(errs))
    statement = build_run_ledger_statement(predicate, subject_name=subject_name, subject_sha256=subject_sha256)
    body = _rfc8785_bytes(statement)
    return dsse.sign_envelope(body, signer, payload_type=INTOTO_STATEMENT_PAYLOAD_TYPE, keyid=keyid)


def _empty_result() -> dict:
    return {"ok": None, "structure_ok": None, "crypto_ok": None, "predicate_type_ok": None,
            "chain_intact": None, "within_budget": None,
            # Finding 01 (2026-07 verify-layer hardening, additive): a uniform automation-safety verdict,
            # computed at the end of verify — never gates anything above, `ok` is unchanged. NOTE:
            # "within_budget" above is this PREDICATE's own declared runBudget (a study-design concept,
            # unrelated to the module-level VerificationBudget DoS guard in budget.py, Finding 15b).
            "automation": None,
            "warnings": [], "errors": []}


def _finalize_failclosed(r: dict) -> dict:
    """RE-GATE never-raise (REGATE-BUDGET-02): a crypto/budget/parse failure over untrusted input yields
    ok=False plus a consistent automation verdict (safeForAutomation=False) — the SAME shape as a full run,
    never a raw exception out of this dict-returning verify surface. Mirrors decision._finalize_failclosed."""
    from .automation_verdict import automation_summary  # noqa: PLC0415
    r["ok"] = False
    r["automation"] = automation_summary(r, required_checks={
        "crypto": "crypto_ok", "structure": "structure_ok", "policy": None,
        "references": ["chain_intact", "within_budget"]})
    return r


def verify_run_ledger(envelope: dict, public_key: bytes, *, strict: bool = False) -> dict:
    """Verify a DSSE-signed Run Ledger. Crypto first, then structure over the EXACT signed bytes.

    ``chain_intact`` and ``within_budget`` are derived from the same ledger invariants the validator enforces
    (a monotone seq with an unbroken prevDigest chain; runs count <= runBudget). They are surfaced as their own
    result fields so a relying party sees WHY structure failed. Read ``ok`` (or ``crypto_ok``) — never an
    individual field alone; on a crypto fail every derived field stays None."""
    from . import dsse  # noqa: PLC0415
    from .budget import DEFAULT_BUDGET  # noqa: PLC0415
    r = _empty_result()
    try:
        # RE-GATE never-raise (REGATE-BUDGET-02): crypto verify + body load + the input_bytes budget check
        # + the strict parse ALL live inside the never-raise try, and the except catches ProofBundleError, so
        # an OVERSIZED (BudgetExceeded) / WIDE (BudgetExceeded from loads_strict) / malformed (BundleFormatError)
        # untrusted envelope yields a fail-closed verdict — never a raw uncaught exception out of this
        # dict-returning verify surface (mirrors decision/outcome; BudgetExceeded is a ProofBundleError sibling
        # of BundleFormatError the old narrow except let escape).
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
    r["predicate_type_ok"] = ptype == RUN_LEDGER_PREDICATE_TYPE
    if not r["predicate_type_ok"]:
        r["errors"].append(f"predicateType is {ptype!r}, expected run-ledger/v0.1 (confusion attack?)")

    predicate = statement.get("predicate") if isinstance(statement, dict) else None
    struct_errs = validate_run_ledger_predicate(predicate, strict=strict)
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
        # install, not a lenient mode — fail closed REGARDLESS of strict (mirrors decision.py), never a
        # silent pass over possibly non-canonical bytes.
        r["errors"].append(
            "RFC-8785 (JCS) canonicalizer unavailable — proofbundle requires rfc8785 (core dependency); "
            "hash_binding fail-closed, cannot verify canonicality")

    canonicality_ok = canonical_ok is True  # absent (None) or non-canonical (False) never passes (fail-closed)
    r["structure_ok"] = (not struct_errs) and bool(r["predicate_type_ok"]) and canonicality_ok

    if isinstance(predicate, dict) and r["crypto_ok"]:
        # Surface the two ledger-specific invariant verdicts (subset of struct_errs, projected for the RP).
        r["chain_intact"] = not any("chain is broken" in e or "monotone" in e or "prevDigest" in e
                                    for e in struct_errs)
        r["within_budget"] = not any("exceed the declared runBudget" in e for e in struct_errs)

    r["ok"] = bool(
        r["crypto_ok"] and r["structure_ok"] and r["predicate_type_ok"]
        and r["chain_intact"] is not False and r["within_budget"] is not False)

    # Finding 01 (additive): a uniform automation-safety verdict — never changes `ok` above. A run ledger
    # carries no separate policy/authorization layer of its own ("policy" not applicable).
    from .automation_verdict import automation_summary  # noqa: PLC0415
    r["automation"] = automation_summary(r, required_checks={
        "crypto": "crypto_ok", "structure": "structure_ok", "policy": None,
        "references": ["chain_intact", "within_budget"],
    })
    return r
