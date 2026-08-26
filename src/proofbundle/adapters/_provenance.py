"""Shared provenance helpers for adapters (v1.8).

The external review found that run-id and config-hash were missing from nearly every adapter and
that the two flagship adapters took the timestamp from the caller rather than the eval log. These
helpers close that: each adapter now records, where the framework exposes it, a stable RUN id, a
CONFIG hash, and the LOG-NATIVE timestamp — so a receipt is traceable back to the exact run.

Design notes (verified against framework source, 2026-07):
  - No framework ships a canonical config hash, so we compute our own. Config is an in-memory
    object re-serialized non-deterministically, so it MUST be canonicalized before hashing —
    RFC 8785 JCS via the same `rfc8785` extra the emit path already needs. If that extra is
    absent we fall back to a deterministic `json.dumps(sort_keys=True)` and LABEL the hash
    algorithm accordingly, so a verifier is never misled about how the hash was formed.
  - The hash is over the config's JSON, prefixed with a domain tag, hex sha256. It is provenance
    metadata (traceability), NOT a security commitment — it is not salted and reveals structure;
    it exists so two receipts from the same config are linkable and a changed config is visible.

**Benchmark-hacking VISIBILITY (additive).** `run_attempts`/`aborted_runs`/`methodology_sha256`/
`benchjack_audit_report_sha256` make retry/best-of-many patterns and the methodology behind a
result *visible* in the signed claim. They are honest metadata, NEVER a cryptographic guarantee
against a gamed benchmark — `eval_evidence_class` already separates `methodology` from
`score_evidence` (a receipt never judges whether the suite is well designed), and THREAT_MODEL.md
states the same boundary for benchmark-hacking explicitly (BenchJack, arXiv:2605.12673): crypto
cannot prove benchmark truth, only that these numbers are what was signed. The two digest fields
are plain sha256 references an auditor re-hashes by hand — same mechanism, same epistemic
strength as `prereg_sha256`/`evaluation_card_sha256` (a match proves only "this is the document
the issuer pointed at", never that the document is honest or complete).
"""

from __future__ import annotations

import hashlib
import json
from typing import Optional

_CONFIG_DOMAIN = b"proofbundle/v1.8/config-hash\x00"


def config_hash(config) -> Optional[str]:
    """Return ``"<alg>:<hex>"`` over the canonical JSON of a config object, or None if it is
    empty/None. ``<alg>`` is ``sha256-jcs`` when RFC 8785 is available, else ``sha256-sortkeys``
    (both deterministic; the label tells a verifier which normalization produced the hex)."""
    if config is None or config == {} or config == []:
        return None
    try:
        import rfc8785  # noqa: PLC0415 — same optional dep as the emit path
        canonical = rfc8785.dumps(config)
        alg = "sha256-jcs"
    except (ImportError, ValueError, TypeError):
        # rfc8785 rejects non-JCS-able values (e.g. floats it deems unsafe); fall back to a
        # deterministic stdlib serialization and label it so the difference is never hidden.
        try:
            canonical = json.dumps(config, sort_keys=True, separators=(",", ":"),
                                   ensure_ascii=False).encode("utf-8")
        except (TypeError, ValueError):
            return None
        alg = "sha256-sortkeys"
    return f"{alg}:{hashlib.sha256(_CONFIG_DOMAIN + canonical).hexdigest()}"


def add_provenance(provenance: dict, *, run_id=None, config=None, log_timestamp=None,
                   config_hash_value: Optional[str] = None,
                   run_attempts: Optional[int] = None, aborted_runs: Optional[int] = None,
                   methodology_sha256: Optional[str] = None,
                   benchjack_audit_report_sha256: Optional[str] = None) -> dict:
    """Merge the standard traceability fields into a provenance dict, skipping absent ones.

    ``config_hash_value`` lets a caller pass a precomputed hash (e.g. over already-canonical
    material) instead of a config object; otherwise ``config`` is hashed here.

    ``run_attempts``/``aborted_runs`` (non-negative integers) and ``methodology_sha256``/
    ``benchjack_audit_report_sha256`` (plain sha256 hex references) are additive VISIBILITY-only
    fields for benchmark-hacking transparency — see the module docstring; they carry no
    verification semantics here (no gate calls this a "guarantee")."""
    if run_id:
        provenance["run_id"] = str(run_id)
    if log_timestamp is not None:
        provenance["run_timestamp"] = str(log_timestamp)
    ch = config_hash_value if config_hash_value is not None else config_hash(config)
    if ch:
        provenance["config_hash"] = ch
    for name, value in (("run_attempts", run_attempts), ("aborted_runs", aborted_runs)):
        if value is not None:
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"{name} must be a non-negative integer, got {value!r}")
            provenance[name] = value
    if methodology_sha256 is not None:
        provenance["methodology_sha256"] = str(methodology_sha256)
    if benchjack_audit_report_sha256 is not None:
        provenance["benchjack_audit_report_sha256"] = str(benchjack_audit_report_sha256)
    return provenance


# --- Reported-version status (v5.0.0, additive) ---------------------------------------------
#
# THE GAP THIS CLOSES. Until now a harness-reported version field was written when the harness
# reported one and simply ABSENT when it did not. Absence therefore carried two different
# meanings and the receipt did not say which:
#
#     the harness ran and reported no version
#     no harness was bound at all, or this adapter never fills the field
#
# For a verifier that ambiguity is the failure class the product exists against: a receipt must
# say what it means. A reader comparing receipts could not tell "nothing to report" from
# "nobody looked".
#
# THE FORM IS A STATUS WITH THREE VALUES, DELIBERATELY NOT A BOOLEAN. A boolean has three states
# of its own — true, false and absent — and would push the same ambiguity one level up.
#
# THE VERSION FIELD ITSELF IS UNTOUCHED. `test_missing_version_field_stays_absent_not_invented`
# forbids writing a value the harness never reported, and that contract still holds byte for
# byte: when nothing was reported the version key stays ABSENT. The status says something about
# the REPORTING, never about the version.
#
# NEVER DERIVED. The status is written only from what the harness actually returned. It is not
# inferred from other fields, and `not_reported` is never an all-clear — it does not fold to
# PASS, and no gate reads it as one.

VERSION_STATUS_REPORTED = "reported"        # the harness returned a version; the field is present
VERSION_STATUS_NOT_REPORTED = "not_reported"   # the harness ran and returned none; field absent
VERSION_STATUS_NOT_BOUND = "not_bound"      # this adapter binds no such field for this format

VERSION_STATUS_VALUES = (VERSION_STATUS_REPORTED, VERSION_STATUS_NOT_REPORTED,
                         VERSION_STATUS_NOT_BOUND)


def bind_reported_version(provenance: dict, field: str, value, *, reason: str,
                          bound: bool = True) -> dict:
    """Write a harness-reported version field together with its explicit status.

    ``field`` is the provenance key (e.g. ``"harness_version"``, ``"task_version"``); the status
    lands in ``f"{field}_status"`` and, when the status is not ``reported``, the mandatory reason
    lands in ``f"{field}_status_reason"``.

    - ``value`` truthy          -> field written, status ``reported`` (no reason: nothing to explain)
    - ``value`` absent/empty    -> field NOT written, status ``not_reported`` + reason
    - ``bound=False``           -> field NOT written, status ``not_bound`` + reason

    ``reason`` is REQUIRED whenever the status can be non-``reported``. An empty reason raises:
    a status that says "not reported" without saying why moves the ambiguity rather than closing
    it, and this helper exists precisely to stop that.
    """
    status_key, reason_key = f"{field}_status", f"{field}_status_reason"
    if bound and value not in (None, ""):
        provenance[field] = str(value)
        provenance[status_key] = VERSION_STATUS_REPORTED
        # A previously written reason would now be stale; the reported case explains itself.
        provenance.pop(reason_key, None)
        return provenance
    if not str(reason or "").strip():
        raise ValueError(
            f"{status_key}={'not_bound' if not bound else 'not_reported'} requires a reason — "
            f"a status without a reason moves the ambiguity instead of closing it")
    provenance[status_key] = (VERSION_STATUS_NOT_BOUND if not bound
                              else VERSION_STATUS_NOT_REPORTED)
    provenance[reason_key] = str(reason).strip()
    return provenance


def version_status_issues(provenance: dict) -> list[str]:
    """Verifier side: every problem with the reported-version status fields, as plain sentences.

    An empty list means the provenance is CONSISTENT in this respect — it never means the
    versions themselves are trustworthy (a status is a statement about the reporting, not about
    the software). Checked:

      1. a status value outside the three literals
      2. a non-``reported`` status without its mandatory reason
      3. ``reported`` while the version field it speaks about is absent
      4. a version field present while its status says it was not reported or not bound

    (3) and (4) are the two ways the pair can contradict itself, and both must be caught: a
    verifier that only looked at the status could be told anything.
    """
    issues: list[str] = []
    for key in sorted(provenance):
        if not key.endswith("_status"):
            continue
        field = key[: -len("_status")]
        status = provenance.get(key)
        if status not in VERSION_STATUS_VALUES:
            issues.append(f"{key}={status!r} is not one of {list(VERSION_STATUS_VALUES)}")
            continue
        reason = str(provenance.get(f"{field}_status_reason") or "").strip()
        if status != VERSION_STATUS_REPORTED and not reason:
            issues.append(f"{key}={status} without {field}_status_reason (reason is mandatory)")
        present = provenance.get(field) not in (None, "")
        if status == VERSION_STATUS_REPORTED and not present:
            issues.append(f"{key}=reported but {field} is absent")
        if status != VERSION_STATUS_REPORTED and present:
            issues.append(f"{key}={status} but {field} is present ({provenance.get(field)!r})")
    return issues
