"""Hugging Face Community Evals bridge — receipt tokens + `.eval_results/*.yaml` entries (v1.4).

HF Community Evals (Feb 2026, beta) lets anyone PR benchmark results into a model repo as
`.eval_results/*.yaml`; entries carry an optional, string-typed ``verifyToken`` documented as "a
signature that can be used to prove that evaluation is provably auditable and reproducible".
Schema verified 2026-07-02 against hub-docs (`eval_results.yaml` spec + docs page).

**Honesty first — what this module does and does not claim.** The Hub's own "verified" badge is
granted by HF **server-side** (currently: evaluation ran in HF Jobs with inspect-ai); the token
format HF validates is not publicly specified. proofbundle therefore does NOT fabricate an
HF-validated token. It defines its own self-describing, offline-verifiable token profile —

    ``pb1.`` + base64url(zlib(bundle JSON))

— which any third party (and, should they choose, HF) can verify with `verify_receipt_token`:
the full receipt travels inside the token, so verification is exactly `verify_bundle`, offline.
Putting it in the schema-valid `verifyToken` field makes the result *proofbundle-verifiable*;
it does not and must not be presented as HF-endorsed. The docs and `to_eval_results_entry` keep
that distinction explicit (the receipt link belongs in `source.url` / `notes` either way).
"""

from __future__ import annotations

import base64
import json
import math
import zlib
from typing import Optional, Tuple

from ._strict_json import loads_strict
from .bundle import verify_bundle
from .errors import BundleFormatError, ProofBundleError, UnsupportedError, VerificationResult

__all__ = ["TOKEN_PREFIX", "receipt_token", "verify_receipt_token",
           "verify_eval_results_entry", "to_eval_results_entry", "eval_results_yaml"]

TOKEN_PREFIX = "pb1."
_MAX_TOKEN_BYTES = 262_144   # 256 KiB decompressed cap — a receipt is a few KB; refuse zip bombs


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    raw = s.encode("ascii")
    return base64.urlsafe_b64decode(raw + b"=" * (-len(raw) % 4))


def receipt_token(bundle: dict) -> str:
    """Pack a receipt bundle into a compact, self-contained token: ``pb1.`` +
    base64url(zlib(canonical bundle JSON)). The token IS the receipt — verifying it is verifying
    the bundle, offline, no lookup."""
    if not isinstance(bundle, dict) or "payload_b64" not in bundle:
        raise BundleFormatError("receipt_token needs a bundle dict")
    canonical = json.dumps(bundle, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return TOKEN_PREFIX + _b64url(zlib.compress(canonical, 9))


def verify_receipt_token(token: str) -> Tuple[VerificationResult, Optional[dict]]:
    """Unpack and verify a ``pb1.`` receipt token. Returns (VerificationResult, bundle_dict).
    Malformed tokens raise BundleFormatError — never a crash, never a silent pass."""
    if not isinstance(token, str) or not token.startswith(TOKEN_PREFIX):
        raise BundleFormatError(f"not a proofbundle receipt token (expected {TOKEN_PREFIX!r} prefix)")
    try:
        decomp = zlib.decompressobj()
        raw = decomp.decompress(_b64url_decode(token[len(TOKEN_PREFIX):]), _MAX_TOKEN_BYTES)
        if decomp.unconsumed_tail:
            raise BundleFormatError("receipt token exceeds the decompression cap")
        bundle = loads_strict(raw)   # WP-C1: duplicate keys rejected fail-closed
    except BundleFormatError:
        raise
    except ProofBundleError as exc:
        # RE-GATE never-raise: loads_strict raises BudgetExceeded (a ProofBundleError, NOT a BundleFormatError
        # nor a ValueError) on a wide/oversized token — surface it as the DOCUMENTED BundleFormatError raise,
        # never a raw BudgetExceeded leak (this function's contract is "malformed tokens raise BundleFormatError").
        raise BundleFormatError("receipt token exceeds the verification budget") from exc
    except (ValueError, TypeError, zlib.error) as exc:
        raise BundleFormatError("receipt token is not valid base64url(zlib(JSON))") from exc
    if not isinstance(bundle, dict):
        raise BundleFormatError("receipt token does not contain a bundle object")
    # Normalize an unsupported schema/alg to BundleFormatError so the documented contract holds — a malformed
    # token never escapes as a different exception type (release-review fix).
    try:
        return verify_bundle(bundle), bundle
    except UnsupportedError as exc:
        raise BundleFormatError(f"receipt token bundle uses an unsupported schema/algorithm: {exc}") from exc


def verify_eval_results_entry(entry: dict) -> dict:
    """VERIFIER-side check of one ``.eval_results`` entry (WP-I2): the builder's value↔verdict
    consistency was emit-side only, so an entry whose ``value`` was edited AFTER the token was
    minted verified fine (``verify_receipt_token`` checks only the bundle inside the token, and a
    Hub reader sees the value, not the token). This closes that: token crypto + the published
    ``value`` must be consistent with the signed claim's threshold verdict.

    Returns ``{ok, crypto_ok, value_consistent, entry_value, claim, warnings[], detail}``:

    * ``crypto_ok`` — the embedded receipt verifies (Ed25519 + Merkle, offline);
    * ``value_consistent`` — ``value <comparator> threshold == passed`` against the DECODED,
      issuer-bound eval claim. Fail-closed: a token whose bundle is not a decodable eval receipt
      yields ``False`` (an eval_results entry claims to publish an eval result — refusing to judge
      it would be the silent skip this project eliminates), as does a missing/non-finite value.
    * ``ok`` — both of the above.

    **Replay boundary (documented, not silently claimed):** the receipt's model/dataset are SALTED
    COMMITMENTS, so this check binds the VALUE to the signed verdict — it can NOT bind the entry's
    ``dataset.id``/``task_id`` to the receipt's committed dataset. A token replayed onto a
    DIFFERENT Hub repo/benchmark with a consistent value still verifies here; binding the identity
    needs the salt opening (``verify_commitment``) out of band. THREAT_MODEL.md carries the same
    row — this function must never be read as a repo-binding check."""
    import math as _math  # noqa: PLC0415
    if not isinstance(entry, dict):
        raise BundleFormatError("verify_eval_results_entry needs an entry dict")
    out: dict = {"ok": False, "crypto_ok": False, "value_consistent": False, "entry_value": None,
                 "claim": None, "detail": "",
                 "warnings": ["value↔verdict bound; dataset/task identity NOT bound (salted "
                              "commitments — needs the salt opening, see THREAT_MODEL)"]}
    # verifyToken is OPTIONAL in the HF schema (six-lens review): a batch verifier over a mixed list
    # must not crash on a token-less entry. It is simply not verifiable → fail-closed ok=False, not
    # a raised error. A malformed (non-string) token is likewise reported, not raised.
    token = entry.get("verifyToken")
    if not isinstance(token, str) or not token:
        out["detail"] = "entry carries no verifyToken — nothing to verify (token is optional in the HF schema)"
        return out
    # Berkeley re-gate (3.6.2): honour this surface's OWN never-raise contract (comment above: "a malformed
    # token is reported, not raised"). verify_receipt_token raises BundleFormatError (a ProofBundleError) on a
    # missing pb1. prefix or bad base64/zlib; a batch verifier over an untrusted third-party .eval_results list
    # must map that to a fail-closed verdict, not crash. Catch the BASE ProofBundleError so no sibling escapes.
    try:
        result, bundle = verify_receipt_token(token)
    except ProofBundleError as exc:
        out["detail"] = f"malformed verifyToken — not verifiable, fail-closed ({exc})"
        return out
    out["crypto_ok"] = bool(result.ok)
    if not result.ok:
        out["detail"] = "embedded receipt does not verify"
        return out
    _val = entry.get("value")
    if _val is None:   # narrow None out before float() (mypy) — a missing value is not verifiable
        out["detail"] = "entry carries no value to check against the signed verdict"
        return out
    if isinstance(_val, bool):   # six-lens review: float(True)==1.0 would sneak a bool past the check;
        out["detail"] = "entry value is a boolean, not a metric number"   # the builder rejects bool too
        return out
    try:
        numeric = float(_val)
    except (TypeError, ValueError, OverflowError):
        out["detail"] = f"entry value {_val!r} is not a number"
        return out
    if not _math.isfinite(numeric):
        out["detail"] = "entry value is not finite"
        return out
    out["entry_value"] = numeric
    from .evalclaim import decode_eval_claim  # noqa: PLC0415
    claim = decode_eval_claim(bundle)
    if claim is None:
        out["detail"] = ("token bundle is not a decodable, issuer-bound eval receipt — cannot "
                         "judge the published value (fail-closed)")
        return out
    out["claim"] = {k: claim[k] for k in ("suite", "metric", "comparator", "threshold", "passed", "n")}
    thr = float(claim["threshold"])
    cmp_ok = {">=": numeric >= thr, ">": numeric > thr,
              "<=": numeric <= thr, "<": numeric < thr}[claim["comparator"]]
    out["value_consistent"] = (cmp_ok == bool(claim["passed"]))
    if not out["value_consistent"]:
        out["detail"] = (f"published value {numeric} contradicts the signed claim: passed="
                         f"{claim['passed']} for {claim['comparator']} {claim['threshold']}")
    out["ok"] = out["crypto_ok"] and out["value_consistent"]
    return out


def to_eval_results_entry(bundle: dict, *, dataset_id: str, task_id: str, value,
                          date: Optional[str] = None, source_url: Optional[str] = None,
                          source_name: Optional[str] = None, source_user: Optional[str] = None,
                          notes: Optional[str] = None, include_token: bool = True,
                          require_verified: bool = True,
                          allow_value_mismatch: bool = False) -> dict:
    """Build one HF `.eval_results/*.yaml` entry for a receipt.

    ``dataset_id``/``task_id`` name the Hub benchmark (per its `eval.yaml`); ``value`` is the
    REQUIRED metric number — the caller chooses what to disclose (a receipt may withhold the
    exact score via SD-JWT; publishing a value here IS a disclosure decision).

    No-Fake guard: with ``require_verified=True`` (default) the bundle must verify NOW — an entry
    is never generated from a broken receipt. ``include_token=True`` puts the ``pb1.`` token in
    ``verifyToken`` (schema-valid, proofbundle-verifiable; NOT the HF-internal badge token — HF's
    "verified" badge is HF's server-side decision, and this module makes no claim about it).

    v1.8 (external review): if the bundle is an eval receipt, the published ``value`` MUST be
    CONSISTENT with the signed pass/fail verdict — ``value <comparator> threshold == passed`` — a
    mismatch raises unless ``allow_value_mismatch=True``. **Scope (do not overclaim):** the signed
    claim minimizes data (it carries ``threshold``/``comparator``/``passed``, NOT the exact score),
    so this binds the value to the correct SIDE of the threshold, not to a true magnitude. It stops
    a value that CONTRADICTS the verdict (a "passed" receipt published with a failing value); it does
    NOT stop an inflated value on the passing side (e.g. a true 0.81 published as 99.9, both above a
    ``>=0.80`` threshold). See THREAT_MODEL.md ("published value" row).
    """
    if require_verified:
        result = verify_bundle(bundle)
        if not result.ok:
            raise BundleFormatError(
                "refusing to build an eval_results entry from a bundle that does not verify: "
                + "; ".join(f"{c.name}: {c.detail}" for c in result.checks if not c.ok))
    if not dataset_id or not task_id:
        raise BundleFormatError("dataset_id and task_id are required (the Hub benchmark identity)")
    if isinstance(value, bool) or not isinstance(value, (int, float, str)):
        raise BundleFormatError("value must be a number (or numeric string)")
    # Reject non-numeric strings AND non-finite values (release-review fix): inf/-inf/nan (whether a float or a
    # string like '1e400'/'nan' that float() accepts) would serialize to the non-standard tokens Infinity/NaN —
    # neither valid JSON nor unambiguous YAML — so an eval_results.yaml value must be a FINITE number.
    try:
        numeric = float(value)
    except (ValueError, TypeError, OverflowError) as exc:   # OverflowError: an int beyond float range
        raise BundleFormatError(f"value {value!r} is not a representable finite number") from exc
    if not math.isfinite(numeric):
        raise BundleFormatError(
            "value must be a finite number — inf/-inf/nan cannot be represented in eval_results.yaml")

    # v1.8 (external review): if the receipt is an eval claim, the published value must be
    # CONSISTENT with the signed pass/fail verdict — a Hub reader sees the value, not the token,
    # so publishing a value that contradicts the receipt is exactly the honesty gap to close.
    # The claim minimizes data (it carries threshold/comparator/passed, not the exact score), so
    # we check the strongest thing available: value <comparator> threshold must equal passed.
    if not allow_value_mismatch:
        from .evalclaim import EVAL_CLAIM_SCHEMA, decode_eval_claim  # noqa: PLC0415
        claim = decode_eval_claim(bundle)
        if claim is not None:
            # decode_eval_claim now guarantees comparator ∈ the 4-value enum and a decimal (finite) threshold, so the
            # lookup below is total and thr is finite — no "=="/"inf" tautology can silently no-op the check.
            if {"threshold", "comparator", "passed"} <= set(claim):
                thr = float(claim["threshold"])
                cmp_ok = {">=": numeric >= thr, ">": numeric > thr,
                          "<=": numeric <= thr, "<": numeric < thr}[claim["comparator"]]
                if cmp_ok != bool(claim["passed"]):
                    raise BundleFormatError(
                        f"published value {numeric} is inconsistent with the receipt: the signed claim "
                        f"says passed={claim['passed']} for {claim['comparator']} {claim['threshold']}, "
                        f"but {numeric} {claim['comparator']} {claim['threshold']} is {cmp_ok} — "
                        "pass allow_value_mismatch=True only if this is intentional")
        else:
            # decode failed. FAIL-CLOSED (release-review CRITICAL) if the payload IS an eval claim but did not decode
            # (e.g. out-of-enum comparator / non-decimal threshold) — refusing to publish an unchecked value. A
            # genuinely NON-eval bundle (different/absent schema) has no verdict to check → skip. The bundle's signature
            # was already verified above (require_verified), so reading the raw payload's schema label is authentic.
            try:
                # WP-C1, DELIBERATE: a duplicate key here raises BundleFormatError and PROPAGATES
                # (it is NOT in the tuple below) — the schema label of a dup-key payload cannot be
                # read reliably, so refusing to publish is the only honest outcome. Adding it to
                # the except would set _is_eval=False and fail OPEN for dup-key eval claims.
                _raw = loads_strict(base64.b64decode(bundle["payload_b64"]).decode("utf-8"))
                _is_eval = isinstance(_raw, dict) and _raw.get("schema") == EVAL_CLAIM_SCHEMA
            except (ValueError, TypeError, KeyError):
                _is_eval = False
            if _is_eval:
                raise BundleFormatError(
                    "cannot verify the published value against the receipt — the eval claim did not decode "
                    "(invalid comparator/threshold?); pass allow_value_mismatch=True only if intentional")

    entry: dict = {"dataset": {"id": dataset_id, "task_id": task_id},
                   "value": numeric if isinstance(value, str) else value}
    if include_token:
        entry["verifyToken"] = receipt_token(bundle)
    if date is not None:
        entry["date"] = date
    source = {}
    if source_url:
        source["url"] = source_url
    if source_name:
        source["name"] = source_name
    if source_user:
        source["user"] = source_user
    if source:
        if "url" not in source:
            raise BundleFormatError("source.url is required when a source is given (HF schema)")
        entry["source"] = source
    if notes is not None:
        entry["notes"] = notes
    return entry


def _yaml_scalar(value) -> str:
    """Serialize one scalar for the entry YAML. Strings are always double-quoted (JSON-style
    escaping is valid YAML), so dates stay strings and tokens survive any special characters."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return json.dumps(value)
    return json.dumps(str(value))


def eval_results_yaml(entries) -> str:
    """Render entries as a `.eval_results/*.yaml` document (block style, deterministic key
    order per the HF spec example). Only the known, shallow schema is emitted — this is a
    purpose-built serializer, not a general YAML writer."""
    order = ("dataset", "value", "verifyToken", "date", "source", "notes")
    dataset_order = ("id", "task_id", "revision")
    source_order = ("url", "name", "user")   # HF hub-docs spec fields (no 'org' — 'user' covers the HF org/user)
    lines = []
    for entry in entries:
        unknown = set(entry) - set(order)
        if unknown:
            raise BundleFormatError(f"unknown eval_results entry field(s): {sorted(unknown)}")
        first = True
        for key in order:
            if key not in entry:
                continue
            prefix = "- " if first else "  "
            first = False
            val = entry[key]
            if key in ("dataset", "source"):
                sub_order = dataset_order if key == "dataset" else source_order
                # fail-loud on unknown nested keys too (symmetric with the top-level check) — a dropped field
                # would silently omit data from the published entry (release-review fix).
                sub_unknown = set(val) - set(sub_order)
                if sub_unknown:
                    raise BundleFormatError(f"unknown {key} field(s): {sorted(sub_unknown)}")
                lines.append(f"{prefix}{key}:")
                for sub in sub_order:
                    if sub in val:
                        lines.append(f"    {sub}: {_yaml_scalar(val[sub])}")
            else:
                lines.append(f"{prefix}{key}: {_yaml_scalar(val)}")
    return "\n".join(lines) + "\n"
