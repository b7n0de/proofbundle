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

from .bundle import verify_bundle
from .errors import BundleFormatError, UnsupportedError, VerificationResult

__all__ = ["TOKEN_PREFIX", "receipt_token", "verify_receipt_token",
           "to_eval_results_entry", "eval_results_yaml"]

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
        bundle = json.loads(raw)
    except BundleFormatError:
        raise
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


def to_eval_results_entry(bundle: dict, *, dataset_id: str, task_id: str, value,
                          date: Optional[str] = None, source_url: Optional[str] = None,
                          source_name: Optional[str] = None, source_user: Optional[str] = None,
                          notes: Optional[str] = None, include_token: bool = True,
                          require_verified: bool = True) -> dict:
    """Build one HF `.eval_results/*.yaml` entry for a receipt.

    ``dataset_id``/``task_id`` name the Hub benchmark (per its `eval.yaml`); ``value`` is the
    REQUIRED metric number — the caller chooses what to disclose (a receipt may withhold the
    exact score via SD-JWT; publishing a value here IS a disclosure decision).

    No-Fake guard: with ``require_verified=True`` (default) the bundle must verify NOW — an entry
    is never generated from a broken receipt. ``include_token=True`` puts the ``pb1.`` token in
    ``verifyToken`` (schema-valid, proofbundle-verifiable; NOT the HF-internal badge token — HF's
    "verified" badge is HF's server-side decision, and this module makes no claim about it).
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
