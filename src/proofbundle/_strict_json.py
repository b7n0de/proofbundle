"""Duplicate-key-rejecting JSON parsing — the one strict parser for every verify path (WP-C1).

``json.loads`` silently keeps the LAST occurrence of a duplicated key (last-wins). On a verify
path that is a classic parser differential (Bishop Fox 2021; the exact bug class behind several
JWT/JOSE CVEs): two implementations parsing the same bytes can disagree about which ``root_b64``
or ``sig_b64`` they verified, so "cross-verifier consensus" silently stops meaning one thing.
RFC 8785 (JCS) forbids duplicate keys outright, and the DSSE statement paths already reject them
INDIRECTLY (a duplicated payload cannot be byte-equal to its own canonical re-serialization) —
but the native bundle path accepted them silently, and an explicit reject with a clear message
beats an incidental byte-mismatch everywhere.

Rule: EVERY ``json.loads``/``json.load`` on attacker-supplied verify-path input goes through
:func:`loads_strict`. Emit-side inputs (a claim file the caller authored) use it too — a duplicate
key in something about to be signed is at best an authoring bug, at worst an attempted differential.

Stdlib-only (``object_pairs_hook``), so the base install keeps rejecting duplicates without any
extra. The hook fires for every nested object, so duplicates are rejected at ANY depth.
"""
from __future__ import annotations

import json
from typing import Any, Union

from .errors import BundleFormatError

__all__ = ["loads_strict"]


def _reject_duplicate_keys(pairs: list) -> dict:
    obj: dict = {}
    for key, value in pairs:
        if key in obj:
            raise BundleFormatError(
                f"duplicate JSON key {key!r} — rejected fail-closed (a duplicated key parses "
                "differently across JSON implementations; parser-differential guard, WP-C1)")
        obj[key] = value
    return obj


def loads_strict(text: Union[str, bytes]) -> Any:
    """``json.loads`` that rejects duplicate object keys at any nesting depth.

    Raises :class:`BundleFormatError` for a duplicate key (fail-closed, clear message) and maps
    ``RecursionError`` from pathologically deep nesting to the same documented malformed-input
    error (never a raw traceback) — mirroring :func:`proofbundle.bundle.load_bundle`. Ordinary
    JSON syntax errors keep raising ``ValueError`` (``json.JSONDecodeError``) so existing
    ``except (ValueError, ...)`` handling at the call sites stays correct."""
    try:
        return json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except RecursionError as exc:
        raise BundleFormatError("JSON nesting is too deep") from exc
