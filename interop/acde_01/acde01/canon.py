"""Canonical bytes, digests and time values used by this implementation's profile.

The draft leaves projection, digest algorithm, canonicalisation and domain separation to the
profile (R-CD-2, lines 665-668). This implementation supports exactly one combination and names it
in the profile; any other value is a profile error, never a silent fallback (Section 10.1, lines
1594-1595: downgrade-resistant selection).
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

PROJECTION = "canonical-json-v1"
DIGEST_ALG = "sha-256"
CANONICALIZATION = "json-sorted-keys-no-whitespace-utf8"
DOMAIN_SEPARATION = "acde01-instruction-v1"
_DOMAIN_PREFIX = b"acde01-instruction-v1\x00"


class CanonError(ValueError):
    """A value that this implementation's canonical projection does not cover."""


def _check_value(v, path="$"):
    if v is None or isinstance(v, (bool, str)):
        return
    if isinstance(v, int):
        return
    if isinstance(v, float):
        raise CanonError(f"{path}: floating-point values are outside the canonical projection")
    if isinstance(v, list):
        for i, x in enumerate(v):
            _check_value(x, f"{path}[{i}]")
        return
    if isinstance(v, dict):
        for k, x in v.items():
            if not isinstance(k, str):
                raise CanonError(f"{path}: object keys must be strings")
            _check_value(x, f"{path}.{k}")
        return
    raise CanonError(f"{path}: {type(v).__name__} is not a JSON value")


def canonical_bytes(value) -> bytes:
    _check_value(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def instruction_digest(content) -> str:
    """Digest of the declared canonical projection of an instruction, with domain separation."""
    return "sha-256:" + hashlib.sha256(_DOMAIN_PREFIX + canonical_bytes(content)).hexdigest()


def document_digest(value) -> str:
    """Digest of any JSON document (input, report, target set) in canonical form, no domain prefix."""
    return "sha-256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def is_digest(s) -> bool:
    if not isinstance(s, str) or not s.startswith("sha-256:"):
        return False
    h = s[len("sha-256:"):]
    return len(h) == 64 and all(c in "0123456789abcdef" for c in h)


def parse_time(s):
    """RFC 3339 UTC time with a literal Z, to an aware datetime. None for anything else."""
    if not isinstance(s, str) or not s.endswith("Z") or "T" not in s:
        return None
    try:
        dt = datetime.fromisoformat(s[:-1] + "+00:00")
    except ValueError:
        return None
    return dt.astimezone(timezone.utc)
