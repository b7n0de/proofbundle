"""Strict readers of the wire values an EQR carries: JSON bytes, base64url digests, times and URIs.

JSON is decoded with proofbundle's strict helper (duplicate keys refused at every depth, bytes after
the value refused), behind a front that refuses what that helper lets through and RFC 8259 / I-JSON
(RFC 7493) do not allow: a byte order mark, any encoding but UTF-8, NaN and the infinities, and an
integer outside the I-JSON range. Each refusal names its reason (rule 2 of the strict decoding
standard of 14 October 2026).
"""
from __future__ import annotations

import base64
import hashlib
import math
import re
from datetime import datetime, timedelta, timezone

import rfc8785

from proofbundle._strict_json import loads_strict

#: RFC 7493 section 2.2: an I-JSON integer is exactly representable as an IEEE 754 double.
I_JSON_MAX = 2 ** 53 - 1
SHA256_B64U_LEN = 43


class WireError(ValueError):
    """A wire value this reader refuses, with the reason."""


def decode_json(raw: bytes):
    """One JSON value from exact bytes, or WireError naming why the bytes are refused."""
    if not isinstance(raw, (bytes, bytearray)):
        raise WireError("the receipt must be given as bytes")
    raw = bytes(raw)
    if raw.startswith(b"\xef\xbb\xbf"):
        raise WireError("a byte order mark precedes the JSON text (RFC 8259 section 8.1)")
    try:
        text = raw.decode("utf-8", "strict")
    except UnicodeDecodeError as exc:
        raise WireError(f"the bytes are not UTF-8 (RFC 8259 section 8.1, RFC 7493 section 2.1): {exc.reason}") from exc
    if "\x00" in text:
        raise WireError("the text contains NUL, which no UTF-8 JSON text of this kind carries")
    try:
        value = loads_strict(text)
    except Exception as exc:  # noqa: BLE001 - every refusal of the strict helper is a refusal here
        raise WireError(f"strict JSON decoding refused the bytes: {type(exc).__name__}: {exc}") from exc
    _i_json(value)
    return value


def _i_json(value, path="$"):
    stack = [(value, path)]
    while stack:
        v, p = stack.pop()
        if isinstance(v, bool) or v is None or isinstance(v, str):
            continue
        if isinstance(v, int):
            if abs(v) > I_JSON_MAX:
                raise WireError(f"{p}: integer outside the I-JSON range (RFC 7493 section 2.2)")
            continue
        if isinstance(v, float):
            if not math.isfinite(v):
                raise WireError(f"{p}: NaN or an infinity is no JSON number (RFC 8259 section 6)")
            continue
        if isinstance(v, list):
            stack.extend((x, f"{p}[{i}]") for i, x in enumerate(v))
            continue
        if isinstance(v, dict):
            stack.extend((x, f"{p}.{k}") for k, x in v.items())
            continue
        raise WireError(f"{p}: {type(v).__name__} is no JSON value")


_B64U = re.compile(r"^[A-Za-z0-9_-]*$")


def b64u_decode(s: str) -> bytes:
    """Base64url without padding (RFC 4648 section 5), canonical form only."""
    if not isinstance(s, str) or not _B64U.match(s):
        raise WireError("not base64url without padding (RFC 4648 section 5): characters outside the alphabet "
                        "or padding")
    if len(s) % 4 == 1:
        raise WireError("base64url text of impossible length")
    raw = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    if base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii") != s:
        raise WireError("base64url text is not in canonical form (non-zero trailing bits)")
    return raw


def b64u_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def sha256_b64u(raw: bytes) -> str:
    return b64u_encode(hashlib.sha256(raw).digest())


def check_digest(s) -> None:
    """A sha-256 digest value in base64url without padding (Section 5, S5-5)."""
    raw = b64u_decode(s)
    if len(raw) != 32 or len(s) != SHA256_B64U_LEN:
        raise WireError(f"a sha-256 digest has 32 bytes, this one has {len(raw)}")


def jcs(value) -> bytes:
    """RFC 8785 bytes of a JSON value (Section 5, S5-1)."""
    try:
        return rfc8785.dumps(value)
    except Exception as exc:  # noqa: BLE001 - every refusal of the canonicalizer is a refusal here
        raise WireError(f"the value has no RFC 8785 form: {type(exc).__name__}: {exc}") from exc


_RFC3339 = re.compile(r"^(\d{4})-(\d{2})-(\d{2})[Tt](\d{2}):(\d{2}):(\d{2})(\.\d+)?([Zz]|[+-]\d{2}:\d{2})$")


def parse_time(s):
    """An RFC 3339 date-time (section 5.6) as an aware UTC datetime. Seconds 60 (a leap second) cannot be
    placed on a timeline here and is refused, with that reason."""
    if not isinstance(s, str):
        raise WireError("a time must be a string in RFC 3339 form")
    m = _RFC3339.match(s)
    if not m:
        raise WireError(f"{s!r} is not an RFC 3339 date-time")
    year, month, day, hour, minute, second = (int(m.group(i)) for i in range(1, 7))
    if second == 60:
        raise WireError(f"{s!r}: a leap second is not placed on a timeline by this reader")
    frac = m.group(7) or ""
    micro = int((frac[1:] + "000000")[:6]) if frac else 0
    off = m.group(8)
    try:
        if off in ("Z", "z"):
            tz = timezone.utc
        else:
            sign = 1 if off[0] == "+" else -1
            oh, om = int(off[1:3]), int(off[4:6])
            if oh > 23 or om > 59:
                raise ValueError("offset out of range")
            tz = timezone(sign * timedelta(hours=oh, minutes=om))
        return datetime(year, month, day, hour, minute, second, micro, tzinfo=tz).astimezone(timezone.utc)
    except ValueError as exc:
        raise WireError(f"{s!r} is not a valid RFC 3339 date-time: {exc}") from exc


_URI = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*:[^\s\x00-\x1f\x7f]+$")


def check_uri(s) -> None:
    """An absolute URI with a scheme (RFC 3986 section 3); no whitespace or control characters."""
    if not isinstance(s, str) or not _URI.match(s):
        raise WireError(f"{s!r} is not a URI with a scheme (RFC 3986 section 3)")
