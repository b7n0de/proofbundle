"""Strict RFC 4648 base64 decoding — one implementation for every wire-bytes surface.

Why this module exists (adversarial deep gate 2026-07, finding L5-02): Python's
``base64.b64decode`` / ``base64.urlsafe_b64decode`` **discard** every character outside the
base alphabet unless ``validate=True`` is passed. RFC 4648 §3.3 says a decoder MUST reject data
outside the alphabet, and for a SIGNED artefact the lax behaviour is worse than a spec
deviation: a 1511-byte DSSE envelope inflated to 51511 bytes with 50000 injected junk characters
decoded to the same bytes and still verified ``ok=True``. It is not a signature bypass (the
decoded bytes are identical) but it means a signed artefact has an unbounded number of byte
forms that verify, when exactly one should.

The strict idiom already existed in this repo (``bundle._b64d`` uses ``validate=True``), but the
JWS/DSSE siblings kept the pre-fix lax shape. This module is the single implementation they all
call, so a ninth wire surface has an obvious right way to decode.
``tests/test_wire_bytes_strict.py`` enforces that property over the whole package by AST
discovery, not over a list of known files.

Alphabets. A single string must use ONE alphabet. Standard (RFC 4648 §4, ``+/``) and url-safe
(§5, ``-_``) are both accepted by :data:`EITHER`, because DSSE requires a verifier to accept
either (secure-systems-lab/dsse protocol.md) and because every JWS surface here accepted both
before this change — restricting them to §5 would reject bytes a third-party producer may
legitimately have emitted. MIXING the two alphabets inside one string is rejected: that is a
second wire form for the same bytes, exactly the malleability this module exists to close.

Padding stays optional (``=`` is appended as needed). The JWS/SD-JWT wire form is unpadded by
spec and the DSSE emit side is padded, so both must decode; over-padding beyond two ``=`` or a
``=`` in the middle is rejected by ``validate=True``.

Errors are always :class:`binascii.Error` (a ``ValueError`` subclass), which is what every call
site in this package already catches — a strict decoder must not turn a rejection into a crash
on a never-raise surface.
"""

from __future__ import annotations

import base64
import binascii

__all__ = ["EITHER", "STANDARD", "b64decode_strict"]

#: accept only the standard RFC 4648 §4 alphabet (``+/``)
STANDARD = "standard"
#: accept the standard §4 or the url-safe §5 alphabet, but not both inside one string
EITHER = "either"

_URLSAFE_TO_STANDARD = str.maketrans("-_", "+/")
_STANDARD_ONLY_CHARS = ("+", "/")
_URLSAFE_ONLY_CHARS = ("-", "_")


def _as_text(value: object) -> str:
    """ASCII text view of ``value``; anything else is malformed input, never a raw crash."""
    if isinstance(value, str):
        return value
    if isinstance(value, (bytes, bytearray, memoryview)):
        try:
            return bytes(value).decode("ascii")
        except UnicodeDecodeError as exc:
            raise binascii.Error("base64 input is not ASCII") from exc
    raise binascii.Error(f"base64 input must be str or bytes, not {type(value).__name__}")


def b64decode_strict(value: object, *, alphabet: str = EITHER) -> bytes:
    """Decode base64 ``value`` strictly: reject every character outside the chosen alphabet.

    ``alphabet`` is :data:`STANDARD` (RFC 4648 §4 only) or :data:`EITHER` (§4 or §5, never mixed
    within one string). Padding is optional. Raises :class:`binascii.Error` on any input that is
    not exactly one canonical encoding of the returned bytes.
    """
    if alphabet not in (STANDARD, EITHER):
        raise ValueError(f"unknown alphabet {alphabet!r} (use STANDARD or EITHER)")
    text = _as_text(value)
    if alphabet == EITHER:
        if (any(c in text for c in _URLSAFE_ONLY_CHARS)
                and any(c in text for c in _STANDARD_ONLY_CHARS)):
            # Two alphabets in one string is a second wire form for the same bytes.
            raise binascii.Error("base64 input mixes the standard and url-safe alphabets")
        text = text.translate(_URLSAFE_TO_STANDARD)
    padded = text + "=" * (-len(text) % 4)
    # validate=True is the whole point: without it a2b_base64 silently drops non-alphabet bytes.
    return base64.b64decode(padded, validate=True)
