"""The ONE strict base64 decoder for untrusted wire bytes — v1.0.

WHY THIS MODULE EXISTS. Deep-gate iteration 7 (2026-08-26) confirmed L3-500-DSSEB64-02: a signed
receipt had an UNBOUNDED family of byte-distinct forms that all verified. ``dsse._b64decode_any``
fell back to ``base64.urlsafe_b64decode`` WITHOUT ``validate=True``, and CPython's default silently
DISCARDS characters outside the alphabet. Measured on the release candidate: a ``!``, a newline, a
space, a tab or a NUL inserted into a signed envelope's ``payload`` -- and into its ``signatures[].sig``
-- still returned ``verify=True`` while the file bytes differed. The project's own shipped Rust
verifier rejected the identical file ("Invalid symbol 33, offset 8").

WHAT WAS ACTUALLY BROKEN, stated narrowly so this is not read as more than it is: NOT signature
forgery and NOT a subject-binding bypass -- ``body_sha256`` and ``derive_subject_digest`` were
byte-identical across every accepted variant. What broke is CANONICAL WIRE-FORM IDENTITY: dedup,
replay detection and transparency-log leaf identity all assume one artefact has one accepted wire
form. RFC 4648 section 3.3 is explicit that a conforming decoder MUST reject characters outside the
alphabet, and two verifiers in one release disagreeing about the same file is a promise the release
cannot keep.

WHY THE DEFECT WAS INPUT-DEPENDENT, and therefore invisible for 26 days. The lax path discards the
junk and THEN checks padding, so whether it raises depends on the length that remains. Measured:
``urlsafe_b64decode(b"aGFsbG8gd2VsdA" + b"!" + pad)`` raises "Incorrect padding", while the same
insertion into a real DSSE payload decoded cleanly. A defect that fails loudly for some inputs and
silently for others cannot be found by trying one input.

THE CLASS, NOT THE INSTANCE. Every decode of an attacker-supplied base64 field reachable from an
exported ``verify_*``/``load_*`` goes through one of the three functions below. A named helper is
the point: a per-site ``validate=True`` would be correct today and would drift tomorrow, which is
exactly how the family grew to 26 sites in the first place.

WHAT THIS MODULE DELIBERATELY DOES NOT DO. ``decode_b64url`` accepts a character of EITHER alphabet
(``-_`` and ``+/``), because ``altchars`` translates before validating. That is a canonicality
question of its own -- one artefact, one alphabet -- and it is a DIFFERENT property from the one
the gate confirmed. Fixing it here would widen a gated change beyond what was measured and could
refuse producers that are conforming today. It is recorded as its own finding rather than folded in
silently: ``B64URL-AKZEPTIERT-BEIDE-ALPHABETE-EINE-ZWEITE-KANONIKALITAETSFRAGE-01``.

EXCEPTIONS. All three raise ``binascii.Error`` (a subclass of ``ValueError``) on any rejection, so
existing handlers written as ``except (ValueError, binascii.Error)`` keep working unchanged and no
caller needs a new except clause.
"""
from __future__ import annotations

import base64
import binascii

__all__ = ["decode_b64", "decode_b64url", "decode_b64_either"]


def _as_bytes(s: "str | bytes") -> bytes:
    """Accept the str and bytes forms both call sites use, rejecting anything else with the same
    error type as a malformed body -- a caller handing us an int must not get a TypeError out of a
    never-raise surface."""
    if isinstance(s, bytes):
        return s
    if isinstance(s, str):
        try:
            return s.encode("ascii")
        except UnicodeEncodeError as e:
            # A non-ASCII character cannot be base64 of any alphabet; say so in the wire vocabulary
            # rather than leaking a unicode error out of a decode.
            raise binascii.Error("non-ASCII character in base64 field") from e
    raise binascii.Error(f"base64 field must be str or bytes, got {type(s).__name__}")


def decode_b64(s: "str | bytes") -> bytes:
    """Standard base64 (``+/``), canonical padding REQUIRED. Rejects any character outside the
    alphabet instead of discarding it."""
    return base64.b64decode(_as_bytes(s), validate=True)


def decode_b64url(s: "str | bytes") -> bytes:
    """base64url with OPTIONAL padding (the JWT/JWS convention this codebase's compact segments
    use). Padding is computed from the ORIGINAL length -- never from what survives a filter -- and
    any character outside the alphabet is rejected.

    See the module docstring: a ``+`` or ``/`` also passes here, deliberately and on the record."""
    raw = _as_bytes(s)
    return base64.b64decode(raw + b"=" * (-len(raw) % 4), altchars=b"-_", validate=True)


def decode_b64_either(s: "str | bytes") -> bytes:
    """Standard OR url-safe, both arms STRICT -- for wire fields whose spec requires a verifier to
    accept either encoding (DSSE envelopes).

    The url-safe arm is tried only when the length is a multiple of 4 after the padding the JWS
    convention omits; anything else is a malformed field rather than a second guess."""
    raw = _as_bytes(s)
    try:
        return base64.b64decode(raw, validate=True)
    except (ValueError, binascii.Error):
        return base64.b64decode(raw + b"=" * (-len(raw) % 4), altchars=b"-_", validate=True)
