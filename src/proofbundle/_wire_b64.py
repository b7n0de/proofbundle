"""The ONE strict base64 decoder family for untrusted wire bytes — v1.1 (canonical, not merely valid).

WHY THIS MODULE EXISTS. Deep-gate iteration 7 (2026-08-26) confirmed L3-500-DSSEB64-02: a signed
receipt had an UNBOUNDED family of byte-distinct forms that all verified. ``dsse._b64decode_any``
fell back to ``base64.urlsafe_b64decode`` WITHOUT ``validate=True``, and CPython's default silently
DISCARDS characters outside the alphabet. Measured on the release candidate: a ``!``, a newline, a
space, a tab or a NUL inserted into a signed envelope's ``payload`` -- and into its ``signatures[].sig``
-- still returned ``verify=True`` while the file bytes differed. The project's own shipped Rust
verifier rejected the identical file ("Invalid symbol 33, offset 8").

WHAT v1.0 STILL LEFT OPEN, and deep gate run 3 on 049b3195 (2026-09-05, finding L1-600-01, class
``canonicity_preserving_perturbation_accepted`` / RT-08) measured it: ``validate=True`` rejects
characters outside the alphabet and a missing pad character, but it does NOT reject NON-ZERO PAD
BITS -- ``base64.b64decode(b"QUJ=", validate=True) == b"AB"`` on CPython 3.10 and 3.11, the same
bytes as the canonical ``QUI=``. RFC 4648 section 3.5 names this: a canonical encoding has zero
pad bits, and a decoder MAY reject anything else. This one MUST, because the invariant this module
guards is "one signed artefact, ONE accepted wire form". Three further forms of the same defect were
measured on the same day: an unpadded standard string re-padded and accepted by the url-safe arm;
the url-safe alphabet accepted where the format mandates standard; and the shipped Rust verifier
TRIMMING whitespace that Python refuses -- two verifiers in one release disagreeing about the same
file, in both directions.

THE CLASS, NOT THE INSTANCE. Every decode of an attacker-supplied base64 field reachable from an
exported ``verify_*``/``load_*`` goes through one of the named helpers below -- and NO module in the
shipped tree calls the stdlib decoders directly any more (``tests/test_wire_bytes_strict.py`` reads
the AST and refuses any such call outside this file). A per-site ``validate=True`` was correct for
the alphabet and wrong for the pad bits, and it drifted to 40 sites; the property has to live in
one place or it does not live at all.

HOW CANONICALITY IS CHECKED. Decode strictly, then RE-ENCODE and compare with the input bytes. The
re-encode comparison is the complete test in one line: it fails for a foreign alphabet character, a
missing or surplus pad character, non-zero pad bits and any whitespace, and it cannot be made
wrong by a future stdlib change to what ``validate=True`` happens to check.

THE FOUR HELPERS.

* ``decode_b64``      -- RFC 4648 section 4 (``+/``), padding REQUIRED, canonical. Native bundle
                          fields, public keys, Merkle roots, anchors: the format mandates standard.
* ``decode_b64url``   -- RFC 4648 section 5 (``-_``), padding ABSENT (RFC 7515 section 2, the JWS
                          convention every compact segment in this codebase uses), canonical. A
                          padded input is a second wire form of the same segment and is refused;
                          v1.0's deliberate acceptance of ``+/`` here (recorded as
                          ``B64URL-AKZEPTIERT-BEIDE-ALPHABETE-EINE-ZWEITE-KANONIKALITAETSFRAGE-01``)
                          is closed by the same comparison.
* ``decode_b64_either`` -- DSSE envelopes only: the DSSE envelope specification (verified
                          2026-09-05, "Either standard or URL-safe encoding is allowed") makes a
                          verifier accept BOTH alphabets, and says nothing about padding, so RFC 4648
                          section 3.2 applies: padding is REQUIRED. Two alphabets, each canonical,
                          each padded -- exactly the rule the shipped Rust verifier enforces
                          (``base64`` 0.22 STANDARD / URL_SAFE), so the two verifiers agree.
* ``decode_b64_c2sp``  -- C2SP signed-note fields (checkpoint body, vkey key material, signature
                          lines) ONLY. The reference implementation is Go's ``encoding/base64``
                          StdEncoding, which is strict on the alphabet and on the presence of
                          padding but LENIENT on pad bits unless ``Strict()`` is used, and the
                          ecosystem's notes are verified by that decoder. Refusing non-zero pad bits
                          here would make this verifier disagree with the format's own reference
                          verifier, so the leniency is kept and named in ONE place instead of being
                          an accident at ten sites. This is the documented exception to the
                          one-wire-form rule, not a forgotten member of the family.

EXCEPTIONS. All helpers raise ``binascii.Error`` (a subclass of ``ValueError``) on any rejection --
including a non-str/bytes input -- so existing handlers written as ``except (ValueError, TypeError)``
or ``except binascii.Error`` keep working unchanged and no caller needs a new except clause.
"""
from __future__ import annotations

import base64
import binascii

__all__ = ["decode_b64", "decode_b64url", "decode_b64_either", "decode_b64_c2sp"]


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


def _canonical_std(raw: bytes) -> bytes:
    """Standard alphabet, padded, canonical: decode strictly, re-encode, demand byte equality."""
    out = base64.b64decode(raw, validate=True)
    if base64.b64encode(out) != raw:
        raise binascii.Error("non-canonical base64 (padding or pad bits): one artefact, one wire form")
    return out


def _canonical_url_padded(raw: bytes) -> bytes:
    """URL-safe alphabet, padded, canonical (the DSSE second alphabet)."""
    out = base64.b64decode(raw, altchars=b"-_", validate=True)
    if base64.urlsafe_b64encode(out) != raw:
        raise binascii.Error("non-canonical base64url (padding or pad bits): one artefact, one wire form")
    return out


def decode_b64(s: "str | bytes") -> bytes:
    """Standard base64 (``+/``), canonical padding REQUIRED, pad bits zero, no whitespace. Rejects
    any character outside the alphabet instead of discarding it, and any second spelling of the
    same bytes."""
    return _canonical_std(_as_bytes(s))


def decode_b64url(s: "str | bytes") -> bytes:
    """base64url WITHOUT padding (RFC 7515 section 2 -- the JWT/JWS/SD-JWT convention every compact
    segment in this codebase uses), canonical: the url-safe alphabet only, no pad character, pad
    bits zero, no whitespace. Padding is computed from the ORIGINAL length -- never from what
    survives a filter -- and the decoded bytes must re-encode to exactly the input."""
    raw = _as_bytes(s)
    out = base64.b64decode(raw + b"=" * (-len(raw) % 4), altchars=b"-_", validate=True)
    if base64.urlsafe_b64encode(out).rstrip(b"=") != raw:
        raise binascii.Error("non-canonical base64url (alphabet, padding or pad bits): one artefact, one wire form")
    return out


def decode_b64_either(s: "str | bytes") -> bytes:
    """DSSE envelope fields: standard OR url-safe alphabet (the specification's MUST), each padded
    and canonical. An unpadded string is a malformed field, not a second guess -- RFC 4648
    section 3.2 requires padding unless the referencing specification says otherwise, and the DSSE
    envelope specification does not. This is the rule the shipped Rust verifier enforces, so
    Python and Rust return the same verdict for the same file."""
    raw = _as_bytes(s)
    try:
        return _canonical_std(raw)
    except (ValueError, binascii.Error):
        return _canonical_url_padded(raw)


def decode_b64_c2sp(s: "str | bytes") -> bytes:
    """C2SP signed-note fields ONLY: standard alphabet, padding REQUIRED, characters outside the
    alphabet refused -- but NON-ZERO PAD BITS TOLERATED, because Go's ``encoding/base64``
    StdEncoding (the reference verifier of the note format) tolerates them unless ``Strict()`` is
    used. The leniency is the format's, named here once; every other helper in this module refuses
    it. Do not use this for any field that is not a C2SP note field."""
    return base64.b64decode(_as_bytes(s), validate=True)
