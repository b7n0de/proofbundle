"""DSSE (Dead Simple Signing Envelope) v1 over Ed25519 — for the in-toto test-result export (v0.9).

Spec verified 2026-07 against secure-systems-lab/dsse (protocol.md, envelope.md) and in-toto/attestation
(spec/v1/envelope.md). The one thing that must be exact:

    PAE(type, body) = "DSSEv1" SP LEN(type) SP type SP LEN(body) SP body

where SP is a single ASCII space (0x20), LEN(s) is the ASCII decimal BYTE length of s with no leading
zeros, `type` is the UTF-8 bytes of payloadType, and `body` is the RAW serialized payload bytes. The
signature is computed over PAE(payloadType, RAW body) — **never over the base64 string** (the classic DSSE
trap). Only the envelope's `payload` and each `signatures[].sig` are base64 (standard RFC 4648 §4, with
padding, NOT base64url); `payloadType` and `keyid` are plaintext.

Verification decodes `payload` and reconstructs PAE over the exact decoded bytes — it never re-serializes
or re-canonicalizes the JSON (that would change bytes and break the signature). We never roll our own
crypto: signing is `cryptography`'s Ed25519, verification is
`proofbundle.signature.verify_ed25519_pinned`.

Base64 note: the envelope's `payload` and each `signatures[].sig` are base64. We EMIT standard RFC 4648 §4
(with padding), but the DSSE spec says a signer MAY use either standard or url-safe base64 and a verifier
MUST accept either — so verification accepts both alphabets. (This is distinct from the C2SP checkpoint,
which mandates standard base64.) The "classic DSSE trap" is a different thing: the SIGNATURE is over the
raw PAE body, never over the base64 string.
"""
from __future__ import annotations

import base64
import binascii
import hashlib
from typing import Any, Optional

from .canonical import _ein_stand, _plain_for_jcs, _puffer_von, _zeichen_von
from .errors import BundleFormatError
from .signature import verify_ed25519_pinned
from ._wire_b64 import decode_b64_either

__all__ = ["openssh_sha256_keyid", "pae", "sign_envelope", "verify_envelope"]


def _b64decode_any(s: str) -> bytes:
    """Decode standard OR url-safe base64 (DSSE verifiers MUST accept either). Tries standard first, then
    url-safe; raises binascii.Error if neither is valid."""
    return decode_b64_either(s)


@_ein_stand
def pae(payload_type: str, body: bytes) -> bytes:
    """DSSEv1 Pre-Authentication Encoding. Signed/verified over the RAW body bytes, never base64.

    Both inputs are read by what they hold (round 12): the type as its characters
    (`canonical._zeichen_von`), the body as its stored bytes (`canonical._puffer_von`: bytes, a
    bytearray, or the bytes a ``memoryview`` views, the three the concatenation took before). At
    cd5d39f4 a ``str`` subclass's own ``encode`` gave the signed PAE another type than the envelope
    wrote, and a ``bytes`` subclass's own ``__len__`` and ``__radd__`` another length and body than it
    stores. A value of another type is BundleFormatError."""
    typ_text, body = _zeichen_von(payload_type), _puffer_von(body)
    if typ_text is None or body is None:
        raise BundleFormatError("DSSE PAE needs a str payload type and a bytes body")
    t = typ_text.encode("utf-8")
    return (b"DSSEv1 " + str(len(t)).encode("ascii") + b" " + t + b" "
            + str(len(body)).encode("ascii") + b" " + body)


@_ein_stand
def openssh_sha256_keyid(public_key_raw: bytes) -> str:
    """OpenSSH's SHA256 fingerprint of a raw 32-byte Ed25519 public key: ``SHA256:`` and the unpadded
    standard base64 of SHA-256 over the key's SSH wire form (RFC 8709 section 4: string "ssh-ed25519",
    string key). It is the keyid go-securesystemslib's ``dsse.SHA256KeyID`` derives and the one sigstore's
    key providers compare, measured against securesystemslib 1.5.1 and GUAC 1.1.0 in
    tools/intoto_external on claude/intoto-external (Z225, finding F3)."""
    if not isinstance(public_key_raw, bytes) or len(public_key_raw) != 32:
        raise ValueError("an Ed25519 public key is 32 raw bytes")

    def string(b: bytes) -> bytes:
        return len(b).to_bytes(4, "big") + b

    digest = hashlib.sha256(string(b"ssh-ed25519") + string(public_key_raw)).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def _default_keyid(signer) -> Optional[str]:
    """The keyid of an Ed25519 signer, or None for a signer that exposes no Ed25519 public key."""
    try:
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # noqa: PLC0415
        raw = signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    except (AttributeError, TypeError, ValueError):
        return None
    return openssh_sha256_keyid(raw) if isinstance(raw, bytes) and len(raw) == 32 else None


@_ein_stand(aussen={"signer": "signierer"})
def sign_envelope(body: bytes, signer, *, payload_type: str, keyid: Optional[str] = None) -> dict:
    """Sign the RAW `body` bytes into a DSSE envelope. `signer` is an Ed25519 private key (its `.sign`
    signs PAE(payload_type, body)). Returns {payload, payloadType, signatures:[{sig[, keyid]}]}.

    The type, the body and the key id are read once, by what they hold, and the envelope carries
    exactly what was signed (round 12): at cd5d39f4 the envelope wrote the caller's own objects
    beside a PAE built from their ``encode`` and ``__radd__``. The body is read as `pae` reads it.

    The in-toto envelope layer says a keyid SHOULD be included for each signing key (in-toto/attestation
    v1.2.0, spec/v1/envelope.md), and securesystemslib and GUAC refuse an envelope without one (Z225, F3).
    So `keyid=None` writes the signer's OpenSSH SHA256 fingerprint (`openssh_sha256_keyid`), a given
    string is written as it is, and `keyid=""` writes none. The keyid is not signed; no verifier in this
    package reads it for a verdict."""
    typ_text, body = _zeichen_von(payload_type), _puffer_von(body)
    if typ_text is None or body is None:
        raise BundleFormatError("DSSE sign_envelope needs a str payload type and a bytes body")
    if keyid is not None and _zeichen_von(keyid) is None:
        raise BundleFormatError("DSSE keyid must be a string or None")
    keyid = _zeichen_von(keyid) if keyid is not None else None
    payload_type = typ_text
    sig = signer.sign(pae(payload_type, body))
    entry = {"sig": base64.b64encode(sig).decode("ascii")}
    if keyid is None:
        keyid = _default_keyid(signer)
    if keyid:
        entry = {"keyid": keyid, "sig": entry["sig"]}
    return {
        "payload": base64.b64encode(body).decode("ascii"),
        "payloadType": payload_type,
        "signatures": [entry],
    }


def _within_budget(envelope: Any) -> None:
    # Structural budget (deep gate wf_cfe249d0-ee8, finding L2-01, P1). This module already bounded TWO
    # dimensions — the base64 payload against input_bytes below, and the signatures COUNT before the verify
    # loop — which is exactly why the gap was easy to miss: the surface looked bounded. It was not. The
    # remaining dimensions were inert on this DIRECT-DICT path, and `signatures[i].sig` in particular is an
    # unbounded attacker-controlled string that reaches `_b64decode_any` in the loop, once per entry up to
    # the signatures cap. A COUNT bound and a SIZE bound are different bounds; having one is not having both.
    #
    # The check sits here rather than in verify_envelope so `load_payload` — the other member of the family
    # — is covered by the same statement instead of by a second call site that can drift out of step.
    from ._strict_json import enforce_structural_budget  # noqa: PLC0415 - local import avoids a cycle
    from .errors import ProofBundleError  # noqa: PLC0415
    try:
        enforce_structural_budget(envelope)
    # ProofBundleError, NICHT nur BudgetExceeded — und der Unterschied ist keine Kosmetik.
    # enforce_structural_budget wirft ZWEI Geschwister: BudgetExceeded bei Ueberbreite, aber
    # BundleFormatError ("JSON nesting is too deep") bei Uebertiefe. Ein schmaler catch faengt nur den
    # ersten. Das ist HEUTE folgenlos, weil der Tiefen-Zweig zufaellig genau den Typ wirft, den diese
    # Funktion ohnehin dokumentiert — aber der Kommentar unten verspricht eine STRUKTURELLE Eigenschaft
    # ("a direct third-party caller never sees a raw sibling exception"), und die haengt dann am Zufall.
    # Die schmale Form stammt aus Zeile 134, wo sie richtig ist: DEFAULT_BUDGET.check wirft nur
    # BudgetExceeded. Sie wurde auf einen Aufruf mit breiterer Fehlerflaeche uebertragen.
    # Die fuenf Geschwister-Flaechen desselben Fixes fangen alle ProofBundleError.
    except ProofBundleError as exc:
        # Same mapping this module already applies twice: the docstrings of the public surfaces name only
        # BundleFormatError, so a direct third-party caller never sees a raw sibling exception.
        raise BundleFormatError(f"DSSE envelope exceeds the verification budget (fail-closed): {exc}") from exc


def _payload_of(envelope: dict) -> bytes:
    p = envelope.get("payload")
    if not isinstance(p, str):
        raise BundleFormatError("DSSE envelope.payload must be a base64 string")
    # DoS (crypto-review 2026-07-15): refuse an oversized base64 payload BEFORE decoding it. The DECODED
    # bytes are capped by each verify_* entry point, but the base64-decode here (which also runs a second
    # time via load_payload) is otherwise unbounded — a 16 MiB base64 string is fully decoded before any
    # cap fires. Cap the raw base64 string against input_bytes (admits ~6 MiB of decoded bytes, comfortably
    # above any legitimate payload; the decoded value is separately re-checked downstream).
    from .budget import DEFAULT_BUDGET  # noqa: PLC0415 - local import avoids a cycle
    if len(p) > DEFAULT_BUDGET.input_bytes:
        # adversarial re-audit round 6: this public verify/load surface documents ONLY BundleFormatError as its
        # malformed-input signal, so an oversized payload maps to it — not a raw BudgetExceeded sibling that
        # a direct third-party caller of verify_envelope / load_payload (following the docstring) would leak.
        raise BundleFormatError(
            f"DSSE envelope.payload exceeds the {DEFAULT_BUDGET.input_bytes}-byte input_bytes budget (fail-closed)")
    try:
        return _b64decode_any(p)
    except (ValueError, TypeError, binascii.Error) as exc:
        raise BundleFormatError("DSSE envelope.payload is not valid base64") from exc


@_ein_stand
def verify_envelope(envelope: dict, public_key: bytes, *, payload_type: Optional[str] = None) -> bool:
    """Verify a DSSE envelope against `public_key` (32 raw Ed25519 bytes). Decodes `payload` and rebuilds
    PAE over exactly those bytes (never re-serialized). True iff at least one signature verifies. If
    `payload_type` is given it MUST equal the envelope's payloadType (pin the type — a Sign/Verify type
    mismatch silently changes the PAE and would otherwise reject a genuine envelope for the wrong reason).

    `public_key` is always a key the CALLER trusts (a DSSE envelope carries none of its own), so a
    malformed, non-canonical or low-order key verifies nothing: under a low-order key a signature made
    with no private key is valid (for every payload under the identity point), and a non-canonical one
    is refused because a trusted key has exactly one encoding. Deep gate Z195, L1-Z195-03: `decision verify --pub`
    with the identity point printed "CRYPTO: OK" and exited 0 for a receipt nobody signed, while the
    same key in a trust policy was refused. Every DSSE verify path (decision, outcome, relation
    statement, run ledger, verification summary, in-toto exports, agent review, the CLI's related
    targets) funnels through this one judgment, `_verify_body`, over the one plain reading of the
    envelope (`_read_once`).

    THE ENVELOPE IS READ ONCE HERE TOO (round 12). Round 11 gave its own verify sites one reading
    and left this call reading the caller's object through its own ``get``; lens run 11 (F8) measured
    the two answering differently for the same input. Now both are the same judgment over the same
    copy: an envelope holding a value that is no JSON value is BundleFormatError here as there, and a
    tuple of signatures is read as the array JSON writes it. A parsed file holds only plain JSON
    values, so nothing changes for one. ``payload_type`` is compared by its characters."""
    umschlag = _read_once(envelope)
    return _verify_body(umschlag, _payload_of(umschlag), public_key, payload_type)


def _verify_body(envelope: dict, body: bytes, public_key: bytes, payload_type: Optional[str]) -> bool:
    """The judgment of `verify_envelope` over the decoded ``body``, reading ``payloadType`` and
    ``signatures`` from ``envelope``, in the order and with the refusals `verify_envelope` has
    always had."""
    from .budget import DEFAULT_BUDGET  # noqa: PLC0415 - local import matches repo convention, avoids any cycle
    ptype = envelope.get("payloadType")
    if not isinstance(ptype, str) or not ptype:
        raise BundleFormatError("DSSE envelope.payloadType must be a non-empty string")
    # The pinned type is compared by its characters (round 12, O1's class): at cd5d39f4 a `str`
    # subclass's own `__ne__` decided whether an envelope of another type was judged at all.
    if payload_type is not None and ptype != _zeichen_von(payload_type):
        return False
    sigs = envelope.get("signatures")
    if not isinstance(sigs, list) or not sigs:
        raise BundleFormatError("DSSE envelope.signatures must be a non-empty list")
    # Finding 15b DoS backstop (crypto-review, 2026-07-15): cap the attacker-controlled signatures list
    # BEFORE the verify loop. Without this, a tiny payload + a million-entry signatures list drives ~O(n)
    # Ed25519 verifies (no early exit, since none verify) = seconds of CPU per request — the input_bytes cap
    # bounds only the decoded payload, not this list. This is the single chokepoint every DSSE verify_*
    # entry point (decision/outcome/verification_summary/run_ledger) funnels through; trust_pack keeps its
    # own equivalent cap before its separate threshold loop. BudgetExceeded is a ProofBundleError subclass,
    # so existing except(ProofBundleError) sites already treat it as fail-closed malformed/over-limit input.
    # adversarial re-audit round 6: map it to the documented BundleFormatError so a DIRECT third-party caller of
    # verify_envelope (docstring says only BundleFormatError) never gets a raw BudgetExceeded on a huge list.
    from .budget import BudgetExceeded  # noqa: PLC0415
    try:
        DEFAULT_BUDGET.check("signatures", len(sigs))
    except BudgetExceeded as exc:
        raise BundleFormatError(f"DSSE envelope has too many signatures (fail-closed): {exc}") from exc
    msg = pae(ptype, body)
    for entry in sigs:
        if not isinstance(entry, dict):
            continue
        raw = entry.get("sig")
        if not isinstance(raw, str):
            continue
        try:
            sig = _b64decode_any(raw)
        except (ValueError, TypeError, binascii.Error):
            continue
        if verify_ed25519_pinned(public_key, sig, msg):
            return True
    return False


@_ein_stand
def load_payload(envelope: dict) -> bytes:
    """Return the raw decoded payload bytes (the in-toto Statement JSON) — for a verified envelope.

    From the one plain reading of the envelope (`_read_once`, round 12), as `verify_envelope` reads
    it, so the two calls answer from what the envelope stores and not from its own methods."""
    return _payload_of(_read_once(envelope))


def _read_once(envelope: Any) -> dict:
    """THE ONE READING of a caller's envelope: the plain copy of what it stores, after the budget.

    THE CLASS (round 11, lens run 10 at fa555f13, findings L4 to L6): the bytes a signature is
    checked over and the bytes that are parsed were two readings of the caller's object.
    `verify_envelope` read ``payload`` through the envelope's own ``get``, and `load_payload` read
    it again the same way. Measured at fa555f13 (and by the lens on main 31816e08) with a dict
    subclass that stores the signed payload and whose ``__getitem__`` and ``get`` answer with
    another from the second read on: `intoto.verify_intoto_dsse`, `verify_eval_result_dsse` and
    `verify_svr_dsse` returned ok=True over a statement the signature does not cover (``result``
    PASSED against a signed FAILED, and SVR properties nobody signed).

    The envelope is read here once and by what it stores: its type is its own (``issubclass`` on
    ``type(envelope)``), the structural budget walks its stored contents, and the copy
    (`canonical._plain_for_jcs`) reads containers through the base types' methods and a ``str``
    subclass as the characters it holds, so no ``__getitem__``, ``get`` or ``encode`` of the caller
    runs. Everything after reads only the copy, which nobody else holds. What the copy refuses is
    refused here, as this module's BundleFormatError: a value that is no JSON value (bytes, a set, a
    key that is not a string) and two keys with the same characters. A tuple is read as the array
    JSON writes it, as the copy reads it everywhere.

    Since round 12 `verify_envelope` and `load_payload` read through here as well, so a caller that
    pairs them reads the envelope's stored contents twice and no method of it; `_verify_and_load` is
    still the one call that returns the verdict with the bytes it judged."""
    if not issubclass(type(envelope), dict):
        raise BundleFormatError("DSSE envelope must be a JSON object")
    _within_budget(envelope)
    return _plain_for_jcs(envelope, lambda text: BundleFormatError(f"DSSE envelope: {text}"))


def _verify_and_load(envelope: Any, public_key: bytes, *,
                     payload_type: Optional[str] = None) -> tuple[bool, bytes]:
    """``(verdict, body)`` from ONE reading of ``envelope`` (`_read_once`): ``body`` is the payload the
    signature was checked over, and the caller parses exactly those bytes.

    The verdict is `verify_envelope`'s: the same reading and the same judgment (`_verify_body`), so
    the same refusals in the same order (lens run 11, F8: at cd5d39f4 this sentence was false,
    because `verify_envelope` still read the caller's object). The body is returned whatever the
    verdict, as `load_payload` did for the callers that report the statement of an envelope that does
    not verify."""
    umschlag = _read_once(envelope)
    body = _payload_of(umschlag)
    return _verify_body(umschlag, body, public_key, payload_type), body
