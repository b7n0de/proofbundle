"""SCITT Signed Statements over proofbundle receipts, the producer side of ``scitt-ccf/v1`` (EXPERIMENTAL).

Needs the ``[scitt]`` extra (cbor2, to read back what was written) and the RFC 8785 canonicalizer
(the ``[anchors]`` / ``[eval]`` extra, for the receipt root). Nothing here opens a network connection.

WHAT A STATEMENT IS HERE. A COSE_Sign1 (RFC 9052, tag 18) that is an RFC 9995 COSE Hash Envelope:

* payload: the receipt's anchor root, the SHA-256 of the RFC 8785 form of the bundle without its
  ``anchors`` (``anchors.receipt_canonical_root``), the root a ``receipt`` anchor stamps and the
  ``canonical_root`` that ``scitt_ccf.verify_transparent_statement`` binds a statement to;
* protected: alg (1), kid (4), CWT Claims (15, RFC 9597) with ``iss`` (1) and ``sub`` (2) as RFC 9943
  section 6 requires, payload hash algorithm (258) = -16 (SHA-256), preimage content type (259) =
  ``application/json`` (the preimage is the RFC 8785 JSON text), and payload location (260) only when
  the caller supplies one;
* unprotected: empty. A Transparency Service puts its receipts there (label 394) when it registers
  the statement.

No label stands in both buckets, none twice, label 3 (content type) in neither; 258, 259 and 260 only
in the protected header (RFC 9995 section 4); CWT Claims exactly once and protected. The encoding is
deterministic (RFC 8949 section 4.2.1): shortest heads, definite lengths, map keys in the bytewise
order of their encodings. The same key, bundle and arguments give the same bytes.

KEYS (owner decision B, 2026-09-27). EdDSA (-8) over Ed25519, the key of the receipt world, with a
protected ``kid``, is the default. By default the kid is the hexadecimal SHA-256 of the key's
SubjectPublicKeyInfo, ASCII, the self-binding measured on every CCF receipt (``scitt_ccf``). A kid
only names a key; trust comes from the relying party. The ``scitt-ccf/v1`` reader verifies statement
keys selected by a protected ``x5chain`` only (owner answer N7 b), so an EdDSA statement is outside
that reader's profile by design.

ES256 (-7) with a protected ``x5chain`` (label 33, RFC 9360: a byte string for one certificate, an
array for more, the end-entity certificate first) exists only for statements that must pass that
reader, register with scitt-ccf-ledger and cross-verify with microsoft/scitt-verifier. The P-256 key
and the chain come from the user, and the end-entity certificate must carry the signing key. It is
the one ECDSA signature proofbundle makes, and it carries the low ``s``
(``signature.canonical_es256_signature``); no kid is written, the chain names the key.

A statement says that the holder of the key signed this receipt root under this issuer and subject.
It says nothing about whether any recorded number is true, and without a receipt from a Transparency
Service it says nothing about registration.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Optional

from ._cbor_prescan import encode_head
from .errors import BundleFormatError, ProofBundleError

__all__ = ["MEDIA_TYPE", "NOT_REGISTERED", "ScittStatementError", "StatementCheck", "check_signed_statement",
           "sign_statement"]

#: Label 259: the content type of the hash envelope's preimage, the RFC 8785 text of the receipt.
MEDIA_TYPE = "application/json"

#: Registration states of a statement (owner order, part 3): a named state, never an error and never
#: a pass of an anchor.
NOT_REGISTERED = "not_registered"
REGISTRATION_NOT_EVALUATED = "not_evaluated"
CONFIRMED = "confirmed"

_ALG, _CRIT, _CTY, _KID, _CWT, _X5CHAIN = 1, 2, 3, 4, 15, 33
_PAYLOAD_HASH_ALG, _PREIMAGE_CTY, _PAYLOAD_LOCATION, _RECEIPTS = 258, 259, 260, 394
_CWT_ISS, _CWT_SUB = 1, 2
_EDDSA, _ES256, _SHA256 = -8, -7, -16
#: crit labels the check processes, as in the scitt-ccf/v1 reader.
_CRIT_PROCESSED = (_ALG, _PAYLOAD_HASH_ALG)
#: RFC 8410 SubjectPublicKeyInfo of an Ed25519 key: this prefix, then the 32 key bytes.
_ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
#: Why a label may not stand in the unprotected header, per label; any other label: only receipts do.
_UNPROTECTED_WHY = {
    _PAYLOAD_HASH_ALG: "label 258 in the unprotected header: MUST be protected only (RFC 9995 section 4)",
    _PREIMAGE_CTY: "label 259 in the unprotected header: protected only (RFC 9995 section 4)",
    _PAYLOAD_LOCATION: "label 260 in the unprotected header: protected only (RFC 9995 section 4)",
    _CWT: "label 15 (CWT Claims) in the unprotected header: exactly once and protected "
          "(RFC 9597 section 2, RFC 9943 section 6)",
    _CTY: "label 3 (content type) in the unprotected header: in neither bucket of a hash envelope",
    _CRIT: "label 2 (crit) in the unprotected header",
    _KID: "label 4 (kid) in the unprotected header: the key is named in the protected header only",
    _X5CHAIN: "label 33 (x5chain) in the unprotected header: not integrity protected (RFC 9360)",
}


class ScittStatementError(BundleFormatError):
    """The producer refuses to write a statement: an argument it cannot write honestly, a bundle
    without a receipt root, or bytes that did not read back as written."""


def _enc(value: Any) -> bytes:
    """Deterministic CBOR (RFC 8949 section 4.2.1) for the few types a statement holds."""
    if isinstance(value, bool) or value is None:
        raise ScittStatementError(f"no deterministic encoding here for {type(value).__name__}")
    if isinstance(value, int):
        return encode_head(0, value) if value >= 0 else encode_head(1, -1 - value)
    if isinstance(value, (bytes, bytearray)):
        return encode_head(2, len(value)) + bytes(value)
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return encode_head(3, len(raw)) + raw
    if isinstance(value, list):
        return encode_head(4, len(value)) + b"".join(_enc(v) for v in value)
    if isinstance(value, dict):
        items = sorted((_enc(k), _enc(v)) for k, v in value.items())
        if len({k for k, _v in items}) != len(items):
            raise ScittStatementError("two map keys with one encoding")
        return encode_head(5, len(items)) + b"".join(k + v for k, v in items)
    raise ScittStatementError(f"no deterministic encoding here for {type(value).__name__}")


def _text(value: Any, what: str) -> str:
    """A non-empty text string that encodes as UTF-8 (no lone surrogate)."""
    if not isinstance(value, str) or not value:
        raise ScittStatementError(f"{what} must be a non-empty text string")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise ScittStatementError(f"{what} is not valid UTF-8 text") from None
    return value


def _receipt_root(bundle: Any) -> bytes:
    """The payload: the anchor root of a receipt that verifies."""
    if not isinstance(bundle, dict):
        raise ScittStatementError("the receipt must be a bundle (a JSON object)")
    from .anchors import receipt_canonical_root  # noqa: PLC0415
    from .bundle import verify_bundle  # noqa: PLC0415
    try:
        result = verify_bundle(bundle)
    except (ProofBundleError, ValueError, TypeError, RecursionError) as exc:
        raise ScittStatementError(f"the receipt cannot be verified: {type(exc).__name__}") from None
    if not result.ok:
        failed = [c.name for c in result.checks if not c.ok]
        raise ScittStatementError(f"the receipt does not verify (failed: {', '.join(failed)}); "
                                  "a statement over it would sign a root nobody can check")
    try:
        return receipt_canonical_root({k: v for k, v in bundle.items() if k != "anchors"})
    except (ProofBundleError, ValueError, RecursionError) as exc:
        raise ScittStatementError(f"the receipt has no canonical root: {exc}") from None


def _spki(public_key) -> bytes:
    from cryptography.hazmat.primitives import serialization  # noqa: PLC0415
    return public_key.public_bytes(serialization.Encoding.DER,
                                   serialization.PublicFormat.SubjectPublicKeyInfo)


def sign_statement(bundle: dict, signer, *, issuer: str, subject: str, kid: Optional[bytes] = None,
                   location: Optional[str] = None, x5chain: Optional[list] = None) -> bytes:
    """A tagged COSE_Sign1 hash envelope over ``bundle``'s receipt root, signed by ``signer``.

    ``signer`` is an Ed25519 private key (``emit.load_signer``; EdDSA with a protected kid, the
    default) or a P-256 private key together with ``x5chain``, the DER certificates from the end-entity
    one up (ES256 with a protected x5chain). ``issuer`` and ``subject`` become the CWT ``iss`` and
    ``sub``; ``kid`` (EdDSA only) defaults to the hexadecimal SHA-256 of the signer's
    SubjectPublicKeyInfo; ``location`` becomes label 260. The bundle must verify. The bytes are read
    back with the ``scitt-ccf/v1`` reader and the signature checked before they are returned. Raises
    ``ScittStatementError`` for anything it cannot write honestly, ``scitt_ccf.ScittUnavailable``
    without the ``[scitt]`` extra.
    """
    from cryptography.hazmat.primitives.asymmetric import ec  # noqa: PLC0415
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: PLC0415

    from . import scitt_ccf  # noqa: PLC0415
    if isinstance(signer, Ed25519PrivateKey):
        if x5chain is not None:
            raise ScittStatementError("an EdDSA statement names its key by kid; x5chain belongs to the "
                                      "ES256 path (owner decision B)")
        alg = _EDDSA
    elif isinstance(signer, ec.EllipticCurvePrivateKey):
        if signer.curve.name != "secp256r1":
            raise ScittStatementError("ES256 needs a P-256 key")
        if kid is not None:
            raise ScittStatementError("an ES256 statement names its key by the protected x5chain; no kid "
                                      "is written")
        alg = _ES256
    else:
        raise ScittStatementError("the signer must be an Ed25519 private key (EdDSA, COSE alg -8) or a "
                                  "P-256 private key with an x5chain (ES256, COSE alg -7)")
    issuer = _text(issuer, "issuer")
    subject = _text(subject, "subject")
    if location is not None:
        location = _text(location, "location")
    spki = _spki(signer.public_key())
    protected: dict = {_ALG: alg, _CWT: {_CWT_ISS: issuer, _CWT_SUB: subject},
                       _PAYLOAD_HASH_ALG: _SHA256, _PREIMAGE_CTY: MEDIA_TYPE}
    if alg == _EDDSA:
        if kid is None:
            kid = scitt_ccf._derived_kid(spki)
        elif not isinstance(kid, (bytes, bytearray)) or not kid:
            raise ScittStatementError("kid must be a non-empty byte string")
        protected[_KID] = bytes(kid)
    else:
        chain = _x5chain(x5chain, spki)
        protected[_X5CHAIN] = chain[0] if len(chain) == 1 else chain
    if location is not None:
        protected[_PAYLOAD_LOCATION] = location
    payload = _receipt_root(bundle)
    protected_raw = _enc(protected)
    tbs = scitt_ccf._sig_structure(protected_raw, payload)
    signature = signer.sign(tbs) if alg == _EDDSA else _es256(signer, tbs)
    data = (encode_head(6, 18) + encode_head(4, 4) + _enc(protected_raw) + _enc({}) + _enc(payload)
            + _enc(signature))
    _read_back(data, protected, payload, spki)
    return data


def _x5chain(x5chain: Any, spki: bytes) -> list:
    """The user's chain as DER certificates, the end-entity one carrying the signing key."""
    from cryptography import x509  # noqa: PLC0415

    from . import scitt_ccf  # noqa: PLC0415
    if not isinstance(x5chain, (list, tuple)) or not x5chain:
        raise ScittStatementError("an ES256 statement needs an x5chain: the DER certificates from the "
                                  "end-entity one up")
    chain = []
    for i, cert in enumerate(x5chain):
        if not isinstance(cert, (bytes, bytearray)):
            raise ScittStatementError(f"x5chain entry {i} is not DER bytes")
        try:
            x509.load_der_x509_certificate(bytes(cert))
        except ValueError:
            raise ScittStatementError(f"x5chain entry {i} is not a DER X.509 certificate") from None
        chain.append(bytes(cert))
    try:
        leaf = x509.load_der_x509_certificate(chain[0])
        leaf_spki = scitt_ccf._canonical_spki(scitt_ccf._key_from_spki(scitt_ccf._tbs_spki(
            leaf.tbs_certificate_bytes)))
    except scitt_ccf._KeyRefused as exc:
        raise ScittStatementError(f"the end-entity certificate's key cannot be read: {exc}") from None
    if leaf_spki != spki:
        raise ScittStatementError("the end-entity certificate does not carry the signing key")
    return chain


def _es256(signer, tbs: bytes) -> bytes:
    """ES256 as COSE writes it, R || S (RFC 9053 section 2.1), with the low S: the one spelling of
    every signature proofbundle makes (owner decision on finding D1)."""
    from cryptography.hazmat.primitives import hashes  # noqa: PLC0415
    from cryptography.hazmat.primitives.asymmetric import ec, utils  # noqa: PLC0415

    from .signature import canonical_es256_signature  # noqa: PLC0415
    r, s = utils.decode_dss_signature(signer.sign(tbs, ec.ECDSA(hashes.SHA256())))
    return canonical_es256_signature(r.to_bytes(32, "big") + s.to_bytes(32, "big"))


def _read_back(data: bytes, protected: dict, payload: bytes, spki: bytes) -> None:
    """The reader must see what was meant, the header rules must hold, and the producer's own check
    must confirm the statement under the signer's public key."""
    from . import scitt_ccf  # noqa: PLC0415
    st = scitt_ccf.decode_cose_sign1(data, role="statement")
    if not (st.tagged and st.unprotected == {} and st.payload == payload and st.protected == protected):
        raise ScittStatementError("the statement did not read back as written")
    why = _header_rules(st)
    if why:
        raise ScittStatementError(f"the statement breaks its own header rules: {why}")
    key = {"spki": spki, "kid": protected[_KID]} if _KID in protected else spki
    check = check_signed_statement(data, canonical_root=payload, statement_keys=[key])
    if check.status != CONFIRMED:
        raise ScittStatementError(f"the statement does not verify as written: {check.status} {check.detail}")


# ------------------------------------------------------------------------------------------------
# The check: a Signed Statement against a receipt root, under relying-party keys
# ------------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class StatementCheck:
    """The producer's verdict on one Signed Statement: a status, two booleans and the registration.

    ``status`` is ``confirmed`` or one of the ``scitt-ccf/v1`` statement statuses (``no_lib``,
    ``malformed``, ``outside_profile``, ``unbound``, ``statement_signature_invalid``,
    ``needs_rp_trust``). ``registration`` is ``not_registered`` without a receipt under label 394,
    ``not_evaluated`` when one is present but no relying-party service key was supplied or the
    statement itself is not confirmed, else the status of ``scitt_ccf.verify_transparent_statement``.
    """

    status: str
    readable: bool
    signature_valid: Optional[bool]
    registration: str
    registration_detail: str = ""
    alg: Optional[int] = None
    kid: Optional[bytes] = None
    issuer: Optional[str] = None
    subject: Optional[str] = None
    payload_digest: Optional[bytes] = None
    detail: str = ""
    ignored_trust: tuple = field(default=())

    def to_dict(self) -> dict:
        return {k: (v.hex() if isinstance(v, bytes) else list(v) if isinstance(v, tuple) else v)
                for k, v in ((k, getattr(self, k)) for k in self.__dataclass_fields__)}


def check_signed_statement(data: bytes, *, canonical_root: Optional[bytes], statement_keys=None,
                           rp_trust: Optional[dict] = None) -> StatementCheck:
    """Check a Signed Statement (or the statement inside a Transparent Statement) offline.

    The bytes must be read by the ``scitt-ccf/v1`` reader (no duplicate keys, no indefinite lengths,
    no label in both buckets), follow the header rules of this module's docstring, carry
    ``canonical_root`` as payload, and verify over the RFC 9052 section 4.4 ToBeSigned under an
    Ed25519 key the relying party supplies in ``statement_keys``: SubjectPublicKeyInfo DER bytes, or
    ``{"spki": bytes, "kid": bytes}``. The statement's kid only selects among those keys; a bare
    SPKI is named by its default kid. Never raises; every refusal is a status.
    """
    from .scitt_ccf import ScittUnavailable  # noqa: PLC0415
    try:
        return _check(data, canonical_root, statement_keys, rp_trust)
    except ScittUnavailable as exc:
        return StatementCheck(status="no_lib", readable=False, signature_valid=None,
                              registration=REGISTRATION_NOT_EVALUATED, detail=str(exc))
    except Exception as exc:  # noqa: BLE001 - a check must never crash its caller
        return StatementCheck(status="malformed", readable=False, signature_valid=None,
                              registration=REGISTRATION_NOT_EVALUATED,
                              detail=f"refused (fail-closed): {type(exc).__name__}")


def _check(data, canonical_root, statement_keys, rp_trust) -> StatementCheck:
    from . import scitt_ccf  # noqa: PLC0415
    if not isinstance(data, (bytes, bytearray)):
        return StatementCheck(status="malformed", readable=False, signature_valid=None,
                              registration=REGISTRATION_NOT_EVALUATED, detail="the statement is not bytes")
    data = bytes(data)
    try:
        st = scitt_ccf.decode_cose_sign1(data, role="statement")
    except scitt_ccf.ScittFormatError as exc:
        return StatementCheck(status=exc.status, readable=False, signature_valid=None,
                              registration=REGISTRATION_NOT_EVALUATED, detail=str(exc))
    ph = st.protected
    raw_cwt = ph.get(_CWT)
    cwt: dict = raw_cwt if isinstance(raw_cwt, dict) else {}
    alg, kid = ph.get(_ALG), ph.get(_KID)
    seen = {
        "alg": alg if isinstance(alg, int) and not isinstance(alg, bool) else None,
        "kid": kid if isinstance(kid, bytes) else None,
        "issuer": cwt.get(_CWT_ISS) if isinstance(cwt.get(_CWT_ISS), str) else None,
        "subject": cwt.get(_CWT_SUB) if isinstance(cwt.get(_CWT_SUB), str) else None,
        "payload_digest": st.payload if isinstance(st.payload, bytes) and len(st.payload) == 32 else None,
    }
    registered = _RECEIPTS in st.unprotected

    def verdict(status, valid=None, detail="", ignored=()):
        registration, why = (NOT_REGISTERED, "no receipt under label 394") if not registered else \
            (REGISTRATION_NOT_EVALUATED, "the statement itself is not confirmed")
        if registered and status == CONFIRMED:
            registration, why = _registration(data, canonical_root, statement_keys, rp_trust)
        return StatementCheck(status=status, readable=True, signature_valid=valid, registration=registration,
                              registration_detail=why, detail=detail, ignored_trust=tuple(ignored), **seen)

    why = _header_rules(st)
    if why:
        return verdict("outside_profile", detail=why)
    root_ok = isinstance(canonical_root, (bytes, bytearray)) and len(canonical_root) == 32
    if not root_ok:
        return verdict("unbound", detail="canonical_root must be 32 bytes (a SHA-256 root)")
    if st.payload != bytes(canonical_root):
        return verdict("unbound", detail="the statement's payload is not this receipt's root")
    if seen["alg"] == _ES256:
        # the scitt-ccf/v1 statement signature: the protected x5chain selects among the relying party's
        # keys (owner answer N4 b), never trust on its own
        try:
            selector = scitt_ccf._statement_key_selector(st)
        except scitt_ccf.ScittFormatError as exc:
            return verdict(exc.status, detail=str(exc))
        status, valid, ignored, detail = scitt_ccf._statement_signature(st, statement_keys, selector)
        return verdict(status, valid, detail=detail, ignored=ignored)
    keys, ignored = _ed25519_keys(statement_keys)
    if not keys:
        return verdict("needs_rp_trust", detail="no relying-party Ed25519 statement key", ignored=ignored)
    candidates = [pub for pub, key_kid in keys if key_kid == kid]
    if not candidates:
        return verdict("needs_rp_trust", ignored=ignored,
                       detail="no relying-party statement key has the statement's kid")
    tbs = scitt_ccf._sig_structure(st.protected_raw, st.payload)
    # The statement key is a trust anchor supplied from outside the statement: the house rule for
    # trusted Ed25519 keys applies (a low-order key lets a signature made without any secret verify).
    from .signature import verify_ed25519_pinned  # noqa: PLC0415
    for raw in candidates:
        if verify_ed25519_pinned(raw, st.signature, tbs):
            return verdict(CONFIRMED, True, ignored=ignored)
    return verdict("statement_signature_invalid", False, ignored=ignored,
                   detail=f"the signature fails under every key the kid selects ({len(candidates)})")


def _header_rules(st) -> Optional[str]:
    """None if the statement follows the producer's header rules, else the first rule it breaks."""
    ph, uh = st.protected, st.unprotected
    if not st.tagged:
        return "the statement is not tagged 18"
    from ._membership import is_member  # noqa: PLC0415
    for label in uh:
        if label != _RECEIPTS:
            return _UNPROTECTED_WHY[label] if not isinstance(label, bool) and is_member(label, _UNPROTECTED_WHY) \
                else f"label {label!r} in the unprotected header: only receipts (394) stand there"
    alg = ph.get(_ALG)
    if isinstance(alg, bool) or alg not in (_EDDSA, _ES256):
        return f"alg {alg!r}: the producer's statements are EdDSA (-8) or ES256 (-7)"
    if _PAYLOAD_HASH_ALG not in ph:
        return "label 258 absent from the protected header: not an RFC 9995 hash envelope"
    hash_alg = ph[_PAYLOAD_HASH_ALG]
    if isinstance(hash_alg, bool) or hash_alg != _SHA256:
        return f"label 258 is {hash_alg!r}, not -16 (SHA-256)"
    cty = ph.get(_PREIMAGE_CTY, "")
    if isinstance(cty, bool) or not (isinstance(cty, str) or (isinstance(cty, int) and cty >= 0)):
        return "label 259 is not uint / tstr (RFC 9995)"
    if not isinstance(ph.get(_PAYLOAD_LOCATION, ""), str):
        return "label 260 is not tstr (RFC 9995)"
    if _CTY in ph:
        return "label 3 (content type) in the protected header: in neither bucket of a hash envelope"
    if _CWT not in ph:
        return "label 15 (CWT Claims) absent from the protected header (RFC 9943 section 6)"
    claims = ph[_CWT]
    if not isinstance(claims, dict):
        return "label 15 (CWT Claims) is not a map"
    for claim, name in ((_CWT_ISS, "iss"), (_CWT_SUB, "sub")):
        value = claims.get(claim)
        if not isinstance(value, str) or not value:
            return f"label 15 (CWT Claims) has no non-empty text {name} (RFC 9943 section 6)"
    kid = ph.get(_KID)
    if alg == _EDDSA and (not isinstance(kid, bytes) or not kid):
        return "label 4 (kid) is not a non-empty byte string in the protected header"
    if alg == _ES256 and _X5CHAIN not in ph:
        return "no protected x5chain (label 33): an ES256 statement names its key by it (owner answer N7 b)"
    from .scitt_ccf import _crit_ok  # noqa: PLC0415
    why = _crit_ok(ph, _CRIT_PROCESSED)
    if why:
        return why
    if st.payload is None:
        return "the payload is detached"
    if len(st.payload) != 32:
        return f"a SHA-256 hash envelope payload is 32 bytes, not {len(st.payload)}"
    return None


def _ed25519_keys(entries) -> tuple:
    """Relying-party entries -> ([(raw public key, kid)], [why an entry was ignored]). A key of
    another type, or bytes that are not an Ed25519 SubjectPublicKeyInfo, are absent trust."""
    from .signature import ed25519_trust_anchor_weakness  # noqa: PLC0415
    usable: list = []
    ignored: list = []
    if not isinstance(entries, (list, tuple)):
        return usable, ([] if entries is None else ["statement keys are not a list"])
    for i, entry in enumerate(entries[:64]):
        if isinstance(entry, (bytes, bytearray)):
            spki, kid = bytes(entry), None
        elif isinstance(entry, dict) and isinstance(entry.get("spki"), (bytes, bytearray)):
            spki, kid = bytes(entry["spki"]), entry.get("kid")
            if kid is not None and not isinstance(kid, (bytes, bytearray)):
                ignored.append(f"key {i}: kid is not bytes")
                continue
        else:
            ignored.append(f"key {i}: neither SubjectPublicKeyInfo DER bytes nor {{'spki', 'kid'}}")
            continue
        if len(spki) != len(_ED25519_SPKI_PREFIX) + 32 or not spki.startswith(_ED25519_SPKI_PREFIX):
            ignored.append(f"key {i}: not an Ed25519 SubjectPublicKeyInfo")
            continue
        weakness = ed25519_trust_anchor_weakness(spki[len(_ED25519_SPKI_PREFIX):])
        if weakness is not None:
            ignored.append(f"key {i}: {weakness} Ed25519 key, refused as a trust anchor")
            continue
        usable.append((spki[len(_ED25519_SPKI_PREFIX):],
                       bytes(kid) if kid is not None else hashlib.sha256(spki).hexdigest().encode("ascii")))
    if len(entries) > 64:
        ignored.append("keys beyond 64 ignored")
    return usable, ignored


def _registration(data: bytes, canonical_root, statement_keys, rp_trust) -> tuple:
    """(state, detail) of the receipts under label 394, through the scitt-ccf/v1 reader."""
    services = rp_trust.get("scitt_ccf_services") if isinstance(rp_trust, dict) else None
    if not services:
        return (REGISTRATION_NOT_EVALUATED, "a receipt is present under label 394; no relying-party "
                                            "service key was supplied, so it is not evaluated")
    from .scitt_ccf import verify_transparent_statement  # noqa: PLC0415
    trust = dict(rp_trust)
    trust.setdefault("scitt_statement_keys", statement_keys)
    ts = verify_transparent_statement(data, canonical_root=canonical_root, rp_trust=trust)
    return (ts.status, ts.detail or ts.status)
