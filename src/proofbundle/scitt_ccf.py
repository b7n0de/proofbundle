"""SCITT Transparent Statements with CCF receipts, the ``scitt-ccf/v1`` profile of ADR 0009 (EXPERIMENTAL).

Needs the ``[scitt]`` extra (cbor2, pinned to the measured version). Without it every entry point
refuses with status ``no_lib``; nothing here falls back to a weaker reader.

NOT AN ANCHOR TYPE YET. This module reads, recomputes and verifies. It is not registered with
``anchors.register_anchor_type`` and no verify path reaches it; that integration is a later work
package. It changes no verdict of any bundle.

FOUR VALUES, KEPT APART (ADR 0009, Decision 2):

1. hash envelope payload -- the statement's payload, an RFC 9995 digest of the anchored target;
   here it must be SHA-256 (label 258 = -16) and equal the ``canonical_root`` the caller supplies
2. local ToBeSigned ID -- not part of this API (owner decision Q4 c); the Sig_structure is built
   internally to check a signature and is never exposed as an identifier
3. CCF data-hash -- recomputed from the statement bytes by the rule measured in
   ``tools/scitt_ccf_external``: SHA-256 over ``d2 84 || protected || a0 || payload || signature``,
   the unprotected header cleared, every element as served
4. CCF Merkle root -- computed from each inclusion proof, draft-ietf-scitt-receipts-ccf-profile-05;
   the detached payload over which the receipt signature is checked

TRUST comes only from ``rp_trust`` (ADR 0009, Decision 5):

* ``rp_trust["scitt_ccf_services"]``: ``{issuer: [key, ...]}``, the issuer compared as an exact
  string with the CWT ``iss`` in the receipt's protected header
* ``rp_trust["scitt_statement_keys"]``: ``[key, ...]`` for the statement signer, always required
  (owner decision Q3 b)

A key is SubjectPublicKeyInfo DER bytes, or ``{"spki": bytes, "kid": bytes}``; ``load_cose_keyset``
turns a COSE_KeySet as served by ``/.well-known/scitt-keys`` into that form. A kid only selects
among the keys the relying party already trusts for that issuer; a kid, a key embedded in the
evidence, an ``x5chain`` certificate or an algorithm label in a key set is never trust.

The statement's PROTECTED ``x5chain`` selects among the relying party's statement keys the same
way (owner answer N4 b): only a key equal to the end-entity certificate's key is tried, no such
key is ``needs_rp_trust``, and a selected key must verify. The certificate is never trust. An
``x5chain`` in the unprotected bucket selects nothing, and a statement without a protected one is
outside the profile (owner answer N7 b).

RESULTS are three separate booleans -- ``readable``, ``signature_valid``, ``profile_satisfied`` --
next to one status from a closed set (ADR 0009, Decisions 9 and 10). No result sets ``warn`` and
none carries a trusted time; the receipt's signed ``iat`` is reported as ``receipt_iat``,
informative only (owner decision Q2 a).
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Optional

from ._cbor_prescan import CborRefused, Tag, encode_head, scan
from ._membership import is_member
from .errors import BundleFormatError, UnsupportedError

PROFILE = "scitt-ccf/v1"

# COSE and SCITT labels (RFC 9052, RFC 9942, RFC 9943, RFC 9995)
_ALG, _CRIT, _CTY, _KID, _CWT, _X5CHAIN = 1, 2, 3, 4, 15, 33
_PAYLOAD_HASH_ALG, _PREIMAGE_CTY, _PAYLOAD_LOCATION = 258, 259, 260
_RECEIPTS, _VDS, _VDP, _INCLUSION, _CONSISTENCY = 394, 395, 396, -1, -2
_CCF_LEDGER_SHA256 = 2         # requested assignment in -05 (TBD_1), not yet made by IANA
_SHA256 = -16

#: Limits of the profile (ADR 0009, Decision 8), counted in bytes of encoded input.
MAX_STATEMENT_BYTES = 65536
MAX_DEPTH = 16
MAX_RECEIPTS = 8
MAX_INCLUSION_PROOFS = 8
MAX_PATH = 64
MAX_EVIDENCE_BYTES = 1024
MAX_TRUSTED_KEYS = 64

#: The own statuses of a CCF consistency receipt (draft-ietf-scitt-receipts-ccf-profile-05, section
#: 4), in the order that decides the result. A set of its own: a consistency receipt relates two roots
#: of one ledger and says nothing about any statement, so none of these is a statement's status.
CONSISTENCY_STATUS_ORDER = (
    "no_lib", "malformed", "outside_profile",
    "consistency_proof_missing",         # 4.1: vdp MUST carry -2 with one or more proofs
    "consistency_payload_attached",      # 4.1: the payload (the newer root) MUST be detached
    "consistency_newer_roots_differ",    # 4.1: every proof MUST compute to the same newer root
    "consistency_anchor_not_canonical",  # 4: the anchor MUST be the largest complete subtree
    "consistency_older_root_mismatch",   # 4.2: no proof recomputes the older root the caller holds
    "consistency_issuer_mismatch",       # PROOFBUNDLE'S OWN RULE, not a requirement of -05: the older
                                         # root came from another service's receipt (SECTION4_WGLC.md, G3)
    "signature_invalid", "needs_rp_trust")
MAX_CONSISTENCY_PROOFS = 8

#: The closed set of statuses, in the order that decides an entry without a confirmed receipt.
STATUS_ORDER = ("no_lib", "malformed", "outside_profile", "unbound", "statement_signature_invalid",
                "root_mismatch", "signature_invalid", "receipt_not_bound", "needs_rp_trust")
CONFIRMED = "confirmed"

#: COSE algorithm -> (key kind, curve name or hash name, coordinate or salt length)
_ALGS = {
    -7: ("ec", "secp256r1", "SHA256", 32),
    -35: ("ec", "secp384r1", "SHA384", 48),
    -37: ("rsa-pss", None, "SHA256", 32),
    -38: ("rsa-pss", None, "SHA384", 48),
}
_RECEIPT_ALGS = (-7, -35)
_STATEMENT_ALGS = (-7, -35, -37, -38)
_RSA_BITS = (2048, 8192)

#: crit labels v1 processes (ADR 0009, Decision 7); anything else listed in crit is outside v1.
_STATEMENT_CRIT_PROCESSED = (_ALG, _PAYLOAD_HASH_ALG)
_RECEIPT_CRIT_PROCESSED = (_ALG, _KID, _CWT, _VDS)
#: Why a statement without a protected x5chain is outside the profile (owner answer N7 b).
_NO_X5CHAIN = "no protected x5chain: scitt-ccf/v1 selects the statement key by it (owner answer N7 b)"
_UNPROTECTED_X5CHAIN = "; the x5chain in the unprotected header is not integrity protected and selects nothing"
#: CWT claims that may carry tag 1 in a statement's protected header (owner decision Q8 a).
_CWT_TIME_CLAIMS = (4, 5, 6)


class ScittFormatError(BundleFormatError):
    """The bytes are not read under ``scitt-ccf/v1``. ``status`` is ``malformed`` or ``outside_profile``."""

    def __init__(self, status: str, detail: str):
        self.status = status
        super().__init__(f"{status}: {detail}")


class ScittUnavailable(UnsupportedError):
    """The ``[scitt]`` extra is not installed, or its cbor2 lacks an option the profile needs."""

    status = "no_lib"


# ------------------------------------------------------------------------------------------------
# The reader: our pre-scan decides, cbor2 must read the same values
# ------------------------------------------------------------------------------------------------
def _cbor2():
    try:
        import cbor2  # noqa: PLC0415 - optional extra
    except ImportError as exc:
        raise ScittUnavailable("scitt-ccf needs the [scitt] extra: pip install 'proofbundle[scitt]'") from exc
    try:
        cbor2.loads(b"\xa0", allow_duplicate_keys=False, allow_indefinite=False)
    except TypeError as exc:
        raise ScittUnavailable("the installed cbor2 cannot reject duplicate keys and indefinite "
                               "lengths; the [scitt] extra pins the measured version") from exc
    return cbor2


def _same(ours: Any, theirs: Any, cbor2) -> bool:
    """Do the pre-scan and cbor2 read the same value? Container types differ by cbor2 version
    (list or tuple, dict or frozendict), so the comparison is by content, never by type name."""
    if isinstance(ours, bool) or ours is None:
        return theirs is ours
    if isinstance(ours, int):
        return isinstance(theirs, int) and not isinstance(theirs, bool) and theirs == ours
    if isinstance(ours, (bytes, str)):
        return type(theirs) is type(ours) and theirs == ours
    if isinstance(ours, list):
        return (isinstance(theirs, (list, tuple)) and len(theirs) == len(ours)
                and all(_same(a, b, cbor2) for a, b in zip(ours, theirs)))
    if isinstance(ours, dict):
        try:
            keys = list(theirs.keys())
        except AttributeError:
            return False
        if len(keys) != len(ours) or any(k not in ours for k in keys if isinstance(k, (int, str))):
            return False
        return all(isinstance(k, (int, str)) and not isinstance(k, bool) and _same(ours[k], theirs[k], cbor2)
                   for k in keys)
    if isinstance(ours, Tag):
        if ours.number == 1:
            # cbor2 turns tag 1 into a datetime (measured, 5.9.0 and 6.1.4); that is the one mapped position
            import datetime  # noqa: PLC0415
            if isinstance(ours.value, bool) or not isinstance(ours.value, int):
                return False
            return (isinstance(theirs, datetime.datetime) and theirs.tzinfo is not None
                    and theirs == datetime.datetime.fromtimestamp(ours.value, datetime.timezone.utc))
        return (isinstance(theirs, cbor2.CBORTag) and theirs.tag == ours.number
                and _same(ours.value, theirs.value, cbor2))
    return False


def _read(data: bytes, *, tag_allowed, max_bytes: int = MAX_STATEMENT_BYTES):
    """Pre-scan, then cbor2 with its strict options; both must read the same value."""
    cbor2 = _cbor2()
    try:
        sc = scan(data, max_bytes=max_bytes, max_depth=MAX_DEPTH, tag_allowed=tag_allowed)
    except CborRefused as exc:
        raise ScittFormatError("malformed", str(exc)) from exc
    try:
        theirs = cbor2.loads(bytes(data), allow_duplicate_keys=False, allow_indefinite=False,
                             max_depth=MAX_DEPTH + 2)
    except Exception as exc:  # noqa: BLE001 - any cbor2 refusal of bytes the pre-scan accepted is a disagreement
        raise ScittFormatError("malformed", f"cbor2 refused what the pre-scan accepted: "
                                            f"{type(exc).__name__}") from exc
    if not _same(sc.value, theirs, cbor2):
        raise ScittFormatError("malformed", "the pre-scan and cbor2 read different values")
    return sc


def _root_18(path: tuple, number: int) -> bool:
    return path == () and number == 18


def _statement_protected_tags(path: tuple, number: int) -> bool:
    return number == 1 and len(path) == 2 and path[0] == _CWT and path[1] in _CWT_TIME_CLAIMS


def _no_tags(path: tuple, number: int) -> bool:
    return False


@dataclass(frozen=True)
class CoseSign1:
    """A COSE_Sign1 as served: the bytes, their four element spans, and the decoded headers."""

    raw: bytes
    tagged: bool
    spans: tuple
    protected_raw: bytes
    protected: dict
    unprotected: dict
    payload: Optional[bytes]
    signature: bytes

    def element(self, index: int) -> bytes:
        a, b = self.spans[index]
        return self.raw[a:b]


def decode_cose_sign1(data: bytes, *, role: str = "statement") -> CoseSign1:
    """Read a COSE_Sign1 (RFC 9052 section 4.2) under the profile's reader rules.

    ``role`` is ``statement`` or ``receipt``; it decides where tag 1 may stand (only around a CWT
    time claim of a statement's protected header). Raises ``ScittFormatError`` or
    ``ScittUnavailable``; the protected header is kept as the exact bytes served.
    """
    if role != "statement" and role != "receipt":
        raise ScittFormatError("malformed", "role must be 'statement' or 'receipt'")
    sc = _read(data, tag_allowed=_root_18)
    body = sc.value.value if isinstance(sc.value, Tag) else sc.value
    if not isinstance(body, list) or len(body) != 4 or len(sc.element_spans) != 4:
        raise ScittFormatError("malformed", "a COSE_Sign1 is an array of exactly four elements")
    prot_raw, unprot, payload, sig = body
    if not isinstance(prot_raw, bytes):
        raise ScittFormatError("malformed", "the protected header is not a byte string")
    if not isinstance(unprot, dict):
        raise ScittFormatError("malformed", "the unprotected header is not a map")
    if payload is not None and not isinstance(payload, bytes):
        raise ScittFormatError("malformed", "the payload is neither a byte string nor nil")
    if not isinstance(sig, bytes):
        raise ScittFormatError("malformed", "the signature is not a byte string")
    if prot_raw == b"":
        raise ScittFormatError("malformed", "the protected header is empty; alg must be protected")
    policy = _statement_protected_tags if role == "statement" else _no_tags
    prot = _read(prot_raw, tag_allowed=policy).value
    if not isinstance(prot, dict):
        raise ScittFormatError("malformed", "the protected header does not decode to a map")
    both = [k for k in prot if k in unprot]
    if both:
        raise ScittFormatError("malformed", f"label(s) {both!r} in both header buckets")
    return CoseSign1(raw=bytes(data), tagged=sc.tagged_with == 18, spans=sc.element_spans,
                     protected_raw=prot_raw, protected=prot, unprotected=unprot,
                     payload=payload, signature=sig)


def _sig_structure(protected_raw: bytes, payload: bytes) -> bytes:
    """RFC 9052 section 4.4 ToBeSigned for COSE_Sign1, external_aad empty by profile."""
    parts = [encode_head(3, 10) + b"Signature1",
             encode_head(2, len(protected_raw)) + protected_raw,
             encode_head(2, 0),
             encode_head(2, len(payload)) + payload]
    return encode_head(4, 4) + b"".join(parts)


def _data_hash(st: CoseSign1) -> bytes:
    """Value 3: SHA-256 over tag 18, the four-element head, the protected header, an empty map,
    payload and signature, each as served (measured rule, ADR 0009 Decision 3)."""
    return hashlib.sha256(b"\xd2\x84" + st.element(0) + b"\xa0" + st.element(2)
                          + st.element(3)).digest()


def recompute_data_hash(data: bytes) -> bytes:
    """Value 3 of a Transparent Statement, recomputed from its bytes. Raises ``ScittFormatError``
    for bytes outside the profile's reader, including an untagged statement, whose data-hash rule
    is not measured."""
    st = decode_cose_sign1(data, role="statement")
    if not st.tagged:
        raise ScittFormatError("outside_profile", "untagged COSE_Sign1; the data-hash rule is "
                                                  "measured for tag 18 only")
    return _data_hash(st)


# ------------------------------------------------------------------------------------------------
# Keys and signatures (cryptography), algorithm bound to key type and curve
# ------------------------------------------------------------------------------------------------
def _crit_ok(headers: dict, processed: tuple) -> Optional[str]:
    crit = headers.get(_CRIT)
    if crit is None:
        return None
    if not isinstance(crit, list) or not crit:
        return "crit is not a non-empty array"
    for label in crit:
        if isinstance(label, bool) or not isinstance(label, (int, str)):
            return "crit lists something that is not a label"
        if label not in headers:
            return f"crit lists {label!r}, which is not in the protected header"
        if label not in processed:
            return f"crit lists {label!r}, which scitt-ccf/v1 does not process"
    return None


def _load_spki(spki: bytes):
    from cryptography.hazmat.primitives.serialization import load_der_public_key  # noqa: PLC0415
    return load_der_public_key(spki)


def _normalize_keys(entries) -> tuple[list, list]:
    """RP key entries -> [(spki, kid)] and the reasons entries were ignored. Malformed RP material
    can only ever be absent trust, never trust."""
    usable: list = []
    ignored: list = []
    if not isinstance(entries, (list, tuple)):
        return usable, ([] if entries is None else ["trusted keys are not a list"])
    for i, e in enumerate(entries[:MAX_TRUSTED_KEYS]):
        if isinstance(e, (bytes, bytearray)):
            spki, kid = bytes(e), None
        elif isinstance(e, dict) and isinstance(e.get("spki"), (bytes, bytearray)):
            spki = bytes(e["spki"])
            kid = e.get("kid")
            if kid is not None and not isinstance(kid, (bytes, bytearray)):
                ignored.append(f"key {i}: kid is not bytes")
                continue
            kid = None if kid is None else bytes(kid)
        else:
            ignored.append(f"key {i}: neither SPKI DER bytes nor {{'spki', 'kid'}}")
            continue
        try:
            _load_spki(spki)
        except Exception as exc:  # noqa: BLE001 - an unreadable RP key is absent trust
            ignored.append(f"key {i}: not a readable SubjectPublicKeyInfo ({type(exc).__name__})")
            continue
        usable.append((spki, kid))
    if len(entries) > MAX_TRUSTED_KEYS:
        ignored.append(f"keys beyond {MAX_TRUSTED_KEYS} ignored")
    return usable, ignored


def _derived_kid(spki: bytes) -> bytes:
    """The self-binding measured on every -05 receipt: hex(SHA-256(SubjectPublicKeyInfo)), ASCII."""
    return hashlib.sha256(spki).hexdigest().encode("ascii")


def _verify(alg: Any, spki: bytes, tbs: bytes, signature: bytes) -> bool:
    """True only if ``alg`` belongs to the key's type and curve AND the signature verifies."""
    from cryptography.exceptions import InvalidSignature  # noqa: PLC0415
    from cryptography.hazmat.primitives import hashes  # noqa: PLC0415
    from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa, utils  # noqa: PLC0415
    if isinstance(alg, bool) or not isinstance(alg, int) or not is_member(alg, _ALGS):
        return False
    kind, curve, hname, n = _ALGS[alg]
    key = _load_spki(spki)
    h = getattr(hashes, hname)()
    try:
        if kind == "ec":
            if not isinstance(key, ec.EllipticCurvePublicKey) or key.curve.name != curve:
                return False
            if len(signature) != 2 * n:
                return False
            der = utils.encode_dss_signature(int.from_bytes(signature[:n], "big"),
                                             int.from_bytes(signature[n:], "big"))
            key.verify(der, tbs, ec.ECDSA(h))
            return True
        if kind == "rsa-pss":
            if not isinstance(key, rsa.RSAPublicKey):
                return False
            if not _RSA_BITS[0] <= key.key_size <= _RSA_BITS[1]:
                return False
            key.verify(signature, tbs, padding.PSS(mgf=padding.MGF1(h), salt_length=n), h)
            return True
    except InvalidSignature:
        return False
    return False


def load_cose_keyset(data: bytes) -> list:
    """A COSE_KeySet (as served by ``/.well-known/scitt-keys``) -> ``[{"spki": bytes, "kid": bytes}]``.

    EC2 keys on P-256 and P-384 only; any other key in the set is skipped. Raises
    ``ScittFormatError`` for bytes that are not a key set, ``ScittUnavailable`` without the extra.
    """
    from cryptography.hazmat.primitives import serialization  # noqa: PLC0415
    from cryptography.hazmat.primitives.asymmetric import ec  # noqa: PLC0415
    keys = _read(data, tag_allowed=_no_tags).value
    if not isinstance(keys, list):
        raise ScittFormatError("malformed", "a COSE_KeySet is an array")
    curves = {1: (ec.SECP256R1, 32), 2: (ec.SECP384R1, 48)}
    out = []
    for k in keys[:MAX_TRUSTED_KEYS]:
        if not isinstance(k, dict) or k.get(1) != 2:
            continue
        crv = k.get(-1)
        if isinstance(crv, bool) or not isinstance(crv, int) or crv not in curves:
            continue
        cls, n = curves[crv]
        x, y, kid = k.get(-2), k.get(-3), k.get(2)
        if not (isinstance(x, bytes) and isinstance(y, bytes) and len(x) == n and len(y) == n):
            continue
        try:
            pub = ec.EllipticCurvePublicNumbers(int.from_bytes(x, "big"), int.from_bytes(y, "big"),
                                                cls()).public_key()
        except ValueError:
            continue
        spki = pub.public_bytes(serialization.Encoding.DER,
                                serialization.PublicFormat.SubjectPublicKeyInfo)
        out.append({"spki": spki, "kid": kid if isinstance(kid, bytes) else None})
    return out


# ------------------------------------------------------------------------------------------------
# Results
# ------------------------------------------------------------------------------------------------
@dataclass(frozen=True)
class ReceiptCheck:
    """One receipt, read and checked on its own."""

    index: int
    status: str
    readable: bool = False
    signature_valid: Optional[bool] = None
    bound: Optional[bool] = None
    issuer: Optional[str] = None
    kid: Optional[bytes] = None
    kid_bound_to_key: Optional[bool] = None
    merkle_root: Optional[bytes] = None
    data_hashes: tuple = ()
    receipt_iat: Optional[int] = None
    ccf_txid: Optional[str] = None
    consistency_proofs_present: bool = False
    detail: str = ""


@dataclass(frozen=True)
class TransparentStatementCheck:
    """The verdict on one Transparent Statement: three separate results and one status."""

    status: str
    readable: bool
    signature_valid: bool
    profile_satisfied: bool
    statement_status: str
    statement_signature_valid: Optional[bool] = None
    payload_digest: Optional[bytes] = None
    data_hash: Optional[bytes] = None
    receipts: tuple = ()
    detail: str = ""
    profile: str = PROFILE
    ignored_trust: tuple = field(default=())

    def to_dict(self) -> dict:
        def conv(v):
            if isinstance(v, bytes):
                return v.hex()
            if isinstance(v, tuple):
                return [conv(x) for x in v]
            if isinstance(v, ReceiptCheck):
                return {k: conv(getattr(v, k)) for k in v.__dataclass_fields__}
            return v
        return {k: conv(getattr(self, k)) for k in self.__dataclass_fields__}


@dataclass(frozen=True)
class ConsistencyCheck:
    """One CCF consistency receipt against an older root the caller already holds (-05, section 4).

    It relates two roots of one ledger and establishes nothing about ledger contents on its own."""

    status: str
    readable: bool = False
    signature_valid: Optional[bool] = None
    older_root_matches: Optional[bool] = None
    newer_root: Optional[bytes] = None
    proofs: int = 0
    issuer: Optional[str] = None
    kid: Optional[bytes] = None
    kid_bound_to_key: Optional[bool] = None
    receipt_iat: Optional[int] = None
    ccf_txid: Optional[str] = None
    inclusion_proofs_present: bool = False
    detail: str = ""
    profile: str = PROFILE

    def to_dict(self) -> dict:
        return {k: (v.hex() if isinstance(v, bytes) else v)
                for k, v in ((k, getattr(self, k)) for k in self.__dataclass_fields__)}


def _first(statuses) -> str:
    present = [s for s in statuses if s != CONFIRMED]
    for s in STATUS_ORDER:
        if s in present:
            return s
    return CONFIRMED


# ------------------------------------------------------------------------------------------------
# Statement side
# ------------------------------------------------------------------------------------------------
def _statement_profile(st: CoseSign1) -> Optional[str]:
    """None if the statement is a v1 hash envelope, else why it is outside the profile."""
    ph, uh = st.protected, st.unprotected
    if not st.tagged:
        return "the statement is not tagged 18"
    alg = ph.get(_ALG)
    if isinstance(alg, bool) or not isinstance(alg, int) or alg not in _STATEMENT_ALGS:
        return f"statement algorithm {alg!r} is not in scitt-ccf/v1"
    if _PAYLOAD_HASH_ALG not in ph:
        return "not an RFC 9995 hash envelope: label 258 absent from the protected header"
    if ph.get(_PAYLOAD_HASH_ALG) != _SHA256 or isinstance(ph.get(_PAYLOAD_HASH_ALG), bool):
        return "label 258 is not -16 (SHA-256)"
    for label in (_PREIMAGE_CTY, _PAYLOAD_LOCATION):
        if label in uh:
            return f"label {label} in the unprotected header"
    if _CTY in ph or _CTY in uh:
        return "label 3 (content type) present in a hash envelope"
    why = _crit_ok(ph, _STATEMENT_CRIT_PROCESSED)
    if why:
        return why
    if _CRIT in uh:
        return "crit in the unprotected header"
    if _X5CHAIN not in ph:
        return _NO_X5CHAIN + (_UNPROTECTED_X5CHAIN if _X5CHAIN in uh else "")
    if st.payload is None:
        return "the payload is detached; the data-hash rule is measured for embedded payloads only"
    if len(st.payload) != 32:
        return f"a SHA-256 hash envelope payload is 32 bytes, not {len(st.payload)}"
    return None


def verify_statement_signature(data: bytes, *, statement_keys=None) -> tuple:
    """ToBeSigned of a statement and its signature under relying-party statement keys.

    Returns ``(status, valid)``: ``("confirmed", True)``, ``("statement_signature_invalid", False)``,
    ``("needs_rp_trust", None)`` without usable keys, or a reader status with ``None``. The
    algorithm is the protected header's; a key of another type or curve counts as a failed check.
    """
    try:
        st = decode_cose_sign1(data, role="statement")
        selector = _statement_key_selector(st)
        return _statement_signature(st, statement_keys, selector)[:2]
    except ScittUnavailable:
        return ("no_lib", None)
    except ScittFormatError as exc:
        return (exc.status, None)
    except BundleFormatError:
        return ("malformed", None)
    except Exception:  # noqa: BLE001 - a verifier must never crash its caller
        return ("malformed", None)


def _statement_key_selector(st: CoseSign1) -> tuple:
    """Owner answer N4 b: which relying-party statement keys are tried. A selector, never trust.

    Returns ``(mode, spki, note)``. ``mode`` is ``"x5chain"`` when the protected header carries
    label 33: then only a key equal to the end-entity certificate's key is tried (``spki``, None
    when that key cannot be loaded, so none can match). Without a protected ``x5chain`` ``mode`` is
    ``"none"``: v1 requires one (owner answer N7 b) and no key is tried. RFC 9360 (WG source,
    draft-ietf-cose-x509-08): ``COSE_X509 = bstr / [ 2*certs: bstr ]``, the first certificate is
    the end-entity one, and it MUST be integrity protected, so an unprotected ``x5chain`` selects
    nothing. Raises ``ScittFormatError`` for a protected ``x5chain`` of another shape or whose
    end-entity certificate is not DER X.509.
    """
    if _X5CHAIN not in st.protected:
        return ("none", None, _NO_X5CHAIN + (_UNPROTECTED_X5CHAIN if _X5CHAIN in st.unprotected else ""))
    chain = st.protected[_X5CHAIN]
    if isinstance(chain, bytes):
        leaf = chain
    elif isinstance(chain, list):
        if len(chain) < 2 or not all(isinstance(c, bytes) for c in chain):
            raise ScittFormatError("malformed", "x5chain is an array, but not of two or more "
                                                "certificates as byte strings (RFC 9360)")
        leaf = chain[0]
    else:
        raise ScittFormatError("malformed", "x5chain is neither a byte string nor an array (RFC 9360)")
    from cryptography import x509  # noqa: PLC0415
    try:
        cert = x509.load_der_x509_certificate(leaf)
    except Exception as exc:  # noqa: BLE001 - unreadable evidence is malformed, never a crash
        raise ScittFormatError("malformed", "the x5chain end-entity certificate is not DER X.509 "
                                            f"({type(exc).__name__})") from None
    try:
        key = cert.public_key()
    except Exception as exc:  # noqa: BLE001 - e.g. UnsupportedAlgorithm, not a ValueError
        return ("x5chain", None, "the x5chain end-entity key cannot be loaded "
                                 f"({type(exc).__name__}), so no relying-party key can match")
    return ("x5chain", _canonical_spki(key), "statement key selected by the protected x5chain")


def _canonical_spki(key) -> bytes:
    from cryptography.hazmat.primitives import serialization  # noqa: PLC0415
    return key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def _statement_signature(st: CoseSign1, statement_keys, selector: tuple) -> tuple:
    """-> (status, valid, ignored trust, detail)."""
    if st.payload is None:
        return ("outside_profile", None, [], "the payload is detached")
    mode, leaf_spki, note = selector
    if mode == "none":
        return ("outside_profile", None, [], note)
    keys, ignored = _normalize_keys(statement_keys)
    if not keys:
        return ("needs_rp_trust", None, ignored,
                "no relying-party statement key (the statement signer is always required)")
    if mode == "x5chain":
        # compared as keys, not as encodings: both sides re-encoded from the loaded key
        candidates = [spki for spki, _kid in keys
                      if leaf_spki is not None and _canonical_spki(_load_spki(spki)) == leaf_spki]
        if not candidates:
            return ("needs_rp_trust", None, ignored,
                    f"{note}; no relying-party statement key is the x5chain end-entity key")
    else:
        raise ValueError(f"unknown selector mode {mode!r}")    # fail closed: no mode tries every key
    tbs = _sig_structure(st.protected_raw, st.payload)
    alg = st.protected.get(_ALG)
    for spki in candidates:
        if _verify(alg, spki, tbs, st.signature):
            return (CONFIRMED, True, ignored, "")
    return ("statement_signature_invalid", False, ignored,
            f"{note}; the statement signature fails under every key tried ({len(candidates)})")


# ------------------------------------------------------------------------------------------------
# Receipt side
# ------------------------------------------------------------------------------------------------
class _ProofRefused(Exception):
    """A proof that violates the -05 CDDL; always ``malformed``."""


def _receipt_head(rc: CoseSign1) -> tuple:
    """(kid, issuer, iat, txid, vdp) of a receipt, each None (vdp: {}) where absent or mistyped."""
    ph, uh = rc.protected, rc.unprotected
    raw_kid, raw_cwt, raw_ccf, raw_vdp = ph.get(_KID), ph.get(_CWT), ph.get("ccf.v1"), uh.get(_VDP)
    cwt: dict = raw_cwt if isinstance(raw_cwt, dict) else {}
    ccf: dict = raw_ccf if isinstance(raw_ccf, dict) else {}
    raw_iss, raw_iat, raw_txid = cwt.get(1), cwt.get(6), ccf.get("txid")
    return (raw_kid if isinstance(raw_kid, bytes) else None,
            raw_iss if isinstance(raw_iss, str) else None,
            raw_iat if isinstance(raw_iat, int) and not isinstance(raw_iat, bool) else None,
            raw_txid if isinstance(raw_txid, str) else None,
            raw_vdp if isinstance(raw_vdp, dict) else {})


def _receipt_outside(rc: CoseSign1, kid: Optional[bytes], iss: Optional[str]) -> Optional[str]:
    """The protected-header rules every -05 receipt shares, inclusion or consistency (3.1, 4.1)."""
    ph = rc.protected
    alg = ph.get(_ALG)
    if not rc.tagged:
        return "the receipt is not tagged 18"
    if isinstance(alg, bool) or not isinstance(alg, int) or alg not in _RECEIPT_ALGS:
        return f"receipt algorithm {alg!r} is not in scitt-ccf/v1"
    if ph.get(_VDS) != _CCF_LEDGER_SHA256 or isinstance(ph.get(_VDS), bool):
        return f"vds is {ph.get(_VDS)!r}, not {_CCF_LEDGER_SHA256} (CCF_LEDGER_SHA256)"
    if kid is None:
        return "the receipt has no kid"
    if iss is None:
        return "the receipt has no CWT issuer in its protected header"
    return None


def _is_ccf(rc: CoseSign1) -> bool:
    """vds says CCF_LEDGER_SHA256, so the -05 CDDL applies to the proofs of this receipt."""
    vds = rc.protected.get(_VDS)
    return vds == _CCF_LEDGER_SHA256 and not isinstance(vds, bool)


def _receipt_crit(rc: CoseSign1) -> Optional[str]:
    if _CRIT in rc.unprotected:
        return "crit in the unprotected header"
    return _crit_ok(rc.protected, _RECEIPT_CRIT_PROCESSED)


def _proof_map(p: Any, what: str, keys: str) -> tuple:
    article = "an" if what[0] in "aeiou" else "a"
    if not isinstance(p, bytes):
        raise _ProofRefused(f"{article} {what} is not a byte string")
    try:
        d = _read(p, tag_allowed=_no_tags).value
    except ScittFormatError as exc:
        raise _ProofRefused(f"{what}: {exc}") from None
    if not isinstance(d, dict) or len(d) != 2 or 1 not in d or 2 not in d:
        raise _ProofRefused(f"{article} {what} is exactly {keys}")
    path = d[2]
    if not (isinstance(path, list) and 1 <= len(path) <= MAX_PATH):
        raise _ProofRefused(f"a path has 1 to {MAX_PATH} elements")
    for e in path:
        if not (isinstance(e, list) and len(e) == 2 and isinstance(e[0], bool)
                and isinstance(e[1], bytes) and len(e[1]) == 32):
            raise _ProofRefused("a path element is [bool, bstr .size 32]")
    return d[1], path


def _inclusion_root(p: Any) -> tuple:
    """-05 section 3.2 compute_root of one ccf-inclusion-proof -> (root, data-hash of its leaf)."""
    leaf, path = _proof_map(p, "inclusion proof", "{1: leaf, 2: path}")
    if not (isinstance(leaf, list) and len(leaf) == 3):
        raise _ProofRefused("a leaf has three components")
    itx, ev, dh = leaf
    if not (isinstance(itx, bytes) and len(itx) == 32 and isinstance(dh, bytes) and len(dh) == 32
            and isinstance(ev, str) and 1 <= len(ev.encode("utf-8")) <= MAX_EVIDENCE_BYTES):
        raise _ProofRefused("leaf components violate the -05 CDDL sizes")
    h = hashlib.sha256(itx + hashlib.sha256(ev.encode("utf-8")).digest() + dh).digest()
    for left, sib in path:
        h = hashlib.sha256(sib + h if left else h + sib).digest()
    return h, dh


def _consistency_roots(p: Any) -> tuple:
    """-05 section 4.2 compute_roots of one ccf-consistency-proof -> (older, newer, first tag).

    Folding the anchor with the left siblings alone gives the older root, with all siblings the
    newer one. The first tag is returned because it decides whether the anchor is the one section 4
    requires: see ``verify_consistency_receipt``."""
    anchor, path = _proof_map(p, "consistency proof", "{1: anchor, 2: path}")
    if not (isinstance(anchor, bytes) and len(anchor) == 32):
        raise _ProofRefused("the anchor is bstr .size 32")
    older = newer = anchor
    for left, sib in path:
        if left:
            older = hashlib.sha256(sib + older).digest()
            newer = hashlib.sha256(sib + newer).digest()
        else:
            newer = hashlib.sha256(newer + sib).digest()
    return older, newer, path[0][0]


def _receipt(index: int, raw: Any, data_hash: bytes, services: Any) -> ReceiptCheck:
    if not isinstance(raw, bytes):
        return ReceiptCheck(index, "malformed", detail="a receipt is a byte string")
    try:
        rc = decode_cose_sign1(raw, role="receipt")
    except ScittFormatError as exc:
        return ReceiptCheck(index, exc.status, detail=str(exc))
    ph = rc.protected
    kid, iss, iat, txid, vdp = _receipt_head(rc)
    # readable means: parses under the -05 CDDL, proofs included (ADR 0009, Decision 10). So it is
    # False until the inclusion proofs have parsed, and a proof that does not parse is malformed,
    # whatever else the receipt is: malformed precedes outside_profile in STATUS_ORDER.
    base: dict[str, Any] = dict(index=index, readable=False, issuer=iss, kid=kid, receipt_iat=iat,
                                ccf_txid=txid, consistency_proofs_present=_CONSISTENCY in vdp)

    def out(status: str, **kw) -> ReceiptCheck:
        merged = {**base, **kw}
        if status == "malformed":
            merged["readable"] = False
        return ReceiptCheck(status=status, **merged)

    alg = ph.get(_ALG)
    proofs = vdp.get(_INCLUSION)
    parsed: list = []
    if _is_ccf(rc):
        # THE PROOFS BEFORE THE PROFILE (Codex, PR 278): an early profile branch must not skip the
        # shape of what follows it, or an unsupported algorithm makes junk proofs look readable.
        raw_vdp = rc.unprotected.get(_VDP)
        if raw_vdp is not None and not isinstance(raw_vdp, dict):
            return out("malformed", detail="vdp (396) is not a map")
        if proofs is not None and not isinstance(proofs, list):
            return out("malformed", detail="the inclusion proofs are not an array")
        if isinstance(proofs, list) and len(proofs) > MAX_INCLUSION_PROOFS:
            return out("malformed", detail=f"more than {MAX_INCLUSION_PROOFS} inclusion proofs")
        try:
            parsed = [_inclusion_root(p) for p in proofs or []]
        except _ProofRefused as exc:
            return out("malformed", detail=str(exc))
        base.update(readable=bool(parsed))
    why = _receipt_outside(rc, kid, iss)
    if why is None and rc.payload is not None:
        why = "the receipt payload is attached; -05 requires it detached"
    if why is None:
        why = _receipt_crit(rc)
    if why:
        return out("outside_profile", detail=why)
    if not parsed:
        return out("outside_profile", detail="no inclusion proof under 396 / -1")

    roots = [h for h, _dh in parsed]
    hashes_ = [dh for _h, dh in parsed]
    root = roots[0]
    base.update(merkle_root=root, data_hashes=tuple(hashes_))
    if any(r != root for r in roots):
        return out("root_mismatch", detail="inclusion proofs compute different roots")
    bound = all(dh == data_hash for dh in hashes_)

    trusted = services.get(iss) if isinstance(services, dict) else None
    keys, _ignored = _normalize_keys(trusted)
    candidates = [(spki, k) for spki, k in keys if (k if k is not None else _derived_kid(spki)) == kid]
    if not candidates:
        # NOT receipt_not_bound, which says the receipt signature is valid (ADR 0009, Decision 9):
        # without a key nothing is authenticated, so an unverifiable receipt must not claim the
        # cross-binding verdict (Codex, PR 278). The unbound leaf stays reported as a fact.
        return out("needs_rp_trust", bound=bound,
                   detail="no relying-party key for this issuer and kid" + (
                       "" if bound else "; the leaf's data-hash is not this statement's, unauthenticated"))
    tbs = _sig_structure(rc.protected_raw, root)
    good = [spki for spki, _k in candidates if _verify(alg, spki, tbs, rc.signature)]
    if not good:
        return out("signature_invalid", signature_valid=False, bound=bound,
                   detail="the receipt signature does not verify over the computed root")
    kid_bound = _derived_kid(good[0]) == kid
    if not bound:
        return out("receipt_not_bound", signature_valid=True, bound=False, kid_bound_to_key=kid_bound,
                   detail="valid receipt for another statement: data-hash differs")
    return out(CONFIRMED, signature_valid=True, bound=True, kid_bound_to_key=kid_bound)


# ------------------------------------------------------------------------------------------------
# The whole Transparent Statement
# ------------------------------------------------------------------------------------------------
def verify_transparent_statement(proof: bytes, *, canonical_root: bytes,
                                 rp_trust: Optional[dict] = None) -> TransparentStatementCheck:
    """Verify a Transparent Statement under ``scitt-ccf/v1`` against a target's canonical root.

    Never raises for any input: every refusal is a status. ``profile_satisfied`` holds only when the
    statement is a v1 hash envelope whose payload equals ``canonical_root``, its signature verifies
    under a relying-party statement key, and at least one receipt is confirmed under a
    relying-party service key and bound to this statement (owner decision Q5 a).
    """
    try:
        return _verify_transparent_statement(proof, canonical_root, rp_trust)
    except ScittUnavailable as exc:
        return TransparentStatementCheck(status="no_lib", readable=False, signature_valid=False,
                                         profile_satisfied=False, statement_status="no_lib",
                                         detail=str(exc))
    except Exception as exc:  # noqa: BLE001 - a verifier must never crash its caller
        return TransparentStatementCheck(status="malformed", readable=False, signature_valid=False,
                                         profile_satisfied=False, statement_status="malformed",
                                         detail=f"refused (fail-closed): {type(exc).__name__}")


def _verify_transparent_statement(proof, canonical_root, rp_trust) -> TransparentStatementCheck:
    def verdict(status, **kw):
        kw.setdefault("readable", False)
        kw.setdefault("signature_valid", False)
        kw.setdefault("statement_status", status)
        return TransparentStatementCheck(status=status, profile_satisfied=status == CONFIRMED, **kw)

    if not isinstance(proof, (bytes, bytearray)):
        return verdict("malformed", detail="the proof is not bytes")
    root_ok = isinstance(canonical_root, (bytes, bytearray)) and len(canonical_root) == 32
    trust = rp_trust if isinstance(rp_trust, dict) else {}
    try:
        st = decode_cose_sign1(bytes(proof), role="statement")
        selector = _statement_key_selector(st)
    except ScittFormatError as exc:
        return verdict(exc.status, detail=str(exc))

    statement_status = CONFIRMED
    why = _statement_profile(st)
    payload_digest = st.payload if (st.payload is not None and len(st.payload) == 32) else None
    stmt_valid = None
    ignored: list = []
    if why:
        statement_status = "outside_profile"
    elif not root_ok:
        statement_status, why = "unbound", "canonical_root must be 32 bytes (a SHA-256 root)"
    elif st.payload != bytes(canonical_root):
        statement_status, why = "unbound", "the statement's payload is not this target's root"
    else:
        statement_status, stmt_valid, ignored, why = _statement_signature(
            st, trust.get("scitt_statement_keys"), selector)

    receipts = st.unprotected.get(_RECEIPTS)
    if not isinstance(receipts, list) or not receipts:
        return verdict("malformed", readable=True, statement_status=statement_status,
                       statement_signature_valid=stmt_valid, payload_digest=payload_digest,
                       detail="no receipt under label 394: a Signed Statement is not a Transparent Statement")
    if len(receipts) > MAX_RECEIPTS:
        return verdict("malformed", readable=True, statement_status=statement_status,
                       detail=f"more than {MAX_RECEIPTS} receipts")
    data_hash = _data_hash(st) if st.tagged else None
    checks = tuple(_receipt(i, r, data_hash if data_hash is not None else b"", trust.get("scitt_ccf_services"))
                   for i, r in enumerate(receipts))
    receipt_statuses = [c.status for c in checks]
    best = CONFIRMED if CONFIRMED in receipt_statuses else _first(receipt_statuses)
    status = best if statement_status == CONFIRMED else _first([statement_status, best])
    return verdict(status,
                   readable=any(c.readable for c in checks),
                   signature_valid=any(c.signature_valid is True for c in checks),
                   statement_status=statement_status,
                   statement_signature_valid=stmt_valid,
                   payload_digest=payload_digest,
                   data_hash=data_hash,
                   receipts=checks,
                   ignored_trust=tuple(ignored),
                   detail=why or "")


# ------------------------------------------------------------------------------------------------
# Consistency receipts (draft-ietf-scitt-receipts-ccf-profile-05, section 4)
# ------------------------------------------------------------------------------------------------
def verify_consistency_receipt(consistency_receipt: bytes, *, older_root: bytes, older_issuer: str,
                               rp_trust: Optional[dict] = None) -> ConsistencyCheck:
    """Verify a CCF consistency receipt against an older root the caller has already verified.

    ``older_root`` must be a root the caller verified itself, typically ``merkle_root`` of a
    ``confirmed`` inclusion receipt, and ``older_issuer`` that receipt's issuer. -05, section
    "Consistency Receipts": verifiers MUST compare the recomputed older root with a root they have
    already verified, not with one supplied alongside the receipt; this function cannot tell where
    ``older_root`` came from, so that duty stays with the caller.

    Never raises. ``confirmed`` holds only when every -05 section 4 rule this reader can check holds:
    ``vdp`` carries one or more consistency proofs (4.1), the payload is detached (4.1), every proof,
    and every inclusion proof beside them, computes the same newer root (4.1, section 5), every
    proof's first path element is a right sibling, which is what the anchor section 4 requires
    looks like (see below), at least one proof recomputes ``older_root`` (4.2), the receipt's issuer
    is ``older_issuer`` (proofbundle's own rule, not a requirement of -05; owner answer S1 a keeps it
    until the working group answers gap G3), and a relying-party key for that issuer and kid verifies the
    receipt signature over the newer root (4.2). Anything else is one of
    ``CONSISTENCY_STATUS_ORDER``, the first that applies.

    THE ANCHOR CHECK. -05 says the anchor cannot be checked without knowing m. What can be checked
    is the first tag: the required anchor is the largest complete subtree ending at T[m-1], so its
    sibling in the newer tree is always on its right, while a smaller anchor further down the same
    edge folds to the same two roots and always starts with a left sibling. Measured exhaustively in
    tools/scitt_ccf_external/consistency_probe.py; a proof that starts with a left sibling also
    covers the case m = n, which section 4 excludes (0 < m < n).
    """
    try:
        return _verify_consistency(consistency_receipt, older_root, older_issuer, rp_trust)
    except ScittUnavailable as exc:
        return ConsistencyCheck(status="no_lib", detail=str(exc))
    except Exception as exc:  # noqa: BLE001 - a verifier must never crash its caller
        return ConsistencyCheck(status="malformed", detail=f"refused (fail-closed): {type(exc).__name__}")


def _verify_consistency(receipt, older_root, older_issuer, rp_trust) -> ConsistencyCheck:
    if not isinstance(receipt, (bytes, bytearray)):
        return ConsistencyCheck(status="malformed", detail="the receipt is not bytes")
    try:
        rc = decode_cose_sign1(bytes(receipt), role="receipt")
    except ScittFormatError as exc:
        return ConsistencyCheck(status=exc.status, detail=str(exc))
    kid, iss, iat, txid, _vdp = _receipt_head(rc)
    raw_vdp = rc.unprotected.get(_VDP)
    # readable: the consistency proofs parsed under the -05 CDDL; False until they have (the same
    # rule as for inclusion receipts, ADR 0009 Decision 10).
    base: dict[str, Any] = dict(readable=False, issuer=iss, kid=kid, receipt_iat=iat, ccf_txid=txid,
                                inclusion_proofs_present=isinstance(raw_vdp, dict) and _INCLUSION in raw_vdp)

    def out(status: str, **kw) -> ConsistencyCheck:
        merged = {**base, **kw}
        if status == "malformed":
            merged["readable"] = False
        return ConsistencyCheck(status=status, **merged)

    computed: list = []
    inclusion_roots: list = []
    if _is_ccf(rc) and raw_vdp is not None:
        # THE PROOFS BEFORE THE PROFILE (Codex, PR 278), as in _receipt: a shape defect is
        # malformed whatever the profile says, and malformed precedes outside_profile.
        if not isinstance(raw_vdp, dict):
            return out("malformed", detail="vdp (396) is not a map")
        unknown = [k for k in raw_vdp if k not in (_INCLUSION, _CONSISTENCY)]
        if unknown:
            return out("malformed", detail=f"vdp carries {unknown!r}; -05 defines -1 and -2 only")
        proofs = raw_vdp.get(_CONSISTENCY)
        inclusion = raw_vdp.get(_INCLUSION)
        for name, arr in (("consistency", proofs), ("inclusion", inclusion)):
            if arr is not None and not isinstance(arr, list):
                return out("malformed", detail=f"the {name} proofs are not an array")
            if arr is not None and len(arr) > MAX_CONSISTENCY_PROOFS:
                return out("malformed", detail=f"more than {MAX_CONSISTENCY_PROOFS} {name} proofs")
        try:
            computed = [_consistency_roots(p) for p in proofs or []]
            inclusion_roots = [_inclusion_root(p)[0] for p in inclusion or []]
        except _ProofRefused as exc:
            return out("malformed", detail=str(exc))
        base.update(proofs=len(computed), readable=bool(computed))
    why = _receipt_outside(rc, kid, iss) or _receipt_crit(rc)
    if why:
        return out("outside_profile", detail=why)
    if raw_vdp is None:
        return out("consistency_proof_missing", detail="no vdp (396) in the unprotected header")
    if not computed:
        return out("consistency_proof_missing", detail="no consistency proof under 396 / -2 (4.1)")
    if rc.payload is not None:
        return out("consistency_payload_attached",
                   detail="the payload is attached; 4.1 requires the newer root detached")
    newer = computed[0][1]
    base.update(newer_root=newer)
    if any(n != newer for _o, n, _f in computed) or any(r != newer for r in inclusion_roots):
        return out("consistency_newer_roots_differ",
                   detail="the proofs of this receipt compute different newer roots (4.1, section 5)")
    older_ok = (isinstance(older_root, (bytes, bytearray)) and len(older_root) == 32
                and any(o == bytes(older_root) for o, _n, _f in computed))
    base.update(older_root_matches=older_ok)

    trusted = (rp_trust.get("scitt_ccf_services") if isinstance(rp_trust, dict) else None)
    trusted = trusted.get(iss) if isinstance(trusted, dict) else None
    keys, _ignored = _normalize_keys(trusted)
    candidates = [spki for spki, k in keys if (k if k is not None else _derived_kid(spki)) == kid]
    good = [spki for spki in candidates
            if _verify(rc.protected.get(_ALG), spki, _sig_structure(rc.protected_raw, newer), rc.signature)]
    if candidates:
        base.update(signature_valid=bool(good),
                    kid_bound_to_key=(_derived_kid(good[0]) == kid) if good else None)

    if any(first_left for _o, _n, first_left in computed):
        return out("consistency_anchor_not_canonical",
                   detail="a proof starts with a left sibling: its anchor is not the largest complete "
                          "subtree ending at the older tree's last transaction (section 4)")
    if not older_ok:
        return out("consistency_older_root_mismatch",
                   detail="no proof recomputes the older root the caller holds (4.2)")
    if not isinstance(older_issuer, str) or older_issuer != iss:
        return out("consistency_issuer_mismatch",  # proofbundle's own rule, not a requirement of -05
                   detail="the older root was verified from another service's receipt (proofbundle's "
                          "own rule, not a requirement of -05)")
    if not candidates:
        return out("needs_rp_trust", detail="no relying-party key for this issuer and kid")
    if not good:
        return out("signature_invalid", detail="the receipt signature does not verify over the newer root")
    return out(CONFIRMED)
