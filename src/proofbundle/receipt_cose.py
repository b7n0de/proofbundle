"""COSE_Sign1 Hash Envelopes that cite a Signed Evaluation Receipt, in both directions (EXPERIMENTAL).

Needs the ``[scitt]`` extra (cbor2): a statement is read with it, and every statement this module writes
is read back with it before it is returned. The receipt format itself (``signed_eval_receipt``) needs no
CBOR, and nothing here runs unless a caller imports this module. Nothing here opens a network connection.

THE RULE, one statement for one receipt digest (the section "COSE and SCITT" of
draft-gruszka-evaluation-receipt-mappings, as proposed for its next revision):

* payload: the receipt digest, SHA-256 over B, 32 bytes: a COSE Hash Envelope (RFC 9995);
* protected header, exactly these five labels:

  - 1 (alg): -19 (Ed25519, RFC 9864) or -8 (EdDSA, RFC 9053), whichever the caller names; there is no
    default, both mean Ed25519 here;
  - 4 (kid): the COSE Key Thumbprint (RFC 9679, SHA-256) of the statement key, 32 bytes;
  - 15 (CWT Claims, RFC 9597): exactly 1 (``iss``), a URI, and 2 (``sub``), the ``model_id_commit`` of B;
  - 258 (payload hash algorithm): -16 (SHA-256);
  - 259 (preimage content type): the receipt type, as text;

* unprotected header: the empty map;
* tag 18, and the whole COSE_Sign1, the protected header inside it included, in the core deterministic
  encoding of RFC 8949 section 4.2.1, so one statement has one byte string.

FORWARD, ``receipt_to_statement``: the receipt must pass every step of the draft's Section 6 under the key
the caller fixed, or no statement is made.

BACKWARD, ``check_statement``: a statement is accepted only if it reads under the rule, its signature
verifies under a statement key of the relying party that its kid names, and its payload is the digest of
the presented receipt, which itself passes the draft's Section 6 under the receipt key the relying party
fixed; ``sub`` must be that receipt's model commitment. Every other outcome is a status, never a pass,
and the check never raises for what it is given to read.

WHAT IS LOST. The statement carries the digest and the model commitment of B, nothing else of the receipt:
not the score, threshold, comparator, verdict, suite or timestamp, not the dataset commitment, not the
receipt's signature or key hint. A Receiver that relies on the assertion needs the
receipt itself; the statement only names it. The statement's signature is not the receipt's signature,
even when one key makes both.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from typing import Any, NamedTuple, Optional, Sequence

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .signature import ed25519_trust_anchor_weakness, plain_bytes, verify_ed25519_pinned
from .signed_eval_receipt import RECEIPT_TYPE, verify_signed_eval_receipt

__all__ = ["ALG_ED25519", "ALG_EDDSA", "ALGS", "ACCEPTED", "STATUSES", "CoseUnavailable", "ReceiptCoseError",
           "StatementCheck", "cose_key_thumbprint", "receipt_to_statement", "check_statement"]

#: COSE algorithm values this rule writes and reads, both for Ed25519 keys.
ALG_ED25519 = -19   # RFC 9864, fully specified
ALG_EDDSA = -8      # RFC 9053, polymorphic EdDSA
ALGS = (ALG_ED25519, ALG_EDDSA)

ACCEPTED = "accepted"
#: Every status ``check_statement`` returns; only ``accepted`` is a pass.
STATUSES = (ACCEPTED, "no_lib", "malformed", "outside_profile", "untrusted_key", "signature_invalid",
            "receipt_not_verified", "digest_mismatch", "subject_mismatch")

_ALG, _KID, _CWT, _HASH_ALG, _PREIMAGE_CTY = 1, 4, 15, 258, 259
_ISS, _SUB = 1, 2
_SHA256 = -16
_TAG_SIGN1 = 18
_LABELS = frozenset({_ALG, _KID, _CWT, _HASH_ALG, _PREIMAGE_CTY})
_CLAIMS = frozenset({_ISS, _SUB})
#: A URI as RFC 3986 starts it: a scheme, a colon, then no space or control character.
_URI_RE = re.compile(r"\A[A-Za-z][A-Za-z0-9+.-]*:[^\x00-\x20\x7f]+\Z")
_COMMIT_RE = re.compile(r"\Asha256:[0-9a-f]{64}\Z")
_MAX_KEYS = 64


class ReceiptCoseError(ValueError):
    """The forward direction refuses: a receipt that does not verify, an argument it cannot write
    honestly, or bytes that did not read back as written."""


class CoseUnavailable(ImportError):
    """The ``[scitt]`` extra is not installed, or its cbor2 lacks the strict options the reader needs."""


class _Refused(Exception):
    def __init__(self, status: str, detail: str):
        super().__init__(detail)
        self.status, self.detail = status, detail


class StatementCheck(NamedTuple):
    """The verdict on one statement. ``status`` is one of ``STATUSES``; ``ok`` only for ``accepted``.
    The header values are filled in as far as the statement could be read; ``receipt_step`` names the
    first failing step of the draft's Section 6 for ``receipt_not_verified``."""
    status: str
    detail: str = ""
    alg: Optional[int] = None
    kid: Optional[bytes] = None
    issuer: Optional[str] = None
    subject: Optional[str] = None
    payload: Optional[bytes] = None
    receipt_step: Optional[str] = None
    ignored_keys: tuple = ()

    @property
    def ok(self) -> bool:
        return self.status == ACCEPTED


# ---- deterministic CBOR (RFC 8949 section 4.2.1) for the few types a statement holds ---------------------
def _head(major: int, n: int) -> bytes:
    if n < 24:
        return bytes([major << 5 | n])
    for size, info in ((1, 24), (2, 25), (4, 26), (8, 27)):
        if n < 1 << (8 * size):
            return bytes([major << 5 | info]) + n.to_bytes(size, "big")
    raise _Refused("malformed", "an integer beyond 64 bits has no plain CBOR head")


def _enc(value: Any) -> bytes:
    if value is True:
        return b"\xf5"
    if value is False:
        return b"\xf4"
    if value is None:
        return b"\xf6"
    if type(value) is int:
        return _head(0, value) if value >= 0 else _head(1, -1 - value)
    if type(value) is bytes:
        return _head(2, len(value)) + value
    if type(value) is str:
        raw = value.encode("utf-8")
        return _head(3, len(raw)) + raw
    if type(value) is list:
        return _head(4, len(value)) + b"".join(_enc(v) for v in value)
    if type(value) is dict:
        items = sorted((_enc(k), _enc(v)) for k, v in value.items())
        return _head(5, len(items)) + b"".join(k + v for k, v in items)
    raise _Refused("malformed", f"no deterministic encoding for a {type(value).__name__}")


def _sig_structure(protected_raw: bytes, payload: bytes) -> bytes:
    """RFC 9052 section 4.4 ToBeSigned for a COSE_Sign1, external_aad empty."""
    return _enc(["Signature1", protected_raw, b"", payload])


def cose_key_thumbprint(public_key: bytes) -> bytes:
    """RFC 9679 COSE Key Thumbprint with SHA-256 of a raw Ed25519 public key: SHA-256 over the deterministic
    encoding of the OKP key's required parameters {1 (kty): 1 (OKP), -1 (crv): 6 (Ed25519), -2 (x): key}."""
    raw = plain_bytes(public_key)
    if raw is None or len(raw) != 32:
        raise ValueError("an Ed25519 public key is 32 bytes")
    return hashlib.sha256(_enc({1: 1, -1: 6, -2: raw})).digest()


# ---- the reader --------------------------------------------------------------------------------------------
def _cbor2() -> Any:
    try:
        import cbor2  # noqa: PLC0415 - the [scitt] extra
    except ImportError:
        raise CoseUnavailable("the [scitt] extra (cbor2) is not installed") from None
    try:
        cbor2.loads(b"\xa0", allow_duplicate_keys=False, allow_indefinite=False)
    except TypeError:
        raise CoseUnavailable("this cbor2 cannot refuse duplicate keys and indefinite lengths; the [scitt] "
                              "extra pins the version the reader was measured with") from None
    return cbor2


def _loads(cbor2: Any, data: bytes) -> Any:
    try:
        return cbor2.loads(data, allow_duplicate_keys=False, allow_indefinite=False)
    except Exception as exc:  # noqa: BLE001 - any refusal of the decoder is a malformed statement
        raise _Refused("malformed", f"not CBOR this reader accepts ({type(exc).__name__})") from None


def _plain(value: Any) -> Any:
    """The decoded value in exact built-in types; a tag, a float or a simple value other than true, false
    and null is not part of a statement."""
    if value is None or value is True or value is False or type(value) in (int, bytes, str):
        return value
    if isinstance(value, (list, tuple)):
        return [_plain(v) for v in value]
    if isinstance(value, Mapping):
        return {_plain(k): _plain(v) for k, v in value.items()}
    raise _Refused("malformed", f"a {type(value).__name__} is not part of a statement")


class _Sign1(NamedTuple):
    tagged: bool
    protected_raw: bytes
    protected: dict
    unprotected: dict
    payload: Optional[bytes]
    signature: bytes


def _read(data: bytes) -> _Sign1:
    cbor2 = _cbor2()
    top = _loads(cbor2, data)
    tagged = isinstance(top, cbor2.CBORTag)
    if tagged and top.tag != _TAG_SIGN1:
        raise _Refused("malformed", f"tag {top.tag}, not 18 (COSE_Sign1)")
    body = _plain(top.value if tagged else top)
    if type(body) is not list or len(body) != 4:
        raise _Refused("malformed", "not a COSE_Sign1, an array of four")
    protected_raw, unprotected, payload, signature = body
    if type(protected_raw) is not bytes or type(unprotected) is not dict or type(signature) is not bytes \
            or not (payload is None or type(payload) is bytes):
        raise _Refused("malformed", "the four members of a COSE_Sign1 do not have their types")
    if (_head(6, _TAG_SIGN1) if tagged else b"") + _enc(body) != data:
        raise _Refused("malformed", "the COSE_Sign1 is not in the deterministic encoding (RFC 8949 section "
                                    "4.2.1), or data follows it")
    protected: Any = {}
    if protected_raw:
        decoded = _loads(cbor2, protected_raw)
        if isinstance(decoded, cbor2.CBORTag):
            raise _Refused("malformed", "the protected header is a tag, not a map")
        protected = _plain(decoded)
        if type(protected) is not dict:
            raise _Refused("malformed", "the protected header is not a map")
        if _enc(protected) != protected_raw:
            raise _Refused("malformed", "the protected header is not in the deterministic encoding, or data "
                                        "follows it")
    return _Sign1(tagged, protected_raw, protected, unprotected, payload, signature)


def _rule_broken(st: _Sign1, algs: tuple) -> Optional[str]:
    """None if the statement follows the rule of the module docstring, else the first rule it breaks."""
    if not st.tagged:
        return "the statement is not tagged 18 (COSE_Sign1)"
    if st.unprotected:
        return "the unprotected header is not empty"
    ph = st.protected
    if any(type(k) is not int for k in ph) or set(ph) != _LABELS:
        return "the protected header does not hold exactly the labels 1, 4, 15, 258 and 259"
    alg = ph[_ALG]
    if type(alg) is not int or alg not in algs:
        return f"alg {alg!r} is not one of {list(algs)}"
    kid = ph[_KID]
    if type(kid) is not bytes or len(kid) != 32:
        return "kid is not a 32-byte COSE Key Thumbprint (RFC 9679, SHA-256)"
    claims = ph[_CWT]
    if type(claims) is not dict or any(type(k) is not int for k in claims) or set(claims) != _CLAIMS:
        return "the CWT Claims (15) are not a map of exactly iss (1) and sub (2)"
    if type(claims[_ISS]) is not str or not _URI_RE.match(claims[_ISS]):
        return "iss is not a URI"
    if type(claims[_SUB]) is not str or not _COMMIT_RE.match(claims[_SUB]):
        return "sub is not a model commitment, sha256: followed by 64 lowercase hexadecimal digits"
    if type(ph[_HASH_ALG]) is not int or ph[_HASH_ALG] != _SHA256:
        return f"label 258 is {ph[_HASH_ALG]!r}, not -16 (SHA-256)"
    if type(ph[_PREIMAGE_CTY]) is not str or ph[_PREIMAGE_CTY] != RECEIPT_TYPE:
        return f"label 259 is not the receipt type {RECEIPT_TYPE}"
    if st.payload is None:
        return "the payload is detached"
    if len(st.payload) != 32:
        return f"the payload is {len(st.payload)} bytes, not a 32-byte SHA-256 digest"
    if len(st.signature) != 64:
        return f"the signature is {len(st.signature)} bytes, not an Ed25519 signature"
    return None


def _statement_keys(entries: Any) -> tuple:
    """Relying-party statement keys -> ([(raw key, thumbprint)], [why an entry was ignored]). Only an
    Ed25519 key of 32 bytes that is no weak trust anchor counts; anything else is absent trust."""
    usable: list = []
    ignored: list = []
    if not isinstance(entries, (list, tuple)):
        return usable, (["statement keys are not a list"] if entries is not None else [])
    for i, entry in enumerate(entries[:_MAX_KEYS]):
        raw = plain_bytes(entry)
        if raw is None or len(raw) != 32:
            ignored.append(f"key {i}: not a 32-byte Ed25519 public key")
            continue
        weakness = ed25519_trust_anchor_weakness(raw)
        if weakness is not None:
            ignored.append(f"key {i}: {weakness} Ed25519 key, refused as a trust anchor")
            continue
        usable.append((raw, cose_key_thumbprint(raw)))
    if len(entries) > _MAX_KEYS:
        ignored.append(f"keys beyond {_MAX_KEYS} ignored")
    return usable, ignored


def _algs(algs: Any) -> tuple:
    if not isinstance(algs, (list, tuple)) or not algs or any(type(a) is not int or a not in ALGS for a in algs):
        raise ValueError(f"algs must name one or more of {list(ALGS)}")
    return tuple(algs)


# ---- backward ----------------------------------------------------------------------------------------------
def check_statement(statement: bytes, *, receipt: bytes, receipt_key: bytes, statement_keys: Sequence[bytes],
                    algs: Sequence[int] = ALGS) -> StatementCheck:
    """Check STATEMENT, a COSE_Sign1 under the rule of the module docstring, against RECEIPT, verified under
    RECEIPT_KEY (32 raw bytes) by the draft's Section 6, with the relying party's STATEMENT_KEYS (raw
    32-byte Ed25519 public keys; the statement's kid only selects among them). ALGS narrows the accepted
    alg values. Never raises for what it reads; every refusal is a status."""
    accepted = _algs(algs)
    seen: dict = {}
    ignored: list = []
    try:
        data = plain_bytes(statement)
        if data is None:
            raise _Refused("malformed", "the statement is not a bytes value")
        st = _read(data)
        ph = st.protected
        raw_claims = ph.get(_CWT)
        claims: dict = raw_claims if type(raw_claims) is dict else {}
        seen = {"alg": ph.get(_ALG) if type(ph.get(_ALG)) is int else None,
                "kid": ph.get(_KID) if type(ph.get(_KID)) is bytes else None,
                "issuer": claims.get(_ISS) if type(claims.get(_ISS)) is str else None,
                "subject": claims.get(_SUB) if type(claims.get(_SUB)) is str else None,
                "payload": st.payload}
        why = _rule_broken(st, accepted)
        if why:
            raise _Refused("outside_profile", why)
        keys, ignored = _statement_keys(statement_keys)
        candidates = [raw for raw, thumbprint in keys if thumbprint == ph[_KID]]
        if not candidates:
            raise _Refused("untrusted_key", "no relying-party statement key has the statement's kid")
        tbs = _sig_structure(st.protected_raw, st.payload or b"")
        if not any(verify_ed25519_pinned(raw, st.signature, tbs) for raw in candidates):
            raise _Refused("signature_invalid", "the signature fails under the key the kid selects")
        verdict = verify_signed_eval_receipt(receipt, receipt_key)
        if not verdict.ok or verdict.payload is None:
            return StatementCheck("receipt_not_verified", f"the presented receipt fails the draft's Section 6: "
                                  f"{verdict.reason}", receipt_step=verdict.step_label,
                                  ignored_keys=tuple(ignored), **seen)
        if hashlib.sha256(verdict.payload).digest() != st.payload:
            raise _Refused("digest_mismatch", "the payload is not SHA-256 over B of the presented receipt")
        if json.loads(verdict.payload)["model_id_commit"] != ph[_CWT][_SUB]:
            raise _Refused("subject_mismatch", "sub is not the model commitment of the presented receipt")
        return StatementCheck(ACCEPTED, "the statement cites the presented receipt under a relying-party key",
                              ignored_keys=tuple(ignored), **seen)
    except _Refused as refusal:
        return StatementCheck(refusal.status, refusal.detail, ignored_keys=tuple(ignored), **seen)
    except CoseUnavailable as exc:
        return StatementCheck("no_lib", str(exc))
    except Exception as exc:  # noqa: BLE001 - a check never crashes its caller and never passes by accident
        return StatementCheck("malformed", f"refused (fail-closed): {type(exc).__name__}", **seen)


# ---- forward -----------------------------------------------------------------------------------------------
def receipt_to_statement(receipt: bytes, receipt_key: bytes, signer: Ed25519PrivateKey, *, issuer: str,
                         alg: int) -> bytes:
    """The COSE_Sign1 that cites RECEIPT under the rule of the module docstring, signed by SIGNER.

    RECEIPT must pass every step of the draft's Section 6 under RECEIPT_KEY (32 raw bytes), or no statement
    is made. ISSUER becomes ``iss`` and must be a URI; ALG is -19 or -8 and has no default. The bytes are
    read back and checked with ``check_statement`` under the signer's public key before they are returned.
    Raises ``ReceiptCoseError`` for anything it cannot write honestly, ``CoseUnavailable`` without the
    ``[scitt]`` extra."""
    if type(alg) is not int or alg not in ALGS:
        raise ReceiptCoseError(f"alg must be {ALG_ED25519} (Ed25519, RFC 9864) or {ALG_EDDSA} (EdDSA, RFC 9053); "
                               "there is no default")
    if not isinstance(signer, Ed25519PrivateKey):
        raise ReceiptCoseError("the signer must be an Ed25519 private key")
    if type(issuer) is not str or not _URI_RE.match(issuer):
        raise ReceiptCoseError("issuer must be a URI (a scheme, a colon, no space or control character)")
    _cbor2()
    verdict = verify_signed_eval_receipt(receipt, receipt_key)
    if not verdict.ok or verdict.payload is None:
        raise ReceiptCoseError(f"the receipt does not verify (step {verdict.step_label}: {verdict.reason}); "
                               "no statement is made")
    digest = hashlib.sha256(verdict.payload).digest()
    subject = json.loads(verdict.payload)["model_id_commit"]
    public = signer.public_key().public_bytes_raw()
    protected = {_ALG: alg, _KID: cose_key_thumbprint(public), _CWT: {_ISS: issuer, _SUB: subject},
                 _HASH_ALG: _SHA256, _PREIMAGE_CTY: RECEIPT_TYPE}
    protected_raw = _enc(protected)
    signature = signer.sign(_sig_structure(protected_raw, digest))
    data = _head(6, _TAG_SIGN1) + _enc([protected_raw, {}, digest, signature])
    check = check_statement(data, receipt=receipt, receipt_key=receipt_key, statement_keys=[public], algs=(alg,))
    if not check.ok:
        raise ReceiptCoseError(f"the statement did not read back as written: {check.status}, {check.detail}")
    return data
