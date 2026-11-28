"""A local test stand-in for a SCITT service, for this example only.

proofbundle reads and verifies SCITT Transparent Statements with CCF receipts (src/proofbundle/scitt_ccf.py,
profile scitt-ccf/v1), but it has no producer of signed statements (ADR 0009 names one as later work). This
module is that producer for the example, and nothing in src/ uses it:

* ``signed_statement`` writes an RFC 9995 hash envelope: a tagged COSE_Sign1 with ES256, label 258 = -16
  (SHA-256), the preimage content type (259), CWT Claims with iss and sub, and the signer's certificate in the
  protected x5chain (33). The payload is the 32-byte SHA-256 the caller gives.
* ``LocalLedger.register`` plays the service: it puts the statement's CCF data-hash into a leaf next to three
  filler leaves, computes the Merkle root, and signs it in a receipt in the shape of
  draft-ietf-scitt-receipts-ccf-profile-06 (vds 2, an inclusion proof under 396 / -1, the payload detached), as
  the reader in src/proofbundle/scitt_ccf.py computes it.
* ``transparent`` puts receipts under label 394 of the statement's unprotected header.

It is not a CCF ledger and runs no consensus, no TEE and no network service: it shows the bytes a relying party
checks, not a registration policy. Every key is a test key derived from a public label (``ec_key``) and every
ECDSA signature is deterministic (RFC 6979), so the example's files are the same on every run. Needs a
cryptography release with ``deterministic_signing`` (43 or later).
"""
from __future__ import annotations

import datetime
import hashlib

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID

_P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


# ---------------------------------------------------------------- a small deterministic CBOR encoder
def _head(major: int, n: int) -> bytes:
    if n < 24:
        return bytes([major << 5 | n])
    for ai, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if n < 1 << (8 * size):
            return bytes([major << 5 | ai]) + n.to_bytes(size, "big")
    raise ValueError("integer too large")


class Tag:
    def __init__(self, tag: int, value):
        self.tag, self.value = tag, value


def cbor(v) -> bytes:
    """Shortest-form CBOR. Map keys keep the caller's order, as the services measured for the reader write them."""
    if v is None:
        return b"\xf6"
    if v is True:
        return b"\xf5"
    if v is False:
        return b"\xf4"
    if isinstance(v, int):
        return _head(0, v) if v >= 0 else _head(1, -1 - v)
    if isinstance(v, bytes):
        return _head(2, len(v)) + v
    if isinstance(v, str):
        b = v.encode("utf-8")
        return _head(3, len(b)) + b
    if isinstance(v, list):
        return _head(4, len(v)) + b"".join(cbor(x) for x in v)
    if isinstance(v, dict):
        return _head(5, len(v)) + b"".join(cbor(k) + cbor(x) for k, x in v.items())
    if isinstance(v, Tag):
        return _head(6, v.tag) + cbor(v.value)
    raise TypeError("cannot encode %s" % type(v).__name__)


def _tbs(protected: bytes, payload: bytes) -> bytes:
    """RFC 9052 section 4.4, Sig_structure of a COSE_Sign1 with empty external_aad."""
    return cbor(["Signature1", protected, b"", payload])


# ---------------------------------------------------------------- test keys
def ec_key(label: str) -> ec.EllipticCurvePrivateKey:
    """A P-256 TEST key whose scalar is SHA-256 over the public label, reduced into the group. Anyone can rebuild
    it from the label; never use it for anything real."""
    d = int.from_bytes(hashlib.sha256(label.encode("ascii")).digest(), "big") % (_P256_ORDER - 1) + 1
    return ec.derive_private_key(d, ec.SECP256R1())


def spki(key) -> bytes:
    pub = key.public_key() if hasattr(key, "public_key") else key
    return pub.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def kid_of(key) -> bytes:
    """The kid the CCF services measured for the reader use: hex(SHA-256(SubjectPublicKeyInfo)), ASCII."""
    return hashlib.sha256(spki(key)).hexdigest().encode("ascii")


def es256(key: ec.EllipticCurvePrivateKey, data: bytes) -> bytes:
    """ES256 (RFC 9053 section 2.1): r || s, 32 bytes each, deterministic as in RFC 6979."""
    r, s = utils.decode_dss_signature(key.sign(data, ec.ECDSA(hashes.SHA256(), deterministic_signing=True)))
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def test_certificate(key: ec.EllipticCurvePrivateKey, name: str, issuer_label: str) -> bytes:
    """A DER certificate for ``key``, issued by an Ed25519 TEST issuer derived from ``issuer_label`` so that the
    certificate bytes are deterministic. The reader takes only the subject key from it, to select among the
    relying party's pinned statement keys; the certificate is never trust."""
    issuer = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(issuer_label.encode("ascii")).digest())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name + " TEST KEY ONLY"),
                         x509.NameAttribute(NameOID.ORGANIZATION_NAME, "example")])
    issuer_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "example test issuer TEST KEY ONLY")])
    return (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer_name).public_key(key.public_key())
            .serial_number(1)
            .not_valid_before(datetime.datetime(2026, 11, 1, tzinfo=datetime.timezone.utc))
            .not_valid_after(datetime.datetime(2027, 11, 1, tzinfo=datetime.timezone.utc))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(issuer, None).public_bytes(serialization.Encoding.DER))


# ---------------------------------------------------------------- the signed statement
def signed_statement(digest: bytes, key, cert_der: bytes, *, iss: str, sub: str,
                     preimage_type: str = "application/vnd.in-toto+json") -> bytes:
    """A tagged COSE_Sign1 hash envelope (RFC 9995) over ``digest``, the SHA-256 of the record's payload bytes."""
    if len(digest) != 32:
        raise ValueError("a SHA-256 hash envelope payload is 32 bytes")
    protected = cbor({1: -7, 258: -16, 259: preimage_type, 15: {1: iss, 2: sub}, 33: cert_der})
    return cbor(Tag(18, [protected, {}, digest, es256(key, _tbs(protected, digest))]))


def _split(statement: bytes) -> tuple:
    """The protected header, payload and signature of a statement this module wrote, as bytes."""
    if statement[:2] != b"\xd2\x84":
        raise ValueError("not a tagged COSE_Sign1 of this module")
    out, i = [], 2
    for _ in range(4):
        major, ai = statement[i] >> 5, statement[i] & 31
        if major == 5 and ai == 0:      # the empty unprotected map
            out.append(b"")
            i += 1
            continue
        if major != 2:
            raise ValueError("expected a byte string")
        i += 1
        n = ai
        if ai >= 24:
            size = 1 << (ai - 24)
            n = int.from_bytes(statement[i:i + size], "big")
            i += size
        out.append(statement[i:i + n])
        i += n
    if i != len(statement):
        raise ValueError("trailing bytes")
    return out[0], out[2], out[3]


def data_hash(statement: bytes) -> bytes:
    """The CCF data-hash of a statement: SHA-256 over tag 18, the array head, the protected header, an empty
    unprotected map, payload and signature (the rule src/proofbundle/scitt_ccf.py recomputes)."""
    prot, payload, sig = _split(statement)
    return hashlib.sha256(b"\xd2\x84" + cbor(prot) + b"\xa0" + cbor(payload) + cbor(sig)).digest()


def transparent(statement: bytes, receipts: list) -> bytes:
    """The statement with ``receipts`` under label 394 of its unprotected header: a Transparent Statement."""
    prot, payload, sig = _split(statement)
    return b"\xd2\x84" + cbor(prot) + cbor({394: list(receipts)}) + cbor(payload) + cbor(sig)


# ---------------------------------------------------------------- the local ledger
class LocalLedger:
    """Four leaves, the statement's at ``position``; the receipt proves its inclusion under the signed root."""

    def __init__(self, key, *, issuer: str, iat: int, txid: str = "2.17", position: int = 2):
        self.key, self.issuer, self.iat, self.txid, self.position = key, issuer, iat, txid, position

    @staticmethod
    def _leaf(itx: bytes, evidence: str, dh: bytes) -> bytes:
        return hashlib.sha256(itx + hashlib.sha256(evidence.encode("utf-8")).digest() + dh).digest()

    def register(self, statement: bytes, *, signing_key=None, kid=None, dh: bytes | None = None) -> bytes:
        """The receipt for ``statement``. ``signing_key``, ``kid`` and ``dh`` stand in for the service key, its kid
        and the data-hash only where a case of cases.md needs another one."""
        dh = data_hash(statement) if dh is None else dh
        itx = hashlib.sha256(b"local ledger internal transaction %d" % self.position).digest()
        evidence = "ce:2.%d:" % (16 + self.position) + hashlib.sha256(b"commit evidence").hexdigest()
        leaves = [hashlib.sha256(b"filler leaf %d" % i).digest() for i in range(4)]
        leaves[self.position] = self._leaf(itx, evidence, dh)
        level1 = [hashlib.sha256(leaves[0] + leaves[1]).digest(), hashlib.sha256(leaves[2] + leaves[3]).digest()]
        root = hashlib.sha256(level1[0] + level1[1]).digest()
        p = self.position
        path = [[p % 2 == 1, leaves[p ^ 1]], [p >= 2, level1[1 - p // 2]]]   # [left, sibling], leaf upwards
        key = self.key if signing_key is None else signing_key
        protected = cbor({1: -7, 4: kid_of(key) if kid is None else kid, 395: 2,
                          15: {1: self.issuer, 2: "scitt.ccf.signature.v1", 6: self.iat},
                          "ccf.v1": {"txid": self.txid}})
        proof = cbor({1: [itx, evidence, dh], 2: path})
        return cbor(Tag(18, [protected, {396: {-1: [proof]}}, None, es256(key, _tbs(protected, root))]))
