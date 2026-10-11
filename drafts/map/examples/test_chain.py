"""Deterministic test material for the certificate profile of draft-gruszka-evaluation-receipt-mappings-01.

PURE TEST MATERIAL. Nothing made here may be used for anything real.

  * an RSA-3072 test root: its primes come from a search seeded with SHA-256 over a fixed label (candidates from a
    SHA-256 counter stream, the two top bits and the low bit set, then the next odd number that passes trial division
    and Miller-Rabin with the first 64 primes as bases and whose p-1 is prime to 65537);
  * P-256 test leaves: the private scalar is SHA-256 over a fixed label, reduced into [1, n-1];
  * self-signed root and leaf certificates with fixed serial numbers and dates, signed with sha256WithRSAEncryption
    (RSASSA-PKCS1-v1_5 is deterministic);
  * ES256 signatures with the deterministic nonce of RFC 6979 Section 3.2 (HMAC-SHA-256), so that every run gives the
    same bytes; the result is verified with the cryptography library before it is returned.

Only the generator imports this module; the checkers read the certificates and statements as bytes.
"""
import datetime
import hashlib
import hmac

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
EKU_CODE_SIGNING = ExtendedKeyUsageOID.CODE_SIGNING.dotted_string
NOT_BEFORE = datetime.datetime(2026, 1, 1, 0, 0, 0)
NOT_AFTER = datetime.datetime(2035, 12, 31, 23, 59, 59)
SMALL_PRIMES = [p for p in range(3, 20000, 2) if all(p % d for d in range(3, int(p ** 0.5) + 1, 2))]
MR_BASES = [2] + SMALL_PRIMES[:63]


def _stream(label: str):
    counter = 0
    while True:
        yield from hashlib.sha256(label.encode("utf-8") + counter.to_bytes(4, "big")).digest()
        counter += 1


def _probable_prime(n: int) -> bool:
    if any(n % p == 0 for p in SMALL_PRIMES):
        return n in SMALL_PRIMES
    d, s = n - 1, 0
    while d % 2 == 0:
        d, s = d // 2, s + 1
    for a in MR_BASES:
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _prime(label: str, bits: int, e: int = 65537) -> int:
    stream = _stream(label)
    c = int.from_bytes(bytes(next(stream) for _ in range(bits // 8)), "big")
    c |= (3 << (bits - 2)) | 1
    c &= (1 << bits) - 1
    while not (_probable_prime(c) and (c - 1) % e != 0):
        c += 2
    return c


def rsa_test_key(label: str, bits: int = 3072):
    e = 65537
    p = _prime(label + " p", bits // 2)
    q = _prime(label + " q", bits // 2)
    if p == q:
        raise SystemExit("equal primes")
    n = p * q
    d = pow(e, -1, (p - 1) * (q - 1))
    pub = rsa.RSAPublicNumbers(e, n)
    return rsa.RSAPrivateNumbers(p, q, d, rsa.rsa_crt_dmp1(d, p), rsa.rsa_crt_dmq1(d, q),
                                 rsa.rsa_crt_iqmp(p, q), pub).private_key()


def p256_test_key(label: str):
    scalar = int.from_bytes(hashlib.sha256(label.encode("utf-8")).digest(), "big") % (P256_N - 1) + 1
    return ec.derive_private_key(scalar, ec.SECP256R1())


def spki_der(public_key) -> bytes:
    return public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)


def _name(cn: str):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def certificate(subject_key, issuer_key, cn: str, issuer_cn: str, serial: int, ca: bool, eku=None) -> bytes:
    b = (x509.CertificateBuilder().subject_name(_name(cn)).issuer_name(_name(issuer_cn))
         .public_key(subject_key.public_key()).serial_number(serial)
         .not_valid_before(NOT_BEFORE).not_valid_after(NOT_AFTER)
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
         .add_extension(x509.KeyUsage(digital_signature=not ca, content_commitment=False, key_encipherment=False,
                                      data_encipherment=False, key_agreement=False, key_cert_sign=ca,
                                      crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(subject_key.public_key()), critical=False)
         .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
                        critical=False))
    if eku:
        b = b.add_extension(x509.ExtendedKeyUsage([x509.ObjectIdentifier(eku)]), critical=False)
    return b.sign(issuer_key, hashes.SHA256()).public_bytes(Encoding.DER)


def _bits2int(b: bytes) -> int:
    return int.from_bytes(b, "big")  # SHA-256 and P-256 both have 256 bits


def rfc6979_k(x: int, h1: bytes) -> int:
    """RFC 6979 Section 3.2 with HMAC-SHA-256 for a 256-bit q."""
    q = P256_N
    xb = x.to_bytes(32, "big")
    hb = (_bits2int(h1) % q).to_bytes(32, "big")
    v, k = b"\x01" * 32, b"\x00" * 32
    k = hmac.new(k, v + b"\x00" + xb + hb, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    k = hmac.new(k, v + b"\x01" + xb + hb, hashlib.sha256).digest()
    v = hmac.new(k, v, hashlib.sha256).digest()
    while True:
        v = hmac.new(k, v, hashlib.sha256).digest()
        t = _bits2int(v)
        if 1 <= t < q:
            return t
        k = hmac.new(k, v + b"\x00", hashlib.sha256).digest()
        v = hmac.new(k, v, hashlib.sha256).digest()


def es256_sign(key, message: bytes) -> bytes:
    """ECDSA P-256 with SHA-256 and the RFC 6979 nonce; returns r || s, 32 bytes each (RFC 9053 Section 2.1)."""
    x = key.private_numbers().private_value
    h = hashlib.sha256(message).digest()
    k = rfc6979_k(x, h)
    r = ec.derive_private_key(k, ec.SECP256R1()).public_key().public_numbers().x % P256_N
    s = pow(k, -1, P256_N) * (_bits2int(h) + r * x) % P256_N
    if r == 0 or s == 0:
        raise SystemExit("degenerate signature")
    key.public_key().verify(encode_dss_signature(r, s), message, ec.ECDSA(hashes.SHA256()))
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def self_test():
    """RFC 6979 Appendix A.2.5, P-256 with SHA-256, message "sample"."""
    x = 0xC9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721
    key = ec.derive_private_key(x, ec.SECP256R1())
    k = rfc6979_k(x, hashlib.sha256(b"sample").digest())
    sig = es256_sign(key, b"sample")
    return (k == 0xA6E3C57DD01ABE90086538398355DD4C3B17AA873382B0F24D6129493D8AAD60
            and sig.hex().upper() == "EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716"
                                     "F7CB1C942D657C41D436C7A1B6E29F65F3E900DBB9AFF4064DC4AB2F843ACDA8")
