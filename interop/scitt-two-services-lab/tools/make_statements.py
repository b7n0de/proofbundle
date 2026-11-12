#!/usr/bin/env python3
"""Test statements for the two-services lab.

Usage: python -I -B make_statements.py <folder interop/scitt-statement-identification-03> <out folder>

Two sets, both only from the folder at 30c93494 and from test keys with fixed seeds:

R  the candidates of the 14 cases, byte for byte as in the case files. Equal bytes are submitted once.
D  derived from base statements 01, 02 and 03 so that the ledger can accept them: same payload and content type,
   CWT Claims with the sub of the base statement and a did:x509 issuer of a test CA, x5chain [leaf, root] in the
   protected header, no kid, empty unprotected header, tag 18. Signed again with the leaf key.
   D6 is the bytes of D1 with one entry in the unprotected header, not signed again (as C5).

For each statement statements.json gives the reference of Section 6 of -03 computed from the submitted bytes
(ToBeSigned, alg -16, external_aad empty), with check_cases.py of the folder. The Ed25519 signatures and the
certificates are deterministic, the ES256 signature of D1 is not: a second run writes other D1 bytes.
"""
import base64
import datetime
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

FOLDER = Path(sys.argv[1])
OUT = Path(sys.argv[2])
OUT.mkdir(parents=True, exist_ok=False)
sys.dont_write_bytecode = True
_spec = importlib.util.spec_from_file_location("cc", FOLDER / "check_cases.py")
cc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cc)

SEED = b"b7lab DELTA-SCITT-INTEROP-LABOR-20261112-01 "
EKU = "1.3.6.1.5.5.7.3.3"  # codeSigning, in the leaf and in the did:x509 issuer


# --- CBOR, only what is needed here, in the preferred encoding
def head(major, n):
    if n < 24:
        return bytes([major << 5 | n])
    for extra, width in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if n < 1 << (8 * width):
            return bytes([major << 5 | extra]) + n.to_bytes(width, "big")
    raise ValueError(n)


def integer(n):
    return head(0, n) if n >= 0 else head(1, -1 - n)


def bstr(b):
    return head(2, len(b)) + b


def tstr(s):
    b = s.encode("utf-8")
    return head(3, len(b)) + b


def cbor_map(pairs):
    """pairs: [(encoded key, encoded value)], ordered by the key bytes (RFC 8949 Section 4.2.1)."""
    pairs = sorted(pairs, key=lambda p: p[0])
    return head(5, len(pairs)) + b"".join(k + v for k, v in pairs)


def array(items):
    return head(4, len(items)) + b"".join(items)


# --- keys and certificates
def ed_key(name):
    return ed25519.Ed25519PrivateKey.from_private_bytes(hashlib.sha256(SEED + name.encode()).digest())


def p256_key(name):
    n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    d = int.from_bytes(hashlib.sha256(SEED + name.encode()).digest(), "big") % (n - 1) + 1
    return ec.derive_private_key(d, ec.SECP256R1())


NOT_BEFORE = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
NOT_AFTER = datetime.datetime(2036, 1, 1, tzinfo=datetime.timezone.utc)


def certificate(subject, key, issuer_name, issuer_key, serial, ca):
    b = (x509.CertificateBuilder()
         .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)]))
         .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_name)]))
         .public_key(key.public_key()).serial_number(serial)
         .not_valid_before(NOT_BEFORE).not_valid_after(NOT_AFTER)
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
         .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
                        critical=False))
    if ca:
        b = b.add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False, key_encipherment=False,
                                          data_encipherment=False, key_agreement=False, key_cert_sign=True,
                                          crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
    else:
        b = b.add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                                          data_encipherment=False, key_agreement=False, key_cert_sign=False,
                                          crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
        b = b.add_extension(x509.ExtendedKeyUsage([x509.ObjectIdentifier(EKU)]), critical=False)
    return b.sign(issuer_key, None).public_bytes(serialization.Encoding.DER)


CA_NAME = "b7lab interop test root"
ca_key = ed_key("root")
ca_der = certificate(CA_NAME, ca_key, CA_NAME, ca_key, 1, True)
leaves = {"ed25519": ed_key("leaf-ed25519"), "p256": p256_key("leaf-p256")}
leaves = {k: (key, certificate("b7lab interop test leaf " + k, key, CA_NAME, ca_key, 2 + i, False))
          for i, (k, key) in enumerate(sorted(leaves.items()))}
DID = "did:x509:0:sha256:%s::eku:%s" % (
    base64.urlsafe_b64encode(hashlib.sha256(ca_der).digest()).decode().rstrip("="), EKU)
assert ExtendedKeyUsageOID.CODE_SIGNING.dotted_string == EKU


# --- statements
def reference_of(raw):
    """Reference of -03 Section 6 from the bytes as check_cases.py reads them; None if not a statement."""
    read = cc.read_candidate(raw)
    if read is None:
        return None
    _tag, protected, payload, _sig = read
    if payload is None:
        return {"tbs_sha256": None, "reason": "payload absent and not supplied"}
    tbs = cc.to_be_signed(protected, b"", payload)
    return {"tbs_sha256": hashlib.sha256(tbs).hexdigest()}


def sign(alg, key, protected, payload):
    sig_structure = array([tstr("Signature1"), bstr(protected), bstr(b""), bstr(payload)])
    if alg in (-8, -19):
        return key.sign(sig_structure)
    r, s = decode_dss_signature(key.sign(sig_structure, ec.ECDSA(hashes.SHA256())))
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def raw_value(protected_bytes, item):
    return protected_bytes[item.start:item.end]


base = json.loads((FOLDER / "base_statements.json").read_text(encoding="utf-8"))["statements"]


def derived(sid, alg, leaf):
    raw = base64.b64decode(base[sid]["bytes"]["base64"])
    _tag, protected, payload, _sig = cc.read_candidate(raw)
    old = {k.value: v for k, v in cc.decode_one(protected).value}
    cwt = {k.value: v for k, v in old[15].value}
    pairs = [(integer(1), integer(alg)), (integer(3), raw_value(protected, old[3])),
             (integer(15), cbor_map([(integer(1), tstr(DID)), (integer(2), raw_value(protected, cwt[2]))])),
             (integer(33), array([bstr(leaves[leaf][1]), bstr(ca_der)]))]
    if -70001 in old:
        pairs.append((integer(-70001), raw_value(protected, old[-70001])))
    new_protected = cbor_map(pairs)
    sig = sign(alg, leaves[leaf][0], new_protected, payload)
    return bytes([0xD2]) + array([bstr(new_protected), cbor_map([]), bstr(payload), bstr(sig)])


statements = {}
# R: the 14 candidates
for path in sorted((FOLDER / "cases").glob("C*.json"), key=lambda p: int(p.stem[1:])):
    case = json.loads(path.read_text(encoding="utf-8"))
    raw = base64.b64decode(case["inputs"]["candidate"]["base64"])
    sha = hashlib.sha256(raw).hexdigest()
    same = next((n for n, s in statements.items() if s["sha256"] == sha), None)
    if same:
        statements[same]["cases"].append(case["id"])
        continue
    statements["R_" + case["id"]] = {"set": "R", "cases": [case["id"]], "bytes": raw, "sha256": sha}
# D: derived
for name, sid, alg, leaf in (("D1", "01", -7, "p256"), ("D2", "02", -8, "ed25519"), ("D3", "03", -8, "ed25519"),
                             ("D4", "01", -8, "ed25519"), ("D5", "01", -19, "ed25519")):
    raw = derived(sid, alg, leaf)
    statements[name] = {"set": "D", "base_statement": sid, "alg": alg, "leaf": leaf, "bytes": raw,
                        "sha256": hashlib.sha256(raw).hexdigest()}
d1 = statements["D1"]["bytes"]
unprotected = cc.decode_one(d1).value.value[1]
assert d1[unprotected.start:unprotected.end] == b"\xa0"
d6 = d1[:unprotected.start] + cbor_map([(integer(-65537), tstr("b7lab"))]) + d1[unprotected.end:]
statements["D6"] = {"set": "D", "base_statement": "01", "alg": -7, "leaf": "p256",
                    "change": "D1 with one entry in the unprotected header, not signed again", "bytes": d6,
                    "sha256": hashlib.sha256(d6).hexdigest()}

for name, s in statements.items():
    (OUT / (name + ".cbor")).write_bytes(s["bytes"])
    s["length"] = len(s["bytes"])
    s["reference_submitted"] = reference_of(s["bytes"])
    s["sha256_whole"] = s.pop("sha256")
    del s["bytes"]
(OUT / "test_ca_root.der").write_bytes(ca_der)
for leaf, (_key, der) in leaves.items():
    (OUT / ("test_leaf_%s.der" % leaf)).write_bytes(der)
(OUT / "statements.json").write_text(json.dumps({"did_x509_issuer": DID, "eku": EKU, "seed_prefix": SEED.decode(),
                                                 "statements": statements}, indent=1, sort_keys=True) + "\n",
                                     encoding="utf-8")
for name, s in statements.items():
    ref = s["reference_submitted"]
    print(name, s["set"], s.get("cases", ""), s.get("alg", ""), s["length"], s["sha256_whole"][:16],
          "not a statement" if ref is None else (ref.get("tbs_sha256") or "no ToBeSigned")[:16])
print("issuer", DID)
