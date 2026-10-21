#!/usr/bin/env python3
"""The shared vectors of `verify_statement_signature`, run by the Python and the Rust verifier.

WHAT IT WRITES. tests/fixtures/scitt_statement_signature/vectors.json: statements, relying-party keys
and the status and verdict each vector is built to produce. tests/test_scitt_statement_signature_parity.py
runs both verifiers over every vector, and tools/pb_verify_rs/crosscheck.py runs them in CI.

WHERE THE BYTES COME FROM.
- Real: signed statements a local scitt-ccf-ledger accepted (tools/scitt_ccf_external/differential_corpus
  and differential_corpus_round2, scitt-ccf-ledger 00101f76, CCF 7.0.17), with the signer each round
  recorded in its summary.json. The two rounds have two different ES256 signers.
- Synthetic: throwaway keys made here and never stored (EC P-256 and P-384, RSA 2048 with e 65537 and
  with e 3, RSA 1024, Ed25519), a self-signed certificate for each, and statements built byte by byte.

THE ORACLE. Every vector carries the status and verdict it is designed to produce, read from the
reader's rules (ADR 0009, `proofbundle.scitt_ccf`). The generator refuses to write the file unless the
Python verifier returns exactly that for every vector; the Rust verifier is then held to the same.

FORM. Certificates, keys and the real statements are stored once under `refs` and named by the
vectors. A statement or key is a list of parts: a hex string, `{"ref": name}`, or `{"zeros": n}`.

Usage:  PYTHONPATH=src python tools/scitt_ccf_external/statement_signature_vectors.py [--check]
"""
from __future__ import annotations

import argparse
import datetime
import json
import sys
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa, utils
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
from proofbundle import scitt_ccf as C  # noqa: E402
from proofbundle._cbor_prescan import encode_head  # noqa: E402

OUT = ROOT / "tests" / "fixtures" / "scitt_statement_signature" / "vectors.json"
HERE = Path(__file__).resolve().parent
ROUND1 = HERE / "differential_corpus"
ROUND2 = HERE / "differential_corpus_round2"

P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
TIME_MIN, TIME_MAX = -62135596800, 253402300799


def assemble(parts: list, refs: dict) -> bytes:
    out = b""
    for p in parts:
        if isinstance(p, str):
            out += bytes.fromhex(p)
        elif "ref" in p:
            out += bytes.fromhex(refs[p["ref"]])
        else:
            out += bytes(p["zeros"])
    return out


def bstr(b: bytes) -> bytes:
    return encode_head(2, len(b)) + b


def uint(n: int) -> bytes:
    return encode_head(0, n) if n >= 0 else encode_head(1, -1 - n)


def spki(key) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.DER,
                                         serialization.PublicFormat.SubjectPublicKeyInfo)


def certificate(key, sign_hash=True) -> bytes:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "pb")])
    start = datetime.datetime(2026, 9, 1, tzinfo=datetime.timezone.utc)
    builder = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
               .public_key(key.public_key()).serial_number(1)
               .not_valid_before(start).not_valid_after(start + datetime.timedelta(days=365)))
    return builder.sign(key, hashes.SHA256() if sign_hash else None).public_bytes(serialization.Encoding.DER)


class Builder:
    """Statements byte by byte, the relying-party keys and the refs they name."""

    def __init__(self):
        self.refs: dict = {}
        self.vectors: list = []
        self.keys = {
            "p256": ec.generate_private_key(ec.SECP256R1()),
            "p256_other": ec.generate_private_key(ec.SECP256R1()),
            "p384": ec.generate_private_key(ec.SECP384R1()),
            "rsa2048": rsa.generate_private_key(public_exponent=65537, key_size=2048),
            "rsa2048_e3": rsa.generate_private_key(public_exponent=3, key_size=2048),
            "rsa1024": rsa.generate_private_key(public_exponent=65537, key_size=1024),
            "ed25519": ed25519.Ed25519PrivateKey.generate(),
        }
        for name, key in self.keys.items():
            self.refs[f"cert_{name}"] = certificate(key, sign_hash=name != "ed25519").hex()
            self.refs[f"spki_{name}"] = spki(key).hex()
        point = self.keys["p256"].public_key().public_bytes(serialization.Encoding.X962,
                                                             serialization.PublicFormat.CompressedPoint)
        self.refs["spki_p256_compressed"] = (bytes.fromhex("3039301306072a8648ce3d020106082a8648ce3d030107032200")
                                             + point).hex()

    # -- signing ------------------------------------------------------------------------------------
    def sign(self, name: str, tbs: bytes, **kw) -> bytes:
        key = self.keys[name]
        if name.startswith("p256") or name == "p384":
            h, n = (hashes.SHA256(), 32) if name.startswith("p256") else (hashes.SHA384(), 48)
            r, s = utils.decode_dss_signature(key.sign(tbs, ec.ECDSA(h)))
            return r.to_bytes(n, "big") + s.to_bytes(n, "big")
        if name.startswith("rsa"):
            h = hashes.SHA384() if kw.get("ps384") else hashes.SHA256()
            salt = kw.get("salt", 48 if kw.get("ps384") else 32)
            return key.sign(tbs, padding.PSS(mgf=padding.MGF1(h), salt_length=salt), h)
        return key.sign(tbs)

    # -- headers ------------------------------------------------------------------------------------
    @staticmethod
    def cbor_map(pairs: list) -> bytes:
        return encode_head(5, len(pairs)) + b"".join(k + v for k, v in pairs)

    def protected(self, alg: bytes | None, x5chain: bytes | None, extra: list = ()) -> bytes:
        pairs = []
        if alg is not None:
            pairs.append((b"\x01", alg))
        pairs.append((uint(258), uint(-16)))
        if x5chain is not None:
            pairs.append((uint(33), x5chain))
        return self.cbor_map(pairs + list(extra))

    def leaf(self, name: str) -> bytes:
        return bstr(bytes.fromhex(self.refs[f"cert_{name}"]))

    # -- vectors ------------------------------------------------------------------------------------
    def add(self, vid, what, statement: bytes, keys: list, status, valid, *, origin="synthetic",
            parts: list | None = None):
        cert_parts = parts if parts is not None else self.compress(statement)
        self.vectors.append({"id": vid, "what": what, "origin": origin, "statement": cert_parts,
                             "keys": [[{"ref": k}] if not k.startswith("hex:") else [k[4:]] for k in keys],
                             "want": {"status": status, "valid": valid}})

    def compress(self, statement: bytes) -> list:
        """The statement as parts: each stored certificate it contains becomes a reference."""
        parts: list = []
        rest = statement
        names = sorted((n for n in self.refs if n.startswith("cert_")), key=lambda n: -len(self.refs[n]))
        while rest:
            hit = None
            for n in names:
                c = bytes.fromhex(self.refs[n])
                i = rest.find(c)
                if i >= 0 and (hit is None or i < hit[0]):
                    hit = (i, n, len(c))
            if hit is None:
                parts.append(rest.hex())
                break
            i, n, length = hit
            if i:
                parts.append(rest[:i].hex())
            parts.append({"ref": n})
            rest = rest[i + length:]
        return parts

    def statement(self, prot: bytes, *, unprot: bytes = b"\xa0", payload: bytes | None = b"\x11" * 32,
                  signer: str | None = "p256", sig: bytes | None = None, tag: bytes = b"\xd2", **kw) -> bytes:
        if sig is None:
            sig = self.sign(signer, C._sig_structure(prot, payload if payload is not None else b""), **kw)
        pay = bstr(payload) if payload is not None else b"\xf6"
        return tag + b"\x84" + bstr(prot) + unprot + pay + bstr(sig)


def real_vectors(b: Builder) -> None:
    s1 = json.loads((ROUND1 / "summary.json").read_text(encoding="utf-8"))["signer"]
    s2 = json.loads((ROUND2 / "summary.json").read_text(encoding="utf-8"))["signer"]
    b.refs["spki_round1_signer"] = s1["spki_hex"]
    b.refs["spki_round2_signer"] = s2["spki_hex"]
    real = (
        ("r01-round1-control", ROUND1, "control", "request.hex", ["spki_round1_signer"], "confirmed", True,
         "the round 1 control as the ledger accepted it, with the round 1 signer"),
        ("r02-round1-control-served", ROUND1, "control", "statement.hex", ["spki_round1_signer"], "confirmed", True,
         "the same statement as served, its receipt under label 394 in the unprotected header"),
        ("r03-round1-high-s-twin", ROUND1, "f03-high-s-twin", "request.hex", ["spki_round1_signer"], "confirmed", True,
         "a signature (r, n - s) the ledger accepted: ECDSA over P-256 does not require a low s"),
        ("r04-round1-indefinite", ROUND1, "b03-indefinite1", "request.hex", ["spki_round1_signer"], "malformed", None,
         "the ledger accepted an indefinite-length item; the reader refuses indefinite lengths"),
        ("r05-round2-control", ROUND2, "control", "request.hex", ["spki_round2_signer"], "confirmed", True,
         "the round 2 control with the round 2 signer, a different key from round 1"),
        ("r06-round2-keys-descending", ROUND2, "g01-keys-descending", "request.hex", ["spki_round2_signer"],
         "confirmed", True, "a protected header whose keys are not in core deterministic order; its bytes are signed"),
        ("r07-round2-alg-1-byte-argument", ROUND2, "g03-alg-1-byte-argument", "request.hex", ["spki_round2_signer"],
         "malformed", None, "the ledger accepted alg with a one-byte argument head; the reader refuses a head not "
         "in its shortest form"),
        ("r08-round1-control-round2-signer", ROUND1, "control", "request.hex", ["spki_round2_signer"],
         "needs_rp_trust", None, "the round 1 statement with only the round 2 signer's key"),
        ("r09-round1-control-both-signers", ROUND1, "control", "request.hex",
         ["spki_round2_signer", "spki_round1_signer"], "confirmed", True, "both signers' keys; the matching one decides"),
    )
    for vid, root, case, fname, keys, status, valid, what in real:
        ref = f"statement_{root.name}_{case}_{fname.split('.')[0]}"
        b.refs[ref] = (root / "vectors" / case / fname).read_text(encoding="ascii").strip()
        b.add(vid, what, b"", keys, status, valid, parts=[{"ref": ref}],
              origin=f"tools/scitt_ccf_external/{root.name}/vectors/{case}/{fname}")


def synthetic_vectors(b: Builder) -> None:
    es256 = b.protected(b"\x26", b.leaf("p256"))
    ok = b.statement(es256)
    add = b.add
    add("s01-es256", "ES256 over P-256, the key the protected x5chain names", ok, ["spki_p256"], "confirmed", True)
    flip = bytearray(ok)
    flip[-1] ^= 1
    add("s02-es256-bit-flip", "the last signature byte flipped", bytes(flip), ["spki_p256"],
        "statement_signature_invalid", False)
    sig = ok[-64:]
    r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    add("s03-es256-high-s", "the twin (r, n - s) of a valid signature", ok[:-64] + r.to_bytes(32, "big")
        + (P256_N - s).to_bytes(32, "big"), ["spki_p256"], "confirmed", True)
    add("s04-es256-r-zero", "r is zero", ok[:-64] + bytes(32) + sig[32:], ["spki_p256"],
        "statement_signature_invalid", False)
    add("s05-es256-63-bytes", "a signature of 63 bytes", ok[:-66] + bstr(sig[:63]), ["spki_p256"],
        "statement_signature_invalid", False)
    add("s06-es256-empty-signature", "an empty signature", ok[:-66] + b"\x40", ["spki_p256"],
        "statement_signature_invalid", False)
    es384 = b.protected(b"\x38\x22", b.leaf("p384"))
    ok384 = b.statement(es384, signer="p384")
    add("s07-es384", "ES384 over P-384", ok384, ["spki_p384"], "confirmed", True)
    flip = bytearray(ok384)
    flip[-1] ^= 1
    add("s08-es384-bit-flip", "the last signature byte flipped", bytes(flip), ["spki_p384"],
        "statement_signature_invalid", False)
    ps256 = b.protected(b"\x38\x24", b.leaf("rsa2048"))
    okps = b.statement(ps256, signer="rsa2048")
    add("s09-ps256", "PS256 with RSA 2048", okps, ["spki_rsa2048"], "confirmed", True)
    flip = bytearray(okps)
    flip[-1] ^= 1
    add("s10-ps256-bit-flip", "the last signature byte flipped", bytes(flip), ["spki_rsa2048"],
        "statement_signature_invalid", False)
    ps384 = b.protected(b"\x38\x25", b.leaf("rsa2048"))
    add("s11-ps384", "PS384 with RSA 2048", b.statement(ps384, signer="rsa2048", ps384=True),
        ["spki_rsa2048"], "confirmed", True)
    for attempt in range(4096):
        payload = attempt.to_bytes(2, "big") * 16
        tbs = C._sig_structure(ps256, payload)
        sig = b.sign("rsa2048", tbs)
        if sig[0] == 0:
            break
    else:
        raise SystemExit("no PS256 signature with a leading zero byte in 4096 attempts")
    add("s12-ps256-short-signature", "a valid signature whose leading zero byte is left out (255 bytes)",
        b.statement(ps256, payload=payload, sig=sig[1:]), ["spki_rsa2048"], "confirmed", True)
    add("s13-ps256-long-signature", "a valid signature with a zero byte put in front (257 bytes)",
        b.statement(ps256, payload=payload, sig=b"\x00" + sig), ["spki_rsa2048"],
        "statement_signature_invalid", False)
    n = b.keys["rsa2048"].public_key().public_numbers().n
    for attempt in range(4096):
        payload = (attempt + 1).to_bytes(2, "big") * 16
        sig = b.sign("rsa2048", C._sig_structure(ps256, payload))
        if int.from_bytes(sig, "big") + n < 1 << 2048:
            break
    else:
        raise SystemExit("no PS256 signature s with s + n below 2^2048 in 4096 attempts")
    add("s14-ps256-signature-plus-n", "s + n for a valid s, still 256 bytes: not a number below n",
        b.statement(ps256, payload=payload, sig=(int.from_bytes(sig, "big") + n).to_bytes(256, "big")),
        ["spki_rsa2048"], "statement_signature_invalid", False)
    add("s15-ps256-salt-20", "PS256 signed with a 20-byte salt; the profile's salt is 32",
        b.statement(ps256, signer="rsa2048", salt=20), ["spki_rsa2048"], "statement_signature_invalid", False)
    ps1024 = b.protected(b"\x38\x24", b.leaf("rsa1024"))
    add("s16-ps256-rsa-1024", "PS256 with RSA 1024, below the 2048 bits the profile takes",
        b.statement(ps1024, signer="rsa1024"), ["spki_rsa1024"], "statement_signature_invalid", False)
    pse3 = b.protected(b"\x38\x24", b.leaf("rsa2048_e3"))
    add("s17-ps256-exponent-3", "PS256 with RSA 2048 and public exponent 3",
        b.statement(pse3, signer="rsa2048_e3"), ["spki_rsa2048_e3"], "confirmed", True)
    wrong = b.protected(b"\x38\x22", b.leaf("p256"))
    add("s18-alg-es384-p256-key", "alg ES384 over a P-256 key: the algorithm names another curve",
        b.statement(wrong, sig=b.sign("p256", C._sig_structure(wrong, b"\x11" * 32))), ["spki_p256"],
        "statement_signature_invalid", False)
    eddsa = b.protected(b"\x27", b.leaf("p256"))
    add("s19-alg-eddsa", "alg EdDSA (-8), which v1 does not verify with", b.statement(eddsa), ["spki_p256"],
        "statement_signature_invalid", False)
    text = b.protected(b"\x65ES256", b.leaf("p256"))
    add("s20-alg-text", "alg as the text ES256", b.statement(text), ["spki_p256"],
        "statement_signature_invalid", False)
    absent = b.protected(None, b.leaf("p256"))
    add("s21-alg-absent", "no alg in the protected header", b.statement(absent), ["spki_p256"],
        "statement_signature_invalid", False)
    add("s22-alg-unprotected", "alg in the unprotected header only", b.statement(absent, unprot=b"\xa1\x01\x26"),
        ["spki_p256"], "statement_signature_invalid", False)
    add("s23-untagged", "a COSE_Sign1 without tag 18", b.statement(es256, tag=b""), ["spki_p256"],
        "confirmed", True)
    add("s24-payload-5-bytes", "a payload of 5 bytes; the signature check does not read its length",
        b.statement(es256, payload=b"\x22" * 5), ["spki_p256"], "confirmed", True)
    add("s25-payload-detached", "a detached payload (nil)", b.statement(es256, payload=None), ["spki_p256"],
        "outside_profile", None)
    nox5 = b.protected(b"\x26", None)
    add("s26-no-x5chain", "no x5chain", b.statement(nox5), ["spki_p256"], "outside_profile", None)
    add("s27-x5chain-unprotected", "the x5chain in the unprotected header only",
        b.statement(nox5, unprot=b"\xa1\x18\x21" + b.leaf("p256")), ["spki_p256"], "outside_profile", None)
    two = b.protected(b"\x26", b"\x82" + b.leaf("p256") + b.leaf("p384"))
    add("s28-x5chain-array", "an x5chain array of two certificates; the first is the end-entity one",
        b.statement(two), ["spki_p256"], "confirmed", True)
    add("s29-x5chain-array-of-one", "an x5chain array of one certificate",
        b.statement(b.protected(b"\x26", b"\x81" + b.leaf("p256"))), ["spki_p256"], "malformed", None)
    add("s30-x5chain-array-with-int", "an x5chain array whose second member is an integer",
        b.statement(b.protected(b"\x26", b"\x82" + b.leaf("p256") + b"\x01")), ["spki_p256"], "malformed", None)
    add("s31-x5chain-int", "an x5chain that is an integer", b.statement(b.protected(b"\x26", b"\x01")),
        ["spki_p256"], "malformed", None)
    add("s32-x5chain-not-der", "an x5chain byte string that is not DER X.509",
        b.statement(b.protected(b"\x26", bstr(b"not a certificate"))), ["spki_p256"], "malformed", None)
    trailing = bstr(bytes.fromhex(b.refs["cert_p256"]) + b"\x00")
    add("s33-x5chain-trailing-byte", "the certificate followed by one byte",
        b.statement(b.protected(b"\x26", trailing)), ["spki_p256"], "malformed", None)
    ed = b.protected(b"\x27", b.leaf("ed25519"))
    add("s34-leaf-ed25519", "an Ed25519 end-entity key and the same key as the relying party's: v1 does not "
        "verify with Ed25519, so the key is not trust", b.statement(ed, signer="ed25519"), ["spki_ed25519"],
        "needs_rp_trust", None)
    add("s35-leaf-ed25519-p256-key", "an Ed25519 end-entity key and a P-256 relying-party key",
        b.statement(ed, signer="ed25519"), ["spki_p256"], "needs_rp_trust", None)
    # relying-party keys
    add("k01-compressed-point", "the relying-party key as a compressed P-256 point: the same key", ok,
        ["spki_p256_compressed"], "confirmed", True)
    add("k02-no-key", "no relying-party key", ok, [], "needs_rp_trust", None)
    add("k03-other-key", "another P-256 key", ok, ["spki_p256_other"], "needs_rp_trust", None)
    add("k04-garbage-then-key", "a key that is not DER first, then the matching key", ok,
        ["hex:00ff", "spki_p256"], "confirmed", True)
    add("k05-match-at-64", "63 other keys, then the matching one: the 64th key is read", ok,
        ["spki_p256_other"] * 63 + ["spki_p256"], "confirmed", True)
    add("k06-match-at-65", "64 other keys, then the matching one: keys beyond 64 are ignored", ok,
        ["spki_p256_other"] * 64 + ["spki_p256"], "needs_rp_trust", None)
    add("k07-rsa-key-for-ec-leaf", "an RSA relying-party key for a P-256 end-entity key", ok, ["spki_rsa2048"],
        "needs_rp_trust", None)


def reader_vectors(b: Builder) -> None:
    add = b.add
    es256 = b.protected(b"\x26", b.leaf("p256"))
    ok = b.statement(es256)
    keys = ["spki_p256"]
    add("c01-trailing-byte", "one byte after the data item", ok + b"\x00", keys, "malformed", None)
    body = ok[1:]
    wide = b"\xd2\x84" + bstr(es256) + b"\xa0" + b"\x59\x00\x20" + b"\x11" * 32 + body[-66:]
    add("c02-payload-head-not-shortest", "the payload's length in a two-byte head", wide, keys, "malformed", None)
    add("c03-indefinite-unprotected", "an indefinite-length unprotected map",
        b.statement(es256, unprot=b"\xbf\xff"), keys, "malformed", None)
    add("c04-float", "a float in the unprotected header",
        b.statement(es256, unprot=b"\xa1\x18\x63\xf9\x3e\x00"), keys, "malformed", None)
    add("c05-undefined", "undefined in the unprotected header",
        b.statement(es256, unprot=b"\xa1\x18\x63\xf7"), keys, "malformed", None)
    add("c06-simple-value-16", "the simple value 16 in the unprotected header",
        b.statement(es256, unprot=b"\xa1\x18\x63\xf0"), keys, "malformed", None)
    add("c07-duplicate-key", "a key twice in the unprotected map",
        b.statement(es256, unprot=b"\xa2\x18\x63\x01\x18\x63\x02"), keys, "malformed", None)
    add("c08-text-key-not-utf8", "a text key that is not UTF-8",
        b.statement(es256, unprot=b"\xa1\x62\xc3\x28\x01"), keys, "malformed", None)
    add("c09-bool-map-key", "a map key that is true", b.statement(es256, unprot=b"\xa1\xf5\x01"), keys,
        "malformed", None)
    add("c10-tag-17", "tag 17 at the root", b"\xd1" + ok[1:], keys, "malformed", None)
    add("c11-tag-18-around-map", "tag 18 around a map", b"\xd2\xa0", keys, "malformed", None)
    add("c12-bignum-tag", "tag 2 in the unprotected header",
        b.statement(es256, unprot=b"\xa1\x18\x63\xc2\x41\x01"), keys, "malformed", None)
    nest = 13
    add("c13-depth-16", "an item at nesting depth 16", b.statement(es256, unprot=b"\xa1\x18\x63" + b"\x81" * nest + b"\x01"),
        keys, "confirmed", True)
    add("c14-depth-17", "an item at nesting depth 17",
        b.statement(es256, unprot=b"\xa1\x18\x63" + b"\x81" * (nest + 1) + b"\x01"), keys, "malformed", None)
    add("c15-protected-empty", "an empty protected header byte string",
        b"\xd2\x84\x40\xa0" + bstr(b"\x11" * 32) + bstr(ok[-64:]), keys, "malformed", None)
    add("c16-protected-array", "a protected header that is an array", b.statement(b"\x80"), keys, "malformed", None)
    add("c17-label-both-buckets", "kid in both header buckets",
        b.statement(b.protected(b"\x26", b.leaf("p256"), [(b"\x04", b"\x41\x01")]), unprot=b"\xa1\x04\x41\x01"),
        keys, "malformed", None)
    add("c18-three-elements", "a COSE_Sign1 of three elements", b"\xd2\x83" + bstr(es256) + b"\xa0" + bstr(b"\x11" * 32),
        keys, "malformed", None)
    add("c19-signature-text", "a signature that is a text string", ok[:-66] + b"\x78\x40" + b"a" * 64, keys,
        "malformed", None)
    add("c20-payload-int", "a payload that is an integer",
        b"\xd2\x84" + bstr(es256) + b"\xa0" + b"\x01" + bstr(ok[-64:]), keys, "malformed", None)
    add("c21-unprotected-array", "an unprotected header that is an array", b.statement(es256, unprot=b"\x80"), keys,
        "malformed", None)
    # the size limit: exactly 65536 bytes is read, one more is not
    filler_at = len(b"\xd2\x84" + bstr(es256))
    base = len(b.statement(es256, unprot=b"\xa1\x18\x63\x59\x01\x00"))   # a filler with a two-byte length head
    for vid, total, status, valid in (("c22-65536-bytes", 65536, "confirmed", True),
                                      ("c23-65537-bytes", 65537, "malformed", None)):
        fill = total - base
        unprot = b"\xa1\x18\x63" + encode_head(2, fill)
        assert len(unprot) == 6, "the filler's length must take the two-byte head"
        st = b.statement(es256, unprot=unprot + bytes(fill))
        assert len(st) == total
        head = st[:filler_at + len(unprot)]
        tail = st[filler_at + len(unprot) + fill:]
        add(vid, f"a statement of {total} bytes; the limit is {C.MAX_STATEMENT_BYTES}", b"", keys, status, valid,
            parts=b.compress(head) + [{"zeros": fill}] + b.compress(tail))
    # header types (RFC 9052, RFC 9597, RFC 9995), each in the unprotected header
    for vid, what, pair in (
            ("h01-kid-text", "kid as a text string", b"\x04\x61a"),
            ("h02-crit-empty", "an empty crit", b"\x02\x80"),
            ("h03-crit-bool", "a crit whose member is true", b"\x02\x81\xf5"),
            ("h04-cty-negative", "a content type that is a negative integer", b"\x03\x20"),
            ("h05-cwt-array", "CWT claims as an array", b"\x0f\x80"),
            ("h06-258-text", "label 258 as text", b"\x19\x01\x02\x61a"),
            ("h07-259-negative", "label 259 as a negative integer", b"\x19\x01\x03\x20"),
            ("h08-260-bytes", "label 260 as a byte string", b"\x19\x01\x04\x41\x01"),
            ("h09-alg-bytes", "alg as a byte string", b"\x01\x41\x01")):
        prot = es256 if not vid.startswith("h09") else b.protected(None, b.leaf("p256"))
        add(vid, what, b.statement(prot, unprot=b"\xa1" + pair), keys, "malformed", None)
    # tag 1 around a CWT time claim of the protected header (owner decision Q8 a)
    for vid, what, claim, value, status, valid in (
            ("t01-tag1-iat", "tag 1 around the CWT iat", 6, 1790000000, "confirmed", True),
            ("t02-tag1-min", "tag 1 at the first second of year 1", 4, TIME_MIN, "confirmed", True),
            ("t03-tag1-below-min", "tag 1 one second before year 1", 4, TIME_MIN - 1, "malformed", None),
            ("t04-tag1-max", "tag 1 at the last second of year 9999", 5, TIME_MAX, "confirmed", True),
            ("t05-tag1-above-max", "tag 1 one second after year 9999", 5, TIME_MAX + 1, "malformed", None),
            ("t06-tag1-claim-1", "tag 1 around CWT claim 1 (issuer)", 1, 0, "malformed", None)):
        cwt = (b"\x0f", b"\xa1" + uint(claim) + b"\xc1" + uint(value))
        add(vid, what, b.statement(b.protected(b"\x26", b.leaf("p256"), [cwt])), keys, status, valid)
    add("t07-tag1-text", "tag 1 around a text string",
        b.statement(b.protected(b"\x26", b.leaf("p256"), [(b"\x0f", b"\xa1\x06\xc1\x61a")])), keys, "malformed", None)
    add("t08-tag1-unprotected", "tag 1 in the unprotected CWT claims",
        b.statement(es256, unprot=b"\xa1\x0f\xa1\x06\xc1\x00"), keys, "malformed", None)


def build() -> dict:
    b = Builder()
    real_vectors(b)
    synthetic_vectors(b)
    reader_vectors(b)
    return {
        "schema": "proofbundle.scitt_statement_signature_vectors.v1",
        "surface": "proofbundle.scitt_ccf.verify_statement_signature",
        "rust_subcommand": "verify-scitt-statement-signature",
        "generated_by": "tools/scitt_ccf_external/statement_signature_vectors.py",
        "oracle": ("each vector's want is the status and verdict it is built to produce under the reader's "
                   "rules (ADR 0009); the generator wrote the file only after the Python verifier returned "
                   "exactly that for every vector"),
        "refs": b.refs,
        "vectors": b.vectors,
    }


def python_verdict(doc: dict, v: dict) -> tuple:
    data = assemble(v["statement"], doc["refs"])
    keys = [assemble(k, doc["refs"]) for k in v["keys"]]
    return C.verify_statement_signature(data, statement_keys=keys)


def check(doc: dict) -> list:
    bad = []
    for v in doc["vectors"]:
        got = python_verdict(doc, v)
        want = (v["want"]["status"], v["want"]["valid"])
        if got != want:
            bad.append(f"{v['id']}: Python {got}, built for {want}")
    return bad


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--check", action="store_true", help="hold the stored vectors to the Python verifier")
    a = ap.parse_args(argv)
    if a.check:
        doc = json.loads(OUT.read_text(encoding="utf-8"))
    else:
        doc = build()
    bad = check(doc)
    for line in bad:
        print("MISMATCH", line)
    if bad:
        return 1
    if not a.check:
        OUT.parent.mkdir(parents=True, exist_ok=True)
        OUT.write_text(json.dumps(doc, indent=1) + "\n", encoding="utf-8")
    print(f"{len(doc['vectors'])} vectors, Python gives every built verdict; "
          f"{OUT.relative_to(ROOT)}: {OUT.stat().st_size if OUT.exists() else 0} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
