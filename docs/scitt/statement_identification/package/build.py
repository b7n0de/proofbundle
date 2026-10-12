#!/usr/bin/env python3
"""How the files of this package were made. Needs cbor2 and cryptography.

Running this again makes two new Ed25519 key pairs and therefore new signatures, key identifiers and digests in
references.json; what is derived from fixed inputs only (the artifact digest in the payloads, the audit text, the
times and the subject) stays the same. The committed files are one run of it. It generates the keys in memory and writes the two public
keys only.

Usage: python3 build.py   (writes into the directory this file is in)
"""
import datetime
import hashlib
import json
from pathlib import Path

import cbor2
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HERE = Path(__file__).resolve().parent
ALG, CONTENT_TYPE, KID, CWT_CLAIMS = 1, 3, 4, 15  # COSE header parameter labels
ISS, SUB, IAT = 1, 2, 6  # CWT claim keys
EDDSA, SHA256 = -8, -16  # COSE algorithm identifiers
REF = -70001  # a private-use header label (less than -65536); this package proposes no label
SUBJECT = "pkg:generic/example-widget@1.0.0"


def spki(key) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.DER,
                                         serialization.PublicFormat.SubjectPublicKeyInfo)


def when(iso: str) -> int:
    return int(datetime.datetime.fromisoformat(iso).replace(tzinfo=datetime.timezone.utc).timestamp())


def to_be_signed(protected: bytes, payload: bytes) -> bytes:
    """RFC 9052 sections 4.4 and 9: the Sig_structure of a COSE_Sign1, external_aad empty."""
    return cbor2.dumps(["Signature1", protected, b"", payload])


def sign1(key, iss: str, iat: int, content_type: str, payload: bytes, refs: list) -> bytes:
    header = {ALG: EDDSA, CONTENT_TYPE: content_type, KID: hashlib.sha256(spki(key)).digest(),
              CWT_CLAIMS: {ISS: iss, SUB: SUBJECT, IAT: iat}}
    if refs:
        header[REF] = refs
    protected = cbor2.dumps(header)
    signature = key.sign(to_be_signed(protected, payload))
    return cbor2.dumps(cbor2.CBORTag(18, [protected, {}, payload, signature]))


def write_hex(name: str, data: bytes) -> None:
    text = data.hex()
    (HERE / name).write_text("\n".join(text[i:i + 64] for i in range(0, len(text), 64)) + "\n",
                             encoding="ascii")


def main() -> None:
    keys = {"issuer": Ed25519PrivateKey.generate(), "auditor": Ed25519PrivateKey.generate()}
    for name, key in keys.items():
        (HERE / f"{name}.pub.pem").write_bytes(key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
    artifact_digest = hashlib.sha256(b"example-widget-1.0.0.tar.gz, example bytes\n").hexdigest()

    def json_bytes(obj) -> bytes:
        return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")

    original = sign1(keys["issuer"], "https://issuer.example", when("2026-09-20T10:00:00"), "application/json",
                     json_bytes({"artifact": "example-widget-1.0.0.tar.gz", "sha256": artifact_digest,
                                 "license": "MIT"}), [])
    original_tbs = to_be_signed(*[cbor2.loads(original).value[i] for i in (0, 2)])
    reference = [SHA256, "ToBeSigned", hashlib.sha256(original_tbs).digest()]
    audit = sign1(keys["auditor"], "https://auditor.example", when("2026-09-22T14:30:00"), "text/plain",
                  b"The artifact digest in the referenced statement was recomputed from the released "
                  b"artifact and matches. This audit covers the referenced bytes only.\n", [reference])
    correction = sign1(keys["issuer"], "https://issuer.example", when("2026-09-25T09:15:00"), "application/json",
                       json_bytes({"artifact": "example-widget-1.0.0.tar.gz", "sha256": artifact_digest,
                                   "license": "Apache-2.0",
                                   "note": "The license in the referenced statement was wrong."}), [reference])

    files = {"01-original.cose.hex": (original, "issuer"), "02-audit.cose.hex": (audit, "auditor"),
             "03-correction.cose.hex": (correction, "issuer")}
    statements = {}
    for name, (raw, signer) in files.items():
        write_hex(name, raw)
        item = cbor2.loads(raw).value
        claims = cbor2.loads(item[0])[CWT_CLAIMS]
        statements[name] = {
            "public_key": f"{signer}.pub.pem", "iss": claims[ISS], "sub": claims[SUB],
            "sha256_to_be_signed": hashlib.sha256(to_be_signed(item[0], item[2])).hexdigest(),
            "sha256_cose_sign1": hashlib.sha256(raw).hexdigest(), "size_bytes": len(raw)}
    why = ("ToBeSigned excludes the signature, the unprotected header and the outer wrapper, so changes "
           "confined to those parts preserve it; it does not normalize the bytes inside the protected header "
           "or the payload. It names this class of signed inputs, not a particular signature instance. "
           "Matching it does not establish signature validity, payload truth, issuer trust or registration. "
           "A digest of the whole COSE_Sign1 bytes changes with any of those excluded parts.")
    covered = ("the Sig_structure [\"Signature1\", body_protected, external_aad, payload] of the referenced "
               "COSE_Sign1, encoded as RFC 9052 sections 4.4 and 9 specify; the protected value is the original "
               "byte-string contents; external_aad is the empty byte string and the payload is embedded")
    references = [{"from": src, "location": f"protected header, label {REF}, entry 0", "to": "01-original.cose.hex",
                   "digest_algorithm": "SHA-256 (COSE algorithm -16)", "covers": "ToBeSigned",
                   "covered_bytes": covered, "why_these_bytes": why, "digest": reference[2].hex()}
                  for src in ("02-audit.cose.hex", "03-correction.cose.hex")]
    doc = {"package": "SCITT statement identification: three signed statements and the references between them",
           "reference_format": f"a protected header parameter, private-use label {REF}, holding an array of "
                               "[digest algorithm (COSE algorithm identifier), covered bytes (text), digest (bstr)]",
           "statements": statements, "references": references}
    (HERE / "references.json").write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
