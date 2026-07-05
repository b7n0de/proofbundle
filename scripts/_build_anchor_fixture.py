#!/usr/bin/env python3
"""One-off: build the committed RFC 3161 anchor fixture from a captured FreeTSA token + its public
CA/TSA certs. Stores everything as base64 DER inside a single JSON (the anchor `frozen` format) so no
PEM/CRT files are committed. Re-run only to refresh the fixture. NOT part of the test suite."""
import base64
import hashlib
import json
import sys

from cryptography import x509
from cryptography.hazmat.primitives.serialization import Encoding

CAP = sys.argv[1]      # scratchpad capture dir
OUT = sys.argv[2]      # tests/fixtures/anchors/freetsa_receipt_anchor.json

# the exact canonical root that was timestamped
ROOT = hashlib.sha256(b"proofbundle-anchor-test-canonical-root").digest()

token = open(f"{CAP}/freetsa.tsr", "rb").read()
cacert = x509.load_pem_x509_certificate(open(f"{CAP}/freetsa_cacert.pem", "rb").read())
tsacert = x509.load_pem_x509_certificate(open(f"{CAP}/freetsa_tsa.crt", "rb").read())


def b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


anchor = {
    "type": "rfc3161-tsa",
    "target": "receipt",
    "canonicalRoot": b64(ROOT),
    "proof": b64(token),
    "anchoredAt": "2026-07-05T00:00:00Z",
    "frozen": {
        "tsa": "freetsa",
        "rootCertsDerB64": [b64(cacert.public_bytes(Encoding.DER))],
        "tsaCertDerB64": b64(tsacert.public_bytes(Encoding.DER)),
    },
}
with open(OUT, "w") as f:
    json.dump(anchor, f, indent=2)
    f.write("\n")
print("wrote", OUT)
