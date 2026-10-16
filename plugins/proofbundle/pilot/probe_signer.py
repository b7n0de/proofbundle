#!/usr/bin/env python3
"""A signer for the pilot's PROBES only (Z405, DECISIONS.md D55), never the signer of the pilot.

The gate holds no key. It hands the DSSE pre-authentication bytes of a decision receipt to the signer the operator
names in pilot.json, which writes the 64-byte Ed25519 signature in base64 on stdout. In the pilot that signer is the
operator's, and its key is out of reach of the agent session (RUNBOOK.md). This one derives its key from a public
label, as the vectors of the pilot profile do (tools/pilot/github_write_profile.py on main, test_key), so anyone can
make the same key: it shows that the plumbing works and says nothing about who signed.

    probe_signer.py --label LABEL            sign stdin, write the signature in base64
    probe_signer.py --label LABEL --public   write the public key in hex
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

#: The prefix of every probe key: whoever reads a label reads the key.
PREFIX = b"proofbundle pilot probe key, never a key of the pilot: "


def probe_key(label: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(PREFIX + label.encode("utf-8")).digest())


def public_hex(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--label", required=True, help="the public label the probe key is derived from")
    parser.add_argument("--public", action="store_true", help="write the public key in hex instead of signing")
    args = parser.parse_args(argv)
    key = probe_key(args.label)
    if args.public:
        print(public_hex(key))
        return 0
    sys.stdout.write(base64.b64encode(key.sign(sys.stdin.buffer.read())).decode("ascii") + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
