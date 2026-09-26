#!/usr/bin/env python3
"""Read proofbundle's DSSE-wrapped in-toto attestations with two foreign Python libraries.

Runs in its own environment, never proofbundle's: `in-toto-attestation` (the Python binding of the
in-toto attestation framework) and `securesystemslib` with its crypto extra (the DSSE Envelope of the
Secure Systems Lab). Nothing of proofbundle is imported.

  * DSSE: `securesystemslib.dsse.Envelope.from_dict`, then `verify` under an `SSlibKey` of the test
    key. securesystemslib matches a signature to a key by keyid, so the key is given the keyid of the
    keyid control; an envelope without keyid is measured as it is.
  * Statement: the payload, decoded by securesystemslib's own base64 helper (the one its Envelope
    uses), parsed into the `Statement` protobuf with `json_format.Parse`, once strictly (its default)
    and once with `ignore_unknown_fields`, then `Statement.validate()`.

usage: probe_python.py <public key, hex of 32 raw bytes> <keyid> <envelope.json>...
Prints one JSON object per envelope.
"""
from __future__ import annotations

import copy
import json
import sys


def probe(pub_raw: bytes, keyid: str, path: str) -> dict:
    from google.protobuf import json_format
    from in_toto_attestation.v1 import statement_pb2
    from in_toto_attestation.v1.statement import Statement
    from securesystemslib._internal.utils import b64dec
    from securesystemslib.dsse import Envelope
    from securesystemslib.signer import SSlibKey

    out: dict = {"file": path.rsplit("/", 1)[-1]}
    with open(path, encoding="utf-8") as fh:
        raw = json.load(fh)
    out["payload_type"] = raw.get("payloadType")
    key = SSlibKey(keyid, "ed25519", "ed25519", {"public": pub_raw.hex()})
    try:
        env = Envelope.from_dict(copy.deepcopy(raw))
        try:
            env.verify([key], 1)
            out["dsse_verified"] = True
        except Exception as exc:  # noqa: BLE001 - the library's refusal is the measured outcome
            out["dsse_verified"] = False
            out["dsse_error"] = f"{type(exc).__name__}: {exc}"
    except Exception as exc:  # noqa: BLE001
        out["dsse_verified"] = False
        out["dsse_error"] = f"Envelope.from_dict: {type(exc).__name__}: {exc}"

    body = b64dec(raw["payload"]).decode("utf-8")
    try:
        json_format.Parse(body, statement_pb2.Statement())
    except Exception as exc:  # noqa: BLE001
        out["statement_strict_parse_error"] = f"{type(exc).__name__}: {exc}"
    try:
        pb = json_format.Parse(body, statement_pb2.Statement(), ignore_unknown_fields=True)
    except Exception as exc:  # noqa: BLE001
        out["statement_lenient_parse_error"] = f"{type(exc).__name__}: {exc}"
        return out
    st = Statement.copy_from_pb(pb)
    try:
        st.validate()
    except Exception as exc:  # noqa: BLE001
        out["statement_validate_error"] = f"{type(exc).__name__}: {exc}"
    out["statement_type"] = st.pb.type
    out["predicate_type"] = st.pb.predicate_type
    out["subjects"] = [{"name": s.name, "digest": dict(s.digest)} for s in st.pb.subject]
    out["predicate_keys"] = sorted(st.pb.predicate.keys())
    return out


def main() -> int:
    if len(sys.argv) < 4:
        print(__doc__, file=sys.stderr)
        return 2
    pub = bytes.fromhex(sys.argv[1])
    for path in sys.argv[3:]:
        print(json.dumps(probe(pub, sys.argv[2], path), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
