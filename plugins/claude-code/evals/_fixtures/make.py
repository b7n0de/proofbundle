"""Write the signed fixtures of the eval suite into data/. Run once; the output is committed.

    uv run --no-project --with proofbundle==<the pin in server/proofbundle_mcp.py> python make.py

The scaffold scripts copy these files into each case's workspace. They run with no network, so the
fixtures cannot be made at scaffold time. Every signing key is made here and dropped: only its public
half is written, so the suite carries no private key.

Files:
  receipt-valid.json     a decision receipt that verifies under issuer.pub
  receipt-tampered.json  the same receipt with one byte of the signed payload changed
  issuer.pub             the issuer key of both receipts, base64
  bundle-valid.json      an evidence bundle signed by the key policy.json pins
  bundle-tampered.json   the same bundle with one byte of the payload changed
  policy.json            a trust policy that pins the bundle's signer
"""
import base64
import json
import pathlib
import subprocess
import sys

from proofbundle.decision import emit_decision_receipt
from proofbundle.emit import emit_bundle, generate_signer

DATA = pathlib.Path(__file__).resolve().parent / "data"


def pub(key) -> str:
    return base64.b64encode(key.public_key().public_bytes_raw()).decode()


def flip(envelope: dict, field: str) -> dict:
    raw = bytearray(base64.b64decode(envelope[field]))
    raw[len(raw) // 2] ^= 1
    return dict(envelope, **{field: base64.b64encode(bytes(raw)).decode()})


def write(name: str, obj) -> None:
    (DATA / name).write_text(obj if isinstance(obj, str) else json.dumps(obj, indent=2) + "\n", encoding="utf-8")


def main() -> None:
    DATA.mkdir(exist_ok=True)
    issuer = generate_signer()
    template = json.loads(subprocess.run([sys.executable, "-m", "proofbundle.cli", "decision", "init"],
                                         check=True, capture_output=True, text=True).stdout)
    receipt = emit_decision_receipt(template, issuer)
    write("receipt-valid.json", receipt)
    write("receipt-tampered.json", flip(receipt, "payload"))
    write("issuer.pub", pub(issuer) + "\n")
    builder = generate_signer()
    bundle = emit_bundle(b"release artefact", builder)
    write("bundle-valid.json", bundle)
    write("bundle-tampered.json", flip(bundle, "payload_b64"))
    write("policy.json", {"schema": "proofbundle/trust-policy/v0.1", "policy_id": "release-evidence",
                          "allowed_issuers": [{"public_key_b64": pub(builder)}],
                          "signature": {"require_expected_signer": True}})


if __name__ == "__main__":
    main()
