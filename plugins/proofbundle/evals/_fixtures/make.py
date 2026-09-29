"""Write the signed fixtures of the eval suite into data/. Run once; the output is committed.

    uv run --no-project --with proofbundle==<the pin in server/proofbundle_mcp.py> python make.py

The scaffold scripts copy these files into each case's workspace. They run with no network, so the
fixtures cannot be made at scaffold time. Every signing key is made here and dropped: only its public
half is written, so the suite carries no private key.

Files:
  receipt-valid.json     a decision receipt that verifies under issuer.pub
  receipt-tampered.json  the same receipt with one byte of the signed payload changed
  issuer.pub             the issuer key of both receipts, base64
  bundle-valid.json      an evidence bundle signed by the key policy.json pins; its payload names the
                         tree digest of the commit the scaffold makes (hooks/proofbundle_gate.py,
                         subject_statement)
  bundle-tampered.json   the same bundle with one byte of the payload changed
  policy.json            a trust policy that pins the bundle's signer
  evidence.json          the declaration the scaffold commits, naming that tree digest as the subject

The tree digest is measured here, from a git repository holding the same covered file the scaffold
commits (README.md), not typed: the scaffold's repo modes commit README.md and .proofbundle/ only, and
the digest leaves .proofbundle/ out.
"""
import base64
import json
import pathlib
import subprocess
import sys
import tempfile

from proofbundle.decision import emit_decision_receipt
from proofbundle.emit import emit_bundle, generate_signer

DATA = pathlib.Path(__file__).resolve().parent / "data"
GATE_DIR = pathlib.Path(__file__).resolve().parents[2] / "hooks"
#: The one covered file of every repo mode, byte for byte what scaffold.sh writes.
README = "A project that publishes a release.\n"


def pub(key) -> str:
    return base64.b64encode(key.public_key().public_bytes_raw()).decode()


def flip(envelope: dict, field: str) -> dict:
    raw = bytearray(base64.b64decode(envelope[field]))
    raw[len(raw) // 2] ^= 1
    return dict(envelope, **{field: base64.b64encode(bytes(raw)).decode()})


def write(name: str, obj) -> None:
    (DATA / name).write_text(obj if isinstance(obj, str) else json.dumps(obj, indent=2) + "\n", encoding="utf-8")


def scaffold_tree_digest():
    sys.dont_write_bytecode = True
    sys.path.insert(0, str(GATE_DIR))
    import proofbundle_gate as gate  # noqa: E402 - the plugin's own gate, next to this suite
    with tempfile.TemporaryDirectory() as tmp:
        git = ["git", "-C", tmp, "-c", "user.name=Eval", "-c", "user.email=eval@example.org",
               "-c", "commit.gpgsign=false"]
        subprocess.run(git + ["init", "-q", "-b", "main"], check=True)
        pathlib.Path(tmp, "README.md").write_text(README, encoding="utf-8")
        subprocess.run(git + ["add", "-A"], check=True)
        subprocess.run(git + ["commit", "-q", "-m", "release"], check=True)
        return gate.tree_digest(tmp, "HEAD"), gate


def main() -> None:
    DATA.mkdir(exist_ok=True)
    issuer = generate_signer()
    template = json.loads(subprocess.run([sys.executable, "-m", "proofbundle.cli", "decision", "init"],
                                         check=True, capture_output=True, text=True).stdout)
    receipt = emit_decision_receipt(template, issuer)
    write("receipt-valid.json", receipt)
    write("receipt-tampered.json", flip(receipt, "payload"))
    write("issuer.pub", pub(issuer) + "\n")
    digest, gate = scaffold_tree_digest()
    builder = generate_signer()
    bundle = emit_bundle(gate.subject_statement(digest), builder)
    write("bundle-valid.json", bundle)
    write("bundle-tampered.json", flip(bundle, "payload_b64"))
    write("policy.json", {"schema": "proofbundle/trust-policy/v0.1", "policy_id": "release-evidence",
                          "allowed_issuers": [{"public_key_b64": pub(builder)}],
                          "signature": {"require_expected_signer": True}})
    write("evidence.json", {"schema": gate.DECLARATION_SCHEMA, "evidence": [
        {"kind": "bundle", "path": ".proofbundle/build.bundle.json", "policy": ".proofbundle/policy.json",
         "subject": {"algorithm": gate.TREE_ALGORITHM, "digest": digest}}]})


if __name__ == "__main__":
    main()
