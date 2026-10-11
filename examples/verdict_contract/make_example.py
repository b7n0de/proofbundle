"""Producer side of the worked example: one raw reviewer reply in, one signed receipt out.

    python make_example.py --reply reply.txt --out out --key example.key

The reply is read as BYTES and hashed before anything decodes it. The verdict comes from
verdict_contract.find_verdict on the strict UTF-8 decoding of those bytes, with no newline
translation. A small verdict record binds the reply digest, the parser file digest and the verdict;
the agent-review receipt binds the record through `reviewRuns[0].evidenceRef`. The pull request in
the receipt is a toy one (see toy_repo.py); its identifiers are example values, not a real PR.
"""
import argparse
import datetime
import hashlib
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from proofbundle import agent_review as AR

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import toy_repo  # noqa: E402
import verdict_contract as vc  # noqa: E402

PARSER = {"repository": "https://github.com/tonydzi/verdict-contract",
          "commit": "73561ee356fc01d6c976a93fb9110d2df2a2df4e",
          "path": "verdict_contract.py", "function": "find_verdict"}
EXAMPLE_PR = {"kind": "githubPullRequest", "forge": "github.com",
              "repositoryId": "R_example_not_a_real_repository",
              "pullRequestNodeId": "PR_example_not_a_real_pull_request"}
RAW_BODY = "## Toy pull request\n\nAdds `sub` to calc.py. Built by toy_repo.py for a worked example.\n"


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def load_key(path: Path) -> Ed25519PrivateKey:
    if path.exists():
        return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(path.read_text().strip()))
    key = Ed25519PrivateKey.generate()
    raw = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                            serialization.NoEncryption())
    path.write_text(raw.hex() + "\n")
    path.chmod(0o600)
    return key


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--reply", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    ap.add_argument("--key", required=True, type=Path)
    ap.add_argument("--declared-at", default=None)
    a = ap.parse_args(argv)
    out = a.out
    out.mkdir(parents=True, exist_ok=True)

    reply = a.reply.read_bytes()                       # the exact bytes, before any decoding
    verdict = vc.find_verdict(reply.decode("utf-8"))   # strict UTF-8, no newline translation
    record = {
        "parser": {**PARSER, "sha256": sha256((HERE / "verdict_contract.py").read_bytes())},
        "reply": {"path": "reply.txt", "sha256": sha256(reply), "length": len(reply),
                  "decoding": "strict UTF-8, no newline translation"},
        "verdict": verdict,
        "exitCode": vc.exit_code(verdict),
    }
    record_bytes = (json.dumps(record, indent=2, sort_keys=True) + "\n").encode("utf-8")
    (out / "reply.txt").write_bytes(reply)
    (out / "verdict.json").write_bytes(record_bytes)

    toy = toy_repo.build(out / "toyrepo")
    declared = a.declared_at or datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ")
    prepared = AR.prepare_body_for_disclosure(RAW_BODY)
    predicate = {
        "schemaVersion": "0.1.0",
        "reviewId": "verdict-contract-worked-example",
        "subjectContext": {**EXAMPLE_PR, **toy, "bodyCoreDigest": AR.body_core_digest(prepared)},
        "declaration": {
            "authoring": [],
            "reviewRuns": [{
                "assurance": "selfDeclared",
                "assertedBy": ("one LLM reviewer reply, parsed with verdict_contract.find_verdict; "
                               "evidenceRef is the sha256 of verdict.json, which names the sha256 "
                               "of the exact reply bytes, the parser file and the verdict"),
                "evidenceRef": {"sha256": sha256(record_bytes)},
            }],
            "findings": [], "findingsTotal": 0,
            "nonClaims": [
                "does not show that a review ran in CI or anywhere else",
                "does not show that the reply was produced from this diff",
                "does not show that the review was right",
                "the reply in this example was written for the example and is not a real review",
            ],
        },
        "coverage": {"status": "PARTIAL",
                     "knownGaps": ["one reviewer reply is recorded; other runs are not visible"]},
        "times": {"declaredAt": declared},
        "limitations": [
            "Tier 1 self-declaration: the key holder states this association, nobody observed it",
            "example key and example pull request identifiers, no real pull request",
        ],
    }
    predicate["limitationCodes"] = AR.derive_limitation_codes(predicate)
    # The visible block is rendered before the receipt exists, with a placeholder digest that the
    # self-reference substitution replaces, so its core digest is the one of the final block.
    block = AR.render_disclosure_block(predicate, receipt_digest="0" * 64, legacy_v01=True)
    body = AR.replace_disclosure_block(prepared, block)
    predicate["subjectContext"]["disclosureCoreDigest"] = AR.disclosure_core_digest(body)

    key = load_key(a.key)
    envelope = AR.emit_agent_review(predicate, key)
    receipt_bytes = (json.dumps(envelope, indent=2, sort_keys=True) + "\n").encode("utf-8")
    (out / "receipt.json").write_bytes(receipt_bytes)
    (out / "publickey.hex").write_text(key.public_key().public_bytes_raw().hex() + "\n")
    final_block = AR.render_disclosure_block(predicate, receipt_digest=sha256(receipt_bytes))
    (out / "pr_body.md").write_bytes(AR.replace_disclosure_block(body, final_block).encode("utf-8"))
    print(json.dumps({"verdict": verdict, "exitCode": vc.exit_code(verdict),
                      "reply_sha256": sha256(reply), "record_sha256": sha256(record_bytes),
                      "receipt_sha256": sha256(receipt_bytes)}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
