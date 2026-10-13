"""Offline check of the worked example. No network, no CI log.

    python check_example.py out
    python check_example.py DIR --public-key <64 hex digits>

1. The receipt verifies with the expected public key, against the pull request context the checker
   computes itself (toy repository ids, the raw diff-tree digest, the body as it stands). The expected
   key is the example key pinned below, or the key the caller gives with --public-key. The folder's
   publickey.hex decides nothing: the producer writes it next to the receipt, so a package issued by
   another key would bring its own (CODEX-630-K4).
2. sha256(verdict.json) is the receipt's reviewRuns[0].evidenceRef.
3. sha256(reply.txt, raw bytes) and sha256(verdict_contract.py) are the ones verdict.json names.
4. verdict_contract.find_verdict on the reply gives the verdict verdict.json states.
Exit 0 only when all four hold. The verdict itself is printed; it is not the exit status.
"""
import argparse
import base64
import hashlib
import json
import sys
from pathlib import Path

from proofbundle import agent_review as AR
from proofbundle import canonicalize_statement

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import toy_repo  # noqa: E402
import verdict_contract as vc  # noqa: E402

#: The key the files in out/ were signed with, pinned in the checker and not read from the folder it checks.
EXAMPLE_PUBLIC_KEY = bytes.fromhex("1547dfe036045ac7a69f1673c3c0cf3710dea9f90dc28dfdce6405573ca00e1f")

EXAMPLE_PR = {"kind": "githubPullRequest", "forge": "github.com",
              "repositoryId": "R_example_not_a_real_repository",
              "pullRequestNodeId": "PR_example_not_a_real_pull_request"}


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def main(d: Path, expected_key: bytes | None = None) -> int:
    """Check the package in `d` against `expected_key`, by default EXAMPLE_PUBLIC_KEY."""
    ok = True
    pubkey = EXAMPLE_PUBLIC_KEY if expected_key is None else expected_key

    def line(passed: bool, text: str) -> None:
        nonlocal ok
        ok = ok and passed
        print(("ok    " if passed else "FAIL  ") + text)

    envelope = json.loads((d / "receipt.json").read_bytes())
    body = (d / "pr_body.md").read_bytes().decode("utf-8")
    toy = toy_repo.build(d / "toyrepo")
    expected_sc = {**EXAMPLE_PR, **toy, "bodyCoreDigest": AR.body_core_digest(body),
                   "disclosureCoreDigest": AR.disclosure_core_digest(body)}
    r = AR.verify_agent_review_any(
        envelope, pubkey, expected_subject_digest=sha256(canonicalize_statement(expected_sc)),
        observed_body=body, policy=AR.load_policy())
    line(r["ok"] is True, f"receipt: ok={r['ok']} crypto={r['crypto_ok']} "
                          f"subject={r['expected_subject_match']} body={r['body_core_digest_match']} "
                          f"policy={r.get('policy_decision')} errors={r['errors']}")

    predicate = json.loads(base64.b64decode(envelope["payload"]))["predicate"]
    claimed = predicate["declaration"]["reviewRuns"][0]["evidenceRef"]["sha256"]
    record_bytes = (d / "verdict.json").read_bytes()
    line(sha256(record_bytes) == claimed, "verdict.json is the record the receipt binds")

    record = json.loads(record_bytes)
    reply = (d / "reply.txt").read_bytes()
    line(sha256(reply) == record["reply"]["sha256"], "reply.txt, raw bytes, is the reply the record names")
    line(sha256((HERE / "verdict_contract.py").read_bytes()) == record["parser"]["sha256"],
         "verdict_contract.py is the parser file the record names")

    try:
        again = vc.find_verdict(reply.decode("utf-8"))
    except UnicodeDecodeError as exc:
        again = f"undecodable: {exc}"
    line(again == record["verdict"], f"find_verdict again: {again}, record says {record['verdict']}")
    print(f"verdict {record['verdict']}, exit_code {vc.exit_code(record['verdict'])} "
          f"(a self-declaration, see the receipt's nonClaims)")
    return 0 if ok else 1


def _public_key(text: str) -> bytes:
    raw = bytes.fromhex(text)
    if len(raw) != 32:
        raise ValueError("an Ed25519 public key has 32 bytes")
    return raw


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Offline check of the worked example.")
    ap.add_argument("folder", nargs="?", default="out", type=Path)
    ap.add_argument("--public-key", type=_public_key, default=None,
                    help="the expected Ed25519 public key, 64 hex digits; by default the example key")
    a = ap.parse_args()
    sys.exit(main(a.folder, a.public_key))
