"""Offline check of the worked example. No network, no CI log.

    python check_example.py out

1. The receipt verifies with the pinned public key, against the pull request context the checker
   computes itself (toy repository ids, the raw diff-tree digest, the body as it stands).
2. sha256(verdict.json) is the receipt's reviewRuns[0].evidenceRef.
3. sha256(reply.txt, raw bytes) and sha256(verdict_contract.py) are the ones verdict.json names.
4. verdict_contract.find_verdict on the reply gives the verdict verdict.json states.
Exit 0 only when all four hold. The verdict itself is printed; it is not the exit status.
"""
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

EXAMPLE_PR = {"kind": "githubPullRequest", "forge": "github.com",
              "repositoryId": "R_example_not_a_real_repository",
              "pullRequestNodeId": "PR_example_not_a_real_pull_request"}


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def main(d: Path) -> int:
    ok = True

    def line(passed: bool, text: str) -> None:
        nonlocal ok
        ok = ok and passed
        print(("ok    " if passed else "FAIL  ") + text)

    envelope = json.loads((d / "receipt.json").read_bytes())
    pubkey = bytes.fromhex((d / "publickey.hex").read_text().strip())
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


if __name__ == "__main__":
    sys.exit(main(Path(sys.argv[1] if len(sys.argv) > 1 else "out")))
