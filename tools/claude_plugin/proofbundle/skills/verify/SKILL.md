---
name: verify
description: Verify a proofbundle agent-review receipt (a DSSE envelope, usually named *.receipt.json) by running the proofbundle verifier and reporting its verdict. Use when someone asks whether such a receipt is genuine, valid, or belongs to a given pull request or commit. Not for npm, payment, or other unrelated files that happen to be called receipt.json.
---

# Verify a proofbundle agent-review receipt

Report what the **verifier** says. Never report what the receipt says about itself.

## The one rule that matters

A receipt carries a `strength` field. **Do not read it and report it.** A receipt is a statement
about itself; asking it whether it is valid answers a different question than the one that was
asked. Run the verifier and report its verdict.

The same trap has a second, sharper form, and it is easy to walk into: the verifier takes an
`expected_subject_digest`. **Derive that digest from the object you are actually looking at — the
pull request, commit, or artifact — never by re-deriving it from the predicate inside the receipt
you are verifying.** Re-deriving it from the receipt proves only that the receipt is internally
consistent with itself. A valid receipt copied from a *different* subject would still report
`MATCH`. The proofbundle library documents this exact case (`agent_review.py`, finding of
2026-08-31): "whoever copies a valid receipt and claims it belongs to another pull request changes
nothing about the envelope; they lie beside it."

### How to obtain that digest

The verifier compares against `subjectContext` — so build one from the object you are looking at
and let the library derive the digest, rather than hashing anything by hand:

```bash
PYTHONPATH=src python3 -c "
from proofbundle import agent_review as ar
print(ar._subject_digest({'subjectContext': {
    'forge': 'github', 'kind': 'githubPullRequest',
    'repositoryId': '<repo node id>', 'pullRequestNodeId': '<PR node id>',
    'headSha': '<head sha you are looking at>', 'baseSha': '<base sha>',
}}))"
```

Take every value from the pull request in front of you (`gh pr view <n> --json id,headRefOid,baseRefOid`),
never from the receipt. Hashing the file yourself will not match: the digest is computed over a
canonicalised structure, not over raw bytes.

If no independent subject digest is available, run without one and say so plainly: the run then
checked internal consistency and the signature, and **nothing established that the receipt belongs
to the object in front of you**. That is an honest partial result, not a passed verification.

## Before running

The verifier lives in the `proofbundle` package, and it is not installed by this plugin:

```bash
python3 -m pip install 'proofbundle[eval]'
```

The `[eval]` extra is required — the canonicalizer (RFC 8785) lives there, and without it the
verifier raises `AgentReviewError` while hashing. If the environment already has a proofbundle
source checkout, `PYTHONPATH=src` against that checkout works too; do not assume it.

## Running it

```bash
python3 - "$RECEIPT" "$PUBKEY_HEX" "$EXPECTED_SUBJECT_DIGEST" <<'PY'
import json, sys
from proofbundle import agent_review as ar
env = json.load(open(sys.argv[1]))
key = bytes.fromhex(sys.argv[2])
erwartet = sys.argv[3] if len(sys.argv) > 3 and sys.argv[3] else None
r = ar.verify_agent_review(env, key, expected_subject_digest=erwartet)
print(json.dumps({k: r[k] for k in ("ok", "crypto_ok", "subject_binding_ok",
                                    "expected_subject_match", "reason_codes",
                                    "warnings", "errors")}, indent=2))
PY
```

## Reporting

One line for the verdict, then the measured fields, each with its value. Name `reason_codes`
verbatim rather than paraphrasing them.

Say which of these three you actually ran, because they are not the same claim:

1. **Signature only** — no public key from an independent source. Weakest; says the bytes parse.
2. **Signature and internal consistency** — no expected subject digest. The receipt hangs together;
   nothing ties it to your object.
3. **Signature, consistency and binding** — an expected subject digest from the object itself.
   Only this one answers "does this receipt belong to what I am looking at".
4. **All three, but the key came from the same place as the receipt** — the most common case in
   practice, and the weakest. If the public key hex was taken from the same pull request, issue or
   artifact repository that carries the receipt, the chain is circular one level up: whoever could
   forge the receipt could supply the key beside it. Binding then shows `MATCH` and proves nothing
   about who signed. Say so explicitly, and name where the key came from. A key is only a trust
   anchor if its provenance is independent of the thing it verifies.

This fourth case was found by a foreign-family review on 2026-09-14 and is the same circularity as
the subject digest, one level higher: it is easy to fix the digest and leave the key untouched.

Honest limits, always worth stating: this verifies a signature and a binding. It says nothing about
whether the reviewed work is correct, and it is not a security audit.

## A limit of the version pin

This skill was written against proofbundle 6.0.0 (tag `v6.0.0`). Be aware that `__version__` in the
package does not move with every commit, so a reported `6.0.0` does not by itself prove the
installed code is the tagged code. If the verdict matters, pin the install to the tag.
