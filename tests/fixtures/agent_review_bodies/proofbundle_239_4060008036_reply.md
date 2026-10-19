Confirmed, and the class is wider than the one call site you named: the tool measured the tree after an audit that had run somewhere else, so the property it claims, that the digested tree is the examined tree, was asserted by the caller and never established by the tool. The audit now runs inside the tool between two measurements, a supplied record is refused, and the remaining blind spot is named instead of measured away.

## Reproduced

Measured at `8c7a6c2c076d1ce37f21d5baf27a08e070c6d67a`, the head of this pull request before the change, with the tool's own flags of that head. Modify `a.txt`, write the audit output from the modified bytes into a file, restore the file with `git checkout --`, then emit:

```
git status --porcelain            -> (empty)
pre_tag_receipt.py --emit-payload -> rc=0, payload written, subject_tree_digest = clean HEAD
```

The payload bound the clean head to output that no run over that head produced. The inline path shares the call, so it had the same hole.

## Fix

`build_context` now measures the tree clean and equal to `HEAD` (head id and tree digest), starts `--audit-command` itself in the tree as a program with arguments and no shell, measures again, and refuses when either measurement differs or the second finds dirt. `audit_exit_code` is what the program returned, `audit_output_digest` is the sha256 of the bytes this process captured into `--audit-output-file`, which has to lie outside the tree and must not exist before the run. The flag that let a caller type an exit code is gone; a record that already exists is refused rather than bound, which is the shape of the reproduction above.

Commit measured db72e8ed4171c77525c26aeb19d60e0421c7f75d

## Catch proof

Nine cases in `tests/test_pre_tag_receipt_refuses_a_dirty_tree.py` measure this path. Against the previous head every one of them is red, and the reproduction script that drives the OLD tool with its OLD flags emits a payload in the modify, audit, restore scenario and none with the change; the control with a clean tree emits under both.

## Not covered

A change made and undone during the run, by the audit program or by a concurrent writer, lies between the two measurements and is invisible to them. The docstring says so. The audit program's behaviour is recorded, not judged, and the interpreter is trusted, not measured.

## Register

Thread b7n0de/proofbundle#239:4057990627, verdict Confirmed, class THE-MEASUREMENT-RAN-AFTER-THE-RUN-IT-VOUCHES-FOR-01.

Measurement, not certification.

<!-- proofbundle:agent-review:begin -->
Agent review receipt, Tier 1, selfDeclared, verified offline with proofbundle 6.0.0 (tag v6.0.0).
Receipt, commit-pinned
[receipt r1 for #239](https://github.com/b7n0de/proofbundle/blob/351656a41f116638819487bd96b966b7a3f10a6d/receipts/agent_review/proofbundle_239_4057990627.receipt.json)
Digest of the receipt
sha256:850c316fabcb4130c8388fe0b8a5837e58c92960e7f313e004e1b4ae0fd25bf3
Public key used to verify
[public key](https://github.com/b7n0de/proofbundle/blob/351656a41f116638819487bd96b966b7a3f10a6d/receipts/agent_review/proofbundle_239_4057990627.publickey.hex)
<!-- proofbundle:agent-review:end -->

Written by the operating agent under a standing owner authorisation for Codex threads; measurements are its own, at the head named above.
