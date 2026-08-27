# Deep-gate run record — 500, iteration 8 (release ceremony), 2026-08-27

`pre-tag-adversarial-audit: RUN | version=5.0.0`

## What this record attests

An adversarial DEEP-mode deep-gate re-verification of the v5.0.0 **release ceremony code** at commit
`2b8a16e` (diff `bc96fa5..2b8a16e`, exactly two files: `scripts/pre_tag_audit_gate.py` P1-A fix +
`scripts/pre_tag_receipt.py` two-half keyless mode). **Verdict: `WITHSTANDS_DEEPGATE`.**

All five falsification targets held, each with an executable proof in a throwaway worktree + generated
ed25519 keys (real repo untouched, worktrees cleaned):
- **T1 — option C holds:** committed receipt ACCEPTs; injecting `evil-backdoor-pkg==6.6.6` into
  `pyproject [project.dependencies]` shifts `subject_tree_digest` (`662e2741…→c3616263…`) → gate
  REJECTs ("does not bind THIS tree"). The refuted src-only option-B supply-chain hole stays closed.
- **T2 — the P1-A gate fix opened no bypass:** 8-scenario verdict parity between `bc96fa5` and `2b8a16e`
  is identical EXCEPT the bare-run (no `PYTHONPATH=src`) — `bc96fa5` crashed uncaught (local-green→CI-red),
  `2b8a16e` rules cleanly. A tampered working-tree `signature.py` (`verify_ed25519→True`) reaches the
  signature check with zero power: signer-trust (#8) and tree-binding (#4) already gate it; a committed
  src tamper changes the tree digest and REJECTs at #4. The fail-closed wrapper only maps exceptions→REJECT
  (never False→True) — no false-accept path.
- **T3 — keyless mode:** payload == `canonical_bytes(context)` byte-identical; lying subject_tree_digest,
  attacker self-signed key, context/payload mismatch, garbage signature, and trusted-pubkey impersonation
  are all REJECTed by the gate or REFUSED fail-closed by assemble (no receipt on disk).
- **T4 — F2 byte-identity:** `git diff bc96fa5..2b8a16e -- pre_tag_receipt_lib.py` EMPTY (the security core
  unchanged); exactly 2 files changed; inline path produces a byte-identical receipt.
- **T5 — no regression:** harness 32/32, `type_confusion_gate --strict` 57/57 raw=0, meta-tests 9/9,
  option-C meta-test passes.

Honest boundaries named (pre-existing, not exploits, not introduced by this diff): the trust-anchor rests
on commit authority over `audit_artifacts/pre_tag_trusted_pubkeys.txt` (branch protection / CODEOWNERS);
gate-source binding is a post-signing tripwire, not containment; the `opentimestamps` env-gap tests fail
identically at the `bc96fa5` baseline (outside the diff).

## Relationship to the tagged tree

The deep-gate certifies the **ceremony code + the src product** as of `2b8a16e`. The ceremony files
(`scripts/pre_tag_*.py`) are byte-identical from `2b8a16e` through the branch head `ac1d005`
(`git diff 2b8a16e..ac1d005 -- 'scripts/pre_tag_*.py'` is empty), so T1–T4 carry unchanged. The
release-prep changes added AFTER this record — `docs/release_scope/5.0.0.md` (doc); the ruff-E702
test-lint splits; the **reverted** `version_pin` bump (it is deliberately kept at `3.6.0` until the
vor-tag re-baseline — `audit_candidate_matrix.version_pin_binding` fails closed on the 3.6.0-vs-5.0.0
drift, which is the L6-01 fix, not the literal); `src/proofbundle/evalclaim.py` (+1 line,
`assert isinstance(comparator, str)` — a mypy type-narrowing assert, behavior-preserving because the
`is_member(comparator, _COMPARATORS)` guard already guarantees a str when it is reached); and three
test files gaining the canonical `_HAS_OTS`/`@skipUnless` opentimestamps skip-guards — do **not** touch
any verify surface or the ceremony. An independent adversarial re-gate at `ac1d005` (2026-08-27)
confirmed all four targets HELD under executable proof (the assert is behavior-preserving for every
JSON/validated input incl. `python -O`; the guards RUN and PASS with anchors, skip honestly without,
and still catch a seeded defect; `type_confusion_gate --strict` 57/57 and the harness are identical),
so the verdict carries to the branch head. The cryptographic binding to the exact tagged tree is the **signed pre-tag
receipt** (option C, `subject_tree_digest` = final tree minus `audit_artifacts/`), produced at tag time
via the Mac key-custody handshake; `pre_tag_audit_gate.py --strict` in `release.yml` verifies it and
blocks the build without it.

## Provenance

Subagent DEEP-mode deep-gate (adversarial, executable exploits); driver scripts retained under the
session scratchpad `deepgate/` (`scenarios.py`, `t2_tamper.py`, `t3_keyless.py`, `t3_edges.py`,
`t3_impersonate.py`, `build_base.sh`). Independent diverse lens: un-Gegenlesung = ACCEPT (all four
falsification questions held). Key-custody review agent + `verify_keyless.py` corroborate. "WITHSTANDS"
= ready for the owner-GO'd tag, not "released"; the tag/PyPI/DOI publish is the owner one-way door
(Owner-GO Option A, 2026-08-27).
