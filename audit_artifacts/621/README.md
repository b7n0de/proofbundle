# Audit artefacts for 6.2.1

## What this directory is, and what it is not

This is the release surface of 6.2.1. It opens with the commit that adds the findings register signed for 6.2.1,
before the pre-tag receipt of 6.2.1 is produced. At that commit it holds this file and nothing else: no tag
`v6.2.1` exists, no pre-tag receipt was produced here, and no audit of the final head has a verdict yet. The
neighbouring directory `audit_artifacts/620/` holds the artefacts of the released 6.2.0 and is the document to read
for that release.

`scripts/claims_hygiene_check.py` scans the Markdown of the highest numbered directory under `audit_artifacts/` as
the current release surface, so this directory carries its own README from its first commit.

## What lands here, and where the rest stands

1. The findings register. The signed carrier the release gate reads stays `audit_artifacts/findings_register_361.json`;
   the maintainer signs it over its canonical body for version 6.2.1, and `C12.2` reads and counts that register, not
   any prose here.
2. The pre-tag receipt, `pre_tag_receipt_v6.2.1.json`, beside this file. It is produced from a fresh checkout of the
   final head of the release preparation by `scripts/pre_tag_receipt.py --version 6.2.1`, which runs the audit
   command itself and records the command and its exit status.

## The signed register of this cut

The structured, signed carrier the release gate reads is `audit_artifacts/findings_register_361.json`, scoped to
`6.2.1` since 2026-10-10 — 26 entries, 17 closed, 9 open, **0 open P0/P1** (counted, not quoted): the population and
the statuses of the 6.2.0 register, with no entry added, removed or changed; only the version and the generation time
move. `C12.2` reads and counts that register, not any prose here, and
`tests/test_die_zahlen_neben_dem_register_werden_nachgerechnet.py` recomputes the three figures in this paragraph from
the register on every run.

| check | state on this cut |
|---|---|
| findings register, 0 open P0/P1 | NOT MEASURED via C12.2 — 26 findings in the signed, version-bound register (`6.2.1`); the pre-tag audit of the final head has not run yet, so the gate's own verdict is not quoted here |

## The limits of this document, named rather than left out

- Everything above describes the chain as ordered, not as completed. Whether each record exists, verifies and binds
  the tagged tree is measured in the tagged tree, not read from this file.
- A gate line copied into a signed record reports the house gate's result. It is not an independent audit
  certificate.
