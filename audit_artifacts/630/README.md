# Audit artefacts for 6.3.0

## What this directory is, and what it is not

This is the release surface of 6.3.0. It opens with the commit that adds the findings register signed for 6.3.0,
before the pre-tag receipt of 6.3.0 is produced. At that commit it holds this file and nothing else: no tag
`v6.3.0` exists, no pre-tag receipt was produced here, and no audit of the final head has a verdict yet. The
neighbouring directory `audit_artifacts/621/` holds the artefacts of the released 6.2.1 and is the document to read
for that release.

`scripts/claims_hygiene_check.py` scans the Markdown of the highest numbered directory under `audit_artifacts/` as
the current release surface, so this directory carries its own README from its first commit.

## What lands here, and where the rest stands

1. The findings register. The signed carrier the release gate reads stays `audit_artifacts/findings_register_361.json`;
   the maintainer signs it over its canonical body for version 6.3.0, and `C12.2` reads and counts that register, not
   any prose here.
2. The pre-tag receipt, `pre_tag_receipt_v6.3.0.json`, beside this file. It is to be produced from a fresh checkout
   of the final release-preparation head with `scripts/pre_tag_receipt.py`, using version `6.3.0` and explicitly
   selecting `audit_artifacts/630/pre_tag_receipt_v6.3.0.json` with `--out`. The supplied audit command runs while
   the receipt context is produced; its command and exit status are recorded before signing.

## The signed register of this cut

The structured, signed carrier the release gate reads is `audit_artifacts/findings_register_361.json`, scoped to
`6.3.0` since 2026-10-13 — 36 entries, 19 closed, 17 open, **0 open P0/P1** (counted, not quoted). Against the register
of 6.2.1 it adds ten entries from the defect search on the 6.3.0 candidate and changes no other: `CODEX-630-K1` and
`CODEX-630-K2` are closed by pull requests 346 and 347, and `CODEX-630-K3` to `CODEX-630-K10` are open with severity P2
by the owner's triage of 2026-10-12 and move to 6.3.1. `RESTRISIKO_630.md` promises each of them. `C12.2` reads and
counts that register, not any prose here, and `tests/test_die_zahlen_neben_dem_register_werden_nachgerechnet.py`
recomputes the three figures in this paragraph from the register on every run.

| check | state on this cut |
|---|---|
| findings register, 0 open P0/P1 | NOT MEASURED via C12.2 — 36 findings in the signed, version-bound register (`6.3.0`); the pre-tag audit of the final head has not run yet, so the gate's own verdict is not quoted here |

## The limits of this document, named rather than left out

- Everything above describes the chain as ordered, not as completed. Whether each record exists, verifies and binds
  the tagged tree is measured in the tagged tree, not read from this file.
- A gate line copied into a signed record reports the house gate's result. It is not an independent audit
  certificate.
- The severity P2 of `CODEX-630-K3` to `CODEX-630-K10` is the owner's triage; the defect search rated them P1 under its
  own contract, and each register entry says so.
