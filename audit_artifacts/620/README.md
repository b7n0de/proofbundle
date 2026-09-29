# Audit artefacts for 6.2.0

## What this directory is, and what it is not

This is the release surface of 6.2.0. It opens with the commit that sets the release commit of the
notes, before the tag chain of 6.2.0 runs. At that commit it holds this file and nothing else: no
tag `v6.2.0` exists, no pre-tag receipt was produced here, and no closing round has a verdict yet.
The neighbouring directory `audit_artifacts/610/` holds the artefacts of the released 6.1.0 and is
the document to read for that release.

The directory exists before the receipt for a reason that belongs to the checks, not to the
release. `scripts/claims_hygiene_check.py` scans the Markdown of the highest numbered directory
under `audit_artifacts/` as the current release surface. A `620/` that held only the receipt would
have moved that scan away from `610/README.md` onto a directory with no Markdown in it.

## What lands here, and where the rest stands

The tag chain of 6.2.0 files these records, each in its own commit, in this order:

1. The findings register. The signed carrier the release gate reads stays
   `audit_artifacts/findings_register_361.json`; the owner signs it over its canonical body for
   version 6.2.0, and `C12.2` reads and counts that register, not any prose here.
2. The pre-tag receipt, `pre_tag_receipt_v6.2.0.json`, beside this file, written there with
   `--out` (the tool's default name carries no `v`). It is produced from a fresh checkout of the
   register commit by `scripts/pre_tag_receipt.py --version 6.2.0`, which runs the audit command
   itself and records the command and its exit status. It binds the tree
   without itself and without the mutable evidence paths, so its arrival changes no digest another
   record of the chain binds.
3. The closing round runs at the receipt commit. Its verdict is not written into this directory:
   the signed soak and differential records under `audit_artifacts/360/` carry it as their
   `gate_zeile`, with the head the round checked and its verdict, and the audit-candidate matrix
   refuses a gate line whose head is not the commit the record binds.

## The limits of this document, named rather than left out

- Everything above describes the chain as ordered, not as completed. Whether each record exists,
  verifies and binds the tagged tree is measured in the tagged tree, not read from this file.
- The recorded soak of the chain is a short one. It does not satisfy `C6.3`, which asks for a
  24-hour soak at the candidate; that run follows the tag and is recorded after it.
- A gate line copied into a signed record reports the house gate's result. It is not an
  independent audit certificate.
