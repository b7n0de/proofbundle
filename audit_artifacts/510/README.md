# Pre-tag audit artefacts for release 5.1.0

## Which file is the receipt for the released tree

**`pre_tag_receipt_v5.1.0.json`** is the one. It binds

    version              5.1.0
    subject_tree_digest  997f4bc5f1d0b947289c3ace932f04d128c58709c8513d35e7078af7cc7aed9b
    commit               bdf6142ad422f4aa318723c93536eca67ba460b0
    signer_pubkey        iJipntJA8N//h+ln9CgLzeC9n/M5OdCZNeBhbfagom8=

`scripts/pre_tag_audit_gate.py --strict` verifies it and exits 0.

## The other receipt files here are SUPERSEDED, and deliberately kept

`receipt_510.json`, `receipt_context_510.json` and `receipt_payload_510.bin` are from an earlier
attempt on 2026-09-01. They are not broken and they were not faked: the signature over that payload
verifies against the same pinned public key. They bind the tree `88831cd5...`, and that tree was
moved four times afterwards (three fix rounds plus the closing round of the deep gate, landed as
PR 167). A moved tree is a new payload, so a new signature was required.

They are kept rather than deleted because they are honest history of what was attested when. The
gate rejects them by measurement, not by convention, with the reason `receipt subject_tree_digest
does not bind THIS tree`. Do not read them as the receipt for 5.1.0.

## What the audit outcome actually was

`PARTIAL_GATE_NO_WITHSTANDS`, not `WITHSTANDS_DEEPGATE`. Eight findings remain open, each with its
class and the ruling on whether it can reach a user of the shipped package. They are listed in
`RESTRISIKO_510.md` at the repository root, and that file's sha256 is bound inside the receipt as
`audit_output_digest`, so the residual risk cannot be detached from the attestation.

One caveat about reading the receipt: `audit_exit_code` is `0`, but that number carries no
information. `verify_receipt` rejects every other value, so a valid receipt can only ever show `0`,
and it therefore cannot express a verdict. The verdict is in `audit_command` in words, and in
`RESTRISIKO_510.md` in detail.
