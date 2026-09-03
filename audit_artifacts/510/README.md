# Pre-tag audit artefacts for release 5.1.0

## Which file is the receipt for the released tree

**`pre_tag_receipt_v5.1.0.json`** is the one. It binds

    version              5.1.0
    subject_tree_digest  fd22e5e58432456911de12e83befd61f714a4648f023eeffd275e5f8a829cb04
    commit               e837ddc0304b8162e0ccdf58a89895c8cc3639ee
    signer_pubkey        iJipntJA8N//h+ln9CgLzeC9n/M5OdCZNeBhbfagom8=

`scripts/pre_tag_audit_gate.py --strict` verifies it and exits 0.

## The other receipt files are SUPERSEDED, deliberately kept, and live in `superseded/`

They moved into the subfolder on 2026-09-03, for reading order only. The gate's candidate scan is
`rglob`, so it descends and they are STILL rejected candidates — measured after the move, the gate
lists three rejections with `superseded/` in the paths. See `superseded/README.md`, which records
both the intent and the measurement that corrected it.

`superseded/receipt_510.json`, `superseded/receipt_context_510.json` and
`superseded/receipt_payload_510.bin` are from an earlier
attempt on 2026-09-01. They are not broken and they were not faked: the signature over that payload
verifies against the same pinned public key. They bind the tree `88831cd5...`, which was moved
afterwards. A moved tree is a new payload, so a new signature was required.

They are kept rather than deleted because they are honest history of what was attested when. The
gate rejects them by measurement, not by convention, with the reason `receipt subject_tree_digest
does not bind THIS tree`. Do not read them as the receipt for 5.1.0.

## Why the receipt lives here and not next to the code

`subject_tree_digest` is computed over `git ls-tree HEAD` excluding this directory. That exclusion
removes the circular binding: adding the receipt here leaves the bound tree unchanged. It also
means the opposite is true and it cost this release two signatures to learn it — a change under
`src/` or `scripts/` DOES move the tree and invalidates any signature taken before it. The order is
therefore fixed: land the code, then mint the receipt, then tag.

## What the audit outcome actually was

`PARTIAL_GATE_NO_WITHSTANDS`, not `WITHSTANDS_DEEPGATE`. Eight findings remain open, each with its
class and the ruling on whether it can reach a user of the shipped package. They are listed in
`RESTRISIKO_510.md` at the repository root, and that file's sha256 is bound inside the receipt as
`audit_output_digest`, so the residual risk cannot be detached from the attestation.

One caveat about reading the receipt: `audit_exit_code` is `0`, but that number carries no
information. `verify_receipt` rejects every other value, so a valid receipt can only ever show `0`,
and it therefore cannot express a verdict. The verdict is in `audit_command` in words, and in
`RESTRISIKO_510.md` in detail.
