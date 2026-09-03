# Superseded pre-tag receipts from the first attempt on 2026-09-01

These three files are kept, not deleted. They are honest history of what was attested when.

    receipt_510.json          bound tree 88831cd5...
    receipt_context_510.json  bound tree 88831cd5...
    receipt_payload_510.bin   the signed payload for both

## They are not broken and they were not faked

The signature over that payload verifies against the same pinned public key that signs the current
receipt. What changed is the tree: `88831cd5...` was moved afterwards, and a moved tree is a new
payload, so a new signature was required. The receipt for the released tree is
`../pre_tag_receipt_v5.1.0.json`.

## Why they moved into this subfolder on 2026-09-03, and what that did NOT achieve

The move is organizational. It separates two files that can never again attest anything from the
one file that attests the released tree, so a reader opening `audit_artifacts/510/` sees one
receipt and a folder, not three receipts.

**It does not take them out of the gate's candidate set, and the first draft of this file claimed
that it would.** `scripts/pre_tag_audit_gate.py` collects candidates with `rglob("*.json")`, which
descends. Measured immediately after the move: the gate still lists three rejections, now with the
`superseded/` prefix in their paths. The gate's own docstring says `rglob` in as many words at line
185; the claim was written from an assumption and the measurement corrected it within a minute.

So the REJECTED lines stay. What the reader gains is that the paths now say `superseded/`, which
is at least a label on the noise rather than a removal of it. Whether the gate should skip a
`superseded/` subfolder is a change to the gate and belongs in its own review, not in a cleanup.

Nothing about the gate's rule changed. It still rejects by measurement, with the reason `receipt
subject_tree_digest does not bind THIS tree`.
