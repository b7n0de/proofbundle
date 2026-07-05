# Draft PR to evaleval/every_eval_ever — proofbundle converter (DRAFT, human submits)

**Status:** draft only. Per this repo's norms (see OUTREACH_issue_inspect_evals.md), outreach is
posted and discussed by the human maintainer personally — never auto-submitted.

## Proposed title
Add a converter: every_eval_ever aggregate JSON → signed, offline-verifiable proofbundle receipt

## Proposed body

Hi — proofbundle (MIT, Python) turns eval results into Ed25519-signed, Merkle-anchored,
offline-verifiable receipts with salted model/dataset commitments and selective disclosure
(SD-JWT). Since v0.9 it ships a converter that reads an every_eval_ever v0.2.x aggregate JSON
(validated against the vendored schema, no runtime import of every_eval_ever) and emits a signed
receipt; since v1.4 the same receipt packs into a compact `pb1.` token suitable for fields like
Hugging Face Community Evals' `verifyToken`.

This PR offers the converter (or a pointer-to-it in your docs, whichever fits your scope) so EEE
results can optionally carry cryptographic integrity end-to-end: EEE standardizes the *metadata*;
a receipt adds authorship + integrity without changing your schema.

Scope honesty: a receipt attests authenticity/integrity of a claimed result — not computation
correctness and not absence of cherry-picking (that needs pre-registration or reproduction).
Happy to adapt to your preferred integration shape (converter module in-repo, docs link, or a
`verifyToken`-style optional field in a future schema rev).

## Checklist before submitting
- [ ] Re-validate the converter against the CURRENT EEE schema version on their main
- [ ] Link a runnable example (examples/eee_receipt.py) and the INTEROP.md section
- [ ] Reference the HF Community Evals bridge as the adjacent consumer
