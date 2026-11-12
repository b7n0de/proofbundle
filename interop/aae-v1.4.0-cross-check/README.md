# Cross-check with MolTrust: the AAE conformance vectors v1.4.0, computed with the proofbundle verifier

Run on 12 November 2026, as our half of a cross-check MolTrust proposed on the audit list. MolTrust computes the
Appendix A vectors of draft-gruszka-audit-decision-receipts with a checker of its own; we compute the vectors of
https://github.com/MoltyCel/aae-conformance-vectors with the steps of our verifier that carry over.

## What was read first

Written from the text alone. Read before the run: draft-kroehl-agentic-trust-aae-02 (Sections 2.2.2 and 3, from the
IETF archive, SHA-256 08e202ecc06d245b287e60591098c22d8af480fc88cb455defc9e7612a473b4c), and in the repository
README.md, docs/CONFORMANCE.md, vectors/enforce/README.md, schema/enforce-vector-schema.json and the vectors. Not
read: the reference code of that repository (examples/, tools/, .github/) and its recorded results (RESULTS.md).

## Inputs, pinned

- aae-conformance-vectors at tag v1.4.0, commit 531f880155ea1ce993a7ca74137b12c255d5b2ee (tag object
  04954c3a0e086feeaebfa0451698bc4361016ed3). `inputs.sha256` lists the SHA-256 of every vector file the run read.
- proofbundle: the `src` of this branch, identical to 82411560bb0c240c4cb9af8a6c08061789faeb64, imported through
  `PYTHONPATH` (the module path is printed in `output.txt`); Python 3.10.12; the RFC 8785 package `rfc8785` 0.1.4.

## What carries over, and what does not

Our verifier binds a decision by decisionRef, SHA-256 over the exact payload bytes, which must be their own RFC 8785
serialization. Two of its steps carry over:

- **JCS**: the RFC 8785 canonicalizer of proofbundle (`canonical.canonicalize_statement`). AAE computes action_binding
  as `sha256:` followed by the lowercase hex of SHA-256(TAG || 0x00 || JCS(A)), with TAG `aae:enforce-action:v1`
  (Section 2.2.2). The JCS octets are ours; the domain tag is added as the draft states it.
- **Exact octets**: SHA-256 over exact octets, as decisionRef is taken. AAE's delegator_aae_hash is `sha-256:`
  followed by base64url of SHA-256 over the parent JWS compact serialization as retrieved (Section 3).

The rest rests on a field set our verifier does not have, and is marked NOT APPLICABLE with its reason, not as a
failure: grant selection, dispositions and the constraint language, the verdict, the enforce core and its digest (the
core holds enforce_version, mandate_digest, transaction_digest, action_digest, the verdict, grant_index, the structured
predicate trace without diagnostic reason text, and prev_core_digest; decisionRef covers a decision payload with other
members), ratification, and the nine steps of Section 5 of AAE apart from the delegator_aae_hash link.

## Result

From `result.json`, written by the run in `output.txt`:

| Family | Vectors | Computed | Result |
|---|---|---|---|
| enforce, kernel enforce_check | 21 | action_binding of the transaction's action, for all 21 | our binding equals the stated binding of at least one grant in 14 (01, 08 to 19, 21; two grants in 21), and of no grant in 7 (02 to 07, 20) |
| enforce, kernel ratify | 5 | nothing | NOT APPLICABLE |
| native | 15 | SHA-256 of the parent JWS for each delegation link, the parent found by delegator_aae_id | 10 links: the parent hash is computed for 9 and reproduces all 3 stated hashes (06 twice, 11); the 7 other links omit the OPTIONAL hash, and in one of them, in vector 10, the parent id occurs twice, so no parent hash is computed |

Two checks against what the vectors state:

- Section 2.2.3 reaches PERMIT or PENDING only through a grant whose binding matches. All five vectors that expect
  PERMIT or PENDING (01, 11, 13, 15, 19) have such a grant under our binding.
- Two vectors state the result of the binding predicate in their trace: 01 PASS and 20 FAIL. Our comparison agrees
  with both.

The verdicts and core digests of the 21 enforce_check vectors, the 5 ratify vectors and the rest of the 15 native
vectors are NOT APPLICABLE, each with the reason in `result.json`.

## Limits

- Our canonicalizer delegates to the `rfc8785` package. If MolTrust's implementation uses the same package, agreement
  on the JCS octets says less than two independent canonicalizers would.
- The matching action bindings use the action input and the domain tag of AAE; this run does not compare the decision
  digests of the two drafts. For a decision as a whole, the two drafts name different field sets.

## How to run

    git clone https://github.com/MoltyCel/aae-conformance-vectors && git -C aae-conformance-vectors checkout v1.4.0
    PYTHONPATH=/absolute/path/to/proofbundle/src python3 -B cross_check.py aae-conformance-vectors result.json

Not with `-I`: it ignores `PYTHONPATH` and would import an installed proofbundle instead of the checkout. `output.txt`
is the full output of that run, with the versions, the commits and the imported module path at its head.

## Files and licence

Check the files with `sha256sum -c MANIFEST.sha256`. The vectors are not copied here; they are under the Apache 2.0
licence of their repository. This folder is under the licence in LICENSE.

Assisted by little helpers.
