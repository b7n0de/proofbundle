# Open questions — what needs human judgement

The items an external reviewer is asked to judge. None of these is closeable by this project reviewing
its own code more carefully (Finding 12); they are recorded here so the review starts from a list, not
from zero. Each conclusion in [`index.json`](index.json) links the open questions it cannot close.

| id | question | why it is external | referenced by |
|---|---|---|---|
| **Q1_ANCHOR_TRUST_ROOT_DISTRIBUTION** | How are the anchor trust roots (Bitcoin block headers, TSA roots) distributed to and trusted by a relying party in practice? | A trust-root distribution model is an operational/PKI judgement, not a code property. | C1 |
| **Q2_PRIMITIVE_HARDNESS** | Are the cryptographic primitives (Ed25519, SHA-256, ML-DSA) and their library bindings sound as used? | IACR 2025/980: formal models cover logic, not primitive hardness. Requires cryptographer review. | C2, C3 |
| **Q3_SIDE_CHANNELS** | Are there timing/side-channel leaks in the verify path? | Side-channel analysis needs instrumentation and expertise outside the project's own instruments. | C2 |
| **Q4_REUSABLE_WORKFLOW_ORG_SHARED** | Is the SLSA-L3 reusable signing workflow shared at the org level per GitHub's L3 guidance, and are its permissions minimal? | Depends on org/repo settings a reviewer must inspect, not just the workflow file. | C4 |
| **Q5_SINGLE_MAINTAINER_INDEPENDENCE** | The whole project is single-maintainer with AI assistance under human review. | Institutional independence cannot be self-manufactured (Finding 12). | all |

## How the release deltas add to this list

Each release drops any NEW open questions it surfaces here, so the list grows with the surface instead
of being rediscovered at the end:

- **3.4.0** (relation_signer, decoy-parent): key-ceremony trust-root questions, decoy-parent detection
  completeness.
- **3.5.0** (relation_statement, Rust parity): differential-coverage gaps between Python and Rust.
- **3.6.0** (audit-candidate): the consolidated finalized scope-freeze questions.

## Status

All items **OPEN**. This file is honest about being a to-do list for an external party, not a set of
resolved claims.
