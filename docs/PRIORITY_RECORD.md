# Priority record (dated public evidence only)

This document does one thing: it timestamps, with dated public records, when proofbundle's core
combination became public. That combination is **signed (Ed25519) receipts, an external time anchor,
and a typed relation/v0.1 lineage between receipts.**

It makes no claim of being first, and no claim against any named third-party work. It is a list of
facts with dates, nothing more. Priority, if it ever matters, is shown only through these public
timestamps, never asserted in prose. This mirrors the standing related-work rule in
[RELATED_WORK.md](RELATED_WORK.md).

## Archival records (Zenodo)

- **Software, all versions:** concept DOI [10.5281/zenodo.21110642](https://doi.org/10.5281/zenodo.21110642)
  (resolves to the latest software version; also in `CITATION.cff`).
- **Technical Note, all versions:** concept DOI
  [10.5281/zenodo.21230466](https://doi.org/10.5281/zenodo.21230466).
- **Technical Note 3.2.3:** version DOI
  [10.5281/zenodo.21384526](https://doi.org/10.5281/zenodo.21384526), published 16 July 2026.

## Public release history (GitHub tags and PyPI)

The GitHub release tags and the matching PyPI releases are the primary dated record. The milestones
that carry the three parts of the core combination:

| Date (UTC) | Tag | What became public |
|---|---|---|
| 2026-07-01 | v0.7.1 | first public release of the receipt tool |
| 2026-07-02 | v1.0.0 | signed (Ed25519) plus RFC 6962 Merkle receipt, verified offline |
| 2026-07-03 | v2.0.0b1 | external time anchors, beta (`[anchors]`: RFC 3161, OpenTimestamps) |
| 2026-07-09 | v2.0.0 | external time anchor layer out of beta |
| 2026-07-10 | v2.1.0 | universal content root, decision receipts |
| 2026-07-12 | v3.0.0 | anchor trust moved to the relying party (secure by default) |
| 2026-07-16 | v3.3.0 | typed relation/v0.1 lineage between receipts (EXPERIMENTAL) |

Full tag history is in the repository (`git tag`) and on the
[GitHub releases page](https://github.com/b7n0de/proofbundle/releases); PyPI carries the matching
release dates at [pypi.org/project/proofbundle](https://pypi.org/project/proofbundle/#history).

## Standards engagement

- **in-toto attestation issue [#565](https://github.com/in-toto/attestation/issues/565)** ("New
  predicate proposal: eval-result"), opened 3 July 2026: a public proposal for an in-toto eval-result
  predicate, referencing proofbundle as the MIT reference implementation.

## How to read this

Each row is a public, dated artifact anyone can resolve. The record establishes *when* something was
published, not that it was published before anyone else, and not that the numbers inside any receipt
are true. Those boundaries are the whole point of the project (`THREAT_MODEL.md`,
`docs/NON_CLAIMS.md`).
