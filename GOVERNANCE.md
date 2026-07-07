# Governance

proofbundle is currently a **single-maintainer project** (Konrad Gruszka, [@b7n0de](https://github.com/b7n0de)).
This document says how decisions are made and what support you can expect — honestly, without
pretending to be a foundation.

## Decision making

- The maintainer decides releases, scope and API changes. The guiding rules are already codified:
  the honest-scope line ("it deliberately does not prove that a score is true", see
  [THREAT_MODEL.md](THREAT_MODEL.md)), no home-grown cryptography (standards only, see
  [SPEC.md](SPEC.md)), and no silent breaking changes to the receipt format (versioned schema).
- Substantive proposals happen in **public issues and pull requests** — including the maintainer's
  own roadmap work, so the project history shows how decisions were reached.
- External contributions are reviewed within the support window below. A rejected proposal gets a
  stated reason, not silence.

## Support expectations

- **Security reports:** see [SECURITY.md](SECURITY.md) — private disclosure, acknowledged within
  7 days.
- **Bugs in the verifier's trusted core** (a receipt that verifies but should not, or fails but
  should not): highest priority, treated as a defect in the product's one promise.
- **Issues and PRs:** best-effort response within 14 days. This is an honest single-maintainer
  budget, not an SLA.
- **Versioning:** semantic versioning; the stable line stays verifiable by the published verifier.
  Betas are marked pre-release and never silently replace stable.

## Becoming a maintainer

Sustained, high-quality contributions (reviews, verified bug reports, features with tests) are the
path. The bar for co-maintainership of a verification tool is deliberately high: the trusted core
asks for demonstrated care with cryptographic code and with the project's honest-scope discipline.

## Provenance and AI assistance

Parts of this codebase are developed with AI assistance under continuous human review. The design
decisions, threat model and scope boundaries are human work and documented as such
([SPEC.md](SPEC.md), [THREAT_MODEL.md](THREAT_MODEL.md), the technical note). Test evidence,
mutation gates and CI are public; the project does not hide how it is built.
