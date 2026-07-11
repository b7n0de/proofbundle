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

Trust is granted **gradually**, never in one step:

- **Contributor** — opens issues/PRs; every change goes through review and CI like anyone's.
- **Triager / reviewer** — after a track record of useful triage or review, may be invited to help
  label and review. This grants *cockpit-internal* rights only (comment, label-suggest); it never
  grants merge, release, or secret access.
- **Co-maintainer** — after sustained trusted work, may be invited. Merge and release rights are a
  **separate, explicit grant per person**, not automatic with the role, and default to off.

Roles are recorded in [`oss_maintainer_roles.json`](oss_maintainer_roles.json) at the repository
root (DEFAULT DENY: no delegated right without an explicit entry). Code ownership of the trusted
core, the spec, the schemas and the CI/release wiring is declared in
[`.github/CODEOWNERS`](.github/CODEOWNERS), so a change to those paths requires the maintainer's
review — **more eyes, not weaker gates**. The Owner remains the highest authority; the Fork-PR CI
secret-isolation guard and branch protection apply to everyone unchanged.

A note on caution (the XZ-utils lesson): a pattern of helpful contributions combined with pressure
for rights or merge speed is a red flag, not a reason to accelerate. The real gate is diff review
and build isolation, not rapport. New-contributor activity is screened the same way for everyone
(see the contributor-vetting process); this protects the project without discouraging honest
first-time contributors.

**Removing rights.** A role or a granted right can be withdrawn at any time by the Owner — for
inactivity, on request, or on any concern — by removing the entry from the roles registry. No
process is owed for revocation of a delegated right; the default state is no rights.

## Contributors

proofbundle's first external contribution is issue **#28** (the CLI `--version` printing the pinned
spec revision, WP-B1), from **[@onxxdatas](https://github.com/onxxdatas)**. It is recorded in the
roles registry for the governance story; like every contributor, they hold no delegated rights
(DEFAULT DENY) — the change went through the same review and CI as any other.

## Provenance and AI assistance

Parts of this codebase are developed with AI assistance under continuous human review. The design
decisions, threat model and scope boundaries are human work and documented as such
([SPEC.md](SPEC.md), [THREAT_MODEL.md](THREAT_MODEL.md), the technical note). Test evidence,
mutation gates and CI are public; the project does not hide how it is built.
