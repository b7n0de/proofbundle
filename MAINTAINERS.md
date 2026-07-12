# Maintainers

proofbundle is a **single-maintainer project**.

| Maintainer | GitHub | Role |
|---|---|---|
| Konrad Gruszka | [@b7n0de](https://github.com/b7n0de) | Owner — merge, release, secrets, admin |

There are no delegated maintainers today. How maintenance works, how decisions are made,
the support window, and the (deliberately high) bar for co-maintainership are documented in
[GOVERNANCE.md](GOVERNANCE.md).

The machine-readable role registry is [`oss_maintainer_roles.json`](oss_maintainer_roles.json)
(**DEFAULT DENY** — nobody holds a delegated merge / release / secret / triage right without an
explicit entry). Ownership of the trusted core, the normative spec, the schemas, and the CI /
release wiring is enforced by [`.github/CODEOWNERS`](.github/CODEOWNERS).

## Reaching a maintainer

- **Security issues:** follow [SECURITY.md](SECURITY.md) — private disclosure, acknowledged within
  7 days. Do not open a public issue for a vulnerability.
- **Bugs, features, questions:** open a public issue or pull request. Best-effort response within
  14 days (an honest single-maintainer budget, not an SLA).
- **A receipt that verifies but should not, or fails but should not** — a defect in the verifier's
  one promise — is the highest priority; say so in the issue title.
