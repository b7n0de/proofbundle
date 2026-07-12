# Operations security (supply-chain posture)

This is a **checklist**, not a claim. [SECURITY.md](../SECURITY.md) is about *receiving* vulnerability
reports; this file is about the operational posture that protects the **release supply chain** — the
accounts, keys, domain and CI that stand between the reviewed source and what a user installs.

Items marked **[Owner · to verify]** are operational actions only the maintainer can perform and
verify (account settings, registrar locks, key custody); this document does **not** assert they are
done — each is the target posture **to be confirmed**, never a statement that it is true today. The
per-line marker (not just this preamble) carries that status so it survives a reader skimming only the
list. Items marked **[repo]** are enforced by files in this repository and are reviewable in a PR.

## Accounts and identity

- **[Owner · to verify]** GitHub account and the `b7n0de` org on 2FA with a **hardware security key** (WebAuthn),
  recovery codes stored offline. No SMS 2FA.
- **[Owner · to verify]** PyPI account for the `proofbundle` project on 2FA (hardware key), and the account that
  can publish is separate from day-to-day use where practical.
- **[Owner · to verify]** Org member access reviewed; no standing admin beyond the maintainer (see
  [oss_maintainer_roles.json](../oss_maintainer_roles.json), DEFAULT DENY).

## Release integrity

- **[Owner · to verify]** Publish to PyPI via **Trusted Publishing (OIDC)** where possible, so no long-lived API
  token exists; if a token is used, it is **project-scoped**, short-lived, and stored only in the CI
  secret store, never in a file or commit.
- **[repo/Owner]** The publish workflow runs in a protected GitHub **environment** with a required
  reviewer, so a release cannot be cut without an explicit human approval (the branch-protection /
  environment gate is the G1 hardening step; verify it is applied before relying on it).
- **[Owner · to verify]** Tags are **protected** (only the maintainer can create release tags) and every release
  is cut from `main` after CI is green — a tag never precedes a green build.
- **[repo]** The release checklist ([RELEASE.md](../RELEASE.md)) is followed and its evidence recorded.

## Signing keys

- **[repo]** Signing secrets (the receipt signer, the BBS issuer, any anchor key) are **git-ignored**
  and never committed; the corresponding **public key pin is committed** and CI checks the embedded
  key matches the pin, so a swapped key fails closed. The signer modules load a key, they never mint or
  silently re-pin one (root-of-trust protection).
- **[Owner · to verify]** Private keys live only where the maintainer controls them (local, 0600, or a hardware/KMS
  custodian), never in CI for the offline-verifiable artifacts.

## CI / supply chain

- **[repo]** Third-party GitHub Actions are pinned by **full commit SHA**, not a moving tag, so a
  compromised upstream tag cannot silently change the build.
- **[repo]** Fork PRs run under **secret isolation** — a pull request from a fork cannot read the
  release/publish secrets; the trusted jobs do not run on untrusted code with secrets in scope.
- **[repo]** Static analysis (CodeQL) and the mutation / claims / conformance gates run in CI; a red
  required check blocks merge once branch protection requires them (G1).
- **[Owner · to verify]** An OpenSSF **Scorecard** run is enabled and its badge reflects the real score, not an
  aspirational one.

## Domain and predicate URIs

- **[Owner · to verify]** `b7n0de.com` (which serves the vendored predicate URIs, e.g.
  `https://b7n0de.com/proofbundle/predicates/decision-receipt/v0.1`) has **registrar lock** and
  **DNSSEC**, and the predicate paths are served over HTTPS. A predicate URI is part of a receipt's
  signed bytes, so a hijacked domain is a supply-chain issue even though verification itself is offline.

## Audit note

Nothing here weakens the offline guarantee: a proofbundle receipt verifies without any of these
services. This posture protects the *distribution* of the verifier and the *authoring* of receipts, not
the verification a user runs. If an item cannot be confirmed, it is a gap to close, not something to
mark done — the honest-scope rule applies to operations too.
