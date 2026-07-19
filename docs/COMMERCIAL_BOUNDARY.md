# Commercial boundary

proofbundle's trust core is open source and stays that way. This file draws the line
explicitly, so no future packaging decision can quietly move it.

## OSS core (free, forever)

- The **format**: bundle layout, receipt types, canonicalization, content roots.
- The **schemas**: every predicate and policy schema shipped in this repository.
- The **verifier**: full offline verification with every check and every verdict label.
- The **basic CLI**: `verify`, `demo`, `intoto`, and the other shipped subcommands.
- The **core test vectors**: the whole conformance corpus, including external vectors.
- **Basic integrations**: the in-toto export, the documented anchor types, the examples.

## Commercial layer (may be paid)

Operations, reporting, integration and governance *around* the core:

- Enterprise audit pack generator
- Verification portal
- Managed trust policies
- Key rotation playbooks
- Auditor onboarding
- Customer-specific connectors
- Compliance report templates
- SLA support

## The rule

> Offline verification must remain free and independent. The paid layer must add
> operations, reporting, integrations and governance, not remove trust from the open core.

Concretely: nothing a relying party needs in order to *verify* a bundle — code, schema,
vector, or documentation — may ever require a license, an account, or a network service.
A commercial feature that would weaken this boundary is rejected by policy, not negotiated
case by case.

Status note (honest): as of 2026-07 no commercial layer exists; this document is the
standing boundary for when one does.
