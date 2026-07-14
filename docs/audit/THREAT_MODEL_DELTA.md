# Threat Model Delta — 3.2.0

What new attack surface 3.2.0 introduces and how it is bounded. This is a DELTA on the existing
proofbundle threat model (the receipt/bundle/anchor layers), scoped to the new O-item predicates. Every
new surface is EXPERIMENTAL and fail-closed.

## New assets and the trust boundary

| New surface | Asset it protects | In scope for 3.2.0 | Explicitly NOT claimed |
|---|---|---|---|
| Action Outcome Receipt (O1) | who executed a decided action, and against which decision | role separation + decisionRef binding are cryptographically bound | that the effect was good/desired, or that execution actually occurred (self-asserted status is warned) |
| Trust Pack (O2) | which keys hold which role, authenticated by a threshold of root keys | a single leaked root key below threshold cannot forge a pack; rotation needs the old root to vouch | that the key holders are honest |
| Public Transparency (O3) | whether a checkpoint's origin/root/tree-size are cryptographically anchored | the aggregate PASSes only with a verified signature or witness quorum | general log conformance without interop vectors |
| SD-JWT VC (O7) | issuer authenticity + holder binding of selectively disclosed claims | issuer signature is verified; a `cnf`-bound credential without proof-of-possession fails | that a disclosed claim is true |

## Attacks considered and closed (see SECURITY_FINDINGS_CLOSED.md)

- **Sybil on the root threshold** (C1): one key under many names. Closed by distinct-key-material counting.
- **Root-takeover via rotation** (C2): mint a "v2" with self-owned keys chained by the public
  `prevVersionDigest`. Closed by requiring the old root to sign the new pack.
- **Self-issued credential** (C3): a garbage issuer signature accepted. Closed by verifying the issuer
  signature.
- **Subject rehang / cross-receipt substitution** (C4, N1): point a statement's subject elsewhere, or
  graft an eval SD-JWT onto a non-eval payload. Closed by subject classification + the eval-root-graft
  binding check.
- **Own-frozen anchor** (WP-A1): a producer commits its own Bitcoin block header. Never trusted — only a
  relying-party-supplied header confirms; `--require-anchor` without one is policy-unmet (exit 3).

## Residual threats (honest, out of 3.2.0 scope)

- The producer with a valid signing key can still sign a FALSE claim — integrity is not truth
  (No-Overclaim). This is inherent and documented, not a bug.
- An external, independent security audit before the `Stable` classifier is still open; O9 provides
  CODEOWNERS + required-review governance, not a third-party audit.
- The Rust O8 verifier reproduces the corpus but does not independently CONFIRM a live OTS anchor
  (no OTS-binary / Bitcoin-header verification yet).
