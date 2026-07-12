# W2 conformance corpus — adversarial review evidence (2026-07-11)

Risk-tiered review of the W2 conformance corpus before merge. The corpus makes a
cryptographic **confirmed-anchor** claim, so the confirmation was reviewed by an
independent adversarial lens (re-fetching the real Bitcoin block header itself), in
addition to the author's own bidirectional tamper tests. No-Fake evidence, recorded with
the PR.

## Lens 1 — anchor non-circularity + byte order (independent adversarial re-verification)

**Verdict: the "genuinely confirmed, non-circular" claim holds. No overclaim, no defect.**

- Frozen value `ba725ff4…d2a26486` (case.json) == `bytes.fromhex(blockstream_BE)[::-1]` — exact,
  round-trips both ways.
- Real block 957504 merkle root **independently re-fetched from two explorers** (blockstream.info
  AND mempool.space, identical value `8664a2d2…f45f72ba`), from sources that never saw this proof —
  so the grounding is external, not derived from the proof.
- OTS proof parsed independently: `file_digest` == `sha256(decision_receipt.jcs)` == MANIFEST content
  root (proof bound to the real document); `BitcoinBlockHeaderAttestation` at height 957504 commits
  `ba725ff4…` == frozen == reverse of the real chain merkle root.
- **Not circular:** Fact A (OTS op-chain derives the value from `sha256(jcs)`) ∧ Fact B (independent
  fetch shows the real chain carries that value) ⟹ genuine Bitcoin inclusion. Circularity would need
  the frozen value to have no grounding beyond the proof; case.json documents `independent_source`
  (provider, block hash, BE display) and it reproduces live.
- **Byte order safe:** a big-endian value as frozen → `block_mismatch` (wrongly *fails*, never wrongly
  passes); correct LE → `confirmed`; empty → `upgraded_unverified` (honest); zeroed → `block_mismatch`.
- Disclosed caveat (not a defect): the green run proves op-chain→frozen; frozen→real-chain is a
  documented, reproducible out-of-band step (as real OTS clients trust a local node's header), and
  case.json discloses it and scopes the case to anchor-lifecycle + canonicalization (`schema_conformant:
  false`, 12 findings), so it does not overclaim schema conformance.

## Lens 2 — harness soundness / anti-tautology

All fixture-byte tampers are CAUGHT (JCS byte-identity, content-root vs MANIFEST/expected, evidenceRef
binding in isolation, wrong frozen root → `block_mismatch`, `.ots` swap → `unbound`, sophisticated
metric-tamper-plus-regenerate → root mismatch). **One real defect found (MEDIUM, fixed):** every check
was gated on its key being present in `expected`, so a case with `expected: {}` (or a dropped key)
passed green asserting nothing — a fake-PASS-by-omission. **Fix:** a required-expectations floor
(fail-closed on a missing mandatory key) plus the defining checks (JCS, content-root, evidenceRef,
anchor-when-`.ots`-ships) now run unconditionally; the affirmative "ok" note can no longer claim a
comparison that did not run. Two LOWs fixed: a missing fixture is now a per-case FAIL (try/except in
`run()`) instead of a run-aborting traceback. Regression tests added
(`TestHarnessFailsClosed`: empty-expected, dropped-key, dropped-anchor, missing-fixture). Deployment
note (not code): the `anchors` CI job should be a REQUIRED status check so the confirmed-anchor
refutation sits on the merge gate — tracked for the G1 branch-protection step.

## Lens 3 — No-Overclaim text audit

No hard false claim survived; five wording/precision refinements, all applied: (F1) README no longer
folds the Bitcoin anchor into "interop proven" — anchor confirmation and canonicalization interop are
stated separately; (F2) the README states the present 12-finding validator result crisply rather than
softening it to "pending regeneration"; (F3) the wrong-header rejection is attributed to
`test_anchors_ots.py` (the corpus runs the positive check) in case.json, conformance/README, CHANGELOG;
(F4) the confirmed case's cross-reference to the gap record notes that record analyses the regenerated
vector while the 12-count is reproduced for this OLD vector; (F5) "block header … frozen" corrected to
"block merkle root". Attribution to MarkovianProtocol/Colin verified present and correct throughout.
