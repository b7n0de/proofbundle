# Threat-model delta — 3.6.0 audit-candidate

This chapter records what 3.6.0 adds to `THREAT_MODEL.md` for the audit-candidate scope freeze. It does
not restate the base threat model; it names the surfaces the external reviewer should focus on and the
defenses added in this release.

## New / reinforced defenses in 3.6.0

### T-360-1 payloadType / predicateType confusion (Trust Pack)

- Threat: a DSSE envelope of one type is accepted as a Trust Pack, or a mislabelled `payloadType` field
  is passed through to a downstream consumer that trusts it.
- Defense: `trust_pack.verify_trust_pack` binds its PAE to the in-toto statement type (the signed bytes
  commit to the type), AND now pins the envelope `payloadType` field fail-closed against the same
  constant (defense-in-depth, 3.6.0). The `predicateType` must be trust-pack/v0.1 or the pack is
  rejected. Negative vectors: `tests/test_trust_pack_payloadtype_negatives.py`.
- Formal status: obligation O7 (payloadType binding) is declared RESERVED in `formal/model.py` — the
  property is code-enforced and vector-tested but NOT yet a formal proof (No-Fake: no fabricated proof).

### T-360-2 raw-crash / DoS on hostile input (Never-Raise)

- Threat: a crafted input drives a public verifier into a raw, uncaught exception (a parser-differential
  or DoS vector).
- Defense: the F4 type-confusion matrix asserts every public verifier returns or raises a typed
  ProofBundleError (never a raw traceback), structurally over the AST-discovered verifier set. The
  bounded fuzz-soak (`scripts/fuzz_soak.py`) exercises the same property with hundreds of thousands of
  random inputs across every parser class, counting untriaged crashes and false accepts (both zero on
  the recorded run). Resource budgets bound attacker-scaled inputs before the verify loop.

### T-360-3 silent test / coverage regression

- Threat: a change silently drops a test suite or fuzz coverage, so a defense regresses undetected.
- Defense: the locked test manifest (`scripts/test_manifest_gate.py`) fails CI on any drop below the
  committed floor or any collection error; the ClusterFuzzLite coverage-regression gate does the same
  for the fuzz surface.

### T-360-4 build / provenance tampering

- Threat: the published artifact does not correspond to the reviewed source, or is not reproducible.
- Defense: reproducible sdist (byte-identical two-build check), hermetic published-artifact cleanroom
  gate, and the SLSA-L3-shape reusable attest workflow (signing separated from the build). See
  `AUDITOR_OPEN_POINTS.md` D for what the reviewer still confirms on a real published artifact.

## Scope freeze for the external audit

The audit-candidate attack surface the external reviewer is asked to examine is the Trusted-Core
verifier set named in `index.json` conclusion C2 plus the relation ladder (C3) and the anchor verifiers
(C1). Everything the machine cannot decide is itemised in `AUDITOR_OPEN_POINTS.md`. The status stays
BETA / relation EXPERIMENTAL until that review closes.
