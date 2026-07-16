# Formal model (Fundament F3) — the versioned lineage-ladder proof

`model.py` is ONE growing, versioned formal model of the relation-lineage **logic**. It exists so
that 3.4.0 / 3.5.0 / 3.6.0 add their invariants as new proof obligations to a single model instead
of re-modelling from scratch each release (Front-Loading, `GO_OWNER_PB_ROADMAP_FRONTLOAD_20260716`).

## What is proven

The aggregation ladder mirrors `proofbundle.relation.verify_relationship_edges` exactly:

```
rank  NOT_EVALUATED = 0  <  VERIFIED = 1  <  DECLARED_UNRESOLVED = 2  <  FAIL = 3
aggregate(edges) = max rank present            (empty edge set -> NOT_EVALUATED)
```

Obligations (each tagged `version_added`, additive):

| id | added | property |
|---|---|---|
| O1 LADDER_IS_JOIN | 3.3.1-frontload | aggregate == the max-rank join over per-edge resolutions |
| O2 FAIL_ABSORBING | 3.3.1-frontload | aggregate is FAIL **iff** at least one edge is FAIL (one poisoned ancestor poisons the chain) |
| O3 UNRESOLVED_NOT_UPGRADED | 3.3.1-frontload | an unresolved edge is never aggregated up to VERIFIED |
| O4 SELF_REF_FAILS | 3.3.1-frontload | a self-referential edge (target == subject) resolves FAIL — cross-checked against the real implementation |
| O5 TARGET_PIN_NOT_CRYPTO | 3.4.0 | *reserved* — a declared target-pin is orthogonal to cryptoValid |
| O6 RETRACTS_NEVER_RAISES | 3.5.0 | *reserved* — a retracts relation never raises cryptoValid |
| O7 PAYLOADTYPE_BINDING | 3.6.0 | *reserved* — payloadType binding (33-check matrix) |

A `reserved` obligation is declared honestly and is **not** counted as proven — no fabricated proof.

## Two backends, reported honestly (No-Fake)

- **bounded_enumeration** (always): every obligation predicate is checked exhaustively over every
  rank-tuple up to `--bound` edges (default 5) — a complete proof over the bounded domain.
- **z3** (when the `formal` extra is installed): *additionally* proves the max-join identity and its
  two safety corollaries for a much higher symbolic arity (`4**16`, far past what enumeration can
  walk). z3 never replaces the per-obligation enumeration; it only extends the core identity. The
  output states which ran (`prover_mode`).

The model is also **grounded in the real code**: `agrees_with_implementation()` runs
`verify_relationship_edges` on constructed edge configs and asserts the aggregate matches the
modelled ladder (self-ref -> FAIL, FAIL absorbs a co-present unresolved edge, a lone unresolved edge
stays DECLARED_UNRESOLVED, no profile -> NOT_EVALUATED). The model is not a disconnected abstraction.

## Honest scope (the boundary an external audit still owns)

Per IACR 2025/980 (formal verification of crypto protocol implementations in Rust) and OwlC
(IACR 2025/1092): a model of this kind covers **logic** — the ladder, the aggregation, the
self-reference/cycle binding, the "lineage never upgrades cryptoValid" separation. It does **NOT**
cover:

- cryptographic **primitive hardness** (Ed25519, SHA-256 — assumed, not proven here);
- **side-channel** freedom;
- **whole-program** correctness.

Those stay external-audit terrain and are documented as such in
`docs/readiness_pack/tamper_resistance.md` and `docs/readiness_pack/OPEN_QUESTIONS.md`. This model
proves the part that is mechanically decidable, and says plainly which part is not.

## Run

```bash
python formal/model.py            # human summary, exit 0 iff all non-reserved obligations proven
python formal/model.py --json     # machine-readable result (prover_mode, obligations, crosscheck)
pip install -e ".[formal]"        # adds z3-solver -> the z3-extended symbolic proof also runs
```
