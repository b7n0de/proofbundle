# Testing strategy — catching input variations

How proofbundle tries to catch the *variations* of an input, not just the happy path. This records the
methods in use, why, and the honest state of each (SOTA references at the end).

## Layers

1. **Fixed unit + negative vectors.** Every crypto-critical verify path has malformed / tamper / wrong-key
   / boundary vectors that must fail closed. This is the baseline (~1180 tests).
2. **Differential / interop.** A second, independent implementation verifies the same artifact
   (BBS cross-impl, the SD-JWT reference fixture, the O8 Rust verifier reproducing the conformance
   corpus). Catches spec-divergence a single implementation cannot see.
3. **Property-based (Hypothesis).** Generational testing: a strategy produces hundreds of input
   variations per run and a *metamorphic relation* (a property that must hold for ALL of them) is
   asserted. This is the primary "catch all variations" mechanism — a single property replaces an
   unbounded set of hand vectors.
4. **Fuzz (never-crash).** `test_fuzz_parsers.py` asserts the parsers never raw-crash on arbitrary bytes.
5. **Mutation (anti-Goodhart).** `scripts/mutation_check.py` breaks each security check and requires the
   suite to go red — proving the green suite means something (see below).

## Property-based coverage

| Area | File | Relation |
|---|---|---|
| Merkle RFC 6962 | `test_merkle_property.py` | inclusion/consistency roundtrip; tampered leaf rejected |
| content root (ADR 0002) | `test_content_root_property.py` | producer == verifier root; key-order invariance |
| subject binding (O6) | `test_content_root_property.py` | derived classifies DERIVED; any predicate mutation → EXTERNAL_ATTESTED; malformed never crashes |
| hash agility (B2) | `test_anchor_longevity_property.py` | every current alg round-trips; any single mismatched leg fails; unknown ids fail closed |
| renewal chain (B3) | `test_anchor_longevity_property.py` | any ascending mixed-mode sequence verifies; any data-object tamper fails |
| SD-JWT (adversarial) | `test_sdjwt_adversarial.py` | algorithm confusion (`none`/`HS256`/absent) never yields sig_ok; disclosure tamper / uncommitted disclosure breaks structure |
| DSSE (adversarial) | `test_dsse_adversarial.py` | multi-sig array (valid-among-forged verifies, forged-only rejected); PAE length-prefix prevents type/body collision; payloadType bound into signed bytes; url-safe b64 accepted |
| Merkle consistency | `test_merkle_consistency_property.py` | consistency roundtrip; tampered proof element / swapped roots / wrong second root rejected |
| Witness quorum dedup | `test_checkpoint_quorum_property.py` | one key under ANY number of names counts as one witness; distinct-key count is name-independent (split-view resistance, generalizing the fixed 2-name case) |

A property test earns its keep by *finding* spec imprecision: writing the subject-binding property
immediately surfaced that a literal `None` predicate is (correctly) treated as unbindable — the property
was refined to match the real contract, which a fixed vector would not have exposed.

## Ranked remaining gaps (from the 2026-07-14 coverage survey)

Done across three waves: content root, subject binding, hash agility, renewal, SD-JWT, DSSE
multi-signature, Merkle consistency, witness-quorum dedup (generative).

The other survey items turned out to be **already covered** by fixed adversarial tests PLUS a mutation
operator (verified, not a defer): `anchors_ots` WP-A1 backdating (`test_anchors_ots.py`
frozen-vs-relying-party cases + the `anchors_ots: WP-A1 needs_rp_trust self-trust` mutation operator);
`tlogproof` verdict conjunction (each leg's failure is a fixed red case — `test_red_wrong_leaf` /
`_wrong_log_key` / `_quorum_not_met` — plus the `tlogproof: verdict conjunction -> disjunction` mutation
operator); `checkpoint` domain separation (`test_red_log_vkey_is_not_a_witness_vkey` + the `cosign: keyID
domain separation` operator); `kbjwt` (27 adversarial tests + the `kbjwt: sd_hash binding` operator). A
generative version of these would be complementary but low marginal value given the fixed + mutation
coverage. Genuinely-thin coverage has been closed.

## Mutation testing — the anti-Goodhart gate (already in CI)

Mutation testing (break the code, require the suite to go RED) is the meta-check that proves the tests
catch variations. proofbundle does NOT use an off-the-shelf mutator; it ships a curated, differential
gate `scripts/mutation_check.py` (the CI `mutation` job). Each operator disables ONE security check
(binding, framing, key-domain separation, quorum counting, fail-open, output truthfulness) and the gate
asserts every non-equivalent mutant is KILLED (strictly more red than the baseline); documented-equivalent
mutants are asserted to SURVIVE (honesty both ways — a curation an untargeted mutator cannot express).

The anchor-longevity work added three operators for the new modules (killed by the unittest property
tests, which is what `unittest discover` runs): B2 dual-hash digest comparison disabled → forged bytes
verify; B2 deprecated-algorithm reject disabled; B3 ArchiveTimeStamp covering check disabled → tamper /
break survives. Extend this list whenever a new fail-closed check ships.

Aside: the generic tool `mutmut` 3.6 was tried and does not fit this `src/`-layout — its sandbox copies
only the configured module and breaks intra-package imports (`hashalg` importing `.errors`). No
`[tool.mutmut]` config is committed (a config that does not run cleanly would be a false green). The
curated `mutation_check.py` gate is the working mechanism and is stronger here because it is targeted and
false-positive-free.

## References (SOTA, 2026)

Property-based testing is fuzzing that asserts semantic relations, not just no-crash
([nelhage](https://blog.nelhage.com/post/property-testing-is-fuzzing/)); Hypothesis is the definitive
Python PBT tool ([HypoFuzz literature](https://hypofuzz.com/docs/literature.html)). Differential fuzzing
raises assurance by comparing implementations
([Quarkslab](https://blog.quarkslab.com/differential-fuzzing-for-cryptography.html),
[AdaCore](https://www.adacore.com/blog/automated-assurance-through-differential-fuzzing)). PBT for
security protocols: [MDPI Computers 14(5) 179](https://www.mdpi.com/2073-431X/14/5/179).
