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

A property test earns its keep by *finding* spec imprecision: writing the subject-binding property
immediately surfaced that a literal `None` predicate is (correctly) treated as unbindable — the property
was refined to match the real contract, which a fixed vector would not have exposed.

## Ranked remaining gaps (from the 2026-07-14 coverage survey)

Done in the first two waves: content root, subject binding, hash agility, renewal, SD-JWT, DSSE
multi-signature, Merkle consistency. Still to add, most-critical first: `checkpoint.witness_quorum`
key-material dedup (one key, many names → one witness) + domain separation (a log key must never be
accepted as a witness); `anchors_ots` frozen-vs-relying-party backdating vectors;
`tlogproof.verify_tlog_proof` verdict-conjunction independence; `kbjwt` disclosure-set drop/swap
metamorphic. These are tracked, not done.

## Mutation testing — evaluated, follow-up

Mutation testing (mutate the source, require the suite to KILL each mutant) is the meta-check that proves
the tests actually catch variations. `mutmut` 3.6 was evaluated: its sandbox copies only the configured
`source_paths` into a `mutants/` tree, which breaks a `src/`-layout package's intra-package imports
(`hashalg` importing `.errors` fails to resolve). Shipping a config that does not run cleanly would be a
false green, so no `[tool.mutmut]` config is committed. The resolution path (copy the whole package into
the sandbox, or a tool that mutates the installed package in place, e.g. cosmic-ray) is a tracked
follow-up. Until then, property-based generation is the working variation-coverage layer.

## References (SOTA, 2026)

Property-based testing is fuzzing that asserts semantic relations, not just no-crash
([nelhage](https://blog.nelhage.com/post/property-testing-is-fuzzing/)); Hypothesis is the definitive
Python PBT tool ([HypoFuzz literature](https://hypofuzz.com/docs/literature.html)). Differential fuzzing
raises assurance by comparing implementations
([Quarkslab](https://blog.quarkslab.com/differential-fuzzing-for-cryptography.html),
[AdaCore](https://www.adacore.com/blog/automated-assurance-through-differential-fuzzing)). PBT for
security protocols: [MDPI Computers 14(5) 179](https://www.mdpi.com/2073-431X/14/5/179).
