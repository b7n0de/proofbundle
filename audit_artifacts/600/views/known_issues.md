### Known issues, 6.0.0

* A2 (P2), Both read their result without reading the `population_complete` bound — the same shape as `N17`, one gate over. A verdict from an incomplete population reads l
* A3 (P3), The evidence paths are hard-wired to `audit_artifacts/360` instead of being derived from the version under test. It works today because 6.0.0 reuses that direct
* N14 (P2), Class: a signing path in the shipped tree. INSTANCE `scripts/sign_readiness_artifact.py` is CLOSED — the inline `--privkey-file` mode is gone and, measured by A
* N15 (P2), Both distributions of 6.0.0 are **bit-reproducible as shipped**, and this section states the property with the path to recompute it rather than a digest, becaus
* N16 (P2), The published composite action interpolates two untrusted inputs straight into a `run:` shell body; byte-identical to the public `v1.0.0` tag, so 6.0.0 neither 
* N17 (P2), The parity gate swallows an unparseable source file and then rules from the ABSENCE of complaints over what is left; on this candidate the population is complet
* N18 (P2), `pip install <sdist> && pytest` without the `[test]` extras is RED, not skipped, while `pyproject.toml` promises "clean skips"
* N19 (P3), The mutation gate collects with `unittest discover` and therefore measures 2537 of 3702 tests, **measured at `59d0679`**; 59 of 252 test files are invisible to 
* N20 (P3), One mutation operator is NOT MEASURABLE rather than killed or survived — it removes the resource ceiling under test and the run reached 111 GiB resident before 
* R1 (NOT MEASURED), A shipped specification artefact contradicts the shipped code — open, re-measured
* R2 (NOT MEASURED), A subfield reads safer than before, against the invariant the round enforced — open, NOT re-measured
* R3 (NOT MEASURED), `resolve_receipt_chain` raises a raw exception on a non-mapping envelope — open, re-measured
* R4 (NOT MEASURED), Verify sites report an internal error for a truthy non-list — open, re-measured in count only
* R5 (NOT MEASURED), The guard that should catch changelog omissions is blind to content — open, unchanged by design
* R6 (NOT MEASURED), The witness cannot see the lenses of a round run in a foreign repository — open, unchanged
* R7 (NOT MEASURED), Three numbers in shipped artefacts are wrong, each already wrong when written — open, re-measured
* S5 (NOT MEASURED), The two new riegel are bound one at a time, never together — open, named by the cross-family lens
* S6 (NOT MEASURED), A REQUIRED check is red because a wall-clock ceiling is a number from one machine — open, calibrated, not yet measured in CI
* S8 (NOT MEASURED), The reference load measures sha256 only, and six of the twelve axes are not hash-bound — open, NOT measurable on one machine
* S9 (NOT MEASURED), The one-second budget is a declared policy, not a derived number — open by design, named because it is load-bearing
* S10 (NOT MEASURED), Four lines of the advisory matrix are red because three evidence artefacts bind a tree the candidate has overtaken — open, owner-gated on the signature

Generated from the findings register. The register carries the rest.
