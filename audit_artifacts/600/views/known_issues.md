### Known issues, 6.0.0

* A1 (P2), The trust anchor lives in `audit_artifacts/`, the one directory the subject tree digest excludes. The anchor is therefore outside the digest that is supposed to
* A2 (P2), Both read their result without reading the `population_complete` bound — the same shape as `N17`, one gate over. A verdict from an incomplete population reads l
* A3 (P3), The evidence paths are hard-wired to `audit_artifacts/360` instead of being derived from the version under test. It works today because 6.0.0 reuses that direct
* N14 (P2), Class: a signing path in the shipped tree. INSTANCE `scripts/sign_readiness_artifact.py` is CLOSED — the inline `--privkey-file` mode is gone and, measured by A
* N15 (P2), Both distributions of 6.0.0 are **bit-reproducible as shipped**, and this section states the property with the path to recompute it rather than a digest, becaus
* N16 (P2), The published composite action interpolates two untrusted inputs straight into a `run:` shell body; byte-identical to the public `v1.0.0` tag, so 6.0.0 neither 
* N17 (P2), The parity gate swallows an unparseable source file and then rules from the ABSENCE of complaints over what is left; on this candidate the population is complet
* N18 (P2), `pip install <sdist> && pytest` without the `[test]` extras is RED, not skipped, while `pyproject.toml` promises "clean skips"
* N19 (P3), The mutation gate collects with `unittest discover` and therefore measures 2537 of 3702 tests, **measured at `59d0679`**; 59 of 252 test files are invisible to 
* N20 (P3), One mutation operator is NOT MEASURABLE rather than killed or survived — it removes the resource ceiling under test and the run reached 111 GiB resident before 
* N21 (P3), **The release-deciding check `C12.2` flips PASS to FAIL on 2027-09-07 by design.** The closing-round fix makes an expired anchor key authorise nothing *now*, an

Generated from the findings register. The register carries the rest.
