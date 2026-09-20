### Known issues, 6.1.0

<!-- proofbundle:verbatim-quote:begin -->
* COMMIT-PATTERN-DOMAIN-NOT-AT-VERIFY-BOUNDARY-01 (NOT MEASURED), Carried in `tests/test_eval_claim_domains_are_enforced.py` as `BEKANNTE_LUECKEN` -- which, like the A-17 fix above, arrives with the verify-boundary pull reques
* SMALL-ORDER-KEY-AT-CARRIER-SIGNATURE-01 (NOT MEASURED), Refusing small-order keys at this one block is a code change with its own catch proof, not a documentation edit, so it is not in this cut.
* SHIPPED-TOOL-VERDICT-NOT-RE-RUN-01 (NOT MEASURED), **A shipped tool verdict is quoted but not re-run.** `pyproject.toml` states that eight mypy versions and six ruff versions exit 0 over this tree.
* DREI-VERBRAUCHER-COERCEN-PASSED-DOKUMENTIERT-IST-EINER-01 (NOT MEASURED), Target 6.2.0, and as a CLASS fix rather than three guards: one check that every public exporter passes through, with the catch-proof at the public functions ins
<!-- proofbundle:verbatim-quote:end -->

Generated from the findings register. The register carries the rest.
