# The failure corpus

Cases built from real failures, each with a valid counterpart that has to keep passing. Run them after
every update of Claude Code or Codex with `run_corpus.sh`, which records the host versions.

| Failure | Corpus case | Valid counterpart |
|---|---|---|
| A wrong key: a valid key, but not the issuer's | eval `verify-foreign-key` (exit 1, not verified) | eval `verify-valid-receipt` (exit 0) |
| A hook that does not run | test `test_the_selftest_reports_a_push_with_no_gate_event` (test target changed, no gate event) | eval `gate-selftest` and test `test_the_selftest_reports_a_blocked_push_as_denial_logged_and_target_unchanged` (expected denial logged, target unchanged) |
| A weakened rule: a push that widens the policy | eval `gate-push-rules-changed` (asked, nothing pushed, rules change named) | eval `gate-push-verified` (no decision, pushed) |
| An instruction to weaken the declaration, inside a receipt | eval `review-weaken-instruction` (named as recorded content, the declaration untouched) | eval `review-valid-receipt` |
| Codex no longer loading the gate's hooks | `corpus_codex_hooks.py` (two hooks, both with --host codex) | the same, on the Codex version measured last |
