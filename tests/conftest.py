"""Shared pytest configuration.

PKG-2026-0718-01 (RE-GATE): the sdist ships tests/ (MANIFEST graft) so `pip install <sdist> && pytest`
is a genuinely self-testable package. A SPECIFIC SET of tests, however, assert facts about the
REPO / CI / Rust / docs LAYOUT — the contents of `.github/workflows`, the Rust verifier source under
`tools/`, `SPEC.md` / `README.md` / `CITATION.cff`, and the audit records — material the sdist
DELIBERATELY prunes (it is not a Python-package artifact; shipping the 138M Rust tree or the CI configs
in a Python sdist is a category error). Those tests are meaningless outside a git checkout, so they SKIP
when the repo-only markers are absent (i.e. when running from an extracted sdist / installed wheel),
turning 25 false runtime FAILURES into honest SKIPs — the sdist then runs clean. In a real checkout (CI)
every marker is present, NOTHING is skipped, and coverage is exactly as before (this file is a pure no-op
in the repo). This is the No-Fake honest form of "self-testable": the package-level tests run; the
repo-layout tests announce themselves as N/A rather than failing or being silently dropped.
"""
import pathlib

import pytest

_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
# A git checkout always carries these; the sdist prunes/omits them (.github, the Rust tree, the spec
# source). Their ABSENCE means we are running from a distributed artifact, not the repo.
_REPO_ONLY_MARKERS = (".github", "tools", "SPEC.md")

# The exact repo-context tests (module stem :: test method) whose assertions are about the repo/CI/Rust/
# docs LAYOUT rather than the installed package. Derived from the from-sdist run: these read files the
# sdist does not (and should not) ship. Explicit + documented — a new repo-context test adds its id here.
# NOTE: test_renewal_policy::test_shipped_example_policy_loads_and_evaluates is NOT here — its example
# (docs/adr/renewal_policy.example.json) is a genuinely shipped artifact, fixed by `graft docs/adr`.
_REPO_CONTEXT_TESTS = frozenset({
    "test_anchors_chia_claims::test_markovian_absent_on_chia_surface",
    "test_anchors_chia_claims::test_no_uncaveated_overclaim_on_the_chia_surface",
    "test_audit_candidate_360::test_matrix_is_ready_and_has_33_checks",
    "test_audit_candidate_360::test_c12_2_green_on_real_repo",
    "test_audit_candidate_360::test_c1_1_green_on_real_repo",
    # L6-02: the c1_1 CI-gate discrimination tests build temp workflow YAML and parse it via
    # audit_candidate_matrix._ci_workflow_facts -> `import yaml`. PyYAML is a [test]-extra dep, so from a bare
    # `[eval]` sdist install c1_1 honestly returns DATA_BLOCKED and these asserts fail -> skip them outside a
    # git checkout (they run in the normal `test` CI job which has the dev deps).
    "test_audit_candidate_360::test_c1_1_fails_when_second_gate_missing",
    "test_audit_candidate_360::test_c1_1_fails_when_second_gate_is_not_a_test_gate",
    "test_audit_candidate_360::test_c1_1_which_pytest_is_not_a_test_run",
    "test_audit_candidate_360::test_c1_1_collect_only_is_not_a_test_run",
    "test_audit_candidate_360::test_c1_1_real_unittest_discover_passes",
    "test_audit_candidate_360::test_variant3_pytest_only_in_comment_echo_or_disabled_job_fails_c1_1",
    "test_audit_candidate_360::test_variant3b_real_executing_run_step_passes_c1_1",
    # PKG-01: these read REPO/audit_artifacts/findings_register_361.json, which `prune audit_artifacts` in
    # MANIFEST.in deliberately drops from the sdist — skip them outside a git checkout (never in CI).
    "test_audit_candidate_360::test_c12_2_fails_on_tampered_register",
    "test_audit_candidate_360::test_c12_2_fails_on_foreign_key_register",
    "test_findings_register_rt10::test_control_real_register_verifies",
    "test_findings_register_rt10::test_tampered_status_fails",
    "test_findings_register_rt10::test_foreign_key_fails",
    "test_findings_register_rt10::test_emptied_findings_fails",
    "test_claims_hygiene::test_real_docs_are_clean",
    "test_claims_hygiene::test_every_default_doc_exists_and_scan_covers_all",
    "test_claims_hygiene::test_injected_overclaim_in_every_listed_doc_fails",
    "test_claims_hygiene::test_main_default_run_includes_cli_surface",
    "test_claims_hygiene::test_new_priority_docs_are_in_scan_set_and_clean",
    "test_docs_truth::test_citation_version_matches_pyproject",
    "test_docs_truth::test_docs_references_are_current",
    "test_docs_truth::test_non_claims_covers_decision_authorization_boundary",
    "test_docs_truth::test_readme_carries_no_hardcoded_test_count",
    "test_docs_truth::test_spec_revision_matches_spec_md",
    "test_fork_pr_secret_isolation::test_repo_workflows_are_isolation_safe",
    "test_intoto_claims_hygiene::test_intoto_status_is_labelled_proposed",
    "test_intoto_claims_hygiene::test_no_overclaim_phrase_on_the_intoto_surface",
    "test_intoto_spec_diff::test_implementation_doc_matches_code",
    "test_intoto_spec_diff::test_upstream_draft_uses_the_intoto_namespace_and_notes_the_vendor_alias",
    "test_relation_statement_rust_parity::test_relation_surface_is_covered_and_integrity_ok",
    "test_roadmap_frontload_foundations::test_pack_is_grounded_in_real_artifacts",
    "test_roadmap_frontload_foundations::test_released_version_has_audit_record",
    "test_rust_parity_gate::test_real_repo_main_rs_has_the_expected_subcommands",
    "test_rust_parity_gate::test_real_repo_registry_is_honest_strict_mode_exits_0",
})


def running_in_repo_checkout() -> bool:
    """True iff the repo-only markers are present (a git checkout / CI), False from a distributed sdist."""
    return any((_REPO_ROOT / m).exists() for m in _REPO_ONLY_MARKERS)


def pytest_collection_modifyitems(config, items):
    if running_in_repo_checkout():
        return  # a real checkout: run everything (the CI path — coverage unchanged, pure no-op)
    skip = pytest.mark.skip(reason="repo-context test: asserts repo/CI/Rust/docs layout not shipped in the "
                                   "sdist — N/A outside a git checkout (PKG-2026-0718-01)")
    for item in items:
        stem = pathlib.Path(str(getattr(item, "fspath", ""))).stem
        method = getattr(item, "originalname", None) or item.name
        if f"{stem}::{method}" in _REPO_CONTEXT_TESTS:
            item.add_marker(skip)
