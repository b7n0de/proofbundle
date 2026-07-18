"""Tests for the fork-PR secret-isolation guard.

The guard proves a fork PR can never reach a secret. These tests prove the guard itself is
correct AND has teeth. The `test_bypass_*` cases are the concrete evasions an independent
6-lens review found against the first version — each MUST now be caught (regression lock).
"""
import importlib.util
import unittest
from pathlib import Path

try:
    import yaml
except ImportError:  # PB-2026-0718-L6-01: PyYAML is a dev-only dep — clean skip from a bare sdist install
    import pytest
    pytest.skip("PyYAML not installed (dev-only dependency)", allow_module_level=True)

_ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("fpi", _ROOT / "scripts" / "fork_pr_secret_isolation.py")
fpi = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fpi)


def _analyze(wf: dict, extra_lines=None):
    raw = yaml.safe_dump(wf).splitlines() + (extra_lines or [])
    return fpi.analyze_workflow("t.yml", wf, raw)


class ForkPrIsolationGuard(unittest.TestCase):
    def test_selfcheck_passes(self):
        self.assertTrue(fpi.selfcheck())

    def test_repo_workflows_are_isolation_safe(self):
        findings, n = fpi.scan(str(_ROOT / ".github" / "workflows"))
        self.assertGreater(n, 0, "no workflows scanned — path wrong?")
        self.assertEqual(findings, [], f"real workflows leak a fork vector: {findings}")

    def test_pull_request_target_pwn_flagged(self):
        wf = {"on": {"pull_request_target": None},
              "jobs": {"j": {"runs-on": "ubuntu-latest", "permissions": {"contents": "write"},
                             "steps": [{"uses": "actions/checkout@" + "a" * 40,
                                        "with": {"ref": "${{ github.event.pull_request.head.sha }}"}}]}}}
        f = _analyze(wf)
        self.assertTrue(any("pwn-request" in x for x in f))
        self.assertTrue(any("write permissions" in x for x in f))

    def test_github_token_is_not_a_repo_secret(self):
        wf = {"on": {"pull_request": None},
              "jobs": {"j": {"runs-on": "ubuntu-latest",
                             "steps": [{"env": {"T": "${{ secrets.GITHUB_TOKEN }}"}, "run": "true"}]}}}
        self.assertEqual(_analyze(wf), [])

    def test_self_hosted_on_fork_trigger_flagged(self):
        wf = {"on": {"pull_request": None},
              "jobs": {"j": {"runs-on": ["self-hosted", "linux"], "steps": [{"run": "true"}]}}}
        self.assertTrue(any("self-hosted" in x for x in _analyze(wf)))

    def test_unpinned_action_flagged(self):
        wf = {"on": {"pull_request": None},
              "jobs": {"j": {"runs-on": "ubuntu-latest", "steps": [{"uses": "actions/checkout@v4"}]}}}
        f = _analyze(wf, extra_lines=["      - uses: actions/checkout@v4"])
        self.assertTrue(any("not SHA-pinned" in x for x in f))

    def test_sha_pinned_action_ok(self):
        wf = {"on": {"pull_request": None},
              "jobs": {"j": {"runs-on": "ubuntu-latest",
                             "steps": [{"uses": "actions/checkout@" + "a" * 40}]}}}
        f = _analyze(wf, extra_lines=["      - uses: actions/checkout@" + "a" * 40])
        self.assertEqual([x for x in f if "SHA-pinned" in x], [])

    def test_trusted_only_triggers_are_na(self):
        wf = {"on": {"push": {"tags": ["v*"]}},
              "jobs": {"j": {"runs-on": "ubuntu-latest", "permissions": {"id-token": "write"},
                             "steps": [{"run": "echo ${{ secrets.PYPI_TOKEN }}"}]}}}
        self.assertEqual(_analyze(wf), [])

    def test_plain_pull_request_write_perm_not_flagged_as_token_leak(self):
        wf = {"on": {"pull_request": None},
              "jobs": {"j": {"runs-on": "ubuntu-latest", "permissions": {"contents": "write"},
                             "steps": [{"run": "true"}]}}}
        self.assertEqual([x for x in _analyze(wf) if "write permissions" in x], [])

    # ---- Regression locks: the concrete review bypasses (each MUST be caught) ----
    def test_bypass_root_env_secret(self):
        wf = {"on": {"pull_request_target": None}, "env": {"T": "${{ secrets.DEPLOY_TOKEN }}"},
              "jobs": {"j": {"runs-on": "ubuntu-latest", "steps": [{"run": "true"}]}}}
        self.assertTrue(any("workflow-root env" in x for x in _analyze(wf)))

    def test_bypass_secrets_inherit(self):
        wf = {"on": {"pull_request_target": None},
              "jobs": {"call": {"uses": "o/r/.github/workflows/x.yml@" + "a" * 40, "secrets": "inherit"}}}
        self.assertTrue(any("secrets: inherit" in x for x in _analyze(wf)))

    def test_bypass_bracket_secret_notation(self):
        wf = {"on": {"pull_request": None},
              "jobs": {"j": {"runs-on": "ubuntu-latest", "steps": [{"run": "echo ${{ secrets['DEPLOY'] }}"}]}}}
        self.assertTrue(any("DEPLOY" in x for x in _analyze(wf)))

    def test_bypass_gh_pr_checkout(self):
        wf = {"on": {"pull_request_target": None}, "permissions": {"contents": "read"},
              "jobs": {"j": {"runs-on": "ubuntu-latest", "steps": [{"run": "gh pr checkout 5"}]}}}
        self.assertTrue(any("pwn-request" in x for x in _analyze(wf)))

    def test_bypass_refs_pull_merge(self):
        wf = {"on": {"pull_request_target": None}, "permissions": {"contents": "read"},
              "jobs": {"j": {"runs-on": "ubuntu-latest",
                             "steps": [{"uses": "actions/checkout@" + "a" * 40,
                                        "with": {"ref": "refs/pull/${{ github.event.number }}/merge"}}]}}}
        self.assertTrue(any("pwn-request" in x for x in _analyze(wf)))

    def test_bypass_issue_comment_trigger(self):
        wf = {"on": {"issue_comment": None}, "permissions": {"contents": "write"},
              "jobs": {"j": {"runs-on": "ubuntu-latest", "steps": [{"run": "echo ${{ secrets.DEPLOY }}"}]}}}
        self.assertTrue(any("DEPLOY" in x for x in _analyze(wf)))

    def test_bypass_workflow_run_artifact_injection(self):
        wf = {"on": {"workflow_run": {"workflows": ["CI"]}}, "permissions": {"contents": "read"},
              "jobs": {"j": {"runs-on": "ubuntu-latest", "permissions": {"contents": "read"},
                             "steps": [{"uses": "actions/download-artifact@" + "a" * 40},
                                       {"run": "bash ./dist/build.sh"}]}}}
        self.assertTrue(any("injection" in x for x in _analyze(wf)))

    def test_bypass_missing_permissions_block_privileged(self):
        wf = {"on": {"pull_request_target": None},
              "jobs": {"j": {"runs-on": "ubuntu-latest", "steps": [{"run": "true"}]}}}
        self.assertTrue(any("NO explicit permissions" in x for x in _analyze(wf)))

    def test_bypass_reusable_workflow_call_secret(self):
        wf = {"on": {"workflow_call": None}, "permissions": {"contents": "write"},
              "jobs": {"j": {"runs-on": "ubuntu-latest", "steps": [{"run": "echo ${{ secrets.DEPLOY }}"}]}}}
        self.assertTrue(any("reusable" in x and "DEPLOY" in x for x in _analyze(wf)))

    # ---- Second adversarial round (re-review V2→V3): 6 further bypasses + 1 false positive ----
    def test_bypass_root_env_laundered_head_checkout(self):
        wf = {"on": {"pull_request_target": None}, "env": {"PR": "${{ github.event.pull_request.head.sha }}"},
              "jobs": {"j": {"runs-on": "ubuntu-latest", "permissions": {"contents": "read"},
                             "steps": [{"run": "git checkout ${{ env.PR }}"}]}}}
        self.assertTrue(any("pwn-request" in x for x in _analyze(wf)))

    def test_bypass_matrix_self_hosted(self):
        wf = {"on": {"pull_request": None},
              "jobs": {"j": {"runs-on": "${{ matrix.os }}",
                             "strategy": {"matrix": {"os": ["ubuntu-latest", "self-hosted"]}},
                             "steps": [{"run": "true"}]}}}
        self.assertTrue(any("self-hosted" in x for x in _analyze(wf)))

    def test_bypass_computed_secret_access(self):
        wf = {"on": {"pull_request_target": None}, "permissions": {"contents": "read"},
              "jobs": {"j": {"runs-on": "ubuntu-latest",
                             "steps": [{"run": "echo ${{ secrets[format('{0}_KEY', matrix.env)] }}"}]}}}
        self.assertTrue(any("computed secret" in x for x in _analyze(wf)))

    def test_bypass_artifact_python3_and_named_payload(self):
        for run in ("python3 payload.py", "node index.js", "sh x.sh"):
            wf = {"on": {"workflow_run": {"workflows": ["CI"]}}, "permissions": {"contents": "read"},
                  "jobs": {"j": {"runs-on": "ubuntu-latest", "permissions": {"contents": "read"},
                                 "steps": [{"uses": "actions/download-artifact@" + "a" * 40}, {"run": run}]}}}
            self.assertTrue(any("injection" in x for x in _analyze(wf)), run)

    def test_bypass_permissions_as_sequence(self):
        wf = {"on": {"pull_request_target": None},
              "jobs": {"j": {"runs-on": "ubuntu-latest", "permissions": [{"contents": "write"}],
                             "steps": [{"run": "true"}]}}}
        self.assertTrue(any("sequence" in x for x in _analyze(wf)))

    def test_secrets_inherit_does_not_leak_to_sibling_job(self):
        """FP fix: only the job that actually declares `secrets: inherit` is flagged, not a
        harmless sibling in the same privileged workflow."""
        wf = {"on": {"pull_request_target": None},
              "jobs": {"call": {"uses": "o/r/.github/workflows/x.yml@" + "a" * 40, "secrets": "inherit"},
                       "safe": {"runs-on": "ubuntu-latest", "permissions": {"contents": "read"},
                                "steps": [{"run": "echo hi"}]}}}
        f = _analyze(wf)
        self.assertTrue(any("call:" in x and "inherit" in x for x in f))
        self.assertFalse(any("safe:" in x and "inherit" in x for x in f))

    def test_composite_action_secret_and_unpinned_caught(self):
        """A local composite action reached by a fork-reachable workflow is part of the surface."""
        import os
        import shutil
        import tempfile
        d = tempfile.mkdtemp()
        try:
            os.makedirs(os.path.join(d, ".github/workflows"))
            os.makedirs(os.path.join(d, ".github/actions/x"))
            with open(os.path.join(d, ".github/workflows/w.yml"), "w") as fh:
                fh.write("on:\n  pull_request_target:\n    branches: [main]\npermissions:\n"
                         "  contents: read\njobs:\n  j:\n    runs-on: ubuntu-latest\n"
                         "    steps:\n      - uses: ./.github/actions/x\n")
            with open(os.path.join(d, ".github/actions/x/action.yml"), "w") as fh:
                fh.write("runs:\n  using: composite\n  steps:\n"
                         "    - run: echo ${{ secrets.INNER }}\n      shell: bash\n"
                         "    - uses: actions/setup-node@v4\n")
            findings, _ = fpi.scan(os.path.join(d, ".github/workflows"))
            self.assertTrue(any("composite" in x and "INNER" in x for x in findings))
            self.assertTrue(any("composite" in x and "not SHA-pinned" in x for x in findings))
        finally:
            shutil.rmtree(d)

    # ---- Third adversarial round (re-review V3→V4): 5 further bypasses + 2 false positives ----
    def test_bypass_merge_commit_sha_checkout(self):
        wf = {"on": {"pull_request_target": None}, "permissions": {"contents": "read"},
              "jobs": {"j": {"runs-on": "ubuntu-latest",
                             "steps": [{"uses": "actions/checkout@" + "a" * 40,
                                        "with": {"ref": "${{ github.event.pull_request.merge_commit_sha }}"}}]}}}
        self.assertTrue(any("pwn-request" in x for x in _analyze(wf)))

    def test_bypass_head_repo_full_name_checkout(self):
        wf = {"on": {"pull_request_target": None}, "permissions": {"contents": "read"},
              "jobs": {"j": {"runs-on": "ubuntu-latest",
                             "steps": [{"uses": "actions/checkout@" + "a" * 40,
                                        "with": {"repository": "${{ github.event.pull_request.head.repo.full_name }}"}}]}}}
        self.assertTrue(any("pwn-request" in x for x in _analyze(wf)))

    def test_bypass_issues_discussion_triggers(self):
        for trig in ("issues", "discussion", "discussion_comment"):
            wf = {"on": {trig: None}, "permissions": {"contents": "write"},
                  "jobs": {"j": {"runs-on": "ubuntu-latest", "steps": [{"run": "echo ${{ secrets.DEPLOY }}"}]}}}
            self.assertTrue(any("DEPLOY" in x for x in _analyze(wf)), trig)

    def test_artifact_injection_no_false_positive_on_test_reporter(self):
        """FP-fix: download-artifact + a parse-only action (dorny/test-reporter) + a summary
        step must NOT be flagged as injection — only a `run:` that executes counts."""
        wf = {"on": {"workflow_run": {"workflows": ["CI"]}}, "permissions": {"contents": "read"},
              "jobs": {"j": {"runs-on": "ubuntu-latest", "permissions": {"contents": "read"},
                             "steps": [{"uses": "actions/download-artifact@" + "a" * 40, "with": {"path": "./artifacts"}},
                                       {"uses": "dorny/test-reporter@" + "a" * 40},
                                       {"run": "echo done >> $GITHUB_STEP_SUMMARY", "shell": "bash"}]}}}
        self.assertFalse(any("injection" in x for x in _analyze(wf)))

    def test_artifact_injection_still_caught_on_real_exec(self):
        wf = {"on": {"workflow_run": {"workflows": ["CI"]}}, "permissions": {"contents": "read"},
              "jobs": {"j": {"runs-on": "ubuntu-latest", "permissions": {"contents": "read"},
                             "steps": [{"uses": "actions/download-artifact@" + "a" * 40},
                                       {"run": "bash ./artifact/report.sh"}]}}}
        self.assertTrue(any("injection" in x for x in _analyze(wf)))

    def test_composite_transitive_and_internal_checkout(self):
        """Two-level composite chain (inner secret) + a composite that checks out PR head itself."""
        import os
        import shutil
        import tempfile
        d = tempfile.mkdtemp()
        try:
            os.makedirs(os.path.join(d, ".github/workflows"))
            os.makedirs(os.path.join(d, ".github/actions/outer"))
            os.makedirs(os.path.join(d, ".github/actions/inner"))
            with open(os.path.join(d, ".github/workflows/w.yml"), "w") as fh:
                fh.write("on:\n  pull_request_target:\n    branches: [main]\npermissions:\n"
                         "  contents: read\njobs:\n  j:\n    runs-on: ubuntu-latest\n"
                         "    steps:\n      - uses: ./.github/actions/outer\n")
            with open(os.path.join(d, ".github/actions/outer/action.yml"), "w") as fh:
                fh.write("runs:\n  using: composite\n  steps:\n    - uses: ./.github/actions/inner\n")
            with open(os.path.join(d, ".github/actions/inner/action.yml"), "w") as fh:
                fh.write("runs:\n  using: composite\n  steps:\n"
                         "    - run: echo ${{ secrets.PYPI_TOKEN }}\n      shell: bash\n"
                         "    - uses: actions/checkout@" + "b" * 40 + "\n"
                         "      with:\n        ref: ${{ github.event.pull_request.head.sha }}\n")
            findings, _ = fpi.scan(os.path.join(d, ".github/workflows"))
            self.assertTrue(any("inner" in x and "PYPI_TOKEN" in x for x in findings), findings)
            self.assertTrue(any("inner" in x and "internally" in x for x in findings), findings)
        finally:
            shutil.rmtree(d)


    # ---- Final verify (V4→V5): GHA context names are case-insensitive ----
    def test_bypass_uppercase_secrets(self):
        wf = {"on": {"pull_request_target": None}, "permissions": {"contents": "read"},
              "jobs": {"j": {"runs-on": "ubuntu-latest", "steps": [{"run": "echo ${{ Secrets.PYPI_TOKEN }}"}]}}}
        self.assertTrue(any("PYPI_TOKEN" in x for x in _analyze(wf)))

    def test_bypass_uppercase_head_checkout(self):
        wf = {"on": {"pull_request_target": None}, "permissions": {"contents": "read"},
              "jobs": {"j": {"runs-on": "ubuntu-latest",
                             "steps": [{"uses": "actions/checkout@" + "a" * 40,
                                        "with": {"ref": "${{ GitHub.Event.Pull_Request.Head.Sha }}"}}]}}}
        self.assertTrue(any("pwn-request" in x for x in _analyze(wf)))

    def test_github_token_lowercase_still_allowed(self):
        """The GITHUB_TOKEN exemption is case-insensitive too — `secrets.github_token` is fine."""
        wf = {"on": {"pull_request": None},
              "jobs": {"j": {"runs-on": "ubuntu-latest",
                             "steps": [{"env": {"T": "${{ secrets.github_token }}"}, "run": "true"}]}}}
        self.assertEqual([x for x in _analyze(wf) if "secret" in x], [])


if __name__ == "__main__":
    unittest.main()
