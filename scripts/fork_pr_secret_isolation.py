#!/usr/bin/env python3
"""fork_pr_secret_isolation.py — prove that a fork PR can never reach a secret.

Invariant (the part this guard MECHANICALLY enforces): no *fork-reachable* job in this repo's
workflows may reach a repository secret, carry a writable GITHUB_TOKEN, run on a self-hosted
runner, run an unpinned third-party action, or run under a privileged trigger while checking
out and executing the PR head code.

Fork-reachable triggers = anything a user with only READ access (i.e. a fork contributor) can
cause. These are ``pull_request`` (safe by design: no secrets, read-only token) plus the
PRIVILEGED ones that run in the base-repo context WITH secrets: ``pull_request_target``,
``workflow_run``, ``issue_comment``, ``pull_request_review``, ``pull_request_review_comment``.
Trusted-only triggers (``push``, ``push: tags``, ``release``, ``schedule``,
``workflow_dispatch``, ``branch_protection_rule``) are N/A — a fork cannot fire them.
``workflow_call`` (reusable) is analysed too: a reusable workflow that itself touches secrets/
write/self-hosted is a latent leak if any fork-reachable caller invokes it.

What it checks (per fork-reachable job, and workflow-root env):
  * a ``secrets.NAME`` / ``secrets['NAME']`` / ``secrets: inherit`` reference (not GITHUB_TOKEN),
  * ``permissions: write`` under a PRIVILEGED trigger, or NO ``permissions:`` block at all under
    a privileged trigger (implicit-broad-token, OpenSSF Scorecard heuristic),
  * a ``self-hosted`` runner,
  * a third-party ``uses:`` not pinned to a 40-hex commit SHA,
  * a privileged trigger that checks out the PR head — literal ``head.ref``/``head.sha``/
    ``head_ref`` OR ``gh pr checkout`` OR ``refs/pull/<n>/{merge,head}`` OR ``pull/<n>/head``,
  * ``workflow_run`` that downloads an artifact and then executes it (artifact injection).

It also follows LOCAL composite-action calls (``uses: ./.github/actions/…``) into their
``action.yml`` and audits those for secret references and unpinned nested actions, and resolves
``strategy.matrix`` runners so a matrix-injected ``self-hosted`` cannot hide.

HONEST SCOPE (what it does NOT do): pure static YAML/text analysis. It does not resolve the
runtime semantics of an action, does not follow the reusable-workflow call graph across OTHER
repos (only local composite actions), does not detect script injection from unsanitised
``github.event.*`` interpolation, and does not model cache poisoning. Those remain review
responsibilities; see the runbook.

SOTA: GitHub Security Lab "Preventing pwn requests"; GitHub "Securely using pull_request_target";
OpenSSF Scorecard Dangerous-Workflow / Token-Permissions / Pinned-Dependencies; tj-actions
tag-repoint incident (March 2025). Exit 0 = clean, exit 1 = risk. ``--selfcheck`` proves teeth.
"""
from __future__ import annotations

import argparse
import glob
import json
import os
import re
import sys

try:
    import yaml
except ImportError:  # pragma: no cover - CI installs pyyaml for the guard job
    print(json.dumps({"result": "ERROR", "findings": ["pyyaml not installed — pip install pyyaml"]}))
    sys.exit(2)

_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
# secrets.NAME  OR  secrets['NAME'] / secrets["NAME"]  (both are valid GHA expression syntax).
# IGNORECASE: GHA context names are case-insensitive — `${{ Secrets.X }}` resolves the same as
# `${{ secrets.x }}`, so a one-letter uppercase must not evade detection (final-verify bypass).
_SECRET_RE = re.compile(r"secrets\.([A-Za-z_][A-Za-z0-9_]*)|secrets\[\s*['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]\s*\]",
                        re.IGNORECASE)
# PR-head checkout in all its common shapes (pwn-request when the trigger is privileged).
# Kept broad because GitHub itself (actions/checkout v7, June 2026) had to harden the same set
# server-side — merge_commit_sha and head.repo.full_name are canonical bypass shapes.
_HEAD_REF_RE = re.compile(
    r"pull_request\.head\.(ref|sha)|pull_request\.merge_commit_sha|"
    r"pull_request\.head\.repo\.full_name|github\.head_ref|gh\s+pr\s+checkout|"
    r"refs/pull/[^/\s]+/(merge|head)|pull/\$\{\{[^}]*\}\}/(merge|head)", re.IGNORECASE)
# Triggers a fork contributor (read access only) can cause. The privileged ones run WITH secrets.
# issues/discussion/discussion_comment: any user can open these on a public repo with zero perms.
_SAFE_FORK_TRIGGERS = {"pull_request"}
_PRIVILEGED_FORK_TRIGGERS = {"pull_request_target", "workflow_run", "issue_comment",
                            "pull_request_review", "pull_request_review_comment",
                            "issues", "discussion", "discussion_comment"}
_FORK_TRIGGERS = _SAFE_FORK_TRIGGERS | _PRIVILEGED_FORK_TRIGGERS
_ALLOWED_SECRETS = {"GITHUB_TOKEN"}


def _triggers(wf: dict) -> set[str]:
    on = wf.get("on") if isinstance(wf, dict) else None
    if on is None and isinstance(wf, dict):
        on = wf.get(True)  # YAML parses the bare key `on:` as the boolean True
    if isinstance(on, str):
        return {on}
    if isinstance(on, list):
        return {str(x) for x in on}
    if isinstance(on, dict):
        return {str(k) for k in on.keys()}
    return set()


def _as_text(node) -> str:
    return json.dumps(node, ensure_ascii=False, default=str)


_ALLOWED_SECRETS_CI = {s.upper() for s in _ALLOWED_SECRETS}


def _secret_names(text: str) -> list[str]:
    out = []
    for a, b in _SECRET_RE.findall(text):
        name = a or b
        if name and name.upper() not in _ALLOWED_SECRETS_CI:  # GHA context names are case-insensitive
            out.append(name)
    return out


def _has_secrets_inherit(node) -> bool:
    """`secrets: inherit` on a job that calls a reusable workflow forwards ALL repo secrets."""
    if isinstance(node, dict):
        if str(node.get("secrets")).strip().lower() == "inherit":
            return True
        return any(_has_secrets_inherit(v) for v in node.values())
    if isinstance(node, list):
        return any(_has_secrets_inherit(v) for v in node)
    return False


def _permissions_write(perms) -> bool:
    if perms is None:
        return False
    if isinstance(perms, str):
        return perms.strip() == "write-all"
    if isinstance(perms, dict):
        return any(str(v).strip() == "write" for v in perms.values())
    return False


def _unpinned_actions(text_lines: list[str]) -> list[str]:
    bad: list[str] = []
    for ln in text_lines:
        m = re.search(r"uses:\s*([^\s#]+)", ln)
        if not m:
            continue
        ref = m.group(1).strip().strip('"').strip("'")
        if ref.startswith("."):
            continue
        if ref.startswith("docker://") and "@sha256:" in ref:
            continue
        if "@" not in ref:
            bad.append(ref)
            continue
        if not _SHA_RE.match(ref.split("@", 1)[1]):
            bad.append(ref)
    return bad


def _runs_on_self_hosted(job: dict) -> bool:
    """A ``runs-on`` value OR any strategy.matrix value that can resolve to self-hosted.
    ``runs-on: ${{ matrix.os }}`` is only as safe as every matrix entry (re-review bypass #3)."""
    ro = job.get("runs-on")
    vals = ro if isinstance(ro, list) else [ro]
    if any("self-hosted" in str(v) for v in vals if v is not None):
        return True
    # If runs-on interpolates a matrix value, inspect every matrix entry.
    if any("matrix" in str(v) for v in vals if v is not None):
        matrix = (((job.get("strategy") or {}) if isinstance(job.get("strategy"), dict) else {}).get("matrix")) or {}
        return "self-hosted" in _as_text(matrix)
    return False


def _computed_secret_access(text: str) -> bool:
    """``secrets[<expr>]`` with a non-literal index (format(), matrix.x, env.X) — a documented
    per-environment secret-lookup idiom that literal-name matching misses (re-review bypass #4)."""
    for m in re.finditer(r"secrets\[\s*([^\]]+?)\s*\]", text, re.IGNORECASE):
        idx = m.group(1).strip()
        if not (idx.startswith("'") or idx.startswith('"')):  # a quoted literal is already caught by _SECRET_RE
            return True
    return False


def _permissions_is_sequence(perms) -> bool:
    """``permissions: [ ... ]`` — a list where a mapping is expected. GitHub rejects it, but a
    guard must not silently pass a shape it cannot reason about (re-review bypass #6)."""
    return isinstance(perms, list)


def _run_commands(job: dict) -> list[str]:
    """The literal `run:` shell commands of a job's steps (not with:-inputs, not shell: fields)."""
    cmds: list[str] = []
    for step in (job.get("steps") or []) if isinstance(job, dict) else []:
        if isinstance(step, dict) and isinstance(step.get("run"), str):
            cmds.append(step["run"])
    return cmds


def _downloads_and_executes_artifact(job: dict) -> bool:
    """workflow_run artifact-injection: download a fork-produced artifact, then run code from it.
    Precise (re-review v3 FP-fix): only a `run:` command that invokes an interpreter/exec counts
    as execution — a `with: path: ./artifacts` input or a `shell: bash` field must NOT trip it
    (GitHub's recommended dorny/test-reporter pattern only parses, never executes)."""
    text = _as_text(job)
    if "download-artifact" not in text:
        return False
    for cmd in _run_commands(job):
        if re.search(r"\b(bash|sh|python3?|node|npm|npx|ruby|make)\b", cmd) or "chmod +x" in cmd \
                or re.search(r"(^|\s|&&|;|\|)\s*\./", cmd):
            return True
    return False


def analyze_workflow(name: str, wf: dict, raw_lines: list[str]) -> list[str]:
    """Return risk strings for one workflow. Empty = safe/N-A for fork PRs."""
    trigs = _triggers(wf)
    fork_trigs = trigs & _FORK_TRIGGERS
    reusable = "workflow_call" in trigs
    if not fork_trigs and not reusable:
        return []  # N/A: no fork can fire these triggers, not a reusable callee
    findings: list[str] = []
    jobs = wf.get("jobs", {}) if isinstance(wf, dict) else {}
    top_perms = wf.get("permissions")
    privileged = bool(fork_trigs & _PRIVILEGED_FORK_TRIGGERS)
    scope = "reusable(workflow_call)" if reusable and not fork_trigs else "fork-reachable"

    # Workflow-root env: a secret OR a laundered PR-head-SHA parked as a sibling of jobs: is
    # reachable by every job (re-review bypasses #1-env and #2).
    root_env_text = _as_text(wf.get("env")) if isinstance(wf, dict) else ""
    for s in _secret_names(root_env_text):
        findings.append(f"{name}: workflow-root env references repo secret: {s}")
    root_head = privileged and _HEAD_REF_RE.search(root_env_text)

    for jname, job in (jobs or {}).items():
        if not isinstance(job, dict):
            continue
        text = _as_text(job)
        secs = _secret_names(text)
        if secs:
            findings.append(f"{name}:{jname}: {scope} job references repo secret(s): {sorted(set(secs))}")
        if _computed_secret_access(text):
            findings.append(f"{name}:{jname}: {scope} job uses computed secret access secrets[<expr>] (dynamic secret lookup)")
        if _has_secrets_inherit(job):
            findings.append(f"{name}:{jname}: 'secrets: inherit' forwards ALL repo secrets on a {scope} path")
        eff_perms = job.get("permissions", top_perms)
        if privileged and _permissions_write(eff_perms):
            findings.append(f"{name}:{jname}: privileged trigger + write permissions (fork carries write token)")
        if privileged and _permissions_is_sequence(eff_perms):
            findings.append(f"{name}:{jname}: privileged trigger + permissions as a sequence (unparseable scope — treat as unsafe)")
        if privileged and eff_perms is None:
            findings.append(f"{name}:{jname}: privileged trigger with NO explicit permissions block (implicit broad token)")
        if _runs_on_self_hosted(job):
            findings.append(f"{name}:{jname}: self-hosted runner on a {scope} trigger")
        if privileged and (_HEAD_REF_RE.search(text) or root_head):
            findings.append(f"{name}:{jname}: privileged trigger checks out PR head code (pwn-request shape)")
        if "workflow_run" in fork_trigs and _downloads_and_executes_artifact(job):
            findings.append(f"{name}:{jname}: workflow_run downloads and executes a fork-produced artifact (injection)")

    unpinned = _unpinned_actions(raw_lines)
    if unpinned:
        findings.append(f"{name}: third-party action(s) not SHA-pinned: {sorted(set(unpinned))}")
    return findings


def _local_action_refs(raw_lines: list[str]) -> list[str]:
    """`uses: ./path` — a LOCAL composite action a workflow calls (re-review bypass #1)."""
    refs = []
    for ln in raw_lines:
        m = re.search(r"uses:\s*(\./[^\s#'\"]+)", ln)
        if m:
            refs.append(m.group(1).strip())
    return refs


def _check_composite_action(action_path: str, ref: str, repo_root: str,
                            privileged: bool, seen: set[str]) -> list[str]:
    """A local composite action reached by a fork-reachable workflow is part of the attack
    surface: its `secrets.*`, computed secrets, unpinned nested `uses:`, and — under a privileged
    caller — its OWN PR-head checkout all count. Recurses into further local composite calls
    (re-review v3 #4 transitive chain, #5 composite-internal checkout)."""
    findings: list[str] = []
    if ref in seen or not os.path.isfile(action_path):
        return findings
    seen.add(ref)
    with open(action_path, encoding="utf-8") as f:
        raw = f.read()
    for s in _secret_names(raw):
        findings.append(f"composite {ref}: references repo secret: {s}")
    if _computed_secret_access(raw):
        findings.append(f"composite {ref}: uses computed secret access secrets[<expr>]")
    unpinned = _unpinned_actions(raw.splitlines())
    if unpinned:
        findings.append(f"composite {ref}: nested action(s) not SHA-pinned: {sorted(set(unpinned))}")
    if privileged and _HEAD_REF_RE.search(raw):
        findings.append(f"composite {ref}: checks out PR head code internally (pwn-request shape)")
    # Recurse into local composite actions this one itself calls.
    for nref in _local_action_refs(raw.splitlines()):
        base = os.path.normpath(os.path.join(repo_root, nref))
        for cand in (os.path.join(base, "action.yml"), os.path.join(base, "action.yaml"), base):
            if os.path.isfile(cand):
                findings += _check_composite_action(cand, nref, repo_root, privileged, seen)
                break
    return findings


def scan(workflows_dir: str) -> tuple[list[str], int]:
    paths = sorted(glob.glob(os.path.join(workflows_dir, "*.yml")) +
                   glob.glob(os.path.join(workflows_dir, "*.yaml")))
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(workflows_dir)))
    findings: list[str] = []
    checked_composites: set[str] = set()
    for p in paths:
        with open(p, encoding="utf-8") as f:
            raw = f.read()
        try:
            wf = yaml.safe_load(raw)
        except yaml.YAMLError as exc:
            findings.append(f"{os.path.basename(p)}: YAML parse error: {exc}")
            continue
        if not isinstance(wf, dict):
            continue
        lines = raw.splitlines()
        findings += analyze_workflow(os.path.basename(p), wf, lines)
        # If this workflow is fork-reachable, follow its local composite-action calls into
        # .github/actions/**/action.yml and audit those too (once each).
        trigs = _triggers(wf)
        if (trigs & _FORK_TRIGGERS) or ("workflow_call" in trigs):
            privileged = bool(trigs & _PRIVILEGED_FORK_TRIGGERS)
            for ref in _local_action_refs(lines):
                if ref in checked_composites:
                    continue
                # normpath resolves the leading ./ without eating the dot of .github
                base = os.path.normpath(os.path.join(repo_root, ref))
                for cand in (os.path.join(base, "action.yml"), os.path.join(base, "action.yaml"), base):
                    if os.path.isfile(cand):
                        findings += _check_composite_action(cand, ref, repo_root, privileged, checked_composites)
                        break
    return findings, len(paths)


# ---- Anti-tautology selfcheck: an intentionally unsafe fixture MUST trip several detectors -------
_UNSAFE_FIXTURE = {
    "on": {"pull_request_target": {"branches": ["main"]}},
    "jobs": {
        "pwn": {
            "runs-on": ["self-hosted"],
            "permissions": {"contents": "write"},
            "steps": [
                {"uses": "actions/checkout@v4", "with": {"ref": "${{ github.event.pull_request.head.sha }}"}},
                {"run": "echo ${{ secrets.PYPI_TOKEN }} && pip install -e ."},
            ],
        }
    },
}
_SAFE_FIXTURE = {
    "on": {"pull_request": {"branches": ["main"]}},
    "permissions": {"contents": "read"},
    "jobs": {"test": {"runs-on": "ubuntu-latest",
                      "steps": [{"uses": "actions/checkout@" + "a" * 40}, {"run": "pytest"}]}},
}


def selfcheck() -> bool:
    raw_unsafe = yaml.safe_dump(_UNSAFE_FIXTURE).splitlines() + ["uses: actions/checkout@v4"]
    unsafe = analyze_workflow("unsafe.yml", _UNSAFE_FIXTURE, raw_unsafe)
    safe = analyze_workflow("safe.yml", _SAFE_FIXTURE, yaml.safe_dump(_SAFE_FIXTURE).splitlines())
    unsafe_ok = (any("secret" in f for f in unsafe)
                 and any("self-hosted" in f for f in unsafe)
                 and any("pwn-request" in f for f in unsafe))
    return unsafe_ok and len(safe) == 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Fork-PR secret-isolation guard")
    ap.add_argument("--dir", default=".github/workflows", help="workflows directory")
    ap.add_argument("--selfcheck", action="store_true", help="prove the detector has teeth, then exit")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    if args.selfcheck:
        ok = selfcheck()
        print(json.dumps({"selfcheck": "PASS" if ok else "FAIL"}))
        return 0 if ok else 1

    if not selfcheck():
        print(json.dumps({"result": "ERROR", "findings": ["selfcheck failed — the guard itself is broken"]}))
        return 2

    findings, n = scan(args.dir)
    result = "PASS" if not findings else "FAIL"
    out = {"result": result, "workflows_scanned": n, "findings": findings,
           "scope": "static YAML analysis of fork-reachable jobs — see runbook for the honest scope boundary",
           "defense_in_depth": ("this guard is one layer: it keeps the current workflows clean and catches the "
                                "known pwn-request/secret patterns. The invariant is actually enforced by the "
                                "COMBINATION of (a) no secrets in fork-reachable jobs, (b) default read-only "
                                "GITHUB_TOKEN, (c) the fork-PR approval gate, and (d) actions/checkout v7's "
                                "server-side head-checkout hardening — not by pattern-matching alone."),
           "invariant": "no fork-reachable job reaches a secret / write-token / self-hosted / unpinned action / pwn-request / artifact-injection"}
    # codeql[py/clear-text-logging]: findings carry secret NAMES parsed from the workflow YAML
    # (e.g. "PYPI_TOKEN" — already public in the file), never secret VALUES. This guard is a static
    # analyser that never has access to a secret's value; reporting the offending name is its purpose.
    print(json.dumps(out, indent=2))
    return 0 if result == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
