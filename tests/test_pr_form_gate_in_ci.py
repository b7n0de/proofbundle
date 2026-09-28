"""The pull-request form gate has its own workflow, and the workflow runs when the form changes.

Owner decision 2026-09-28: every pull request carries a milestone from the moment it opens, and its
description ends with the house footer. The judgement lives in `b7_pr_form_gate.py`; this module
holds the other half, the one that decides whether the judgement is ever made. A gate that nothing
calls is a file, and a gate that runs only on a push judges a description that may have been edited
since: a milestone removed at 10:00 stays green until somebody pushes.

Owner order of 2026-09-28, 13:4x Berlin: the check must not live in ci.yml and must not make ci.yml
run on more events. Every event ci.yml subscribes to restarts the whole suite; an edited description
is not a reason for that. The check therefore has its own file, `.github/workflows/pr-form.yml`, and
it is not built from a condition on a job: GitHub reports a job skipped by a condition as success,
and a skipped check at the same head could hide a red one.

Properties, each with a case that fails without it:

- pr-form.yml starts on `pull_request` with `edited`, `milestoned` and `demilestoned` beside the
  three default types, for every base branch, so a stacked pull request is judged as well, and not
  on `labeled` or `unlabeled`: the milestone is the only sorting sign on a pull request, and the gate
  has no rule about labels (owner order of 2026-09-28, 14:17 Berlin);
- no job and no step of pr-form.yml carries `if:` or `continue-on-error`, so the check runs on every
  event it subscribes to and its red is red;
- the workflow token reads contents and nothing else, and every action is pinned to a commit;
- exactly one step runs the gate on the runner's own event payload, `$GITHUB_EVENT_PATH`, never on
  text spliced into the command line, and its exit is the step's exit: executed under `bash -e`, the
  shell the runner uses, with `python` replaced by a stand-in that records each call;
- ci.yml neither runs the gate nor subscribes to the three events the gate needs.
"""
from __future__ import annotations

import pathlib
import re
import subprocess

import pytest

yaml = pytest.importorskip("yaml")

REPO = pathlib.Path(__file__).resolve().parents[1]
WORKFLOWS = REPO / ".github" / "workflows"
FORM = WORKFLOWS / "pr-form.yml"
CI = WORKFLOWS / "ci.yml"

FORM_GATE = "b7_pr_form_gate.py"
GATE_CALL = f'python scripts/{FORM_GATE} --event "$GITHUB_EVENT_PATH"'
FORM_EVENTS = ("edited", "milestoned", "demilestoned")
PUSH_EVENTS = ("opened", "synchronize", "reopened")
LABEL_EVENTS = ("labeled", "unlabeled")
_PINNED = re.compile(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")


def _load(path: pathlib.Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def _on(workflow: dict) -> dict:
    # YAML 1.1 reads the bare key `on` as the boolean True.
    on = workflow.get(True) or workflow.get("on") or {}
    if isinstance(on, dict):
        return on
    return {name: None for name in ([on] if isinstance(on, str) else on)}


def _steps(workflow: dict) -> list[tuple[str, dict]]:
    return [(name, step) for name, job in (workflow.get("jobs") or {}).items()
            for step in job.get("steps") or []]


def _gate_steps(workflow: dict) -> list[tuple[str, dict]]:
    return [(name, step) for name, step in _steps(workflow) if FORM_GATE in str(step.get("run") or "")]


# ------------------------------------------------------------------------------------------------
# The judgements, each a function of a loaded workflow, so a catch proof can hand it a mutant
# ------------------------------------------------------------------------------------------------

def trigger_findings(workflow: dict) -> list[str]:
    on = _on(workflow)
    found = [f"starts on `{event}`" for event in on if event != "pull_request"]
    pull_request = on.get("pull_request")
    if not isinstance(pull_request, dict):
        return found + ["does not start on `pull_request` with a list of types"]
    types = list(pull_request.get("types") or [])
    found += [f"does not start on `{t}`" for t in PUSH_EVENTS + FORM_EVENTS if t not in types]
    found += [f"starts on `{t}`" for t in LABEL_EVENTS if t in types]
    found += [f"narrows the pull requests by `{key}`" for key in
              ("branches", "branches-ignore", "paths", "paths-ignore") if key in pull_request]
    return found


def condition_findings(workflow: dict) -> list[str]:
    found = []
    for name, job in (workflow.get("jobs") or {}).items():
        found += [f"job {name} carries `{key}`" for key in ("if", "continue-on-error") if key in job]
    for name, step in _steps(workflow):
        found += [f"a step of job {name} carries `{key}`" for key in ("if", "continue-on-error")
                  if key in step]
    return found


def token_findings(workflow: dict) -> list[str]:
    found = []
    if workflow.get("permissions") != {"contents": "read"}:
        found.append(f"workflow permissions are {workflow.get('permissions')!r}, not contents: read")
    for name, job in (workflow.get("jobs") or {}).items():
        if "permissions" in job:
            found.append(f"job {name} sets its own permissions {job['permissions']!r}")
    for name, step in _steps(workflow):
        uses = step.get("uses")
        if uses is not None and not _PINNED.match(str(uses)):
            found.append(f"job {name} uses {uses!r}, not pinned to a commit")
    return found


def call_findings(workflow: dict) -> list[str]:
    steps = _gate_steps(workflow)
    if len(steps) != 1:
        return [f"{len(steps)} steps run the gate, not one"]
    (_, step), = steps
    run = str(step["run"])
    found = []
    if GATE_CALL not in run:
        found.append("the gate is not run on the runner's event payload")
    if "${{" in run:
        found.append("an expression is spliced into the command line")
    if any("${{" in str(value) for value in (step.get("env") or {}).values()):
        found.append("an expression reaches the step's environment")
    return found


def ci_findings(workflow: dict) -> list[str]:
    found = [f"ci.yml runs {FORM_GATE}"] if _gate_steps(workflow) else []
    types = list((_on(workflow).get("pull_request") or {}).get("types") or [])
    found += [f"ci.yml starts on `{t}`" for t in FORM_EVENTS if t in types]
    return found


def run_step(workflow: dict, form_exit: int, tmp_path: pathlib.Path) -> tuple[int, list[str]]:
    (_, step), = _gate_steps(workflow)
    log = tmp_path / "calls"
    stand_in = f'python() {{\n  echo "$1" >> "{log}"\n  return {form_exit}\n}}\n'
    script = tmp_path / "step.sh"
    script.write_text(stand_in + str(step["run"]) + "\n", encoding="utf-8")
    done = subprocess.run(["bash", "-e", str(script)],
                          env={"PATH": "/usr/bin:/bin", "GITHUB_EVENT_PATH": "/dev/null"},
                          capture_output=True, text=True, timeout=30)
    calls = log.read_text(encoding="utf-8").split() if log.exists() else []
    return done.returncode, calls


# ------------------------------------------------------------------------------------------------
# The tree as it stands
# ------------------------------------------------------------------------------------------------

@pytest.fixture(scope="module")
def form() -> dict:
    assert FORM.is_file(), f"{FORM.relative_to(REPO)} is absent: nothing runs the form gate"
    return _load(FORM)


def test_the_workflow_starts_on_every_event_that_changes_the_form(form):
    assert trigger_findings(form) == []


def test_no_condition_decides_whether_the_check_runs_or_counts(form):
    assert condition_findings(form) == []


def test_the_token_reads_contents_only_and_every_action_is_pinned(form):
    assert token_findings(form) == []


def test_one_step_runs_the_gate_on_the_event_payload(form):
    assert call_findings(form) == []


@pytest.mark.parametrize(("form_exit", "step_green"), [(0, True), (1, False)])
def test_the_gate_runs_and_its_exit_is_the_steps_exit(form, tmp_path, form_exit, step_green):
    code, calls = run_step(form, form_exit, tmp_path)
    assert calls == [f"scripts/{FORM_GATE}"], calls
    assert (code == 0) is step_green, f"step exit {code} for gate exit {form_exit}"


def test_ci_yml_neither_runs_the_gate_nor_starts_on_its_events():
    assert ci_findings(_load(CI)) == []


def test_no_other_workflow_runs_the_gate():
    others = sorted(p.name for p in WORKFLOWS.glob("*.y*ml")
                    if p.name != FORM.name and _gate_steps(_load(p)))
    assert others == [], f"the gate runs outside {FORM.name}: {others}"


# ------------------------------------------------------------------------------------------------
# Catch proofs: each judgement finds the mutant it exists for
# ------------------------------------------------------------------------------------------------

def _mutant(form: dict) -> dict:
    return yaml.safe_load(yaml.safe_dump(form))


def test_catch_proof_a_missing_event_a_second_trigger_a_base_filter_and_a_label_event(form):
    for event in FORM_EVENTS + PUSH_EVENTS:
        m = _mutant(form)
        _on(m)["pull_request"]["types"].remove(event)
        assert trigger_findings(m) == [f"does not start on `{event}`"]
    m = _mutant(form)
    _on(m)["pull_request_target"] = {"types": ["opened"]}
    assert trigger_findings(m) == ["starts on `pull_request_target`"]
    m = _mutant(form)
    _on(m)["pull_request"]["branches"] = ["main"]
    assert trigger_findings(m) == ["narrows the pull requests by `branches`"]
    for event in LABEL_EVENTS:
        m = _mutant(form)
        _on(m)["pull_request"]["types"].append(event)
        assert trigger_findings(m) == [f"starts on `{event}`"]


def test_catch_proof_a_condition_on_the_job_or_the_step(form):
    name = next(iter(form["jobs"]))
    for key, value in (("if", "github.event.action != 'edited'"), ("continue-on-error", True)):
        m = _mutant(form)
        m["jobs"][name][key] = value
        assert condition_findings(m) == [f"job {name} carries `{key}`"]
        m = _mutant(form)
        _gate_steps(m)[0][1][key] = value
        assert condition_findings(m) == [f"a step of job {name} carries `{key}`"]


def test_catch_proof_a_wider_token_and_an_unpinned_action(form):
    m = _mutant(form)
    m["permissions"] = {"contents": "read", "pull-requests": "write"}
    assert len(token_findings(m)) == 1
    m = _mutant(form)
    name = next(iter(m["jobs"]))
    m["jobs"][name]["permissions"] = "write-all"
    assert token_findings(m) == [f"job {name} sets its own permissions 'write-all'"]
    m = _mutant(form)
    step = next(step for _, step in _steps(m) if "uses" in step)
    step["uses"] = step["uses"].split("@")[0] + "@v7"
    assert len(token_findings(m)) == 1


def test_catch_proof_a_spliced_description_an_injected_env_and_a_second_call(form):
    m = _mutant(form)
    _gate_steps(m)[0][1]["run"] = f'python scripts/{FORM_GATE} --body "${{{{ github.event.pull_request.body }}}}"'
    assert call_findings(m) == ["the gate is not run on the runner's event payload",
                                "an expression is spliced into the command line"]
    m = _mutant(form)
    _gate_steps(m)[0][1].setdefault("env", {})["BODY"] = "${{ github.event.pull_request.body }}"
    assert call_findings(m) == ["an expression reaches the step's environment"]
    m = _mutant(form)
    job = next(iter(m["jobs"].values()))
    job["steps"].append(dict(_gate_steps(m)[0][1]))
    assert call_findings(m) == ["2 steps run the gate, not one"]


def test_catch_proof_an_ignored_red_turns_the_step_green(form, tmp_path):
    m = _mutant(form)
    step = _gate_steps(m)[0][1]
    step["run"] = str(step["run"]) + " || true"
    code, _ = run_step(m, 1, tmp_path)
    assert code == 0


def test_catch_proof_the_gate_back_in_ci_yml():
    m = _load(CI)
    job = next(iter(m["jobs"].values()))
    job["steps"] = list(job.get("steps") or []) + [{"run": GATE_CALL}]
    _on(m)["pull_request"]["types"] = list(_on(m)["pull_request"]["types"]) + list(FORM_EVENTS)
    assert ci_findings(m) == ([f"ci.yml runs {FORM_GATE}"]
                              + [f"ci.yml starts on `{t}`" for t in FORM_EVENTS])
