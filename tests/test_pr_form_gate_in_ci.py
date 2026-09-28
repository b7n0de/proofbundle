"""The pull-request form gate has a caller, and the caller runs again when the form changes.

Owner decision 2026-09-28: every pull request carries a milestone from the moment it opens, and its
description ends with the house footer. The judgement lives in `b7_pr_form_gate.py`; this module
holds the other half, the one that decides whether the judgement is ever made. A gate that nothing
calls is a file, and a gate that runs only on a push judges a description that may have been edited
since: a milestone removed at 10:00 stays green until somebody pushes.

Three properties, each with a case that fails without it:

- ci.yml subscribes to `edited`, `milestoned` and `demilestoned`, so a change of description or
  milestone starts a run that reads the new state;
- the step that runs the release-scope title gate also runs the form gate on the runner's own event
  payload, `$GITHUB_EVENT_PATH`, never on text spliced into the command line;
- a red title gate does not skip the form gate, and a red form gate turns the step red: both
  verdicts are made on every run. Executed under `bash -e`, the shell the runner uses, with
  `python` replaced by a stand-in that records each call.
"""
from __future__ import annotations

import pathlib
import subprocess

import pytest

yaml = pytest.importorskip("yaml")

REPO = pathlib.Path(__file__).resolve().parents[1]
CI = REPO / ".github" / "workflows" / "ci.yml"

TITLE_GATE = "b7_release_scope_title_gate.py"
FORM_GATE = "b7_pr_form_gate.py"
FORM_EVENTS = ("edited", "milestoned", "demilestoned")


def _ci() -> dict:
    return yaml.safe_load(CI.read_text(encoding="utf-8"))


def _pull_request_types(workflow: dict) -> list:
    # YAML 1.1 reads the bare key `on` as the boolean True.
    on = workflow.get(True) or workflow.get("on") or {}
    return list((on.get("pull_request") or {}).get("types") or [])


def _title_gate_steps(workflow: dict) -> list[tuple[str, dict]]:
    found = []
    for name, job in (workflow.get("jobs") or {}).items():
        for step in job.get("steps") or []:
            if TITLE_GATE in str(step.get("run") or ""):
                found.append((name, step))
    return found


def test_the_trigger_subscribes_to_every_event_that_changes_the_form():
    types = _pull_request_types(_ci())
    missing = [t for t in FORM_EVENTS if t not in types]
    assert not missing, f"ci.yml does not start a run on {missing} (types={types})"


def test_the_events_the_trigger_already_had_stay():
    types = _pull_request_types(_ci())
    for kept in ("opened", "synchronize", "reopened", "labeled", "unlabeled"):
        assert kept in types, f"`{kept}` was dropped from the pull_request types ({types})"


def test_exactly_one_step_runs_the_title_gate_and_it_also_runs_the_form_gate():
    steps = _title_gate_steps(_ci())
    assert len(steps) == 1, f"expected one step running the title gate, found {len(steps)}"
    _, step = steps[0]
    run = str(step["run"])
    assert f'python scripts/{FORM_GATE} --event "$GITHUB_EVENT_PATH"' in run, (
        "the title gate's step does not run the form gate on the runner's event payload")


def test_the_job_runs_on_pull_request_events_only():
    (name, _), = _title_gate_steps(_ci())
    job = _ci()["jobs"][name]
    assert str(job.get("if", "")).strip() == "github.event_name == 'pull_request'"
    assert "continue-on-error" not in job


def test_the_description_never_reaches_the_command_line():
    """The description is text anyone who opens a pull request writes. The gate reads it from the
    payload file; no expression may splice it, or anything else, into the shell line."""
    (_, step), = _title_gate_steps(_ci())
    assert "${{" not in str(step["run"])
    env = step.get("env") or {}
    assert not any("body" in str(v) for v in env.values()), env


def _run_step(title_exit: int, form_exit: int, tmp_path: pathlib.Path) -> tuple[int, list[str]]:
    (_, step), = _title_gate_steps(_ci())
    log = tmp_path / "calls"
    stand_in = (
        "python() {\n"
        f'  echo "$1" >> "{log}"\n'
        f'  case "$1" in *{TITLE_GATE}) return {title_exit};; *{FORM_GATE}) return {form_exit};; esac\n'
        "  return 99\n"
        "}\n")
    script = tmp_path / "step.sh"
    script.write_text(stand_in + str(step["run"]) + "\n", encoding="utf-8")
    env = {"PATH": "/usr/bin:/bin", "PR_TITLE": "t", "PR_BRANCH": "b", "GITHUB_EVENT_PATH": "/dev/null"}
    done = subprocess.run(["bash", "-e", str(script)], env=env, capture_output=True, text=True,
                          timeout=30)
    calls = log.read_text(encoding="utf-8").split() if log.exists() else []
    return done.returncode, calls


@pytest.mark.parametrize(("title_exit", "form_exit", "step_green"), [
    (0, 0, True), (1, 0, False), (0, 1, False), (1, 1, False)])
def test_both_gates_run_and_either_red_turns_the_step_red(tmp_path, title_exit, form_exit, step_green):
    code, calls = _run_step(title_exit, form_exit, tmp_path)
    assert calls == [f"scripts/{TITLE_GATE}", f"scripts/{FORM_GATE}"], calls
    assert (code == 0) is step_green, f"step exit {code} for title {title_exit}, form {form_exit}"


def test_catch_proof_a_chained_call_skips_the_form_gate(tmp_path):
    """The stand-in has teeth: a step written with `&&` skips the form gate on a red title."""
    (_, step), = _title_gate_steps(_ci())
    chained = {"run": f'python scripts/{TITLE_GATE} --branch "$PR_BRANCH" --title "$PR_TITLE" && '
                      f'python scripts/{FORM_GATE} --event "$GITHUB_EVENT_PATH"'}
    log = tmp_path / "calls"
    stand_in = (f'python() {{ echo "$1" >> "{log}"; case "$1" in *{TITLE_GATE}) return 1;; esac; }}\n')
    script = tmp_path / "step.sh"
    script.write_text(stand_in + chained["run"] + "\n", encoding="utf-8")
    subprocess.run(["bash", "-e", str(script)], env={"PATH": "/usr/bin:/bin"}, capture_output=True,
                   timeout=30)
    assert log.read_text(encoding="utf-8").split() == [f"scripts/{TITLE_GATE}"]
    assert step["run"] != chained["run"]
