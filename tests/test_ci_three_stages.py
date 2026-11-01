"""The CI runs in three stages (ci.yml): before the merge queue, in it, and at night.

THE RED CASE FIRST. Against the ci.yml of main 61b585b5 most cases below fail: main has no stage, no night, runs the
mutation layer in the merge queue, where 36 mutation jobs would hold every candidate for hours, and runs `coverage` on
every pull request, where it is the long pole of every run. Measured over the 24 green pull-request runs since the
legs run in seven parts (30.10.2026): the longest test part took 18 to 25 min, `coverage` 42 to 105 min.

THE FORM ON THE PARTS. The legs of `test` keep their seven parts and their five interpreters before the queue, in it
and at night; only a fork pull request without the `landung` label and the push of a landed tree run 3.12, as
before. RELEASE.md asks for the CI matrix green on all supported Pythons on the release pull request, and this keeps
it. What moves:
  - `coverage`, the whole suite under the floor, runs in the queue once per candidate, and on a pull request only
    until the rules of the base branch carry a merge queue, which the job merge-queue-state reads through
    scripts/merge_queue_state.py (a release/ pull request of this repository keeps it, its mutation layer needs
    it). A repository variable decided this in the first form; the reading of the head 37137a9d (P1) found that
    nothing tied it to the queue, and the owner chose the rules (answer A on card OA-75a1805115);
  - the mutation layer leaves the queue for the night (schedule, new), with the cost curves of the budget axes;
  - the collector all-checks-passed judges per stage and also needs the language gate and the title gate, which
    block before the queue.
The first stage of the delivery (a selection of test files from the import graph) is not part of this form: on this
tree it chose the whole suite for 40 of 40 landings since 25.10.2026 and for a change of one test file alone, since
tests/conftest.py reaches every file.

Each case evaluates the workflow's own expressions against an event, so a stage that drifts turns a case red. The
expressions are few and plain: event names, `startsWith`, `contains` over the labels, `fromJSON`, `always()`,
`!cancelled()`, the output of the job merge-queue-state, `&&`, `||`, `==` and `!=`. They are evaluated as Python, where `and` and `or` return an operand
just as GitHub's `&&` and `||` do; a name this file does not know raises, so a new kind of condition cannot pass
unread.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

REPO = Path(__file__).resolve().parents[1]
CI = REPO / ".github" / "workflows" / "ci.yml"
EVENTS = ("pull_request", "merge_group", "push", "schedule", "workflow_dispatch")
FIVE = ["3.10", "3.11", "3.12", "3.13", "3.14"]


def _ci() -> dict:
    return yaml.safe_load(CI.read_text(encoding="utf-8"))


_NAMES = (
    ("github.event.pull_request.head.repo.full_name", "head_repo"),
    ("github.event.pull_request.labels.*.name", "labels"),
    ("github.repository", "repository"),
    ("github.event_name", "event_name"),
    ("github.ref_name", "ref_name"),
    ("github.head_ref", "head_ref"),
    ("needs.merge-queue-state.outputs.required", "queue_required"),
    ("!cancelled()", "not_cancelled()"),
)


def _evaluate(expression: str, event: str, queue_required: str = "", head_ref: str = "feature/x",
              head_repo: str = "o/r", labels: tuple[str, ...] = (), ref_name: str | None = None):
    """The value of one workflow expression at an event."""
    text = " ".join(str(expression).split())
    if text.startswith("${{") and text.endswith("}}"):
        text = text[3:-2].strip()
    for name, py in _NAMES:
        text = text.replace(name, py)
    text = text.replace("&&", " and ").replace("||", " or ")
    text = text.replace("startsWith(", "starts_with(").replace("fromJSON(", "from_json(")
    if re.search(r"![^=]", text):
        raise AssertionError(f"a negation this file does not read: {expression!r}")
    if event != "pull_request":
        head_ref, head_repo, labels = "", "", ()
    namespace = {
        "event_name": event, "repository": "o/r", "head_repo": head_repo, "head_ref": head_ref,
        "labels": list(labels),
        "ref_name": ref_name if ref_name is not None else {"pull_request": "1/merge", "merge_group":
                                                           "gh-readonly-queue/main/pr-1-abc"}.get(event, "main"),
        "queue_required": queue_required, "starts_with": lambda s, p: str(s).startswith(p), "from_json": json.loads,
        "contains": lambda seq, x: x in seq,
        "always": lambda: True,  # a status function: nothing is cancelled here
        "not_cancelled": lambda: True,
        "__builtins__": {},
    }
    return eval(text, namespace)  # noqa: S307 - the workflow's own text, names restricted above


def _stage(event: str) -> str:
    return _evaluate(_ci()["env"]["CI_STAGE"], event)


def _job_runs(job: str, event: str, **kw) -> bool:
    cond = _ci()["jobs"][job].get("if")
    return True if cond is None else bool(_evaluate(cond, event, **kw))


@pytest.mark.parametrize("event, stage", [("pull_request", "pre-queue"), ("merge_group", "queue"),
                                          ("push", "queue"), ("schedule", "nightly"),
                                          ("workflow_dispatch", "nightly")])
def test_every_event_has_its_stage(event, stage):
    assert _stage(event) == stage


def test_the_night_has_a_trigger():
    on = _ci().get(True) or _ci().get("on")
    crons = [c.get("cron") for c in on.get("schedule") or []]
    assert crons and all(isinstance(c, str) and len(c.split()) == 5 for c in crons), crons
    assert "merge_group" in on, "the queue needs its trigger, or no job reports on a queue entry"


@pytest.mark.parametrize("event, kw, interpreters", [
    ("pull_request", {}, FIVE),
    ("pull_request", {"head_ref": "chore/prepare-6.5.0"}, FIVE),
    ("pull_request", {"head_repo": "fork/r"}, ["3.12"]),
    ("pull_request", {"head_repo": "fork/r", "labels": ("landung",)}, FIVE),
    ("merge_group", {}, FIVE),
    ("push", {}, ["3.12"]),
    ("schedule", {}, FIVE),
    ("workflow_dispatch", {}, FIVE),
])
def test_the_five_interpreters_stay_on_every_pull_request_of_this_repository(event, kw, interpreters):
    """RELEASE.md, per release: the CI matrix green on all supported Pythons on the release pull request, whose
    branch is chore/prepare-X.Y.Z. A pull request of this repository therefore keeps the five; the parts make them
    cost no wall clock (longest part 18 to 25 min since 30.10.2026)."""
    expr = _ci()["jobs"]["test"]["strategy"]["matrix"]["python-version"]
    assert _evaluate(expr, event, **kw) == interpreters


def test_the_collector_reads_the_full_matrix_with_the_same_expression_as_the_matrix():
    """A second copy on purpose (all-checks-passed), held to the matrix's own condition word for word."""
    matrix = " ".join(_ci()["jobs"]["test"]["strategy"]["matrix"]["python-version"].split())
    full = " ".join(_ci()["jobs"]["all-checks-passed"]["steps"][0]["env"]["FULL_MATRIX"].split())
    inner = full[3:-2].strip() if full.startswith("${{") else full
    assert inner.strip("( )") in matrix, (inner, matrix)


@pytest.mark.parametrize("event", ["merge_group", "push", "schedule", "workflow_dispatch"])
def test_coverage_runs_everywhere_but_on_a_pull_request_once_the_queue_is_required(event):
    assert _job_runs("coverage", event)
    assert _job_runs("coverage", event, queue_required="true"), "the queue binds only the pull request"


def test_before_the_queue_coverage_runs_until_the_merge_queue_is_required():
    assert _job_runs("coverage", "pull_request"), "without the merge queue nothing may land without the suite's floor"
    for unread in ("", "false", "required", "yes"):
        assert _job_runs("coverage", "pull_request", queue_required=unread), (
            f"only the answer `true` of the reader switches it, not {unread!r}")
    assert not _job_runs("coverage", "pull_request", queue_required="true")
    assert _job_runs("coverage", "pull_request", queue_required="true", head_ref="release/6.5.0"), (
        "a release/ pull request of this repository keeps coverage: its mutation layer needs it")
    assert not _job_runs("coverage", "pull_request", queue_required="true", head_ref="release/6.5.0",
                         head_repo="fork/r"), "a fork's branch name decides nothing"


@pytest.mark.parametrize("job", ["mutation", "mutation-summary"])
def test_the_mutation_layer_runs_at_night_not_in_the_queue(job):
    assert _job_runs(job, "schedule") and _job_runs(job, "workflow_dispatch")
    assert _job_runs(job, "pull_request", head_ref="release/6.5.0"), "a release/ pull request keeps its layer"
    assert _job_runs(job, "push", ref_name="release/6.5.0"), "a push to a release/ branch keeps its layer"
    for event in ("merge_group", "push", "pull_request"):
        assert not _job_runs(job, event), event


def test_the_cost_curves_run_at_night_only():
    assert [e for e in EVENTS if _job_runs("cost-curves", e)] == ["schedule", "workflow_dispatch"]
    assert _ci()["jobs"]["cost-curves"]["strategy"]["matrix"]["python-version"] == ["3.12", "3.14"]


def test_the_collector_judges_the_gates_of_a_pull_request_too():
    assert _ci()["jobs"]["all-checks-passed"]["needs"] == ["test", "coverage", "new-lines-english",
                                                         "release-scope-title", "merge-queue-state"]
    env = _ci()["jobs"]["all-checks-passed"]["steps"][0]["env"]
    assert env["MERGE_QUEUE"] == "${{ needs.merge-queue-state.outputs.required }}"
    assert "CI_STAGE" not in env, "the stage comes from the workflow's env, one definition"


def test_the_legs_of_test_keep_their_parts_and_their_one_suite_step():
    """The form changes nothing in the job `test`: tests/test_ci_test_parts_cover_the_suite.py holds its shape."""
    job = _ci()["jobs"]["test"]
    assert job["strategy"]["matrix"]["part"] == [1, 2, 3, 4, 5, 6, 7]
    assert "if" not in job
    assert len([s for s in job["steps"] if "-m pytest" in str(s.get("run", ""))]) == 1


def test_the_queue_is_read_from_the_rules_not_declared_by_a_variable():
    """The reading of the head 37137a9d (P1): a repository variable switched coverage off with nothing tying it to the
    queue. The job merge-queue-state reads the rules of the base branch with scripts/merge_queue_state.py, runs on
    every event, and coverage waits for it without depending on its success: `!cancelled()`, so a reader that failed
    leaves coverage running."""
    text = CI.read_text(encoding="utf-8")
    assert "vars.MERGE_QUEUE" not in text, "the variable still decides somewhere"
    job = _ci()["jobs"]["merge-queue-state"]
    assert "if" not in job, "the reader runs on every event"
    steps = [s for s in job["steps"] if "scripts/merge_queue_state.py" in str(s.get("run", ""))]
    assert len(steps) == 1 and steps[0].get("id") == "read", steps
    assert job["outputs"]["required"] == "${{ steps.read.outputs.required }}"
    assert steps[0]["env"]["GITHUB_TOKEN"] == "${{ github.token }}"
    coverage = _ci()["jobs"]["coverage"]
    assert coverage["needs"] == ["merge-queue-state"]
    assert " ".join(str(coverage["if"]).split()).startswith("!cancelled() &&"), coverage["if"]
