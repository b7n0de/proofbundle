"""Whether the merge queue is on for a branch is read from the rules GitHub applies to it
(scripts/merge_queue_state.py), not declared by a repository variable.

WHY (the reading of the head 37137a9d of pull request 462, P1, and the owner's answer A on its card). The
variable MERGE_QUEUE switched `coverage` off on a pull request without anything tying it to the queue: set
while a direct merge was still possible, a pull request could land without the whole suite under its floor.
The rules of the branch say whether the queue is on, and the same reader serves ci.yml and landung.yml.

THE SAFE SIDE. Every answer that is not a readable list holding a rule of type `merge_queue` reads as off, and
off means `coverage` runs. A reader that cannot read slows a pull request down; it never lets one land
without the suite.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "merge_queue_state.py"

RULES_WITHOUT_QUEUE = [{"type": "required_status_checks", "parameters": {}}, {"type": "pull_request"},
                       {"type": "deletion"}, {"type": "non_fast_forward"}]
RULES_WITH_QUEUE = RULES_WITHOUT_QUEUE + [{"type": "merge_queue", "parameters": {"merge_method": "MERGE"}}]
ENV = {"GITHUB_REPOSITORY": "o/r", "BRANCH": "main", "GITHUB_TOKEN": "t"}


def _script():
    spec = importlib.util.spec_from_file_location("merge_queue_state_under_test", SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _run(tmp_path, answer, env=None, s=None):
    """main() with a fake API that returns `answer`, or raises it when it is an exception; the output file as
    GitHub Actions hands it over. An exception of the script is built from the module `s` that runs it, since
    a second load of the script brings a second class of the same name."""
    s = s or _script()
    out = tmp_path / "output"
    out.write_text("", encoding="utf-8")
    asked = []

    def fetch(path, token):
        asked.append(path)
        if isinstance(answer, Exception):
            raise answer
        return answer
    rc = s.main(fetch=fetch, env=dict(env if env is not None else ENV, GITHUB_OUTPUT=str(out)))
    return rc, out.read_text(encoding="utf-8"), asked


def test_a_rule_of_type_merge_queue_is_the_queue():
    s = _script()
    assert s.required(RULES_WITH_QUEUE) is True
    assert s.required(RULES_WITHOUT_QUEUE) is False
    assert s.required([]) is False


def test_with_the_queue_in_the_rules_the_output_is_true(tmp_path):
    rc, out, asked = _run(tmp_path, RULES_WITH_QUEUE)
    assert rc == 0 and out == "required=true\n", out
    assert asked == ["repos/o/r/rules/branches/main"], asked


def test_without_the_queue_in_the_rules_the_output_is_false(tmp_path):
    rc, out, _ = _run(tmp_path, RULES_WITHOUT_QUEUE)
    assert rc == 0 and out == "required=false\n", out


def test_an_unreadable_answer_is_off_and_still_exit_0(tmp_path):
    s = _script()
    for answer in (s.ReadError("HTTP 403"), {"message": "Not Found"}, ["merge_queue"], None):
        rc, out, _ = _run(tmp_path, answer, s=s)
        assert rc == 0 and out == "required=false\n", (answer, out)


def test_a_missing_repository_or_branch_is_off(tmp_path):
    for missing in ("GITHUB_REPOSITORY", "BRANCH"):
        env = {k: v for k, v in ENV.items() if k != missing}
        rc, out, asked = _run(tmp_path, RULES_WITH_QUEUE, env=env)
        assert rc == 0 and out == "required=false\n" and asked == [], (missing, out, asked)


def test_a_branch_name_is_quoted_into_the_path(tmp_path):
    rc, out, asked = _run(tmp_path, RULES_WITH_QUEUE, env=dict(ENV, BRANCH="release/6.5"))
    assert asked == ["repos/o/r/rules/branches/release%2F6.5"], asked
