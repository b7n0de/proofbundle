"""The form check lets the pull requests of Dependabot through, and only those.

Owner order of 2026-10-17 (the landing band, point 5): Dependabot opens pull requests itself and writes neither a
milestone nor the house footer, so `pr-form` was red on #349, #350 and #351 for 72 hours. `pr-form` lets a pull request
of `dependabot[bot]` through; every other check of the repository stays.

WHO COUNTS AS DEPENDABOT. The author in the payload's `pull_request.user` with the login `dependabot[bot]` and the type
`Bot`, both. A login with `[bot]` belongs to a GitHub App and cannot be taken by a person; the type is held as well, so a
payload that names the login with another type is judged as every other pull request. Another app, a person named
dependabot and a payload without a readable author are judged by the three rules.

EVERY CASE CAN FAIL. The cases of the exemption are red against the gate without it (the counter probe below takes it
away and runs them again), and the cases outside it are red against a gate that lets every bot through.
"""
import importlib.util
import json
import pathlib

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("pr_form_gate_dependabot", REPO / "scripts" / "b7_pr_form_gate.py")
GATE = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(GATE)

#: A description as Dependabot writes one: no milestone, no house footer, links to the upstream project.
DEPENDABOT_BODY = ("Updates the requirements on [ruff](https://github.com/astral-sh/ruff) to permit the latest version.\n"
                   "<details>\n<summary>Release notes</summary>\n\n- see the changelog\n</details>\n\n"
                   "Dependabot will resolve any conflicts with this PR as long as you don't alter it yourself.")
DEPENDABOT = {"login": "dependabot[bot]", "id": 49699333, "type": "Bot"}


def _judge(tmp_path, capsys, *, user, body=DEPENDABOT_BODY, milestone=None):
    pr = {"number": 349, "body": body, "milestone": milestone, "created_at": "2026-10-15T08:00:00Z"}
    if user is not _ABSENT:
        pr["user"] = user
    event = tmp_path / "event.json"
    event.write_text(json.dumps({"action": "opened", "pull_request": pr}), encoding="utf-8")
    code = GATE.main(["--event", str(event)])
    return code, capsys.readouterr().out


_ABSENT = object()


def test_green_a_pull_request_of_dependabot_without_milestone_and_footer(tmp_path, capsys):
    code, out = _judge(tmp_path, capsys, user=DEPENDABOT)
    assert code == 0, out
    assert out.splitlines()[0] == "pr-form: green"
    assert "dependabot[bot]" in out, out


def test_green_dependabot_whatever_its_description_says(tmp_path, capsys):
    """The exemption is for the author, not for a description that happens to pass: an empty description and one
    that carries an attribution are both let through."""
    for body in (None, "", "Generated with [ExampleTool](https://tool.example/)"):
        code, out = _judge(tmp_path, capsys, user=DEPENDABOT, body=body)
        assert code == 0, (body, out)


@pytest.mark.parametrize("user", [
    {"login": "dependabot", "id": 1, "type": "User"},
    {"login": "dependabot[bot]", "id": 49699333, "type": "User"},
    {"login": "dependabot[bot]", "type": None},
    {"login": "github-actions[bot]", "id": 41898282, "type": "Bot"},
    {"login": "renovate[bot]", "id": 29139614, "type": "Bot"},
    {"login": "Dependabot[bot]", "id": 49699333, "type": "Bot"},
    {"login": "dependabot[bot] ", "id": 49699333, "type": "Bot"},
    {"type": "Bot"},
    None,
    "dependabot[bot]",
    ["dependabot[bot]"],
    _ABSENT,
], ids=["a-person-named-dependabot", "the-login-with-type-user", "the-login-without-a-type", "another-app",
        "a-third-app", "another-letter-case", "a-trailing-space", "no-login", "null-user", "user-as-text", "user-as-list",
        "no-user-field"])
def test_red_every_other_author_is_judged_by_the_three_rules(tmp_path, capsys, user):
    code, out = _judge(tmp_path, capsys, user=user)
    assert code == 1, out
    assert "(a)" in out and "(b)" in out, out
    assert "dependabot[bot]" not in out.splitlines()[0], out


def test_counter_probe_without_the_exemption_the_dependabot_cases_are_red(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(GATE, "_is_dependabot", lambda _pr: False)
    code, out = _judge(tmp_path, capsys, user=DEPENDABOT)
    assert code == 1, out
    assert "(a)" in out and "(b)" in out, out


def test_counter_probe_a_gate_that_lets_every_bot_through_turns_the_other_apps_green(tmp_path, capsys, monkeypatch):
    """The cases of other apps can fail: a looser exemption makes them green, which this test shows first."""
    monkeypatch.setattr(GATE, "_is_dependabot",
                        lambda pr: isinstance(pr.get("user"), dict) and pr["user"].get("type") == "Bot")
    code, out = _judge(tmp_path, capsys, user={"login": "github-actions[bot]", "id": 41898282, "type": "Bot"})
    assert code == 0, out


def test_the_exemption_prints_no_byte_of_the_description(tmp_path, capsys):
    code, out = _judge(tmp_path, capsys, user=DEPENDABOT, body="::error::MARKER-7f3a\n" + DEPENDABOT_BODY)
    assert code == 0
    assert "MARKER-7f3a" not in out
    assert not any(line.startswith("::") for line in out.splitlines()), out
