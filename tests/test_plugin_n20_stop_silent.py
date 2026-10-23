"""Nachtrag 20, Ergänzung 3, part 7.3 and part 8 at the Stop hook (DECISIONS.md D53).

A passed end without a finding is silent; the log keeps it. A blocked end gives the model its one line as the reason,
as before, and shows the user the short line with the D number, in German where a person set it. An end without a done
verdict and a pass with a finding of the hook's own files stay visible as they were
(tests/test_plugin_done_check.py, tests/test_plugin_review_fix8_r4_pass_end_messages.py).

Red at b4f14212: there a passed end printed its message and a block showed the long line to the user.
"""
from __future__ import annotations

import json
import pathlib
import re

import pytest

import test_plugin_done_check as dc
from _gate_answer import Silent

gate = dc.gate


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    dc._clean_git_config.__wrapped__(monkeypatch)


@pytest.fixture
def env(tmp_path):
    return dc.env.__wrapped__(tmp_path)


@pytest.fixture
def keys(tmp_path):
    return dc.Keys(tmp_path)


@pytest.fixture
def declared(tmp_path, keys):
    repo = dc.repo.__wrapped__(tmp_path)
    dc._declare_done(repo, keys.public)
    dc._commit(repo, "declare the done check")
    return repo


def with_log(env: dict, tmp_path: pathlib.Path, language: str | None = None) -> dict:
    gate_dir = pathlib.Path(env["PROOFBUNDLE_GATE_DIR"])
    gate_dir.mkdir(parents=True, exist_ok=True)
    if language is not None:
        (gate_dir / "language").write_text(language, encoding="utf-8")
    return {**env, "CLAUDE_PLUGIN_DATA": str(tmp_path / "plugin-data")}


def last_log(env: dict) -> dict:
    lines = (pathlib.Path(env["CLAUDE_PLUGIN_DATA"]) / gate.LOG_NAME).read_text(encoding="utf-8").splitlines()
    return json.loads(lines[-1])


def test_a_passed_end_without_a_finding_is_silent_and_logged(env, declared, keys, tmp_path):
    env = with_log(env, tmp_path)
    dc._receipt(declared, keys.signer)
    code, answer, _stderr = dc.stop(env, declared)
    assert code == 0 and isinstance(answer, Silent) and answer == {}   # nothing on stdout
    entry = last_log(env)
    assert entry["tool"] is None and entry["actions"] == ["Stop"] and entry["verdict"] == "pass", entry
    assert entry["reason_ids"] == ["done"], entry


@pytest.mark.parametrize("language", ["en", "de"])
def test_a_blocked_end_shows_the_short_line_and_gives_the_model_the_one_line(env, declared, tmp_path, language):
    env = with_log(env, tmp_path, language)
    code, answer, _stderr = dc.stop(env, declared)
    assert code == 0 and answer["decision"] == "block", answer
    assert answer["reason"].startswith("proofbundle done check: ") and "\n" not in answer["reason"]
    line = answer["systemMessage"]
    assert len(line) <= 160 and line != answer["reason"], line
    assert re.search(r"\(D26\)\.$", line), line
    if language == "de":
        assert line == ("Tor hält das Ende auf, weil die Arbeit ohne Quittung einer Pflichtprüfung als fertig gelten "
                        "würde (D26)."), line   # the danger since Nachtrag 47 (O46-5)
        assert "—" not in line and "–" not in line and ": " not in line
    else:
        assert line == ("Gate holds the end because the work would count as done without a receipt of a required "
                        "check (D26)."), line   # the danger since Nachtrag 47 (O46-5)
    assert last_log(env)["verdict"] == "deny"


def test_without_a_done_check_the_end_stays_silent(env, tmp_path):
    repo = dc.repo.__wrapped__(tmp_path)
    assert dc.stop(env, repo)[:2] == (0, None)
