"""Owner choice 4 A of 2026-10-11: Level 1 names a change of the evidence rules against the recorded state as a hint,
never as a verdict.

The hint names the two local trees read, the source commit, the record's ref and its commit; where the choice is unclear
the ref is called a locally recorded candidate ref. A missing or unreadable comparison is no equality. The scope of the
rules stays, the done check included; a subject or receipt change is no rules change. A comparison of the tips claims no
check of the commits between them. The wording is the review's: "The evidence rules at source commit <source> differ
from local ref <ref> at <recorded commit>. This is a local comparison. The actual push destination and its current state
remain NOT MEASURED." The verdict stays NOT MEASURED (push_not_measured). Red against d4a0cd96, where Level 1 named no
comparison with a local record.
"""
from __future__ import annotations

import json
import pathlib
import subprocess

import test_claude_code_plugin_gate as cg
from test_claude_code_plugin_gate import _clean_git_config, repo, shim  # noqa: F401  (fixtures)

gate = cg.gate
pytestmark = cg.pytestmark if hasattr(cg, "pytestmark") else []

LOCAL = "This is a local comparison. The actual push destination and its current state remain NOT MEASURED."


def _rev(folder: pathlib.Path, rev: str) -> str:
    return subprocess.run(["git", "-C", str(folder), "rev-parse", rev], capture_output=True, text=True,
                          check=True).stdout.strip()


def _record(folder: pathlib.Path, change, remote_ref: str = "refs/heads/main") -> str:
    """A commit on top of HEAD that `change` edits, written to `remote_ref` on the remote and fetched, while the
    branch main stays at HEAD; its id."""
    head = _rev(folder, "HEAD")
    cg._git(folder, "checkout", "-q", "-b", "elsewhere")
    change(folder)
    cg._commit(folder, "the recorded state")
    recorded = _rev(folder, "HEAD")
    cg._git(folder, "push", "-q", "-f", "--no-verify", "origin", f"elsewhere:{remote_ref}")
    cg._git(folder, "checkout", "-q", "main")
    cg._git(folder, "branch", "-q", "-D", "elsewhere")
    cg._git(folder, "fetch", "-q", "--no-tags", "origin")
    assert _rev(folder, "HEAD") == head
    return recorded


def _remove_declaration(folder: pathlib.Path) -> None:
    cg._git(folder, "rm", "-q", "-r", ".proofbundle")


def _ask(env: dict, folder: pathlib.Path, command: str = "git push origin main") -> str:
    answer = cg.run_gate(env, folder, command)
    assert cg.decision(answer) == "ask", answer
    return cg.reason(answer)


def test_a_rules_difference_against_the_local_record_is_a_hint(shim, repo):  # noqa: F811
    recorded = _record(repo, _remove_declaration)
    head = _rev(repo, "HEAD")
    text = _ask(shim, repo)
    assert (f"The evidence rules at source commit {head[:12]} differ from local ref refs/remotes/origin/main at "
            f"{recorded[:12]}. {LOCAL}") in text, text
    assert (f"Trees read: {_rev(repo, 'HEAD^{tree}')[:12]} at {head[:12]} and "
            f"{_rev(repo, recorded + '^{tree}')[:12]} at {recorded[:12]}") in text, text
    assert "the declaration is declared at the source commit and absent at the local ref" in text, text
    assert "only these two tips were compared, no commit between them" in text, text
    assert "the push changes the evidence rules" not in text, text
    assert cg.at_destination(cg.run_gate(shim, repo, "git push origin main"))   # the verdict stays NOT MEASURED


def test_a_recorded_candidate_is_named_a_candidate(shim, repo):  # noqa: F811
    recorded = _record(repo, _remove_declaration, remote_ref="refs/tags/refs/heads/main")
    text = _ask(shim, repo, "git push origin HEAD:refs/heads/main")
    assert ("differ from locally recorded candidate ref refs/recorded/origin/tags/refs/heads/main at "
            f"{recorded[:12]}. {LOCAL}") in text, text


def test_a_subject_change_is_no_rules_change(shim, repo):  # noqa: F811
    def new_subject(folder: pathlib.Path) -> None:
        (folder / "README.md").write_text("another release\n", encoding="utf-8")
        declaration = json.loads((folder / gate.DECLARATION).read_text(encoding="utf-8"))
        declaration["evidence"][0]["subject"]["digest"] = "cd" * 32
        (folder / gate.DECLARATION).write_text(json.dumps(declaration), encoding="utf-8")
        cg._git(folder, "add", "-A")

    _record(repo, new_subject)
    text = _ask(shim, repo)
    assert "differ from" not in text and "could not be compared" not in text, text


def test_an_unreadable_side_is_no_equality(shim, repo):  # noqa: F811
    def folder_at_declaration(folder: pathlib.Path) -> None:
        cg._git(folder, "rm", "-q", gate.DECLARATION)
        (folder / gate.DECLARATION).mkdir()
        (folder / gate.DECLARATION / "inside").write_text("x", encoding="utf-8")
        cg._git(folder, "add", "-A")

    recorded = _record(repo, folder_at_declaration)
    text = _ask(shim, repo)
    assert (f"could not be compared with local ref refs/remotes/origin/main at {recorded[:12]}: git does not give "
            "one side whole; a comparison that could not be made is no equality") in text, text


def test_a_missing_record_is_no_equality(shim, repo):  # noqa: F811
    text = _ask(shim, repo, "git push origin main:fresh")
    assert (f"Today's fetch rules map fresh to no present ref, so the evidence rules at source commit "
            f"{_rev(repo, 'HEAD')[:12]} were compared with none; that is no equality.") in text, text


def test_control_equal_rules_name_no_difference(shim, repo):  # noqa: F811
    text = _ask(shim, repo)
    assert "differ from" not in text and "No local record" not in text, text


def test_d20_states_the_hint():
    decisions = (pathlib.Path(gate.__file__).resolve().parents[1] / "DECISIONS.md").read_text(encoding="utf-8")
    flat = " ".join(decisions.split())
    assert "Level 1 names a difference of the evidence rules against a local record as a hint, never as a verdict" in flat
