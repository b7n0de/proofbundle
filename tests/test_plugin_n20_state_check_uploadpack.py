"""D47 part 1, follow-up note 20 (O19-1): the uploadpack keys of D44 do not hinder the state check of add, commit -m and the
checkout of worktree add.

Measured in follow-up note 19 (truth_n19_state.jsonl, 45 runs, git 2.43.0 under strace -f with no network): `git add`,
`git commit -m` and `git worktree add -q` started the same programs with each of the five keys set true, false or to an
invalid value as without it, and opened no connection. In the corpus with the keys in every .git/config, 6 rows asked
only for them. The owner chose to free them (O19-1, 16.10.2026 18:3x Berlin).

Unchanged: uploadpack.packObjectsHook (it names a program) and every neighbouring name ask, as in D44; every other
finding of the state check stands after the key.

RED at a8ca017a for each freed case (the state check named the key), under Codex too, where the same state check
runs; the controls answer the same at both heads.
"""
from __future__ import annotations

import pytest

import _worktree_layout as w
import test_plugin_uploadpack_read_profile as d44

pytestmark = w.d.pytestmark
DELTA, KEYS, VALUES, NEIGHBOURS = d44.DELTA, d44.KEYS, d44.VALUES, d44.NEIGHBOURS
_answer, _append = d44._answer, d44._append
FORMS = {"add": "git add README.md", "commit": "git commit -m one-more", "add_minus_c": "git -C {repo} add README.md",
         "commit_minus_c": "git -C {repo} commit -m one-more",
         "worktree_add": "git -C {repo} worktree add -q -b n20 {target} HEAD"}


@pytest.fixture(autouse=True)
def _clean(monkeypatch, tmp_path):
    w.clean(monkeypatch, tmp_path)


@pytest.fixture
def main(tmp_path):
    repo = w.main_repo(tmp_path)
    (repo / "README.md").write_text("one\ntwo\n")
    return repo


def _command(main, tmp_path, form: str) -> str:
    if form.startswith("commit"):
        w.git(main, "add", "README.md")
    return FORMS[form].format(repo=main, target=tmp_path / "wt_n20")


@pytest.mark.parametrize("form", sorted(FORMS))
def test_N20_control_the_form_is_free_without_the_keys(tmp_path, main, form):
    assert _answer(main, _command(main, tmp_path, form), **DELTA)[:2] == (0, None)


@pytest.mark.parametrize("value", VALUES)
@pytest.mark.parametrize("key", KEYS)
@pytest.mark.parametrize("form", sorted(FORMS))
def test_N20_a_state_form_with_an_uploadpack_key_is_free(tmp_path, main, form, key, value):
    w.git(main, "config", key, value)
    code, decision, reason = _answer(main, _command(main, tmp_path, form), **DELTA)
    assert (code, decision) == (0, None), reason


@pytest.mark.parametrize("form", ["add", "worktree_add"])
def test_N20_all_five_keys_without_a_value_are_free(tmp_path, main, form):
    _append(main, "[uploadpack]\n" + "".join(f"\t{k.split('.', 1)[1]}\n" for k in KEYS))
    assert _answer(main, _command(main, tmp_path, form), **DELTA)[:2] == (0, None)


@pytest.mark.parametrize("form", ["add", "commit_minus_c"])
def test_N20_control_pack_objects_hook_asks(tmp_path, main, form):
    w.git(main, "config", "uploadpack.packObjectsHook", "true")
    code, decision, reason = _answer(main, _command(main, tmp_path, form), **DELTA)
    assert (code, decision) == (0, "ask") and "uploadpack.packobjectshook" in reason, reason


@pytest.mark.parametrize("key", NEIGHBOURS)
def test_N20_control_a_neighbouring_key_asks(tmp_path, main, key):
    _append(main, "[{}]\n\t{} = true\n".format(*key.rsplit(".", 1)) if key.count(".") == 1 else
            '[{} "{}"]\n\t{} = true\n'.format(key.split(".", 1)[0], key.split(".", 1)[1].rsplit(".", 1)[0],
                                             key.rsplit(".", 1)[1]))
    code, decision, reason = _answer(main, _command(main, tmp_path, "add"), **DELTA)
    assert (code, decision) == (0, "ask"), (key, reason)


def test_N20_an_uploadpack_key_hides_no_other_finding(tmp_path, main):
    w.git(main, "config", "uploadpack.allowFilter", "true")
    w.git(main, "config", "diff.external", "true")
    code, decision, reason = _answer(main, _command(main, tmp_path, "add"), **DELTA)
    assert (code, decision) == (0, "ask") and "diff.external" in reason and "uploadpack" not in reason, reason


@pytest.mark.parametrize("form", ["add_minus_c", "commit_minus_c"])
def test_N20_under_codex_too_the_key_changes_nothing(tmp_path, main, form):
    command = _command(main, tmp_path, form)
    before = _answer(main, command, host="codex", **DELTA)[:2]
    w.git(main, "config", "uploadpack.allowAnySHA1InWant", "true")
    assert _answer(main, command, host="codex", **DELTA)[:2] == before
