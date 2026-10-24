"""D112, Nachtrag 41 point 2 (O40-3): a variable of the hook's environment like HOME in a path word is put in.

The order: variables from the environment of the hook like HOME are put in by the gate; code of other languages stays
unread (D8), cd stays class e. Found in PLUGIN_N35 as the open siblings of F35-1 and F35-2 (O40-3): `$D/x` of a
variable the command does not set named no path, so `rm -r $ELSE/build` or `echo x >> $RC/.bashrc` got no answer where
the same words with the path written out are denied.

Measured with Claude Code 2.1.303 (truth_env_o403.sh, the stand-in API, three Bash calls, sha256 prefixes of the values
only): without a start file 24 names have the same value in the PreToolUse hook and in the Bash call, HOME, PATH,
TMPDIR, XDG_CONFIG_HOME, LANG and a name set at the start among them; PWD differs after a cd, CLAUDE_PROJECT_DIR is
the hook's only, AI_AGENT has another value; an export of one call is gone in the next. With a ~/.bashrc that exports
TMPDIR and XDG_CONFIG_HOME anew, exactly these two differ.

The rule: where a word starts with `$X`, `${X}`, `${X:-w}` or `${X-w}` (quoted or not, with a literal rest) and X is
in the hook's environment and is not a name the call sets itself or did not see with the hook's value (PWD, OLDPWD,
SHLVL, _, BASH*, CLAUDE_PROJECT_DIR, AI_AGENT), the path with the hook's value is judged in addition to what the gate
judged before (a value the command sets, D100, stays); for `${X:-w}` with X unset or empty the literal w. A start file
may set another value, so the path is a candidate and never frees: a word that was not known stays not known where the
gate counts that (write_targets). The reason names the word as written, never the value (D49).

RED at f18b3183 (the head of PLUGIN_N42): every form below; the controls are green at both.
"""
from __future__ import annotations

import os
import time

import pytest

import test_plugin_n30_short_line_d72 as d72

gate = d72.gate
pytestmark = d72.pytestmark
HOSTS = ("claude", "codex")


@pytest.fixture
def world(tmp_path, monkeypatch):
    r = d72._repo(tmp_path)
    (r / "f.txt").write_text("x\n")
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    (home / ".claude").mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("KEYS", str(home / ".ssh"))
    monkeypatch.setenv("CFG", str(home / ".claude"))
    monkeypatch.setenv("RC", str(home))
    monkeypatch.setenv("ELSE", str(tmp_path / "elsewhere"))
    monkeypatch.setenv("EMPTY", "")
    monkeypatch.delenv("UNSET_X", raising=False)
    monkeypatch.delenv("CLAUDE_PROJECT_DIR", raising=False)
    return {"repo": r, "home": home, "else": tmp_path / "elsewhere"}


def _ids(out):
    return [] if out is None else [v.reason_id for v in out.verdicts]


def _out(world, form, host="claude"):
    form = form.replace("{H}", str(world["home"])).replace("{E}", str(world["else"]))
    return gate.decide(form, str(world["repo"]), time.monotonic() + 60, host)


#: (the form through a variable of the hook's environment, the same form with the path written out, the reason)
FORMS = [
    ("cat $KEYS/config", "cat {H}/.ssh/config", "secret_path"),
    ("cat \"${KEYS}/config\"", "cat {H}/.ssh/config", "secret_path"),
    ("rm -r $ELSE/build", "rm -r {E}/build", "delete_outside_work"),
    ("find $ELSE/build -delete", "find {E}/build -delete", "delete_outside_work"),
    ("echo x >> $ELSE/log", "echo x >> {E}/log", "append_outside_work"),
    ("cp f.txt $CFG/settings.json", "cp f.txt {H}/.claude/settings.json", "write_to_host_settings"),
    ("cp f.txt ${CFG:-/nowhere}/settings.json", "cp f.txt {H}/.claude/settings.json", "write_to_host_settings"),
    ("cp f.txt ${UNSET_X:-{H}/.claude}/settings.json", "cp f.txt {H}/.claude/settings.json", "write_to_host_settings"),
    ("cp f.txt ${UNSET_X-{H}/.claude}/settings.json", "cp f.txt {H}/.claude/settings.json", "write_to_host_settings"),
    ("echo x >> $RC/.bashrc", "echo x >> {H}/.bashrc", "write_to_shell_start"),
    ("cat > $RC/.bashrc <<'E'\nx\nE", "cat > {H}/.bashrc <<'E'\nx\nE", "write_to_shell_start"),
    ("D=$RC; cp f.txt $D/.bashrc", "cp f.txt {H}/.bashrc", "write_to_shell_start"),
    ("bash -c 'cat $KEYS/config'", "cat {H}/.ssh/config", "secret_path"),
    ("cp f.txt $EMPTY/etc/profile.d/x.sh", "cp f.txt /etc/profile.d/x.sh", None),
]


@pytest.mark.parametrize("host", HOSTS)
@pytest.mark.parametrize("form,written,reason", FORMS, ids=[f[0].splitlines()[0] for f in FORMS])
def test_D112_a_variable_of_the_hook_environment_is_put_in(world, form, written, reason, host):
    """The form through the variable gets the answer of the form with the path written out, and its reason."""
    literal = _out(world, written, host)
    got = _out(world, form, host)
    assert literal is not None and got is not None, (form, host, _ids(got))
    assert got.decision == literal.decision, (form, host, got.decision, literal.decision, _ids(got))
    if reason is not None:
        assert reason in _ids(got) and reason in _ids(literal), (form, host, _ids(got), _ids(literal))
    for name in ("KEYS", "CFG", "ELSE"):
        assert os.environ[name] not in got.text, "D49: the reason names the word as written, never the value"


@pytest.mark.parametrize("form", ["cp f.txt $TMPDIR/x", "cp f.txt \"$HOME/notes.txt\"", "cat $UNSET_X/config",
                                  "cp f.txt $PWD/out.txt", "cp f.txt $OLDPWD/out.txt", "ls $KEYS", "test -d $KEYS",
                                  "cp f.txt ${UNSET_X:-out}/x.txt", "echo $CFG", "cat ${CFG}x/settings.json"])
def test_D112_control_forms_keep_their_answer(world, form):
    """A variable that is not set, a name the call sets itself, a word without a path, a folder only named by ls or
    test (D102), a default in the work folder and a variable glued to more name: no new answer."""
    out = _out(world, form)
    for reason in ("secret_path", "delete_outside_work", "append_outside_work", "write_to_host_settings",
                   "write_to_shell_start"):
        assert reason not in _ids(out), (form, _ids(out))


def test_D112_a_name_the_call_does_not_see_with_the_hook_value_is_not_put_in(world, monkeypatch):
    """Measured: CLAUDE_PROJECT_DIR is in the hook's environment only, PWD changes with cd, AI_AGENT has another value
    in the call; none of them is put in."""
    for name in ("CLAUDE_PROJECT_DIR", "PWD", "OLDPWD", "AI_AGENT", "SHLVL", "BASH_ENV"):
        monkeypatch.setenv(name, str(world["home"] / ".ssh"))
        out = _out(world, f"cat ${name}/config")
        assert "secret_path" not in _ids(out), (name, _ids(out))
        monkeypatch.delenv(name)


def test_D112_a_name_the_command_sets_is_the_command_s_not_the_hook_s(world):
    """D100 reads the value the command sets; a name the command sets in a way the gate cannot read (`$(mktemp -d)`)
    keeps today's answer; the hook's value comes in only for a name the command does not set. A program's own
    assignment before it does not count (bash expands the program's words first, D100)."""
    assert "secret_path" not in _ids(_out(world, "KEYS=/nowhere; cat $KEYS/config"))
    assert "delete_outside_work" not in _ids(_out(world, "ELSE=$(mktemp -d); rm -r $ELSE/build"))
    assert "secret_path" in _ids(_out(world, "KEYS=/nowhere cat $KEYS/config"))
    assert "secret_path" in _ids(_out(world, "OTHER=/nowhere; cat $KEYS/config"))


def test_D112_an_unquoted_value_with_blanks_is_split_as_bash_splits_it(world, monkeypatch):
    """`$TWO/config` with TWO=`<home>/.ssh x` is two words to bash, `<home>/.ssh` and `x/config`; quoted it is one path
    whose folder is `.ssh x`, no folder of keys."""
    monkeypatch.setenv("TWO", f"{world['home']}/.ssh x")
    assert "secret_path" in _ids(_out(world, "cat $TWO/config"))
    assert "secret_path" not in _ids(_out(world, "cat \"$TWO/config\""))


def test_D112_the_hook_value_is_a_candidate_a_word_not_known_stays_not_known(world):
    """A redirection through a variable stays a target that is not known (write_targets), so what the gate does for
    an unknown target holds; the hook's value adds its path."""
    steps = gate._sh_parse("echo x > $ELSE/out.txt") if hasattr(gate, "_sh_parse") else None
    assert steps is not None
    flat = []
    gate._sh_walk(steps, str(world["repo"]), flat)
    targets, unknown = flat[0].write_targets({"ELSE": os.environ["ELSE"]})
    assert unknown is True and targets == [str(world["else"] / "out.txt")], (targets, unknown)


def test_D112_without_the_hook_environment_nothing_is_put_in(world):
    """A word of a name the environment the gate is given does not hold names no path, as before."""
    out = gate.decide("cat $KEYS/config", str(world["repo"]), time.monotonic() + 60, "claude",
                      environ={"PATH": os.environ["PATH"], "HOME": str(world["home"])})
    assert "secret_path" not in _ids(out), _ids(out)


@pytest.mark.parametrize("form,word", [("echo x >> $RC/.bashrc", "$RC/.bashrc"), ("echo x >> $HOME/.bashrc", "$HOME/.bashrc"),
                                       ("echo x >> ~/.bashrc", "~/.bashrc"), ("cp f.txt \"${RC}/.profile\"", "\"${RC}/.profile\""),
                                       ("cp f.txt $REPO_DIR/.git/hooks/pre-commit", "$REPO_DIR/.git/hooks/pre-commit")])
def test_D112_the_reason_of_a_write_names_the_word_as_written(world, monkeypatch, form, word):
    """D49: a write the gate judges as a file-tool write (D96, D97, the state of a repository) names the word as written
    where the shell makes its path of the environment, never the path; found with D112 at f18b3183 for `~/.bashrc` and
    `$HOME/.bashrc` already."""
    monkeypatch.setenv("REPO_DIR", str(world["repo"]))
    out = _out(world, form)
    assert out is not None and out.decision in ("ask", "deny"), (form, _ids(out))
    assert str(world["home"]) not in out.text and str(world["repo"]) not in out.text, out.text
    assert word in out.text, (word, out.text)


def test_D112_a_default_with_the_colon_counts_an_empty_value_as_unset(world):
    """`${X:-w}` gives w where X is empty, `${X-w}` gives the empty value (bash): EMPTY is set and empty."""
    out = _out(world, "cp f.txt ${EMPTY:-{H}/.claude}/settings.json")
    assert "write_to_host_settings" in _ids(out), _ids(out)
    out = _out(world, "cp f.txt ${EMPTY-{H}/.claude}/settings.json")
    assert "write_to_host_settings" not in _ids(out), _ids(out)


def test_D112_the_reason_names_the_word_also_where_a_link_resolves_the_path(world, tmp_path, monkeypatch):
    """A write through a link to the repository: the reason names neither the link nor the folder it resolves to."""
    link = tmp_path / "repo-link"
    os.symlink(world["repo"], link)
    monkeypatch.setenv("REPO_LINK", str(link))
    out = _out(world, "cp f.txt $REPO_LINK/.git/hooks/pre-commit")
    assert out is not None and out.decision in ("ask", "deny"), _ids(out)
    assert str(world["repo"]) not in out.text and str(link) not in out.text, out.text
    assert "$REPO_LINK/.git/hooks/pre-commit" in out.text, out.text
