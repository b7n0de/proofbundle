"""Round 6, R6-2: the git allow-list frees a subcommand only in a checked invocation form.

A subcommand name alone does not establish that an invocation cannot execute other programs; options
and Git configuration can select helpers, filters, hooks or editors. These tests judge the COMMAND TEXT
only (via the gate's `_strict_git`); they run no helper programs and transfer nothing.

Red against 2b813de2 (the four forms returned None = free); green after the fix (NOT MEASURED).
Since review round 9 (owner choice B) no form here is free any more; only the bare `git --version` is.
"""
import importlib.util
import os

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
GATE = os.path.join(HERE, "..", "plugins", "proofbundle", "hooks", "proofbundle_gate.py")


def _gate():
    spec = importlib.util.spec_from_file_location("pb_gate_r62", GATE)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _not_measured(g, words):
    r = g._strict_git(words, "/repo")
    # review round 9, owner choice B: a repository form carries _NOT_FREE, a possible transfer _MAYBE_PUSH
    return r is not None and r[1] is g.UNKNOWN and r[2] in ([g._MAYBE_PUSH], [g._NOT_FREE])


def _free(g, words):
    return g._strict_git(words, "/repo") is None


# the four reproduced forms from the review (helper-script paths shortened) -> NOT MEASURED
FOUR_FORMS = [
    ["grep", "--open-files-in-pager=/tmp/ship.sh", "needle"],
    ["fetch", "--upload-pack=/tmp/upload.sh", "origin"],
    ["-c", "diff.external=/tmp/ship.sh", "diff"],
    ["rebase", "-x/tmp/ship.sh", "HEAD~1"],
]


def test_four_review_forms_are_not_measured():
    g = _gate()
    for words in FOUR_FORMS:
        assert _not_measured(g, words), words


def test_established_not_measured_is_never_lost():
    """A `-c` sets NOT MEASURED in the global-option parse; an allow-listed subcommand must not drop it."""
    g = _gate()
    assert _not_measured(g, ["-c", "core.pager=/tmp/x", "log"])
    assert _not_measured(g, ["-c", "diff.external=/tmp/x", "show", "HEAD"])


def test_rebase_exec_attached_short_form():
    g = _gate()
    assert _not_measured(g, ["rebase", "-x/tmp/ship.sh", "HEAD~1"])      # attached
    assert _not_measured(g, ["rebase", "-x", "/tmp/ship.sh", "HEAD~1"])  # separated
    assert _not_measured(g, ["rebase", "--exec=/tmp/ship.sh", "HEAD~1"])
    assert _not_measured(g, ["rebase", "--exec", "/tmp/ship.sh", "HEAD~1"])


def test_other_program_selecting_options_are_not_measured():
    g = _gate()
    assert _not_measured(g, ["fetch", "--exec=/tmp/x", "origin"])     # --exec is an --upload-pack alias
    assert _not_measured(g, ["grep", "-Oopen", "needle"])             # -O opens a pager program
    assert _not_measured(g, ["log", "--output=/tmp/x"])               # writes a file
    assert _not_measured(g, ["diff", "--ext-diff"])                   # enables external diff
    assert _not_measured(g, ["rebase", "-i", "HEAD~2"])               # interactive editor


def test_unmodelled_transports_stay_not_measured():
    g = _gate()
    assert _not_measured(g, ["send-pack", "origin"])
    assert _not_measured(g, ["frobnicate"])          # unknown subcommand


def test_the_formerly_checked_forms_are_not_free():
    """Review round 9, owner choice B: the bare forms and vetted options that were free are not free by their words
    any more; only the bare `git --version` stays free. Since review fix 18 part B (class a, D34) each of these read forms is
    marked for the judge, which frees it only after the read profile of its repository."""
    g = _gate()
    for words in (["status"], ["status", "-s"], ["log", "--oneline"], ["diff", "--stat"],
                  ["show", "HEAD"], ["grep", "needle"], ["branch", "-a"],   # fetch left the list (R7-2)
                  ["-C", "/path", "status"], ["log", "--oneline", "-n", "5"]):
        assert not _free(g, words) and g._strict_git(words, "/repo")[2] == [g._READ_FREE], words
    assert _free(g, ["--version"])
    # follow-up note 19b: rebase left the allow-list (S1, fallback A), so even its bare form is NOT MEASURED now
    assert _not_measured(g, ["rebase", "HEAD~1"])


def test_real_push_still_resolves():
    g = _gate()
    assert g._strict_git(["push", "origin", "main"], "/repo") == ("git push", "/repo", ["origin", "main"])


# --- siblings of the class (CLASSES AND SIBLINGS): the environment and git config writes ----

def _calls(g, command):
    return g.gated_calls(command)


@pytest.mark.parametrize("command", [
    "GIT_EXTERNAL_DIFF=/tmp/ship.sh git diff",            # the environment form of -c diff.external=
    "GIT_SSH_COMMAND=/tmp/ship.sh git fetch origin",      # selects the transport program for fetch
    "GIT_PAGER=/tmp/ship.sh git log",                     # a pager program
    "GIT_EDITOR=/tmp/ship.sh git commit",                 # an editor program
    "GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=diff.external GIT_CONFIG_VALUE_0=/tmp/ship.sh git diff",
    "HOME=/tmp/elsewhere git diff",                       # a different global configuration
    "env GIT_EXTERNAL_DIFF=/tmp/ship.sh git diff",        # through the env wrapper
    "export GIT_EXTERNAL_DIFF=/tmp/ship.sh; git diff",    # exported earlier in the same command
    "bash -c 'GIT_EXTERNAL_DIFF=/tmp/ship.sh git diff'",  # nested
    "git config diff.external /tmp/ship.sh",              # a config write that selects a helper
    "git config core.editor /tmp/ship.sh",
    "git config set diff.external /tmp/ship.sh",          # git 2.46+ form
    "git config --edit",                                  # opens an editor
    "git config --file /tmp/x.cfg diff.external y",       # an unvetted option
])
def test_environment_and_config_writes_that_can_select_a_program_are_not_measured(command):
    g = _gate()
    calls = _calls(g, command)
    assert calls and all(c[1] is g.UNKNOWN for c in calls), (command, calls)


@pytest.mark.parametrize("command", [
    "GIT_PAGER=cat git log", "GIT_EDITOR=true git commit", "git config user.name t", "git config get user.email",
    "git config --includes --get remote.origin.url", "git config --file x.cfg --list",
    "git status && git diff --stat",
])
def test_vetted_assignments_and_config_reads_are_not_free(command):
    """Review round 9, owner choice B: a vetted assignment or a configuration read leaves the form a repository
    form, and none is free. A vetted pager assignment keeps a read form so too (class a, D34: it counts like a pager
    key). A read step of a longer command keeps its mark for the text of D37 under Codex and is not free either
    (follow-up note 11)."""
    g = _gate()
    calls = _calls(g, command)
    marks = ([g._NOT_FREE], [g._READ_NOT_FREE])
    assert calls and all(c[2] in marks for c in calls), (command, calls)


@pytest.mark.parametrize("command", ["GIT_TERMINAL_PROMPT=0 git status", "LC_ALL=C git status"])
def test_a_vetted_assignment_the_read_profile_accepts_leaves_a_read_form_marked(command):
    """Review fix 18 part B, class a (D34): an assignment that selects no pager and no unknown GIT_* setting leaves the read
    form marked for the judge, which frees it only after the read profile."""
    g = _gate()
    assert _calls(g, command) == [("git status", ".", [g._READ_FREE])]


@pytest.mark.parametrize("command", ["git config --get remote.origin.url", "git config --list"])
def test_a_config_read_of_d68_is_marked_for_the_read_profile(command):
    """Follow-up note 27, O23-7 (D68): the four read actions of `git config` are read forms of class a; the judge frees them
    only after the read profile, never under Codex."""
    g = _gate()
    assert _calls(g, command) == [("git config", ".", [g._READ_FREE])]


def test_an_unvetted_askpass_makes_a_push_not_measured():
    g = _gate()
    assert g.gated_calls("GIT_ASKPASS=/tmp/ship.sh git push origin main") == [("git push", g.UNKNOWN, None)]
    assert g.gated_calls("GIT_TERMINAL_PROMPT=0 git push origin main") == [("git push", ".", ["origin", "main"])]
