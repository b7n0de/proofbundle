"""Runde 6, R6-2: the git allow-list frees a subcommand only in a checked invocation form.

A subcommand name alone does not establish that an invocation cannot execute other programs; options
and Git configuration can select helpers, filters, hooks or editors. These tests judge the COMMAND TEXT
only (via the gate's `_strict_git`); they run no helper programs and transfer nothing.

Red against 2b813de2 (the four forms returned None = free); green after the fix (NOT MEASURED).
"""
import importlib.util
import os

HERE = os.path.dirname(os.path.abspath(__file__))
GATE = os.path.join(HERE, "..", "plugins", "proofbundle", "hooks", "proofbundle_gate.py")


def _gate():
    spec = importlib.util.spec_from_file_location("pb_gate_r62", GATE)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _not_measured(g, words):
    r = g._strict_git(words, "/repo")
    return r is not None and r[1] is g.UNKNOWN and r[2] == [g._MAYBE_PUSH]


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


def test_checked_forms_stay_free():
    """Bare forms and vetted inert options remain free, so the gate does not become uselessly noisy."""
    g = _gate()
    for words in (["status"], ["status", "-s"], ["log", "--oneline"], ["diff", "--stat"],
                  ["show", "HEAD"], ["grep", "needle"], ["branch", "-a"], ["fetch", "origin"],
                  ["rebase", "HEAD~1"], ["-C", "/path", "status"], ["log", "--oneline", "-n", "5"]):
        assert _free(g, words), words


def test_real_push_still_resolves():
    g = _gate()
    assert g._strict_git(["push", "origin", "main"], "/repo") == ("git push", "/repo", ["origin", "main"])
