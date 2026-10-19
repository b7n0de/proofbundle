"""D95, Nachtrag 37, point 4 (B37-1, B37-2): a data step that writes a file counts as a write, read as getopt reads it.

The order: a data step that writes a file counts as writing, read as getopt reads it (bundled short options, a value
directly at the option, abbreviations of long options, `-` and `--` as operands), measured with GNU coreutils 9.4 and
8.32; every program of _SH_DATA that can write a file checked, built or not affected, with a measurement; a write into
`.git/hooks`, `.git/config` or the gate's directory carries the weight of _D72_WRITES.

Measured with GNU coreutils 9.4 under strace -f in an empty folder per form (truth_data_writes_n37.py, 70 forms;
truth_getopt_n37b.py, 121 forms; date only as the user nobody with an empty capability set and EPERM injected into every
call that sets the clock): sort writes the file of each -o in every spelling getopt takes (`-uoF`, `--o=F`, `--outp F`,
`F` after the operands, `-` is a file there) and temporary files `sortXXXXXX` in the folder of -T or TMPDIR; uniq writes
its second operand unless it is `-`, with the obsolete `+N` read as an option before `--` and as a file after it or under
POSIXLY_CORRECT; tee writes every operand, `-` included, and every word after `--`; tac writes `cutmpXXXXXX` in TMPDIR
from a pipe; date calls clock_settime for -s, --set, --se and an operand that is no `+FORMAT`; an abbreviated
--compress-program starts the program. Every other program of _SH_DATA opened no file for writing in the forms measured.
8.32 is NOT MEASURED here (no such program in this container, no network).

RED at the head of PLUGIN_N35: every write of a data step into the configuration, the hooks or the gate's directory in a
spelling the old rules did not read, alone and in a chain, date setting the clock and an abbreviated compress program
in a chain, and a data step whose word the shell builds. The counter cases and the old rules are controls, green at both.
"""
from __future__ import annotations

import json
import os
import sys
import time

import pytest

import _gate_answer as ga
import test_plugin_n30_short_line_d72 as d72

gate = d72.gate
pytestmark = d72.pytestmark
_clean = d72._clean
HOSTS = ("claude", "codex")


@pytest.fixture
def repo(tmp_path):
    """A repository with f.txt, a folder named `-d` (so a word that starts with a dash can name a path in it) and an
    ordinary folder tmpdir."""
    r = d72._repo(tmp_path)
    (r / "f.txt").write_text("b\na\na\n")
    (r / "-d").mkdir()
    (r / "tmpdir").mkdir()
    return r


def _out(repo, form, host="claude"):
    command = form.replace("{R}", str(repo)).replace("{GATE}", os.environ["PROOFBUNDLE_GATE_DIR"])
    return gate.decide(command, str(repo), time.monotonic() + 60, host)


def _ids(out):
    return [] if out is None else [v.reason_id for v in out.verdicts]


def _written(repo, command):
    steps: list = []
    gate._sh_walk(gate._sh_parse(command), str(repo), steps)
    return steps[0].write_targets()


#: Measured spellings and the files they wrote (truth_data_writes_n37.py and truth_getopt_n37b.py with GNU coreutils 9.4;
#: OUT, OUT1, OUT2 the outputs, IN the input, TMP the temporary folder).
MEASURED = [
    ("sort -o OUT IN", ["OUT"]), ("sort -oOUT IN", ["OUT"]), ("sort -uo OUT IN", ["OUT"]), ("sort -uoOUT IN", ["OUT"]),
    ("sort -ruo OUT IN", ["OUT"]), ("sort --output=OUT IN", ["OUT"]), ("sort --output OUT IN", ["OUT"]),
    ("sort --out=OUT IN", ["OUT"]), ("sort --o=OUT IN", ["OUT"]), ("sort --outp OUT IN", ["OUT"]),
    ("sort IN -o OUT", ["OUT"]), ("sort -k1 -o OUT IN", ["OUT"]), ("sort -t -o IN", []), ("sort -- -o IN", []),
    ("sort -k -o IN", []), ("sort -S 1M -o OUT IN", ["OUT"]), ("sort -m -o OUT IN IN", ["OUT"]), ("sort -o - IN", ["-"]),
    ("sort -u IN", []), ("sort -o OUT -- IN", ["OUT"]), ("sort --outpu=OUT IN", ["OUT"]), ("sort -bo OUT IN", ["OUT"]),
    ("sort -to IN", []), ("sort -To IN", ["o/sortXXXXXX"]), ("sort --o OUT IN", ["OUT"]),
    ("sort +0 -1 -o OUT IN", ["OUT"]), ("sort -T TMP IN", ["TMP/sortXXXXXX"]), ("sort -TTMP IN", ["TMP/sortXXXXXX"]),
    ("sort --temporary-directory=TMP IN", ["TMP/sortXXXXXX"]), ("sort --te=TMP IN", ["TMP/sortXXXXXX"]),
    ("sort --t=TMP IN", ["TMP/sortXXXXXX"]), ("TMPDIR=TMP sort IN", ["TMP/sortXXXXXX"]),
    ("sort -yo IN", []),
    ("uniq IN OUT", ["OUT"]), ("uniq -c IN OUT", ["OUT"]), ("uniq - OUT", ["OUT"]), ("uniq -- IN OUT", ["OUT"]),
    ("uniq -f 1 IN OUT", ["OUT"]), ("uniq -f1 IN OUT", ["OUT"]), ("uniq --skip-fields 1 IN OUT", ["OUT"]),
    ("uniq --skip-f=1 IN OUT", ["OUT"]), ("uniq IN -c OUT", ["OUT"]), ("uniq IN -", []), ("uniq IN", []),
    ("uniq -- -x OUT", ["OUT"]), ("uniq --group IN OUT", ["OUT"]), ("uniq --all-repeated=separate IN OUT", ["OUT"]),
    ("uniq +1 IN OUT", ["OUT"]), ("uniq IN +1 OUT", ["OUT"]), ("uniq -1 IN OUT", ["OUT"]), ("uniq -12c IN OUT", ["OUT"]),
    ("uniq -cf1 IN OUT", ["OUT"]), ("uniq -cf 1 IN OUT", ["OUT"]), ("uniq -- IN -x", ["-x"]), ("uniq -- IN +1", ["+1"]),
    ("uniq IN -- OUT", ["OUT"]), ("uniq --check=1 IN OUT", ["OUT"]), ("uniq --skip-c 1 IN OUT", ["OUT"]),
    ("uniq --gr IN OUT", ["OUT"]), ("uniq - -", []),
    ("tee OUT", ["OUT"]), ("tee -a OUT", ["OUT"]), ("tee OUT1 OUT2", ["OUT1", "OUT2"]), ("tee -", ["-"]),
    ("tee -- -x", ["-x"]), ("tee -- OUT", ["OUT"]), ("tee -ap OUT", ["OUT"]), ("tee -i OUT", ["OUT"]),
    ("tee --app OUT", ["OUT"]), ("tee --a OUT", ["OUT"]), ("tee --output-error OUT", ["OUT"]),
    ("tee --output-error=warn OUT", ["OUT"]), ("tee --o OUT", ["OUT"]),
    ("TMPDIR=TMP tac", ["TMP/cutmpXXXXXX"]), ("tac IN", []),
]


@pytest.mark.parametrize("form, files", MEASURED)
def test_D95_a_data_step_writes_what_getopt_reads_as_measured(repo, form, files):
    """Each measured file is among the files the step writes for the gate; where the program wrote none, the gate names
    none. The gate may name more where another reading of the same words writes more (`uniq IN -c OUT` writes `-c` under
    POSIXLY_CORRECT), never fewer."""
    written, _unknown = _written(repo, form)
    for f in files:
        assert f in written, (form, written)
    if not files:
        assert written == [], (form, written)


#: Writes into the configuration, the hooks or the gate's directory in a spelling only getopt reads. Alone each asked
#: nothing at the head of PLUGIN_N35 (no answer).
PROTECTED = [
    "sort -uo .git/hooks/pre-commit f.txt", "sort -uo.git/hooks/pre-commit f.txt", "sort -ruo .git/config f.txt",
    "sort -o .git/config f.txt", "sort --out=.git/config f.txt", "sort --o=.git/config f.txt",
    "sort --outp .git/config f.txt", "sort -bo .git/config f.txt", "sort f.txt -o .git/config",
    "sort -o .git/config -- f.txt", "sort -k1 -o .git/config f.txt", "sort +0 -1 -o .git/config f.txt",
    "sort -T .git/hooks f.txt", "sort --te=.git/hooks f.txt", "TMPDIR=.git/hooks sort f.txt",
    "TMPDIR=.git/hooks tac f.txt",
    "uniq f.txt .git/config", "uniq -c f.txt .git/hooks/pre-commit", "uniq +1 f.txt .git/config",
    "uniq -cf1 f.txt .git/config", "uniq --skip-c 1 f.txt .git/config", "uniq --gr f.txt .git/config",
    "uniq -- f.txt -d/../.git/config", "uniq f.txt -d/../.git/config",
    "uniq f.txt -cf/../.git/config", "uniq +1 .git/config",
    "tee -- -d/../.git/config < f.txt", "tee f.txt -d/../.git/config < f.txt",
]


@pytest.mark.parametrize("host", HOSTS)
@pytest.mark.parametrize("form", PROTECTED)
def test_D95_a_write_of_a_data_step_into_configuration_or_hooks_asks_like_a_file_write(repo, form, host):
    out = _out(repo, form, host)
    assert out is not None and out.decision == "ask" and "write_to_repo_state" in _ids(out), (form, host, _ids(out))


@pytest.mark.parametrize("host", HOSTS)
@pytest.mark.parametrize("form", ["sort -uo {GATE}/mode f.txt", "sort --out={GATE}/mode f.txt",
                                  "uniq f.txt {GATE}/mode", "uniq -- f.txt {GATE}/rules.json",
                                  "sort -T {GATE} f.txt"])
def test_D95_a_write_of_a_data_step_into_the_gate_directory_is_denied(repo, form, host):
    out = _out(repo, form, host)
    assert out is not None and out.decision == "deny" and "write_to_gate_dir" in _ids(out), (form, host, _ids(out))


@pytest.mark.parametrize("form", ["sort -uo .git/config f.txt && git status", "sort -uo.git/config f.txt && git status",
                                  "sort --out=.git/config f.txt && git status", "uniq +1 f.txt .git/config && git status",
                                  "sort -T .git/hooks f.txt && git status", "tee -- -d/../.git/config < f.txt && git status"])
def test_D95_the_write_gives_the_chain_its_reason_and_the_line_its_weight(repo, form):
    """D72: the line names the git step and gives the reason of the write (D8), as for a redirection."""
    out = _out(repo, form)
    assert out.decision == "ask" and "write_to_repo_state" in _ids(out), _ids(out)
    assert " git status because the write touches git configuration or hooks (D8)." in d72._line(out), d72._line(out)


@pytest.mark.parametrize("form", [
    "date -s 2020-01-01 && git status", "date -us 2020 && git status", "date -us2020 && git status",
    "date --set=2020-01-01 && git status", "date --set 2020-01-01 && git status", "date --se=2020-01-01 && git status",
    "date 0101000020 && git status", "date -u 0101000020 && git status",
    "sort --compress-p=sh -S 1 f.txt && git status", "sort --co=sh f.txt && git status", "sort --co sh f.txt && git status",
    "sort --c=sh f.txt && git status", "sort --bogus f.txt && git status", "uniq --s=1 f.txt && git status",
    "tee -x out.txt < f.txt && git status",
    "sort $OPT f.txt && git status", "uniq f.txt $OUT && git status", "date $D && git status",
    "sort *.txt && git status", "git status && sort $OPT f.txt", "git log -1; date $D", "git status | tee $OUT"])
def test_D95_a_data_step_that_sets_the_clock_starts_a_program_or_cannot_be_read_is_no_read_step(repo, form):
    """date that sets the clock, sort that starts a compress program, an option getopt refuses and a word the shell
    builds make the step no data step: the git step after it is not free."""
    out = _out(repo, form)
    assert out is not None and out.decision in ("ask", "deny"), (form, _ids(out))


@pytest.mark.parametrize("form", [
    "sort -T tmpdir f.txt && git status", "sort -u f.txt && git status", "sort -t, -k2 f.txt && git status",
    "uniq f.txt && git status", "uniq f.txt - && git status", "uniq -c f.txt && git status",
    "tee out.txt < f.txt && git status", "date +%s && git status", "date -u +%F && git status",
    "date -d 2020-01-01 && git status", "date -ds && git status", "date -r f.txt && git status",
    "sort -yo f.txt && git status"])
def test_D95_control_a_data_step_that_writes_no_guarded_file_stays_free(repo, form):
    out = _out(repo, form)
    assert out is not None and out.decision == "pass", (form, _ids(out))


@pytest.mark.parametrize("form", ["sort -o out.txt f.txt && git status", "uniq f.txt out.txt && git status",
                                  "sort -t -o f.txt && git status", "sort --output=out.txt f.txt && git status",
                                  "sort --o=out.txt f.txt && git status", "sort -uoout.txt f.txt && git status",
                                  "uniq +1 f.txt out.txt && git status"])
def test_D95_the_old_rules_stay_and_an_output_file_in_any_spelling_changes_the_state(repo, form):
    out = _out(repo, form)
    assert out is not None and out.decision == "ask" and "step_after_state_change" in _ids(out), (form, _ids(out))


@pytest.mark.parametrize("form", ["sort -o out.txt f.txt", "sort -o - f.txt", "uniq f.txt out.txt", "tee out.txt",
                                  "tee - < f.txt", "date -s 2020-01-01", "sort -T tmpdir f.txt"])
def test_D95_control_a_data_step_alone_that_writes_no_guarded_file_gets_no_answer(repo, form):
    assert _out(repo, form) is None, form


def test_D95_the_measured_programs_and_temporary_names():
    assert set(gate._GETOPT_SPECS) == {"sort", "uniq", "tee", "date"}
    assert gate._GETOPT_TEMP_NAMES == {"sort": "sortXXXXXX", "tac": "cutmpXXXXXX"}
    assert {"sort", "uniq", "tee", "date", "tac"} <= gate._SH_DATA


@pytest.mark.parametrize("words, posix, options, operands, problem", [
    (["-uoF", "IN"], False, [("u", None), ("o", "F")], [("IN", False)], None),
    (["--out", "F", "IN"], False, [("o", "F")], [("IN", False)], None),
    (["--c=sh"], False, [], [], "ambiguous"), (["--x"], False, [], [], "unrecognized"),
    (["-x"], False, [], [], "invalid option"), (["-o"], False, [], [], "requires an argument"),
    (["--debug=1"], False, [], [], "doesn't allow"), (["--", "-o", "F"], False, [], [("-o", True), ("F", True)], None),
    (["-", "-o", "F"], False, [("o", "F")], [("-", False)], None), (["-y", "o", "IN"], False, [("y", "")],
                                                                      [("o", False), ("IN", False)], None),
    (["-y", "12", "IN"], False, [("y", "12")], [("IN", False)], None),
])
def test_D95_getopt_as_measured_for_sort(words, posix, options, operands, problem):
    got_options, got_operands, why = gate._getopt_read("sort", words, posix)
    if problem is None:
        assert why is None and got_options == options and got_operands == operands, (got_options, got_operands, why)
    else:
        assert why is not None and problem in why, why


def test_D95_getopt_under_posixly_correct_ends_the_options_at_the_first_operand():
    assert gate._getopt_read("tee", ["OUT", "-a"], posix=True)[1] == [("OUT", False), ("-a", True)]
    assert gate._getopt_read("tee", ["OUT", "-a"])[:2] == ([("a", None)], [("OUT", False)])
    assert gate._getopt_read("uniq", ["IN", "--", "X"], posix=True)[1] == [("IN", False), ("--", True), ("X", True)]


def test_D95_an_abbreviation_that_names_one_option_by_several_names_is_no_ambiguity():
    """`date --u` stands for --uct, --utc and --universal, all `-u` (measured: exit 0); `date --rfc` is ambiguous."""
    assert gate._getopt_read("date", ["--u"]) == ([("u", None)], [], None)
    assert "ambiguous" in gate._getopt_read("date", ["--rfc"])[2]


@pytest.mark.parametrize("form", ["sort -uo .git/config f.txt", "echo x > .git/config"])
def test_D95_under_the_switch_of_claude_code_the_write_of_a_data_step_is_answered_like_a_redirection(repo, tmp_path,
                                                                                                    form):
    """The hook with --autonomous (D85): the data step's write and the redirection get the same answer."""
    answers = []
    for command in (form, "echo x > .git/config"):
        event = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": str(repo), "session_id": "s-d95",
                 "tool_input": {"command": command}}
        env = {k: os.environ[k] for k in ("PATH", "HOME", "LC_ALL", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_SYSTEM",
                                          "PROOFBUNDLE_GATE_DIR")}
        env["CLAUDE_PLUGIN_DATA"] = str(tmp_path / "data")
        proc, entry = ga.run_hook([sys.executable, "-I", gate.__file__, "--host", "claude", gate.AUTONOMOUS_FLAG],
                                  json.dumps(event), env, cwd=str(repo))
        assert proc.returncode == 0, proc.stderr
        answers.append((json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecision"], entry["autonomy"]["klasse"],
                        "write_to_repo_state" in entry["reason_ids"]))
    assert answers[0] == answers[1] and answers[0][2], answers
