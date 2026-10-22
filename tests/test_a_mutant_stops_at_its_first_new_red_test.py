"""A mutant run stops at its first new red test (ECHO-MUTATION-HOCHRECHNUNG-UND-STOPP-01, owner choice 2026-10-22).

WHY THIS FILE EXISTS. At 07b6122c a KILLED mutant took as long as the baseline: nine mutants 2002 s to
2104 s against a baseline of 2089.6 s over 528 test files, because the run of scripts/mutation_check.py
went on through every selected file after the first had gone red. The mutant run now stops at its
first failure (`-x`), without the tests that were red in the baseline of the same selection. A kill
counts only when that test holds, red again under the mutant and green on the restored tree; a run that
goes through without a red test is the survivor's full run; anything else runs the full selection as
before. The red tests come from the JUnit report, not from text.

The cases run real pytest over planted trees through `_run_operators`. Every planted test writes a trace
line on each run, saying whether the source was mutated, so a case can count what the mutant run ran.
The cases that say "red on 07b6122c" fail there: that gate runs the whole selection under every mutant.
"""
from __future__ import annotations

import contextlib
import importlib.util
import io
import subprocess
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

_SPUR = '''
from pathlib import Path


def spur(name):
    quelle = (Path(__file__).parents[1] / "src" / "mini" / "core.py").read_text(encoding="utf-8")
    zustand = "mutant" if "if False:" in quelle else "rein"
    with (Path(__file__).parent / "spur.log").open("a", encoding="utf-8") as f:
        f.write(f"{name} {zustand}\\n")
'''

_KERN = {
    "src/mini/__init__.py": "",
    "src/mini/core.py": "def check(x):\n    if x is None:\n        return False\n    return True\n",
    "tests/_spur.py": _SPUR,
}

#: The operator of every case: the None check disabled.
_OPERATOR = ("src/mini/core.py", "if x is None:", "if False:", "mini: None check disabled")


def _test(name: str, body: str) -> str:
    return textwrap.dedent(f'''
        from mini.core import check
        from _spur import spur


        def test_{name}():
            spur("{name}")
    ''') + textwrap.indent(textwrap.dedent(body), "    ")


def _modul():
    spec = importlib.util.spec_from_file_location("_mc_erster_fehler", ROOT / "scripts" / "mutation_check.py")
    mc = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mc)
    return mc


def _fahre(tmp_path: Path, files: dict[str, str], expect_killed: bool) -> tuple[int, str, list[str]]:
    """`_run_operators` with real pytest over a planted tree and the one operator; (gaps, output, trace)."""
    for rel, text in {**_KERN, **files}.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    mc = _modul()
    mc.MUTATIONS = [(*_OPERATOR, expect_killed)]
    puffer = io.StringIO()
    with contextlib.redirect_stdout(puffer):
        gaps = mc._run_operators(tmp_path)
    spur = tmp_path / "tests" / "spur.log"
    return gaps, puffer.getvalue(), spur.read_text(encoding="utf-8").splitlines() if spur.exists() else []


_ERLAUBT = ('{"eintraege": [{"test": "tests.test_a_known_red::test_known_red", '
            '"fehlerklasse": "call:PermissionError", "art": "root", "grund": "planted for this case"}]}')


def test_a_killed_mutant_ends_early_with_the_same_verdict(tmp_path):
    """The killer is the first file of the selection; the run under the mutant stops there, and the later
    file never runs under it. KILLED, confirmed, as before. Red on 07b6122c: the later file ran under
    the mutant."""
    gaps, text, spur = _fahre(tmp_path, {
        "tests/test_a_killer.py": _test("killer", "assert check(None) is False\n"),
        "tests/test_b_later.py": _test("later", "assert check(1)\n"),
    }, expect_killed=True)
    assert spur.count("later mutant") == 0, spur
    assert spur.count("later rein") == 1, spur          # the baseline ran it
    assert gaps == 0 and "KILLED" in text and "confirmed=1" in text, text
    assert "killed by tests.test_a_killer::test_killer" in text, text
    assert "stopped at its first new red test" in text, text


def test_a_test_red_in_the_baseline_is_left_out_and_never_kills(tmp_path):
    """The first file is red in the baseline (on the allowlist, a test that needs root) and stays red
    under the mutant; nothing else goes red. It is left out of the mutant run and the mutant SURVIVES, as
    before. Red on 07b6122c: it ran again under the mutant."""
    gaps, text, spur = _fahre(tmp_path, {
        "scripts/mutation_baseline_allowlist.json": _ERLAUBT,
        "tests/test_a_known_red.py": _test("known_red", "raise PermissionError('root needed')\n"),
        "tests/test_b_check.py": _test("check", "assert check(1)\n"),
    }, expect_killed=False)
    assert gaps == 0 and "SURVIVED" in text and "KILLED" not in text, text
    assert spur.count("known_red mutant") == 0 and spur.count("known_red rein") == 1, spur
    assert spur.count("check mutant") == 1, spur        # the rest of the selection ran under the mutant


def test_behind_a_test_red_in_the_baseline_the_first_new_red_test_kills(tmp_path):
    """The same tree with a killer behind the baseline-red file: the mutant run leaves that file out,
    stops at the killer, and the mutant is KILLED, as before. Red on 07b6122c: the baseline-red file ran
    under the mutant."""
    gaps, text, spur = _fahre(tmp_path, {
        "scripts/mutation_baseline_allowlist.json": _ERLAUBT,
        "tests/test_a_known_red.py": _test("known_red", "raise PermissionError('root needed')\n"),
        "tests/test_b_killer.py": _test("killer", "assert check(None) is False\n"),
        "tests/test_c_later.py": _test("later", "assert check(1)\n"),
    }, expect_killed=True)
    assert gaps == 0 and "KILLED" in text and "killed by tests.test_b_killer::test_killer" in text, text
    assert spur.count("known_red mutant") == 0 and spur.count("later mutant") == 0, spur


def test_ANTI_PARITY_a_survivor_runs_the_whole_selection(tmp_path):
    """No test reaches the disabled check: every file of the selection runs under the mutant once, and
    the mutant SURVIVES, as before. Passes on 07b6122c too; it holds that a survivor is not cut short."""
    gaps, text, spur = _fahre(tmp_path, {
        f"tests/test_{c}_green.py": _test(f"{c}_green", "assert check(1)\n") for c in "abc"
    }, expect_killed=False)
    assert gaps == 0 and "SURVIVED" in text, text
    assert [spur.count(f"{c}_green mutant") for c in "abc"] == [1, 1, 1], spur


def test_ANTI_PARITY_a_first_red_test_that_is_no_killer_runs_the_full_selection(tmp_path):
    """The first red test under the mutant was skipped in the baseline, so it is no killer; the full
    selection decides, as before, and finds the killer behind it."""
    gaps, text, spur = _fahre(tmp_path, {
        "tests/test_a_optional.py": textwrap.dedent('''
            import pytest
            from pathlib import Path

            MUTANT = "if False:" in (Path(__file__).parents[1] / "src" / "mini" / "core.py").read_text()


            @pytest.mark.skipif(not MUTANT, reason="runs only where the check is off")
            def test_optional():
                assert False
        '''),
        "tests/test_b_killer.py": _test("killer", "assert check(None) is False\n"),
    }, expect_killed=True)
    assert gaps == 0 and "KILLED" in text and "killed by tests.test_b_killer::test_killer" in text, text
    assert "stopped at its first new red test" not in text, text
    assert spur.count("killer mutant") >= 2, spur       # the full run, then the confirmation


def _baum(tmp_path: Path, files: dict[str, str]) -> Path:
    for rel, text in files.items():
        p = tmp_path / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(textwrap.dedent(text), encoding="utf-8")
    return tmp_path


def test_the_run_that_stops_early_names_its_first_red_test_from_the_report(tmp_path):
    """The `-x` banner ("stopping after 1 failures") is no abort for this run: the report names the first
    red test and nothing after it. The same tree without the flag counts both."""
    mc = _modul()
    baum = _baum(tmp_path, {"tests/test_p.py": '''
        def test_eins():
            assert False


        def test_zwei():
            assert False
    '''})
    aus: list = []
    assert mc._red_count(baum, aus=aus, erster_fehler=True) == 1, aus
    assert aus == [{"tests.test_p::test_eins": "call:AssertionError"}], aus
    assert mc._red_count(baum) == 2


def test_an_abort_before_the_first_red_test_stays_not_measurable(tmp_path):
    """`pytest.exit` ends the run before any test failed: the report holds no red record, and the run
    says nothing, as the full run would."""
    mc = _modul()
    baum = _baum(tmp_path, {"tests/test_p.py": '''
        import pytest


        def test_eins():
            pytest.exit("abgebrochen", returncode=1)


        def test_zwei():
            assert False
    '''})
    assert mc._red_count(baum, erster_fehler=True) is None


def test_only_the_run_that_stops_early_carries_the_flags(monkeypatch, tmp_path):
    """`-x` and the left-out tests stand in the call only when asked; a test by `--deselect`, a module
    that failed to collect by `--ignore`. The default call is the one the other contracts hold."""
    mc = _modul()
    _baum(tmp_path, {"tests/test_p.py": "", "tests/test_q.py": ""})
    gesehen = []
    monkeypatch.setattr(mc.subprocess, "run",
                        lambda argv, **kw: (gesehen.append(argv), subprocess.CompletedProcess(argv, 0, "", ""))[1])
    monkeypatch.setattr(mc, "_AUSSCHLUSS_JE_MUTANTE", {})
    mc._lauf_der_suite(tmp_path, None, ("tests/test_p.py",), erster_fehler=True,
                       ausklammern=("tests.test_p::test_a", "tests.test_q", "tests.test_gone::test_x"))
    mc._lauf_der_suite(tmp_path, None, ("tests/test_p.py",))
    frueh, voll = gesehen
    assert "-x" in frueh and "--deselect=tests/test_p.py::test_a" in frueh and "--ignore=tests/test_q.py" in frueh, frueh
    assert not any("test_gone" in a for a in frueh), frueh
    assert "-x" not in voll and not any(a.startswith(("--deselect", "--ignore=tests/test_q")) for a in voll), voll
