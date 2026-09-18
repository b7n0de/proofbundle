"""Contract for the diff-scoped language guard (owner decision OA-bba542170c).

The case that matters here is the one an adversarial read found on the day the guard shipped.
Its first version decided "is this line inside a docstring" by counting triple quotes in the
lines before it and flipping a flag on every odd count. One triple quote inside an ordinary
one-line string is enough to invert that flag, and from then on the file is read inside out.

The failure is not a wrong verdict about a line. It is the guard no longer looking at the line,
while the report stays green, and that is the more expensive of the two.
"""
from __future__ import annotations

import importlib.util
import pathlib

_WURZEL = pathlib.Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location(
    "nz", _WURZEL / "scripts" / "neue_zeilen_sind_englisch.py")
NZ = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(NZ)

Q = chr(34) * 3
DEUTSCH = "    Diese deutsche Zeile mit der und die und das gehoert geprueft."


def _baum(tmp_path, quelle: str, name: str = "probe.py"):
    (tmp_path / name).write_text(quelle, encoding="utf-8")
    return tmp_path


def test_ROT_eine_docstringzeile_entgeht_nicht_wegen_eines_zitats_davor(tmp_path, monkeypatch):
    """The planted case. A code line carrying one triple quote inside a string used to invert
    the parity, so the real docstring opener closed it and everything inside counted as code.
    """
    # SINGLE quotes outside, so the line is VALID Python and carries one triple quote inside a
    # string. The first version of this case used double quotes outside and did not parse at all;
    # it failed against the fix for the wrong reason, and a case that cannot occur proves nothing.
    quelle = ("x = 'er sagte " + Q + " und ging'\n"
              "def f():\n"
              "    " + Q + "\n"
              + DEUTSCH + "\n"
              "    " + Q + "\n"
              "    return 1\n")
    monkeypatch.setattr(NZ, "REPO", _baum(tmp_path, quelle))
    assert NZ._ist_prosa("probe.py", 4, DEUTSCH) is True


def test_dieselbe_zeile_ohne_die_stoerzeile_war_immer_schon_prosa(tmp_path, monkeypatch):
    """The counterweight: without the code line the old version was right. The difference
    between the two cases IS the defect, so both belong here.
    """
    quelle = "def f():\n    " + Q + "\n" + DEUTSCH + "\n    " + Q + "\n"
    monkeypatch.setattr(NZ, "REPO", _baum(tmp_path, quelle))
    assert NZ._ist_prosa("probe.py", 3, DEUTSCH) is True


def test_eine_codezeile_bleibt_code(tmp_path, monkeypatch):
    """A guard that calls everything prose catches every line and measures nothing."""
    quelle = "def f():\n    " + Q + "doc" + Q + "\n    return 1\n"
    monkeypatch.setattr(NZ, "REPO", _baum(tmp_path, quelle))
    assert NZ._ist_prosa("probe.py", 3, "    return 1") is False


def test_ein_kommentar_braucht_die_datei_nicht(tmp_path, monkeypatch):
    """A comment is recognisable from the fragment alone, and stays so when the file is gone."""
    monkeypatch.setattr(NZ, "REPO", tmp_path)
    assert NZ._ist_prosa("gibtesnicht.py", 1, "# ein Kommentar") is True


def test_eine_datei_die_nicht_tokenisiert_ist_nicht_messbar_und_kein_pass(tmp_path, monkeypatch):
    """Not measurable is not a pass. A broken file yields None, and the caller reads that as
    not-prose rather than as a clean line.
    """
    monkeypatch.setattr(NZ, "REPO", _baum(tmp_path, "def f(\n"))
    assert NZ._prosazeilen("probe.py") is None


def test_die_schwelle_verlangt_zwei_listenwoerter(tmp_path):
    """One list word is noise. The threshold is the one the 2687-line measurement used."""
    assert NZ.SCHWELLE == 2
    assert len(NZ.DP.treffer("the die is cast")) < NZ.SCHWELLE
    assert len(NZ.DP.treffer("der Riegel und die Zeile")) >= NZ.SCHWELLE


def test_the_git_range_is_measurable_on_a_real_repository(tmp_path, monkeypatch):
    """The first version built the range as two arguments (`"<base>..."`, `"HEAD"`); git
    replied with its usage text and exit 129, and the guard reported NOT MEASURABLE on every
    run -- including the pull request that carried it (run 35287424973). No test here had ever
    let it touch git. This one does: a real repository, a base commit, a commit that adds a
    German comment, and the guard must SEE the added line."""
    import subprocess
    repo = tmp_path / "r"
    repo.mkdir()
    def git(*a):
        subprocess.run(["git", "-C", str(repo), *a], check=True, capture_output=True, text=True)
    git("init", "-q")
    (repo / "m.py").write_text("x = 1\n", encoding="utf-8")
    git("add", "m.py")
    git("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "-m", "base")
    base = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True,
                          text=True, check=True).stdout.strip()
    (repo / "m.py").write_text("x = 1\n# das ist eine deutsche Zeile und sie wird gesehen\n", encoding="utf-8")
    git("add", "m.py")
    git("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "-m", "change")
    monkeypatch.setattr(NZ, "REPO", repo)
    je_datei, grund = NZ._neue_zeilen(base)
    assert not grund.startswith("NOT MEASURABLE"), grund
    assert "m.py" in je_datei and any("deutsche" in z for _, z in je_datei["m.py"]), je_datei
    # and the working-tree form measures the uncommitted state
    (repo / "m.py").write_text("x = 1\n# now english\n", encoding="utf-8")
    je_datei, grund = NZ._neue_zeilen(base, arbeitsbaum=True)
    assert not grund.startswith("NOT MEASURABLE"), grund
    assert any("english" in z for _, z in je_datei.get("m.py", [])), je_datei
