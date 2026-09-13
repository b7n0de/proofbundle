"""Der pre-commit-Hook ruft den MANIFEST-Pruefknoten, und zwar NUR wenn scripts/ betroffen ist.

WARUM ES DIESE DATEI GIBT, gemessen und nicht vermutet. Am 13.09.2026 fielen DREI Zweige an
``test_jede_datei_unter_scripts_ist_in_manifest_entschieden`` — PR 200 mit
``b7_paketinhalt_ohne_schluesselmaterial.py`` (1 failed / 4024 passed in 21:45 min), PR 198 mit
``b7_historie.py`` (1 failed / 4158 passed in 26:08 min) und ``feat/pr-language-gate`` mit
``pr_language_gate.py``, letzterer von einem Nachbar-Sweep gefunden, BEVOR er CI kostete. Zusammen
neun Jobs zu je 22 bis 42 Minuten, um je EINE Zeile zu erfahren.

Der Riegel war dabei nie falsch. Falsch war sein ORT: er sass am Ende des gruendlichsten Jobs,
obwohl seine Eingabe vollstaendig im Arbeitsbaum steht. Die Latenz eines Riegels gehoert zu seiner
Wirkung.

WAS HIER GEPRUEFT WIRD, und warum es nicht der Pruefknoten selbst ist: dass der HOOK ihn AUFRUFT,
und nur dann. Der Knoten hat seinen eigenen Vertrag; dieser hier misst die VERDRAHTUNG. Dazu laeuft
das echte Hook-Skript gegen einen gebauten Baum mit einem gefaelschten ``git`` auf dem PATH — die
gestagte Menge ist damit eine Eingabe und keine Annahme.
"""
from __future__ import annotations

import os
import pathlib
import subprocess

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
HOOK = REPO / "scripts" / "git-hooks" / "pre-commit"


def _baue_baum(tmp_path: pathlib.Path, gestaged: list[str], knoten_faellt: bool = False):
    """Ein Baum, der dem Hook genau so weit gleicht, wie er ihn anfasst."""
    wurzel = tmp_path / "baum"
    (wurzel / "scripts").mkdir(parents=True)
    (wurzel / "tests").mkdir()
    (wurzel / "scripts" / "mutant_signature_guard.py").write_text(
        "import sys\nsys.exit(0)\n", encoding="utf-8")
    marke = wurzel / "knoten_lief"
    (wurzel / "tests" / "test_sdist_ohne_signierwerkzeug.py").write_text(
        "import pathlib\n"
        "def test_jede_datei_unter_scripts_ist_in_manifest_entschieden():\n"
        f"    pathlib.Path({str(marke)!r}).write_text('ja')\n"
        f"    assert not {knoten_faellt!r}, 'gepflanzter Fehlschlag'\n",
        encoding="utf-8")

    bin_ = tmp_path / "bin"
    bin_.mkdir()
    liste = "\\n".join(gestaged)
    (bin_ / "git").write_text(
        "#!/bin/sh\n"
        'if [ "$1" = "rev-parse" ]; then printf "%s\\n" ' + f"'{wurzel}'" + "; exit 0; fi\n"
        'if [ "$1" = "diff" ]; then printf "' + liste + '\\n"; exit 0; fi\n'
        "exit 0\n", encoding="utf-8")
    (bin_ / "git").chmod(0o755)
    return wurzel, bin_, marke


def _fahre(tmp_path, gestaged, knoten_faellt=False):
    wurzel, bin_, marke = _baue_baum(tmp_path, gestaged, knoten_faellt)
    umwelt = dict(os.environ, PATH=f"{bin_}{os.pathsep}{os.environ['PATH']}")
    p = subprocess.run(["sh", str(HOOK)], cwd=wurzel, env=umwelt,
                       capture_output=True, text=True, timeout=300)
    return p, marke


def test_eine_datei_unter_scripts_loest_den_pruefknoten_aus(tmp_path):
    pytest.importorskip("pytest")
    p, marke = _fahre(tmp_path, ["scripts/b7_neu.py", "README.md"])
    assert marke.is_file(), (
        "der Hook hat den MANIFEST-Pruefknoten NICHT gerufen, obwohl eine Datei unter scripts/ "
        f"gestaged war — dann erfaehrt der Autor die Ein-Zeilen-Tatsache wieder erst nach 26 Minuten.\n"
        f"stdout: {p.stdout}\nstderr: {p.stderr}")
    assert p.returncode == 0, p.stderr


def test_eine_aenderung_ausserhalb_von_scripts_startet_ihn_gar_nicht(tmp_path):
    """Die Gegenrichtung, und sie ist kein Schoenheitsfehler: laefe der Knoten bei JEDEM Commit,
    kostete der Hook jede Aenderung die pytest-Startzeit, und ein teurer Hook wird abgeschaltet."""
    p, marke = _fahre(tmp_path, ["docs/etwas.md", "README.md"])
    assert not marke.exists(), (
        "der Hook startet den Pruefknoten auch ohne Bezug zu scripts/ — das verteuert jeden Commit")
    assert p.returncode == 0, p.stderr


def test_faellt_der_knoten_faellt_der_hook(tmp_path):
    """Der Fangnachweis, der zaehlt: eine gruene Verdrahtung, die den Fehlschlag verschluckt, ist
    schlimmer als keine, weil sie wie eine Pruefung aussieht."""
    pytest.importorskip("pytest")
    p, marke = _fahre(tmp_path, ["scripts/b7_neu.py"], knoten_faellt=True)
    assert marke.is_file(), "der Knoten lief nicht — dann prueft dieser Fall nichts"
    assert p.returncode != 0, (
        f"der Knoten ist gefallen und der Hook meldet trotzdem Erfolg.\nstdout: {p.stdout}")


def test_der_hook_ruft_genau_den_knoten_den_auch_ci_faehrt():
    """Kein zweiter Erzeuger (OA-714de2fcdd): der Hook darf die Frage nicht NACHBAUEN, sondern muss
    denselben Pruefknoten rufen. Gemessen am Text des Hooks UND an der Existenz des Knotens."""
    text = HOOK.read_text(encoding="utf-8")
    knoten = ("tests/test_sdist_ohne_signierwerkzeug.py::"
              "test_jede_datei_unter_scripts_ist_in_manifest_entschieden")
    assert knoten in text, "der Hook nennt den gemeinsamen Pruefknoten nicht"
    ziel = REPO / "tests" / "test_sdist_ohne_signierwerkzeug.py"
    assert ziel.is_file(), f"{ziel} gibt es nicht — der Hook zeigt ins Leere"
    assert "def test_jede_datei_unter_scripts_ist_in_manifest_entschieden" in ziel.read_text(
        encoding="utf-8"), "der genannte Knoten existiert in der Datei nicht mehr"
