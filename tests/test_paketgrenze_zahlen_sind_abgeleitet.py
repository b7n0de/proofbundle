"""Die Zahlen ueber die Paketgrenze werden ABGELEITET, nicht getippt.

HERKUNFT: deep gate Lauf 5, Linse 3 (2026-09-07), VERDIKT REJECT. Der Kopf von `tests/conftest.py`
nannte zwei Zahlen — "39" false runtime failures und "113" kollateral uebersprungene Tests, beide
"measured 2026-09-02". Die Linse hat sie auf dem Kandidaten nachgemessen, auf zwei unabhaengigen
Wegen: ein echter `pytest -rs`-Lauf aus dem gebauten sdist und die Ableitungslogik selbst gegen die
gesammelten Items. Beide Wege treffen sich auf **296** statt 113 — Faktor 2,6. Zehn Testdateien, die
NACH dem Messdatum entstanden, tragen allein 123 dieser Skips.

WAS DIESEN FUND VON EINEM GEWOEHNLICHEN OVERCLAIM UNTERSCHEIDET, und warum diese Datei existiert:
der Docstring hat die Drift SELBST VORHERGESAGT ("the number was never re-derived after the suite
grew"). Die Vorhersage war richtig und hat nichts bewirkt — `conftest.py` wurde danach viermal
geaendert, zweimal am Tag des Einfrierens, und keine dieser Aenderungen hat die Zahl nachgezogen.
Eine Warnung, die nicht zu einem Mechanismus wird, ist eine Warnung, die recht behaelt und nichts
nuetzt. Genau das war Linse 3s Fund F4: es gab KEINE Zusicherung, die die Zahlen an eine Messung
band. Die Struktur war gattert, die Schlagzeile nicht.

DIE KLASSE: eine Zahl steht getippt, wo eine Messung gehoert, und veraltet still, sobald die Menge
waechst. Dieselbe Klasse traf in derselben Runde zwei weitere Flaechen — die Konstante `ERWARTET=88`
im CI-Sammel-Job (die Operatorenliste stand da schon auf 100) und die Bedingung im Release-Standard
vom 05.09. Registriert als `ZAHL-IM-STANDARD-VERALTET-STILL-WENN-DIE-LISTE-WAECHST-01`.
"""
from __future__ import annotations

import importlib.util
import re
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
CONFTEST = REPO / "tests" / "conftest.py"

#: Die Module, deren Zahlen der Kopf von `conftest.py` WOERTLICH nennt. Sie stehen dort als Beleg
#: fuer die Kostenaussage, also muessen sie gebunden sein — sonst belegt der Beleg nichts.
#: Linse 3 hat mit genau diesen beiden ihren Messweg kalibriert; beide stimmten auf den Punkt.
_ZITIERTE_ZAHLEN = {
    "test_fork_pr_secret_isolation": 34,
    "test_audit_marker_line_wrap": 9,
}


def _conftest_modul():
    spec = importlib.util.spec_from_file_location("_conftest_zahlen", CONFTEST)
    m = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = m
    spec.loader.exec_module(m)
    return m


def _gesammelte_items(modul: str) -> int:
    """Die Zahl der Items eines Moduls, gefragt beim SAMMLER statt gezaehlt am Quelltext."""
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider",
         "-p", "no:randomly", str(REPO / "tests" / f"{modul}.py")],
        cwd=str(REPO), capture_output=True, text=True, timeout=600,
        env={"PYTHONPATH": str(REPO / "src"), "PATH": "/usr/bin:/bin:/usr/local/bin",
             "HOME": str(Path.home())})
    # Von HINTEN, wie ueberall in dieser Runde: die Bilanz ist die letzte passende Zeile, nicht die
    # erste im Blob (deep gate Lauf 5, Linse 5).
    for zeile in reversed((proc.stdout or "").splitlines()):
        treffer = re.search(r"(\d+)\s+tests?\s+collected", zeile)
        if treffer:
            return int(treffer.group(1))
    raise AssertionError(f"kein Sammelergebnis fuer {modul}:\n{proc.stdout[-800:]}")


def test_die_im_kopf_zitierten_zahlen_stimmen_mit_dem_sammler_ueberein():
    """DIE ZUSICHERUNG, die Linse 3s Fund F4 schliesst.

    Der Kopf von `conftest.py` nennt zwei Module mit Zahlen ("34 skipped, 1 needed" und "9 skipped,
    0 needed"). Diese Zahlen sind der BELEG fuer die Kostenaussage. Waechst eines der Module, ohne
    dass die Zahl mitwaechst, belegt der Beleg etwas anderes als das, was dasteht — genau so ist die
    Aggregatzahl 113 auf 296 gelaufen, ohne dass es jemandem auffiel.
    """
    kopf = CONFTEST.read_text(encoding="utf-8").split('"""')[1]
    for modul, erwartet in _ZITIERTE_ZAHLEN.items():
        assert f"{erwartet} skipped" in kopf, (
            f"Der Kopf von conftest.py nennt '{erwartet} skipped' fuer {modul} nicht mehr. Wird die "
            f"Zahl dort geaendert, muss sie hier mitgeaendert werden — beides zusammen ist der Sinn "
            f"dieser Zusicherung.")
        gemessen = _gesammelte_items(modul)
        assert gemessen == erwartet, (
            f"{modul} sammelt {gemessen} Tests, der Kopf von conftest.py nennt {erwartet}. Die Zahl "
            f"im Text ist veraltet. Das ist derselbe Vorgang, den Linse 3 fuer die Aggregatzahl "
            f"nachgewiesen hat (113 -> gemessen 296): eine getippte Zahl veraltet still, sobald die "
            f"Menge waechst.")


def test_der_kopf_traegt_KEINE_getippte_aggregatzahl_mehr():
    """DER RIEGEL GEGEN DEN RUECKFALL, und er ist der eigentliche Klassen-Fix.

    Die Einzelzahlen oben sind gebunden und duerfen deshalb dastehen. Eine AGGREGATZAHL ueber die
    ganze Suite darf es nicht: sie aendert sich mit jeder neuen Testdatei, und niemand rechnet sie
    nach. Genau deshalb stand hier 113, waehrend es 296 waren.
    """
    kopf = CONFTEST.read_text(encoding="utf-8").split('"""')[1]
    # Eine Aggregatbehauptung hat die Form "<Zahl> package-level tests" / "<Zahl> of them".
    verdaechtig = re.findall(
        r"\b(\d{2,})\s+(?:package-level tests|of them (?:do|are)|false runtime FAILURES)", kopf)
    assert not verdaechtig, (
        f"Der Kopf von conftest.py nennt wieder eine getippte Aggregatzahl: {verdaechtig}. Diese "
        f"Zahl waechst mit jeder Testdatei und wird von niemandem nachgerechnet — sie stand am "
        f"2026-09-02 auf 113 und war am 2026-09-07 gemessen 296. Wer sie braucht, leitet sie ab.")


def test_die_ableitung_erkennt_die_zitierten_module_ausserhalb_eines_checkouts(tmp_path):
    """DIE KONTROLLE zur Zusicherung oben, und sie ist keine Formalie: die Zahlen bedeuten nur
    etwas, wenn diese Module ausserhalb eines Checkouts ueberhaupt uebersprungen werden.

    Gebaut wird ein Baum OHNE die Repo-Marker (`.github`, `tools`, `SPEC.md`) — also die Lage, in
    der eine entpackte sdist laeuft. Erkennt die Ableitung die Module dort nicht, ist die ganze
    Kostenaussage gegenstandslos.
    """
    m = _conftest_modul()
    (tmp_path / "tests").mkdir()
    for modul in _ZITIERTE_ZAHLEN:
        shutil.copy2(REPO / "tests" / f"{modul}.py", tmp_path / "tests" / f"{modul}.py")
    assert not any((tmp_path / marker).exists() for marker in m._REPO_ONLY_MARKERS), \
        "Vorbedingung: der Wegwerfbaum darf keinen Repo-Marker tragen"
    for modul in _ZITIERTE_ZAHLEN:
        assert m.modul_ist_repo_kontext(tmp_path / "tests" / f"{modul}.py", tmp_path), (
            f"{modul} wird ausserhalb eines Checkouts NICHT als Repo-Kontext erkannt. Dann laeuft "
            f"es aus dem Paket heraus und faellt, statt ehrlich zu ueberspringen — und die Zahlen "
            f"im Kopf beschreiben einen Mechanismus, den es nicht gibt.")


def test_ANTI_PARITAET_die_ableitung_haelt_ein_reines_paketmodul_NICHT_fuer_repo_kontext(tmp_path):
    """Ohne diesen Fall bestuende der obige auch bei einer Ableitung, die IMMER True sagt — dann
    uebersprænge das Paket seine ganze Suite und meldete das als sauberen Lauf."""
    m = _conftest_modul()
    (tmp_path / "tests").mkdir()
    rein = tmp_path / "tests" / "test_rein_paketbezogen.py"
    rein.write_text("def test_x():\n    assert 1 + 1 == 2\n", encoding="utf-8")
    assert not m.modul_ist_repo_kontext(rein, tmp_path), (
        "Ein Modul ohne jeden Repo-Pfad gilt als Repo-Kontext. Dann wird aus dem Paket heraus alles "
        "uebersprungen, und ein Lauf ohne einen einzigen ausgefuehrten Test liest sich als gruen.")
