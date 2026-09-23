"""Check 6 erkennt eine Release-Behauptung an ihrer FORM, nicht an einem Wort.

DER BEFUND, gemessen 2026-09-23 gegen `README.md` an `origin/main`: die Datei nennt die aktuelle
Fassung in SIEBEN Zeilen und VIER Formen, und `_CURRENT_CLAIM` traf **keine einzige** davon —
weil keine das Wort `current` oder `latest` traegt:

    **[vX.Y.Z](…/releases/tag/vX.Y.Z) · Beta · …**
    python -m pip install proofbundle==X.Y.Z
    https://raw.githubusercontent.com/b7n0de/proofbundle/vX.Y.Z/examples/example_bundle.json

Check 6 ist genau dafuer da, dass „die Stelle, die niemand angemeldet hat" nicht unbeobachtet
veraltet. Er beobachtete eine Satzform, waehrend die folgenreichsten Aussagen der Titelseite drei
andere benutzten.

FANGNACHWEIS, end-to-end gefahren (nicht behauptet): Quellversion UND die verfolgte Prosa
(`RELEASE.md`, `PROGRESS.md`) auf die naechste Fassung gehoben, CHANGELOG-Abschnitt ergaenzt,
**README unveraendert gelassen**.

    ALTES Tor (origin/main)   rc=0  GRUEN  — „OK — source version <neu>"
    NEUES Tor                 rc=1  ROT    — nennt README.md:27

Das alte Tor meldete gruen, waehrend die README die alte Fassung acht Mal zum Installieren
anbot.

DIE GEGENRICHTUNG WIEGT HIER SCHWERER ALS DER FUND. Der Modulkopf sagt ausdruecklich, dass
historische Aussagen NICHT angefasst werden duerfen: „since X.Y.Z" und „as of X.Y.Z" halten
fest, WANN etwas wahr wurde, und ein Tor, das ihre Hebung verlangt, macht aus einer Tatsache
eine Luege. Ein Muster, das zu viel faengt, ist hier teurer als eines, das zu wenig faengt.

Lauf: python3 -m pytest tests/test_versionstor_sieht_nicht_nur_eine_satzform.py -q
"""
from __future__ import annotations

import importlib.util
import pathlib
import re
import subprocess
import sys

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
TOR = REPO / "scripts" / "check_version_and_changelog.py"


def _gate():
    s = importlib.util.spec_from_file_location("_u5_gate", TOR)
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m


AKTUELL = "6.1.0"      # die Quellversion an origin/main, gegen die hier geurteilt wird


def _trifft(text: str, version: str = AKTUELL) -> str | None:
    """Der NAME der Form, die der PRUEFER meldet — oder None.

    GEHT DURCH DIE ECHTE FUNKTION, und das ist eine KORREKTUR, die der eigene Fangnachweis
    erzwungen hat. Die erste Fassung dieses Helfers lief ueber `_CLAIM_SHAPES` und wendete die
    Regel „nur die aktuelle Zahl zaehlt" SELBST an — eine zweite Umsetzung derselben Logik.
    Gemessen: zwei von vier Pflanzungen blieben NICHT GEFANGEN, weil sie den Produktionspfad
    aenderten und dieser Helfer seine eigene Kopie weiterbenutzte. Ein Test, der die Regel
    nachbaut, prueft sich selbst.

    Jetzt wird ein Wegwerf-Repo mit EINER Datei gebaut und `check_undeclared_places` darauf
    gerufen — derselbe Weg, den auch das Tor geht.
    """
    import tempfile
    with tempfile.TemporaryDirectory(prefix="u5_trifft_") as tmp:
        repo = pathlib.Path(tmp)
        (repo / "pyproject.toml").write_text(f'[project]\nversion = "{version}"\n', encoding="utf-8")
        (repo / "DOKU.md").write_text(text + "\n", encoding="utf-8")
        g = _gate()
        g._tracked_files = lambda _repo: ["DOKU.md"]
        funde = g.check_undeclared_places(repo)
    if not funde:
        return None
    for form, _, _, _ in _gate()._CLAIM_SHAPES:
        if f"as a {form} " in funde[0]:
            return form
    return "UNBEKANNTE_FORM"


# ── DIE VIER FORMEN, die eine aktuelle Fassung behaupten ────────────────────────────────────

@pytest.mark.parametrize("text,erwartete_form", [
    ("python -m pip install proofbundle==6.1.0", "install pin"),
    ("python -m pip install 'proofbundle[eval]==6.1.0'", "install pin"),
    ("[v6.1.0](https://github.com/b7n0de/proofbundle/releases/tag/v6.1.0)", "release tag link"),
    ("https://raw.githubusercontent.com/b7n0de/proofbundle/v6.1.0/examples/x.json",
     "version-pinned URL"),
    ("current release: 6.1.0", "current/latest phrase"),
    ("latest version 6.1.0", "current/latest phrase"),
])
def test_jede_form_einer_release_behauptung_wird_erkannt(text, erwartete_form):
    assert _trifft(text) == erwartete_form


# ── DIE GEGENRICHTUNG: Geschichte bleibt Geschichte ─────────────────────────────────────────

@pytest.mark.parametrize("text", [
    "since v6.1.0 the anchor has been stable",
    "as of 6.1.0 this holds",
    "Behaviour changed in 6.1.0 and has not moved since.",
    "see docs/release_scope/6.1.0.md for what belongs to that release",
    "## [6.1.0] - 2026-09-20",
    "audit_artifacts/610/pre_tag_receipt_v6.1.0.json",
    # Von Gegenlese-Linse 1 ausgefuehrt gefunden: die erste Fassung meldete alle drei.
    "pip uninstall proofbundle==6.0.0",
    # UND die Fassung, auf die es bei der Wortgrenze ankommt: eine Anleitung, die AKTUELLE
    # Version zu ENTfernen. Ohne `\\binstall` trifft das Muster das Ende von „uninstall", und
    # der Zahlvergleich rettet hier nicht — die Zahl IST die aktuelle. Der eigene Fangnachweis
    # hat das erzwungen: mit der alten Zahl blieb die Pflanzung „Wortgrenze entfernt"
    # NICHT GEFANGEN.
    "pip uninstall proofbundle==6.1.0",
    "[v5.0.0 release notes](https://github.com/b7n0de/proofbundle/releases/tag/v5.0.0)",
    "https://raw.githubusercontent.com/b7n0de/proofbundle/v5.0.0/examples/x.json",
])
def test_historische_und_benennende_formen_werden_NICHT_gefangen(text):
    """Ein Tor, das die Hebung einer historischen Aussage verlangt, macht aus einer Tatsache
    eine Luege — die Regel steht woertlich im Modulkopf."""
    assert _trifft(text) is None, f"faelschlich gefangen als {_trifft(text)!r}: {text!r}"


def test_eine_release_scope_datei_ist_keine_behauptung_aber_ein_tag_link_schon():
    """Die zwei liegen nah beieinander und muessen verschieden beurteilt werden."""
    assert _trifft("docs/release_scope/6.1.0.md") is None
    assert _trifft("…/releases/tag/v6.1.0") == "release tag link"


# ── DER PREIS, weil ein flutender Sweep abgeschaltet wird ───────────────────────────────────

def test_der_sweep_flutet_nicht():
    """GEMESSEN vor dem Bau: ueber alle verfolgten Dateien ausserhalb der ausgenommenen Praefixe
    treffen die drei neuen Formen VIER Mal, alle in README.md. Ein Melder, der beim ersten Lauf
    Dutzende Stellen wirft, wird abgeschaltet, bevor er den ersten echten Fall zeigt.

    DIE VORBEDINGUNG STEHT ZUERST, und sie ist eine KORREKTUR (Gegenlese-Linse 2, 23.09.2026):
    ohne sie leitete dieser Test seine Vergleichsmenge live aus `_CLAIM_SHAPES` ab und war
    VAKUUM-WAHR, sobald die Reparatur ganz entfernt wird — leere Menge, Aussage trivial erfuellt.
    Er bewachte damit nicht „die Reparatur ist da und flutet nicht", sondern nur „was uebrig ist,
    flutet nicht". Gemessen an der Gegenprobe: bei entfernter Reparatur blieb er gruen.
    """
    rc = subprocess.run(["git", "-C", str(REPO), "ls-files"], capture_output=True, text=True)
    if rc.returncode != 0:
        pytest.skip("kein git-Index lesbar")
    g = _gate()
    neue = [(f, m) for f, m, _n, _ in g._CLAIM_SHAPES if f != "current/latest phrase"]
    assert len(neue) >= 3, (
        f"die Reparatur ist nicht da: nur {len(neue)} zusaetzliche Formen. Ohne diese Zeile "
        f"waere der Rest des Tests vakuum-wahr")
    dateien = set()
    for rel in rc.stdout.splitlines():
        if rel.startswith(g._SWEEP_EXCLUDE_PREFIXES) or rel == str(TOR.relative_to(REPO)):
            continue
        try:
            t = (REPO / rel).read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if any(m.search(t) for _, m in neue):
            dateien.add(rel)
    assert len(dateien) <= 3, f"der Sweep trifft {len(dateien)} Dateien: {sorted(dateien)}"


def test_das_tor_zitiert_sich_nicht_selbst_in_die_falle():
    """Beim ersten Lauf meldete die neue Regel ZWEI Funde: README.md und diese Prueferdatei
    selbst — ihr Kommentar zitierte die README mitsamt echter Versionsnummer. Ein Sweep kann eine
    Behauptung nicht von ihrem Zitat unterscheiden; der Modulkopf sagt deshalb, dass eine
    Veranschaulichung die eigene Fassung nicht ausschreiben darf. Kein Ausnahmepfad fuer diese
    Datei — sie haelt die Regel ein, statt von ihr befreit zu sein."""
    g = _gate()
    assert len([f for f, _, _n, _ in g._CLAIM_SHAPES]) >= 4, (
        "ohne die vollstaendige Formenliste waere dieser Test vakuum-wahr")
    quelle = TOR.read_text(encoding="utf-8")
    version, _ = g._source_version(REPO)
    assert version, "ohne Quellversion sagt dieser Test nichts"
    # Die Prueferdatei darf die EIGENE aktuelle Fassung nicht in einer Behauptungsform tragen.
    for form, muster, _n, _ in g._CLAIM_SHAPES:
        for treffer in muster.findall(quelle):
            assert treffer != version, (
                f"{TOR.name} traegt die eigene Fassung {version} als {form} — genau die Stelle, "
                f"die der Sweep zu Recht meldet")


def test_ein_ausnahmepfad_fuer_die_prueferdatei_existiert_nicht(tmp_path, monkeypatch):
    """Ein Pruefer, der sich selbst ausnimmt, hoert auf, die Datei zu pruefen, die am ehesten
    Behauptungen zitiert.

    AN DIE WIRKUNG GEBUNDEN, NICHT AN DIE SCHREIBWEISE — und das ist eine KORREKTUR
    (Gegenlese-Linse 2, 23.09.2026, mit ausgefuehrtem Gegenbeweis). Die erste Fassung suchte im
    Quelltext nach `rel ==` plus dem Dateinamen. Die Linse hat eine ECHTE, funktionierende
    Selbstausnahme gebaut — ueber einen `Path(__file__).resolve()`-Vergleich statt eines
    Literals — und dieser Test blieb **gruen**, waehrend eine gepflanzte Behauptung in der
    Prueferdatei nachweislich verschwand. Eine Bindung an die Textform prueft, wie jemand
    schreibt, nicht was der Code tut.

    Jetzt wird es GEMESSEN: eine Behauptung an genau dem Pfad der Prueferdatei muss gemeldet
    werden. Wie eine Ausnahme geschrieben waere, ist damit gleichgueltig.

    DIE KOPIE WIRD GEPRUEFT, NICHT DAS ORIGINAL — und auch das ist eine Korrektur, gefunden vom
    eigenen Fangnachweis. Die zweite Fassung dieses Tests legte die Behauptung in eine
    Wegwerfdatei und liess das ORIGINALMODUL darueber laufen. Eine Ausnahme ueber
    `Path(__file__)` vergleicht dann gegen den Pfad des Originals und greift nie: die Pflanzung
    „Prueferdatei nimmt sich selbst aus" blieb **NICHT GEFANGEN**. Erst wenn das gepflanzte
    Modul SELBST laeuft, zeigt sich seine Ausnahme.
    """
    rel = "scripts/check_version_and_changelog.py"
    ziel = tmp_path / rel
    ziel.parent.mkdir(parents=True, exist_ok=True)
    quelle = TOR.read_text(encoding="utf-8")
    # Die Behauptung steht IM Pruefer, und der Pruefer, der sie finden muss, ist diese Kopie.
    ziel.write_text(quelle + "\n# gepflanzte Behauptung:\n"
                             "# python -m pip install proofbundle==9.9.9\n", encoding="utf-8")
    s = importlib.util.spec_from_file_location("_u5_gate_kopie", ziel)
    g = importlib.util.module_from_spec(s)
    s.loader.exec_module(g)
    monkeypatch.setattr(g, "_tracked_files", lambda _repo: [rel])
    funde = g.check_undeclared_places(tmp_path)
    assert funde, ("die Prueferdatei wurde NICHT gesweept — sie nimmt sich selbst aus, gleich "
                   "mit welcher Schreibweise")
    # Geprueft wird, DASS die Datei gesweept wird, nicht WELCHE ihrer Zeilen zuerst meldet: der
    # Sweep bricht nach dem ersten Fund je Datei ab, und welche Zeile das ist, haengt am Inhalt.
    # Eine Selbstausnahme haette `funde` LEER gelassen — das ist die Eigenschaft.
    assert rel in funde[0], funde


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))


# ── EINE ANMELDUNG DECKT EIN MUSTER, NICHT EINE DATEI ───────────────────────────────────────

def test_eine_anmeldung_legt_die_geschwisterbelege_nicht_stumm(tmp_path, monkeypatch):
    """DER SCHWERSTE FUND der Gegenlesung, und er traf nicht die Reparatur, sondern die Abhilfe.

    `check_undeclared_places` verglich `rel in declared` — dateiweit. Wer eine Datei fuer EIN
    Muster anmeldet (genau die Option A, die meine eigene Owner-Karte anbietet), nahm sie damit
    GANZ aus dem Sweep. Gemessen an README.md: nach der Anmeldung des Tag-Links meldete der
    Sweep NICHTS mehr, obwohl drei weitere Belege derselben Klasse unveraendert darin stehen.

    Das ist schlimmer als der Ausgangszustand: vorher unentdeckt, danach per Anmeldung dauerhaft
    stillgelegt — und der Sweep meldete Ruhe.
    """
    g = _gate()
    rel = "DOKU.md"
    (tmp_path / rel).write_text(
        "[v6.1.0](https://github.com/x/y/releases/tag/v6.1.0)\n"
        "python -m pip install paket==6.1.0\n", encoding="utf-8")
    monkeypatch.setattr(g, "_tracked_files", lambda _repo: [rel])

    ohne = g.check_undeclared_places(tmp_path)
    assert ohne and "DOKU.md:1" in ohne[0], ohne

    # Die erste Zeile anmelden — die zweite MUSS sichtbar bleiben.
    monkeypatch.setattr(g, "_TRACKED_PLACES",
                        [(rel, re.compile(r"/releases/tag/v" + g._SEMVER), "der Tag-Link")])
    mit = g.check_undeclared_places(tmp_path)
    assert mit, ("die Anmeldung hat die ganze Datei stillgelegt — die zweite Behauptung ist "
                 "unbeobachtet")
    assert "DOKU.md:2" in mit[0] and "install pin" in mit[0], mit


def test_eine_veraltete_WORTbehauptung_bleibt_ein_fund():
    """Die Unterscheidung, die Linse 1 erzwungen hat: ein WORT behauptet Aktualitaet aus sich
    heraus, gleich welche Zahl danebensteht — eine veraltete Wortbehauptung ist deshalb SEHR
    wohl ein Fund. Nur die FORM braucht die aktuelle Zahl, um eine Behauptung zu sein."""
    assert _trifft("current release: 5.0.0") == "current/latest phrase"
    assert _trifft("latest version 5.0.0") == "current/latest phrase"
