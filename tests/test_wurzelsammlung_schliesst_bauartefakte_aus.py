"""`pytest` aus der Repo-Wurzel darf nicht an Bauartefakten ersticken — und der Riegel dafuer
muss die WIRKUNG tragen, nicht nur dastehen.

BEFUND PB-PYTEST-WURZEL-LAEUFT-NICHT-01 (2026-08-18). Gemessen: `pytest` aus der Wurzel brach mit
740 Sammelfehlern in 1,95 s ab, samtlich `import file mismatch` — die entpackten sdist-Baeume unter
`dist_pkgtest*/` tragen dieselben Modul-Basenamen wie `tests/`, und ohne `__init__.py` entscheidet
pytest den Modulnamen nach Basename. Wer zuerst gesammelt wird, gewinnt; der zweite kollidiert.
Die Verzeichnisse sind gitignored, `git status` ist also sauber — pytest laeuft sie trotzdem ab.
Das ist teuer, weil die kanonischen Suiten GRUEN sind: wer die Wurzel-Form nimmt, sieht Rot und
schliesst daraus das Falsche.

WARUM ES DIESE DATEI BRAUCHT. Der Fix lebte in `pyproject.toml` und war von keinem Test gedeckt.
Eine Konfigurationszeile ohne Test faellt still zurueck: sie verschwindet bei einem Merge-Konflikt,
einem Werkzeugwechsel oder einer aufgeraeumten Liste, ohne dass etwas rot wird.

DIE QUELLE IST PYTEST SELBST, NICHT DIE DATEI — und das ist eine Korrektur an meinem ersten Entwurf.
Der las `pyproject.toml` mit `tomllib` und uebersprang sich auf diesem Interpreter (Python 3.10,
`tomllib` gibt es ab 3.11) in DREI gruen aussehenden SKIPs. Unter eingepflanztem Defekt blieben sie
gruen: der Test mass nichts und sah wie eine Deckung aus. `pytestconfig.getini` liest den Wert, den
pytest WIRKLICH benutzt — naeher am Gegenstand als die Datei, und ohne Interpreter-Abhaengigkeit.
Ein fehlender Wert ist hier ein FEHLSCHLAG, nie ein Skip: ein Skip bei vorhandenem Gegenstand ist
die Abwesenheit einer Messung, die sich wie ihr Ergebnis liest.

DIE DREI TESTS SIND ABSICHTLICH VERSCHIEDEN GEBAUT:
  * Wirkung: die realen Verzeichnisnamen werden ausgeschlossen;
  * Anti-Tautologie: der NEUE Eintrag traegt die Wirkung — nimmt man ihn weg, faellt sie weg.
    Ohne diesen Zwilling waere der erste Test auch dann gruen, wenn der pytest-Default die Arbeit
    taete und die Zeile Dekoration waere. Genau das war die Gefahr: `dist` steht im Default,
    `dist_pkgtest` matcht ihn aber NICHT (der Default vergleicht exakt);
  * Gegenrichtung: ein zu breiter Riegel versteckt echte Tests — sauber, aber blind.
"""
from __future__ import annotations

import fnmatch

# Die Namen, an denen es GEMESSEN gescheitert ist — nicht erfunden, sondern die realen
# Bauartefakt-Verzeichnisse aus dem Arbeitsbaum, in dem der Befund entstand.
_ERSTICKER = ["dist_pkgtest", "dist_pkgtest2", "dist_pkgtest3", "dist_pkgtest4", "dist_pkgtest5",
              ".venv", ".venv311", "build", "dist"]
# Der Eintrag, dessen Wirkung der Zwilling nachweist.
_NEUER_EINTRAG = "dist_*"


def _norecursedirs(pytestconfig) -> list[str]:
    """Der EFFEKTIVE Wert, den pytest benutzt — nicht der Dateitext, nicht eine Kopie im Test.

    Eine im Test getippte Kopie prueft den Test gegen sich selbst: sie bliebe gruen, wenn jemand
    die Konfiguration aendert, und wuerde rot, wenn jemand nur den Test aendert — beides falsch.
    """
    werte = list(pytestconfig.getini("norecursedirs") or [])
    assert werte, ("pytest kennt kein `norecursedirs` — der Riegel gegen die Sammelkollision ist "
                   "weg, nicht nur unvollstaendig")
    return werte


def _wird_ausgeschlossen(name: str, muster: list[str]) -> bool:
    """Dieselbe Entscheidung, die pytest trifft: fnmatch des VERZEICHNISNAMENS gegen die Muster."""
    return any(fnmatch.fnmatch(name, m) for m in muster)


def test_die_realen_erstickenden_verzeichnisse_werden_ausgeschlossen(pytestconfig):
    muster = _norecursedirs(pytestconfig)
    nicht_gedeckt = [n for n in _ERSTICKER if not _wird_ausgeschlossen(n, muster)]
    assert nicht_gedeckt == [], (
        f"diese Bauartefakt-Verzeichnisse werden weiterhin gesammelt: {nicht_gedeckt} — genau sie "
        f"erzeugten die 740 `import file mismatch`-Fehler (Muster: {muster})")


def test_der_neue_eintrag_traegt_die_wirkung_und_ist_keine_dekoration(pytestconfig):
    """ANTI-TAUTOLOGIE: ohne `dist_*` muss die Deckung der `dist_*`-Baeume fallen.

    Bleibt sie bestehen, taete der pytest-Default die Arbeit und der Test darueber pruefte nichts,
    was dieser Fix hinzugefuegt hat.
    """
    muster = _norecursedirs(pytestconfig)
    assert _NEUER_EINTRAG in muster, f"{_NEUER_EINTRAG!r} steht nicht mehr in norecursedirs"
    ohne = [m for m in muster if m != _NEUER_EINTRAG]
    weiter_gedeckt = [n for n in _ERSTICKER
                      if n.startswith("dist_") and _wird_ausgeschlossen(n, ohne)]
    assert weiter_gedeckt == [], (
        f"{weiter_gedeckt} waeren auch OHNE {_NEUER_EINTRAG!r} ausgeschlossen — dann misst der "
        f"Test darueber den pytest-Default, nicht diesen Fix")


def test_die_getrackte_testmenge_wird_nicht_mit_ausgeschlossen(pytestconfig):
    """Die Gegenrichtung: ein Riegel, der zu breit greift, versteckt echte Tests.

    `tests/` und `scripts/` duerfen von keinem Muster erfasst werden — sonst waere die Sammlung
    zwar fehlerfrei, aber leerer als vorher, und das ist der schlechtere Zustand (ein gruener
    Balken ohne Deckung).
    """
    muster = _norecursedirs(pytestconfig)
    erfasst = [n for n in ("tests", "scripts", "src", "proofbundle")
               if _wird_ausgeschlossen(n, muster)]
    assert erfasst == [], (
        f"{erfasst} werden von norecursedirs erfasst — die Sammlung waere sauber, aber blind "
        f"(Muster: {muster})")
