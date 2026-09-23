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


def _trifft(text: str) -> str | None:
    """Der NAME der Form, die zuschlaegt — oder None. Der Name zaehlt: eine Bindung ueber die
    falsche Form waere ein Treffer aus dem falschen Grund."""
    for form, muster, _ in _gate()._CLAIM_SHAPES:
        if muster.search(text):
            return form
    return None


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
    Dutzende Stellen wirft, wird abgeschaltet, bevor er den ersten echten Fall zeigt."""
    rc = subprocess.run(["git", "-C", str(REPO), "ls-files"], capture_output=True, text=True)
    if rc.returncode != 0:
        pytest.skip("kein git-Index lesbar")
    g = _gate()
    neue = [(f, m) for f, m, _ in g._CLAIM_SHAPES if f != "current/latest phrase"]
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
    quelle = TOR.read_text(encoding="utf-8")
    version, _ = g._source_version(REPO)
    assert version, "ohne Quellversion sagt dieser Test nichts"
    # Die Prueferdatei darf die EIGENE aktuelle Fassung nicht in einer Behauptungsform tragen.
    for form, muster, _ in g._CLAIM_SHAPES:
        for treffer in muster.findall(quelle):
            assert treffer != version, (
                f"{TOR.name} traegt die eigene Fassung {version} als {form} — genau die Stelle, "
                f"die der Sweep zu Recht meldet")


def test_ein_ausnahmepfad_fuer_die_prueferdatei_existiert_nicht():
    """Ein Pruefer, der sich selbst ausnimmt, hoert auf, die Datei zu pruefen, die am ehesten
    Behauptungen zitiert."""
    quelle = TOR.read_text(encoding="utf-8")
    assert not re.search(r"check_version_and_changelog\.py[\"']?\s*[,)]?\s*(?:#.*)?$"
                         r"|rel\s*==\s*[\"'][^\"']*check_version_and_changelog",
                         quelle, re.M), "die Datei nimmt sich selbst vom Sweep aus"


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-q"]))
