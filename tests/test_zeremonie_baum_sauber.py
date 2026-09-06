"""Der Riegel muss einen unsauberen Baum FANGEN — auch wenn nur eine UNGETRACKTE Datei stoert.

WARUM ES DIESEN TEST GIBT. Am 2026-09-06 kostete dieselbe Verwechslung drei Instanzen an einem Tag:
ein ungetracktes ``scratchpad/`` im Kandidatenbaum waehrend des Distributionsbaus, eine ungetrackte
ABGEWIESENE Receipt-Datei, die die Vollsuite ROT machte, und ein ungetracktes Rust-Bauartefakt, das
ein Testurteil von ``DATA_BLOCKED`` auf ``FAIL`` kippte. Jedes Mal dieselbe Begruendung —
„ungetrackt, also sieht es nicht wie Bestand aus" —, eine Aussage ueber den INDEX, waehrend jedes
Werkzeug die PLATTE liest.

Geprueft wird in BEIDE Richtungen: der Riegel faengt eine ungetrackte Datei, ein ungetracktes
Verzeichnis und eine modifizierte getrackte Datei, und er laesst einen sauberen Baum durch. Ohne
die letzte Haelfte waere ein Riegel, der IMMER abbricht, hier gruen und trotzdem wertlos.

WAS DIESE FAELLE NICHT ABDECKEN, damit niemand mehr hineinliest, als gemessen ist: die dritte
Instanz oben ist ein IGNORIERTER Pfad, der WAEHREND des Laufs entsteht. Beides liegt ausserhalb
dessen, was ``--porcelain`` vor dem Lauf zeigen kann. Offen als
``BAUMRIEGEL-SIEHT-IGNORIERTE-PFADE-NICHT-DIE-DRITTE-INSTANZ-BLEIBT-01``.
"""
from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
RIEGEL = REPO / "scripts" / "b7_zeremonie_baum_sauber.py"


def _lauf(repo: Path) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(RIEGEL), "--repo", str(repo)],
                          capture_output=True, text=True, timeout=120)


@pytest.fixture()
def sauberer_baum():
    with tempfile.TemporaryDirectory() as td:
        repo = Path(td)
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        (repo / "datei.txt").write_text("inhalt\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(repo), "add", "-A"], check=True)
        subprocess.run(["git", "-C", str(repo), "-c", "user.email=t@x", "-c", "user.name=t",
                        "commit", "-qm", "start"], check=True)
        yield repo


def test_ein_sauberer_baum_geht_durch(sauberer_baum):
    """DIE ANTI-PARITAETS-HAELFTE. Ohne sie waere ein immer-abbrechender Riegel gruen."""
    r = _lauf(sauberer_baum)
    assert r.returncode == 0, f"sauberer Baum wurde abgewiesen:\n{r.stdout}"
    assert "Baum sauber" in r.stdout


def test_eine_UNGETRACKTE_datei_bricht_ab_und_wird_genannt(sauberer_baum):
    """DER FUND VOM 06.09.2026, ausfuehrbar. Eine ungetrackte Datei ist NICHT wirkungslos."""
    (sauberer_baum / "abgewiesenes_receipt.json").write_text('{"a":1}\n', encoding="utf-8")
    r = _lauf(sauberer_baum)
    assert r.returncode == 1, f"ungetrackte Datei wurde durchgelassen:\n{r.stdout}"
    assert "abgewiesenes_receipt.json" in r.stdout, (
        "der Riegel bricht ab, nennt die Datei aber nicht — eine Meldung ohne Namen zwingt zum "
        f"Suchen und wird umgangen:\n{r.stdout}")


def test_ein_ungetracktes_VERZEICHNIS_bricht_ebenfalls_ab(sauberer_baum):
    """Die zweite Instanz desselben Tages war ein ungetracktes scratchpad/-VERZEICHNIS."""
    (sauberer_baum / "scratchpad").mkdir()
    (sauberer_baum / "scratchpad" / "probe.py").write_text("x = 1\n", encoding="utf-8")
    r = _lauf(sauberer_baum)
    assert r.returncode == 1, f"ungetracktes Verzeichnis wurde durchgelassen:\n{r.stdout}"
    assert "scratchpad" in r.stdout


def test_eine_modifizierte_getrackte_datei_bricht_ab(sauberer_baum):
    (sauberer_baum / "datei.txt").write_text("geaendert\n", encoding="utf-8")
    r = _lauf(sauberer_baum)
    assert r.returncode == 1, f"modifizierte Datei wurde durchgelassen:\n{r.stdout}"
    assert "datei.txt" in r.stdout


def test_ohne_git_ist_es_NICHT_MESSBAR_und_keine_freigabe():
    """NICHT MESSBAR ist keine Freigabe. Ein Riegel, der bei fehlender Auskunft durchwinkt,
    ist wertlos — und rc 2 unterscheidet den Fall vom gemessenen Abbruch (rc 1)."""
    with tempfile.TemporaryDirectory() as td:
        r = _lauf(Path(td))
        assert r.returncode == 2, f"kein Repo, trotzdem rc={r.returncode}:\n{r.stdout}"
        assert "NICHT MESSBAR" in r.stdout
