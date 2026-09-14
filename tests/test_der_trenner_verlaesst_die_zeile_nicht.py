"""Ein Wertmuster, das den Zeilenumbruch frisst, macht die naechste Zeile zum Geheimnis.

Gefunden am 14.09.2026 beim GEGENPRUEFEN der drei Codex-P1 an PR 200, nicht von ihnen gemeldet.
Der Trenner zwischen Feldname und Wert war `\\s*[:=]\\s*`, und `\\s` enthaelt `\\n`. Gemessen:

    API_KEY=\\nSIGNING_PRIVATE_KEY=      -> Treffer, der gemeldete WERT ist der NAME der naechsten Zeile
    API_KEY=\\nHARMLOSE_ZEILE_OHNE_ALLES -> Treffer auf eine Zeile ohne jedes Geheimnis

Ein leerer Platzhalter mit einer langen Zeile darunter ist die kanonische `.env.example`. Ein
Riegel, der bei der EMPFOHLENEN Schreibweise anschlaegt, wird abgeschaltet, und dann faengt er
auch das Echte nicht mehr. Deshalb steht die Gegenrichtung hier gleichberechtigt neben dem Fang.
"""
from __future__ import annotations

import importlib.util
import io
import json
import pathlib
import subprocess
import sys
import tarfile

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
GUARD = REPO / "scripts" / "b7_paketinhalt_ohne_schluesselmaterial.py"


@pytest.fixture(scope="module")
def g():
    s = importlib.util.spec_from_file_location("paketriegel", GUARD)
    m = importlib.util.module_from_spec(s)
    sys.modules["paketriegel"] = m
    s.loader.exec_module(m)
    return m


def _urteil(tmp_path, name, inhalt: bytes) -> tuple[int, str]:
    p = tmp_path / "probe.tar.gz"
    with tarfile.open(p, "w:gz") as tf:
        ti = tarfile.TarInfo(f"pkg-1.0/{name}")
        ti.size = len(inhalt)
        tf.addfile(ti, io.BytesIO(inhalt))
    r = subprocess.run([sys.executable, str(GUARD), str(p)], capture_output=True, text=True)
    return r.returncode, json.loads(r.stdout)["urteil"]


@pytest.mark.parametrize("inhalt", [
    b"API_KEY=\nSIGNING_PRIVATE_KEY=\n",
    b"API_KEY=\nHARMLOSE_ZEILE_OHNE_ALLES\n",
    b"SECRET_KEY=\n\nSOME_OTHER_LONG_IDENTIFIER\n",
])
def test_ein_leerer_platzhalter_ist_kein_geheimnis(tmp_path, inhalt):
    """DER FANGNACHWEIS DER GEGENRICHTUNG. Vorher gab genau das TREFFER."""
    rc, urteil = _urteil(tmp_path, ".env.example", inhalt)
    assert (rc, urteil) == (0, "SAUBER"), f"Fehlalarm auf {inhalt!r}"


@pytest.mark.parametrize("inhalt", [
    b"API_KEY=sk-ABCDEFGHIJKLMNOPQRSTUV\n",
    b"SIGNING_PRIVATE_KEY=MC4CAQAwBQYDK2VwBCIEIHqLmNoPqRsTuVwXyZ0123456789abcd\n",
    b"github_pat_" + b"A1b2C3d4E5" * 8 + b"xy\n",
])
def test_ein_echtes_geheimnis_in_EINER_zeile_faellt_weiter_auf(tmp_path, inhalt):
    """Die andere Richtung. Ein Riegel, der nichts mehr faengt, ist kein Fix."""
    rc, urteil = _urteil(tmp_path, ".env", inhalt)
    assert (rc, urteil) == (1, "TREFFER"), f"nicht gefangen: {inhalt[:40]!r}"


def test_der_trenner_kennt_keinen_zeilenumbruch(g):
    """Die EIGENSCHAFT, nicht die Schreibweise des Musters."""
    assert g._TRENNER.find(rb"\n") == -1
    assert rb"\s" not in g._TRENNER, "der Trenner benutzt wieder eine Klasse, die \\n enthaelt"


def test_kein_muster_trennt_mehr_mit_einer_klasse_die_den_umbruch_enthaelt():
    """Ein Fix an einer von zwei Stellen laesst die zweite still zurueckkehren."""
    quelle = GUARD.read_text(encoding="utf-8")
    kern = quelle.split("_TRENNER = ", 1)[1]
    assert r"\s*[:=]\s*" not in kern, "eine Trennstelle benutzt noch die alte Klasse"


def test_der_treffer_bleibt_innerhalb_einer_zeile(g):
    """Auch wo der Treffer richtig ist, darf er nicht ueber die Zeilengrenze reichen."""
    probe = b"API_KEY=sk-ABCDEFGHIJKLMNOPQRSTUV\nNAECHSTE_ZEILE_BLEIBT_DRAUSSEN\n"
    treffer = [m.group(0) for muster in g.MUSTER["T"] for m in muster.finditer(probe)]
    assert treffer, "der echte Fall wird gar nicht mehr gefangen"
    for t in treffer:
        assert b"\n" not in t, f"der Treffer laeuft ueber die Zeile: {t!r}"
