"""Wer einen Digest bindet, pinnt die Bytes — sonst schreibt der Checkout die Herkunft um.

FUND, Codex 3999820862 (P2). `.gitattributes` hielt die Belegdateien auf LF, aber nicht die beiden
QUELLDOKUMENTE, aus denen die Belege geschnitten sind und deren Digest der Traeger ebenfalls
nachrechnet. GEMESSEN am 13.09.2026 in einem Checkout mit `core.autocrlf=true`:
RESTRISIKO_600.md kommt mit 5202 CRLF-Paaren an, RESTRISIKO_600_OBJEKTKLASSEN.json mit 1473, beide
Digests weichen ab. Die byte-genaue Herkunft war dort nicht pruefbar.

DIE KLASSE: eine Liste von Ausnahmen wird VON HAND gefuehrt, waehrend die Menge, die sie decken
soll, aus den Daten waechst. Jede neue digest-gebundene Datei muss daran denken, hier eingetragen
zu werden — und genau das vergisst man.

DESHALB LEITET DIESER VERTRAG DIE MENGE AB, statt sie zu wiederholen. Er liest, welche Pfade der
Traeger per sha256 bindet, und verlangt fuer jeden eine Regel in `.gitattributes`. Ein neuer
gebundener Pfad faellt hier auf, bevor ein Windows-Checkout ihn umschreibt.
"""
from __future__ import annotations

import fnmatch
import json
import pathlib

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
TRAEGER = REPO / "audit_artifacts" / "600" / "findings_register_v2.json"
ATTR = REPO / ".gitattributes"


def _gebundene_pfade() -> set[str]:
    """Jeder Pfad, dessen BYTES der Traeger per Digest festnagelt."""
    if not TRAEGER.is_file():
        pytest.skip(f"NICHT MESSBAR: {TRAEGER} fehlt")
    d = json.loads(TRAEGER.read_text(encoding="utf-8"))
    raus = {q["path"] for q in d["inventory"].get("source_documents") or [] if q.get("sha256")}
    for r in d.get("records") or []:
        for e in r.get("evidence") or []:
            if e.get("sha256") and e.get("path"):
                raus.add(e["path"])
            if e.get("source_sha256") and e.get("source_path"):
                raus.add(e["source_path"])
    return raus


def _regeln() -> list[str]:
    if not ATTR.is_file():
        pytest.skip(f"NICHT MESSBAR: {ATTR} fehlt")
    raus = []
    for zeile in ATTR.read_text(encoding="utf-8").splitlines():
        z = zeile.strip()
        if not z or z.startswith("#"):
            continue
        teile = z.split()
        if len(teile) >= 2 and "-text" in teile[1:]:
            raus.append(teile[0])
    return raus


def _gepinnt(pfad: str, regeln: list[str]) -> bool:
    return any(fnmatch.fnmatch(pfad, m) or fnmatch.fnmatch(pathlib.PurePath(pfad).name, m)
               for m in regeln)


def test_es_gibt_ueberhaupt_gebundene_pfade():
    """[ZAEHLT] Ein Riegel ueber eine leere Menge misst nichts."""
    p = _gebundene_pfade()
    assert len(p) >= 3, f"nur {len(p)} gebundene Pfade gefunden — dann prueft dieser Fall nichts"


def test_jeder_digestgebundene_pfad_traegt_eine_regel():
    """[ZAEHLT] Der Fund selbst, als Mengenaussage statt als zwei Zeilen."""
    regeln = _regeln()
    offen = sorted(p for p in _gebundene_pfade() if not _gepinnt(p, regeln))
    assert not offen, (
        f"{len(offen)} digest-gebundene Datei(en) ohne `-text`-Regel: {offen[:6]}. In einem "
        f"Checkout mit core.autocrlf=true aendern sich ihre Bytes und damit ihr Digest, und die "
        f"veroeffentlichte Herkunft ist dort nicht pruefbar")


def test_die_beiden_quelldokumente_stehen_namentlich_drin():
    """[ZAEHLT] Der gemeldete Fall, damit die Regel nicht nur zufaellig von einem Glob getroffen wird."""
    roh = ATTR.read_text(encoding="utf-8")
    for n in ("RESTRISIKO_600.md", "RESTRISIKO_600_OBJEKTKLASSEN.json"):
        assert f"{n} -text" in roh, f"{n} ist nicht namentlich gepinnt"


def test_ANTI_eine_regel_OHNE_minus_text_zaehlt_nicht(tmp_path):
    """[ZAEHLT] Die Messung darf nicht jede Zeile fuer eine Pinnung halten.

    `text=auto` ist das GEGENTEIL einer Pinnung — es schaltet die Umschrift ein. Ein Leser, der
    nur den Dateinamen sucht, haelt so eine Zeile fuer Schutz.
    """
    datei = tmp_path / ".gitattributes"
    datei.write_text("RESTRISIKO_600.md text=auto\n# ein Kommentar -text\nleere_zeile\n",
                     encoding="utf-8")
    regeln = []
    for zeile in datei.read_text(encoding="utf-8").splitlines():
        z = zeile.strip()
        if not z or z.startswith("#"):
            continue
        teile = z.split()
        if len(teile) >= 2 and "-text" in teile[1:]:
            regeln.append(teile[0])
    assert regeln == [], f"eine Nicht-Pinnung wurde als Regel gelesen: {regeln}"
    assert not _gepinnt("RESTRISIKO_600.md", regeln)


def test_FANG_der_zustand_VOR_dem_fix_faellt_hier_durch():
    """[ZAEHLT] Gegenrichtung an der echten Menge: die alte Regelliste deckt sie NICHT.

    Das ist der Fangnachweis. Waere er gruen, prueft dieser Vertrag nichts — die alte Fassung von
    `.gitattributes` ist genau die Lage, die der Bericht gemeldet hat.
    """
    vorher = ["docs/register/G1.md", "audit_artifacts/600/register_evidence/*.md"]
    offen = sorted(p for p in _gebundene_pfade() if not _gepinnt(p, vorher))
    assert offen, "die alte Regelliste deckte schon alles — dann misst dieser Vertrag nichts"
    assert "RESTRISIKO_600.md" in offen, offen[:5]


def test_die_grenze_der_messung_steht_im_text():
    """[GETRENNT] Was dieser Vertrag NICHT sieht, gehoert hingeschrieben."""
    q = pathlib.Path(__file__).read_text(encoding="utf-8")
    assert "DIE KLASSE" in q and "LEITET DIESER VERTRAG DIE MENGE AB" in q
