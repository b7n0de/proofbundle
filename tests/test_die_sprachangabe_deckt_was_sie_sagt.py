"""Die Sprachangabe des Traegers deckt, was sie sagt — Zitate behalten ihre Sprache und stehen dabei.

HERKUNFT, Codex r3999621601. Der Traeger fuehrte `language: en` und trug deutsche Prosa. Wer ein
Dokument nach seiner Sprachangabe auswaehlt oder darstellt, bekam etwas materiell anderes, als die
Angabe sagt.

UEBERSETZEN WAR HIER KEINE OPTION, und das ist der Kern des Fixes. Gemessen stammen 79 Titel und
33 Klassenbegruendungen WORTWOERTLICH aus `RESTRISIKO_600.md`, einer deutschen Quelle, und die
Belegdateien sind byte-gepinnt: `pruefe_v2` rechnet ihren Digest gegen genau diese Bytes. Eine
Uebersetzung waere eine Faelschung der Evidenz. Ein Zitat behaelt seine Sprache; das ist keine
Schwaeche des Dokuments, sondern die Bedingung dafuer, dass es nachrechenbar bleibt.

Deshalb wurde die ANGABE wahr gemacht statt der Inhalt passend. `language` beschreibt die ERZEUGTE
Prosa, und die ist durchgaengig englisch. Was zitiert ist, steht in `language_scope` mit seiner
eigenen Sprache, seiner Quelle und dem Grund.

EINE ZWEITE RUNDE AM EIGENEN ZUSATZ: das Feld `severity.source_reason` kam heute dazu und trug
deutschen Text — derselbe Fund an der Ergaenzung, die eine Runde vorher entstanden war. Was der
Erzeuger selbst schreibt, folgt der Angabe; was er zitiert, steht im Geltungsbereich.

EHRLICHE GRENZE: gemessen wird ueber eine benannte Menge deutscher Funktionswoerter. Ein deutscher
Satz ohne eines davon faellt durch. Das ist eine Untergrenze der Messung, keine Zusicherung.
"""
from __future__ import annotations

import fnmatch
import json
import pathlib
import re

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
TRAEGER = REPO / "audit_artifacts" / "600" / "findings_register_v2.json"

#: Deutsche Funktionswoerter. Benannt, damit die Grenze der Messung sichtbar ist.
_DEUTSCH = re.compile(
    r"\b(die|der|das|und|nicht|wird|liegt|keine|eine|ist|werden|steht|waere|kein|fuer|auch)\b")


def _doc():
    if not TRAEGER.is_file():
        pytest.skip(f"NICHT MESSBAR: {TRAEGER} fehlt")
    return json.loads(TRAEGER.read_text(encoding="utf-8"))


def _deutsche_felder(doc) -> dict:
    raus: dict[str, int] = {}

    def geh(o, pfad=""):
        if isinstance(o, dict):
            for k, v in o.items():
                geh(v, f"{pfad}.{k}")
        elif isinstance(o, list):
            for v in o:
                geh(v, f"{pfad}[]")
        elif isinstance(o, str) and _DEUTSCH.search(o):
            raus[pfad] = raus.get(pfad, 0) + 1
    geh(doc)
    return raus


def test_der_traeger_nennt_einen_geltungsbereich():
    """[ZAEHLT] Eine Angabe ohne Geltungsbereich verschweigt ihre Ausnahme."""
    ls = _doc().get("language_scope")
    assert ls, "der Traeger fuehrt keinen language_scope"
    assert ls.get("generated_prose"), "die Sprache der erzeugten Prosa ist nicht genannt"
    q = ls.get("quoted_from_source") or {}
    for feld in ("language", "source", "fields", "why"):
        assert q.get(feld), f"quoted_from_source nennt {feld!r} nicht"


def test_jedes_deutsche_feld_liegt_im_geltungsbereich():
    """[ZAEHLT] Der Fund selbst, ueber den ganzen Traeger."""
    doc = _doc()
    muster = (doc.get("language_scope", {}).get("quoted_from_source", {}) or {}).get("fields") or []
    offen = [p for p in _deutsche_felder(doc)
             if "language_scope" not in p
             and not any(fnmatch.fnmatch(p.lstrip("."), m) for m in muster)]
    assert not offen, (
        f"{len(offen)} Feld(er) tragen deutsche Prosa ausserhalb des deklarierten "
        f"Geltungsbereichs: {sorted(offen)}")


def test_die_zitierte_quelle_existiert_und_ist_die_gepinnte():
    """[ZAEHLT] Ein Geltungsbereich, der auf eine Datei zeigt, die es nicht gibt, deckt nichts."""
    doc = _doc()
    q = doc["language_scope"]["quoted_from_source"]
    p = REPO / q["source"]
    assert p.is_file(), f"die genannte Quelle fehlt: {q['source']!r}"
    genannt = {s["path"] for s in doc["inventory"]["source_documents"]}
    assert q["source"] in genannt, (
        f"die zitierte Quelle {q['source']!r} steht nicht im Inventar — dann ist ihr Digest nicht "
        f"gebunden, und das Zitat nicht nachrechenbar")


def test_die_erzeugten_gruende_sind_in_der_deklarierten_sprache():
    """[ZAEHLT] Was der Erzeuger selbst schreibt, folgt der Angabe."""
    doc = _doc()
    fehler = []
    for r in doc["records"]:
        for f in ("kind_reason", "class_reason", "last_measured_reason"):
            if r.get(f) and _DEUTSCH.search(r[f]):
                fehler.append(f"{r['id']}.{f}")
        sev = r.get("severity") or {}
        for f in ("reason", "source_reason", "source_state"):
            if sev.get(f) and _DEUTSCH.search(str(sev[f])):
                fehler.append(f"{r['id']}.severity.{f}")
    assert not fehler, f"{len(fehler)} erzeugte Begruendungen tragen deutsche Prosa: {fehler[:6]}"


def test_ANTI_die_zitate_wurden_NICHT_uebersetzt():
    """[ZAEHLT] Gegenrichtung, und sie ist die wichtigere.

    Wer die Titel uebersetzte, um die Sprachangabe zu retten, faelschte die Evidenz: die Belege
    sind byte-gepinnt und ihr Digest wird gegen genau diese Bytes gerechnet. Dieser Fall haelt
    fest, dass die Zitate ihre Sprache BEHALTEN.
    """
    doc = _doc()
    deutsch_in_titeln = sum(1 for r in doc["records"] if _DEUTSCH.search(r.get("title") or ""))
    assert deutsch_in_titeln >= 20, (
        f"nur {deutsch_in_titeln} Titel tragen noch deutsche Prosa — wurden die Zitate uebersetzt? "
        f"Dann stimmen die Belegdigests nicht mehr mit der Quelle ueberein")


def test_die_grenze_der_messung_steht_im_text():
    """[ZAEHLT] Eine Wortliste ist eine Untergrenze, und das gehoert hingeschrieben."""
    q = pathlib.Path(__file__).read_text(encoding="utf-8")
    assert "EHRLICHE GRENZE" in q
    assert "Untergrenze der Messung" in q
