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


def _alle_strings(doc) -> list[tuple[str, str]]:
    """Jede Zeichenkette des Traegers mit ihrem Pfad. EIN Sammler fuer beide Fragen."""
    raus: list[tuple[str, str]] = []

    def geh(o, pfad=""):
        if isinstance(o, dict):
            for k, v in o.items():
                geh(v, f"{pfad}.{k}")
        elif isinstance(o, list):
            for v in o:
                geh(v, f"{pfad}[]")
        elif isinstance(o, str):
            raus.append((pfad, o))
    geh(doc)
    return raus


def _deutsche_felder(doc) -> dict:
    raus: dict[str, int] = {}
    for pfad, wert in _alle_strings(doc):
        if _DEUTSCH.search(wert):
            raus[pfad] = raus.get(pfad, 0) + 1
    return raus


def _gruppen(doc) -> list:
    """Die Zitatgruppen, je Quelle eine. Die alte Ein-Quellen-Form ist ausdruecklich KEIN Treffer."""
    q = (doc.get("language_scope") or {}).get("quoted_from_source")
    assert isinstance(q, list), (
        f"`quoted_from_source` ist keine Liste von Gruppen ({type(q).__name__}). Die erste Fassung "
        f"nannte EINE Quelle fuer Felder aus ZWEI Dateien — eine Herkunftsangabe, die auf die "
        f"falsche Datei zeigt, ist nicht nachrechenbar.")
    return q


def _quellwerte(repo: pathlib.Path, quelle: str):
    """Die zitierbaren Bytes einer Quelle. JSON wird GEPARST, nicht als Rohtext gelesen.

    WARUM GEPARST: die erste Fassung dieser Messung verglich geparste Zeichenketten gegen den
    ROHTEXT der JSON — jeder Wert mit einem Anfuehrungszeichen darin scheiterte an der
    Maskierung und galt faelschlich als erzeugt. An der Eigenschaft messen, nicht an der
    Schreibweise; das galt hier fuer das Messwerkzeug selbst.
    """
    p = repo / quelle
    if not p.is_file():
        return None
    roh = p.read_text(encoding="utf-8")
    if not quelle.endswith(".json"):
        return roh
    werte: set[str] = set()

    def sammle(x):
        if isinstance(x, str):
            werte.add(x.strip())
        elif isinstance(x, dict):
            for v in x.values():
                sammle(v)
        elif isinstance(x, list):
            for v in x:
                sammle(v)
    sammle(json.loads(roh))
    return werte


def nicht_woertlich(doc, repo: pathlib.Path) -> list[str]:
    """Welche als ZITAT deklarierten Werte stehen NICHT woertlich in ihrer genannten Quelle?"""
    raus = []
    for g in _gruppen(doc):
        quelle = g.get("source")
        vorrat = _quellwerte(repo, quelle or "")
        if vorrat is None:
            raus.append(f"{quelle}: die genannte Quelle fehlt")
            continue
        muster = g.get("fields") or []
        for pfad, wert in _alle_strings(doc):
            if "language_scope" in pfad or not wert.strip():
                continue
            if not any(fnmatch.fnmatch(pfad.lstrip("."), m) for m in muster):
                continue
            drin = wert.strip() in vorrat if isinstance(vorrat, set) else wert.strip() in vorrat
            if not drin:
                raus.append(f"{pfad} steht nicht woertlich in {quelle}: {wert[:70]!r}")
    return raus


def test_der_traeger_nennt_einen_geltungsbereich():
    """[ZAEHLT] Eine Angabe ohne Geltungsbereich verschweigt ihre Ausnahme."""
    ls = _doc().get("language_scope")
    assert ls, "der Traeger fuehrt keinen language_scope"
    assert ls.get("generated_prose"), "die Sprache der erzeugten Prosa ist nicht genannt"
    gruppen = _gruppen(_doc())
    assert gruppen, "der Geltungsbereich nennt keine einzige Zitatgruppe"
    for g in gruppen:
        for feld in ("language", "source", "fields", "why"):
            assert g.get(feld), f"eine Zitatgruppe nennt {feld!r} nicht: {g}"


def test_jedes_deutsche_feld_liegt_im_geltungsbereich():
    """[ZAEHLT] Der Fund selbst, ueber den ganzen Traeger."""
    doc = _doc()
    muster = [m for g in _gruppen(doc) for m in (g.get("fields") or [])]
    offen = [p for p in _deutsche_felder(doc)
             if "language_scope" not in p
             and not any(fnmatch.fnmatch(p.lstrip("."), m) for m in muster)]
    assert not offen, (
        f"{len(offen)} Feld(er) tragen deutsche Prosa ausserhalb des deklarierten "
        f"Geltungsbereichs: {sorted(offen)}")


def test_die_zitierte_quelle_existiert_und_ist_die_gepinnte():
    """[ZAEHLT] Ein Geltungsbereich, der auf eine Datei zeigt, die es nicht gibt, deckt nichts."""
    doc = _doc()
    genannt = {s["path"] for s in doc["inventory"]["source_documents"]}
    for g in _gruppen(doc):
        assert (REPO / g["source"]).is_file(), f"die genannte Quelle fehlt: {g['source']!r}"
        assert g["source"] in genannt, (
            f"die zitierte Quelle {g['source']!r} steht nicht im Inventar — dann ist ihr Digest "
            f"nicht gebunden, und das Zitat nicht nachrechenbar")


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


# ── DIE DEKLARATION WIRD NACHGERECHNET, NICHT GEGLAUBT ────────────────────────────────────
#
# ZWEITE RUNDE AN DER EIGENEN ARBEIT, selbst gefunden am 13.09.2026. Der Geltungsbereich der
# ersten Fassung fuehrte `inventory.assurance_checks[].prose_rationale_note` als ZITAT — das Feld
# ist aber selbst geschrieben. Damit deckte die Ausnahme etwas, das gar nicht zitiert ist, und
# genau das ist die Klasse, gegen die dieser Traeger gebaut wurde: eine Angabe, die mehr behauptet,
# als sie traegt. Ein Geltungsbereich, den niemand nachrechnet, ist eine zweite Erzaehlung neben
# der ersten.

def test_jedes_als_zitat_deklarierte_feld_steht_woertlich_in_seiner_quelle():
    """[ZAEHLT] Der Fund an der eigenen Ausnahme: deklariert ist nicht dasselbe wie zitiert."""
    offen = nicht_woertlich(_doc(), REPO)
    assert not offen, (
        f"{len(offen)} als Zitat deklarierte Wert(e) stehen nicht woertlich in ihrer genannten "
        f"Quelle — dann ist die Ausnahme eine Behauptung: {offen[:4]}")


def test_FANG_ein_deklariertes_aber_ERZEUGTES_feld_faellt_auf():
    """[ZAEHLT] Gegenrichtung rot: genau die Lage, die in der ersten Fassung gruen war."""
    import copy  # noqa: PLC0415
    doc = copy.deepcopy(_doc())
    gruppen = _gruppen(doc)
    assert gruppen, "keine Gruppe zu erweitern"
    # Ein Feld, dessen Wert der Erzeuger selbst schreibt, in den Geltungsbereich schmuggeln.
    gruppen[0].setdefault("fields", []).append("inventory.assurance_checks[].prose_rationale_note")
    for a in doc["inventory"]["assurance_checks"]:
        a["prose_rationale_note"] = "die Zusicherung haelt, und dieser Satz steht in keiner Quelle"
    offen = nicht_woertlich(doc, REPO)
    assert any("prose_rationale_note" in x for x in offen), (
        f"ein erzeugtes Feld wurde als Zitat deklariert und faellt NICHT auf: {offen[:3]}")


def test_ANTI_der_echte_traeger_bleibt_ohne_befund():
    """[ZAEHLT] Ein Riegel, der alles meldet, misst nichts."""
    assert nicht_woertlich(_doc(), REPO) == []
