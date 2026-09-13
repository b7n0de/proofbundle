"""Wer einen Anker nach aussen behauptet, nennt die Eindeutigkeitsgrenze — Auftrag 20260913T2012Z, Schritt 4.

DER FUND, gemessen am 13.09.2026 gegen den eigenen Bestand (Messung 1, Equivocation, gegen den Kopf
`4e32e83`). `docs/readiness_pack/tamper_resistance.md` erklaert das AuditWeave-Problem (a) fuer
geschlossen, weil der Content-Root an eine "external append-only reference" gebunden wird, und nennt
unter "The honest limit (what this does NOT claim)" VIER Grenzen. Die fuenfte, benachbarte fehlte:

    Ein externer Anker beweist Existenz VOR einem Zeitpunkt, nicht EINDEUTIGKEIT. Ein Aussteller kann
    zwei divergente, je in sich intakte Belege derselben Studie in dieselbe Kette ankern und jedem
    Leser einen zeigen. Beide verifizieren. Beide melden `confirmed`.

Kein Satz dort war falsch. Falsch war die LESART, die er einlaedt: in CT/SCITT ist `append-only`
genau das Wort, aus dem Nicht-Gabelbarkeit folgt, und der Adressat dieses Dokuments kommt aus diesem
Umfeld — das Dokument sagt es selbst ("so an external auditor finds it addressed rather than
missing"). Der maschinenlesbare Zwilling in `docs/readiness_pack/index.json` war schwaecher als die
Prosa: er trug ueberhaupt keine Grenze, nur die Schliessung.

WARUM DIE PRUEFUNG AN EINER KENNUNG HAENGT UND NICHT AN EINER FORMULIERUNG. Der erste Entwurf dieses
Riegels suchte die Grenze per Regex in der Prosa (`equivocat|split[- ]view|two divergent|uniqueness`).
GEMESSEN fiel damit ausgerechnet `docs/predicates/run-ledger.md` durch — die Flaeche, die die Grenze
seit jeher WOERTLICH nennt, nur mit anderen Worten ("two intact ledgers ... present each to a
different reader"). Ein Muster ueber Prosa misst die SCHREIBWEISE, nicht die Eigenschaft, und haette
hier die sorgfaeltigste Flaeche als Luecke gemeldet. Deshalb traegt die Grenze eine stabile Kennung,
die ein Mensch bewusst setzt, und geprueft wird auf Identitaet.

DIE AUSNAHME IST EINE EIGENSCHAFT, KEINE PFADLISTE. `docs/RELATED_WORK.md` nennt
"blockchain-anchored, tamper-resistant audit trails" — ueber eine FREMDE Arbeit (arXiv 2604.22096).
Das ist keine Behauptung von uns. Ein Treffer ist deshalb ausgenommen, wenn sein Satz eine fremde
Quelle zitiert UND kein Subjekt der ersten Person traegt. Diese Bauform ist von
`scripts/claims_hygiene_check.py` uebernommen, wo dieselbe Unterscheidung fuer `append-only` schon
steht; der Erste-Person-Ausdruck wird von dort IMPORTIERT statt kopiert, damit die beiden nicht
auseinanderlaufen (OA-714de2fcdd, kein zweiter Erzeuger).
"""
from __future__ import annotations

import importlib.util
import json
import pathlib
import re

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]

#: Die stabile Kennung der Grenze. Sie steht in der Prosa, im Bedrohungsmodell und im
#: maschinenlesbaren Zwilling — ein Wort, das nur gesetzt wird, wenn jemand es setzen will.
TOKEN = "LIMIT_ANCHOR_EXISTENCE_NOT_UNIQUENESS"

#: Der ANSPRUCH, nach dem gesucht wird: eine Flaeche, die den externen Anker als Widerstands-
#: eigenschaft nach aussen behauptet. Abgeleitet aus dem Wortlaut, den tamper_resistance.md und
#: der AuditWeave-Zitatzeile fuehren, nicht erfunden.
ANSPRUCH = re.compile(
    r"external\s+append[- ]only\s+reference|tamper[- ]resistan|silently\s+recompute|"
    r"cannot\s+silently\s+(?:re)?comput", re.IGNORECASE)

#: Eine fremde Quelle im selben Satz: arXiv-Kennung, DOI oder eine Verweis-URL.
FREMDE_QUELLE = re.compile(r"arxiv[:\s]|doi[:\s]|https?://", re.IGNORECASE)

_CH = REPO / "scripts" / "claims_hygiene_check.py"
_spec = importlib.util.spec_from_file_location("claims_hygiene_check", _CH)
_chm = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_chm)
#: IMPORTIERT, nicht kopiert — siehe Modul-Docstring.
ERSTE_PERSON = _chm._FIRST_PARTY_SUBJECT


#: Der Anfang eines Aufzaehlungspunktes oder eines Absatzes.
_BLOCKSTART = re.compile(r"(?m)^(?:[-*+]\s|\d+\.\s|[ \t]*$)")


def _umfeld(text: str, pos: int) -> str:
    """Der umschliessende Aufzaehlungspunkt oder Absatz — NICHT der "Satz".

    Die erste Fassung schnitt am Punkt. GEMESSEN fiel sie ueber `arXiv 2604.22096`: die Kennung
    traegt selbst Punkte, der Treffer landete in einem Fragment ohne das Zitat, und die Ausnahme
    fuer fremde Arbeiten feuerte nie. In einer Literaturliste ist der Aufzaehlungspunkt die Einheit,
    in der ein Gegenstand benannt wird, nicht der Satz.
    """
    links, rechts = 0, len(text)
    for m in _BLOCKSTART.finditer(text):
        if m.start() <= pos:
            links = m.start()
        else:
            rechts = m.start()
            break
    return text[links:rechts]


def pruefe(flaechen: dict[str, str]) -> list[str]:
    """Die reine Regel. Eingabe ``{relativer Pfad: Text}``, Ausgabe die Flaechen ohne Grenze.

    Rein, damit sie an einem GEBAUTEN Gegenbeispiel fallen kann. Eine Zusicherung, die nur den
    echten Baum lesen kann, hat kein Gegenbeispiel und ist damit nicht fangnachweisbar — genau die
    Luecke, die diese Sitzung am eigenen CI-Vertrag gefunden hat.
    """
    fehlt = []
    for rel, text in sorted(flaechen.items()):
        if TOKEN in text:
            continue
        for m in ANSPRUCH.finditer(text):
            satz = _umfeld(text, m.start())
            if FREMDE_QUELLE.search(satz) and not ERSTE_PERSON.search(satz):
                continue        # Aussage ueber eine FREMDE Arbeit, nicht ueber uns
            fehlt.append(rel)
            break
    return fehlt


def _markdown_des_baums() -> dict[str, str]:
    aus = {}
    for p in sorted(REPO.rglob("*.md")):
        s = str(p)
        if any(t in s for t in (".git/", "node_modules", "/htmlcov/", "site-packages", "/.venv/")):
            continue
        aus[str(p.relative_to(REPO))] = p.read_text(encoding="utf-8", errors="replace")
    return aus


# ── die Zusicherungen am echten Baum ─────────────────────────────────────────────────────────────

def test_jede_flaeche_die_den_anker_behauptet_nennt_die_grenze():
    if not (REPO / "THREAT_MODEL.md").is_file():
        pytest.skip("kein Repo-Kontext")
    fehlt = pruefe(_markdown_des_baums())
    assert fehlt == [], (
        "diese Flaeche(n) behaupten den externen Anker als Widerstandseigenschaft, nennen aber die "
        f"Eindeutigkeitsgrenze {TOKEN} nicht: {fehlt} — ein Anker beweist Existenz vor einem "
        "Zeitpunkt, nie Eindeutigkeit")


def test_der_maschinenlesbare_zwilling_ist_nicht_schwaecher_als_die_prosa():
    """Der Zwilling war die schwaechere Haelfte: die Prosa nannte vier Grenzen, das JSON keine."""
    p = REPO / "docs" / "readiness_pack" / "index.json"
    if not p.is_file():
        pytest.skip("kein Repo-Kontext")
    c1 = next(c for c in json.loads(p.read_text(encoding="utf-8"))["conclusions"]
              if c["id"].startswith("C1_"))
    assert "closes_external_open_problem" in c1, "C1 behauptet keine Schliessung mehr — Test veraltet"
    grenze = c1.get("does_not_close")
    assert grenze, "C1 erklaert ein fremdes offenes Problem fuer geschlossen und nennt keine Grenze"
    assert grenze.get("id") == TOKEN
    for ref in grenze.get("stated_in", []):
        assert (REPO / ref).is_file(), f"does_not_close.stated_in zeigt auf {ref!r}, das es nicht gibt"


def test_das_bedrohungsmodell_trennt_den_aussteller_vom_log_betreiber():
    """Zeile 28 deckte den Split View des LOG-BETREIBERS. Die Doppelausgabe durch den AUSSTELLER
    fehlte — ein Nachbar, keine Wiederholung."""
    p = REPO / "THREAT_MODEL.md"
    if not p.is_file():
        pytest.skip("kein Repo-Kontext")
    text = p.read_text(encoding="utf-8")
    kopf = "## What it structurally does NOT catch"
    assert kopf in text
    abschnitt = text.split(kopf, 1)[1].split("\n## ", 1)[0]
    assert TOKEN in abschnitt, (
        "die Doppelausgabe durch den Aussteller steht nicht in der Liste dessen, was das Modell "
        "strukturell NICHT faengt")


# ── Fangnachweise: beide Richtungen, wie der Auftrag es verlangt ─────────────────────────────────

def test_fangnachweis_rot_eine_behauptung_ohne_die_grenze_wird_gefunden():
    gebaut = {"x.md": "proofbundle binds the content root to an external append-only reference."}
    assert pruefe(gebaut) == ["x.md"]


def test_fangnachweis_gruen_dieselbe_behauptung_mit_der_grenze_ist_sauber():
    gebaut = {"x.md": ("proofbundle binds the content root to an external append-only reference.\n"
                       f"The honest limit ({TOKEN}): it proves existence, not uniqueness.")}
    assert pruefe(gebaut) == []


def test_fangnachweis_an_der_ECHTEN_datei_nicht_an_einer_gebauten():
    """Der Fangnachweis, der zaehlt. Ein gebautes Beispiel beweist, dass die Regel FUNKTIONIERT;
    dieser beweist, dass sie an der Datei greift, um die es ging. Die echte Datei wird um die
    Kennung erleichtert — das ist exakt ihr Zustand vor diesem Fix — und muss dann fallen."""
    p = REPO / "docs" / "readiness_pack" / "tamper_resistance.md"
    if not p.is_file():
        pytest.skip("kein Repo-Kontext")
    echt = p.read_text(encoding="utf-8")
    assert TOKEN in echt, "die echte Datei traegt die Kennung nicht mehr — dann ist der Fix weg"
    vorher = echt.replace(TOKEN, "")
    rel = "docs/readiness_pack/tamper_resistance.md"
    assert pruefe({rel: vorher}) == [rel], (
        "der Riegel findet die Luecke in der ECHTEN Datei nicht, wenn man ihr die Kennung nimmt — "
        "dann bindet er an etwas anderes als an die Grenze")
    assert pruefe({rel: echt}) == []


def test_fangnachweis_die_ausnahme_ist_eng_und_kippt_bei_erster_person():
    """Die Ausnahme fuer fremde Arbeiten darf nicht zum Freibrief werden: dieselbe Zeile mit einem
    Subjekt der ersten Person ist wieder ein Fund, obwohl die Quelle noch dasteht."""
    fremd = ("- **Who Audits the Auditor?** (arXiv 2604.22096, 23 April 2026): blockchain-anchored, "
             "tamper-resistant audit trails so a privileged operator cannot rewrite records.")
    assert pruefe({"r.md": fremd}) == []
    eigen = fremd.replace("blockchain-anchored", "our blockchain-anchored")
    assert pruefe({"r.md": eigen}) == ["r.md"], (
        "ein Satz mit Subjekt der ersten Person bleibt ein Fund, auch mit Zitat daneben")


def test_fangnachweis_die_kennung_allein_traegt_nicht_wenn_der_anspruch_fehlt():
    """Gegenrichtung der Ausnahme: eine Flaeche OHNE Anspruch wird nie gemeldet, auch ohne Kennung.
    Sonst faerbt der Riegel den halben Baum rot."""
    assert pruefe({"harmlos.md": "This document explains how to install the CLI."}) == []
