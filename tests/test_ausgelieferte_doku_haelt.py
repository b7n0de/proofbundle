"""Der Doku-Waechter muss AUF DEM AUSGELIEFERTEN ZUSTAND urteilen, nicht nur im Checkout.

GEMESSEN am 01.09.2026, und das ist der Anlass: `tests/test_docs_truth.py` ist der einzige
Aufrufer von `scripts/doc_link_check.py`, und in der sdist ueberspringen sich dort ALLE SIEBEN
Pruefungen ("N/A outside a git checkout"). `docs/RECEIPT_ENVELOPE_PROFILE.md` verwies auf zwei
Dokumente, die nicht mitgeliefert werden — ausgeliefert tote Links, und nichts hat es gemessen.
Zugleich nannten 14 Faelle `docs/AGENT_REVIEW_PREDICATE.md` normativ, ohne dass die Datei im Paket
lag.

DIE KLASSE: ein Waechter, dessen einziger Aufrufer sich im Auslieferungszustand ueberspringt,
laesst genau den ausgelieferten Zustand ungeprueft.

Die Faelle hier bauen SYNTHETISCHE Wurzeln, bei denen die richtige Antwort unabhaengig feststeht —
die Erwartung wird also nicht vom Prueflig geborgt. Jeder Mutant prueft zuerst, dass seine
Mutation ueberhaupt angekommen ist; eine wirkungslose Mutation belegt nichts.
"""
from __future__ import annotations

import importlib.util
import json
import pathlib
import shutil

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location(
    "shipped_docs_check", REPO / "scripts" / "shipped_docs_check.py")
SDC = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(SDC)


def _wurzel(tmp: pathlib.Path, *, mit_spez: bool = True, mit_totem_link: bool = False,
            mit_waechter: bool = True, mit_korpus: bool = True) -> pathlib.Path:
    """Baut eine Wurzel OHNE .git — genau die Lage, in der die sdist beim Nutzer liegt."""
    r = tmp / "wurzel"
    (r / "docs").mkdir(parents=True)
    (r / "scripts").mkdir()
    (r / "docs" / "PROFIL.md").write_text(
        "# Profil\n\n" + ("[weg](VERSCHWUNDEN.md)\n" if mit_totem_link else "[hier](PROFIL.md)\n"),
        encoding="utf-8")
    if mit_spez:
        (r / "docs" / "SPEZ.md").write_text("# Spezifikation\n", encoding="utf-8")
    if mit_waechter:
        shutil.copy2(REPO / "scripts" / "doc_link_check.py", r / "scripts" / "doc_link_check.py")
    if mit_korpus:
        fall = r / "conformance" / "agent_review" / "ein-fall"
        fall.mkdir(parents=True)
        (fall / "case.json").write_text(
            json.dumps({"specRefs": ["docs/SPEZ.md"]}), encoding="utf-8")
    assert not (r / ".git").exists(), "die Wurzel darf keinen git-Kontext haben"
    return r


def test_urteilt_ohne_git_kontext(tmp_path):
    """Der Kern: eine Wurzel ohne .git bekommt ein ECHTES Urteil, kein Uebersprungen."""
    e = SDC.pruefe(_wurzel(tmp_path))
    assert e["zustand"] == "ok", e
    assert e["tote_links"]["zustand"] == "ok"
    assert e["spezifikationen"]["zustand"] == "ok"
    assert e["spezifikationen"]["genannt"] == 1


def test_fehlende_spezifikation_faellt_durch(tmp_path):
    """MUSS-FEHLSCHLAG P2: der Fall nennt sie normativ, das Paket enthaelt sie nicht."""
    r = _wurzel(tmp_path, mit_spez=False)
    assert not (r / "docs" / "SPEZ.md").exists(), "Mutation nicht angekommen"
    e = SDC.pruefe(r)
    assert e["zustand"] == "verletzt", e
    assert [f["specRef"] for f in e["spezifikationen"]["fehlend"]] == ["docs/SPEZ.md"]


def test_toter_link_faellt_durch(tmp_path):
    """MUSS-FEHLSCHLAG P1: ein ausgeliefertes Dokument zeigt auf etwas Nichtvorhandenes."""
    r = _wurzel(tmp_path, mit_totem_link=True)
    assert "VERSCHWUNDEN.md" in (r / "docs" / "PROFIL.md").read_text(), "Mutation nicht angekommen"
    e = SDC.pruefe(r)
    assert e["zustand"] == "verletzt", e
    assert any("VERSCHWUNDEN.md" in t["target"] for t in e["tote_links"]["tote"]), e


@pytest.mark.parametrize("fehlt,achse", [("waechter", "tote_links"), ("korpus", "spezifikationen")])
def test_fehlender_pruefstand_ist_nicht_messbar_und_keine_freigabe(tmp_path, fehlt, achse):
    """Der dritte Zustand: kein Pruefstand heisst NICHT `ok`."""
    r = _wurzel(tmp_path, mit_waechter=(fehlt != "waechter"), mit_korpus=(fehlt != "korpus"))
    e = SDC.pruefe(r)
    assert e[achse]["zustand"] == "nicht_messbar", e
    assert e["zustand"] != "ok", "nicht messbar darf nie als Freigabe durchgehen"


def test_die_abgrenzung_stammt_aus_EINER_quelle(tmp_path):
    """Kein zweites Verzeichnis-Verbot: die Regel gehoert `doc_link_check`, hier steht keine Kopie."""
    text = (REPO / "scripts" / "shipped_docs_check.py").read_text(encoding="utf-8")
    for verzeichnis in ("archive", "node_modules"):
        assert f'"{verzeichnis}"' not in text and f"'{verzeichnis}'" not in text, (
            f"{verzeichnis!r} steht hier als eigene Liste — die Abgrenzung gehoert doc_link_check")


def test_kein_toter_link_im_vorliegenden_zustand():
    """P1 hart: das gilt im Checkout WIE in der sdist, seit die zwei Links absolut sind."""
    e = SDC.pruefe(REPO)
    assert e["tote_links"]["zustand"] == "ok", e["tote_links"]
    assert (e["tote_links"]["geprueft"] or 0) > 0, "0 Links geprueft — der Test saehe nichts"


GRUNDLINIE = json.loads(
    (REPO / "conformance" / "unshipped_spec_refs_baseline.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("ist,anzahl,soll_verletzt,warum", [
    (set(), 0, False, "nichts fehlt"),
    (set(GRUNDLINIE["dokumente"]), GRUNDLINIE["anzahl_nennungen_offen"], False,
     "genau die Grundlinie"),
    ({"docs/GANZ_NEU.md"}, 1, True, "ein Dokument, das die Grundlinie nicht kennt"),
    (set(GRUNDLINIE["dokumente"]), GRUNDLINIE["anzahl_nennungen_offen"] + 1, True,
     "gleiche Dokumente, aber eine Nennung mehr"),
    ({"docs/AGENT_REVIEW_PREDICATE.md"}, 1, True, "die geschlossene Spezifikation faellt heraus"),
])
def test_das_urteil_ueber_die_luecke_greift(ist, anzahl, soll_verletzt, warum):
    """MUSS-FEHLSCHLAG der Ratsche — mit synthetischen Mengen, weil die GEMESSENE Menge im
    Checkout leer ist (dort liegt jede Datei vor) und jede Behauptung darueber trivial waere."""
    verletzt = SDC.luecke_beurteilen(ist, anzahl, GRUNDLINIE)
    assert bool(verletzt) is soll_verletzt, f"{warum}: {verletzt}"


def test_eine_nachgezogene_grundlinie_darf_die_spezifikation_nicht_freigeben():
    """MUSS-FEHLSCHLAG, den die Faelle oben NICHT isolieren koennen.

    Solange `docs/AGENT_REVIEW_PREDICATE.md` nicht in der Grundlinie steht, faengt sie schon die
    erste Regel ("neu dazugekommen") — die dritte Regel ist dort maskiert. Gefaehrlich wird genau
    der andere Fall: jemand zieht die Grundlinie nach, nimmt die Spezifikation auf, und damit waere
    ihr Herausfallen wieder erlaubt. Diese Grundlinie ist deshalb absichtlich weicher als die echte."""
    weicher = {"dokumente": {"docs/AGENT_REVIEW_PREDICATE.md": 14}, "anzahl_nennungen_offen": 14}
    verletzt = SDC.luecke_beurteilen({"docs/AGENT_REVIEW_PREDICATE.md"}, 14, weicher)
    assert verletzt, (
        "eine nachgezogene Grundlinie darf nicht erlauben, dass die Spezifikation aus dem Paket "
        "faellt — 14 Faelle nennen sie normativ")
    assert any("gefallen" in v for v in verletzt), verletzt


def test_die_grundlinie_ist_gemessen_und_benennt_sich_als_luecke():
    assert GRUNDLINIE["anzahl_nennungen_offen"] > 0, "eine Grundlinie ohne Luecke braucht niemand"
    assert GRUNDLINIE["dokumente"], "keine Dokumente benannt"
    assert "docs/AGENT_REVIEW_PREDICATE.md" not in GRUNDLINIE["dokumente"], (
        "die geschlossene Spezifikation gehoert nicht in die Grundlinie")
    assert "KEINE Freigabe" in GRUNDLINIE["warum_es_diese_datei_gibt"], (
        "die Grundlinie muss sich selbst als Luecke ausweisen, nicht als Erlaubnis")


def test_die_luecke_der_spezifikationen_waechst_NICHT():
    """P2 als Ratsche gegen eine FESTGESCHRIEBENE Grundlinie.

    Warum keine harte Gruen-Forderung: gemessen am 01.09.2026 nennen 143 von 168 specRefs
    Dokumente, die das Paket nicht enthaelt — zehn Stueck. Das zu schliessen heisst, diese
    Dokumente samt der transitiven Huelle ihrer Linkziele auszuliefern; MANIFEST.in trifft diese
    Wahl bewusst einzeln per Pfad und begruendet dort, warum `graft docs` ausscheidet. Das ist eine
    Verpackungsentscheidung des Owners, kein Nebenzug im Tag-Vorlauf.

    Was dieser Test dafuer leistet: die Luecke ist BENANNT statt vergessen, sie darf nicht wachsen,
    und kein neues Dokument darf dazukommen. Die Grundlinie ist gemessene, eingefrorene Zahl — sie
    wird NICHT zur Laufzeit aus dem Prueflig abgeleitet, sonst bestuende jeder Zustand."""
    e = SDC.pruefe(REPO)["spezifikationen"]
    if e["zustand"] == "nicht_messbar":
        pytest.skip(e.get("grund", "conformance/ fehlt"))
    ist = {f["specRef"] for f in e["fehlend"]}
    verletzt = SDC.luecke_beurteilen(ist, len(e["fehlend"]), GRUNDLINIE)
    assert not verletzt, (
        f"{verletzt} — entweder in MANIFEST.in aufnehmen oder den specRef auf eine absolute URL "
        f"stellen. Gemessen: {len(e['fehlend'])} von {e['genannt']} Nennungen ohne Datei.")
    assert e["genannt"] > 0, "kein specRef gemessen — der Test saehe nichts"
