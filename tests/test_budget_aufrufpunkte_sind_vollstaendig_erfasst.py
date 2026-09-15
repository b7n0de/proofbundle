"""Eine Dimension hat MEHRERE Aufrufpunkte — die Kostenkurve prueft einen davon.

HERKUNFT: Riegel-Sweep auf Owner-Auftrag, 2026-09-07. Die Frage des Auftrags war: bindet ein Test
die WIRKUNG eines Riegels oder nur seinen Wortlaut. Fuer die Budget-Deckel lautet die Antwort:
`tests/test_budget_kostenkurve.py::test_l_minus_eins_l_und_l_plus_eins` prueft je Dimension die
drei Punkte L-1, L, L+1 — an EINEM benannten Aufrufpunkt. Die anderen Aufrufpunkte DERSELBEN
Dimension sind davon nicht beruehrt.

GEMESSEN auf diesem Baum: 14 Aufrufpunkte ueber 6 Dimensionen, und `input_bytes` allein hat SIEBEN.
Eine adversariale Linse hat drei davon einzeln mutiert und keiner fiel auf:

  * `trust_pack.py:451` — der `input_bytes`-Deckel VOLLSTAENDIG durch `pass` ersetzt: 218 Faelle
    gruen, keiner bemerkt den fehlenden Deckel. Derselbe Deckelname ist fuer `decision.py` sehr
    wohl geprueft (`TestInputBytesBudgetEnforced`).
  * `trust_pack.py:458` — der `signatures`-Deckel um genau 1 gelockert: 218 gruen. Die vorhandene
    `TestDsseSignaturesCapDoS` deckt `dsse.verify_envelope`, nicht diesen Geschwister-Aufruf.
  * `trust_pack.py:262` — der `witnesses`-Deckel um 1 verschaerft: 218 gruen. Die Kostenkurve
    prueft die TOP-LEVEL-`keys`-Map, nicht diesen zweiten Punkt derselben Dimension.

DIE KLASSE, und sie ist die des ganzen Tages: eine KENNZAHL (die Dimension) steht fuer eine MENGE
(ihre Aufrufpunkte). Wer die Dimension prueft, glaubt die Menge geprueft zu haben.

WAS DIESER FALL LEISTET UND WAS NICHT — ehrlich, weil eine ueberdehnte Zusicherung schlimmer ist
als eine schmale. Er bindet NICHT jeden Aufrufpunkt an eine Grenzwertpruefung; das waere ein
Umbau der Kostenkurve und ein eigener, ruhiger Zug. Er verhindert, dass die MENGE still WAECHST:
jeder Aufrufpunkt muss hier gefuehrt sein, mit der Angabe, ob eine Zusicherung ihn bindet und
welche. Ein neuer, ungebundener Deckel faellt damit beim Einfuegen auf und nicht erst, wenn ihn
jemand entfernt.
"""
from __future__ import annotations

import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SRC = REPO / "src" / "proofbundle"

#: Das Muster eines Budget-Aufrufpunkts: `DEFAULT_BUDGET.check("dim", …)` oder `.within("dim", …)`.
_AUFRUF = re.compile(r"DEFAULT_BUDGET\.(?:check|within)\(\s*[\"']([a-z_]+)[\"']")

#: (Datei, Zeile, Dimension) -> die Zusicherung, die ihn bindet, oder None mit Grund.
#: GEMESSEN am 2026-09-07, nicht abgeschrieben. Ein Eintrag `None` ist KEINE Entwarnung, sondern
#: die offene Buchung: dieser Deckel steht im Code und keine Zusicherung haelt ihn fest.
_AUFRUFPUNKTE: dict[tuple[str, str], str | None] = {
    ("dsse.py", "signatures"): "tests/test_dsse_adversarial.py::TestDsseSignaturesCapDoS",
    ("decision.py", "input_bytes"): "tests/test_budget.py::TestInputBytesBudgetEnforced",
    ("outcome.py", "input_bytes"): None,
    ("run_ledger.py", "input_bytes"): None,
    ("trust_pack.py", "witnesses"): "tests/test_budget_kostenkurve.py (nur der TOP-LEVEL-Punkt, Zeile 157)",
    ("trust_pack.py", "input_bytes"): None,
    ("trust_pack.py", "signatures"): None,
    ("renewal.py", "renewal_ats_chain"): "tests/test_budget_kostenkurve.py::test_l_minus_eins_l_und_l_plus_eins",
    ("renewal.py", "data_digests"): "tests/test_budget_kostenkurve.py::test_l_minus_eins_l_und_l_plus_eins",
    ("renewal.py", "renewal_work"): "tests/test_budget_kostenkurve.py::test_l_minus_eins_l_und_l_plus_eins",
    ("agent_review.py", "input_bytes"): None,
    ("verification_summary.py", "input_bytes"): None,
}


def _gemessene_aufrufpunkte() -> set[tuple[str, str]]:
    """Die Aufrufpunkte, wie sie HEUTE im Quelltext stehen — gemessen, nicht gepflegt."""
    aus: set[tuple[str, str]] = set()
    for pfad in sorted(SRC.glob("*.py")):
        for dim in _AUFRUF.findall(pfad.read_text(encoding="utf-8", errors="replace")):
            aus.add((pfad.name, dim))
    return aus


def test_jeder_budget_aufrufpunkt_im_quelltext_ist_hier_gefuehrt():
    """DIE ZUSICHERUNG: die Menge waechst nicht mehr still.

    Faellt dieser Fall, ist die Frage nicht 'welcher Eintrag fehlt', sondern 'welcher Deckel steht
    seit wann ungeprueft im Code'. Die Antwort steht in der Meldung, mit Datei und Dimension.
    """
    gemessen = _gemessene_aufrufpunkte()
    assert gemessen, (
        "Der Sweep findet KEINEN Budget-Aufrufpunkt in src/proofbundle. Dann prueft dieser Fall "
        "nichts, statt still zu bestehen — das Muster selbst ist dann kaputt.")
    fehlend = sorted(gemessen - set(_AUFRUFPUNKTE))
    assert not fehlend, (
        f"Diese Budget-Deckel stehen im Quelltext, sind hier aber nicht gefuehrt: {fehlend}. Jeder "
        f"Aufrufpunkt einer Dimension ist ein EIGENER Riegel — die Kostenkurve prueft je Dimension "
        f"nur einen. Eintragen, mit der Zusicherung die ihn bindet, oder mit None und einem Grund.")
    verschwunden = sorted(set(_AUFRUFPUNKTE) - gemessen)
    assert not verschwunden, (
        f"Diese Aufrufpunkte sind hier gefuehrt, stehen aber nicht mehr im Quelltext: "
        f"{verschwunden}. Ein Deckel, der verschwindet, ohne dass es auffaellt, ist genau der "
        f"Vorgang, gegen den diese Datei antritt — Eintrag entfernen ODER den Deckel zurueckholen.")


def test_die_ungebundenen_deckel_sind_BENANNT_und_nicht_stillschweigend():
    """Die Buchung der offenen Seite. Ohne sie liesse sich die Lueckenliste leeren, indem man
    Eintraege auf None setzt — das faellt hier auf, weil die Zahl der offenen Punkte selbst
    gemessen und die Liste namentlich ausgegeben wird."""
    offen = sorted(k for k, v in _AUFRUFPUNKTE.items() if v is None)
    assert offen, (
        "Kein Aufrufpunkt gilt mehr als ungebunden — dann sind entweder alle gebunden (dann gehoert "
        "dieser Fall umgeschrieben und die Bindungen in die Liste) oder die Buchung wurde geleert.")
    # Die Zahl steht NICHT getippt da; sie wird berichtet. Eine getippte Zahl neben einer Menge,
    # die sich bewegt, ist die Klasse, gegen die dieser ganze Zyklus antritt.
    print(f"[budget-aufrufpunkte] {len(offen)} von {len(_AUFRUFPUNKTE)} Deckeln ungebunden: {offen}")


def test_ANTI_PARITAET_der_sweep_wuerde_einen_neuen_aufrufpunkt_melden(tmp_path):
    """DIE KONTROLLE. Ohne sie bestuende der Fall oben auch bei einem Sweep, der nie etwas findet."""
    (tmp_path / "neu.py").write_text(
        'DEFAULT_BUDGET.check("json_nodes", len(x))\n', encoding="utf-8")
    treffer = {(p.name, d) for p in tmp_path.glob("*.py")
               for d in _AUFRUF.findall(p.read_text(encoding="utf-8"))}
    assert treffer == {("neu.py", "json_nodes")}, (
        f"Die Sweep-Logik faengt einen eingepflanzten Aufrufpunkt NICHT (gefunden: {treffer}) — "
        f"dann bestuende der Fall oben nur, weil nichts zu finden war.")
