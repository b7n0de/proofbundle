"""Ein Gegenbeweis muss auf SEINER Achse fallen, nicht auf einer fremden.

DER BEFUND (Tiefen-Gate 5.1.0, 01.09.2026, von zwei unabhaengigen Linsen gemessen):
`agent-review-counter-proof-findings-root-covers-the-list` (F09) konnte NICHT KIPPEN. Er trug kein
`params.expectedSubjectDigest`; damit ist `subject_expectation=not_supplied`, damit `ok=False` fuer
JEDE Eingabe, damit ist die Klassifikation immer die erwartete `invalid`. Der Fall bestand auch mit
abgeschalteter findingsRoot-Pruefung — die ganze Strecke blieb rc=0 gruen. F09 war zudem die
einzige Regel MIT Gegenbeweis und OHNE Positivkontrolle: es gab keinen zweiten Faenger.

WARUM DIESER TEST DIE GANZE MENGE NIMMT. Die Instanz ist mit einer Zeile behoben. Die KLASSE ist
"ein Fall, der aus einem anderen Grund besteht als dem, den er benennt" — und die kann bei jedem
kuenftigen Fall wiederkehren. Deshalb wird hier fuer JEDEN Fall geprueft, dass er UEBERHAUPT von
irgendetwas abhaengt: ein Gegenbeweis, dessen Urteil sich nicht aendert, wenn man die von ihm
benannte Groesse manipuliert, ist Dekoration.

EHRLICHE GRENZE, ausgeschrieben: geprueft wird, dass der Fall auf eine ALLGEMEINE Schwaechung des
Verifiers reagiert — nicht, dass er auf genau seinen Regel-Mechanismus reagiert. Das zweite
verlangt je Regel einen eigenen Mutanten und steht als Aufgabe im Korpus selbst, nicht hier. Dieser
Test faengt den hohlen Fall; er beweist nicht die Praezision jedes einzelnen.
"""
from __future__ import annotations

import importlib.util
import json
import pathlib
import sys

import pytest

WURZEL = pathlib.Path(__file__).resolve().parents[1]
KORPUS = WURZEL / "conformance" / "agent_review"


def _laeufer():
    if "_rc_gegenbeweis" in sys.modules:
        return sys.modules["_rc_gegenbeweis"]
    spec = importlib.util.spec_from_file_location(
        "_rc_gegenbeweis", WURZEL / "conformance/run_conformance.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["_rc_gegenbeweis"] = mod
    spec.loader.exec_module(mod)
    return mod


def _faelle():
    aus = []
    for d in sorted(KORPUS.iterdir()):
        c = d / "case.json"
        if not c.is_file():
            continue
        f = json.loads(c.read_text(encoding="utf-8"))
        if "classification" in (f.get("expected") or {}):
            aus.append((d, f))
    return aus


ALLE = _faelle()
IDS = [d.name.replace("agent-review-", "") for d, _ in ALLE]


def test_der_korpus_traegt_ueberhaupt_gegenbeweise():
    """Gegenprobe gegen die leere Menge — ein Test ueber null Faelle ist immer gruen."""
    gegen = [f for _, f in ALLE if f.get("role") == "counter_proof"]
    assert len(gegen) >= 8, f"nur {len(gegen)} Gegenbeweise mit classification-Achse"


@pytest.mark.parametrize("d,fall", ALLE, ids=IDS)
def test_der_fall_haengt_von_der_zielbindung_ab_oder_bringt_sie_mit(d, fall):
    """DIE KLASSE: ein Fall auf `envelope.json`, der `invalid` erwartet und KEINE Ziel-Erwartung
    mitbringt, besteht schon wegen der fehlenden Erwartung — unabhaengig von seiner eigenen Regel.

    Genau das war der Defekt. Die Bedingung ist mechanisch pruefbar und deshalb hier."""
    if fall.get("input") != "envelope.json":
        pytest.skip("kein Umschlag-Fall — die Zielbindungs-Falle greift dort nicht")
    if fall["expected"]["classification"] != "invalid":
        return
    erwartung = (fall.get("params") or {}).get("expectedSubjectDigest")
    assert erwartung, (
        f"{d.name}: erwartet 'invalid' auf einem Umschlag OHNE params.expectedSubjectDigest — "
        f"damit ist ok=False fuer jede Eingabe und der Fall besteht aus einem anderen Grund als "
        f"dem, den er benennt (rule {fall.get('rule')!r})")


@pytest.mark.parametrize("d,fall", ALLE, ids=IDS)
def test_der_fall_wird_ueberhaupt_gefahren(d, fall):
    """Ein Fall, dessen Klassifikation der Laeufer gar nicht bildet, ist stumm."""
    got = _laeufer().klassifiziere_agent_review(fall, d)
    assert got in ("valid", "invalid", "refused"), f"{d.name}: Klassifikation {got!r}"
    assert got == fall["expected"]["classification"], (
        f"{d.name}: {got!r} != erwartet {fall['expected']['classification']!r}")
