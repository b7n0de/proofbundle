"""Eine Schranke hat ZWEI Seiten, getestet ist bisher eine.

WARUM ES DIESE DATEI GIBT. Der kanonische Mutationslauf gegen den 6.0.0-Kandidaten meldete am
2026-09-07 acht Ueberlebende. Sieben davon waren abgedeckt und nur fuer den Sammler des Tors
unsichtbar. Der achte, `budget: data_digests-Schranke praktisch entfernt` (2_000 -> 2_000_000_000),
war etwas anderes: NICHT MESSBAR. Der mutierte Lauf faellt nicht durch einen Test, er sprengt den
Speicher — der Kernel beendete den Prozess nach 393 s statt der ueblichen 65 s.

WARUM IHN KEIN VORHANDENER TEST FAENGT, und beides ist gemessen:

1. `tests/test_budget.py::test_default_budget_is_generous` prueft ausschliesslich UNTERE Schranken
   (`assertGreater`, `assertGreaterEqual`). Eine Mutation, die ein Limit VERGROESSERT, macht es
   grosszuegiger — der Test wird gruener, nicht roter.
2. `tests/test_budget_kostenkurve.py` baut seine Last AM LIMIT (`_messung`: limit//8, //4, //2,
   limit). Bei einem Limit von zwei Milliarden versucht es, zwei Milliarden Eintraege zu bauen —
   es explodiert mit. Ein Lasttest kann eine gesprengte Schranke grundsaetzlich nicht fangen.

DESHALB EINE PINNUNG UND KEINE ERFUNDENE DECKE. Eine obere Schranke pro Dimension muesste sagen,
ab welchem Wert ein Limit keines mehr ist — und diese Zahl haette ich geraten. Die Kostenkurve ist
gegen GENAU DIE WERTE unten gemessen worden; wer einen davon aendert, muss neu messen. Der Test
sagt das in seiner Meldung, statt eine Grenze zu behaupten, die niemand gemessen hat.

EIN BUDGET, DAS ZU GROSSZUEGIG IST, IST KEIN BUDGET. Das ist die Klasse, und sie trifft alle zwoelf
Dimensionen, nicht nur die eine, die der Lauf zufaellig sichtbar gemacht hat.
"""
from __future__ import annotations

import dataclasses

import pytest

from proofbundle.budget import DEFAULT_BUDGET, VerificationBudget

#: Die Werte, gegen die tests/test_budget_kostenkurve.py gemessen wurde. Sie stehen hier als DATEN
#: und nicht als Formel: eine Formel, die den Wert aus der Quelle ableitet, waere mit der Quelle
#: mutierbar und pruefte nichts.
_GEPINNT: dict[str, int] = {
    "input_bytes": 8388608,
    "json_nodes": 200000,
    "json_depth": 64,
    "string_len": 1000000,
    "signatures": 512,
    "merkle_path": 256,
    "disclosures": 256,
    "renewal_ats_chain": 10000,
    "witnesses": 256,
    "int_bits": 8192,
    "data_digests": 2000,
    "renewal_work": 40000000,
}


def test_jede_dimension_ist_gepinnt():
    """ABGELEITET, nicht aufgezaehlt: die Menge kommt aus `VerificationBudget` selbst.

    Eine neue Dimension ohne Pin faellt hier auf, statt still ungeprueft zu bleiben — dieselbe Form
    wie `TestJedeDimensionIstAbgedeckt` in der Kostenkurve, und aus demselben Grund.
    """
    felder = {f.name for f in dataclasses.fields(VerificationBudget)}
    assert felder == set(_GEPINNT), (
        f"ohne Pin: {sorted(felder - set(_GEPINNT))} | "
        f"gepinnt, aber keine Budget-Dimension mehr: {sorted(set(_GEPINNT) - felder)}")


@pytest.mark.parametrize("name", sorted(_GEPINNT), ids=sorted(_GEPINNT))
def test_die_schranke_steht_wo_die_kostenkurve_sie_gemessen_hat(name):
    """DIE ZUSICHERUNG, und sie greift in BEIDE Richtungen — anders als
    `test_default_budget_is_generous`, das nur nach unten prueft."""
    ist = getattr(DEFAULT_BUDGET, name)
    soll = _GEPINNT[name]
    assert ist == soll, (
        f"budget.{name} steht auf {ist}, gepinnt ist {soll}.\n"
        f"Das ist KEIN Fehler, wenn die Aenderung gewollt ist — aber dann ist die Kostenkurve in "
        f"tests/test_budget_kostenkurve.py gegen einen anderen Wert gemessen worden, und die "
        f"Messung gilt nicht mehr. Neu messen, dann den Pin hier nachziehen.\n"
        f"WARUM ES DIESEN PIN GIBT: am 2026-09-07 liess sich budget.data_digests von 2000 auf "
        f"2000000000 setzen, ohne dass EIN Test rot wurde — der Lauf sprengte stattdessen den "
        f"Speicher und wurde vom Kernel beendet. Ein Limit, das nur nach unten geprueft wird, "
        f"laesst sich nach oben abschaffen.")


def test_ANTI_PARITAET_der_pin_faengt_eine_vergroesserte_schranke():
    """OHNE DIESEN FALL WAERE DIE ZUSICHERUNG OBEN WERTLOS.

    Sie besteht auch dann, wenn `_GEPINNT` aus derselben Quelle abgeleitet waere, die sie prueft —
    dann verglichen zwei Kopien desselben mutierten Werts und stimmten immer ueberein. Dieser Fall
    pflanzt genau die Mutation ein, die den Lauf beschaeftigt hat, und verlangt, dass die Logik
    sie faengt.
    """
    mutiert = dataclasses.replace(DEFAULT_BUDGET, data_digests=2_000_000_000)
    assert getattr(mutiert, "data_digests") != _GEPINNT["data_digests"], (
        "Die eingepflanzte Vergroesserung wird NICHT als Abweichung erkannt — dann ist `_GEPINNT` "
        "keine unabhaengige Quelle, sondern eine zweite Ansicht derselben Zahl, und der Test oben "
        "prueft nichts.")
    # Und die Gegenrichtung: der unveraenderte Wert wird NICHT als Abweichung gemeldet.
    assert DEFAULT_BUDGET.data_digests == _GEPINNT["data_digests"], (
        "Der unveraenderte Wert gilt bereits als Abweichung — dann waere der Test ein Dauerrot und "
        "sagte ueber eine echte Aenderung nichts mehr.")
