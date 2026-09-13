"""Eine Achse gilt erst als bestanden, wenn JEDE ihrer Zusicherungen lief.

DER FUND, gemessen am 14.09.2026 und von der Codex-Runde eins an PR 199 gemeldet.
``scripts/budget_axis_measurement.py`` fuhr je Dimension GENAU EINE Zusicherung,
``test_kosten_am_limit_unter_der_obergrenze``, und schrieb deren Ergebnis als ``urteil`` der ACHSE
in den Beleg. Die Klasse ``TestObergrenzeAmGroesstenZugelassenenWert`` fuehrt aber FUENF, darunter
"die Last erreicht das Limit wirklich", das Verhalten bei L-1/L/L+1 und die Speichergrenze.

Der kleinste Fall, an dem das schiefgeht: ein Lastgenerator faellt auf eine winzige Eingabe
zurueck. Dann faellt "die Last erreicht das Limit wirklich" — und die CPU-Zusicherung bleibt
schnell und meldet BESTANDEN. Der Beleg haette ``ok: true`` fuer eine Budget-Suite ausgewiesen,
die rot ist. Dieselbe Auslassung stand in der Kombinationsschleife fuer "erreicht jede benannte
Dimension" und die Speichergrenze.

WAS HIER GEPRUEFT WIRD: die ZUSAMMENFASSUNG, nicht die Budgets selbst. Die Budget-Zusicherungen
haben ihren eigenen Vertrag in ``tests/test_budget_kostenkurve.py`` und messen echte Laufzeiten;
dieser Fall braucht dafuer keine Sekunde, weil er gegen eine Attrappe urteilt. Ein Vertrag ueber
eine Zusammenfassung, der die teuren Messungen mitfahren muss, wird nicht gefahren.
"""
from __future__ import annotations

import importlib.util
import pathlib

REPO = pathlib.Path(__file__).resolve().parents[1]
_SKRIPT = REPO / "scripts" / "budget_axis_measurement.py"
_spec = importlib.util.spec_from_file_location("budget_axis_measurement", _SKRIPT)
bam = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(bam)


class _Attrappe:
    """Zwei Zusicherungen je Dimension: eine haelt, eine reisst."""

    def test_kosten_am_limit_unter_der_obergrenze(self, dim):
        return None

    def test_die_last_erreicht_das_limit_wirklich(self, dim):
        raise AssertionError("die Last erreicht das Limit nicht")


class _AttrappeHeil:
    def test_kosten_am_limit_unter_der_obergrenze(self, dim):
        return None

    def test_die_last_erreicht_das_limit_wirklich(self, dim):
        return None


def test_die_zusicherungen_werden_abgeleitet_und_nicht_getippt():
    """Der Klassenfix: eine neue Zusicherung der Klasse zaehlt automatisch mit."""
    namen = bam.zusicherungen_je_fall(_Attrappe, 2)
    assert namen == ["test_die_last_erreicht_das_limit_wirklich",
                     "test_kosten_am_limit_unter_der_obergrenze"]


def test_am_ECHTEN_modul_sind_es_fuenf_und_nicht_eine():
    """Die Zahl, um die es geht, am wirklichen Testmodul statt an der Attrappe."""
    t = bam._testmodul()
    namen = bam.zusicherungen_je_fall(t.TestObergrenzeAmGroesstenZugelassenenWert, 2)
    assert "test_kosten_am_limit_unter_der_obergrenze" in namen
    assert "test_die_last_erreicht_das_limit_wirklich" in namen, (
        "genau diese fehlte im Urteil, und genau sie faengt einen zurueckgefallenen Lastgenerator")
    assert len(namen) >= 5, f"erwartet mindestens fuenf Zusicherungen, abgeleitet: {namen}"
    k = bam.zusicherungen_je_fall(t.TestKombinierteAchsen, 4)
    assert len(k) >= 3, f"die Kombinationsschleife fuehrt mehr als eine Zusicherung: {k}"


def test_eine_gerissene_zusicherung_faerbt_die_achse_auch_wenn_die_cpu_zusicherung_haelt():
    """DER RUECKNAHME-NACHWEIS. Vor dem Fix lief nur die CPU-Zusicherung, und die haelt hier."""
    urteil, meldung, einzeln = bam._alle_ausgaenge(_Attrappe(), bam.zusicherungen_je_fall(_Attrappe, 2),
                                                   (object(),))
    assert einzeln["test_kosten_am_limit_unter_der_obergrenze"] == "BESTANDEN", (
        "die Vorbedingung des Falls: die frueher allein gefahrene Zusicherung HAELT")
    assert urteil == "GERISSEN", f"die Achse gilt trotz gerissener Zusicherung als {urteil}"
    assert "test_die_last_erreicht_das_limit_wirklich" in meldung, (
        "die Meldung nennt nicht, WAS gerissen ist — dann sagt ein GERISSEN nichts")


def test_haelt_jede_zusicherung_gilt_die_achse():
    """Die Gegenrichtung, ohne die der Fix nur strenger waere statt richtiger."""
    urteil, meldung, einzeln = bam._alle_ausgaenge(
        _AttrappeHeil(), bam.zusicherungen_je_fall(_AttrappeHeil, 2), (object(),))
    assert urteil == "BESTANDEN" and meldung == ""
    assert set(einzeln.values()) == {"BESTANDEN"}


def test_das_einzelurteil_steht_im_beleg_und_nicht_nur_die_summe():
    """Ohne die Aufschluesselung ist das Urteil behauptet statt nachrechenbar."""
    _, _, einzeln = bam._alle_ausgaenge(_Attrappe(), bam.zusicherungen_je_fall(_Attrappe, 2), (object(),))
    assert len(einzeln) == 2 and set(einzeln) == set(bam.zusicherungen_je_fall(_Attrappe, 2))
