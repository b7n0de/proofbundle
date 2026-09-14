"""Der festgehaltene Ausgangsdigest wird GEGEN DIE DATEI gehalten, nicht neu abgeleitet.

DIE KLASSE, gemessen am 2026-09-12: ``RESTRISIKO_600_OBJEKTKLASSEN.json`` traegt unter
``gemessen_an.sha256`` den Digest des Ausgangsregisters — und kein Python im Baum hielt ihn je
dagegen. Ein `git grep -n 'gemessen_an' -- '*.py'` lieferte ausschliesslich
``tests/test_agent_review_conformance_runner.py``, wo derselbe Feldname etwas voellig anderes
bedeutet (eine Zeichenkette wie ``run_conformance.loese_kette``). Die zwei Tests, die
``RESTRISIKO_600.md`` wirklich lesen, vergleichen KENNUNGSMENGEN und keine Bytes.

GEMESSENE FOLGE: ein Wort im Fliesstext geaendert, keine Kennung beruehrt — der Digest wechselte
von ``38e56bf6…`` auf ``98a6820e…``, und die 14 Tests der beiden Populationsvergleiche blieben
gruen. Ein festgehaltener Sollwert ohne Vergleicher ist Dekoration.

WARUM DER SOLLWERT NICHT NEU ABGELEITET WERDEN DARF, und das ist die ganze Regel R10 der
Gegenlesung (``REVIEW_extern_registerform_61_20260911.md``, Abschnitt 6): „Gegen die
festgehaltenen Ausgangsdigests pruefen, NICHT gegen neu aus denselben geaenderten Dateien
erzeugte Sollwerte." Ein Sollwert, den man aus der geaenderten Datei neu berechnet, stimmt immer
— das ist der Selbstbezug, den dieselbe Gegenlesung unter S13 beschreibt. Dieser Test liest den
Sollwert deshalb aus der Objektklassen-Datei und NIE aus dem Register.

RICHTUNG DES URTEILS: eine Abweichung ist ein Fehler, kein Hinweis. Die Objektklassen-Datei sagt
in ihrem eigenen Kopf, sie sei ab ihrer Entstehung „die Quelle der Grundgesamtheit"; diese
Zusage haengt daran, dass ihr Bezugspunkt der ist, den sie nennt.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
OBJEKTKLASSEN = REPO / "RESTRISIKO_600_OBJEKTKLASSEN.json"
REGISTER = REPO / "RESTRISIKO_600.md"


def _festgehalten() -> str:
    if not OBJEKTKLASSEN.is_file():
        pytest.skip("RESTRISIKO_600_OBJEKTKLASSEN.json liegt hier nicht (sdist ohne Repo-Kontext)")
    d = json.loads(OBJEKTKLASSEN.read_text(encoding="utf-8"))
    soll = d.get("gemessen_an", {}).get("sha256")
    assert isinstance(soll, str) and len(soll) == 64, (
        "gemessen_an.sha256 fehlt oder ist kein sha256 — ohne festgehaltenen Sollwert misst "
        f"dieser Test nichts, und 'nichts gemessen' ist nie 'in Ordnung'. Gelesen: {soll!r}")
    return soll


def test_der_festgehaltene_ausgangsdigest_stimmt_mit_der_datei():
    """Die eine Frage, die bisher niemand stellte."""
    if not REGISTER.is_file():
        pytest.skip("RESTRISIKO_600.md liegt hier nicht (sdist ohne Repo-Kontext)")
    soll = _festgehalten()
    ist = hashlib.sha256(REGISTER.read_bytes()).hexdigest()
    assert ist == soll, (
        f"RESTRISIKO_600.md hat sich gegenueber dem festgehaltenen Ausgangsdigest geaendert.\n"
        f"  festgehalten in RESTRISIKO_600_OBJEKTKLASSEN.json::gemessen_an.sha256: {soll}\n"
        f"  tatsaechlich                                                        : {ist}\n"
        f"Entweder ist die Aenderung gewollt — dann gehoert der neue Digest IN DIE DATEI, "
        f"zusammen mit dem Grund —, oder sie ist es nicht. Beides ist eine Entscheidung; "
        f"stillschweigend weiterlaufen ist keine. Die Populationsvergleiche koennen das nicht "
        f"sehen: sie lesen Kennungen, keine Bytes.")


def test_der_sollwert_wird_nicht_aus_dem_register_abgeleitet():
    """Die Gegenrichtung, und sie ist der eigentliche Inhalt der Regel.

    Ein Test, der seinen Sollwert aus derselben Datei neu berechnet, ist immer gruen und misst
    nie etwas. Dieser hier haelt seinen Sollwert aus einer ANDEREN Datei — und dass er das tut,
    steht hier als eigener Fall, damit es niemand spaeter aus Bequemlichkeit umbaut.
    """
    quelle = Path(__file__).read_text(encoding="utf-8")
    kern = quelle.split('def test_der_sollwert_wird_nicht_aus_dem_register_abgeleitet')[0]
    assert "OBJEKTKLASSEN.read_text" in kern, "der Sollwert muss aus der Objektklassen-Datei kommen"
    assert "REGISTER.read_bytes" in kern, "verglichen wird gegen die Bytes des Registers"
    # Der Sollwert darf NIE aus dem Register selbst gebildet werden.
    assert "sha256(OBJEKTKLASSEN" not in kern
    assert kern.count("hashlib.sha256(REGISTER.read_bytes())") == 1, (
        "genau EINE Stelle bildet den Ist-Wert; mehrere waeren mehrere Zusagen")
