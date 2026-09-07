"""Der Formpruefer ueber Release-Notiz und Tag-Text — und der Nachweis, dass es EINE Regelmenge ist.

WARUM ES DIESE DATEI GIBT. Der Release-Standard 6.0.0 verlangt einen „Formpruefer und
Benennungs-Gate ueber Release-Notiz und Tag-Text". GEMESSEN am 2026-09-07 gab es keinen: die
Anspruchshygiene scannte 49 Dokumente, und `release.yml` erzeugt den Release-Text mit
``generate_release_notes: true`` — GitHub komponiert ihn aus PR-Titeln, er ist keine Datei im Baum
und stand in keiner Scanmenge. Der Text, den ein Fremder als ERSTES liest, ging ungeprueft nach
draussen, waehrend jede README-Zeile durch vierzig verbotene Wendungen muss.

DER GEFAEHRLICHSTE FEHLER BEIM SCHLIESSEN DIESER LUECKE waere ein ZWEITER Pruefer mit eigener
Musterliste. Zwei Listen driften auseinander, und dann verbietet die eine Flaeche, was die andere
schreibt. `test_er_nutzt_DIESELBE_regelmenge_wie_die_docs` misst genau das — nicht am Quelltext,
sondern am Verhalten.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]


def _laden(name: str):
    spec = importlib.util.spec_from_file_location(f"_rth_{name}", str(REPO / "scripts" / f"{name}.py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules[f"_rth_{name}"] = m
    spec.loader.exec_module(m)
    return m


_UEBERANSPRUCH = "Release v6.0.0 — this build is production-ready and has been externally audited."
_SAUBER = "Release v6.0.0 — receipts bind authorship and integrity, never truth."


def test_der_formpruefer_faengt_einen_ueberanspruch_im_release_text():
    """DIE ZUSICHERUNG. Ein Release-Text mit einem verbotenen Anspruch faellt."""
    m = _laden("release_text_hygiene")
    v = m.chc.scan_text(_UEBERANSPRUCH, "release-notes")
    assert v, ("Ein Release-Text mit 'production-ready' und 'has been externally audited' passiert "
               "den Formpruefer. Genau diese zwei Wendungen verbietet der Baum in jedem anderen "
               "Text — der Release-Text darf keine Ausnahme sein.")
    phrasen = " ".join(x["phrase"] for x in v)
    assert "production-ready" in phrasen and "audited" in phrasen, (
        f"Der Fund nennt nicht die erwarteten Wendungen: {phrasen}")


def test_ANTI_PARITAET_ein_sauberer_release_text_besteht():
    """DIE KONTROLLE. Ohne sie bestuende die Zusicherung oben auch bei einem Pruefer, der JEDEN Text
    ablehnt — dann waere kein Release-Text mehr moeglich und niemand wuerde ihn benutzen."""
    m = _laden("release_text_hygiene")
    assert m.chc.scan_text(_SAUBER, "release-notes") == [], (
        "Ein sauberer Release-Text wird abgelehnt — ein Pruefer, der alles faengt, faengt nichts.")


def test_er_nutzt_DIESELBE_regelmenge_wie_die_docs(monkeypatch):
    """DER EIGENTLICHE FALL: eine Regelmenge, zwei Eingaenge — gemessen am VERHALTEN.

    Ein Vergleich der Quelltexte wuerde nur zeigen, dass heute niemand eine zweite Liste getippt
    hat. Gemessen wird stattdessen, ob eine Aenderung an der EINEN Liste beim Release-Pruefer
    ankommt: ein frisch eingehaengtes Muster muss dort sofort greifen. Tut es das nicht, gibt es
    zwei Zustaende, und der zweite driftet.
    """
    import re
    m = _laden("release_text_hygiene")
    text = "Dieser Build ist voellig grossartig."
    assert m.chc.scan_text(text, "x") == [], "Vorbedingung: der Satz ist heute sauber"
    monkeypatch.setattr(m.chc, "_FORBIDDEN_RE",
                        list(m.chc._FORBIDDEN_RE) + [(re.compile(r"voellig grossartig"), "Probe")])
    v = m.chc.scan_text(text, "x")
    assert v and v[0]["phrase"] == "Probe", (
        "Ein Muster, das der Dokument-Pruefung hinzugefuegt wird, greift beim Release-Text NICHT. "
        "Dann tragen die beiden Flaechen verschiedene Regeln, und genau das sollte dieses Werkzeug "
        "verhindern.")


def test_ein_leerer_text_besteht_NICHT():
    """LEER IST KEIN BESTEHEN. Ein Formpruefer, der ueber einen leeren Text 'PASS' meldet, ist die
    leer-wahre Zusicherung — er bestuende auch dann, wenn der Text nie ankaeme."""
    m = _laden("release_text_hygiene")
    leerer_eingang = type("S", (), {"read": staticmethod(lambda: "   \n")})()
    alt = sys.stdin
    sys.stdin = leerer_eingang
    try:
        with pytest.raises(SystemExit) as exc:
            m.main(["--stdin", "--label", "leer"])
    finally:
        sys.stdin = alt
    assert "leer" in str(exc.value), f"der Abbruch nennt seinen Grund nicht: {exc.value!r}"


def test_ein_leerer_commitbereich_bricht_ab():
    """Dieselbe Klasse an der zweiten Eingangsform: `--since-tag HEAD` umfasst null Commits. Ein
    Pruefer ueber null Commits besteht immer und sagt nichts."""
    m = _laden("release_text_hygiene")
    with pytest.raises(SystemExit) as exc:
        m.betreffs_seit("HEAD")
    assert "kein Commit" in str(exc.value), f"der Abbruch nennt seinen Grund nicht: {exc.value!r}"
