"""Die Zeitmarke der Registerform wird geprueft, und zwar mit dem VORHANDENEN Pruefer.

HERKUNFT, Codex r3999621598. `--generated-at x` endete mit 0, meldete gruen und schrieb `issued_at`,
`generated_at` und `assessment_cutoff` je als "x". Auch `2026-13-45T99:99:99Z` kam durch — Monat 13,
Tag 45, Stunde 99. Eine strukturell ungueltige Registerform wurde damit als erfolgreich geprueft
veroeffentlicht.

KEIN ZWEITER PRUEFER. `scripts/findings_register.py` traegt `_freshness_error` seit Langem: Form,
Zukunft und Alter in einer Funktion, mit dem stabilen Code REGISTER_STALE. Ihn nachzubauen waere ein
zweiter Erzeuger fuer dieselbe Frage. Diese Sitzung ist genau dieser Klasse schon einmal
aufgesessen, an der Werkzeugbindung; der Fehler steht im Vermerk der Karte OA-24e41ca200.

WAS DABEI MITGESCHLOSSEN WIRD, ohne dass es der Fund verlangt: die Zukunftspruefung faengt auch
einen Lauf, der sein eigenes Register vordatiert. Der Bewertungsgrenzen-Fund (r4000054881) ist damit
auf einer ZWEITEN Ebene geschlossen — einmal an der Grenze selbst, einmal an der Marke.
"""
from __future__ import annotations

import importlib.util
import pathlib

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]


def _gen():
    p = REPO / "scripts" / "gen_findings_register.py"
    if not p.is_file():
        pytest.skip(f"NICHT MESSBAR: {p} fehlt")
    s = importlib.util.spec_from_file_location("_gfr_zeit", p)
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m


def _zeitfehler(marke: str) -> list[str]:
    g = _gen()
    doc = g.baue_v2(REPO, marke)
    return [f for f in g.pruefe_v2(doc, REPO) if f.startswith("Zeitmarke")]


def test_eine_unlesbare_marke_wird_gemeldet():
    """[ZAEHLT] Der Fund selbst, mit dem Wert aus dem Bericht."""
    f = _zeitfehler("x")
    assert f, "eine Marke, die kein Zeitstempel ist, muss auffallen"
    assert "REGISTER_STALE" in f[0], f


def test_eine_syntaktisch_unmoegliche_marke_wird_gemeldet():
    """[ZAEHLT] Monat 13, Tag 45, Stunde 99 — die Form allein reicht nicht."""
    f = _zeitfehler("2026-13-45T99:99:99Z")
    assert f, "ein unmoegliches Kalenderdatum muss auffallen"


def test_eine_VORDATIERTE_marke_wird_gemeldet():
    """[ZAEHLT] Ein Lauf kann sein eigenes Register nicht vordatieren.

    Mitgeschlossen, ohne dass der Fund es verlangt: die zweite Ebene des Bewertungsgrenzen-Fundes.
    """
    f = _zeitfehler("2099-01-01T00:00:00Z")
    assert f, "eine Marke in der Zukunft muss auffallen"
    assert "future" in f[0].lower(), f


def test_eine_GUELTIGE_marke_wird_NICHT_gemeldet():
    """[ZAEHLT] Anti-Paritaet: der Riegel darf nicht alles melden."""
    import datetime  # noqa: PLC0415
    jetzt = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    assert _zeitfehler(jetzt) == [], f"eine gueltige Marke ({jetzt}) wurde gemeldet"


def test_der_pruefer_wird_IMPORTIERT_und_nicht_nachgebaut():
    """[ZAEHLT] Die Regel gegen den zweiten Erzeuger, am Code gemessen.

    Faellt dieser Fall, hat jemand die Frische-Regel hier nachgebaut — dann gibt es zwei Stellen
    fuer dieselbe Frage, und sie driften.
    """
    q = (REPO / "scripts" / "gen_findings_register.py").read_text(encoding="utf-8")
    assert "_freshness_error" in q, "der vorhandene Pruefer wird nicht mehr gerufen"
    assert "findings_register.py" in q, "die Quelle des Pruefers ist nicht genannt"
    for verraeter in ("REGISTER_STALE =", "_REGISTER_MAX_AGE_DAYS", "_REGISTER_FUTURE_SKEW"):
        assert verraeter not in q, f"{verraeter!r} steht hier — die Regel wurde nachgebaut"
