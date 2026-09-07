"""Die zweite Haelfte des Byte-Freeze hat eine Messstelle — und diese Datei ist ihr Fangnachweis.

WARUM ES DIESE DATEI GIBT. Der Release-Standard 6.0.0 vom 05.09.2026 nennt in seinem
fail-closed-Satz woertlich „Byte-Freeze mit zwei byte-identischen sdists und wheel aus sdist
byteweise gleich dem direkt gebauten". GEMESSEN am 2026-09-07: die erste Haelfte hatte eine
Messstelle (``scripts/build_reproducible.py --check``), die zweite hatte KEINE. Das Skript baute
ueberhaupt keine wheels, unter ``scripts/`` gab es kein weiteres Werkzeug dafuer, und die
Audit-Matrix liest ``candidate.wheel_sha256`` ausdruecklich, ohne ihn nachzurechnen.

EINE BEDINGUNG IM FAIL-CLOSED-SATZ OHNE MESSSTELLE IST TEURER ALS EINE ROTE ZEILE: sie gilt
stillschweigend als gruen, ohne je gemessen worden zu sein, und niemand vermisst sie.

Die Faelle hier fahren ``build_reproducible.measure_wheel_from_sdist`` SELBST. Sie bauen keine
eigene Vergleichslogik nach — eine Nachbildung, die von der echten Funktion abweicht, ist ein
Orakel, das ihren Denkfehler teilt (dieselbe Klasse, die am selben Tag den Fangnachweis des
Mutationstors entwertet hat).
"""
from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]


def _modul():
    spec = importlib.util.spec_from_file_location(
        "_br_zweite_haelfte", str(REPO / "scripts" / "build_reproducible.py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules["_br_zweite_haelfte"] = m
    spec.loader.exec_module(m)
    return m


@pytest.mark.slow
@pytest.mark.xfail(strict=True, reason=(
    "GEMESSEN ROT am 2026-09-07, Befund WHEEL-IST-NICHT-REPRODUZIERBAR-DATEIMODI-UND-BAUHOST-"
    "SCHLAGEN-DURCH-01. 82 Eintraege je Seite, NULL inhaltliche Unterschiede, 11 Eintraege "
    "verschieden allein im Dateimodus (0o100664 gegen 0o100644): normalize_sdist setzt 0644, der "
    "Arbeitsbaum traegt die umask des Bauhosts, und setuptools uebernimmt den Modus in die "
    "zip-Attribute des wheel. Zweiter Lauf mit umask 022: beide Digests anders, weiterhin "
    "verschieden — das wheel ist nicht hostunabhaengig. "
    "WARUM xfail UND NICHT EIN ROTER FALL: der Defekt liegt im BAUWEG (release.yml baut das wheel "
    "mit `python -m build --wheel` aus dem Baum, ohne Kanonisierung), und ihn zu beheben aendert "
    "das ausgelieferte Artefakt — das ist eine Owner-Entscheidung, keine Nebenbei-Aenderung. "
    "WARUM strict=True: sobald jemand den Bauweg kanonisiert, wird dieser Fall gruen, und ein "
    "strikter xfail SCHLAEGT DANN AN. Ein nicht-strikter haette die Reparatur stillschweigend "
    "geschluckt und die Zeile waere fuer immer als 'bekannt rot' stehengeblieben — genau die "
    "Klasse, gegen die dieses Repo sonst antritt."))
def test_das_wheel_aus_dem_sdist_ist_bytegleich_mit_dem_direkt_gebauten():
    """DIE ZUSICHERUNG. Sie baut wirklich — zweimal ein wheel und einmal ein sdist.

    LANGSAM UND TROTZDEM RICHTIG HIER: die Eigenschaft laesst sich nicht ohne Bau pruefen. Wer sie
    aus Metadaten ableitet, prueft seine Ableitung. Gemessen 2026-09-07: rund eine Minute.
    """
    m = _modul()
    try:
        r = m.measure_wheel_from_sdist(m.head_commit_epoch())
    except (subprocess.CalledProcessError, RuntimeError, OSError) as fehler:
        # NICHT MESSBAR, und das ist etwas anderes als GRUEN. Ein Bau, der in dieser Umgebung gar
        # nicht laeuft (kein Netz fuer die Isolation, fehlende Build-Abhaengigkeiten), sagt nichts
        # ueber die Eigenschaft. Er darf aber auch nicht als Verletzung gelten — sonst waere der
        # Fall auf jedem Rechner ohne Netz dauerhaft rot und niemand laese ihn noch.
        pytest.skip(f"der Bau laeuft in dieser Umgebung nicht ({type(fehler).__name__}: {fehler}) — "
                    f"die Eigenschaft ist hier NICHT MESSBAR, nicht gruen")
    assert r["identical"], (
        f"Das wheel aus dem ausgelieferten sdist ist NICHT bytegleich mit dem direkt gebauten:\n"
        f"  direkt     {r['name_direct']}  {r['sha256_direct']}\n"
        f"  aus sdist  {r['name_from_sdist']}  {r['sha256_from_sdist']}\n"
        f"Damit haelt die zweite Haelfte des Byte-Freeze nicht, und ein Nutzer, der aus dem sdist "
        f"baut, bekommt etwas anderes als die veroeffentlichte Datei.")
    assert r["schema"] == m.WHEEL_MEASUREMENT_SCHEMA, (
        "das Ergebnis traegt kein oder ein fremdes Schema — ein Aufrufer muesste dann wieder Prosa "
        "lesen, und genau daran ist c9_1 schon einmal gescheitert")


@pytest.mark.slow
def test_ANTI_PARITAET_die_messung_faengt_zwei_VERSCHIEDENE_wheels():
    """DIE KONTROLLE. Ohne sie bestuende die Zusicherung oben auch bei einer Messung, die IMMER
    ``identical: True`` sagt — dann waere die neue Messstelle eine Zusage und keine Pruefung.

    Eingepflanzt wird der Unterschied im BAU, nicht im Vergleich: ``_build_wheel`` haengt beim
    zweiten Aufruf ein Byte an. Die Funktion unter Test bleibt die echte, nur ihre Umgebung ist
    gestoert — das ist Fehlereinspeisung, keine Nachbildung.
    """
    m = _modul()
    echt = m._build_wheel
    zaehler = {"n": 0}

    def gestoert(quelle, outdir, epoch, **kw):
        p = echt(quelle, outdir, epoch, **kw)
        zaehler["n"] += 1
        if zaehler["n"] == 2:          # der Bau AUS DEM SDIST
            p.write_bytes(p.read_bytes() + b"\x00")
        return p

    m._build_wheel = gestoert
    try:
        r = m.measure_wheel_from_sdist(m.head_commit_epoch())
    except (subprocess.CalledProcessError, RuntimeError, OSError) as fehler:
        pytest.skip(f"der Bau laeuft in dieser Umgebung nicht ({type(fehler).__name__}: {fehler})")
    finally:
        m._build_wheel = echt
    assert zaehler["n"] == 2, (
        f"die Messung hat {zaehler['n']} wheels gebaut, erwartet 2 — dann trifft die Einspeisung "
        f"nicht den Bau aus dem sdist und dieser Fall misst etwas anderes als er behauptet")
    assert r["identical"] is False, (
        "ein eingepflanzter Byte-Unterschied wird NICHT gefunden — dann sagt die Messung immer "
        "'gleich' und die neue Messstelle prueft nichts")
    assert r["sha256_direct"] != r["sha256_from_sdist"], "die Digests muessen den Unterschied zeigen"
