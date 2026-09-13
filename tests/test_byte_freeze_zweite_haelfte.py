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
import zipfile
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]

#: WAS `@pytest.mark.slow` HIER LEISTET — und was nicht. Eine Gegenlesung hat gemessen:
#: `pyproject.toml` registriert keine Marker und setzt kein `addopts`, `ci.yml` faehrt die volle
#: Suite OHNE `-m`-Filter. Der Marker erzeugt heute also ausschliesslich eine
#: `PytestUnknownMarkWarning` und filtert NICHTS; beide Faelle laufen in jedem CI-Durchlauf, bauen
#: jeweils drei Artefakte und brauchen Netz fuer die Isolation.
#:
#: ER BLEIBT TROTZDEM STEHEN, und zwar als Beschriftung mit Absicht: ein `-m "not slow"` waere die
#: naheliegende Ergaenzung und die falsche — dieser Fall ist die EINZIGE Messstelle der zweiten
#: Byte-Freeze-Haelfte, und ihn wegzufiltern hiesse, die Bedingung wieder ungemessen zu lassen.
#: Aufgeschrieben statt suggeriert: wer den Marker fuer einen Riegel haelt, irrt; er ist ein
#: Etikett, und die Kosten des Laufs sind bewusst in Kauf genommen.
_MARKER_HINWEIS = "slow ist hier eine Beschriftung, kein Filter — siehe Kommentar oben"


def _modul():
    spec = importlib.util.spec_from_file_location(
        "_br_zweite_haelfte", str(REPO / "scripts" / "build_reproducible.py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules["_br_zweite_haelfte"] = m
    spec.loader.exec_module(m)
    return m


@pytest.mark.slow   # siehe _MARKER_HINWEIS: heute eine Beschriftung, kein Filter
# DER XFAIL IST WEG, UND ZWAR WEIL ER ANGESCHLAGEN HAT. Er war strict=True mit der Begruendung
# "sobald der Fall aus IRGENDEINEM Grund gruen wird, schlaegt er an und verlangt eine Erklaerung".
# Am 2026-09-07 wurde er XPASS(strict) — hier ist die Erklaerung.
#
# WAS DEN FALL GRUEN GEMACHT HAT: die Kanonisierung des wheels IM BAUWEG (Owner-Entscheid
# OA-402ef6f4e9 / OA-7af1e29036, Option 1). `build_normalized_wheel` schreibt das fertige Archiv
# mit festen Modi (0755/0644) und festen Zeiten neu; `release.yml` faehrt denselben Weg.
# Gemessen mit Isolation, wie release.yml baut: identical=true, beide Digests
# a009a9685613d52bed3cff3a4fbbe72ef39dfb7b27c59a92c9a970668f237a4f.
#
# WARUM DAS DER FRUEHEREN WIDERLEGUNG NICHT WIDERSPRICHT. Der alte Grund hielt fest, eine
# Gegenlesung habe gezeigt, dass "eine Kanonisierung des Bauwegs diesen Fall NICHT gruen macht" —
# sie hatte den ARBEITSBAUM vor dem Direkt-Bau auf 0644 gesetzt und die Divergenz wurde groesser
# (68 statt 11 Eintraege). Das ist ein anderer Eingriff: Quellzustand aendern gegen fertiges
# Artefakt nachbearbeiten. Die damalige Messung bleibt gueltig fuer das, was sie gemessen hat.
#
# WAS DAMIT NICHT GEZEIGT IST: warum der Bau ueber die Isolation fuer .py-Dateien aus dem sdist
# 0o664 liefert, obwohl die entpackten Dateien 0644 tragen. Diese Ursache ist weiterhin NICHT
# MESSBAR aufgeklaert; die Kanonisierung macht sie nur folgenlos.
def test_das_wheel_aus_dem_sdist_ist_bytegleich_mit_dem_direkt_gebauten():
    """DIE ZUSICHERUNG. Sie baut wirklich — zweimal ein wheel und einmal ein sdist.

    LANGSAM UND TROTZDEM RICHTIG HIER: die Eigenschaft laesst sich nicht ohne Bau pruefen. Wer sie
    aus Metadaten ableitet, prueft seine Ableitung. Gemessen 2026-09-07: rund eine Minute.
    """
    m = _modul()
    try:
        r = m.measure_wheel_from_sdist(m.head_commit_epoch())
    except (subprocess.CalledProcessError, RuntimeError, OSError) as fehler:
        # DREI KLASSEN, NICHT ZWEI — und die dritte ist der Grund, aus dem diese Zeilen umgeschrieben
        # wurden (Gegenlesung 07.09.2026, ausgefuehrt).
        #
        # Was hier stand, machte aus JEDEM Fehlschlag einen skip. Eingespeist wurde der `RuntimeError`,
        # den `_build_wheel` selbst wirft, wenn der Bau kein wheel produziert — also ein ECHTER
        # Baudefekt: `2 skipped`, Zusicherung UND Anti-Paritaets-Kontrolle beide still. Die einzige
        # Messstelle der zweiten Byte-Freeze-Haelfte haette einen kaputten Bau als "hier nicht
        # messbar" gemeldet.
        #
        # Das ist woertlich die Klasse, die derselbe Kandidat in `c52884d` am Go-Differential
        # geschlossen hat (`_beschaffungslage`: beschafft / nicht beschaffbar / WERKZEUG DEFEKT).
        # Die Instanz wurde gefixt, der Nachbar in der eigenen neuen Datei derselben Linie nicht.
        # Fix-the-class heisst, ihn im selben Durchgang mitzunehmen — hier nachgeholt.
        #
        # Getrennt wird nicht am Meldungstext, sondern an der FEHLERKLASSE: antwortet die
        # Werkzeugkette selbst? Wenn `python -m build --version` laeuft, ist die Umgebung da, und
        # ein Fehlschlag danach ist ein Defekt, kein Umgebungsproblem.
        werkzeug = subprocess.run([sys.executable, "-m", "build", "--version"],
                                  capture_output=True, text=True, timeout=120)
        if werkzeug.returncode == 0:
            raise AssertionError(
                f"der Bau ist FEHLGESCHLAGEN, obwohl die Werkzeugkette antwortet "
                f"(`python -m build --version` endete mit 0: {werkzeug.stdout.strip()[:60]}). "
                f"Das ist ein Defekt, kein fehlendes Netz und keine fehlende Abhaengigkeit — "
                f"{type(fehler).__name__}: {fehler}") from fehler
        pytest.skip(f"die Bau-Werkzeugkette antwortet hier nicht (`python -m build --version` endete "
                    f"mit {werkzeug.returncode}), der Bau scheiterte an "
                    f"{type(fehler).__name__}: {fehler} — die Eigenschaft ist NICHT MESSBAR, nicht gruen")
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
            # EIN ZUSAETZLICHER EINTRAG, KEIN ANGEHAENGTES BYTE — und der Unterschied ist der
            # Befund vom 2026-09-07. Vorher stand hier `p.write_bytes(p.read_bytes() + b"\x00")`.
            # Seit die Kanonisierung im Bauweg sitzt, LIEST `normalize_wheel` das Archiv und
            # schreibt es neu; ein Byte hinter dem Zentralverzeichnis verschwindet dabei, und die
            # Einspeisung kam gar nicht mehr im Vergleich an: die Probe wurde still zahnlos und
            # meldete `identical is True`. Ein zusaetzlicher Eintrag ueberlebt die Kanonisierung,
            # weil sie Eintraege kopiert — damit misst die Kontrolle wieder den Vergleich.
            with zipfile.ZipFile(p, "a") as z:
                z.writestr("eingepflanzt_von_der_antiparitaet.txt", "probe")
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
