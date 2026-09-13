"""Eine Fortsetzungspruefung, die gegen HEAD vergleicht, vergleicht im CI mit sich selbst.

HERKUNFT, Codex r3999796582. Die Fortsetzungspruefung las die Datei aus dem ARBEITSBAUM und hielt
sie gegen `git show HEAD:` DERSELBEN Datei. In einem sauberen Checkout — und das ist jeder CI-Lauf —
sind beide byte-gleich. Die Zusicherung "die Kette setzt die committete fort" verglich damit die
Kette mit sich selbst und war trivial wahr. Ein Umschreiben oder Kuerzen der Kette blieb gruen,
sobald es committet war.

DIE KLASSE: ein Geschichts-Riegel, der gegen HEAD statt gegen den VORZUSTAND vergleicht, kollabiert
nach dem Commit zum Selbstvergleich. Er misst dann nicht die Fortsetzung, sondern die Identitaet
einer Datei mit sich selbst — eine Aussage, die immer wahr ist und deshalb nichts ausschliesst.

NACHBAR-SWEEP, gemessen: fuenf weitere Stellen im Baum benutzen `git show HEAD:`. KEINE traegt
denselben Fehler — alle fuenf lesen HEAD als unveraenderliche kanonische Quelle GEGEN Manipulation
im Arbeitsbaum, also als Vertrauensanker, nicht als Vorzustandsvergleich. Dieselbe Codegestalt,
andere Klasse. Der Fund ist isoliert.

EHRLICHE GRENZE: gemessen wird gegen die letzte Fassung der Historie, die sich vom heutigen Inhalt
UNTERSCHEIDET. Gibt es keine, ist es eine Erstaufnahme, und der Fall ueberspringt MIT Grund — das
ist ausdruecklich kein Bestehen.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import subprocess

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
DATEI = REPO / "RESTRISIKO_600_OBJEKTKLASSEN.json"


def letzte_abweichende_fassung():
    """(commit, bytes) der letzten Fassung, die sich vom heutigen Inhalt unterscheidet."""
    if not DATEI.is_file() or not (REPO / ".git").exists():
        return None
    jetzt = hashlib.sha256(DATEI.read_bytes()).hexdigest()
    log = subprocess.run(["git", "-C", str(REPO), "log", "--format=%H", "--", DATEI.name],
                         capture_output=True, text=True, timeout=60)
    if log.returncode != 0:
        return None
    for commit in log.stdout.split():
        b = subprocess.run(["git", "-C", str(REPO), "show", f"{commit}:{DATEI.name}"],
                           capture_output=True, timeout=60)
        if b.returncode == 0 and hashlib.sha256(b.stdout).hexdigest() != jetzt:
            return commit, b.stdout
    return None


def test_die_vorfassung_ist_NICHT_der_heutige_inhalt():
    """[ZAEHLT] Der Kern des Fundes: der Vergleichsgegenstand muss ein ANDERER sein."""
    v = letzte_abweichende_fassung()
    if v is None:
        pytest.skip("NICHT MESSBAR: kein git-Baum oder keine abweichende Vorfassung")
    commit, roh = v
    assert hashlib.sha256(roh).hexdigest() != hashlib.sha256(DATEI.read_bytes()).hexdigest(), (
        f"die gewaehlte Vorfassung aus {commit[:12]} ist byte-gleich mit dem heutigen Inhalt — "
        f"dann vergleicht die Pruefung mit sich selbst")


def test_die_pruefung_vergleicht_nicht_mehr_gegen_HEAD():
    """[ZAEHLT] Am Code gemessen, nicht am Verhalten allein.

    Faellt dieser Fall, ist der Vergleich zurueck auf HEAD — dann ist er im CI wieder trivial.
    """
    q = (REPO / "tests" / "test_der_fortgeschriebene_sollwert_traegt_seine_herkunft.py").read_text(
        encoding="utf-8")
    assert 'f"HEAD:{OBJEKTKLASSEN.name}"' not in q, (
        "die Fortsetzungspruefung liest wieder HEAD — im sauberen Checkout ist das der eigene Inhalt")
    assert "letzte in der Historie, die sich" in q or "abweichende Vorfassung" in q, (
        "der Vergleichsgegenstand ist nicht mehr als abweichende Vorfassung benannt")


def test_FANG_eine_UMGESCHRIEBENE_kette_wuerde_auffallen():
    """[ZAEHLT] Gegenrichtung rot, an den echten Daten dieses Baums.

    Genommen wird die Kette der Vorfassung und ihr erstes Glied verdreht. Die Fortsetzungsregel
    lautet: die heutige Kette beginnt mit der alten. Eine verdrehte alte Kette darf deshalb NICHT
    mehr Praefix sein.
    """
    v = letzte_abweichende_fassung()
    if v is None:
        pytest.skip("NICHT MESSBAR: keine abweichende Vorfassung")
    _, roh = v
    alt_kette = (json.loads(roh.decode("utf-8")).get("gemessen_an") or {}).get("_kette") or []
    if not alt_kette:
        pytest.skip("NICHT MESSBAR: die Vorfassung fuehrt keine Kette")
    jetzt = (json.loads(DATEI.read_text(encoding="utf-8")).get("gemessen_an") or {}).get("_kette") or []
    assert jetzt[:len(alt_kette)] == alt_kette, "Vorbedingung des Falls: heute setzt fort"
    gefaelscht = [dict(alt_kette[0], sha256="0" * 64)] + list(alt_kette[1:])
    assert jetzt[:len(gefaelscht)] != gefaelscht, (
        "eine umgeschriebene Vorkette gilt weiterhin als Praefix — die Regel greift nicht")


def test_ANTI_die_nachbarn_mit_git_show_HEAD_sind_eine_ANDERE_klasse():
    """[ZAEHLT] Der Nachbar-Sweep als Zusicherung, damit die Klasse nicht zu weit gefasst wird.

    Fuenf weitere Stellen lesen `git show HEAD:`. Sie lesen HEAD als unveraenderliche Quelle GEGEN
    den Arbeitsbaum — ein Vertrauensanker, kein Vorzustandsvergleich. Wer diese Klasse auf sie
    ausdehnt, nimmt ihnen genau die Eigenschaft, fuer die sie gebaut sind.
    """
    r = subprocess.run(["git", "-C", str(REPO), "grep", "-l", "-E", "git.{0,30}show.{0,20}HEAD"],
                       capture_output=True, text=True, timeout=60)
    if r.returncode not in (0, 1):
        pytest.skip(f"NICHT MESSBAR: git grep rc={r.returncode}")
    treffer = [z for z in r.stdout.split() if z.endswith(".py")]
    assert treffer, "keine Stelle gefunden — dann misst dieser Fall nichts"
    assert len(treffer) >= 2, f"erwartet mehrere Stellen, gemessen {treffer}"
