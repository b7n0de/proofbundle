"""Die Version hat EINE Quelle und fuenf Spiegel, und ein Test bewacht sie.

ANLASS, gemessen am 04.09.2026 beim Bau von 5.1.0.post1: die Zahl steht an SECHS Stellen. Fuenf
davon fanden wir, weil ein Werkzeug sie einforderte; die sechste
(`scripts/audit_candidate_matrix.py::VERSION_UNDER_TEST`) fand eine adversariale Gegenlesung, und
sie meldete ihre eigene Drift bereits korrekt — nur zwang das niemanden zum Nachziehen. Eine Zahl,
die an sechs Orten von Hand gepflegt wird, ist keine Quelle, sondern sechs Behauptungen.

WAS DIESER TEST IST UND WAS NICHT. Er macht `pyproject.toml` zur QUELLE und alles andere zum
Spiegel. Er kann NICHT verhindern, dass jemand eine siebte Stelle anlegt — dagegen hilft nur, dass
`bekannte_spiegel()` unten die Stellen NENNT und ein Befund den Dateinamen traegt, damit die
naechste Stelle beim ersten Fehlschlag sichtbar wird statt still zu driften.
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]

#: PEP 440, so weit dieses Projekt es fuehrt. Die Zahl nach einem Suffix ist PFLICHT — "5.1.0.post"
#: ohne sie ist keine Version, und ein Muster, das sie optional macht, winkt Tippfehler durch.
PEP440 = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:\.?(?:a|b|rc)[0-9]+)?(?:\.post[0-9]+)?(?:\.dev[0-9]+)?$")


def _lies(pfad: str, muster: str) -> tuple[str | None, str]:
    """(Wert, Grund). Kein Wert und KEIN Grund gibt es nicht — nicht messbar ist keine Freigabe."""
    p = REPO / pfad
    if not p.is_file():
        return None, f"{pfad} fehlt"
    m = re.search(muster, p.read_text(encoding="utf-8"))
    return (m.group(1), "") if m else (None, f"{pfad}: keine Versionszeile gefunden")


def quelle() -> str:
    v, grund = _lies("pyproject.toml", r'(?m)^\s*version\s*=\s*["\']([^"\']+)["\']')
    assert v, f"die QUELLE selbst ist nicht lesbar: {grund}"
    return v


def bekannte_spiegel() -> dict[str, tuple[str | None, str]]:
    """Jede Stelle, die dieselbe Zahl traegt. Wer eine anlegt, traegt sie HIER ein."""
    return {
        "src/proofbundle/__init__.py": _lies(
            "src/proofbundle/__init__.py", r'(?m)^\s*__version__\s*=\s*["\']([^"\']+)["\']'),
        "CITATION.cff": _lies("CITATION.cff", r'(?m)^\s*version\s*:\s*["\']?([^"\'\s]+)'),
    }


def test_die_quelle_ist_eine_gueltige_pep440_version():
    v = quelle()
    assert PEP440.match(v), f"pyproject.toml traegt {v!r}, das ist keine PEP-440-Version"


@pytest.mark.parametrize("pfad", sorted(bekannte_spiegel()))
def test_jeder_spiegel_zeigt_die_quelle(pfad):
    wert, grund = bekannte_spiegel()[pfad]
    assert wert is not None, grund
    assert wert == quelle(), (
        f"{pfad} traegt {wert!r}, die Quelle pyproject.toml sagt {quelle()!r} — "
        f"eine abweichende Heimat ist eine zweite Wahrheit ueber dieselbe Zahl")


def test_die_oberste_changelog_ueberschrift_nennt_die_quelle_oder_unreleased():
    """DIE AUSNAHME, und sie ist begruendet: ein Changelog fuehrt einen `[Unreleased]`-Block,
    solange die Fassung nicht heraus ist. Das ist Keep-a-Changelog-Konvention und KEINE Drift —
    wer das als Fehler meldet, zwingt zu einer Ankuendigung, die noch nicht stimmt."""
    txt = (REPO / "CHANGELOG.md").read_text(encoding="utf-8")
    m = re.search(r"(?m)^##\s*\[([^\]]+)\]", txt)
    assert m, "CHANGELOG.md hat keine Versions-Ueberschrift"
    kopf = m.group(1)
    assert kopf.lower() == "unreleased" or kopf == quelle(), (
        f"die oberste CHANGELOG-Ueberschrift sagt {kopf!r}, die Quelle {quelle()!r}")


def test_das_versions_tor_liest_dieselbe_zahl():
    sys.path.insert(0, str(REPO / "scripts"))
    import check_version_and_changelog as C          # noqa: PLC0415
    gelesen, woher = C._source_version(REPO)
    assert gelesen == quelle(), f"{woher} liest {gelesen!r}, die Quelle sagt {quelle()!r}"


def test_die_matrix_liest_dieselbe_zahl_statt_sie_zu_tippen():
    """DER SECHSTE SPIEGEL, und der Grund, warum dieser Test existiert. Er prueft NICHT nur den
    Wert: eine wieder fest geschriebene Konstante haette am Tag des Schreibens denselben Wert und
    driftete erst spaeter. Geprueft wird deshalb die BAUFORM — das Modul darf die Zahl nicht als
    Literal tragen."""
    quell = (REPO / "scripts" / "audit_candidate_matrix.py").read_text(encoding="utf-8")
    m = re.search(r"(?m)^VERSION_UNDER_TEST\s*=\s*(.+)$", quell)
    assert m, "VERSION_UNDER_TEST nicht gefunden — wurde die Konstante umbenannt?"
    zuweisung = m.group(1).strip()
    assert not re.match(r'^["\']', zuweisung), (
        f"VERSION_UNDER_TEST ist wieder ein Literal ({zuweisung}). Sie GEHOERT gelesen: eine feste "
        f"Zahl hat am Tag des Schreibens recht und driftet danach lautlos — genau so entstand der "
        f"Fund vom 04.09.2026.")
    sys.path.insert(0, str(REPO / "scripts"))
    import audit_candidate_matrix as M               # noqa: PLC0415
    assert M.VERSION_UNDER_TEST == quelle(), (
        f"die Matrix liest {M.VERSION_UNDER_TEST!r}, die Quelle sagt {quelle()!r}")


def test_die_matrix_meldet_drift_wenn_sie_eintritt():
    """DIE GEGENRICHTUNG. Ohne sie waere der Test darueber auch gruen, wenn der Drift-Melder
    ausgebaut waere — er prueft dann eine Gleichheit, die niemand mehr ueberwacht."""
    sys.path.insert(0, str(REPO / "scripts"))
    import audit_candidate_matrix as M               # noqa: PLC0415
    # Der Melder heisst `version_pin_binding(pinned)` — GEMESSEN, nicht geraten. Die erste Fassung
    # dieses Tests suchte `_version_pin`/`version_pin`, fand nichts und uebersprang sich selbst.
    # Ein Test, der sich bei Namensverfehlung still ueberspringt, meldet Gruen und prueft nichts.
    r = M.version_pin_binding(quelle())
    assert isinstance(r, dict) and "state" in r, f"der Melder liefert keinen Zustand: {r}"
    assert r["state"] != "drift", f"Quelle gegen sich selbst darf keine Drift sein: {r}"
    d = M.version_pin_binding("0.0.0")
    assert d["state"] == "drift", (
        f"eine ECHTE Abweichung muss Drift melden, sonst ordnet der Melder nichts: {d}")


# ── Das Versions-Tor gegen PEP 440, die vier Faelle aus dem Auftrag ─────────────────────────────
#
# Sie stehen als TEST hier und nicht in einer Erinnerung: was RELEASE.md und PROGRESS.md fuer eine
# Post-Release tragen muessen, legt diese Datei fest. Gefahren wird gegen eine KOPIE des Baums in
# tmp_path — das Repo selbst wird nie angefasst, sonst pruefte der Test seinen eigenen Nebeneffekt.

def _baum(tmp_path, version: str, doku_version: str) -> Path:
    z = tmp_path / "repo"
    (z / "docs" / "readiness_pack").mkdir(parents=True)
    (z / "src" / "proofbundle").mkdir(parents=True)
    (z / "pyproject.toml").write_text(f'[project]\nname = "proofbundle"\nversion = "{version}"\n',
                                      encoding="utf-8")
    (z / "src" / "proofbundle" / "__init__.py").write_text(f'__version__ = "{version}"\n',
                                                           encoding="utf-8")
    (z / "CITATION.cff").write_text(f"cff-version: 1.2.0\nversion: {version}\n", encoding="utf-8")
    (z / "RELEASE.md").write_text(f"the 5.x line (current: {doku_version}) and more\n",
                                  encoding="utf-8")
    (z / "docs" / "readiness_pack" / "PROGRESS.md").write_text(
        f"baseline (current release: {doku_version}) text\n", encoding="utf-8")
    (z / "CHANGELOG.md").write_text(f"# Changelog\n\n## [{version}] - 2026-09-04\n\n- x\n",
                                    encoding="utf-8")
    return z


def _tracked_probleme(zielbaum: Path) -> list[str]:
    sys.path.insert(0, str(REPO / "scripts"))
    import check_version_and_changelog as C          # noqa: PLC0415
    return C.check_tracked_places(zielbaum, C._source_version(zielbaum)[0])


@pytest.mark.parametrize("version,doku,erwartet_gruen,warum", [
    ("5.1.0.post1", "5.1.0.post1", True,
     "eine Post-Release, deren Dokumente sie nennen — genau der Fall, der vorher STRUKTURELL "
     "nicht bestehen konnte, weil das Muster nur 5.1.0 herauslas"),
    ("6.0.0", "6.0.0", True, "die gewoehnliche Freigabe bleibt gruen (Regression)"),
    ("5.1.0.post1", "5.1.0", False,
     "Dokumente auf der alten Zahl bei einer Post-Release — das IST Drift und muss rot sein"),
    ("2.0.0b1", "2.0.0b1", True,
     "eine Vorabversion, die RELEASE.md selbst dokumentiert — derselbe Fehlermodus, mitgeheilt"),
])
def test_das_tor_versteht_pep440(tmp_path, version, doku, erwartet_gruen, warum):
    probleme = _tracked_probleme(_baum(tmp_path, version, doku))
    if erwartet_gruen:
        assert not probleme, f"{warum}: {probleme}"
    else:
        assert probleme, f"{warum}: das Tor hat NICHTS gemeldet"


def test_eine_versionsform_ohne_zahl_nach_dem_suffix_ist_keine(tmp_path):
    """`5.1.0.post` OHNE Zahl. Das Muster darf sie NICHT als gueltige Version durchwinken — sonst
    haette ein Tippfehler dieselbe Wirkung wie eine echte Angabe."""
    assert not PEP440.match("5.1.0.post"), "5.1.0.post ohne Zahl gilt faelschlich als Version"
    assert not PEP440.match("5.1.0.postx"), "5.1.0.postx gilt faelschlich als Version"
    assert PEP440.match("5.1.0.post1"), "5.1.0.post1 muss gelten"
