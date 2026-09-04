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

import re
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


# ── `_semver_tuple`, gegen ein UNABHAENGIGES Orakel ────────────────────────────────────────────
#
# DER GRUND, WARUM ES DIESEN BLOCK GIBT, ist ein Befund gegen meine eigene Erfolgsmeldung. Eine
# Gegenlese-Linse hat am 04.09.2026 gemessen: pflanzt man die ALTE Drei-Tupel-Fassung zurueck,
# werden NULL Tests rot. Die ganze Ordnungslogik war ungeprueft — der Mutant, den ich gefahren
# hatte, traf nur das Muster `_SEMVER`, nie diese Funktion. Ein gruener Test ueber der einen
# Haelfte sagt nichts ueber die andere.
#
# DAS ORAKEL IST UNABHAENGIG. Verglichen wird gegen `packaging.version.Version`, also gegen die
# Bibliothek, die PEP 440 definiert — nicht gegen eine zweite Ableitung derselben Annahme. Fehlt
# sie, wird das GESAGT statt uebersprungen: ein stiller skip ist genau die Bauform, die diese
# Datei an anderer Stelle schon einmal entwertet hat.

#: Die Reihenfolge ist ABSICHTLICH gemischt — sortiert eingegeben wuerde ein kaputter Schluessel,
#: der alles gleich bewertet, die Eingabereihenfolge behalten und der Vergleich bestuende.
ORDNUNGSKORPUS = [
    "2.0.0", "1.0.0a2", "1.0.0.post1", "1.0.0rc1", "5.1.0.post1", "1.0.0.dev1", "1.1.0",
    "1.0.0b1", "1.0.0", "2.0.0b1", "1.0.1", "1.0.0a1", "5.1.0", "2.0.0a3", "1.0.0b2",
    "1.0.0.post2", "6.0.0", "5.2.0",
]


def _tuple():
    sys.path.insert(0, str(REPO / "scripts"))
    import check_version_and_changelog as C          # noqa: PLC0415
    return C._semver_tuple


def test_dieser_lauf_misst_diesen_baum():
    """DER RIEGEL SELBST, als eigene Zusicherung. Ohne sie greift er nur dort, wo zufaellig eine
    andere Zusicherung `_matrix()` aufruft — und ein Riegel, dessen Wirkung an der Reihenfolge
    fremder Tests haengt, ist keiner."""
    _pruefe_richtiger_baum()


def test_die_ordnung_stimmt_mit_packaging_ueberein():
    packaging = pytest.importorskip(
        "packaging.version",
        reason="packaging fehlt — die Ordnung ist damit NICHT gemessen, nicht 'in Ordnung'")
    meine = sorted(ORDNUNGSKORPUS, key=_tuple())
    orakel = sorted(ORDNUNGSKORPUS, key=packaging.Version)
    assert meine == orakel, (
        "die Ordnung weicht vom PEP-440-Orakel ab:\n"
        + "\n".join(f"  {a:14s} <-> {b}" for a, b in zip(meine, orakel) if a != b))


@pytest.mark.parametrize("kleiner,groesser,warum", [
    ("1.0.0.dev1", "1.0.0a1", "eine Entwicklungsfassung liegt vor jeder Vorabversion"),
    ("1.0.0a2", "1.0.0b1", "JEDE Alpha liegt vor JEDER Beta — die Nummer entscheidet erst danach"),
    ("1.0.0b2", "1.0.0rc1", "jede Beta vor jedem Release Candidate"),
    ("1.0.0rc1", "1.0.0", "die Vorabversion vor der Freigabe"),
    ("1.0.0", "1.0.0.post1", "die Freigabe vor ihrer Nachbesserung"),
    ("1.0.0.post1", "1.0.0.post2", "und die Nachbesserungen untereinander"),
    ("5.1.0", "5.1.0.post1", "der Fall, der das Tor ueberhaupt ausgeloest hat"),
])
def test_jede_einzelne_stufe_der_ordnung(kleiner, groesser, warum):
    """EINZELN, nicht nur als Sortierung. Eine Sortierung, die an einer Stelle kippt, kann durch
    eine zweite Verdrehung wieder richtig aussehen; diese Paare koennen das nicht."""
    f = _tuple()
    assert f(kleiner) < f(groesser), f"{warum}: {f(kleiner)} nicht < {f(groesser)}"


def test_zwei_vorabphasen_sind_nicht_dieselbe():
    """Der gemessene Fund: b1 und rc1 lieferten IDENTISCHE Schluessel."""
    f = _tuple()
    assert f("1.0.0b1") != f("1.0.0rc1"), "b1 und rc1 sind nicht unterscheidbar"
    assert f("1.0.0a1") != f("1.0.0b1"), "a1 und b1 sind nicht unterscheidbar"


def test_ein_zweites_suffix_geht_nicht_verloren():
    """Der zweite gemessene Fund: `5.1.0.post1.dev2` ergab dasselbe wie `5.1.0.post1`."""
    f = _tuple()
    assert f("5.1.0.post1.dev2") != f("5.1.0.post1"), "die Entwicklungsfassung verschwindet"
    assert f("5.1.0.post1.dev2") < f("5.1.0.post1"), "und sie liegt DAVOR, nicht irgendwo"


def test_was_keine_version_ist_bleibt_vergleichbar():
    """GEGENRICHTUNG zum Fallback. Ein Review-Tag ist keine Version; er muss trotzdem ohne Absturz
    gegen eine echte vergleichbar bleiben, sonst bricht Check 3 an einem fremden Tag."""
    f = _tuple()
    t = f("corpus-review-2026-07-25-iter10")
    assert len(t) == len(f("5.1.0")), "Fallback und Treffer haben verschiedene Laengen"
    assert t < f("5.1.0"), "ein Nicht-Versions-Tag darf keine echte Version ueberholen"


def test_das_muster_frisst_den_eigenen_markennamen_nicht():
    """`5.1.0b7n0de.com` — ohne Wortgrenze las das Muster daraus "5.1.0b7", hielt also den Anfang
    unseres eigenen Markennamens fuer eine Beta-Nummer. Eine halbe Version ist schlimmer als
    keine: sie sieht aus wie eine Messung."""
    sys.path.insert(0, str(REPO / "scripts"))
    import check_version_and_changelog as C          # noqa: PLC0415
    assert re.findall(C._SEMVER, "proofbundle 5.1.0b7n0de.com") == [], "der Markenname wird gefressen"
    assert re.findall(C._SEMVER, "(current: 5.1.0) and more") == ["5.1.0"], "die Regel ist zu eng"
    assert re.findall(C._SEMVER, "current: 5.1.0.post1") == ["5.1.0.post1"], "post faellt durch"


# ── Die SIEBTE Stelle: der Schluessel in release_evidence_slots ────────────────────────────────
#
# Sie stand nicht in `bekannte_spiegel()`, weil sie kein Spiegel IST — sie ist ein Nachschlag-
# Schluessel in einer handgepflegten Tabelle. Eine Gegenlese-Linse hat gemessen, was das kostet:
# seit `VERSION_UNDER_TEST` GELESEN wird statt fest zu stehen, geht der Nachschlag bei einem
# Post-Release ins Leere, `c10_2_slot_filled()` faellt auf FAIL, und der beratende CI-Job meldet
# `audit_candidate_ready=False`. Der Fund ist ein FOLGEFEHLER der Aenderung dieses Zweigs, kein
# Altbestand — genau die Nachbarschaft, die ein Klassenfix mitziehen muss.

def _matrix():
    sys.path.insert(0, str(REPO / "scripts"))
    import audit_candidate_matrix as M               # noqa: PLC0415
    _pruefe_richtiger_baum()
    return M


def _pruefe_richtiger_baum() -> None:
    """Prueft DIESEN Baum, nicht irgendeinen.

    GEMESSEN 04.09.2026 von einer Gegenlese-Linse und selbst nachgestellt: `import proofbundle`
    loest OHNE `PYTHONPATH` ueber die installierte Fassung auf — auf dieser Maschine ist das
    `/home/konrad/proofbundle/src/proofbundle`, ein ANDERER Worktree desselben Repos mit einem
    anderen HEAD. Der Test lief dann durch und pruefte den falschen Checkout. Mit dem
    vorgeschriebenen PYTHONPATH ist es richtig; die Absicherung darf aber nicht in einer
    Anleitung stehen, sonst gilt sie nur, solange sie jemand liest.

    Der Riegel MELDET und rechnet nicht um: einen sys.path zur Laufzeit zu biegen waere ein
    zweiter Mechanismus, der die Ursache verdeckt.
    """
    import proofbundle                                # noqa: PLC0415
    wo = Path(proofbundle.__file__).resolve().parent
    if REPO not in wo.parents:
        raise AssertionError(
            f"`import proofbundle` loest auf {wo} auf, das liegt NICHT unter {REPO}. Dieser Lauf "
            f"wuerde einen fremden Checkout messen. Setze PYTHONPATH={REPO / 'src'}.")


@pytest.mark.parametrize("version,erwartet,warum", [
    ("5.1.0", "5.1.0", "eine Freigabe zeigt auf sich selbst"),
    ("5.1.0.post1", "5.1.0", "ein Post-Release aendert KEINEN Code — die Evidenz der Basis gilt"),
    ("5.1.0.post7", "5.1.0", "und das unabhaengig von der Nummer"),
    ("5.1.0rc1", "5.1.0rc1", "eine Vorabversion NICHT: ihr Code ist ein anderer"),
    ("5.1.0.dev1", "5.1.0.dev1", "eine Entwicklungsfassung ebenso wenig"),
    ("6.0.0", "6.0.0", "eine neue Freigabe braucht ihren eigenen Slot"),
])
def test_der_slot_schluessel_faellt_nur_fuer_post_zurueck(version, erwartet, warum):
    assert _matrix()._slot_schluessel(version) == erwartet, warum


def test_ein_post_release_findet_den_slot_seiner_basis(monkeypatch):
    """DIE WIRKUNG, nicht nur die Regel. Ohne diesen Fall waere der Test oben gruen, auch wenn der
    Nachschlag den Schluessel gar nicht benutzt."""
    M = _matrix()
    monkeypatch.setattr(M, "VERSION_UNDER_TEST", "5.1.0.post1")
    zustand, text = M.c10_2_slot_filled()
    assert zustand == M.PASS, f"das Post-Release findet den Slot seiner Basis nicht: {text}"


def test_eine_vorabversion_findet_ihn_NICHT(monkeypatch):
    """DIE GEGENRICHTUNG, und sie ist der eigentliche Inhalt der Regel. Ein Rueckfall, der ALLES
    auf die Basis zeigen laesst, wuerde jede Vorabversion mit fremder Evidenz gruen faerben."""
    M = _matrix()
    monkeypatch.setattr(M, "VERSION_UNDER_TEST", "5.1.0rc1")
    zustand, _ = M.c10_2_slot_filled()
    assert zustand == M.FAIL, "eine Vorabversion borgt sich die Evidenz der Freigabe"


# ── Der ECHTE Baum, nicht nur ein synthetischer ───────────────────────────────────────────────
#
# DIE LUECKE, die eine Gegenlese-Linse fand und die ich selbst nachgemessen habe: `RELEASE.md` und
# `docs/readiness_pack/PROGRESS.md` sind in `_TRACKED_PLACES` deklariert, wurden von dieser Datei
# aber NIE gegen den echten Repo-Zustand geprueft — nur gegen einen `tmp_path`-Baum. Belegt:
#
#     sed -i 's/current: 5.1.0/current: 9.9.9/' RELEASE.md
#     pytest tests/test_version_single_source.py -q   ->  32 passed        (blind)
#     python3 scripts/check_version_and_changelog.py --repo .
#       -> "RELEASE.md: ... states ['9.9.9'] but the source version is 5.1.0"
#
# `pytest` gruen war damit NICHT gleichbedeutend mit "der echte Gate-Lauf ist gruen", und genau
# diese Gleichsetzung ist der Zweck einer Testdatei, die sich "single source" nennt. Ein
# synthetischer Baum prueft die REGEL; nur der echte prueft den ZUSTAND.

def test_das_echte_repo_besteht_das_echte_tor():
    """Der Gate-Lauf gegen DIESEN Baum, nicht gegen eine Nachbildung.

    Bewusst der ganze `check()` und nicht nur `check_tracked_places`: eine Auswahl waere wieder
    eine Nachbildung, nur eine feinere. Was das Tor im Betrieb sagt, sagt es hier.
    """
    sys.path.insert(0, str(REPO / "scripts"))
    import check_version_and_changelog as C          # noqa: PLC0415
    probleme = C.check(REPO)
    assert not probleme, (
        "das echte Versions-Tor meldet auf diesem Baum Probleme:\n  " + "\n  ".join(probleme))


@pytest.mark.parametrize("pfad,anker", [
    ("RELEASE.md", "current:"),
    ("docs/readiness_pack/PROGRESS.md", "current release:"),
])
def test_jede_prosa_stelle_nennt_die_quelle_im_echten_baum(pfad, anker):
    """EINZELN, mit dem Dateinamen im Befund. Der Test darueber sagt nur DASS etwas klemmt; diese
    Zusicherung sagt WO, und das ist der Unterschied zwischen einem Alarm und einem Hinweis."""
    sys.path.insert(0, str(REPO / "scripts"))
    import check_version_and_changelog as C          # noqa: PLC0415
    txt = (REPO / pfad).read_text(encoding="utf-8")
    gefunden = re.findall(anker.replace(":", r":\s*v?") + C._SEMVER, txt)
    assert gefunden, f"{pfad}: der Anker {anker!r} steht nicht mehr drin — hat sich die Datei geaendert?"
    abweichend = sorted({v for v in gefunden if v != quelle()})
    assert not abweichend, (
        f"{pfad} nennt {abweichend}, die Quelle sagt {quelle()!r}")
