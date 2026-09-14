"""Die Verfuegbarkeit der Historie ist eine VORBEDINGUNG — sie wird gemessen, nicht geschlossen.

FUND, Codex 4000088153 (P1). Die Herkunfts-Zusicherungen fragten `.git`-Existenz und deuteten
danach jedes Nicht-Finden als erfundene Herkunft. Gemessen in `git clone --depth 1`: 1 failed —
ueber eine Herkunft, die es GIBT. Die Pflichtmatrix checkt ohne Tiefenangabe aus, also flach; der
Riegel haette dort auf jeder Python-Version falsch angeschlagen.

DIE KLASSE: eine Zusicherung, die ihre Vorbedingung aus einem STELLVERTRETER schliesst. `.git` ist
der Stellvertreter, "die Historie reicht zurueck" die Eigenschaft. Sie fallen fast immer zusammen —
ausser genau dort, wo der Riegel laufen muss.

BEIDE RICHTUNGEN STEHEN HIER, und die zweite ist die wichtigere: der Fix darf einen ECHTEN Fund
nicht stillstellen. Ein erfundener Vorgaenger bleibt in einer vollstaendigen Historie ein Fund.

EHRLICHE MARKEN (Jury Linse 3, gemessen gegen den Stand VOR dem Fix): nicht jeder Fall hier haette
vorher fallen KOENNEN. Drei sind unter beiden Fassungen gruen — sie halten fest, dass die
Verschaerfung nichts kaputt macht, aber sie belegen den Fix nicht. Sie tragen deshalb [GETRENNT]
statt [ZAEHLT]. Wer eine Anti-Paritaet als Fangnachweis zaehlt, zaehlt seine eigene Vorsicht mit.
"""
from __future__ import annotations

import importlib.util
import pathlib
import subprocess

import pytest

# DIE PFADFORM, NICHT DER BLANKE NAME — und das ist ein Fund des eigenen Riegels von heute
# frueh: `scripts/` wird NICHT ausgeliefert (MANIFEST.in kennt kein `graft scripts`, gemessen an
# SOURCES.txt). Ein blanker `from b7_historie import ...` auf Modulebene braeche im entpackten
# sdist das SAMMELN und mit ihm die ganze Suite. Die Pfadform nennt ein Verzeichnis, und `conftest`
# macht daraus ein ehrliches SKIP statt eines Abbruchs.
_HIST_PFAD = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "b7_historie.py"
_HIST_SPEC = importlib.util.spec_from_file_location("b7_historie", _HIST_PFAD)
_HIST = importlib.util.module_from_spec(_HIST_SPEC)
_HIST_SPEC.loader.exec_module(_HIST)
ABGESCHNITTEN = _HIST.ABGESCHNITTEN
digest_in_historie = _HIST.digest_in_historie
historie_abgeschnitten = _HIST.historie_abgeschnitten
letzte_abweichende_fassung = _HIST.letzte_abweichende_fassung

DATEI = "sache.txt"


def _git(baum, *args):
    r = subprocess.run(["git", "-C", str(baum), *args], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, f"git {args[0]} fehlgeschlagen: {r.stderr[:200]}"
    return r.stdout


def _baum(pfad: pathlib.Path, staende: list[str]) -> pathlib.Path:
    """Ein echtes Repository mit je einem Commit pro Stand. Keine Attrappe — echtes git."""
    pfad.mkdir(parents=True, exist_ok=True)
    _git(pfad, "init", "-q", "-b", "main")
    _git(pfad, "config", "user.email", "pruefer@example.invalid")
    _git(pfad, "config", "user.name", "Pruefer")
    for s in staende:
        (pfad / DATEI).write_text(s, encoding="utf-8")
        _git(pfad, "add", DATEI)
        _git(pfad, "commit", "-q", "-m", f"stand {s}")
    return pfad


def _klone(quelle: pathlib.Path, ziel: pathlib.Path, tiefe: int | None):
    argv = ["git", "clone", "--quiet"]
    if tiefe:
        argv += ["--depth", str(tiefe)]
    argv += [f"file://{quelle}", str(ziel)]
    r = subprocess.run(argv, capture_output=True, text=True, timeout=120)
    if r.returncode != 0:
        pytest.skip(f"NICHT MESSBAR: klonen fehlgeschlagen ({r.stderr.strip()[:100]})")
    return ziel


@pytest.fixture
def baeume(tmp_path):
    """Derselbe Inhalt, zweimal geklont: einmal flach, einmal vollstaendig."""
    quelle = _baum(tmp_path / "quelle", ["eins\n", "zwei\n", "drei\n"])
    return (quelle,
            _klone(quelle, tmp_path / "flach", 1),
            _klone(quelle, tmp_path / "voll", None))


def test_ein_flacher_klon_wird_als_abgeschnitten_erkannt(baeume):
    """[ZAEHLT] Der Kern: `.git` ist da, `git log` antwortet — und die Historie fehlt trotzdem."""
    _, flach, _ = baeume
    assert (flach / ".git").exists(), "Vorbedingung des Falls: der Stellvertreter ist DA"
    assert len(_git(flach, "log", "--format=%H").split()) == 1, "Vorbedingung: nur die Spitze"
    assert historie_abgeschnitten(flach) == ABGESCHNITTEN


def test_ANTI_ein_vollstaendiger_klon_gilt_NICHT_als_abgeschnitten(baeume):
    """[GETRENNT] Gegenrichtung: ein Riegel, der immer 'abgeschnitten' sagt, misst nichts."""
    _, _, voll = baeume
    assert historie_abgeschnitten(voll) is None


def test_FANG_ein_vorhandener_vorgaenger_heisst_im_flachen_klon_NICHT_erfunden(baeume):
    """[ZAEHLT] Genau die Lage des Fundes: der Digest EXISTIERT, er ist nur nicht abrufbar."""
    import hashlib
    quelle, flach, _ = baeume
    alt = hashlib.sha256(b"eins\n").hexdigest()
    zustand, grund = digest_in_historie(flach, DATEI, alt)
    assert zustand == "NICHT MESSBAR", f"gemessen {zustand} — das waere das falsche ROT"
    assert ABGESCHNITTEN in grund, grund
    # Und in der Quelle mit ganzer Historie ist derselbe Digest schlicht da.
    assert digest_in_historie(quelle, DATEI, alt)[0] == "GEFUNDEN"


def test_ein_WIRKLICH_erfundener_vorgaenger_bleibt_ein_FUND(baeume):
    """[GETRENNT] Die teuerste Zusicherung hier: der Fix darf den echten Fall nicht stillstellen."""
    _, _, voll = baeume
    zustand, grund = digest_in_historie(voll, DATEI, "0" * 64)
    assert zustand == "NICHT GEFUNDEN", f"ein erfundener Digest muss ein Fund bleiben, gemessen {zustand}"
    assert grund


def test_erstaufnahme_und_abgeschnitten_sind_ZWEI_zustaende(tmp_path):
    """[ZAEHLT] Ein Wort fuer zwei Ursachen ist der Kern des Fundes, nicht sein Beiwerk."""
    quelle = _baum(tmp_path / "eins", ["nur dieser\n"])
    flach = _klone(quelle, tmp_path / "flach1", 1)
    jetzt = (quelle / DATEI).read_bytes()

    z_voll, _, _, g_voll = letzte_abweichende_fassung(quelle, DATEI, jetzt)
    assert z_voll == "ERSTAUFNAHME", f"gemessen {z_voll}: {g_voll}"

    z_flach, _, _, g_flach = letzte_abweichende_fassung(flach, DATEI, jetzt)
    assert z_flach == "NICHT MESSBAR", f"gemessen {z_flach}: {g_flach}"
    assert ABGESCHNITTEN in g_flach, g_flach


def test_ohne_git_baum_ist_die_historie_nicht_messbar(tmp_path):
    """[GETRENNT] Der dritte Grund, und er traegt seinen eigenen Text: sdist, entpacktes Paket."""
    (tmp_path / DATEI).write_text("ohne git\n", encoding="utf-8")
    grund = historie_abgeschnitten(tmp_path)
    assert grund and "kein git-Baum" in grund, grund


def test_ENDE_ZU_ENDE_die_herkunftsvertraege_werden_im_flachen_klon_NICHT_rot(tmp_path):
    """[ZAEHLT] Genau der gemeldete Fall, an den ECHTEN Vertraegen dieses Baums gefahren.

    Die Faelle darueber pruefen den Erzeuger. Dieser prueft, dass die Vertraege ihn auch benutzen —
    eine Zusicherung am Verhalten, nicht am Text. Gemessen vor dem Fix: 1 failed. Ein flacher
    lokaler Klon kostet unter einer Sekunde und 27 MB, gemessen 13.09.2026.
    """
    repo = pathlib.Path(__file__).resolve().parents[1]
    if not (repo / ".git").exists():
        pytest.skip("NICHT MESSBAR: kein git-Baum, es gibt nichts flach zu klonen")
    klon = _klone(repo, tmp_path / "flach", 1)
    assert historie_abgeschnitten(klon) == ABGESCHNITTEN, "Vorbedingung: der Klon IST flach"

    # DER KLON TRAEGT DEN COMMITTETEN STAND, NICHT DEN ARBEITSBAUM. Ohne diesen Schritt misst der
    # Fall die Fassung von HEAD und nicht die, die gerade geprueft werden soll — eine Messung in
    # einer Kopie ist eine Messung der Kopie. Gelegt wird deshalb der heutige Code auf die
    # abgeschnittene Historie; DAS ist die Eigenschaft, um die es geht.
    module = ["tests/test_der_fortgeschriebene_sollwert_traegt_seine_herkunft.py",
              "tests/test_die_herkunft_vergleicht_nicht_mit_sich_selbst.py"]
    for rel in [*module, "scripts/b7_historie.py"]:
        (klon / rel).write_bytes((repo / rel).read_bytes())
    import os
    import sys
    r = subprocess.run([sys.executable, "-m", "pytest", *module, "-q", "-p", "no:cacheprovider"],
                       cwd=klon, capture_output=True, text=True, timeout=300,
                       env={**os.environ, "PYTHONPATH": "src"})
    # DER RUECKGABEWERT ENTSCHEIDET, NICHT DER TEXT (Jury Linse 3). Die erste Fassung fragte nur,
    # ob " failed" im Text steht. Ausgefuehrt gemessen: "no tests ran" (RC 5) und "No module named
    # pytest" (RC 1) erfuellten diese Bedingung BEIDE — ein Lauf, der gar nicht stattfand, las sich
    # wie ein bestandener. Geprueft wird deshalb der RC UND dass Faelle gelaufen sind.
    assert r.returncode == 0, (
        f"die Herkunftsvertraege enden im flachen Klon mit RC {r.returncode} — genau das falsche "
        f"ROT, gegen das dieser Fall steht:\n{r.stdout[-1500:]}\n{r.stderr[-500:]}")
    assert " passed" in r.stdout, (
        f"kein einziger Fall ist gelaufen — ein leerer Lauf ist kein bestandener:\n{r.stdout[-800:]}")


# ── DIE MARKE IST NICHT DIE EIGENSCHAFT (Jury, Linse 1, 13.09.2026) ────────────────────────
#
# Die erste Fassung von `historie_abgeschnitten()` fragte `--is-shallow-repository`. Das prueft
# nur, ob `$GIT_DIR/shallow` EXISTIERT. Gemessen in einem vollen Klon: `: > .git/shallow` mit NULL
# Bytes kippt die Antwort auf "true", waehrend die Historie vollstaendig lesbar bleibt — aus einem
# echten roten Fund wurde ein Skip, durch eine Datei ohne Commit und ohne Spur.
#
# Das war dieselbe Klasse, gegen die diese Datei gebaut ist, eine Ebene tiefer: der Stellvertreter
# hiess nicht mehr `.git`, sondern `.git/shallow`. Die Faelle hier halten die Unterscheidung fest.

def _shallow_schreiben(baum: pathlib.Path, inhalt: str) -> None:
    gd = subprocess.run(["git", "-C", str(baum), "rev-parse", "--git-dir"],
                        capture_output=True, text=True, timeout=60)
    assert gd.returncode == 0, gd.stderr
    p = pathlib.Path(gd.stdout.strip())
    (p if p.is_absolute() else baum / p).joinpath("shallow").write_text(inhalt, encoding="utf-8")


def test_FANG_eine_LEERE_shallow_marke_schneidet_nichts_ab(baeume):
    """[ZAEHLT] Der Exploit der Jury: eine Datei ohne Inhalt darf keinen Fund stillstellen."""
    _, _, voll = baeume
    assert historie_abgeschnitten(voll) is None, "Vorbedingung: vorher vollstaendig"
    _shallow_schreiben(voll, "")
    assert _git(voll, "rev-parse", "--is-shallow-repository").strip() == "true", (
        "Vorbedingung des Falls: git SELBST sagt jetzt 'flach' — genau darum geht es")
    assert historie_abgeschnitten(voll) is None, (
        "eine leere Pfropfmarke gilt als Abschnitt — dann genuegt eine Datei, um jeden "
        "Herkunftsfund in einen Skip zu verwandeln")


def test_FANG_eine_shallow_marke_mit_MUELL_schneidet_nichts_ab(baeume):
    """[ZAEHLT] Dieselbe Klasse, andere Auspraegung: was git nicht aufloest, ist keine Grenze."""
    _, _, voll = baeume
    _shallow_schreiben(voll, "f" * 40 + "\n")
    assert historie_abgeschnitten(voll) is None


def test_ANTI_der_ECHTE_flache_klon_gilt_weiterhin_als_abgeschnitten(baeume):
    """[ZAEHLT] Gegenrichtung: die Verschaerfung darf den echten Fall nicht verlieren."""
    _, flach, _ = baeume
    assert historie_abgeschnitten(flach) == ABGESCHNITTEN


def test_FANG_ein_erfundener_vorgaenger_bleibt_trotz_LEERER_marke_ein_FUND(baeume):
    """[ZAEHLT] Die Wirkung, nicht nur das Urteil: der Fund kommt zurueck."""
    import hashlib
    _, _, voll = baeume
    _shallow_schreiben(voll, "")
    zustand, grund = digest_in_historie(voll, DATEI, "0" * 64)
    assert zustand == "NICHT GEFUNDEN", f"der Fund wurde stillgestellt: {zustand} / {grund}"
    # Und ein echter Vorgaenger wird weiterhin gefunden.
    assert digest_in_historie(voll, DATEI, hashlib.sha256(b"eins\n").hexdigest())[0] == "GEFUNDEN"


# ── DER NACHBAR AN SICHERHEITSNAHER STELLE (Jury, Linse 2, 13.09.2026) ─────────────────────
#
# `audit_candidate_matrix.py::_anchor_last_touched_at_head` fragt, ob der Vertrauensanker im
# KANDIDATENCOMMIT eingefuehrt wurde — die Kontrolle gegen Selbstregistrierung. In einem flachen
# Checkout hat der Pfropf-Commit keinen Elternteil, `git log` vergleicht ihn gegen einen LEEREN
# Baum, und JEDE vorhandene Datei sieht aus wie neu eingefuehrt. GEMESSEN an diesem Repository:
# voll b05fc6a (frueherer Commit, zulaessig), flach 435ac75 (der Kandidat selbst).
#
# Der Job, der das ruft, checkt ohne Tiefenangabe aus. Die Kontrolle haette bei JEDEM Lauf einen
# rechtmaessig vorregistrierten Anker verdaechtigt. Dieselbe Klasse, andere Datei, sicherheitsnaeher.

def _matrix():
    import importlib.util  # noqa: PLC0415
    p = REPO_WURZEL / "scripts" / "audit_candidate_matrix.py"
    if not p.is_file():
        pytest.skip(f"NICHT MESSBAR: {p} fehlt")
    s = importlib.util.spec_from_file_location("_acm", p)
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m


REPO_WURZEL = pathlib.Path(__file__).resolve().parents[1]


def _anker_baum(pfad: pathlib.Path, anker_rel: str, im_letzten_commit: bool) -> pathlib.Path:
    """Ein Baum, in dem der Anker entweder FRUEH oder erst im Kopf-Commit auftaucht."""
    pfad.mkdir(parents=True, exist_ok=True)
    _git(pfad, "init", "-q", "-b", "main")
    _git(pfad, "config", "user.email", "pruefer@example.invalid")
    _git(pfad, "config", "user.name", "Pruefer")
    ziel = pfad / anker_rel
    ziel.parent.mkdir(parents=True, exist_ok=True)
    if not im_letzten_commit:
        ziel.write_text("anker\n", encoding="utf-8")
        _git(pfad, "add", anker_rel)
        _git(pfad, "commit", "-q", "-m", "anker zuerst")
    (pfad / "sonst.txt").write_text("x\n", encoding="utf-8")
    _git(pfad, "add", "sonst.txt")
    _git(pfad, "commit", "-q", "-m", "zwischenstand")
    if im_letzten_commit:
        ziel.write_text("anker\n", encoding="utf-8")
        _git(pfad, "add", anker_rel)
        _git(pfad, "commit", "-q", "-m", "anker erst jetzt")
    return pfad


def test_FANG_der_vertrauensanker_gilt_im_flachen_klon_NICHT_als_selbstregistriert(tmp_path):
    """[ZAEHLT] Der sicherheitsnahe Nachbar: aus NICHT MESSBAR darf kein Verdacht werden."""
    m = _matrix()
    quelle = _anker_baum(tmp_path / "q", m.READINESS_TRUST_ANCHOR_REL, im_letzten_commit=False)
    flach = _klone(quelle, tmp_path / "flach", 1)
    kopf = _git(flach, "rev-parse", "HEAD").strip()
    selbst, grund = m._anchor_last_touched_at_head(flach, kopf)
    assert selbst is None, (
        f"im flachen Klon meldet die Kontrolle {selbst!r} statt NICHT MESSBAR — ein rechtmaessig "
        f"vorregistrierter Anker wuerde als selbstregistriert verdaechtigt: {grund}")
    assert ABGESCHNITTEN in grund, grund


def test_ANTI_ein_WIRKLICH_im_kopf_eingefuehrter_anker_bleibt_ein_fund(tmp_path):
    """[ZAEHLT] Gegenrichtung: die Verschaerfung darf die Kontrolle nicht abschalten."""
    m = _matrix()
    baum = _anker_baum(tmp_path / "v", m.READINESS_TRUST_ANCHOR_REL, im_letzten_commit=True)
    kopf = _git(baum, "rev-parse", "HEAD").strip()
    selbst, grund = m._anchor_last_touched_at_head(baum, kopf)
    assert selbst is True, f"Selbstregistrierung wird nicht mehr erkannt: {selbst!r} / {grund}"


def test_ein_frueh_eingefuehrter_anker_gilt_bei_voller_historie_als_vorregistriert(tmp_path):
    """[ZAEHLT] Der zulaessige Fall bleibt zulaessig — sonst misst der Riegel nur noch sich selbst."""
    m = _matrix()
    baum = _anker_baum(tmp_path / "f", m.READINESS_TRUST_ANCHOR_REL, im_letzten_commit=False)
    kopf = _git(baum, "rev-parse", "HEAD").strip()
    selbst, grund = m._anchor_last_touched_at_head(baum, kopf)
    assert selbst is False, f"{selbst!r} / {grund}"


# ── EIN NICHT LESBARER BLOB IST KEIN ANDERER INHALT (Jury, Linse 3, 13.09.2026) ────────────
#
# In einem partial clone (`--filter=blob:none`) liefert `git log` die GANZE Commit-Liste, aber
# `git show` scheitert auf jedem Blob, der nicht nachgeladen ist — und ohne erreichbaren Ursprung
# dauerhaft. GEMESSEN: `is-shallow` false, drei Commits sichtbar, `git show <aeltester>:<datei>`
# mit RC 128 "bad object". Die Vorgaengerfassung uebersprang das still und meldete danach
# NICHT GEFUNDEN — dasselbe falsche ROT, ueber einen dritten Stellvertreter.

def _partial_klon(quelle: pathlib.Path, ziel: pathlib.Path) -> pathlib.Path | None:
    _git(quelle, "config", "uploadpack.allowfilter", "true")
    r = subprocess.run(["git", "clone", "--quiet", "--no-local", "--filter=blob:none",
                        f"file://{quelle}", str(ziel)], capture_output=True, text=True, timeout=120)
    if r.returncode != 0:
        pytest.skip(f"NICHT MESSBAR: partial clone nicht moeglich ({r.stderr.strip()[:90]})")
    return ziel


def test_FANG_ein_unlesbarer_blob_wird_NICHT_als_nicht_vorhanden_gemeldet(tmp_path):
    """[ZAEHLT] Der dritte Stellvertreter: die Liste ist vollstaendig, ihr Inhalt nicht."""
    import hashlib
    quelle = _baum(tmp_path / "q", ["eins\n", "zwei\n", "drei\n"])
    alt = hashlib.sha256(b"eins\n").hexdigest()
    assert digest_in_historie(quelle, DATEI, alt)[0] == "GEFUNDEN", "Vorbedingung: es gibt ihn"

    p = _partial_klon(quelle, tmp_path / "p")
    quelle.rename(tmp_path / "q_weg")          # der Ursprung ist weg, nichts kann nachgeladen werden
    assert historie_abgeschnitten(p) is None, "ein partial clone ist nicht flach — das ist der Punkt"

    zustand, grund = digest_in_historie(p, DATEI, alt)
    assert zustand == "NICHT MESSBAR", (
        f"ein Digest, der EXISTIERT, wurde als {zustand} gemeldet — falsches ROT ueber einen "
        f"Blob, den dieser Baum nur nicht lesen kann: {grund}")
    assert "nicht LESBAR" in grund, grund


def test_FANG_auch_die_fortsetzungspruefung_meldet_unlesbar_statt_erstaufnahme(tmp_path):
    """[ZAEHLT] Dieselbe Klasse im zweiten Laeufer — sonst faellt sie dort still durch."""
    quelle = _baum(tmp_path / "q2", ["eins\n", "zwei\n"])
    jetzt = (quelle / DATEI).read_bytes()
    p = _partial_klon(quelle, tmp_path / "p2")
    quelle.rename(tmp_path / "q2_weg")
    zustand, _, _, grund = letzte_abweichende_fassung(p, DATEI, jetzt)
    assert zustand == "NICHT MESSBAR", f"{zustand}: {grund}"
    assert "nicht LESBAR" in grund, grund


def test_ANTI_ein_vollstaendiger_klon_meldet_NICHT_unlesbar(baeume):
    """[GETRENNT] Die Verschaerfung darf nicht jeden Baum fuer unlesbar erklaeren."""
    import hashlib
    _, _, voll = baeume
    assert digest_in_historie(voll, DATEI, hashlib.sha256(b"eins\n").hexdigest())[0] == "GEFUNDEN"
    assert digest_in_historie(voll, DATEI, "0" * 64)[0] == "NICHT GEFUNDEN"
