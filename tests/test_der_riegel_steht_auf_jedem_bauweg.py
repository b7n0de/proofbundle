"""Ein Tor, das nicht an der Tuer steht, ist kein Tor — jeder BAUENDE Ablauf ruft den Riegel.

FUND, Codex 3999892822 (P1). Der Paketinhalts-Riegel stand in genau EINEM Ablauf, und der laeuft
bei Push auf main, bei Pull Requests und nach Plan — NICHT bei einem Tag `v*`. Der
Veroeffentlichungs-Ablauf baut sdist und wheel selbst und haengt sie danach an das Release, ohne
den Riegel je zu rufen. Ein Tag mit Schluesselmaterial im Paket haette beide veroeffentlicht,
waehrend die zugesagte Eigenschaft "der Paketbau bricht ab" auf einem anderen Weg gruen leuchtete.

DIE KLASSE: ein Tor wird an EINEM Weg angebracht, und die Zusage gilt fuer ALLE. Die Luecke ist
nicht im Tor, sondern in der Menge der Wege, auf denen es steht. Sie waechst still mit: wer morgen
einen dritten Bau-Ablauf anlegt, erbt die Zusage und nicht das Tor.

DESHALB MISST DIESER FALL DIE MENGE, NICHT DIE EINZELSTELLE. Er sucht jeden Schritt, der ein
Distributionsartefakt BAUT, und verlangt im selben Auftrag einen Aufruf des Riegels danach. Ein
neuer Bau-Ablauf faellt hier auf, bevor er veroeffentlicht.

EHRLICHE GRENZE: gemessen wird der Text der Ablaufdateien dieses Baums. Ein Bau, der ausserhalb
dieser Dateien geschieht — von Hand, in einem fremden Ablauf, in einem Werkzeug — wird hier nicht
gesehen. Das ist eine Untergrenze, keine Zusicherung.
"""
from __future__ import annotations

import pathlib

import pytest

yaml = pytest.importorskip("yaml", reason="NICHT MESSBAR: PyYAML fehlt")

REPO = pathlib.Path(__file__).resolve().parents[1]
ABLAEUFE = REPO / ".github" / "workflows"
RIEGEL = "b7_paketinhalt_ohne_schluesselmaterial.py"

#: Was als "baut ein Distributionsartefakt" zaehlt. Als Daten, damit ein neuer Bauweg hier
#: eingetragen wird statt still danebenzustehen.
BAUT = ("python -m build", "build_reproducible.py")

#: DIE EINE AUSNAHME, DEKLARIERT STATT STILL. `build_reproducible.py --check` baut zweimal in
#: Wegwerfverzeichnisse und vergleicht die Bytes; es legt kein Artefakt ab und veroeffentlicht
#: nichts. Ein Riegel darauf haette nichts zu pruefen — `dist/` ist danach leer, und eine leere
#: Dateiliste ist im Riegel selbst ein Abbruch. Die Ausnahme greift NUR, wenn im selben Schritt
#: kein `--outdir` steht: sobald ein Schritt ein Artefakt ABLEGT, zaehlt er wieder als Bauweg.
#: GRUND HIER UND NICHT IN EINER KONFIGURATION: eine Ausnahme, die man lesen muss, um sie zu
#: finden, wird beim naechsten Mal versehentlich verbreitert.
NUR_GEPRUEFT = "--check"
LEGT_AB = "--outdir"


def _baut_ein_artefakt(run: str) -> bool:
    if not any(b in run for b in BAUT):
        return False
    return not (NUR_GEPRUEFT in run and LEGT_AB not in run)


def _jobs():
    if not ABLAEUFE.is_dir():
        pytest.skip(f"NICHT MESSBAR: {ABLAEUFE} fehlt")
    for datei in sorted(ABLAEUFE.glob("*.yml")):
        try:
            d = yaml.safe_load(datei.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as e:
            pytest.fail(f"{datei.name} ist nicht lesbar: {e}")
        for name, job in (d.get("jobs") or {}).items():
            yield datei.name, name, (job.get("steps") or [])


def test_es_gibt_ueberhaupt_bauende_auftraege():
    """[ZAEHLT] Ein Riegel ueber eine leere Menge misst nichts — die Menge wird zuerst gezaehlt."""
    bauend = [(f, j) for f, j, s in _jobs()
              if any(_baut_ein_artefakt(str(st.get("run") or "")) for st in s)]
    assert bauend, "kein einziger bauender Auftrag gefunden — dann prueft dieser Fall nichts"


def test_jeder_bauende_auftrag_ruft_den_riegel_NACH_dem_bau():
    """[ZAEHLT] Der Fund selbst, als Mengenaussage statt als Einzelstelle."""
    ohne = []
    for datei, job, schritte in _jobs():
        laeufe = [str(st.get("run") or "") for st in schritte]
        bau = [i for i, r in enumerate(laeufe) if _baut_ein_artefakt(r)]
        if not bau:
            continue
        riegel = [i for i, r in enumerate(laeufe) if RIEGEL in r]
        if not riegel:
            ohne.append(f"{datei}:{job} baut, ruft den Riegel aber nie")
        elif max(riegel) < min(bau):
            ohne.append(f"{datei}:{job} ruft den Riegel VOR dem Bau — dann misst er nichts")
    assert not ohne, (
        f"{len(ohne)} bauende(r) Auftrag/Auftraege ohne Riegel auf dem Weg: {ohne}")


def test_der_veroeffentlichungsweg_prueft_BEIDE_artefakte():
    """[ZAEHLT] Der Ablauf, der ein wheel baut, muss das wheel auch pruefen."""
    fehlend = []
    for datei, job, schritte in _jobs():
        laeufe = [str(st.get("run") or "") for st in schritte]
        if not any("--with-wheel" in r for r in laeufe):
            continue
        aufrufe = [r for r in laeufe if RIEGEL in r]
        if not any(".whl" in r for r in aufrufe):
            fehlend.append(f"{datei}:{job} baut ein wheel, prueft aber keins")
    assert not fehlend, fehlend


def test_die_grenze_der_messung_steht_im_text():
    """[ZAEHLT] Eine Textmessung ueber Ablaufdateien ist eine Untergrenze, und das gehoert hin."""
    q = pathlib.Path(__file__).read_text(encoding="utf-8")
    assert "EHRLICHE GRENZE" in q and "Untergrenze" in q


def test_die_ausnahme_fuer_den_reinen_PRUEFBAU_ist_begruendet():
    """[ZAEHLT] Eine Ausnahme ohne Grund im Text ist eine stille Verbreiterung in spe."""
    q = pathlib.Path(__file__).read_text(encoding="utf-8")
    assert "DIE EINE AUSNAHME, DEKLARIERT STATT STILL" in q
    assert "veroeffentlicht" in q and "--outdir" in q


def test_FANG_ein_pruefbau_MIT_ablage_zaehlt_wieder_als_bauweg():
    """[ZAEHLT] Gegenrichtung: die Ausnahme darf nicht auf jeden --check durchschlagen."""
    assert _baut_ein_artefakt("python scripts/build_reproducible.py --check") is False
    assert _baut_ein_artefakt("python scripts/build_reproducible.py --check --outdir dist") is True
    assert _baut_ein_artefakt("python scripts/build_reproducible.py --outdir dist") is True
    assert _baut_ein_artefakt("python -m build --wheel --outdir dist") is True
    assert _baut_ein_artefakt("echo kein bau") is False
