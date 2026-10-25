"""CAP-1 Teil C: die Sonden der unabhaengigen Umsetzung gegen `proofbundle.cap1`.

`tools/cap1_unabhaengige_umsetzung/sonden.py` erzeugt aus den Autor-Vektoren fuenf Dokumente:
zwei Sonden zu der Stelle, an der der Entwurf schweigt (doppelte JSON-Namen, RFC 8259 §4
'unpredictable'), und drei Kontrollen. Das Werkzeug wird hier NUR AUSGEFUEHRT, nicht veraendert
(Auftrag); die Sonden werden je Lauf frisch in ein Temp-Verzeichnis gebaut, nichts wird kopiert.

Was gemessen wird: unser Leser ist die STRENGE Lesart — ein doppelter Name ist ein Lesefehler,
kein Urteil (S09, S10: BundleFormatError, nie CONFORMS und nie REFUSED). Die Kontrollen zeigen,
dass die Sonden nicht 'alles verweigern': K1 und K2 (unveraenderte Vektoren) sind konform, K3
(einfach gebrochenes R1, kein doppelter Name) faellt an genau R1 — Muss-Fehlschlag, Mengengleichheit.
Ohne die Kontrollen misst der Lauf nichts (lauf.py sagt es woertlich), deshalb sind sie hier Tests.
"""
from __future__ import annotations

import hashlib
import subprocess
import sys
from pathlib import Path

import pytest

from proofbundle import cap1
from proofbundle.errors import BundleFormatError

REPO = Path(__file__).resolve().parents[1]
WERKZEUG = REPO / "tools" / "cap1_unabhaengige_umsetzung" / "sonden.py"
VEKTOREN = REPO / "conformance" / "cap1" / "vectors"


@pytest.fixture(scope="module")
def sonden(tmp_path_factory) -> Path:
    out = tmp_path_factory.mktemp("cap1_sonden")
    r = subprocess.run([sys.executable, str(WERKZEUG), str(VEKTOREN), str(out)],
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
    namen = sorted(p.name for p in out.glob("*.json"))
    assert namen == ["K1_positivkontrolle_PV03.json", "K2_positivkontrolle_PV01.json",
                     "K3_negativkontrolle_R1.json", "S09_doppelter_eligible.json",
                     "S10_doppeltes_complete.json"], namen
    return out


@pytest.mark.parametrize("name", ["S09_doppelter_eligible.json", "S10_doppeltes_complete.json"])
def test_eine_sonde_mit_doppeltem_namen_ist_ein_lesefehler_kein_urteil(sonden, name):
    """Die drei Lesarten der unabhaengigen Umsetzung urteilen ueber dieselben Bytes verschieden
    (last-wins CONFORMS/REFUSED, first-wins umgekehrt, streng JSON-Fehler). Unser Leser ist streng:
    er urteilt gar nicht erst — und die Kontrolle daneben zeigt, dass die Standardbibliothek dasselbe
    Dokument still annimmt."""
    roh = (sonden / name).read_bytes()
    with pytest.raises(BundleFormatError, match="duplicate JSON key"):
        cap1.load_cap1_document(roh)
    import json  # noqa: PLC0415
    assert isinstance(json.loads(roh), dict), "Kontrolle: der Standard-Leser nimmt das Dokument an (last-wins)"


@pytest.mark.parametrize("name", ["K1_positivkontrolle_PV03.json", "K2_positivkontrolle_PV01.json"])
def test_die_positivkontrollen_sind_konform(sonden, name):
    doc = cap1.load_cap1_document((sonden / name).read_bytes())
    assert cap1.check_cap1_document(doc) == []
    assert cap1.is_conformant(doc) is True


def test_die_negativkontrolle_faellt_an_genau_r1(sonden):
    doc = cap1.load_cap1_document((sonden / "K3_negativkontrolle_R1.json").read_bytes())
    gefeuert = sorted({f["rule"] for f in cap1.check_cap1_document(doc)})
    assert gefeuert == ["R1-no-silent-remainder"], gefeuert


#: Owner decision O381-3 (Z381, 2026-10-16): the Rust implementation reads argv with `args_os` and
#: keeps the path a `Path`, so a file under a name that is not UTF-8 gets a verdict instead of a
#: panic (exit 101). Exactly these files differ from 8b581d7, each pinned by the sha256 of its
#: bytes; every other byte of the tool stays as it was, measured over git as before.
_O381_3 = {
    "tools/cap1_unabhaengige_umsetzung/rs/src/main.rs":
        "81ba45aa01036fdcabb5232a941e07b6fca2a1c08371690e16f3b6e25760e739",
    "tools/cap1_unabhaengige_umsetzung/rs/tests/argv.rs":
        "f4288704053027003c02f152e7adfd12aa567cf0b7f4c773d41bda7c27372bed",
}


def test_das_werkzeug_wurde_nicht_veraendert():
    """Der Auftrag verbietet Aenderungen an tools/cap1_unabhaengige_umsetzung; die Fassung im
    Zweig ist byte-gleich mit der auf der Basis 8b581d7 (gemessen ueber git, nicht behauptet)."""
    for pfad, sha in _O381_3.items():
        assert hashlib.sha256((REPO / pfad).read_bytes()).hexdigest() == sha, pfad
    r = subprocess.run(["git", "-C", str(REPO), "diff", "--quiet", "8b581d7", "--",
                        "tools/cap1_unabhaengige_umsetzung",
                        *[f":(exclude){pfad}" for pfad in _O381_3]], capture_output=True, text=True)
    if r.returncode not in (0, 1):
        pytest.skip(f"git nicht messbar: {r.stderr.strip()[:120]}")
    assert r.returncode == 0, "tools/cap1_unabhaengige_umsetzung weicht von der Basis ab"
