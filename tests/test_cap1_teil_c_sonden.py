"""CAP-1 part C: the probes of the independent implementation against `proofbundle.cap1`.

`tools/cap1_unabhaengige_umsetzung/sonden.py` builds five documents from the author's vectors: two
probes aimed at the place where the draft is silent (duplicate JSON names, RFC 8259 §4
'unpredictable'), and three controls. The tool is ONLY EXECUTED here, never modified (per the
order); the probes are rebuilt fresh into a temp directory on every run, nothing is copied.

What is measured: our reader is the STRICT reading — a duplicate name is a read error, not a
verdict (S09, S10: BundleFormatError, never CONFORMS and never REFUSED). The controls show that the
probes do not 'refuse everything': K1 and K2 (unmodified vectors) are conformant, K3 (a singly
broken R1, no duplicate name) fails at exactly R1 — a must-fail, set equality. Without the controls
the run measures nothing (lauf.py says so verbatim), which is why they are tests here.
"""
from __future__ import annotations

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
    """The three readings of the independent implementation judge the same bytes differently
    (last-wins CONFORMS/REFUSED, first-wins the other way round, strict a JSON error). Our reader is
    strict: it does not judge at all — and the control beside it shows that the standard library
    accepts the very same document silently."""
    roh = (sonden / name).read_bytes()
    with pytest.raises(BundleFormatError, match="duplicate JSON key"):
        cap1.load_cap1_document(roh)
    import json  # noqa: PLC0415
    assert isinstance(json.loads(roh), dict), "control: the standard reader accepts the document (last-wins)"


@pytest.mark.parametrize("name", ["K1_positivkontrolle_PV03.json", "K2_positivkontrolle_PV01.json"])
def test_die_positivkontrollen_sind_konform(sonden, name):
    doc = cap1.load_cap1_document((sonden / name).read_bytes())
    assert cap1.check_cap1_document(doc) == []
    assert cap1.is_conformant(doc) is True


def test_die_negativkontrolle_faellt_an_genau_r1(sonden):
    doc = cap1.load_cap1_document((sonden / "K3_negativkontrolle_R1.json").read_bytes())
    gefeuert = sorted({f["rule"] for f in cap1.check_cap1_document(doc)})
    assert gefeuert == ["R1-no-silent-remainder"], gefeuert


def test_das_werkzeug_wurde_nicht_veraendert():
    """The order forbids changes to tools/cap1_unabhaengige_umsetzung; the version on the branch is
    byte-identical to the one on base 8b581d7 (measured through git, not asserted)."""
    r = subprocess.run(["git", "-C", str(REPO), "diff", "--quiet", "8b581d7", "--",
                        "tools/cap1_unabhaengige_umsetzung"], capture_output=True, text=True)
    if r.returncode not in (0, 1):
        pytest.skip(f"git nicht messbar: {r.stderr.strip()[:120]}")
    assert r.returncode == 0, "tools/cap1_unabhaengige_umsetzung weicht von der Basis ab"
