"""SER -04: the verifier written from the text alone gives the result of every vector in the file.

drafts/ser-04/ carries the submitted text of draft-gruszka-signed-evaluation-receipts-04, its vector file and a
verifier built only from that text. This file runs the verifier the way the folder's README says and holds each of
the 66 results, with its first failing step, to the result the vector file states. The first case is the control:
a changed vector has to turn the comparison red, or the comparison measures nothing.
"""
from __future__ import annotations

import base64
import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SER = REPO / "drafts" / "ser-04"
LAUF = SER / "verifier-from-text" / "ser04" / "lauf_ser.py"
TEXT = "draft-gruszka-signed-evaluation-receipts-04.txt"
VEKTOREN = "test-vectors.json"
ANZAHL = 66


def _lauf(ordner: Path, ausgabe: Path) -> dict:
    ausgabe.mkdir(parents=True, exist_ok=True)
    p = subprocess.run([sys.executable, "-I", "-B", str(LAUF), str(ordner), str(ausgabe)],
                       capture_output=True, text=True, timeout=600)
    assert p.returncode == 0, p.stderr[-2000:]
    return json.loads((ausgabe / "ser_lauf.json").read_text(encoding="utf-8"))


def abweichungen(lauf: dict) -> list[str]:
    """Each vector whose result or first failing step is not the one in the file, each failed check of the file
    against Appendix A.3, and a vector count other than 66."""
    out = ["%s: the file says %s %s, the verifier gives %s %s"
           % (r["id"], r["expected"], r["expected_step"], r["result"], r["step"])
           for r in lauf["results"] if not r["same"]]
    out += ["file check failed: %s" % c[0] for c in lauf["file_checks"] if not c[-1]]
    if len(lauf["results"]) != ANZAHL:
        out.append("%d vectors run, not %d" % (len(lauf["results"]), ANZAHL))
    return out


def tabelle(lauf: dict) -> str:
    """results/results.md: one row per vector, the expected and the verifier's result and first failing step."""
    z = ["# SER -04, the result of the verifier from the text for each vector", "",
         "Generated from `ser_lauf.json`; `tests/test_ser04_verifier_from_text.py` renders it again from a fresh run "
         "and compares.", "",
         "| Vector | Label | Expected | Expected first failing step | Verifier | Verifier first failing step |",
         "|---|---|---|---|---|---|"]
    for r in lauf["results"]:
        z.append("| %s | %s | %s | %s | %s | %s |" % (r["id"], r["label"], r["expected"], r["expected_step"],
                                                      r["result"], r["step"]))
    same = sum(1 for r in lauf["results"] if r["same"])
    z += ["", "%d of %d vectors give the expected result and first failing step." % (same, len(lauf["results"])), ""]
    return "\n".join(z)


def test_a_changed_vector_turns_the_comparison_red(tmp_path):
    """P1 is a valid receipt. With one byte of its signature changed it no longer verifies, while the file still
    expects PASS, so the comparison must name P1."""
    kopie = tmp_path / "ser-04"
    kopie.mkdir()
    shutil.copyfile(SER / TEXT, kopie / TEXT)
    doc = json.loads((SER / VEKTOREN).read_text(encoding="utf-8"))
    p1 = [v for v in doc["vectors"] if v["id"] == "P1"][0]
    assert p1["expected"] == "PASS"
    beleg = [b for b in p1["bytes"] if b["label"] == "Receipt"][0]
    receipt = json.loads(bytes.fromhex(beleg["hex"]))
    sig = bytearray(base64.b64decode(receipt["signature"]["sig"]))
    sig[40] ^= 0x01
    receipt["signature"]["sig"] = base64.b64encode(bytes(sig)).decode("ascii")
    beleg["hex"] = json.dumps(receipt, separators=(",", ":")).encode("utf-8").hex()
    (kopie / VEKTOREN).write_text(json.dumps(doc), encoding="utf-8")
    befund = abweichungen(_lauf(kopie, tmp_path / "aus"))
    assert any(b.startswith("P1: the file says PASS all, the verifier gives FAIL") for b in befund), befund


def test_every_vector_gives_the_result_the_file_states(tmp_path):
    """66 of 66, each with the first failing step of the file, and the file holds its size and SHA-256 from A.3."""
    lauf = _lauf(SER, tmp_path / "aus")
    assert abweichungen(lauf) == []
    assert all(v for v in lauf["keychecks"].values() if isinstance(v, bool)), lauf["keychecks"]


def test_the_recorded_run_is_the_run_of_this_folder(tmp_path):
    """results/ser_lauf.json and results/results.md, which the README cites, are what the verifier gives on
    this folder today."""
    lauf = _lauf(SER, tmp_path / "aus")
    aufgezeichnet = json.loads((SER / "results" / "ser_lauf.json").read_text(encoding="utf-8"))
    for teil in ("results", "file_checks", "structure_problems", "keychecks", "A2_vs_file"):
        assert lauf[teil] == aufgezeichnet[teil], teil
    assert (SER / "results" / "results.md").read_text(encoding="utf-8") == tabelle(lauf)


def test_the_folder_carries_the_submitted_bytes():
    """The text and XML as filed at ietf.org, and the vector file Appendix A.3 names."""
    soll = {
        "draft-gruszka-signed-evaluation-receipts-04.xml":
            "f2a7e569af4456d296f44f1f79d27f80d5a3b572e41831f923816fdfcda0081b",
        TEXT: "d60c3dd95aefb8019a5f1c0ce041d8c4eb1d4571302766944bfbc92b91c1e358",
        VEKTOREN: "710cb8abab7ca51cf61b85c5610018f9a153add4c3db4f71b2d597e57b1671d1",
    }
    for name, digest in soll.items():
        assert hashlib.sha256((SER / name).read_bytes()).hexdigest() == digest, name
