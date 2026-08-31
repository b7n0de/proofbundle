"""tests/test_audit_output_aufloesbar.py — loest der signierte audit_output_digest auf ein Artefakt auf?

Anlass 31.08.2026 (Owner): das v5.0.0-Receipt ist gueltig, bindet den Tag-Baum und ist von der
gepinnten Schluesselhaelfte signiert — aber sein ``audit_output_digest`` liegt auf KEINER der 915
verfolgten Dateien. Die Prosa im ``audit_command`` nennt eine Aufzeichnung, die existiert, verfolgt
ist und einen ANDEREN Digest traegt. Der signierte Wert ist damit attribuierbar, aber nicht
nachrechenbar. Fuer 5.1.0 gilt: das Audit-Ergebnis existiert als auffindbares Artefakt, und das
wird VOR der Signatur geprueft.

Hermetisch: eigenes git-Repo je Test, kein Netz, kein Zugriff auf den echten Baum.
"""
from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]


def _lade():
    s = importlib.util.spec_from_file_location(
        "_aufl_test", str(REPO / "scripts" / "audit_output_aufloesbar.py"))
    m = importlib.util.module_from_spec(s)
    sys.modules["_aufl_test"] = m
    s.loader.exec_module(m)
    return m


A = _lade()


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=str(repo), capture_output=True, text=True, check=True,
                   env={"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
                        "GIT_COMMITTER_EMAIL": "t@t", "HOME": str(repo), "PATH": "/usr/bin:/bin"})


@pytest.fixture()
def baum(tmp_path):
    """Ein Repo mit einer verfolgten Aufzeichnung und einer UNverfolgten daneben."""
    repo = tmp_path / "r"
    (repo / "audit_artifacts").mkdir(parents=True)
    _git(repo, "init", "-q")
    (repo / "audit_artifacts" / "lauf.md").write_text("die Aufzeichnung\n", encoding="utf-8")
    (repo / "README.md").write_text("# r\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "init")
    # bewusst NICHT hinzugefuegt: so sieht der fluechtige Fall von 5.0.0 aus
    (repo / "fluechtig.txt").write_text("nur im Arbeitsbaum\n", encoding="utf-8")
    return repo


def _digest(p: Path) -> str:
    return A.sha256_text(p.read_text(encoding="utf-8", errors="ignore"))


def test_verfolgte_datei_wird_gefunden_und_benannt(baum):
    """GRUENE KONTROLLE. Ohne sie misst der Negativfall nur 'findet nie etwas'."""
    d = _digest(baum / "audit_artifacts" / "lauf.md")
    r = A.aufloesbar({"audit_output_digest": d}, baum)
    assert r["zustand"] == "AUFLOESBAR", r
    assert r["treffer"] == ["audit_artifacts/lauf.md"], "der Treffer muss BENANNT werden, nicht nur gezaehlt"
    assert r["geprueft"] >= 2


def test_der_fall_500_eine_datei_ausserhalb_des_baums_loest_nicht_auf(baum):
    """DER GEMESSENE FALL. Der Digest gehoert zu einer Datei, die es gibt — aber nicht im Baum.
    Genau so sah das v5.0.0-Receipt aus, und genau das darf 5.1.0 nicht wiederholen."""
    d = _digest(baum / "fluechtig.txt")
    r = A.aufloesbar({"audit_output_digest": d}, baum)
    assert r["zustand"] == "NICHT_AUFLOESBAR", r
    assert r["treffer"] == []
    assert r["geprueft"] >= 2, "die Zahl der geprueften Dateien gehoert zum Negativurteil"
    assert str(r["geprueft"]) in r["grund"], "ein Negativbefund ohne Population ist ein Eindruck, keine Messung"


def test_fehlendes_feld_ist_NICHT_MESSBAR_weder_ja_noch_nein(baum):
    r = A.aufloesbar({"version": "5.1.0"}, baum)
    assert r["zustand"] == "NICHT_MESSBAR", r
    assert r["digest"] is None


def test_kaputtes_git_ist_NICHT_MESSBAR_nicht_NICHT_AUFLOESBAR(tmp_path):
    """DER UNTERSCHIED, DER ZAEHLT: 'ich habe alles durchsucht und nichts gefunden' ist ein Urteil,
    'ich konnte nicht suchen' ist keines. Eine leere Liste duerfte hier NIE als Negativ gelten."""
    kein_repo = tmp_path / "kein_repo"
    kein_repo.mkdir()
    r = A.aufloesbar({"audit_output_digest": "a" * 64}, kein_repo)
    assert r["zustand"] == "NICHT_MESSBAR", r
    assert r["geprueft"] == 0


def test_der_digest_wird_wie_im_receipt_gerechnet_nicht_ueber_rohbytes(baum):
    """Das Receipt rechnet ueber den DEKODIERTEN Text mit errors='ignore'. Bei einer Datei mit
    einem ungueltigen Byte weicht das von sha256sum ab — ein Pruefer, der Rohbytes hasht, meldete
    die richtige Datei als nicht auffindbar."""
    import hashlib
    p = baum / "audit_artifacts" / "mit_kaputtem_byte.md"
    p.write_bytes("Zeile\n".encode() + b"\xff" + "Ende\n".encode())
    _git(baum, "add", "-A")
    _git(baum, "commit", "-q", "-m", "byte")
    text_digest = A.sha256_text(p.read_text(encoding="utf-8", errors="ignore"))
    byte_digest = hashlib.sha256(p.read_bytes()).hexdigest()
    assert text_digest != byte_digest, "die Fixture trifft den Fall nicht — kein Unterschied zwischen Text und Bytes"
    r = A.aufloesbar({"audit_output_digest": text_digest}, baum)
    assert r["zustand"] == "AUFLOESBAR", "der Text-Digest muss gefunden werden"
    assert "mit_kaputtem_byte.md" in r["treffer"][0]
    r2 = A.aufloesbar({"audit_output_digest": byte_digest}, baum)
    assert r2["zustand"] == "NICHT_AUFLOESBAR", "der Byte-Digest darf NICHT passen — sonst rechnet der Pruefer falsch"


def test_exit_codes_trennen_alle_drei_zustaende(baum, tmp_path, capsys):
    d = _digest(baum / "audit_artifacts" / "lauf.md")
    q = tmp_path / "q.json"

    q.write_text(json.dumps({"audit_output_digest": d}), encoding="utf-8")
    assert A.main(["--receipt", str(q), "--repo", str(baum)]) == 0

    q.write_text(json.dumps({"audit_output_digest": _digest(baum / "fluechtig.txt")}), encoding="utf-8")
    assert A.main(["--receipt", str(q), "--repo", str(baum)]) == 1

    q.write_text(json.dumps({"version": "5.1.0"}), encoding="utf-8")
    assert A.main(["--receipt", str(q), "--repo", str(baum)]) == 2


def test_unlesbares_receipt_stuerzt_nicht_ab_sondern_meldet(tmp_path, baum):
    fehlt = tmp_path / "gibt_es_nicht.json"
    assert A.main(["--receipt", str(fehlt), "--repo", str(baum)]) == 2
