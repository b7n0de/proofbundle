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


# ── THE RELEASE STEP (--version), lesson 2 of 18 November 2026 ────────────────────────────────────
#
# An outside reader asked for the audit output of 6.6.0 and found none: the receipt verified, its
# `audit_output_digest` named no tracked file, and the output came into the tree only through pull
# request 538. From 6.6.1 on, release.yml runs `--version` right after the gate, so a tag whose audit
# output is not a tracked file stops before the build. The gate is replaced by `_Tor` where the test
# needs a verified receipt without a signing key; one case runs the real gate.

QUITTUNG = "audit_artifacts/661/pre_tag_receipt_v6.6.1.json"
#: The real gate loader, bound before any test replaces `A._gate` (a stand-in that asked `A._gate`
#: for the library would ask itself).
_ECHTES_TOR = A._gate
AUSGABE = "audit_artifacts/661/audit_output_v6.6.1.txt"


class _Tor:
    """A stand-in for `pre_tag_audit_gate`: `evaluate` answers as given, `_lib` is the real library."""

    def __init__(self, urteil):
        self.urteil = urteil

    def evaluate(self, repo, version):
        if isinstance(self.urteil, Exception):
            raise self.urteil
        return self.urteil

    def _lib(self):
        return _ECHTES_TOR()._lib()


def _verifiziert(*pfade):
    return {"ok": True, "state": "verified", "verified_receipts": [{"path": p, "reason": "x"} for p in pfade]}


@pytest.fixture()
def release(tmp_path):
    """A tree with the audit output of 6.6.1 tracked, in CRLF so that text and bytes differ."""
    repo = tmp_path / "rel"
    (repo / "audit_artifacts" / "661").mkdir(parents=True)
    _git(repo, "init", "-q")
    (repo / AUSGABE).write_bytes(b"28245 passed\r\n158 skipped\r\n")
    (repo / "README.md").write_text("# rel\n", encoding="utf-8")
    _git(repo, "add", ".")
    _git(repo, "commit", "-q", "-m", "init")
    return repo


def _bytes(p: Path) -> str:
    import hashlib
    return hashlib.sha256(p.read_bytes()).hexdigest()


def _quittung(repo: Path, rel: str, digest: str, *, committen: bool = True) -> None:
    """A receipt naming `digest`, committed by default: the step reads the receipt from the commit."""
    (repo / rel).parent.mkdir(parents=True, exist_ok=True)
    (repo / rel).write_text(json.dumps({"audit_output_digest": digest}), encoding="utf-8")
    if committen:
        _git(repo, "add", "--", rel)
        _git(repo, "commit", "-q", "-m", f"receipt {rel}")


def test_version_findet_die_verfolgte_ausgabe_ueber_ihre_rohen_bytes(release, monkeypatch, capsys):
    """GREEN CONTROL. The receipt names the digest of the raw bytes of a tracked file."""
    _quittung(release, QUITTUNG, _bytes(release / AUSGABE))
    monkeypatch.setattr(A, "_gate", lambda: _Tor(_verifiziert(QUITTUNG)))
    r = A.fuer_version(release, "6.6.1")
    assert r["zustand"] == "AUFLOESBAR", r
    assert r["quittungen"][0]["treffer"] == [AUSGABE], "der Treffer muss benannt werden"
    assert A.main(["--version", "6.6.1", "--repo", str(release)]) == 0


def test_version_eine_nicht_verfolgte_ausgabe_haelt_den_release_an(release, monkeypatch):
    """THE CASE OF 6.6.0. The output exists, but not in the tree."""
    fluechtig = release / "audit_output_ausserhalb.txt"
    fluechtig.write_bytes(b"nur im Arbeitsbaum\n")
    _quittung(release, QUITTUNG, _bytes(fluechtig))
    monkeypatch.setattr(A, "_gate", lambda: _Tor(_verifiziert(QUITTUNG)))
    r = A.fuer_version(release, "6.6.1")
    assert r["zustand"] == "NICHT_AUFLOESBAR", r
    assert A.main(["--version", "6.6.1", "--repo", str(release)]) == 1


def test_version_rechnet_ueber_die_bytes_nicht_ueber_den_text(release, monkeypatch):
    """A reader outside hashes the bytes (sha256sum), and so does the producer. A receipt with the
    text digest of a CRLF file does NOT resolve for the release, while `--receipt` (the older reading)
    resolves it. Without this case a `--version` that takes the text would go unnoticed."""
    text = A.sha256_text((release / AUSGABE).read_text(encoding="utf-8", errors="ignore"))
    assert text != _bytes(release / AUSGABE), "die Fixture trennt Text und Bytes nicht"
    _quittung(release, QUITTUNG, text)
    monkeypatch.setattr(A, "_gate", lambda: _Tor(_verifiziert(QUITTUNG)))
    assert A.fuer_version(release, "6.6.1")["zustand"] == "NICHT_AUFLOESBAR"
    assert A.aufloesbar({"audit_output_digest": text}, release)["zustand"] == "AUFLOESBAR"


def test_version_ohne_verifizierte_quittung_ist_NICHT_MESSBAR(release, monkeypatch, capsys):
    monkeypatch.setattr(A, "_gate", lambda: _Tor({"ok": False, "state": "absent", "verified_receipts": []}))
    r = A.fuer_version(release, "6.6.1")
    assert r["zustand"] == "NICHT_MESSBAR" and r["gate_state"] == "absent", r
    assert A.main(["--version", "6.6.1", "--repo", str(release)]) == 2


def test_version_ein_tor_das_nicht_urteilen_kann_ist_NICHT_MESSBAR(release, monkeypatch):
    monkeypatch.setattr(A, "_gate", lambda: _Tor(RuntimeError("kaputt")))
    r = A.fuer_version(release, "6.6.1")
    assert r["zustand"] == "NICHT_MESSBAR" and "kaputt" in r["grund"], r


def test_version_eine_von_zwei_quittungen_loest_nicht_auf(release, monkeypatch):
    """A finding at one receipt stops the release, whatever lies beside it; both are named."""
    zweite = "audit_artifacts/661/pre_tag_receipt_v6.6.1_b.json"
    _quittung(release, QUITTUNG, _bytes(release / AUSGABE))
    _quittung(release, zweite, "b" * 64)
    monkeypatch.setattr(A, "_gate", lambda: _Tor(_verifiziert(QUITTUNG, zweite)))
    r = A.fuer_version(release, "6.6.1")
    assert r["zustand"] == "NICHT_AUFLOESBAR", r
    assert [q["pfad"] for q in r["quittungen"]] == [QUITTUNG, zweite]
    assert [q["zustand"] for q in r["quittungen"]] == ["AUFLOESBAR", "NICHT_AUFLOESBAR"]


def test_version_eine_unlesbare_quittung_ist_NICHT_MESSBAR(release, monkeypatch):
    monkeypatch.setattr(A, "_gate", lambda: _Tor(_verifiziert("audit_artifacts/661/fehlt.json")))
    r = A.fuer_version(release, "6.6.1")
    assert r["zustand"] == "NICHT_MESSBAR", r


def test_version_gegen_das_echte_tor_ohne_quittung(release):
    """The real gate, without a stand-in. Without a receipt it rules `absent`, and the step measures nothing."""
    r = A.fuer_version(release, "6.6.1")
    assert r["zustand"] == "NICHT_MESSBAR", r
    assert r["gate_state"] == "absent", r


def test_receipt_und_version_schliessen_einander_aus(release, tmp_path):
    q = tmp_path / "q.json"
    q.write_text("{}", encoding="utf-8")
    with pytest.raises(SystemExit) as beide:
        A.main(["--receipt", str(q), "--version", "6.6.1", "--repo", str(release)])
    assert beide.value.code == 2
    with pytest.raises(SystemExit) as keins:
        A.main(["--repo", str(release)])
    assert keins.value.code == 2


def test_version_ein_tor_das_ablehnt_gibt_keine_quittung_frei_auch_mit_verifizierter_daneben(release, monkeypatch):
    """The real gate reports `ok=False` when a rejected receipt lies beside a verified one (DELTA2 N1).
    The step must not then judge the verified receipt as if nothing were wrong."""
    _quittung(release, QUITTUNG, _bytes(release / AUSGABE))
    urteil = {"ok": False, "state": "rejected", "verified_receipts": [{"path": QUITTUNG, "reason": "x"}]}
    monkeypatch.setattr(A, "_gate", lambda: _Tor(urteil))
    r = A.fuer_version(release, "6.6.1")
    assert r["zustand"] == "NICHT_MESSBAR" and r["gate_state"] == "rejected", r


# ── THE STEP READS THE COMMIT, NOT THE WORKING TREE (Codex on pull request 541, P2) ───────────────
#
# A committed symbolic link to an untracked record outside the tree passed as AUFLOESBAR, because the
# step listed the tracked paths and read each from disk, following the link. A tracked file modified
# on disk and a file that is only staged are the same mismatch, and so is a receipt whose bytes on
# disk are not the committed ones. Each case below fails against the reading from disk.


def test_version_ein_symlink_auf_eine_datei_ausserhalb_loest_nicht_auf(release, tmp_path, monkeypatch):
    """THE CASE CODEX MEASURED. The link is committed, the record it points to is not."""
    aussen = tmp_path / "aussen_audit_output.txt"
    aussen.write_bytes(b"the record outside the commit\n")
    link = release / "audit_artifacts" / "661" / "verweis.txt"
    try:
        link.symlink_to(aussen)
    except OSError as exc:
        pytest.skip(f"this file system refuses a symbolic link: {exc}")
    _git(release, "add", "--", "audit_artifacts/661/verweis.txt")
    _git(release, "commit", "-q", "-m", "a link to a record outside the commit")
    _quittung(release, QUITTUNG, _bytes(aussen))
    monkeypatch.setattr(A, "_gate", lambda: _Tor(_verifiziert(QUITTUNG)))
    r = A.fuer_version(release, "6.6.1")
    assert r["zustand"] == "NICHT_AUFLOESBAR", r
    assert r["quittungen"][0]["treffer"] == [], r
    assert A.aufloesbar({"audit_output_digest": A.sha256_text(aussen.read_text(encoding="utf-8"))},
                        release)["zustand"] == "NICHT_AUFLOESBAR", "--receipt reads the commit as well"


def test_version_eine_geaenderte_verfolgte_datei_zaehlt_mit_dem_inhalt_des_commits(release, monkeypatch):
    """The output on disk is changed after the commit. The digest of the new bytes names no file of
    the commit; the digest of the committed bytes still does."""
    committet = _bytes(release / AUSGABE)
    (release / AUSGABE).write_bytes(b"other bytes on disk\n")
    _quittung(release, QUITTUNG, _bytes(release / AUSGABE))
    monkeypatch.setattr(A, "_gate", lambda: _Tor(_verifiziert(QUITTUNG)))
    assert A.fuer_version(release, "6.6.1")["zustand"] == "NICHT_AUFLOESBAR"
    zweite = "audit_artifacts/661/pre_tag_receipt_v6.6.1_c.json"
    _quittung(release, zweite, committet)
    monkeypatch.setattr(A, "_gate", lambda: _Tor(_verifiziert(zweite)))
    r = A.fuer_version(release, "6.6.1")
    assert r["zustand"] == "AUFLOESBAR" and r["quittungen"][0]["treffer"] == [AUSGABE], r


def test_version_eine_nur_gestagte_datei_loest_nicht_auf(release, monkeypatch):
    """Staged is not committed: the tag would not carry it."""
    gestaged = release / "audit_artifacts" / "661" / "nur_gestaged.txt"
    gestaged.write_bytes(b"staged, never committed\n")
    _git(release, "add", "--", "audit_artifacts/661/nur_gestaged.txt")
    _quittung(release, QUITTUNG, _bytes(gestaged), committen=False)
    _git(release, "add", "--", QUITTUNG)
    _git(release, "commit", "-q", "-m", "receipt only", "--", QUITTUNG)
    monkeypatch.setattr(A, "_gate", lambda: _Tor(_verifiziert(QUITTUNG)))
    r = A.fuer_version(release, "6.6.1")
    assert r["zustand"] == "NICHT_AUFLOESBAR", r


def test_version_eine_quittung_nur_im_arbeitsbaum_ist_NICHT_MESSBAR(release, monkeypatch):
    """The gate judged a receipt the commit does not carry: there is nothing to resolve for the tag."""
    _quittung(release, QUITTUNG, _bytes(release / AUSGABE), committen=False)
    monkeypatch.setattr(A, "_gate", lambda: _Tor(_verifiziert(QUITTUNG)))
    r = A.fuer_version(release, "6.6.1")
    assert r["zustand"] == "NICHT_MESSBAR", r
    assert "regular file of the head commit" in r["grund"], r


def test_version_eine_im_arbeitsbaum_geaenderte_quittung_ist_NICHT_MESSBAR(release, monkeypatch):
    """The committed receipt names the committed output, the one on disk names other bytes. The gate
    read the one on disk, so its verdict is not about the commit."""
    _quittung(release, QUITTUNG, _bytes(release / AUSGABE))
    (release / QUITTUNG).write_text(json.dumps({"audit_output_digest": "c" * 64}), encoding="utf-8")
    monkeypatch.setattr(A, "_gate", lambda: _Tor(_verifiziert(QUITTUNG)))
    r = A.fuer_version(release, "6.6.1")
    assert r["zustand"] == "NICHT_MESSBAR", r
    assert "not the one the head commit carries" in r["grund"], r


def test_version_der_text_eines_symlinks_ist_keine_datei_des_commits(release, tmp_path, monkeypatch):
    """A link's blob carries the NAME of its target. A reader who checks out the tag and runs sha256sum
    on that path hashes the target, never that name, so the name must not resolve either."""
    link = release / "audit_artifacts" / "661" / "nur_ein_name.txt"
    try:
        link.symlink_to("gibt_es_nicht.txt")
    except OSError as exc:
        pytest.skip(f"this file system refuses a symbolic link: {exc}")
    _git(release, "add", "--", "audit_artifacts/661/nur_ein_name.txt")
    _git(release, "commit", "-q", "-m", "a dangling link")
    import hashlib
    _quittung(release, QUITTUNG, hashlib.sha256(b"gibt_es_nicht.txt").hexdigest())
    monkeypatch.setattr(A, "_gate", lambda: _Tor(_verifiziert(QUITTUNG)))
    assert A.fuer_version(release, "6.6.1")["zustand"] == "NICHT_AUFLOESBAR"
