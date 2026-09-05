"""KLASSE A — Provenienz und Kandidatenbindung freigabeentscheidender Evidenz (L5-G7-02, P2).

DIE EIGENSCHAFT, ausfuehrbar formuliert und hier gemessen. Eine Pruefung in
``scripts/audit_candidate_matrix.py``, die NICHT in ``_INFORMATIVE_CHECKS`` steht, darf ein Bestehen
nur aus Evidenz bilden, die

  P-A1  eine ed25519-Signatur ueber den kanonischen Bytes ihres GESAMTEN Rumpfes traegt, die unter
        einem EINGECHECKTEN Vertrauensanker verifiziert,
  P-A2  den exakten Kandidaten bindet (Commit, Baumkennung, sdist- und wheel-Digest), wobei die
        Baumkennung gegen den lebenden Baum nachgerechnet wird,
  P-A3  Schema, Erzeuger, Werkzeugversion, Eingabe-Digest, Zeit und Signiererrolle nennt,
  P-A4  frisch ist,
  P-A5  Arbeitszaehler ungleich null traegt — ein signiertes „ok" ueber Nullzaehlern ist kein Beleg,
  P-A6  ihren eigenen Erfolgs- und Fehlerfeldern nicht widerspricht,
  P-A7  und deren Aussage ausschliesslich aus den SIGNIERTEN Feldern gebildet wird.

Fehlen, Versionsabweichung, fehlende Kandidatenbindung, leere Zaehlermenge oder ein selbsterklaerter
Fehlschlag muessen zu FAIL oder DATA_BLOCKED fuehren, nie zu PASS. DATA_BLOCKED ausschliesslich dann,
wenn die UMGEBUNG nicht messen kann.

KEINE PUNKTFIXTURE. Gemessen wird eine MATRIX erfundener Evidenz gegen JEDEN freigabeentscheidenden
Leser (C6.2, C6.3, C8.2) — und die Matrix traegt ihre Anti-Paritaets-Zeile: die echte, signierte,
kandidatsgebundene Evidenz MUSS bestehen, sonst bestuende ein Fix, der alles ablehnt, diese Pruefung.

ABGRENZUNG (Auflage C3 des Gegenlesers): das ist NICHT dieselbe Klasse wie L5-G7-04. Dort wird eine
AUSFUEHRUNG aus QUELLTEXT abgeleitet; das steht in
``tests/test_ausfuehrung_aus_quelltext_l5_g7_04.py`` mit eigener Eigenschaft und eigenem Orakel. Ein
Signaturanker haette jenen Fund nicht verhindert, eine YAML-Analyse diesen nicht.
"""
from __future__ import annotations

import base64
import copy
import hashlib
import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
for _sub in ("src", "scripts"):
    _p = str(REPO / _sub)
    if _p not in sys.path:
        sys.path.insert(0, _p)


def _code_ohne_doku(quelle: str, fn_name: str) -> str:
    """Der AUSFUEHRBARE Rumpf einer Funktion, ohne Docstring und ohne Kommentare.

    WARUM DAS NOETIG IST, und es ist selbst ein kleiner Fund dieser Runde: die erste Fassung dieses
    Tests schnitt den Rumpf als Text aus und fand die alte, lexikalische Zeile — ZITIERT IM
    DOCSTRING, der erklaert, warum sie weg ist. Ein Quelltext-Orakel, das Prosa mitliest, misst die
    Erklaerung statt des Codes. `ast` kennt den Unterschied: Kommentare gibt es dort nicht mehr, und
    der Docstring ist ein benannter Knoten, den man entfernen kann.
    """
    import ast  # noqa: PLC0415
    baum = ast.parse(quelle)
    for knoten in ast.walk(baum):
        if isinstance(knoten, ast.FunctionDef) and knoten.name == fn_name:
            koerper = list(knoten.body)
            if (koerper and isinstance(koerper[0], ast.Expr)
                    and isinstance(koerper[0].value, ast.Constant)
                    and isinstance(koerper[0].value.value, str)):
                koerper = koerper[1:]
            return "\n".join(ast.unparse(k) for k in koerper)
    raise AssertionError(f"Funktion {fn_name!r} nicht gefunden — der Test misst nichts")


def _matrix_modul():
    spec = importlib.util.spec_from_file_location(
        "_acm_klasse_a", str(REPO / "scripts" / "audit_candidate_matrix.py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules["_acm_klasse_a"] = m
    spec.loader.exec_module(m)
    return m


try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    _KRYPTO = True
except ImportError:                                          # pragma: no cover
    _KRYPTO = False

_braucht_krypto = pytest.mark.skipif(
    not _KRYPTO, reason="cryptography fehlt — ohne Signierfaehigkeit ist die Anti-Paritaets-Haelfte "
                        "nicht messbar, und eine Matrix ohne sie misst nur Ablehnung")

VERSION = "9.9.9"
_JETZT = datetime.now(timezone.utc)


def _z(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True, check=True)


def _baum_digest(repo: Path) -> str:
    """Dieselbe Groesse, die das Tor nachrechnet — bewusst UNABHAENGIG hier nachgebaut, damit das
    Orakel nicht die Funktion aufruft, die es prueft."""
    out = _git(repo, "ls-tree", "HEAD").stdout
    zeilen = [ln for ln in out.splitlines() if not ln.endswith("\taudit_artifacts")]
    return hashlib.sha256("\n".join(sorted(zeilen)).encode("utf-8")).hexdigest()


_SOAK_GUT = {
    "schema": "proofbundle.fuzz_soak.v1",
    "seed": 7,
    "requested_duration_seconds": 90.0,
    "elapsed_seconds": 90.0,
    "is_full_soak_24h": False,
    "iterations": 582120,
    "parsers_soaked": 27,
    "untriaged_crashes": [],
    "untriaged_crash_count": 0,
    "false_accepts": [],
    "false_accept_count": 0,
    "ok": True,
}

_DIFF_GUT = {
    "schema": "proofbundle.rust_relation_differential_matrix.v1",
    "total_relation_vectors": 2,
    "all_agree": True,
    "rows": [
        {"caseId": "a", "agree_python_rust": True},
        {"caseId": "b", "agree_python_rust": True},
    ],
}


class Leser:
    """Ein freigabeentscheidender Evidenz-Leser: seine Pruefung, sein Pfad, seine gute Evidenz."""

    def __init__(self, cid, fn_name, rel, gut, absent_ist_umgebung):
        self.cid, self.fn_name, self.rel, self.gut = cid, fn_name, rel, gut
        # Darf DIESE Pflicht eine ABWESENHEIT als Umgebungsaussage lesen? (C6.3: ja, keine Soak-Box;
        # C8.2: ja, wenn die Rust-Binaerdatei fehlt; C6.2: nein, ein kurzer Soak laeuft ueberall.)
        self.absent_ist_umgebung = absent_ist_umgebung

    def __repr__(self):
        return self.cid


LESER = [
    Leser("C6.2", "c6_2_recorded_soak_clean", "audit_artifacts/360/fuzz_soak_latest.json",
          _SOAK_GUT, False),
    Leser("C6.3", "c6_3_full_24h", "audit_artifacts/360/fuzz_soak_latest.json", _SOAK_GUT, True),
    Leser("C8.2", "c8_2_differential_agrees", "audit_artifacts/360/rust_differential_matrix.json",
          _DIFF_GUT, True),
]


def _nullzaehler(b):
    for feld in ("iterations", "parsers_soaked", "elapsed_seconds", "total_relation_vectors"):
        if feld in b:
            b[feld] = 0


def _selbst_widersprechend(b):
    b["ok"] = False
    if "untriaged_crashes" in b:
        b["untriaged_crashes"] = ["a raw crash the counter never counted"]
        b["untriaged_crash_count"] = 1
    if "rows" in b:
        b["rows"][0]["agree_python_rust"] = False


def _zaehler_gegen_liste(b):
    if "untriaged_crashes" in b:
        b["untriaged_crashes"] = ["a raw crash the counter never counted"]   # count bleibt 0
    else:
        b["total_relation_vectors"] = 99                                     # rows bleiben 2


def _mut(fn):
    return ("body", fn)


def _roh(bytes_):
    return ("raw", bytes_)


# ── Die Matrix: erfundene Evidenz, jede Zelle eine eigene Verletzung ──────────────────────────
#
# Jede Zelle ist (name, zelle, sicher_fail). ``sicher_fail`` sagt, ob das Urteil in einer messbaren
# Umgebung genau FAIL sein MUSS; wo es False ist, genuegt „nicht PASS" (die Zelle beruehrt eine
# Pflicht, die eine ABWESENHEIT als Umgebungsaussage lesen darf).
def matrix_zellen():
    alt = _z(_JETZT - timedelta(days=400))
    zukunft = _z(_JETZT + timedelta(days=3))
    return [
        ("fehlend", ("missing", None), False),
        ("null_byte", _roh(b""), True),
        ("leeres_objekt", _roh(b"{}"), True),
        ("zwei_schluessel_ohne_substanz",
         _roh(json.dumps({"untriaged_crash_count": 0, "false_accept_count": 0}).encode()), True),
        ("schema_falsch", _mut(lambda b: b.__setitem__("schema", "etwas.anderes.v1")), True),
        ("versionsabweichend", _mut(lambda b: b.__setitem__("version", "3.6.0")), True),
        ("version_fehlt", _mut(lambda b: b.pop("version", None)), True),
        ("kandidat_fehlt", _mut(lambda b: b.pop("candidate", None)), True),
        ("kandidat_fremder_baum",
         _mut(lambda b: b["candidate"].__setitem__("tree_digest", "0" * 64)), True),
        ("kandidat_ohne_wheel", _mut(lambda b: b["candidate"].pop("wheel_sha256", None)), True),
        ("kandidat_commit_unformig",
         _mut(lambda b: b["candidate"].__setitem__("commit", "nicht-hex")), True),
        ("erzeuger_fehlt", _mut(lambda b: b.pop("producer", None)), True),
        ("werkzeugversion_fehlt", _mut(lambda b: b["producer"].pop("tool_version", None)), True),
        ("eingabe_digest_fehlt", _mut(lambda b: b.pop("input_digest", None)), True),
        ("signiererrolle_fehlt", _mut(lambda b: b.pop("signer_role", None)), True),
        ("zeit_fehlt", _mut(lambda b: b.pop("produced_at", None)), True),
        ("zeit_aus_der_zukunft", _mut(lambda b: b.__setitem__("produced_at", zukunft)), True),
        ("zeit_zu_alt", _mut(lambda b: b.__setitem__("produced_at", alt)), True),
        ("nullzaehler", _mut(_nullzaehler), True),
        ("selbst_widersprechend", _mut(_selbst_widersprechend), True),
        ("zaehler_gegen_liste", _mut(_zaehler_gegen_liste), True),
        ("unsigniert_sonst_makellos", ("unsigned", None), True),
        ("fremder_schluessel", ("foreign_key", None), True),
        ("nach_dem_signieren_veraendert", ("tampered", None), True),
    ]


@pytest.fixture(scope="module")
def welt():
    """Ein echter kleiner git-Baum mit EINGECHECKTEM Vertrauensanker.

    Warum ein echter Baum: der Anker wird aus dem COMMITTETEN Blob gelesen und die Baumkennung
    gegen ``git ls-tree HEAD`` nachgerechnet. Beides in einem tmp-Verzeichnis ohne git zu messen
    hiesse, die Umgebung statt der Evidenz zu pruefen — dann waere jede Zelle DATA_BLOCKED und die
    Matrix saehe gruen aus, ohne irgendetwas ueber die Evidenz zu sagen.
    """
    if not _KRYPTO:
        pytest.skip("cryptography fehlt")
    td = Path(tempfile.mkdtemp(prefix="klasse_a_"))
    try:
        start = subprocess.run(["git", "init", "-q", str(td)], capture_output=True, text=True)
        if start.returncode != 0:
            pytest.skip(f"git ist hier nicht benutzbar: {start.stderr.strip()}")
        schluessel = Ed25519PrivateKey.generate()
        pub = base64.b64encode(schluessel.public_key().public_bytes_raw()).decode()
        fremd = Ed25519PrivateKey.generate()
        (td / "pyproject.toml").write_text(f'[project]\nversion = "{VERSION}"\n', encoding="utf-8")
        (td / "audit_artifacts").mkdir(parents=True, exist_ok=True)
        (td / "audit_artifacts" / "readiness_trusted_pubkeys.txt").write_text(
            "# test anchor\n" + pub + "\n", encoding="utf-8")
        _git(td, "add", "-A")
        _git(td, "-c", "user.email=a@b", "-c", "user.name=a", "commit", "-q", "-m", "anchor")
        yield {"repo": td, "key": schluessel, "pub": pub, "foreign": fremd,
               "commit": _git(td, "rev-parse", "HEAD").stdout.strip(), "tree": _baum_digest(td)}
    finally:
        shutil.rmtree(td, ignore_errors=True)


def _rumpf(welt, gut: dict) -> dict:
    b = copy.deepcopy(gut)
    b["version"] = VERSION
    b["candidate"] = {"commit": welt["commit"], "tree_digest": welt["tree"],
                      "sdist_sha256": "a" * 64, "wheel_sha256": "b" * 64}
    b["producer"] = {"tool": "scripts/fuzz_soak.py", "tool_version": VERSION}
    b["input_digest"] = "c" * 64
    b["signer_role"] = "release-runner"
    b["produced_at"] = _z(_JETZT - timedelta(hours=1))
    return b


def _signiere(rumpf: dict, key) -> dict:
    from proofbundle import canonical
    msg = canonical.canonicalize_statement({k: v for k, v in rumpf.items() if k != "signature"})
    out = dict(rumpf)
    out["signature"] = {
        "alg": "ed25519",
        "public_key_b64": base64.b64encode(key.public_key().public_bytes_raw()).decode(),
        "sig_b64": base64.b64encode(key.sign(msg)).decode()}
    return out


def _lege_ab(welt, leser: Leser, zelle) -> None:
    """Schreibt die Evidenz der Zelle an ihren Ort (oder loescht sie)."""
    ziel = welt["repo"] / leser.rel
    ziel.parent.mkdir(parents=True, exist_ok=True)
    art, nutzlast = zelle
    if art == "missing":
        if ziel.exists():
            ziel.unlink()
        return
    if art == "raw":
        ziel.write_bytes(nutzlast)
        return
    rumpf = _rumpf(welt, leser.gut)
    if art == "body":
        nutzlast(rumpf)
        ziel.write_text(json.dumps(_signiere(rumpf, welt["key"]), indent=2), encoding="utf-8")
        return
    if art == "unsigned":
        ziel.write_text(json.dumps(rumpf, indent=2), encoding="utf-8")
        return
    if art == "foreign_key":
        ziel.write_text(json.dumps(_signiere(rumpf, welt["foreign"]), indent=2), encoding="utf-8")
        return
    if art == "tampered":
        signiert = _signiere(rumpf, welt["key"])
        signiert["iterations"] = 1                       # nach dem Signieren veraendert
        signiert["total_relation_vectors"] = 1
        ziel.write_text(json.dumps(signiert, indent=2), encoding="utf-8")
        return
    raise AssertionError(f"unbekannte Zellenart {art!r}")


def _urteile(welt, leser: Leser):
    m = _matrix_modul()
    m.REPO = welt["repo"]
    m.VERSION_UNDER_TEST = VERSION
    return getattr(m, leser.fn_name)(), m


@_braucht_krypto
@pytest.mark.parametrize("leser", LESER, ids=[le.cid for le in LESER])
def test_die_matrix_erteilt_kein_einziges_bestehen(welt, leser):
    """JEDE Zelle der Matrix gegen JEDEN freigabeentscheidenden Leser: nie PASS.

    Das Orakel steht in der Tabelle, nicht im Code, den es prueft: eine Zelle ist genau dann in
    Ordnung, wenn ihr Urteil FAIL oder DATA_BLOCKED ist — und in einer messbaren Umgebung ist es
    fuer alles, was am ARTEFAKT liegt, genau FAIL (Auflage C2: DATA_BLOCKED heisst ausschliesslich
    „diese Umgebung kann nicht messen").
    """
    zellen = matrix_zellen()
    gesehen = {}
    for name, zelle, sicher_fail in zellen:
        _lege_ab(welt, leser, zelle)
        (verdikt, grund), m = _urteile(welt, leser)
        gesehen[name] = verdikt
        assert verdikt != m.PASS, f"{leser.cid}/{name} erteilte ein Bestehen: {grund}"
        assert verdikt in (m.FAIL, m.DATA_BLOCKED), f"{leser.cid}/{name} -> {verdikt}: {grund}"
        if sicher_fail:
            assert verdikt == m.FAIL, (
                f"{leser.cid}/{name} meldete {verdikt} statt FAIL — eine Aussage ueber die Evidenz "
                f"darf nicht als Umgebungsmangel erscheinen: {grund}")
        elif name == "fehlend":
            # DIE EINE ZELLE, deren richtige Antwort je Pflicht ANDERS lautet — und sie wird deshalb
            # je Pflicht festgeschrieben statt mit „nicht PASS" durchgewinkt. Sonst waere
            # `absent_ist_umgebung` ein Feld, das wie ein Riegel aussieht und keiner ist.
            erwartet = m.DATA_BLOCKED if leser.absent_ist_umgebung else m.FAIL
            assert verdikt == erwartet, (
                f"{leser.cid}/fehlend meldete {verdikt}, erwartet {erwartet}: eine fehlende Evidenz "
                f"heisst bei dieser Pflicht "
                f"{'diese Umgebung erzeugt sie nicht' if leser.absent_ist_umgebung else 'sie fehlt'}"
                f" — {grund}")
    assert len(gesehen) == len(zellen)


@_braucht_krypto
@pytest.mark.parametrize("leser", LESER, ids=[le.cid for le in LESER])
def test_anti_paritaet_die_echte_signierte_evidenz_besteht(welt, leser):
    """ANTI-PARITAET, und sie ist die Haelfte, die die Matrix ueberhaupt wertvoll macht: ein Fix,
    der ALLES ablehnt, bestuende jede Zelle oben und waere wertlos."""
    ziel = welt["repo"] / leser.rel
    ziel.parent.mkdir(parents=True, exist_ok=True)
    rumpf = _rumpf(welt, leser.gut)
    if leser.cid == "C6.3":                      # diese Pflicht verlangt zusaetzlich die vollen 24h
        rumpf["elapsed_seconds"] = 86400.0
        rumpf["is_full_soak_24h"] = True
    ziel.write_text(json.dumps(_signiere(rumpf, welt["key"]), indent=2), encoding="utf-8")
    (verdikt, grund), m = _urteile(welt, leser)
    assert verdikt == m.PASS, (
        f"{leser.cid} lehnte echte, signierte, kandidatsgebundene Evidenz ab: {grund}")


@_braucht_krypto
def test_ohne_eingecheckten_anker_ist_makellose_evidenz_ungueltig(welt):
    """Ein Repo, das keinen Anker eincheckt, kann keine Signatur zuordnen — das ist eine Aussage
    ueber die EVIDENZ (FAIL), nicht ueber die Umgebung."""
    td = Path(tempfile.mkdtemp(prefix="klasse_a_leer_"))
    try:
        start = subprocess.run(["git", "init", "-q", str(td)], capture_output=True, text=True)
        if start.returncode != 0:
            pytest.skip("git ist hier nicht benutzbar")
        (td / "pyproject.toml").write_text(f'[project]\nversion = "{VERSION}"\n', encoding="utf-8")
        (td / "audit_artifacts").mkdir(parents=True, exist_ok=True)
        (td / "audit_artifacts" / "readiness_trusted_pubkeys.txt").write_text(
            "# no keys pinned yet\n", encoding="utf-8")
        _git(td, "add", "-A")
        _git(td, "-c", "user.email=a@b", "-c", "user.name=a", "commit", "-q", "-m", "leer")
        eigene = {"repo": td, "commit": _git(td, "rev-parse", "HEAD").stdout.strip(),
                  "tree": _baum_digest(td)}
        ziel = td / "audit_artifacts" / "360" / "fuzz_soak_latest.json"
        ziel.parent.mkdir(parents=True, exist_ok=True)
        ziel.write_text(json.dumps(_signiere(_rumpf(eigene, _SOAK_GUT), welt["key"]), indent=2),
                        encoding="utf-8")
        m = _matrix_modul()
        m.REPO = td
        m.VERSION_UNDER_TEST = VERSION
        verdikt, grund = m.c6_2_recorded_soak_clean()
        assert verdikt == m.FAIL, f"ein Repo ohne Anker liess Evidenz zu: {verdikt} {grund}"
        assert "trusted key" in grund
    finally:
        shutil.rmtree(td, ignore_errors=True)


@_braucht_krypto
def test_ein_nicht_messbarer_baum_ist_DATA_BLOCKED_und_nie_ein_bestehen(welt):
    """Die GEGENSEITE der Auflage C2: kann die Umgebung wirklich nicht messen (kein git-Baum), ist
    das DATA_BLOCKED — und ausdruecklich weiterhin kein Bestehen."""
    td = Path(tempfile.mkdtemp(prefix="klasse_a_ohnegit_"))
    try:
        ziel = td / "audit_artifacts" / "360" / "fuzz_soak_latest.json"
        ziel.parent.mkdir(parents=True, exist_ok=True)
        ziel.write_text(json.dumps(_signiere(_rumpf(welt, _SOAK_GUT), welt["key"]), indent=2),
                        encoding="utf-8")
        m = _matrix_modul()
        m.REPO = td
        m.VERSION_UNDER_TEST = VERSION
        verdikt, grund = m.c6_2_recorded_soak_clean()
        assert verdikt == m.DATA_BLOCKED, f"{verdikt}: {grund}"
        assert verdikt != m.PASS
    finally:
        shutil.rmtree(td, ignore_errors=True)


@_braucht_krypto
def test_die_zeile_liest_nur_signierte_felder(welt):
    """P-A7 STRUKTURELL: bei ``ART_VERIFIED`` liefert der Helfer ``signed_body`` OHNE den
    Signatur-Umschlag. Ein Feld, das nicht mitsigniert wurde, existiert auf diesem Weg nicht — es
    gibt keinen Platz dafuer, weil der Umschlag das einzige unsignierte Element ist."""
    m = _matrix_modul()
    ziel = welt["repo"] / "audit_artifacts" / "360" / "fuzz_soak_latest.json"
    ziel.parent.mkdir(parents=True, exist_ok=True)
    ziel.write_text(json.dumps(_signiere(_rumpf(welt, _SOAK_GUT), welt["key"]), indent=2),
                    encoding="utf-8")
    res = m._signed_versioned_artifact(
        "audit_artifacts/360/fuzz_soak_latest.json", VERSION, repo=welt["repo"],
        schema="proofbundle.fuzz_soak.v1", counters=("iterations",))
    assert res["state"] == m.ART_VERIFIED, res["detail"]
    assert "signature" not in res["signed_body"], "der Umschlag darf nicht im zugelassenen Rumpf stehen"
    from proofbundle import canonical
    roh = json.loads(ziel.read_text(encoding="utf-8"))
    assert canonical.canonicalize_statement(res["signed_body"]) == canonical.canonicalize_statement(
        {k: v for k, v in roh.items() if k != "signature"}), \
        "der zugelassene Rumpf ist nicht byte-gleich mit dem signierten"


@_braucht_krypto
def test_der_erzeuger_erzeugt_genau_das_was_das_tor_zulaesst(welt):
    """ERZEUGER GEGEN VERBRAUCHER, in einem Durchgang.

    Ein Riegel ohne Weg daran vorbei ist kein Riegel, sondern eine Sackgasse: es MUSS ein Werkzeug
    geben, das zulassbare Evidenz herstellt, und seine Bytes muessen exakt die sein, die das Tor
    nachrechnet. Genau hier faellt eine Kanonisierungs-Abweichung auf — die Art Fehler, die sonst
    erst bei der Freigabe auffaellt, wenn niemand mehr Zeit hat.

    Gefahren wird ``scripts/sign_readiness_artifact.py`` als PROZESS, nicht als Import: so wird
    dieselbe Kommandozeile gemessen, die ein Laeufer spaeter tippt.
    """
    m = _matrix_modul()
    roh = welt["repo"] / "roh_soak.json"
    roh.write_text(json.dumps(_SOAK_GUT, indent=2), encoding="utf-8")
    key_datei = welt["repo"] / "privkey.b64"
    key_datei.write_text(
        base64.b64encode(welt["key"].private_bytes_raw()).decode() + "\n", encoding="utf-8")
    ziel = welt["repo"] / "audit_artifacts" / "360" / "fuzz_soak_latest.json"
    ziel.parent.mkdir(parents=True, exist_ok=True)
    r = subprocess.run(
        [sys.executable, str(REPO / "scripts" / "sign_readiness_artifact.py"),
         "--repo", str(welt["repo"]), "--in", str(roh), "--out", str(ziel),
         "--producer-tool", "scripts/fuzz_soak.py", "--producer-tool-version", VERSION,
         "--input-digest", "d" * 64, "--signer-role", "release-runner",
         "--sdist-sha256", "a" * 64, "--wheel-sha256", "b" * 64,
         "--privkey-file", str(key_datei)],
        capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, f"der Erzeuger scheiterte: {r.stdout}\n{r.stderr}"
    m.REPO = welt["repo"]
    m.VERSION_UNDER_TEST = VERSION
    verdikt, grund = m.c6_2_recorded_soak_clean()
    assert verdikt == m.PASS, (
        f"das Tor lehnt ab, was sein eigener Erzeuger herstellt: {grund}\n{r.stdout}")
    gebaut = json.loads(ziel.read_text(encoding="utf-8"))
    for feld in ("candidate", "producer", "input_digest", "signer_role", "produced_at", "signature"):
        assert feld in gebaut, f"der Erzeuger legt {feld} nicht an"
    assert gebaut["candidate"]["tree_digest"] == welt["tree"]
    assert gebaut["candidate"]["commit"] == welt["commit"]

    # ── DIE SCHLUESSELLOSE ZWEITEILUNG, und sie wird gefahren statt nur beschrieben ──────────────
    # Der Freigabe-Schluessel liegt beim Owner, nicht auf dem Bauwirt. Deshalb gibt es emit/assemble
    # — und ein Modus, den nie jemand faehrt, ist eine Zusage, keine Faehigkeit.
    nutzlast = welt["repo"] / "payload.bin"
    kontext = welt["repo"] / "context.json"
    ziel2 = welt["repo"] / "audit_artifacts" / "360" / "fuzz_soak_latest.json"
    r2 = subprocess.run(
        [sys.executable, str(REPO / "scripts" / "sign_readiness_artifact.py"),
         "--repo", str(welt["repo"]), "--in", str(roh),
         "--producer-tool", "scripts/fuzz_soak.py", "--producer-tool-version", VERSION,
         "--input-digest", "d" * 64, "--signer-role", "release-runner",
         "--sdist-sha256", "a" * 64, "--wheel-sha256", "b" * 64,
         "--emit-payload", str(nutzlast), "--context-out", str(kontext)],
        capture_output=True, text=True, timeout=120)
    assert r2.returncode == 0, f"emit scheiterte: {r2.stdout}\n{r2.stderr}"
    sig = welt["repo"] / "sig.b64"
    sig.write_text(base64.b64encode(welt["key"].sign(nutzlast.read_bytes())).decode(),
                   encoding="utf-8")
    r3 = subprocess.run(
        [sys.executable, str(REPO / "scripts" / "sign_readiness_artifact.py"),
         "--assemble", "--context-in", str(kontext), "--sig-file", str(sig),
         "--signer-pubkey", welt["pub"], "--out", str(ziel2)],
        capture_output=True, text=True, timeout=120)
    assert r3.returncode == 0, f"assemble scheiterte: {r3.stdout}\n{r3.stderr}"
    verdikt2, grund2 = m.c6_2_recorded_soak_clean()
    assert verdikt2 == m.PASS, f"die schluessellos zusammengesetzte Evidenz wird abgelehnt: {grund2}"

    # Und die Gegenrichtung: eine FALSCHE Signatur darf nie zu einem Artefakt auf der Platte werden.
    sig.write_text(base64.b64encode(welt["foreign"].sign(nutzlast.read_bytes())).decode(),
                   encoding="utf-8")
    r4 = subprocess.run(
        [sys.executable, str(REPO / "scripts" / "sign_readiness_artifact.py"),
         "--assemble", "--context-in", str(kontext), "--sig-file", str(sig),
         "--signer-pubkey", welt["pub"], "--out", str(welt["repo"] / "darf_nicht_entstehen.json")],
        capture_output=True, text=True, timeout=120)
    assert r4.returncode != 0, "assemble hat eine nicht passende Signatur eingepackt"
    assert not (welt["repo"] / "darf_nicht_entstehen.json").exists(), \
        "ein schlechtes Paar wurde trotzdem geschrieben"

    for p in (key_datei, roh, nutzlast, kontext, sig):
        p.unlink(missing_ok=True)


@_braucht_krypto
def test_gate_meta_die_matrix_faengt_den_eingepflanzten_defekt(welt):
    """GATE-META-TEST: die Matrix muss beweisen, dass sie einen Defekt DIESER Klasse faengt.

    Eingepflanzt wird die ALTE Zeile von C6.2 — zwei Zaehler, sonst nichts. Sie muss auf mindestens
    einer Zelle ein Bestehen erteilen, sonst misst die Matrix nichts und ihr Gruen oben waere
    bedeutungslos."""
    m = _matrix_modul()
    m.REPO = welt["repo"]
    m.VERSION_UNDER_TEST = VERSION

    def alte_zeile():
        p = welt["repo"] / "audit_artifacts" / "360" / "fuzz_soak_latest.json"
        if not p.is_file():
            return m.FAIL, "no recorded fuzz-soak artifact"
        try:
            a = json.loads(p.read_text(encoding="utf-8"))
        except ValueError:
            return m.FAIL, "unreadable"
        if not isinstance(a, dict):
            return m.FAIL, "not an object"
        ok = a.get("untriaged_crash_count", 1) == 0 and a.get("false_accept_count", 1) == 0
        return (m.PASS, "recorded soak") if ok else (m.FAIL, "soak found crashes")

    leser = LESER[0]
    durchgerutscht = []
    for name, zelle, _ in matrix_zellen():
        _lege_ab(welt, leser, zelle)
        if alte_zeile()[0] == m.PASS:
            durchgerutscht.append(name)
    assert durchgerutscht, ("die Matrix erteilt der ALTEN, defekten Zeile kein einziges Bestehen — "
                            "dann misst sie die Klasse nicht")


@_braucht_krypto
def test_der_anker_unterscheidet_leer_von_nicht_messbar(welt):
    """Auflage C2, an ihrem schaerfsten Punkt. „Dieses Repo checkt keinen Anker ein" (FAIL) und
    „hier ist kein git" (DATA_BLOCKED) sahen in der ersten Fassung gleich aus — beide lieferten eine
    leere Liste, und damit waere ein Umgebungsmangel als ungueltige Evidenz gemeldet worden oder
    umgekehrt. Die drei Zustaende werden hier einzeln erzeugt und gemessen."""
    m = _matrix_modul()
    schluessel, zustand = m._trust_anchor(welt["repo"])
    assert zustand == "ok" and schluessel == [welt["pub"]], (zustand, schluessel)

    leer = Path(tempfile.mkdtemp(prefix="anker_leer_"))
    ohne = Path(tempfile.mkdtemp(prefix="anker_ohne_"))
    kein_repo = Path(tempfile.mkdtemp(prefix="anker_kein_repo_"))
    try:
        for baum, inhalt in ((leer, "# no keys pinned yet\n"), (ohne, None)):
            start = subprocess.run(["git", "init", "-q", str(baum)], capture_output=True, text=True)
            if start.returncode != 0:
                pytest.skip("git ist hier nicht benutzbar")
            (baum / "a.txt").write_text("x\n", encoding="utf-8")
            if inhalt is not None:
                (baum / "audit_artifacts").mkdir(parents=True, exist_ok=True)
                (baum / "audit_artifacts" / "readiness_trusted_pubkeys.txt").write_text(
                    inhalt, encoding="utf-8")
            _git(baum, "add", "-A")
            _git(baum, "-c", "user.email=a@b", "-c", "user.name=a", "commit", "-q", "-m", "x")
        assert m._trust_anchor(leer) == ([], "empty"), "nur Kommentare heisst: kein Anker"
        assert m._trust_anchor(ohne) == ([], "empty"), "gar keine Ankerdatei heisst: kein Anker"
        assert m._trust_anchor(kein_repo) == ([], "unmeasurable"), \
            "kein git-Baum ist eine Aussage ueber die Umgebung, nicht ueber das Repo"
    finally:
        for baum in (leer, ohne, kein_repo):
            shutil.rmtree(baum, ignore_errors=True)


def test_jeder_freigabeentscheidende_artefaktleser_geht_ueber_den_einen_pfad():
    """INVENTAR (Auflage C2): kein freigabeentscheidender Leser darf an der Zulassung vorbeilesen.

    Gemessen am Quelltext, nicht behauptet: ``_json_artifact`` — der ungepruefte Rohleser — darf in
    keiner Funktion mehr vorkommen, die eine freigabeentscheidende Evidenz-Zeile traegt. C10.2 liest
    ``docs/readiness_pack/index.json`` weiterhin so, ist dort aber an das Pack-Manifest gebunden und
    steht mit dieser Grenze im eigenen Test.
    """
    quelle = (REPO / "scripts" / "audit_candidate_matrix.py").read_text(encoding="utf-8")
    m = _matrix_modul()
    entscheidend = {cid for cid, *_ in m.CHECKS} - set(m._INFORMATIVE_CHECKS)
    assert {"C6.2", "C6.3", "C8.2", "C9.1", "C10.2"} <= entscheidend
    for fn in ("c6_2_recorded_soak_clean", "c6_3_full_24h", "c8_2_differential_agrees"):
        koerper = _code_ohne_doku(quelle, fn)
        assert "_json_artifact(" not in koerper, f"{fn} liest noch am Zulassungspfad vorbei"
        assert "_signed_versioned_artifact(" in koerper or "_soak_artifact()" in koerper, \
            f"{fn} benutzt den Zulassungspfad nicht"


def test_c9_1_leitet_sein_urteil_nicht_mehr_aus_prosa_ab():
    """C9.1 gehoert zum Inventar (Auflage C2) und misst selbst, statt eine Ablage zuzulassen. Was
    dort fehlte, war die STRUKTURIERTHEIT der Antwort: das Urteil hing an den Teilzeichenketten
    ``reproducible ok`` / ``byte-identical`` / ``not reproducible`` der Standardausgabe."""
    quelle = (REPO / "scripts" / "audit_candidate_matrix.py").read_text(encoding="utf-8")
    koerper = _code_ohne_doku(quelle, "c9_1_two_sdists_identical")
    # GEMESSEN WIRD DAS LESEN, NICHT DAS SCHREIBEN. Der Satz „two sdist builds are byte-identical"
    # darf im ERGEBNIS stehen — er ist die Aussage. Verboten ist, ihn als EINGABE zu lesen. Eine
    # erste Fassung dieses Tests verbot das Wort ueberhaupt und schlug an der eigenen Ausgabe an;
    # das waere ein Orakel gewesen, das die Formulierung statt der Datenrichtung misst.
    for eingabe_prosa in ("rc.stdout + rc.stderr", "in out", ".lower()"):
        assert eingabe_prosa not in koerper, \
            f"C9.1 liest die Ausgabe weiterhin als Prosa: {eingabe_prosa!r}"
    assert "json.loads(" in koerper, "C9.1 liest kein maschinenlesbares Ergebnis"
    assert "_REPRO_MEASUREMENT_SCHEMA" in koerper, "C9.1 prueft das Schema des Messergebnisses nicht"
    assert "find_spec('build')" in koerper, \
        "die Messbarkeit wird nicht strukturell festgestellt, sondern aus einer Fehlermeldung gelesen"

    import build_reproducible as br                       # noqa: PLC0415
    r = br.measure_reproducible.__doc__ or ""
    assert "STRUKTURIERT" in r or "strukturiert" in r
    assert br.MEASUREMENT_SCHEMA == "proofbundle.reproducible_sdist_check.v1"
