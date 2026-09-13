"""KLASSE A — Provenienz und Kandidatenbindung freigabeentscheidender Evidenz (L5-G7-02, P2).

DIE EIGENSCHAFT, ausfuehrbar formuliert und hier gemessen. Eine Pruefung in
``scripts/audit_candidate_matrix.py``, die NICHT in ``_INFORMATIVE_CHECKS`` steht, darf ein Bestehen
nur aus Evidenz bilden, die

  P-A1  eine ed25519-Signatur ueber den kanonischen Bytes ihres GESAMTEN Rumpfes traegt, die unter
        einem EINGECHECKTEN Vertrauensanker verifiziert,
  P-A2  den exakten Kandidaten bindet (Commit, Baumkennung, sdist- und wheel-Digest), wobei die
        Baumkennung gegen den lebenden Baum nachgerechnet wird,
  P-A2b die GATE-ZEILE des entscheidenden Deep-Gate-Laufs traegt, deren ``head`` an den
        ``candidate.commit`` gebunden ist — damit die Baumaschine nicht ihre eigene Freigabe
        beglaubigt (Release-Standard 6.0.0 vom 05.09.2026, Zeile 18),
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
import os
import shutil
import subprocess
import sys
import tempfile
import time
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


#: Dieselben zwei Pfade wie `sign_readiness_artifact.MUTABLE_EVIDENCE_RELS` — hier als eigene,
#: unabhaengige Konstante, NICHT importiert, damit das Orakel nicht an derselben Quelle haengt wie
#: der Code, den es prueft.
_UNABHAENGIG_AUSGESCHLOSSEN = ("audit_artifacts/360/fuzz_soak_latest.json",
                               "audit_artifacts/360/rust_differential_matrix.json")


def _baum_digest(repo: Path) -> str:
    """Dieselbe Groesse, die das Tor nachrechnet — bewusst UNABHAENGIG hier nachgebaut, damit das
    Orakel nicht die Funktion aufruft, die es prueft.

    NACH C3 (Runde 2): rekursiv (`ls-tree -r`), und ausgeschlossen sind nur die NAMENTLICH bekannten
    mutablen Evidenzpfade — nicht mehr der ganze Ordner `audit_artifacts`. Ein eingecheckter
    Vertrauensanker darunter ist damit Teil der Baumkennung."""
    out = _git(repo, "ls-tree", "-r", "HEAD").stdout
    suffixe = tuple(f"\t{p}" for p in _UNABHAENGIG_AUSGESCHLOSSEN)
    zeilen = [ln for ln in out.splitlines() if not ln.endswith(suffixe)]
    return hashlib.sha256("\n".join(sorted(zeilen)).encode("utf-8")).hexdigest()


# ── Die Gate-Zeile, Form abgelesen am Lauf-4-Verdikt ──────────────────────────────────────────
#
# `office/governance/deepgate_600_lauf3/gate_result_600_lauf4b_FIX_FIRST.json` traegt unter
# `notes.gate_zeile` ein OBJEKT mit 20 Feldern. Verlangt werden hier die SECHS, die die Zeile zu
# einer BINDUNG machen. Der WERT fuer 6.0.0 entsteht erst im Release-Zug (Verdikt Lauf 5); geprueft
# wird deshalb die FORM und die Bindung an den Kandidaten, nicht ein konkreter Digest.
def _gate_zeile(commit: str, *, workflow_sha: str | None = None) -> dict:
    return {
        "gate_version": "v4",
        "workflow_datei": "office/governance/deepgate_600_lauf3/berkeley_gate_workflow_600.js",
        "workflow_sha256": workflow_sha or ("5" * 64),
        "modus": "DEEP 6L/7I",
        "head": commit,
        "verdict": "WITHSTANDS_DEEPGATE",
        "sitzungsmodell": "claude-opus-5 (Claude Opus 5, 1M context)",
    }


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
        # AUFLAGE C1 (Runde 2): ein FORMGUELTIGER, aber beliebiger Commitstring darf nicht genuegen.
        ("kandidat_falscher_commit",
         _mut(lambda b: b["candidate"].__setitem__("commit", "0" * 40)), True),
        # AUFLAGE C2 (Runde 2): freie Digest-Eingaben (auch formgueltige) erzeugen keinen Nachweis —
        # nachgerechnet wird gegen die ECHTEN Dateien in dist/, die die Fixture ablegt.
        ("kandidat_falscher_sdist_digest",
         _mut(lambda b: b["candidate"].__setitem__("sdist_sha256", "f" * 64)), True),
        ("kandidat_falscher_wheel_digest",
         _mut(lambda b: b["candidate"].__setitem__("wheel_sha256", "e" * 64)), True),
        # RELEASE-STANDARD 6.0.0 ZEILE 18: die Gate-Zeile ist eine EIGENE Verletzungsklasse neben
        # der Kandidatenbindung. Die Bindung sagt WELCHE Version gemessen wurde, die Gate-Zeile
        # sagt, WELCHES Tor sie durchgelassen hat — eine Baumaschine, die nur die erste traegt,
        # beglaubigt weiterhin ihre eigene Freigabe. Beide Gruppen stehen hier, nicht die eine ODER
        # die andere; der Merge-Konflikt am 2026-09-07 kam allein daraus, dass beide an derselben
        # Stelle in dieselbe Zellenliste geschrieben werden.
        ("gate_zeile_fehlt", _mut(lambda b: b.pop("gate_zeile", None)), True),
        ("gate_zeile_fremder_lauf",
         _mut(lambda b: b["gate_zeile"].__setitem__("head", "9" * 40)), True),
        ("gate_zeile_unformig",
         _mut(lambda b: b["gate_zeile"].__setitem__("workflow_sha256", "kein-digest")), True),
        ("gate_zeile_kein_objekt", _mut(lambda b: b.__setitem__("gate_zeile", "RUN")), True),
        # DAS VERDIKT, seit 2026-09-07. Die Zeile band bis dahin die HERKUNFT des Laufs und nicht
        # sein ERGEBNIS. Der mittlere Fall ist der gemessene: `gate_result_600_lauf4b_FIX_FIRST.json`
        # traegt `verdict: FIX_FIRST` und ein `release`, das woertlich "do not present ... as
        # WITHSTANDS" sagt — und seine Gate-Zeile bestand die Pruefung vollstaendig, weil keines
        # ihrer zwanzig Felder das Urteil trug.
        ("gate_zeile_ohne_verdikt", _mut(lambda b: b["gate_zeile"].pop("verdict", None)), True),
        ("gate_zeile_verdikt_ist_FIX_FIRST",
         _mut(lambda b: b["gate_zeile"].__setitem__("verdict", "FIX_FIRST")), True),
        ("gate_zeile_verdikt_unbekannt",
         _mut(lambda b: b["gate_zeile"].__setitem__("verdict", "IRGENDEIN_NEUES_WORT")), True),
        # BEINAHETREFFER, nachgetragen 2026-09-07 nach einer gemessenen Abdeckungsluecke. Die drei
        # Faelle darueber pruefen Abwesenheit, einen bekannten Fail-Wert und ein fremdes Wort. Keiner
        # von ihnen faengt einen Wert, der die ERLAUBTE Konstante als PRAEFIX traegt: die Mutation
        # `not in _GATE_VERDICTS_PASS` -> `.startswith(...)` ueberlebte die ganze Matrix (50 passed,
        # vor wie nach der Mutation), und `WITHSTANDS_DEEPGATE_PARTIALLY` waere danach ein Pass
        # gewesen. Ein "teilweise standgehalten" ist kein Standhalten.
        ("gate_zeile_verdikt_traegt_erlaubtes_als_praefix",
         _mut(lambda b: b["gate_zeile"].__setitem__("verdict", "WITHSTANDS_DEEPGATE_PARTIALLY")), True),
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


def _lege_dist_ab(repo: Path, version: str) -> tuple[str, str]:
    """Legt ECHTE sdist/wheel-Dateien in ``dist/`` ab (ungetrackt — C2 liest sie von der Platte,
    nie ueber git) und liefert ihre TATSAECHLICHEN sha256-Digests.

    AUFLAGE C2 (Runde 2): das Tor rechnet Distributions-Digests jetzt aus den echten Dateien nach,
    statt eine freie Zeichenkette zu glauben. Ohne diese Hilfsfunktion wuerden alle „guten" Zellen
    unten DATA_BLOCKED statt PASS — sie muessten dann etwas beweisen, das sie nicht mehr fingieren
    duerfen."""
    dist = repo / "dist"
    dist.mkdir(parents=True, exist_ok=True)
    sdist_bytes = f"fake sdist bytes for the klasse-a fixture, {version}\n".encode()
    wheel_bytes = f"fake wheel bytes for the klasse-a fixture, {version}\n".encode()
    (dist / f"proofbundle-{version}.tar.gz").write_bytes(sdist_bytes)
    (dist / f"proofbundle-{version}-py3-none-any.whl").write_bytes(wheel_bytes)
    return hashlib.sha256(sdist_bytes).hexdigest(), hashlib.sha256(wheel_bytes).hexdigest()


@pytest.fixture(scope="module")
def welt():
    """Ein echter kleiner git-Baum mit EINGECHECKTEM Vertrauensanker, echten dist/-Dateien und
    ZWEI Commits.

    Warum ein echter Baum: der Anker wird aus dem COMMITTETEN Blob gelesen und die Baumkennung
    gegen ``git ls-tree HEAD`` nachgerechnet. Beides in einem tmp-Verzeichnis ohne git zu messen
    hiesse, die Umgebung statt der Evidenz zu pruefen — dann waere jede Zelle DATA_BLOCKED und die
    Matrix saehe gruen aus, ohne irgendetwas ueber die Evidenz zu sagen.

    WARUM ZWEI COMMITS (Auflage C3, Runde 2): der ERSTE Commit traegt NUR den Anker, der ZWEITE
    (= ``welt["commit"]``, = HEAD) den Kandidaten. Ein Anker, dessen einzige committete Geschichte
    der Kandidaten-Commit selbst ist, waere SELBSTREGISTRIERT — genau die Zelle, gegen die
    ``test_ein_anker_im_selben_commit_wie_der_kandidat_ist_selbstregistrierung`` unten misst. Waere
    dieser Baum hier eincommittig, waere jede „gute" Zelle unten selbst eine Instanz jenes Fundes.
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
        (td / "audit_artifacts").mkdir(parents=True, exist_ok=True)
        (td / "audit_artifacts" / "readiness_trusted_pubkeys.txt").write_text(
            # Ankerformat seit Auflage C3, zweite Haelfte (2026-09-06): je Schluessel eine
            # ROLLE und eine FRIST. Ohne sie ist eine Zeile kein Anker mehr — sie sagte, WER
            # unterschreiben darf, aber nicht WOFUER und BIS WANN, und liess signer_role als
            # Selbstauskunft des Erzeugers stehen. Die Frist ist fern, damit dieser Baum
            # keine Zeitbombe wird; die Fristpruefung hat eigene, enge Faelle.
            "# test anchor\n" + pub + " role=readiness_und_register_signierer_600 not_after=2099-12-31\n",
            encoding="utf-8")
        _git(td, "add", "-A")
        _git(td, "-c", "user.email=a@b", "-c", "user.name=a", "commit", "-q", "-m", "anchor")
        (td / "pyproject.toml").write_text(f'[project]\nversion = "{VERSION}"\n', encoding="utf-8")
        _git(td, "add", "-A")
        _git(td, "-c", "user.email=a@b", "-c", "user.name=a", "commit", "-q", "-m", "candidate")
        sdist_sha256, wheel_sha256 = _lege_dist_ab(td, VERSION)
        yield {"repo": td, "key": schluessel, "pub": pub, "foreign": fremd,
               "commit": _git(td, "rev-parse", "HEAD").stdout.strip(), "tree": _baum_digest(td),
               "sdist_sha256": sdist_sha256, "wheel_sha256": wheel_sha256}
    finally:
        shutil.rmtree(td, ignore_errors=True)


def _sra_modul():
    """``scripts/sign_readiness_artifact.py`` als Modul — derselbe Weg wie ``_matrix_modul``."""
    spec = importlib.util.spec_from_file_location(
        "_sra_klasse_a", str(REPO / "scripts" / "sign_readiness_artifact.py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules["_sra_klasse_a"] = m
    spec.loader.exec_module(m)
    return m


def _rumpf(welt, gut: dict) -> dict:
    b = copy.deepcopy(gut)
    b["version"] = VERSION
    b["candidate"] = {"commit": welt["commit"], "tree_digest": welt["tree"],
                      "sdist_sha256": welt["sdist_sha256"], "wheel_sha256": welt["wheel_sha256"]}
    b["gate_zeile"] = _gate_zeile(welt["commit"])
    b["producer"] = {"tool": "scripts/fuzz_soak.py", "tool_version": VERSION}
    b["input_digest"] = "c" * 64
    b["signer_role"] = "readiness_und_register_signierer_600"
    # Auflage C3, dritter Teil (2026-09-06): ein gueltiges Artefakt bindet den Ankerzustand,
    # unter dem es entstand. Der Rumpf holt ihn ueber DIESELBE Funktion, die der Erzeuger
    # benutzt — ein nachgebauter Digest im Test wuerde nur die Nachbildung pruefen.
    b["trust_anchor_digest"] = _sra_modul().trust_anchor_digest(welt["repo"])
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
            #
            # AUSNAHME C8.2, UND SIE IST GEMESSEN, NICHT GEWAEHLT (2026-09-06). Fuer C8.2 haengt die
            # richtige Antwort nicht nur an der Pflicht, sondern am ZUSTAND DER MASCHINE: ohne
            # gebautes Rust-Binary kann diese Umgebung die Matrix gar nicht erzeugen (DATA_BLOCKED),
            # mit Binary hat sie schlicht niemand gefahren (FAIL). Genau so steht es im Code
            # (`c8_2_differential_agrees`), und genau das hat der Test bisher NICHT abgebildet: er
            # schrieb DATA_BLOCKED fest.
            #
            # GEMESSEN, wie es auffiel: die Vollsuite auf 4161985 wurde hier rot, dieselbe Suite auf
            # 85d204b nicht. Ursache ist keine Codeaenderung, sondern
            # `tools/pb_verify_rs/target/release/pb_verify_rs` — ein UNGETRACKTES Bauartefakt, das
            # ein frueherer Test IM SELBEN LAUF um 02:13:47 erzeugt hat. Danach meldet
            # `_rust_parity()["binary_available"]` True, und C8.2 antwortet richtigerweise FAIL.
            #
            # Der Test misst deshalb jetzt dieselbe Groesse wie der Code, statt sie vorwegzunehmen.
            # Das ist KEINE Abschwaechung: die Aussage „nie PASS" und der Zwang, zwischen
            # Umgebungsmangel und Befund zu unterscheiden, bleiben beide — nur die Erwartung folgt
            # dem gemessenen Zustand, statt einen davon zu behaupten. Dieselbe Klasse wie N13 im
            # Restrisiko-Register: ein Ergebnis, das von Laufzeitzustand ausserhalb des Prueflings
            # abhaengt, muss den Zustand LESEN statt ihn anzunehmen.
            erwartet = m.DATA_BLOCKED if leser.absent_ist_umgebung else m.FAIL
            if leser.cid == "C8.2":
                try:
                    binaer_da = bool(m._rust_parity().get("binary_available"))
                except Exception:                        # noqa: BLE001 — Gate kaputt = nicht messbar
                    binaer_da = False
                erwartet = m.FAIL if binaer_da else m.DATA_BLOCKED
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
        sdist_sha256, wheel_sha256 = _lege_dist_ab(td, VERSION)
        eigene = {"repo": td, "commit": _git(td, "rev-parse", "HEAD").stdout.strip(),
                  "tree": _baum_digest(td), "sdist_sha256": sdist_sha256, "wheel_sha256": wheel_sha256}
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


def test_die_ankerhistorie_hat_DREI_zustaende_nicht_zwei():
    """AUFLAGE A4 (Nachtrag 3): „Fangnachweis mit gepflanztem Git-Fehler."

    DIE LUECKE, DIE DIESER TEST SCHLIESST, und sie stand zwei Stunden offen: die Dreizustaendigkeit
    wurde gebaut (Commit 1311498), der vom Auftrag ausdruecklich verlangte Fangnachweis nicht. Ein
    Mechanismus ohne den Nachweis, dass er im gepflanzten Fall wirklich greift, ist eine Behauptung
    ueber Code — genau die Sorte, gegen die diese ganze Runde steht.

    WARUM DER DRITTE ZUSTAND NOETIG IST. Die erste Fassung gab bei einem Git-Fehler, fehlender
    Historie oder nicht aufloesbarem Pfad ``False`` zurueck — also DIESELBE Antwort wie
    „nachweislich NICHT im Kandidatencommit geaendert", und das ist ein Bestehen. Fail-open an
    genau der Stelle, die Selbstregistrierung verhindern soll: wo nichts messbar war, sah der
    Aufrufer ein „in Ordnung". Die Unmessbarkeit einer Sicherheitsrelation ist nie ihre Erfuellung.

    GEPFLANZT WIRD EIN ECHTER GIT-FEHLER, kein simulierter: ein Verzeichnis ohne Repository. Das
    ist der Fall, den ein Consumer wirklich erzeugt, wenn er das Paket ausserhalb eines Checkouts
    auspackt.
    """
    m = _matrix_modul()
    leer = Path(tempfile.mkdtemp(prefix="anker_ohne_git_"))
    try:
        selbst, grund = m._anchor_last_touched_at_head(leer, "a" * 40)
        assert selbst is None, (
            f"ohne git-Repo kam ein URTEIL heraus statt 'nicht messbar': {selbst} / {grund}")
        assert grund, "der dritte Zustand nennt seinen Grund nicht"
    finally:
        shutil.rmtree(leer, ignore_errors=True)

    # ZWEITER GEPFLANZTER FALL: ein echtes Repository, in dem die Ankerdatei nie committet wurde.
    # Auch hier ist die Relation nicht messbar — es gibt keine Historie, gegen die man sie haelte.
    ohne_datei = Path(tempfile.mkdtemp(prefix="anker_ohne_historie_"))
    try:
        start = subprocess.run(["git", "init", "-q", str(ohne_datei)], capture_output=True, text=True)
        if start.returncode != 0:
            pytest.skip("git ist hier nicht benutzbar")
        (ohne_datei / "irgendwas.txt").write_text("x\n", encoding="utf-8")
        _git(ohne_datei, "add", "-A")
        _git(ohne_datei, "-c", "user.email=a@b", "-c", "user.name=a", "commit", "-q", "-m", "ohne anker")
        kopf = _git(ohne_datei, "rev-parse", "HEAD").stdout.strip()
        selbst, grund = m._anchor_last_touched_at_head(ohne_datei, kopf)
        assert selbst is None, (
            f"ohne Ankerhistorie kam ein Urteil heraus statt 'nicht messbar': {selbst} / {grund}")
    finally:
        shutil.rmtree(ohne_datei, ignore_errors=True)


@_braucht_krypto
def test_ohne_git_erteilt_der_ganze_weg_keine_freigabe_und_zwar_frueher():
    """DIE ANDERE HAELFTE — und sie sagt etwas ANDERES, als ich zuerst annahm.

    Die Absicht war: eine nicht messbare Ankerhistorie muss beim AUFRUFER zu DATA_BLOCKED fuehren.
    Gemessen kommt dort ``candidate_unbound`` heraus, und zwar aus einem Grund, der die Sache selbst
    betrifft: ``_artifact_signature_ok`` prueft VOR der Ankerhistorie, ob das Artefakt einen
    ``trust_anchor_digest`` traegt — und dieser Digest wird aus dem COMMITTETEN Ankerblob gebildet.
    Ohne git gibt es keinen committeten Blob, der Digest ist leer, und die fruehere Pruefung greift.

    DARAUS FOLGT EINE EHRLICHE EINSCHRAENKUNG, die hier stehen muss statt in einem Bericht: der
    dritte Zustand von ``_anchor_last_touched_at_head`` ist ueber DIESEN Weg nicht erreichbar,
    solange git ganz fehlt — nicht weil er falsch waere, sondern weil eine vorgelagerte Pruefung
    dieselbe Faehigkeit braucht und zuerst zuschlaegt. Die Dreizustaendigkeit bleibt richtig: sie
    ist die Verteidigung der FUNKTION gegen ihren eigenen fail-open, und der Test darueber misst sie
    direkt. Was sie NICHT ist, ist ein Riegel, der sich am ganzen Weg zeigt.

    WAS DIESER TEST DESHALB FESTHAELT: ohne git erteilt der ganze Weg KEINE Freigabe. Welcher
    Nicht-Freigabe-Zustand genau herauskommt, ist hier zweitrangig und ausdruecklich als
    ``candidate_unbound`` benannt, damit ein spaeterer Umbau, der daraus ein VERIFIED macht,
    auffaellt. Die Zeile ist damit schwaecher als ihr erster Entwurf — und ehrlich, statt eine
    Wirkung zu behaupten, die der Code an dieser Stelle nicht hat.
    """
    m = _matrix_modul()
    schluessel = Ed25519PrivateKey.generate()
    pub = base64.b64encode(schluessel.public_key().public_bytes_raw()).decode()
    zeile = "# test anchor\n" + pub + " role=readiness_und_register_signierer_600 not_after=2099-12-31\n"
    ohne_git = Path(tempfile.mkdtemp(prefix="freigabe_ohne_git_"))
    try:
        (ohne_git / "audit_artifacts").mkdir(parents=True, exist_ok=True)
        (ohne_git / "audit_artifacts" / "readiness_trusted_pubkeys.txt").write_text(zeile, encoding="utf-8")
        kandidat = {"repo": ohne_git, "commit": "b" * 40, "tree": "c" * 40,
                    "sdist_sha256": "d" * 64, "wheel_sha256": "e" * 64}
        koerper = _rumpf(kandidat, {})
        koerper["trust_anchor_digest"] = _sra_modul().trust_anchor_digest(ohne_git)
        art = _signiere(koerper, schluessel)
        trusted = m._anker_zeilen_lesen(zeile)
        assert trusted, "Vorbedingung: die Ankerzeile ist lesbar"
        verdikt, grund = m._artifact_signature_ok(art, trusted, "ok", repo=ohne_git)
        assert verdikt != m.ART_VERIFIED, (
            f"ohne git erteilte der Weg eine Freigabe: {verdikt} / {grund}")
        assert verdikt == m.ART_CANDIDATE_UNBOUND, (
            f"der gemessene Zustand hat sich geaendert: {verdikt} statt candidate_unbound ({grund}). "
            "Das ist kein Fehler, aber es gehoert nachgezogen — der Docstring dieses Tests erklaert, "
            "WARUM hier nicht DATA_BLOCKED steht, und diese Erklaerung waere dann ueberholt")
        assert "trust_anchor_digest" in grund, f"der Grund benennt die zuerst greifende Pruefung nicht: {grund}"
    finally:
        shutil.rmtree(ohne_git, ignore_errors=True)


@_braucht_krypto
def test_ein_anker_im_selben_commit_wie_der_kandidat_ist_selbstregistrierung():
    """Auflage C3 (Runde 2): ein Schluessel, dessen einzige committete Geschichte der Kandidaten-
    Commit selbst ist, ist SELBSTREGISTRIERT statt vorab festgelegt — auch wenn Signatur,
    Kandidatenbindung, Provenienz und Frische sonst makellos sind.

    Das ist genau die Lage, gegen die ``ein Schluessel, der im selben ungeschuetzten Baupfad
    eingefuehrt wird, darf keine Evidenz desselben Pfads autorisieren`` (C3) gerichtet ist: derselbe
    Bauprincipal, der den Kandidaten baut, koennte im selben Commit auch einen neuen vertrauten
    Schluessel einfuehren und sich damit selbst freigeben. Die `welt`-Fixture haelt Anker und
    Kandidat deshalb in ZWEI Commits auseinander; dieser Test ist die Gegenprobe mit nur EINEM."""
    td = Path(tempfile.mkdtemp(prefix="klasse_a_anker_im_kandidatencommit_"))
    try:
        start = subprocess.run(["git", "init", "-q", str(td)], capture_output=True, text=True)
        if start.returncode != 0:
            pytest.skip("git ist hier nicht benutzbar")
        schluessel = Ed25519PrivateKey.generate()
        pub = base64.b64encode(schluessel.public_key().public_bytes_raw()).decode()
        (td / "pyproject.toml").write_text(f'[project]\nversion = "{VERSION}"\n', encoding="utf-8")
        (td / "audit_artifacts").mkdir(parents=True, exist_ok=True)
        # EIN Commit traegt Anker UND Kandidat zugleich.
        (td / "audit_artifacts" / "readiness_trusted_pubkeys.txt").write_text(
            # Ankerformat seit Auflage C3, zweite Haelfte (2026-09-06): je Schluessel eine
            # ROLLE und eine FRIST. Ohne sie ist eine Zeile kein Anker mehr — sie sagte, WER
            # unterschreiben darf, aber nicht WOFUER und BIS WANN, und liess signer_role als
            # Selbstauskunft des Erzeugers stehen. Die Frist ist fern, damit dieser Baum
            # keine Zeitbombe wird; die Fristpruefung hat eigene, enge Faelle.
            "# test anchor\n" + pub + " role=readiness_und_register_signierer_600 not_after=2099-12-31\n",
            encoding="utf-8")
        _git(td, "add", "-A")
        _git(td, "-c", "user.email=a@b", "-c", "user.name=a", "commit", "-q", "-m",
             "anchor+candidate in one commit")
        sdist_sha256, wheel_sha256 = _lege_dist_ab(td, VERSION)
        eigene = {"repo": td, "commit": _git(td, "rev-parse", "HEAD").stdout.strip(),
                  "tree": _baum_digest(td), "sdist_sha256": sdist_sha256, "wheel_sha256": wheel_sha256}
        ziel = td / "audit_artifacts" / "360" / "fuzz_soak_latest.json"
        ziel.parent.mkdir(parents=True, exist_ok=True)
        ziel.write_text(json.dumps(_signiere(_rumpf(eigene, _SOAK_GUT), schluessel), indent=2),
                        encoding="utf-8")
        m = _matrix_modul()
        m.REPO = td
        m.VERSION_UNDER_TEST = VERSION
        verdikt, grund = m.c6_2_recorded_soak_clean()
        assert verdikt == m.FAIL, (
            f"ein im selben Commit wie der Kandidat eingefuehrter Anker wurde zugelassen: "
            f"{verdikt} {grund}")
        assert "same commit" in grund or "self-registered" in grund, (
            f"FAIL kam aus einem anderen Grund als der Selbstregistrierung: {grund}")
    finally:
        shutil.rmtree(td, ignore_errors=True)


@_braucht_krypto
def test_ein_anker_in_einem_frueheren_commit_bleibt_zulaessig():
    """ANTI-PARITAET zum Test oben: ein Fix, der JEDEN Anker ablehnt (nicht nur den im selben
    Commit), waere wertlos. Zwei Commits wie bei ``welt`` — dieselbe Form, eigens nachgebaut, damit
    dieser Test nicht von der `welt`-Fixture abhaengt."""
    td = Path(tempfile.mkdtemp(prefix="klasse_a_anker_frueher_"))
    try:
        start = subprocess.run(["git", "init", "-q", str(td)], capture_output=True, text=True)
        if start.returncode != 0:
            pytest.skip("git ist hier nicht benutzbar")
        schluessel = Ed25519PrivateKey.generate()
        pub = base64.b64encode(schluessel.public_key().public_bytes_raw()).decode()
        (td / "audit_artifacts").mkdir(parents=True, exist_ok=True)
        (td / "audit_artifacts" / "readiness_trusted_pubkeys.txt").write_text(
            # Ankerformat seit Auflage C3, zweite Haelfte (2026-09-06): je Schluessel eine
            # ROLLE und eine FRIST. Ohne sie ist eine Zeile kein Anker mehr — sie sagte, WER
            # unterschreiben darf, aber nicht WOFUER und BIS WANN, und liess signer_role als
            # Selbstauskunft des Erzeugers stehen. Die Frist ist fern, damit dieser Baum
            # keine Zeitbombe wird; die Fristpruefung hat eigene, enge Faelle.
            "# test anchor\n" + pub + " role=readiness_und_register_signierer_600 not_after=2099-12-31\n",
            encoding="utf-8")
        _git(td, "add", "-A")
        _git(td, "-c", "user.email=a@b", "-c", "user.name=a", "commit", "-q", "-m", "anchor")
        (td / "pyproject.toml").write_text(f'[project]\nversion = "{VERSION}"\n', encoding="utf-8")
        _git(td, "add", "-A")
        _git(td, "-c", "user.email=a@b", "-c", "user.name=a", "commit", "-q", "-m", "candidate")
        sdist_sha256, wheel_sha256 = _lege_dist_ab(td, VERSION)
        eigene = {"repo": td, "commit": _git(td, "rev-parse", "HEAD").stdout.strip(),
                  "tree": _baum_digest(td), "sdist_sha256": sdist_sha256, "wheel_sha256": wheel_sha256}
        ziel = td / "audit_artifacts" / "360" / "fuzz_soak_latest.json"
        ziel.parent.mkdir(parents=True, exist_ok=True)
        ziel.write_text(json.dumps(_signiere(_rumpf(eigene, _SOAK_GUT), schluessel), indent=2),
                        encoding="utf-8")
        m = _matrix_modul()
        m.REPO = td
        m.VERSION_UNDER_TEST = VERSION
        verdikt, grund = m.c6_2_recorded_soak_clean()
        assert verdikt == m.PASS, (
            f"ein Anker aus einem FRUEHEREN Commit wurde trotzdem abgelehnt: {verdikt} {grund}")
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


def _c4_probe(welt, rumpf: dict):
    """Legt ``rumpf`` (signiert mit dem Ankerschluessel) als C6.2-Evidenz ab und liefert deren
    Urteil — der gemeinsame Aufbau fuer die drei C4-Tests unten."""
    ziel = welt["repo"] / "audit_artifacts" / "360" / "fuzz_soak_latest.json"
    ziel.parent.mkdir(parents=True, exist_ok=True)
    ziel.write_text(json.dumps(_signiere(rumpf, welt["key"]), indent=2), encoding="utf-8")
    m = _matrix_modul()
    m.REPO = welt["repo"]
    m.VERSION_UNDER_TEST = VERSION
    return m.c6_2_recorded_soak_clean(), m


@_braucht_krypto
def test_c4_fehlendes_ok_feld_ist_ein_gestaendnis(welt):
    """Auflage C4 (Runde 2): ``ok`` wurde nur geprueft, WENN es ueberhaupt vorkam (``12c:498–500``)
    — ein Artefakt OHNE ``ok``-Feld ging bislang unbeanstandet durch die Zulassung."""
    rumpf = _rumpf(welt, _SOAK_GUT)
    del rumpf["ok"]
    (verdikt, grund), m = _c4_probe(welt, rumpf)
    assert verdikt == m.FAIL, f"ein fehlendes ok-Feld wurde zugelassen: {verdikt} {grund}"
    assert "ok" in grund


@_braucht_krypto
def test_c4_fehlendes_fehlerfeld_ist_ein_gestaendnis(welt):
    """Auflage C4 (Runde 2): ein fehlendes Fehlerfeld wurde bislang UEBERSPRUNGEN
    (``12c:501–515``) statt geprueft — ein Artefakt ohne ``untriaged_crash_count`` behauptete
    implizit 0 Abstuerze, ohne es je zu sagen."""
    rumpf = _rumpf(welt, _SOAK_GUT)
    del rumpf["untriaged_crash_count"]
    (verdikt, grund), m = _c4_probe(welt, rumpf)
    assert verdikt == m.FAIL, f"ein fehlendes Pflicht-Fehlerfeld wurde zugelassen: {verdikt} {grund}"
    assert "untriaged_crash_count" in grund


@_braucht_krypto
def test_c4_falsch_typisierter_konsistenzzaehler_ist_ein_gestaendnis(welt):
    """Auflage C4 (Runde 2): die Konsistenzpruefung griff nur, wenn BEIDE Seiten schon den
    erwarteten Typ hatten (``12c:516–520``) — ein Zaehler als String statt int wurde
    stillschweigend uebergangen, statt als Typfehler zu gelten."""
    rumpf = _rumpf(welt, _SOAK_GUT)
    rumpf["untriaged_crash_count"] = "0"          # richtiger Wert, falscher Typ
    (verdikt, grund), m = _c4_probe(welt, rumpf)
    assert verdikt == m.FAIL, (
        f"ein falsch typisierter Konsistenzzaehler wurde zugelassen: {verdikt} {grund}")


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

    SEIT AUFLAGE C9 (Runde 2) GIBT ES KEINEN INLINE-MODUS MEHR: der Erzeuger kennt nur noch den
    schluessellosen Weg (``--emit-payload`` + ``--assemble``), und genau der wird hier gefahren —
    kein ``--privkey-file`` liegt mehr vor, weil das Flag nicht mehr existiert.
    """
    m = _matrix_modul()
    roh = welt["repo"] / "roh_soak.json"
    roh.write_text(json.dumps(_SOAK_GUT, indent=2), encoding="utf-8")
    m.REPO = welt["repo"]
    m.VERSION_UNDER_TEST = VERSION
    # DIE VERDIKT-DATEI, aus der die Gate-Zeile WOERTLICH kopiert wird — sie steht hier, weil der
    # emit-Aufruf weiter unten sie braucht.
    #
    # WAS AUS 3f15b4b BEWUSST NICHT UEBERNOMMEN IST (Merge 2026-09-07): dieser Commit brachte an
    # dieser Stelle die damalige INLINE-Fassung desselben Tests mit, samt `--privkey-file`. Dieses
    # Flag existiert seit Auflage C9 (Runde 2) nicht mehr — es gibt keinen Codepfad im Erzeuger, der
    # einen privaten Schluessel liest. Ein Test, der es faehrt, pruefte nicht den Erzeuger, sondern
    # nur seine Argumentpruefung. Uebernommen ist die ABSICHT — die Gate-Zeile wird KOPIERT statt
    # komponiert —, gefahren auf dem schluessellosen emit/assemble-Weg, den es wirklich gibt.
    verdikt_datei = welt["repo"] / "gate_result.json"
    verdikt_datei.write_text(
        json.dumps({"verdict": "WITHSTANDS_DEEPGATE", "head": welt["commit"],
                    "notes": {"gate_zeile": _gate_zeile(welt["commit"])}}, indent=2),
        encoding="utf-8")

    # ── DIE SCHLUESSELLOSE ZWEITEILUNG, und sie wird gefahren statt nur beschrieben ──────────────
    # Der Freigabe-Schluessel liegt beim Owner, nicht auf dem Bauwirt. Deshalb gibt es emit/assemble
    # — und ein Modus, den nie jemand faehrt, ist eine Zusage, keine Faehigkeit.
    nutzlast = welt["repo"] / "payload.bin"
    kontext = welt["repo"] / "context.json"
    ziel2 = welt["repo"] / "audit_artifacts" / "360" / "fuzz_soak_latest.json"
    ziel2.parent.mkdir(parents=True, exist_ok=True)
    r2 = subprocess.run(
        [sys.executable, str(REPO / "scripts" / "sign_readiness_artifact.py"),
         "--repo", str(welt["repo"]), "--in", str(roh),
         "--producer-tool", "scripts/fuzz_soak.py", "--producer-tool-version", VERSION,
         "--input-digest", "d" * 64, "--signer-role", "readiness_und_register_signierer_600",
         # AUFLAGE C2 (Runde 2): keine frei erfundenen Digest-Strings mehr — das Tor rechnet
         # sdist/wheel jetzt aus den ECHTEN Dateien in dist/ nach (von der Fixture abgelegt).
         "--sdist-sha256", welt["sdist_sha256"], "--wheel-sha256", welt["wheel_sha256"],
         "--gate-zeile-aus-verdikt", str(verdikt_datei),
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
    gebaut = json.loads(ziel2.read_text(encoding="utf-8"))
    for feld in ("candidate", "gate_zeile", "producer", "input_digest", "signer_role",
                 "produced_at", "signature"):
        assert feld in gebaut, f"der Erzeuger legt {feld} nicht an"
    assert gebaut["candidate"]["tree_digest"] == welt["tree"]
    assert gebaut["candidate"]["commit"] == welt["commit"]
    # WOERTLICH uebernommen, nicht zusammengesetzt: was im Verdikt steht, steht im Rumpf. Das ist die
    # eigentliche Zusicherung des Standards — ein Erzeuger, der die Zeile formen koennte, waere
    # wieder die Baumaschine, die ihre eigene Freigabe beglaubigt.
    aus_verdikt = json.loads(verdikt_datei.read_text(encoding="utf-8"))["notes"]["gate_zeile"]
    assert gebaut["gate_zeile"] == aus_verdikt, "die Gate-Zeile wurde veraendert statt kopiert"
    assert "gate_zeile" not in gebaut["signature"], (
        "die Gate-Zeile steht im UMSCHLAG statt im Rumpf — dort waere sie unsigniert und damit "
        "Dekoration statt Bindung")
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

    for p in (roh, verdikt_datei, nutzlast, kontext, sig):
        p.unlink(missing_ok=True)


@_braucht_krypto
def test_der_erzeuger_erfindet_keine_gate_zeile(welt):
    """Der Erzeuger darf die Gate-Zeile nur KOPIEREN. Ein Verdikt ohne ``notes.gate_zeile`` muss ihn
    abbrechen lassen — sonst waere er wieder die Baumaschine, die ihre eigene Freigabe beglaubigt
    (Release-Standard 6.0.0 vom 05.09.2026, Zeile 18).

    PORTIERT AUF DEN SCHLUESSELLOSEN WEG (Merge 2026-09-07): 3f15b4b fuhr diesen Fall mit
    ``--privkey-file``, das es seit Auflage C9 nicht mehr gibt. Gemessen wird derselbe Abbruch am
    emit-Schritt — und das ist sogar die schaerfere Stelle, denn dort entstehen die Bytes, die
    spaeter jemand signiert.
    """
    roh = welt["repo"] / "roh2.json"
    roh.write_text(json.dumps(_SOAK_GUT, indent=2), encoding="utf-8")
    ohne = welt["repo"] / "verdikt_ohne_zeile.json"
    ohne.write_text(json.dumps({"verdict": "WITHSTANDS_DEEPGATE", "notes": {}}), encoding="utf-8")
    nutzlast = welt["repo"] / "darf_nicht_entstehen_payload.bin"
    kontext = welt["repo"] / "darf_nicht_entstehen_context.json"
    gemeinsam = [sys.executable, str(REPO / "scripts" / "sign_readiness_artifact.py"),
                 "--repo", str(welt["repo"]), "--in", str(roh),
                 "--producer-tool", "scripts/fuzz_soak.py", "--producer-tool-version", VERSION,
                 "--input-digest", "d" * 64,
                 "--signer-role", "readiness_und_register_signierer_600",
                 "--sdist-sha256", welt["sdist_sha256"], "--wheel-sha256", welt["wheel_sha256"],
                 "--emit-payload", str(nutzlast), "--context-out", str(kontext)]
    r = subprocess.run(gemeinsam + ["--gate-zeile-aus-verdikt", str(ohne)],
                       capture_output=True, text=True, timeout=120)
    assert r.returncode != 0, f"der Erzeuger hat eine Gate-Zeile erfunden: {r.stdout}"
    assert "notes.gate_zeile" in (r.stdout + r.stderr), (
        f"der Abbruch nennt seinen Grund nicht: {r.stdout}\n{r.stderr}")
    assert not nutzlast.exists(), "trotz fehlender Gate-Zeile wurden signierbare Bytes geschrieben"
    # Und ganz OHNE die Flagge bricht er ebenfalls ab, statt das Feld stillschweigend wegzulassen.
    r2 = subprocess.run(gemeinsam, capture_output=True, text=True, timeout=120)
    assert r2.returncode != 0 and "gate-zeile-aus-verdikt" in (r2.stdout + r2.stderr), (
        f"eine fehlende Flagge liess den Erzeuger durchlaufen: {r2.stdout}\n{r2.stderr}")
    assert not nutzlast.exists()
    for p in (roh, ohne):
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
    # Seit Auflage C3, zweite Haelfte (2026-09-06) ist der Anker eine ZUORDNUNG, keine Liste:
    # je Schluessel eine Rolle und eine Frist. Der Vergleich prueft deshalb beides — dass der
    # richtige Schluessel drin ist UND dass er seine Einschraenkungen mitbringt. Ein Test, der
    # nur die Schluesselmenge vergliche, wuerde einen Anker ohne Rolle und Frist durchwinken,
    # also genau den Zustand, den die Auflage abgeschafft hat.
    assert zustand == "ok", (zustand, schluessel)
    assert set(schluessel) == {welt["pub"]}, (zustand, schluessel)
    assert schluessel[welt["pub"]] == {"role": "readiness_und_register_signierer_600", "not_after": "2099-12-31"}, \
        schluessel[welt["pub"]]

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
        assert m._trust_anchor(leer) == ({}, "empty"), "nur Kommentare heisst: kein Anker"
        assert m._trust_anchor(ohne) == ({}, "empty"), "gar keine Ankerdatei heisst: kein Anker"
        assert m._trust_anchor(kein_repo) == ({}, "unmeasurable"), \
            "kein git-Baum ist eine Aussage ueber die Umgebung, nicht ueber das Repo"
    finally:
        for baum in (leer, ohne, kein_repo):
            shutil.rmtree(baum, ignore_errors=True)


def test_jeder_freigabeentscheidende_artefaktleser_geht_ueber_den_einen_pfad():
    """INVENTAR (Auflage C2): kein freigabeentscheidender Leser darf an der Zulassung vorbeilesen.

    Gemessen am Quelltext, nicht behauptet: ``_json_artifact`` — der ungepruefte Rohleser — darf in
    keiner Funktion mehr vorkommen, die eine freigabeentscheidende Evidenz-Zeile traegt.

    C10.2 liest ``docs/readiness_pack/index.json`` weiterhin ueber ``_json_artifact`` — aber sie ist
    seit Runde 2 (Auflage C5) INFORMATIV, nicht mehr freigabeentscheidend (siehe
    ``test_das_inventar_stimmt_mit_checks_und_admission_fn_ueberein`` unten), und diese Grenze steht
    darum NICHT mehr in der ``entscheidend``-Menge, die diese Funktion prueft.
    """
    quelle = (REPO / "scripts" / "audit_candidate_matrix.py").read_text(encoding="utf-8")
    m = _matrix_modul()
    entscheidend = {cid for cid, *_ in m.CHECKS} - set(m._INFORMATIVE_CHECKS)
    assert {"C6.2", "C6.3", "C8.2", "C9.1"} <= entscheidend
    assert "C10.2" not in entscheidend, \
        "C10.2 ist wieder freigabeentscheidend, aber ihr Zulassungspfad wurde nicht mitgehaertet"
    for fn in ("c6_2_recorded_soak_clean", "c6_3_full_24h", "c8_2_differential_agrees"):
        koerper = _code_ohne_doku(quelle, fn)
        assert "_json_artifact(" not in koerper, f"{fn} liest noch am Zulassungspfad vorbei"
        assert "_signed_versioned_artifact(" in koerper or "_soak_artifact()" in koerper, \
            f"{fn} benutzt den Zulassungspfad nicht"


def test_das_inventar_stimmt_mit_checks_und_admission_fn_ueberein():
    """AUFLAGE C6 (Runde 2): das explizite Inventar ``EVIDENCE_ADMISSION_INVENTORY`` deckt genau
    C6.2, C6.3, C8.2, C8.3, C9.1 und C10.2 — nicht nur drei davon wie der vorige Test — und jede
    Zeile zeigt auf eine tatsaechlich existierende Funktion, deren Zugehoerigkeit zu
    ``_INFORMATIVE_CHECKS`` mit ihrem eigenen ``release_deciding``-Feld uebereinstimmt.

    Eine dokumentierte Ausnahme darf nicht still dieselbe Freigabestaerke behalten (Auflage C6,
    zweiter Satz): C10.2 muss hier ausdruecklich ``release_deciding: False`` UND in
    ``_INFORMATIVE_CHECKS`` stehen — beides, nicht nur eines von beiden."""
    m = _matrix_modul()
    inventar = {e["id"]: e for e in m.EVIDENCE_ADMISSION_INVENTORY}
    assert set(inventar) == {"C6.2", "C6.3", "C8.2", "C8.3", "C9.1", "C10.2"}, sorted(inventar)
    check_ids = {cid for cid, *_ in m.CHECKS}
    for cid, eintrag in inventar.items():
        assert cid in check_ids, f"{cid} steht im Inventar, aber nicht in CHECKS"
        fn = getattr(m, eintrag["admission_fn"], None)
        assert callable(fn), f"{cid} zeigt auf {eintrag['admission_fn']!r} — existiert nicht als Funktion"
        ist_informativ = cid in m._INFORMATIVE_CHECKS
        assert eintrag["release_deciding"] == (not ist_informativ), (
            f"{cid}: release_deciding={eintrag['release_deciding']} widerspricht "
            f"_INFORMATIVE_CHECKS-Mitgliedschaft ({ist_informativ})")
        assert eintrag["property"].strip(), f"{cid} hat keine behauptete Eigenschaft"
        assert eintrag["evidence_kind"].strip(), f"{cid} hat keine Evidenzart"
    # Und die konkrete, in Runde 2 verlangte Ausnahme steht wirklich sichtbar da:
    assert inventar["C10.2"]["release_deciding"] is False
    assert "C10.2" in m._INFORMATIVE_CHECKS


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


class TestDistributionsIdentitaet:
    """AUFLAGE A7 (Nachtrag 3), Fangnachweis mit einer absichtlich JUENGEREN Fremddatei in dist.

    Der Reviewer schrieb: „Eine Distribution ist durch Name, Version und Digest bestimmt, nicht durch
    den juengsten Dateizeitstempel." Die alte Auswahl nahm `sorted(..., key=mtime)[-1]` — ein `touch`
    auf ein fremdes Archiv haette damit die Kandidatenidentitaet verschoben, ohne dass irgendwo etwas
    Falsches steht. Der Fehlgriff sah danach aus wie ein Digest-Konflikt und nicht wie das, was er
    ist: die falsche Datei angesehen.
    """

    def _dist(self, dateien: list[tuple[str, float]]) -> Path:
        td = Path(tempfile.mkdtemp(prefix="dist_identitaet_"))
        (td / "dist").mkdir()
        for name, alter in dateien:
            f = td / "dist" / name
            f.write_bytes(name.encode())
            os.utime(f, (time.time() + alter, time.time() + alter))
        return td

    def test_eine_juengere_fremddatei_verschiebt_die_identitaet_nicht(self):
        """DER FANGNACHWEIS. Das richtige Paar ist alt, die Fremddatei ist JUENGER — unter der
        mtime-Regel haette sie gewonnen."""
        m = _matrix_modul()
        td = self._dist([
            (f"proofbundle-{VERSION}.tar.gz", -3600),
            (f"proofbundle-{VERSION}-py3-none-any.whl", -3600),
            ("proofbundle-9.9.9.tar.gz", +3600),            # eine Stunde JUENGER, fremde Version
            ("proofbundle-9.9.9-py3-none-any.whl", +3600),
        ])
        try:
            sdist, wheel, grund = m._dist_files(td, VERSION)
            assert sdist is not None and wheel is not None, grund
            assert VERSION in sdist.name and VERSION in wheel.name, (
                f"die juengere Fremddatei hat die Auswahl verschoben: {sdist.name} / {wheel.name}")
        finally:
            shutil.rmtree(td, ignore_errors=True)

    def test_zwei_paare_derselben_version_sind_MEHRDEUTIG_statt_sortierbar(self):
        """Mehrdeutigkeit wird GEMELDET, nicht durch eine Sortierregel aufgeloest. Eine zweite
        passende Datei heisst, dass niemand mehr sagen kann, welche veroeffentlicht werden soll —
        und diese Frage darf keine Heuristik beantworten."""
        m = _matrix_modul()
        td = self._dist([
            (f"proofbundle-{VERSION}.tar.gz", 0),
            (f"proofbundle-{VERSION}-py3-none-any.whl", 0),
            (f"proofbundle-{VERSION}-py2-none-any.whl", +60),
        ])
        try:
            sdist, wheel, grund = m._dist_files(td, VERSION)
            assert sdist is None and wheel is None, "zwei passende Wheels wurden stillschweigend sortiert"
            assert "ambiguous" in grund, f"die Mehrdeutigkeit wird nicht benannt: {grund!r}"
        finally:
            shutil.rmtree(td, ignore_errors=True)

    def test_ohne_passendes_paar_ist_es_die_UMGEBUNG_nicht_die_evidenz(self):
        """Kein Bau da heisst DATA_BLOCKED, nicht FAIL — eine Aussage ueber diese Maschine, nicht
        ueber den Kandidaten. Die Gegenrichtung zum Fangnachweis: der Riegel darf nicht einfach
        immer None liefern."""
        m = _matrix_modul()
        td = self._dist([("proofbundle-1.0.0.tar.gz", 0), ("proofbundle-1.0.0-py3-none-any.whl", 0)])
        try:
            sdist, wheel, grund = m._dist_files(td, VERSION)
            assert sdist is None and wheel is None
            assert "no version" in grund and VERSION in grund, grund
        finally:
            shutil.rmtree(td, ignore_errors=True)
        gut = self._dist([(f"proofbundle-{VERSION}.tar.gz", 0),
                          (f"proofbundle-{VERSION}-py3-none-any.whl", 0)])
        try:
            sdist, wheel, grund = m._dist_files(gut, VERSION)
            assert sdist is not None and wheel is not None, (
                f"das saubere Paar wird abgewiesen — der Riegel liefert immer None: {grund}")
        finally:
            shutil.rmtree(gut, ignore_errors=True)


class TestErlaubteEvidenzRelation:
    """C1, zweite Haelfte der Auflage: "die erlaubte Relation fuer einen spaeteren Evidenzcommit
    ausdruecklich modellieren".

    Die erste Fassung ersetzte die Relation durch exakte Gleichheit und begruendete das damit, die
    Evidenzdatei werde nie committet. Die Gegenlesung (2026-09-05, Linse 5 von 6) hat den Ablauf
    nachgebaut und das widerlegt: ``sign_readiness_artifact.MUTABLE_EVIDENCE_RELS`` existiert genau
    dafuer, dass ein Lauf seine eigene Ergebnisdatei committen kann, ``tree_digest`` schliesst diese
    Pfade deshalb aus, und beide sind getrackt. Kandidat committen, Evidenz signieren, Evidenz
    committen — der Baumdigest passte weiter, HEAD war gewandert, und die Gleichheit verwarf genau
    den Ablauf, den die Schwesterdatei zusagt.

    Diese Klasse haelt die MODELLIERTE Relation fest, in beide Richtungen. Eigener Baum je Test:
    die Modul-Fixture ``welt`` ist ``scope="module"``, ein Commit darin wuerde die Nachbartests
    aendern (und wer den Zustand einer geteilten Fixture mutiert, misst danach etwas anderes, als
    er glaubt)."""

    @staticmethod
    def _baum():
        td = Path(tempfile.mkdtemp(prefix="relation_"))
        start = subprocess.run(["git", "init", "-q", str(td)], capture_output=True, text=True)
        if start.returncode != 0:
            shutil.rmtree(td, ignore_errors=True)
            pytest.skip(f"git ist hier nicht benutzbar: {start.stderr.strip()}")
        (td / "audit_artifacts" / "360").mkdir(parents=True, exist_ok=True)
        (td / "pyproject.toml").write_text(f'[project]\nversion = "{VERSION}"\n', encoding="utf-8")
        _git(td, "add", "-A")
        _git(td, "-c", "user.email=a@b", "-c", "user.name=a", "commit", "-q", "-m", "kandidat")
        return td, _git(td, "rev-parse", "HEAD").stdout.strip()

    @staticmethod
    def _committe(td, rel, inhalt, nachricht):
        pfad = td / rel
        pfad.parent.mkdir(parents=True, exist_ok=True)
        pfad.write_text(inhalt, encoding="utf-8")
        _git(td, "add", "-A")
        _git(td, "-c", "user.email=a@b", "-c", "user.name=a", "commit", "-q", "-m", nachricht)
        return _git(td, "rev-parse", "HEAD").stdout.strip()

    def test_gleichheit_bleibt_erlaubt(self):
        """Der Normalfall aendert sich nicht: dieselbe Frage wird gar nicht erst gestellt."""
        td, kandidat = self._baum()
        try:
            erlaubt, grund = _matrix_modul()._evidenz_relation_erlaubt(td, kandidat, kandidat)
            assert erlaubt is True, grund
        finally:
            shutil.rmtree(td, ignore_errors=True)

    def test_ein_spaeterer_evidenzcommit_ist_erlaubt(self):
        """DER FALL, DEN DIE GEGENLESUNG REPRODUZIERT HAT. Der Lauf committet nach dem Signieren
        seine eigene Ergebnisdatei — genau einen Pfad aus MUTABLE_EVIDENCE_RELS — und die Bindung
        muss das ueberleben, weil sie ihn selbst zusagt."""
        # Der Lader dieser Datei, wie an den anderen drei Stellen auch. Hier stand vorher ein
        # `import sign_readiness_artifact as sra`; der war NICHT falsch — die Zeilen 46-50
        # legen `scripts/` auf Modulebene auf `sys.path`, der Import trug sich also selbst.
        # Ich hatte das als Defekt gemeldet, nachdem ich `conftest.py` und `pyproject.toml`
        # geprueft hatte und nicht diese Datei. Die Zeile bleibt trotzdem so: eine Datei mit
        # EINEM Weg zu ihrem Modul ist leichter zu lesen als eine mit zweien.
        sra = _sra_modul()
        td, kandidat = self._baum()
        try:
            head = self._committe(td, sra.MUTABLE_EVIDENCE_RELS[0], '{"ok": true}\n', "evidenz")
            assert head != kandidat, "Vorbedingung: HEAD muss gewandert sein"
            erlaubt, grund = _matrix_modul()._evidenz_relation_erlaubt(td, kandidat, head)
            assert erlaubt is True, (
                f"der dokumentierte Evidenz-Commit wurde verworfen: {grund}")
        finally:
            shutil.rmtree(td, ignore_errors=True)

    def test_ein_commit_der_sonst_etwas_anfasst_ist_nicht_erlaubt(self):
        """Die Gegenrichtung, und der eigentliche Zweck: die Relation ist KEIN Freibrief fuer
        "HEAD ist irgendwie weiter". Wer Quelltext anfasst, ist ein anderer Baustand."""
        td, kandidat = self._baum()
        try:
            head = self._committe(td, "src/heimlich.py", "x = 1\n", "quelltext")
            erlaubt, grund = _matrix_modul()._evidenz_relation_erlaubt(td, kandidat, head)
            assert erlaubt is False, f"ein Quelltext-Commit wurde durchgelassen: {grund}"
            assert "outside the mutable evidence set" in grund
            assert "src/heimlich.py" in grund
        finally:
            shutil.rmtree(td, ignore_errors=True)

    def test_der_vertrauensanker_ist_kein_evidenzpfad(self):
        """Der schaerfste Nachbar: ``audit_artifacts/`` enthaelt BEIDES — die zwei mutablen
        Evidenzdateien und den Vertrauensanker. Ein Commit, der den ANKER aendert, darf niemals als
        Evidenz-Commit durchgehen; das waere genau die Selbstregistrierung, gegen die C3 misst."""
        td, kandidat = self._baum()
        try:
            head = self._committe(td, "audit_artifacts/readiness_trusted_pubkeys.txt",
                                  "# neuer Schluessel\nAAAA\n", "anker")
            erlaubt, grund = _matrix_modul()._evidenz_relation_erlaubt(td, kandidat, head)
            assert erlaubt is False, f"eine Ankeraenderung wurde als Evidenz-Commit gewertet: {grund}"
            assert "readiness_trusted_pubkeys.txt" in grund
        finally:
            shutil.rmtree(td, ignore_errors=True)

    def test_ein_fremder_commit_ist_kein_nachfahr(self):
        """Ein Commit aus einem anderen Zweig ist kein "spaeterer" Commit, auch wenn er existiert
        und wohlgeformt ist. Ohne die Vorfahren-Bedingung waere die Pfadpruefung allein
        umgehbar: ein fremder Baustand, der zufaellig nur Evidenzpfade unterscheidet, kaeme durch."""
        td, kandidat = self._baum()
        try:
            _git(td, "checkout", "-q", "-b", "fremd", kandidat)
            fremd = self._committe(td, "src/fremd.py", "y = 2\n", "fremder zweig")
            _git(td, "checkout", "-q", "-")
            erlaubt, grund = _matrix_modul()._evidenz_relation_erlaubt(td, fremd, kandidat)
            assert erlaubt is False, f"ein Nicht-Vorfahr wurde durchgelassen: {grund}"
            assert "not an ancestor" in grund
        finally:
            shutil.rmtree(td, ignore_errors=True)

    def test_ein_git_fehler_ist_kein_urteil(self):
        """Fail-closed in der dritten Richtung: wo git nicht antwortet, gibt es kein "erlaubt" und
        kein "verboten", sondern ``None`` — die aufrufende Zelle macht daraus UNMEASURABLE_HERE
        statt eines stillen Durchwinkens oder einer erfundenen Ablehnung."""
        td = Path(tempfile.mkdtemp(prefix="kein_git_"))
        try:
            erlaubt, grund = _matrix_modul()._evidenz_relation_erlaubt(td, "a" * 40, "b" * 40)
            assert erlaubt is None, f"ohne git-Repo kam ein Urteil heraus: {erlaubt} / {grund}"
        finally:
            shutil.rmtree(td, ignore_errors=True)

    def test_ein_erfundener_commit_ist_ein_befund_kein_umgebungsmangel(self):
        """Die Trennung, die der Anti-Paritaets-Test erzwungen hat. ``merge-base --is-ancestor``
        gibt fuer ein UNBEKANNTES Objekt exit 128 zurueck — denselben Code wie fuer ein kaputtes
        Repo. Wer beides zusammenwirft, macht aus einem erfundenen Commit einen Umgebungsmangel und
        meldet DATA_BLOCKED statt FAIL. DATA_BLOCKED heisst aber ausschliesslich "diese Umgebung
        kann nicht messen"; ein Artefakt, das einen Commit nennt, den es hier nicht gibt, bindet
        nichts, und das ist ein Befund."""
        td, kandidat = self._baum()
        try:
            erlaubt, grund = _matrix_modul()._evidenz_relation_erlaubt(td, "0" * 40, kandidat)
            assert erlaubt is False, (
                f"ein erfundener Commit ergab {erlaubt!r} statt eines Befundes: {grund}")
            assert "does not exist" in grund
        finally:
            shutil.rmtree(td, ignore_errors=True)


class TestAnkerTraegtRolleUndFrist:
    """C3, zweite Haelfte der Auflage (Owner-Runde 2, umgesetzt 2026-09-06).

    Die erste Haelfte stand: der Anker wird aus dem committeten Blob gelesen und darf nicht im
    Kandidaten-Commit eingefuehrt worden sein. Der Rest des Satzes fehlte — "samt Digest, ROLLE,
    GUELTIGKEITSZEIT und Signierpolitik". ``signer_role`` wurde nur auf ANWESENHEIT geprueft, also
    auf ein Feld, das der Erzeuger selbst schreibt. Eine Rolle, die der Geprueft sich selbst gibt,
    ist keine Rolle; sie sagt nichts darueber, wofuer der Schluessel sprechen DARF.

    Jetzt entscheidet der Anker. Diese Klasse haelt beide Richtungen fest — dass die Bindung
    greift, und dass sie legitime Evidenz nicht abweist.
    """

    ROLLE = "readiness_und_register_signierer_600"

    @staticmethod
    def _anker(text):
        m = _matrix_modul()
        return m._anker_zeilen_lesen(text)

    def test_das_alte_flache_format_ist_kein_anker_mehr(self):
        """Eine nackte base64-Zeile sagt, WER unterschreiben darf, nicht WOFUER und BIS WANN. Sie
        weiter als "Schluessel ohne Einschraenkung" zu lesen, machte das schwaechere Format zur
        stillen Umgehung des staerkeren — und das ist der uebliche Weg, auf dem eine Verschaerfung
        wirkungslos bleibt."""
        assert self._anker("# nur ein Kommentar\nAAAABBBBCCCC\n") == {}

    #: Ein ECHTER Schluessel als Fixture, nicht `AAAA`. Bis zum 06.09.2026 stand hier ueberall die
    #: Zeichenkette `AAAA`, und die Tests waren gruen — weil der Leser das Schluesselmaterial gar
    #: nicht ansah. Review Runde 3, Abschnitt 3, Punkt 3 hat genau das verlangt: kanonisches Base64
    #: mit genau 32 dekodierten Bytes. Ein Fixture, das die neue Pruefung nicht bestehen KANN, haette
    #: die Tests in einen Zustand gebracht, in dem sie die Verschaerfung als Fehler melden.
    ECHTER_PUB = base64.b64encode(b"\x01" * 32).decode("ascii")

    def test_eine_halbe_zeile_autorisiert_nichts(self):
        """Rolle ohne Frist oder Frist ohne Rolle ist keine halbe Autorisierung, sondern keine."""
        assert self._anker(f"{self.ECHTER_PUB} role={self.ROLLE}\n") == {}
        assert self._anker(f"{self.ECHTER_PUB} not_after=2099-12-31\n") == {}

    def test_eine_vollstaendige_zeile_wird_gelesen(self):
        """Gegenrichtung: ein Parser, der alles verwirft, ist kein Parser."""
        a = self._anker(f"# Kopf\n{self.ECHTER_PUB} role={self.ROLLE} not_after=2099-12-31\n")
        assert a == {self.ECHTER_PUB: {"role": self.ROLLE, "not_after": "2099-12-31"}}

    def test_schluesselmaterial_wird_geprueft_nicht_geglaubt(self):
        """AUFLAGE A3 (Nachtrag 3): kanonisches Base64 ueber genau 32 Byte, sonst nichts.

        Vier Wege an einem echten Schluessel vorbei, alle vier muessen scheitern. Ohne diese Zeile
        legte eine Zeile wie `AAAA role=… not_after=…` einen "Schluessel" an, den keine Signatur je
        treffen kann — der Anker behauptete damit etwas ueber Material, das er nie angesehen hat.
        """
        for roh, warum in (
            ("AAAA", "zu kurz, keine 32 Byte"),
            (base64.b64encode(b"\x02" * 31).decode(), "31 Byte statt 32"),
            (base64.b64encode(b"\x03" * 33).decode(), "33 Byte statt 32"),
            ("nicht+base64!!!!" + "A" * 27 + "=", "Alphabetfremdes Zeichen"),
        ):
            assert self._anker(f"{roh} role={self.ROLLE} not_after=2099-12-31\n") == {}, warum

    def test_dubletten_und_unbekanntes_lassen_die_zeile_fallen(self):
        """Eine Zeile, die zweimal `role=` traegt, sagt nicht, WELCHE Rolle gilt — und wer sie
        schreibt, hat sie auch nicht entschieden. Vorher gewann still die letzte."""
        assert self._anker(
            f"{self.ECHTER_PUB} role={self.ROLLE} role=anderes not_after=2099-12-31\n") == {}
        assert self._anker(
            f"{self.ECHTER_PUB} role={self.ROLLE} not_after=2099-12-31 extra=x\n") == {}
        # und derselbe Schluessel in ZWEI Zeilen: beide fallen, weil die zweite die erste sonst
        # still ueberschriebe und niemand sagen kann, welche Frist gilt
        assert self._anker(
            f"{self.ECHTER_PUB} role={self.ROLLE} not_after=2099-12-31\n"
            f"{self.ECHTER_PUB} role={self.ROLLE} not_after=2020-01-01\n") == {}

    def test_eine_unbekannte_rolle_autorisiert_nichts(self):
        """Die Rolle muss aus der vorab festgelegten Liste kommen. Eine freie Zeichenkette bindet
        nichts — sie sagt nur, dass irgendwo dasselbe Wort noch einmal steht."""
        assert self._anker(
            f"{self.ECHTER_PUB} role=irgendwas-erfundenes not_after=2099-12-31\n") == {}

    def test_die_frist_ist_ein_datum_kein_text(self):
        """`9999-99-99` sortierte lexikalisch hinter jedes echte Datum und waere nie abgelaufen.
        Ein Ablaufdatum, das nicht ablaufen kann, ist keins."""
        for schlecht in ("9999-99-99", "2027-13-01", "morgen", "2027-09", ""):
            assert self._anker(
                f"{self.ECHTER_PUB} role={self.ROLLE} not_after={schlecht}\n") == {}, schlecht
        assert self._anker(
            f"{self.ECHTER_PUB} role={self.ROLLE} not_after=2027-09-06\n"), "die Gegenrichtung traegt nicht"

    @_braucht_krypto
    def test_eine_fremde_rolle_wird_abgewiesen(self, welt):
        """Der Kern. Das Artefakt behauptet eine andere Rolle als die, an die der Anker seinen
        Schluessel bindet — und wird nicht zugelassen, obwohl die Signatur mathematisch stimmt und
        der Schluessel im Anker steht."""
        m = _matrix_modul()
        koerper = _rumpf(welt, {})
        koerper["signer_role"] = "irgendwas-anderes"
        art = _signiere(koerper, welt["key"])
        trusted, zustand = m._trust_anchor(welt["repo"])
        assert zustand == "ok" and trusted, "Vorbedingung: der Baum traegt einen lesbaren Anker"
        verdikt, grund = m._artifact_signature_ok(art, trusted, zustand, repo=welt["repo"])
        assert verdikt == m.ART_UNTRUSTED, f"eine fremde Rolle kam durch: {verdikt} / {grund}"
        assert "signer_role" in grund and self.ROLLE in grund

    @_braucht_krypto
    def test_eine_fehlende_rolle_wird_abgewiesen(self, welt):
        m = _matrix_modul()
        koerper = _rumpf(welt, {})
        koerper.pop("signer_role", None)
        art = _signiere(koerper, welt["key"])
        trusted, zustand = m._trust_anchor(welt["repo"])
        verdikt, grund = m._artifact_signature_ok(art, trusted, zustand, repo=welt["repo"])
        assert verdikt == m.ART_UNTRUSTED, f"ein Artefakt ohne Rolle kam durch: {grund}"

    @_braucht_krypto
    def test_evidenz_nach_ablauf_der_frist_wird_abgewiesen(self, welt):
        """Die Gueltigkeitszeit, gemessen am Zeitpunkt der MESSUNG, nicht am Zeitpunkt des Lesens.
        Dafuer bekommt dieser Test einen eigenen Baum mit einer engen Frist — die Modul-Fixture
        traegt bewusst eine ferne, damit sie keine Zeitbombe wird."""
        m = _matrix_modul()
        eng = m._anker_zeilen_lesen(welt["pub"] + " role=readiness_und_register_signierer_600 not_after=2020-01-01\n")
        assert eng, "Vorbedingung: die enge Ankerzeile ist lesbar"
        koerper = _rumpf(welt, {})              # produced_at liegt eine Stunde in der Vergangenheit
        art = _signiere(koerper, welt["key"])
        verdikt, grund = m._artifact_signature_ok(art, eng, "ok", repo=welt["repo"])
        assert verdikt == m.ART_UNTRUSTED, f"Evidenz nach Fristablauf kam durch: {verdikt} / {grund}"
        assert "not_after" in grund

    @_braucht_krypto
    def test_innerhalb_der_frist_und_mit_passender_rolle_geht_es_durch(self, welt):
        """Die Gegenrichtung, und der Grund, warum die beiden Pruefungen oben etwas messen: eine
        Bindung, die auch legitime Evidenz abweist, hat nichts gehaertet, sondern nur zugemacht."""
        m = _matrix_modul()
        art = _signiere(_rumpf(welt, {}), welt["key"])
        trusted, zustand = m._trust_anchor(welt["repo"])
        verdikt, grund = m._artifact_signature_ok(art, trusted, zustand, repo=welt["repo"])
        assert verdikt == m.ART_VERIFIED, f"legitime Evidenz wurde abgewiesen: {verdikt} / {grund}"


class TestAnkerdigestImArtefakt:
    """C3, dritter Teil: "den Trust Anchor samt Digest ... an das Artefakt binden".

    Ohne diese Bindung sagt ein Artefakt nur, WER unterschrieben hat — nicht, gegen welche
    Vertrauensbasis das galt. Wird der Anker spaeter erweitert (ein Schluessel mehr, eine gelockerte
    Rolle, eine verlaengerte Frist), sieht ein altes Artefakt genauso aus wie vorher, und niemand
    kann sagen, unter welchem Zustand es entstand. Mit dem Digest kann das Tor genau das vergleichen.
    """

    @_braucht_krypto
    def test_ein_artefakt_ohne_ankerdigest_wird_abgewiesen(self, welt):
        m = _matrix_modul()
        koerper = _rumpf(welt, {})
        koerper.pop("trust_anchor_digest", None)
        art = _signiere(koerper, welt["key"])
        trusted, zustand = m._trust_anchor(welt["repo"])
        verdikt, grund = m._artifact_signature_ok(art, trusted, zustand, repo=welt["repo"])
        assert verdikt == m.ART_CANDIDATE_UNBOUND, f"kam ohne Ankerbindung durch: {verdikt} / {grund}"
        assert "trust_anchor_digest" in grund

    @_braucht_krypto
    def test_ein_fremder_ankerdigest_wird_abgewiesen(self, welt):
        """Der Fall, den die Auflage meint: das Artefakt entstand unter einer ANDEREN
        Vertrauensbasis als der, die heute gilt."""
        m = _matrix_modul()
        koerper = _rumpf(welt, {})
        koerper["trust_anchor_digest"] = "f" * 64
        art = _signiere(koerper, welt["key"])
        trusted, zustand = m._trust_anchor(welt["repo"])
        verdikt, grund = m._artifact_signature_ok(art, trusted, zustand, repo=welt["repo"])
        assert verdikt == m.ART_CANDIDATE_UNBOUND, f"fremder Ankerdigest kam durch: {verdikt} / {grund}"
        assert "trust basis changed" in grund

    @_braucht_krypto
    def test_der_passende_ankerdigest_geht_durch(self, welt):
        """Gegenrichtung: eine Bindung, die auch den richtigen Zustand abweist, haette nichts
        gehaertet. Und sie belegt zugleich, dass Erzeuger und Tor DENSELBEN Wert rechnen."""
        m = _matrix_modul()
        art = _signiere(_rumpf(welt, {}), welt["key"])
        trusted, zustand = m._trust_anchor(welt["repo"])
        verdikt, grund = m._artifact_signature_ok(art, trusted, zustand, repo=welt["repo"])
        assert verdikt == m.ART_VERIFIED, f"legitime Evidenz abgewiesen: {verdikt} / {grund}"

    def test_erzeuger_und_tor_rechnen_denselben_digest(self, welt):
        """Die eigentliche Klassenaussage: eine Funktion, importiert statt nachgebaut. Zwei Seiten,
        die getrennt entscheiden, WAS der Ankerdigest ist, koennten leise auseinanderlaufen — und
        beide waeren gruen, ohne etwas gemeinsam zu haben."""
        sra = _sra_modul()
        d1 = sra.trust_anchor_digest(welt["repo"])
        assert d1 and len(d1) == 64, d1
        import hashlib as _h
        import subprocess as _s
        roh = _s.run(["git", "-C", str(welt["repo"]), "show",
                      f"HEAD:{sra.TRUST_ANCHOR_REL}"], capture_output=True).stdout
        assert d1 == _h.sha256(roh).hexdigest(), "der Digest ist nicht sha256 des committeten Inhalts"

    def test_ohne_committeten_anker_gibt_es_keinen_digest_sondern_einen_leeren_string(self, welt):
        """Fail-closed: der Digest der LEEREN Zeichenkette waere ein Wert, der wie eine Bindung
        aussieht und keine ist. Stattdessen leer — und das Tor behandelt das wie einen fehlenden
        Anker."""
        sra = _sra_modul()
        leer = Path(tempfile.mkdtemp(prefix="ohne_anker_"))
        try:
            subprocess.run(["git", "init", "-q", str(leer)], capture_output=True)
            (leer / "x.txt").write_text("x\n", encoding="utf-8")
            _git(leer, "add", "-A")
            _git(leer, "-c", "user.email=a@b", "-c", "user.name=a", "commit", "-q", "-m", "ohne anker")
            assert sra.trust_anchor_digest(leer) == ""
        finally:
            shutil.rmtree(leer, ignore_errors=True)
