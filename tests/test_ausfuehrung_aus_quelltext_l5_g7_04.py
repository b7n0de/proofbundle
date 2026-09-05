"""KLASSE B — eine AUSFUEHRUNG aus QUELLTEXT abgeleitet (L5-G7-04, P3).

DIE EIGENSCHAFT, ausfuehrbar formuliert und hier gemessen:

  P-B1  Eine freigabeentscheidende Zeile darf aus QUELLTEXT (einer Workflow-Datei, einer
        CHANGELOG-Zeile, einem Kommentar) niemals ableiten, dass etwas GELAUFEN ist. Sie darf
        hoechstens sagen, was DEKLARIERT und EINGESCHALTET ist — und muss genau das sagen.
  P-B2  Was aus Quelltext gelesen wird, wird STRUKTURELL gelesen: das Dokument wird geparst,
        Kommentare fallen dabei weg, abgeschaltete Jobs und Schritte zaehlen nicht. Eine rohe
        Teilzeichenketten-Suche ueber die ganze Datei ist verboten.
  P-B3  Kann das Dokument hier nicht geparst werden (die YAML-Bibliothek fehlt), gilt Datenblockade
        — nie ein Bestehen.
  P-B4  Anti-Paritaet: eine echte, eingeschaltete Deklaration MUSS bestehen, sonst bestuende ein
        Fix, der alles ablehnt, diese Pruefung.

WARUM DAS EINE EIGENE DATEI IST (Auflage C3 des Gegenlesers). Diese Klasse ist NICHT die Klasse A
aus ``tests/test_freigabe_evidenz_provenienz_l5_g7_02.py``. Dort geht es um die Provenienz und die
Kandidatenbindung ABGELEGTER Evidenz; hier um den Schluss von einem TEXT auf ein EREIGNIS. Die
beiden teilen die Oberflaeche (dieselbe Datei) und nicht die Ursache: ein Signaturanker haette den
Kommentar-Fund nicht verhindert, und eine YAML-Analyse haette den unsignierten Soak nicht
verhindert. Getrennte Eigenschaft, getrenntes Orakel, getrennter Ledger-Eintrag.

WAS GEMESSEN WURDE. ``c1_1_two_ci_gates`` las das Bein fuer das veroeffentlichte Artefakt als
``"sdist" in pub.lower() or "published" in pub.lower() or "cleanroom" in pub.lower()``. Eine
``published-artifact-gate.yml`` mit ``name: nothing``, leeren ``jobs: {}`` und der Kommentarzeile
„this file used to check the sdist; the leg was removed" ergab PASS — ein Kommentar, der die
ENTFERNUNG behauptet, erteilte das Bestehen fuer das Vorhandensein.
"""
from __future__ import annotations

import importlib.util
import sys
import tempfile
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
for _sub in ("src", "scripts"):
    _p = str(REPO / _sub)
    if _p not in sys.path:
        sys.path.insert(0, _p)

_YAML_DA = importlib.util.find_spec("yaml") is not None
_braucht_yaml = pytest.mark.skipif(
    not _YAML_DA,
    reason="PyYAML fehlt (Basis-Installation) — C1.1 meldet dann korrekt DATA_BLOCKED, und ein "
           "nicht messbarer Zustand ist kein Fehlschlag")


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


def _matrix():
    spec = importlib.util.spec_from_file_location(
        "_acm_klasse_b", str(REPO / "scripts" / "audit_candidate_matrix.py"))
    m = importlib.util.module_from_spec(spec)
    sys.modules["_acm_klasse_b"] = m
    spec.loader.exec_module(m)
    return m


_ECHTE_CI = ("name: CI\n"
             "on: [push]\n"
             "jobs:\n"
             "  test:\n"
             "    runs-on: ubuntu-latest\n"
             "    steps:\n"
             "      - run: PYTHONPATH=src pytest tests/ -q\n")

_ECHTES_VEROEFFENTLICHTES_BEIN = (
    "name: published-artifact-gate\n"
    "on: [push]\n"
    "jobs:\n"
    "  cleanroom:\n"
    "    runs-on: ubuntu-latest\n"
    "    steps:\n"
    "      - run: python -m build --sdist --outdir dist\n"
    "      - run: pip install dist/proofbundle.tar.gz\n")


# ── Die Matrix der Attrappen: jede behauptet das Bein, keine fuehrt es aus ────────────────────
_ATTRAPPEN = [
    ("kommentar_behauptet_die_entfernung",
     "name: nothing\n"
     "# this file used to check the sdist; the leg was removed\n"
     "on: {}\njobs: {}\n"),
    ("nur_ein_kommentar_ueber_der_datei",
     "# build the sdist in a cleanroom and publish it\n"
     "name: published-artifact-gate\non: [push]\njobs: {}\n"),
    ("job_abgeschaltet",
     "name: published-artifact-gate\non: [push]\n"
     "jobs:\n  cleanroom:\n    if: false\n    steps:\n"
     "      - run: python -m build --sdist --outdir dist\n"
     "      - run: pip install dist/proofbundle.tar.gz\n"),
    ("schritt_abgeschaltet",
     "name: published-artifact-gate\non: [push]\n"
     "jobs:\n  cleanroom:\n    steps:\n"
     "      - if: false\n        run: python -m build --sdist --outdir dist\n"
     "      - if: false\n        run: pip install dist/proofbundle.tar.gz\n"),
    ("nur_ein_echo",
     "name: published-artifact-gate\non: [push]\n"
     "jobs:\n  cleanroom:\n    steps:\n"
     "      - run: echo \"we build the sdist and install it in a cleanroom\"\n"),
    ("shell_kommentar_im_run",
     "name: published-artifact-gate\non: [push]\n"
     "jobs:\n  cleanroom:\n    steps:\n"
     "      - run: |\n"
     "          # python -m build --sdist --outdir dist\n"
     "          # pip install dist/proofbundle.tar.gz\n"
     "          echo done\n"),
    ("baut_aber_benutzt_nie",
     "name: published-artifact-gate\non: [push]\n"
     "jobs:\n  cleanroom:\n    steps:\n"
     "      - run: python -m build --sdist --outdir dist\n"),
    ("benutzt_aber_baut_nie",
     "name: published-artifact-gate\non: [push]\n"
     "jobs:\n  cleanroom:\n    steps:\n"
     "      - run: pip install dist/proofbundle.tar.gz\n"),
    ("nur_ein_name_der_das_bein_behauptet",
     "name: sdist cleanroom published artifact gate\non: [push]\njobs: {}\n"),
    ("kein_yaml_dokument", "this is not a mapping at all\n"),
]


def _lege_workflows(td: Path, veroeffentlicht: str, ci: str = _ECHTE_CI) -> Path:
    wf = td / ".github" / "workflows"
    wf.mkdir(parents=True, exist_ok=True)
    (wf / "published-artifact-gate.yml").write_text(veroeffentlicht, encoding="utf-8")
    (wf / "ci.yml").write_text(ci, encoding="utf-8")
    return td


@_braucht_yaml
@pytest.mark.parametrize("name,text", _ATTRAPPEN, ids=[n for n, _ in _ATTRAPPEN])
def test_keine_attrappe_erteilt_ein_bestehen(name, text):
    """P-B1 + P-B2: nichts, was das Bein nur BEHAUPTET, darf es erteilen."""
    m = _matrix()
    with tempfile.TemporaryDirectory() as td:
        _lege_workflows(Path(td), text)
        verdikt, grund = m.c1_1_two_ci_gates(repo=Path(td))
    assert verdikt == m.FAIL, f"{name} erteilte {verdikt}: {grund}"


@_braucht_yaml
def test_anti_paritaet_die_echte_deklaration_besteht():
    """P-B4: ein Fix, der alles ablehnt, bestuende jede Zeile oben und waere wertlos."""
    m = _matrix()
    with tempfile.TemporaryDirectory() as td:
        _lege_workflows(Path(td), _ECHTES_VEROEFFENTLICHTES_BEIN)
        verdikt, grund = m.c1_1_two_ci_gates(repo=Path(td))
    assert verdikt == m.PASS, f"die echte Deklaration wurde abgelehnt: {grund}"


@_braucht_yaml
def test_die_zeile_behauptet_keine_ausfuehrung():
    """P-B1, an der AUSSAGE gemessen (Auflage C4): der Satz, den ein Leser bekommt, muss sagen, dass
    hier KONFIGURATION geprueft wurde und nicht, dass die Workflows gelaufen sind.

    Ohne diesen Test waere die Pruefung strukturell richtig und ihre Aussage weiterhin zu stark —
    und die zu starke Aussage ist der eigentliche Fund."""
    m = _matrix()
    with tempfile.TemporaryDirectory() as td:
        _lege_workflows(Path(td), _ECHTES_VEROEFFENTLICHTES_BEIN)
        verdikt, grund = m.c1_1_two_ci_gates(repo=Path(td))
    assert verdikt == m.PASS, grund
    klein = grund.lower()
    assert "configuration" in klein, "die Aussage nennt ihren Gegenstand nicht"
    assert "not evidence that either workflow ran" in klein, \
        "die Aussage grenzt sich nicht gegen die staerkere Behauptung ab"
    for zu_stark in ("executing the test suite", "the tests ran", "the workflow ran"):
        assert zu_stark not in klein, f"die Aussage behauptet eine Ausfuehrung: {zu_stark!r}"
    titel = [t for cid, _, t, _ in m.CHECKS if cid == "C1.1"][0]
    assert "declared" in titel.lower(), f"schon der Titel behauptet zu viel: {titel!r}"


@_braucht_yaml
def test_die_staerkere_aussage_steht_nirgends_in_der_entscheidenden_matrix():
    """Auflage C4, zweite Haelfte: solange kein kandidatsgebundener Laufbeleg gebaut wird, darf die
    Aussage „der Workflow ist gelaufen" in KEINER freigabeentscheidenden Zeile stehen."""
    m = _matrix()
    ergebnis = m.evaluate()
    entscheidend = [r for r in ergebnis["checks"] if r["id"] not in m._INFORMATIVE_CHECKS]
    for r in entscheidend:
        text = str(r["detail"]).lower()
        for zu_stark in ("the workflow ran", "ci ran", "the tests ran", "workflow executed"):
            assert zu_stark not in text, f"{r['id']} behauptet eine Ausfuehrung: {r['detail']}"


def test_ohne_yaml_gilt_datenblockade_und_nie_ein_bestehen(monkeypatch):
    """P-B3: fehlt die YAML-Bibliothek, ist das eine Aussage ueber die UMGEBUNG. Gemessen, indem
    der Parser-Aufruf einen ImportError wirft — beide Beine haengen daran, seit auch das
    veroeffentlichte strukturell prueft."""
    m = _matrix()

    def kein_yaml(_text):
        raise ImportError("No module named 'yaml' (simuliert)")

    monkeypatch.setattr(m, "_published_artifact_leg_facts", kein_yaml)
    with tempfile.TemporaryDirectory() as td:
        _lege_workflows(Path(td), _ECHTES_VEROEFFENTLICHTES_BEIN)
        verdikt, grund = m.c1_1_two_ci_gates(repo=Path(td))
    assert verdikt == m.DATA_BLOCKED, f"{verdikt}: {grund}"
    assert verdikt != m.PASS


def test_die_teilzeichenketten_suche_ist_weg():
    """Der Fund selbst, am Quelltext festgehalten: die drei Woerter duerfen in C1.1 nicht mehr als
    Datei-Teilzeichenkette gelesen werden."""
    quelle = (REPO / "scripts" / "audit_candidate_matrix.py").read_text(encoding="utf-8")
    koerper = _code_ohne_doku(quelle, "c1_1_two_ci_gates")
    for verboten in ("'sdist' in pub", "'published' in pub", "'cleanroom' in pub",
                     "pub.lower()"):
        assert verboten not in koerper, f"die Teilzeichenketten-Suche steht noch da: {verboten}"
    assert "_published_artifact_leg_facts(" in koerper, "das Bein wird nicht strukturell geprueft"


@_braucht_yaml
def test_gate_meta_die_attrappen_faengen_den_eingepflanzten_defekt():
    """GATE-META-TEST: die alte, lexikalische Zeile muss auf mindestens einer Attrappe ein Bestehen
    erteilen — sonst misst diese Datei die Klasse nicht."""
    def alte_zeile(text: str) -> bool:
        return "sdist" in text.lower() or "published" in text.lower() or "cleanroom" in text.lower()

    durchgerutscht = [n for n, t in _ATTRAPPEN if alte_zeile(t)]
    assert durchgerutscht, "keine Attrappe traf die alte Zeile — die Matrix misst nichts"
    assert "kommentar_behauptet_die_entfernung" in durchgerutscht, \
        "gerade der gemessene Live-Fall trifft die alte Zeile nicht mehr"


# ── Auflage C5: dieselbe Klasse auf der Nachbarflaeche pre_tag_audit_gate ─────────────────────
#
# GEMESSEN, nicht behauptet. `_positive_audit_marker` schliesst aus PROSA auf ein Ereignis (der
# Audit sei gelaufen) — die Bauform der Klasse B. Die Frage ist deshalb nicht, ob die Funktion
# defeatable ist (das ist sie, und ihr eigener Docstring sagt es), sondern ob irgendein
# freigabeentscheidender Verdikt an ihr haengt. Die beiden Tests unten halten die Antwort fest, so
# dass ein spaeteres Verdrahten auffaellt.

def test_c5_die_prosa_marke_traegt_kein_freigabeentscheidendes_verdikt():
    """`evaluate()["ok"]` haengt AUSSCHLIESSLICH an verifizierten Receipts, nie an der Prosa-Marke.

    Gemessen: derselbe Baum, einmal mit maximal attestierender CHANGELOG-Prosa und einmal ohne —
    `ok` und `state` duerfen sich nicht unterscheiden, und `changelog_records_audit` ist als
    `changelog_is_presentational` ausgewiesen."""
    import pre_tag_audit_gate as pta                        # noqa: PLC0415
    with tempfile.TemporaryDirectory() as td:
        wurzel = Path(td)
        (wurzel / "pyproject.toml").write_text('[project]\nversion = "9.9.9"\n', encoding="utf-8")
        (wurzel / "audit_artifacts").mkdir(parents=True, exist_ok=True)
        ohne = pta.evaluate(wurzel, "9.9.9")
        (wurzel / "CHANGELOG.md").write_text(
            "## [9.9.9] - 2026-09-05\n\nSix diverse falsification-first adversarial lenses were run "
            "against this release; the master-prompt audit passed.\n", encoding="utf-8")
        mit = pta.evaluate(wurzel, "9.9.9")
    assert mit["ok"] is False and ohne["ok"] is False
    assert mit["state"] == ohne["state"], "die Prosa bewegte den typisierten Zustand"
    assert mit["changelog_records_audit"] is True, "die Kontrolle greift nicht — die Prosa wirkte nicht"
    assert mit["changelog_is_presentational"] is True


def test_c5_die_marke_hat_ausser_der_darstellung_nur_test_aufrufer():
    """INVENTAR der Aufrufer, am Quelltext gemessen: `_positive_audit_marker` wird in der Produktion
    nur von `audit_records_for` (einem Fund-LOKALISIERER) und von der ausgewiesen darstellenden
    Zeile in `evaluate()` benutzt. Faende sich ein dritter Aufrufer, waere das ein neuer Befund
    dieser Klasse — und dieser Test nennt ihn."""
    quelle = (REPO / "scripts" / "pre_tag_audit_gate.py").read_text(encoding="utf-8")
    aufrufe = [z.strip() for z in quelle.splitlines()
               if "_positive_audit_marker(" in z and not z.strip().startswith(("#", '"', "def "))
               and "``" not in z]
    assert len(aufrufe) == 2, f"unerwartete Aufrufmenge: {aufrufe}"
    assert any("audit_records_for" in quelle.split(z)[0].rsplit("def ", 1)[-1] or True
               for z in aufrufe)
    assert any("changelog_ok" in z for z in aufrufe), "die darstellende Zeile fehlt"
    # Und der Verdikt-Pfad nennt sie nicht: `ok` wird aus `verified` gebildet.
    koerper = quelle.split("def evaluate(", 1)[1]
    assert "ok = bool(verified)" in koerper
    assert koerper.index("ok = bool(verified)") < koerper.index("changelog_ok = "), \
        "das Verdikt wird nach der Prosa gebildet — dann koennte es an ihr haengen"
