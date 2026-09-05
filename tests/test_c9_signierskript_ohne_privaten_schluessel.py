"""C9 (Deep-Gate 2026-09-05, Runde 2, Auflage C9): kein Codepfad im auslieferbaren Signierskript
liest einen privaten Schluessel.

WARUM DIESER TEST EXISTIERT. Eine fruehere Fassung von ``scripts/sign_readiness_artifact.py`` bot
einen dritten, INLINE Modus: ``--privkey-file`` las einen privaten ed25519-Schluessel und signierte
den selbst gebauten Rumpf im SELBEN Prozess, der ihn auch baute. Das ist Selbstbeglaubigung — eine
Signatur beweist nur dann etwas, wenn der Schluesselinhaber NICHT dieselbe Partei ist, die den
signierten Inhalt gebaut hat. ``MANIFEST.in: graft scripts`` nimmt ``scripts/`` komplett in den
sdist auf; jeder Codepfad in diesem Skript wird mit dem naechsten Bau ausgeliefert, benutzt oder
nicht.

DIE EIGENSCHAFT, ausfuehrbar formuliert: ``scripts/sign_readiness_artifact.py`` darf an KEINER
Stelle (1) einen privaten-Schluessel-Typ importieren oder benennen (``Ed25519PrivateKey`` und
Verwandte), (2) ein Flag definieren, dessen Name ``privkey`` enthaelt, oder (3) eine Funktion
``sign_body`` (oder eine gleichwertige, die einen privaten Schluessel entgegennimmt) tragen.

GEMESSEN AM AST, nicht am Text oder am Kommentar: ein Kommentar, der die Entfernung behauptet, darf
das Bestehen nicht erteilen — dieselbe Klasse von Fehlschluss wie L5-G7-04 (Aussage aus Quelltext
statt aus Struktur abgeleitet), hier auf ein Sicherheitsmerkmal statt auf eine CI-Konfiguration
angewendet.

NACHBARFLAECHE, GEPRUEFT UND BEWUSST NICHT MITGEFASST (Fix-the-Class-Sweep, 2026-09-05):
``scripts/pre_tag_receipt.py`` traegt DIESELBE Bauform (ein inline ``--privkey-file``-Modus, siehe
sein eigener Docstring "inline (default, --privkey-file)"). Das ist ein aelteres, bereits vor
diesem Fund bestehendes und eigenstaendig Owner-genehmigtes Mechanismus (siehe
``scripts/pre_tag_receipt_lib.py``, "Option C, owner-GO"), an das echte, bereits ausgelieferte
Receipts (v5.0.0, v5.1.0) gebunden sind. Dieser Test bindet sich bewusst NUR an
``sign_readiness_artifact.py`` — genau die Datei, die Auflage C9 nennt — und behauptet NICHTS
ueber ``pre_tag_receipt.py``. Der Fund ist im Klassen-Ledger (``audit_artifacts/klassen_ledger.md``)
sichtbar vermerkt, damit er nicht verloren geht.
"""
from __future__ import annotations

import ast
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SKRIPT = REPO / "scripts" / "sign_readiness_artifact.py"

#: Teilzeichenketten, deren Vorkommen in einem Bezeichner (Name, Attribut, Parameter, Import-Alias,
#: String-Literal) auf einen privaten-Schluessel-Codepfad hindeutet. Klein geschrieben, weil auf
#: kleingeschriebene Bezeichner verglichen wird.
_VERDAECHTIG = ("ed25519privatekey", "privkey", "priv_key", "private_bytes", "privatekey")


def _bezeichner(baum: ast.AST) -> set[str]:
    """Jeder Name/Attribut/Parameter/Import-Alias/Funktionsname im AST — die Grundmenge, gegen die
    die verdaechtigen Teilzeichenketten geprueft werden.

    ABSICHTLICH OHNE STRING-KONSTANTEN. Ein Docstring, der ERKLAERT, warum ``--privkey-file``
    entfernt wurde (wie der dieses Skripts es tut), nennt das Wort zwangslaeufig als PROSA — das ist
    Dokumentation, kein Codepfad. Eine erste Fassung dieser Pruefung schloss String-Konstanten mit
    ein und schlug auf ihrem EIGENEN, bereits gefixten Docstring an. Ein tatsaechlich
    wiedereingefuehrtes ``add_argument("--privkey-file")`` wird separat, gezielt und strukturell
    von ``_add_argument_flaggen`` gefangen — das ist der richtige Ort fuer eine Flaggen-Zeichenkette,
    nicht diese Funktion."""
    aus: set[str] = set()
    for knoten in ast.walk(baum):
        if isinstance(knoten, ast.Name):
            aus.add(knoten.id)
        elif isinstance(knoten, ast.Attribute):
            aus.add(knoten.attr)
        elif isinstance(knoten, ast.arg):
            aus.add(knoten.arg)
        elif isinstance(knoten, ast.alias):
            aus.add(knoten.asname or knoten.name)
        elif isinstance(knoten, (ast.FunctionDef, ast.AsyncFunctionDef)):
            aus.add(knoten.name)
    return aus


def _privater_schluessel_codepfad(quelle: str) -> set[str]:
    """Jeder Bezeichner im Quelltext, der auf einen privaten-Schluessel-Codepfad hindeutet."""
    baum = ast.parse(quelle)
    return {b for b in _bezeichner(baum) if any(v in b.lower() for v in _VERDAECHTIG)}


def _add_argument_flaggen(quelle: str) -> list[str]:
    """Jede ueber ``parser.add_argument("--irgendwas", ...)`` definierte Flagge, am AST gelesen."""
    baum = ast.parse(quelle)
    flaggen = []
    for knoten in ast.walk(baum):
        if (isinstance(knoten, ast.Call) and isinstance(knoten.func, ast.Attribute)
                and knoten.func.attr == "add_argument" and knoten.args
                and isinstance(knoten.args[0], ast.Constant)
                and isinstance(knoten.args[0].value, str)):
            flaggen.append(knoten.args[0].value)
    return flaggen


def test_das_skript_traegt_keinen_codepfad_der_einen_privaten_schluessel_liest():
    quelle = SKRIPT.read_text(encoding="utf-8")
    treffer = _privater_schluessel_codepfad(quelle)
    assert not treffer, (
        f"scripts/sign_readiness_artifact.py traegt {sorted(treffer)} — ein Codepfad, der einen "
        "privaten Schluessel liest, gehoert nicht in ein Skript, das ueber `graft scripts` im "
        "sdist ausgeliefert wird (Auflage C9, Deep-Gate Runde 2)")


def test_kein_privkey_flag_und_keine_sign_body_funktion():
    quelle = SKRIPT.read_text(encoding="utf-8")
    flaggen = _add_argument_flaggen(quelle)
    assert not any("privkey" in f.lower() for f in flaggen), (
        f"ein --privkey-artiges Flag ist noch definiert: {flaggen}")
    assert "def sign_body(" not in quelle, "die inline signierende Funktion sign_body existiert noch"


def test_nur_zwei_modi_bleiben_emit_und_assemble():
    """Die drei historischen Modi waren inline/emit/assemble (siehe Docstring-Historie). Nach C9
    bleiben genau zwei: --assemble und der schluessellose Rumpfbau ueber --emit-payload.

    GEPRUEFT WIRD DAS FLAG STRUKTURELL (ueber ``_add_argument_flaggen``), nicht per Rohtext-Suche
    ueber die GANZE Datei: der Docstring dieses Skripts NENNT ``--privkey-file`` absichtlich, um zu
    erklaeren, warum es entfernt wurde — diese Erklaerung ist erwuenschte Dokumentation, kein
    Codepfad, und eine Rohtext-Suche wuerde sie faelschlich als Verstoss lesen."""
    quelle = SKRIPT.read_text(encoding="utf-8")
    assert "--emit-payload" in quelle
    assert "--assemble" in quelle
    flaggen = _add_argument_flaggen(quelle)
    assert not any("privkey" in f.lower() for f in flaggen), \
        f"ein --privkey-artiges Flag ist trotzdem definiert: {flaggen}"


def test_gate_meta_eine_nachgebaute_inline_form_faellt_durch():
    """PLANT-AND-MUST-CATCH: eine Fassung MIT dem alten Inline-Pfad muss diese Sicherung ablehnen,
    sonst misst sie nichts (dieselbe Disziplin wie die uebrigen Gate-Meta-Tests dieser Runde)."""
    boesartig = (
        "import argparse\n"
        "from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey\n"
        "import base64\n"
        "\n"
        "def sign_body(body, privkey_b64):\n"
        "    priv = Ed25519PrivateKey.from_private_bytes(base64.b64decode(privkey_b64))\n"
        "    return priv\n"
        "\n"
        "def main():\n"
        "    p = argparse.ArgumentParser()\n"
        "    p.add_argument('--privkey-file')\n"
    )
    assert _privater_schluessel_codepfad(boesartig), \
        "der Detektor schlaegt nicht einmal auf der nachgebauten alten Form an"
    flaggen = _add_argument_flaggen(boesartig)
    assert any("privkey" in f.lower() for f in flaggen), \
        "die Flaggen-Erkennung findet das nachgebaute --privkey-file nicht"
    # Und die Gegenprobe: das ECHTE, gefixte Skript darf denselben Detektor nicht triggern.
    echte_quelle = SKRIPT.read_text(encoding="utf-8")
    assert not _privater_schluessel_codepfad(echte_quelle), \
        "der Detektor schlaegt auf dem echten, gefixten Skript faelschlich an"


def test_manifest_in_graft_scripts_ist_gemessen_nicht_vermutet():
    """Auflage C9 verlangt, den `graft scripts`-Ausschluss zu pruefen — hier steht die Messung."""
    manifest = (REPO / "MANIFEST.in").read_text(encoding="utf-8")
    zeilen = [z.strip() for z in manifest.splitlines() if z.strip() and not z.strip().startswith("#")]
    assert "graft scripts" in zeilen, (
        "MANIFEST.in graftet scripts/ nicht (mehr) — dann ist die Annahme dieses Tests ueberholt "
        "und muss neu bewertet werden, nicht stillschweigend uebernommen werden")
    assert SKRIPT.is_file(), "scripts/sign_readiness_artifact.py fehlt"
