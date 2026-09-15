"""Release-ceremony INTEGRATION test (makellose-500 round-14 gate fix, option C).

The pre-tag receipt binds ``subject_tree_digest``. It once bound the FULL ``HEAD^{tree}``, which
INCLUDES the receipt once committed -- committing the attestation changed the tree it bound, so the gate
rejected every committed receipt (circular, proven 2026-08-27). Round 13 (option B) bound
``HEAD:src/proofbundle`` and fixed the circularity, but the deep-gate refuted it: binding only the
package subtree unbinds ``pyproject.toml``, so a dependency injected AFTER signing shipped past the gate.
Round 14 (option C, owner-GO) bound the ``HEAD`` top-level tree MINUS ``audit_artifacts/``.

ROUND 15 (2026-09-07) NARROWED THAT EXCLUSION, and this test now carries the reason. Dropping the
whole directory removed the TRUST ANCHORS from the binding as well --
``audit_artifacts/pre_tag_trusted_pubkeys.txt`` is the very file the gate reads to decide who may
sign. A key added to that anchor AFTER signing left ``subject_tree_digest`` byte-identical, so a
self-signed receipt from a foreign key verified. The exclusion is now the receipt FILE (a pattern,
since every version writes its own) plus the mutable evidence a release run produces while
measuring -- never a whole directory, which is the wording ``sign_readiness_artifact.tree_digest``
had already carried since Auflage C3 while this function still did the opposite.

This test proves the REAL produce -> commit -> verify flow end-to-end (subprocess, real scripts,
real git): a committed receipt verifies, a post-signing dependency injection is REJECTED (the
refuted-option-B exploit), a src change is REJECTED, and a key smuggled into the trust anchor after
signing is REJECTED -- the exact integration the harness's fixed-constant unit tests never
exercised.
"""
import base64
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SCRIPTS = REPO / "scripts"
SRC = REPO / "src"


def _run(cmd, cwd, env=None):
    return subprocess.run(cmd, cwd=str(cwd), capture_output=True, text=True, env=env)


def _git(args, cwd):
    r = _run(["git", "-c", "user.name=t", "-c", "user.email=t@t", *args], cwd)
    assert r.returncode == 0, f"git {args} failed: {r.stderr}"
    return r


def test_committed_receipt_verifies_and_src_change_is_rejected(tmp_path):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    repo = tmp_path / "r"
    (repo / "scripts").mkdir(parents=True)
    (repo / "src" / "proofbundle").mkdir(parents=True)
    (repo / "audit_artifacts" / "500").mkdir(parents=True)
    # sign_readiness_artifact.py gehoert seit 2026-09-07 dazu: subject_tree_digest liest seine
    # MUTABLE_EVIDENCE_RELS, damit Erzeuger und Tor DIESELBEN Pfade ausschliessen. Zwei getippte
    # Listen waeren zwei Aussagen darueber, was ein Kandidat bindet, und keine Seite merkte es.
    for s in ("pre_tag_receipt.py", "pre_tag_audit_gate.py", "pre_tag_receipt_lib.py",
              "sign_readiness_artifact.py"):
        (repo / "scripts" / s).write_bytes((SCRIPTS / s).read_bytes())
    # DER MINIMALBAUM WIRD KOPIERT, NICHT GETIPPT (LAUF11, gemessen am eigenen Fix).
    # Vorher standen hier zwei Dateinamen: __init__.py und signature.py. Als der L2-Fix
    # `pre_tag_receipt.py` auf den strikten Dekoder `proofbundle._wire_b64` umstellte, fiel dieser
    # Test mit `ModuleNotFoundError` um — die getippte Liste war beim ersten neuen Import still zu
    # kurz. Der Kommentar acht Zeilen darueber warnt genau davor ("Zwei getippte Listen waeren zwei
    # Aussagen darueber, was ein Kandidat bindet"), fuer die scripts/-Liste; die src/-Liste darunter
    # war dieselbe Klasse und hat sie niemand angewandt.
    #
    # Jetzt kommt das ganze Paket mit. Die Minimalitaet des Baums ist nicht der Pruefgegenstand —
    # der ist "ein committetes Receipt verifiziert, und eine src-Aenderung wird abgelehnt".
    import shutil  # noqa: PLC0415
    shutil.rmtree(repo / "src" / "proofbundle")
    shutil.copytree(SRC / "proofbundle", repo / "src" / "proofbundle",
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
    # Die Version wird DANACH gesetzt: der Test bindet einen 5.0.0-Kandidaten, und die echte
    # __init__.py traegt die heutige Version.
    (repo / "src" / "proofbundle" / "__init__.py").write_text("__version__ = '5.0.0'\n")
    (repo / "pyproject.toml").write_text('[project]\nname = "proofbundle"\nversion = "5.0.0"\n')
    (repo / "CHANGELOG.md").write_text(
        "## [5.0.0] - 2026-08-25\naudit passed, pre-tag adversarial audit ran\n")
    (repo / "audit_artifacts" / "500" / "PRE_REGISTRATION.md").write_text(
        "pre-tag adversarial audit RUN, PASS\n")

    priv = Ed25519PrivateKey.generate()
    (repo / "audit_artifacts" / "pre_tag_trusted_pubkeys.txt").write_text(
        base64.b64encode(priv.public_key().public_bytes_raw()).decode() + "\n")
    (repo / "_privkey.b64").write_text(base64.b64encode(priv.private_bytes_raw()).decode())
    (repo / "_audit.txt").write_text("audit ran\n")

    _git(["init", "-q"], repo)
    _git(["add", "-A"], repo)
    _git(["commit", "-q", "-m", "candidate"], repo)

    # PB_INLINE_SIGNING: dieser Test prueft den INLINE-Signierweg — den Weg, den der Owner an seiner
    # eigenen Maschine geht. Seit dem Owner-Entscheid 2026-09-06 (Karte OA-8b1a31cc4f) verlangt der
    # Weg eine ausdrueckliche Freigabe, damit er auf dem Bau- und Pruefhost NICHT erreichbar ist. Der
    # Test setzt sie hier bewusst und ausschliesslich fuer seinen eigenen Unterprozess: er misst die
    # Eigenschaft "ein committetes Receipt verifiziert, eine src-Aenderung wird abgelehnt", und die
    # gibt es nur, wenn der Weg auch laufen darf. Die Sperre selbst wird getrennt geprueft
    # (tests/test_sdist_ohne_signierwerkzeug.py::TestInlineSperre, beide Richtungen).
    env = {"PYTHONPATH": f"{repo}/src:{repo}/scripts", "PATH": "/usr/bin:/bin",
           "PB_INLINE_SIGNING": "1"}

    r = _run([sys.executable, "scripts/pre_tag_receipt.py", "--repo", ".", "--version", "5.0.0",
              "--audit-command", "c", "--audit-exit", "0", "--audit-output-file", "_audit.txt",
              "--runner-identity", "test", "--produced-at", "2026-08-27T06:00:00Z",
              "--privkey-file", "_privkey.b64"], repo, env)
    assert r.returncode == 0, f"receipt production failed: {r.stderr}"
    _git(["add", "audit_artifacts/500/"], repo)
    _git(["commit", "-q", "-m", "receipt"], repo)

    # THE FIX: a committed receipt must now VERIFY (before the fix this was REJECT, tree mismatch).
    g = _run([sys.executable, "scripts/pre_tag_audit_gate.py", "--repo", ".", "--version", "5.0.0",
              "--strict"], repo, env)
    assert g.returncode == 0, f"committed receipt must verify after option-B fix: {g.stdout}\n{g.stderr}"
    assert "receipt-verified=True" in g.stdout

    # OPTION C regression (the deep-gate refuted src-only option B here): a dependency injection into
    # pyproject.toml AFTER signing must be REJECTED -- src/proofbundle is unchanged, but pyproject is
    # now inside the bound subject, so the backdoored dep can no longer ship past the gate.
    pj = repo / "pyproject.toml"
    pj.write_text(pj.read_text().replace('version = "5.0.0"',
                  'version = "5.0.0"\ndependencies = ["evil-backdoor-pkg==6.6.6"]', 1))
    _git(["add", "pyproject.toml"], repo)
    _git(["commit", "-q", "-m", "inject dep"], repo)
    gdep = _run([sys.executable, "scripts/pre_tag_audit_gate.py", "--repo", ".", "--version", "5.0.0",
                 "--strict"], repo, env)
    assert gdep.returncode == 1, f"a pyproject dep injection after signing must be REJECTED (option C), got {gdep.returncode}: {gdep.stdout}"
    assert "does not bind THIS tree" in gdep.stdout or "receipt-verified=False" in gdep.stdout

    # NOT WEAKENED: a src/proofbundle change after signing must be REJECTED.
    (repo / "src" / "proofbundle" / "__init__.py").write_text("__version__ = '5.0.0'\n# tampered\n")
    _git(["add", "-A"], repo)
    _git(["commit", "-q", "-m", "tamper src"], repo)
    g2 = _run([sys.executable, "scripts/pre_tag_audit_gate.py", "--repo", ".", "--version", "5.0.0",
               "--strict"], repo, env)
    assert g2.returncode == 1, f"a src change after signing must be REJECTED, got exit {g2.returncode}: {g2.stdout}"
    assert "does not bind THIS tree" in g2.stdout or "receipt-verified=False" in g2.stdout

    # ROUND 15: ein Schluessel, der NACH dem Signieren in den Vertrauensanker kommt, muss abgelehnt
    # werden. Das ist der ausgefuehrte Exploit vom 2026-09-07: der Anker lag im ausgeschlossenen
    # Ordner, sein Digest bewegte sich nicht, und ein selbst signiertes Receipt eines FREMDEN
    # Schluessels verifizierte. Ein Tor, das seinen eigenen Vertrauensanker nicht bindet, laesst den
    # Geprueften bestimmen, wer ihn pruefen darf.
    fremd = Ed25519PrivateKey.generate()
    anker = repo / "audit_artifacts" / "pre_tag_trusted_pubkeys.txt"
    anker.write_text(anker.read_text()
                     + base64.b64encode(fremd.public_key().public_bytes_raw()).decode() + "\n")
    _git(["add", "audit_artifacts/pre_tag_trusted_pubkeys.txt"], repo)
    _git(["commit", "-q", "-m", "smuggle key into the trust anchor"], repo)
    g3 = _run([sys.executable, "scripts/pre_tag_audit_gate.py", "--repo", ".", "--version", "5.0.0",
               "--strict"], repo, env)
    assert g3.returncode == 1, (
        "a key added to the trust anchor after signing must be REJECTED -- the anchor decides WHO "
        f"may sign, so it belongs inside the bound subject; got exit {g3.returncode}: {g3.stdout}")
    assert "does not bind THIS tree" in g3.stdout or "receipt-verified=False" in g3.stdout


def test_nur_der_versions_ordner_ist_eine_quittungsstelle(tmp_path):
    """Fund 3 der Gegenlesung 2026-09-07: der Ausschluss galt fuer JEDEN Ordnernamen.

    ``subject_tree_digest`` nimmt genau eine Datei aus der Bindung: die Quittung, die in dem Baum
    liegt, den sie bindet. Das Muster dafuer las den Ordner als ``[^/\t]+`` — also als beliebiges
    Wort. Damit fiel auch ``audit_artifacts/beliebig/pre_tag_receipt_v9.9.9.json`` heraus, obwohl
    ``beliebig`` kein Versions-Token ist. Kein Konsument nutzte das aus (``_receipt_candidates``
    scoped auf den exakten Token), aber eine Ausnahme, die mehr ausschliesst als noetig, ist der
    Anfang genau der Klasse, die dieser Commit schliesst.

    Zwei Seiten, sonst waere gruen nichts wert: die ECHTE Quittungsstelle muss weiterhin
    unsichtbar bleiben, die erfundene muss sichtbar werden.
    """
    # `sys` steht oben im Modul. Der Riegel
    # `test_kein_test_haengt_an_einem_fremden_import_nebeneffekt` misst einen Aufruf, dessen
    # Empfaenger WOERTLICH `sys` heisst (`ziel.value.id == "sys"`); ein `import sys as _sys` zaehlt
    # dort nicht als Vorbereitung. Gemessen 07.09.2026: dieser Test war der einzige Treffer im
    # ganzen Baum. Der Riegel hat recht — er misst die Wirkung, und eine Umbenennung macht die
    # Vorbereitung fuer ihn unsichtbar. Ohne sie loest der Import nur auf, solange ein ANDERER Test
    # den Pfad vorher gelegt hat: gruen im vollen Lauf, ImportError bei `-k` oder Einzellauf.
    sys.path.insert(0, str(SCRIPTS))
    from pre_tag_receipt_lib import subject_tree_digest

    repo = tmp_path / "r"
    (repo / "audit_artifacts" / "600").mkdir(parents=True)
    (repo / "audit_artifacts" / "beliebig").mkdir(parents=True)
    (repo / "datei.txt").write_text("basis\n")
    _git(["init", "-q"], repo)
    _git(["add", "-A"], repo)
    _git(["commit", "-q", "-m", "basis"], repo)
    vorher = subject_tree_digest(repo)

    # die ECHTE Quittungsstelle: bleibt aussen vor, sonst enthielte der Digest sich selbst
    (repo / "audit_artifacts" / "600" / "pre_tag_receipt_v6.0.0.json").write_text('{"a": 1}\n')
    _git(["add", "-A"], repo)
    _git(["commit", "-q", "-m", "echte quittung"], repo)
    assert subject_tree_digest(repo) == vorher, (
        "die versions-gebundene Quittung muss weiterhin ausserhalb der Bindung liegen")

    # ein frei benannter Ordner ist KEINE Quittungsstelle und gehoert in die Bindung
    (repo / "audit_artifacts" / "beliebig" / "pre_tag_receipt_v9.9.9.json").write_text('{"b": 2}\n')
    _git(["add", "-A"], repo)
    _git(["commit", "-q", "-m", "erfundene quittungsstelle"], repo)
    assert subject_tree_digest(repo) != vorher, (
        "audit_artifacts/<beliebig>/pre_tag_receipt_*.json faellt aus der Bindung — ein Angreifer "
        "duerfte den Ordnernamen nicht selbst waehlen koennen")

    # DIE ZEREMONIE-AUFLAGE, die aus derselben Eigenschaft folgt und deshalb hier festgenagelt wird:
    # ein NACHBAR im selben Versionsordner bewegt den Digest. Bis zur alten Fassung tat er das nicht
    # (sie warf das ganze Verzeichnis weg), und RESTRISIKO_600.md hat genau damit begruendet, warum
    # eine Nachsignatur nicht noetig sei. Seit der Verengung gilt: alles andere unter
    # audit_artifacts/<token>/ muss VOR der Quittung committet sein. Wird dort nach dem Signieren
    # noch etwas geschrieben, ist die Quittung ungueltig — und das faellt in einer Signaturrunde am
    # Mac auf, nicht vorher, wenn es niemand geprueft hat.
    zwischen = subject_tree_digest(repo)
    (repo / "audit_artifacts" / "600" / "PRE_TAG_AUDIT_600.md").write_text("audit ran\n")
    _git(["add", "-A"], repo)
    _git(["commit", "-q", "-m", "pruefbericht neben der quittung"], repo)
    assert subject_tree_digest(repo) != zwischen, (
        "ein Pruefbericht im selben Versionsordner muss den Digest bewegen — sonst waere die "
        "Reihenfolge-Auflage in RESTRISIKO_600.md unbelegt und die Bindung wieder loechrig")


def test_ein_baum_mit_null_eintraegen_ist_kein_digest(tmp_path):
    """Die stille Leermessung — und sie geht MITTEN durch die Formpruefung hindurch.

    `git -C <pfad> ls-tree -r HEAD` endet mit rc=0 und LEERER Ausgabe, wenn unter dem Pfad nichts
    getrackt ist. Der Digest waere dann sha256("") = e3b0c442... — 64 Stellen Kleinhex, formal
    einwandfrei. Gemessen von einer Gegenlesung am 2026-09-07, Ende zu Ende mit echtem Schluessel:
    eine darauf signierte Quittung ergab `ok=true, state=verified` mit dem Grund "signed,
    tree-bound, successful-audit receipt verified" — ueber einen Baum, in dem sich anschliessend
    JEDE Datei aendern durfte, ohne den Digest zu bewegen.

    Die Formpruefung kann das nicht fangen: sie fragt nach der FORM des Wertes, nie nach seiner
    HERKUNFT. Deshalb ein eigener Riegel, und deshalb ein eigener Test — ohne ihn ueberlebte die
    Mutation, die den Riegel wieder herausnimmt, die gesamte Suite (gemessen: 74 passed).
    """
    import sys as _s

    _s.path.insert(0, str(SCRIPTS))
    from pre_tag_receipt_lib import BaumNichtLesbar, subject_tree_digest

    repo = tmp_path / "r"
    unterordner = repo / "nichts_getrackt"
    unterordner.mkdir(parents=True)
    (repo / "datei.txt").write_text("basis\n")
    _git(["init", "-q"], repo)
    _git(["add", "-A"], repo)
    _git(["commit", "-q", "-m", "basis"], repo)

    # Kontrolle: die Wurzel misst etwas.
    voll = subject_tree_digest(repo)
    assert len(voll) == 64 and voll != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

    # Der Unterordner traegt keine getrackte Datei — `ls-tree` sagt rc=0 und nichts.
    with pytest.raises(BaumNichtLesbar) as fehler:
        subject_tree_digest(unterordner)
    assert "ZERO entries" in str(fehler.value), str(fehler.value)


def test_eine_lokale_version_faellt_aus_der_bindung(tmp_path):
    """PEP 440 kennt `+local` und `1!epoch`. Das Muster muss sie kennen, sonst ist die Quittung
    im eigenen Digest enthalten — zirkulaer, sie kann nie verifizieren.

    Gemessen 2026-09-07: `6.1.0+local` und `1!6.0.0` fielen NICHT aus dem Ausschluss, weder in der
    alten noch in der ersten verengten Fassung (die Zeichenklasse des DATEINAMENS kannte `+` und `!`
    in beiden nicht). Kein Sicherheitsloch, ein Funktionsdefekt — und ohne diesen Test ueberlebte
    die Mutation, die `+` und `!` wieder entfernt, die gesamte Suite (gemessen: 74 passed).
    """
    import sys as _s

    _s.path.insert(0, str(SCRIPTS))
    from pre_tag_receipt_lib import subject_tree_digest

    repo = tmp_path / "r"
    (repo / "audit_artifacts" / "610+local").mkdir(parents=True)
    (repo / "datei.txt").write_text("basis\n")
    _git(["init", "-q"], repo)
    _git(["add", "-A"], repo)
    _git(["commit", "-q", "-m", "basis"], repo)
    vorher = subject_tree_digest(repo)

    (repo / "audit_artifacts" / "610+local" / "pre_tag_receipt_v6.1.0+local.json").write_text(
        '{"a": 1}\n')
    _git(["add", "-A"], repo)
    _git(["commit", "-q", "-m", "quittung fuer eine lokale version"], repo)
    assert subject_tree_digest(repo) == vorher, (
        "eine Quittung fuer eine PEP-440-Lokalversion liegt im eigenen Digest — zirkulaer, sie "
        "kann nie verifizieren")
