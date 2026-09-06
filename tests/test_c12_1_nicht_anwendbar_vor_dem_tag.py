"""C12.1 on a pull request: not applicable, not broken — and still sharp everywhere else.

WHY. The owner decision of 2026-08-30 (card OA-4a8daddb55, quoted in the check's own docstring)
says a receipt issued against a work branch would attest a tree that is about to stop existing —
producing one anyway would be the very act this check exists to catch. That decision stands. Its
consequence, though, was that C12.1 is red on EVERY pull request, and a check that is always red
carries no information and teaches every reader to walk past red. Under PR 178, publicly linked
from the SCITT list, an outside reader saw a red cross on a contribution we call clean.

WHAT CHANGES AND WHAT DOES NOT. `audit_candidate_ready` is untouched and keeps saying False for a
work branch — the JSON tells the truth. Only the EXIT CODE stops labelling a work branch broken.
No receipt is produced for a branch; it is merely no longer pretended that one could exist.

THE MUTANT THE ORDER ASKS FOR: a tag run without a receipt must still go red. That is the whole
point of the narrowing, so it is tested first and from several directions.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SKRIPT = REPO / "scripts" / "audit_candidate_matrix.py"


def _lauf(event: str | None) -> subprocess.CompletedProcess:
    import os
    env = dict(os.environ)
    if event is None:
        env.pop("GITHUB_EVENT_NAME", None)
    else:
        env["GITHUB_EVENT_NAME"] = event
    return subprocess.run([sys.executable, str(SKRIPT)], capture_output=True, text=True,
                          cwd=str(REPO), env=env, timeout=300)


def _quittungslage() -> str:
    """``GUELTIG`` | ``ABGELEHNT`` | ``ABWESEND`` | ``NICHT_MESSBAR`` — der Zustand der Quittungen im
    Baum, gemessen OHNE das Tor zu fragen, dessen Matrixzeile hier geprueft wird.

    ES RUFT DIE REGEL AUF, STATT SIE NACHZUBAUEN. Die erste Fassung baute die Gueltigkeit selbst
    nach und prueste DREI Bedingungen: Baumbindung, Signierer im Anker, Ed25519-Signatur. Gemessen
    am 06.09.2026 gegen die echten Produktionsfunktionen: ``verify_receipt`` prueft SIEBEN — dazu
    ``schema``, ``version``, ``gate_source_digest`` und ``audit_exit_code``. Eine korrekt signierte
    Quittung ueber einen FEHLGESCHLAGENEN Audit (``audit_exit_code=1``) galt dem Nachbau als
    gueltig. Zwei Implementierungen derselben Regel driften auseinander; das ist hier gemessen,
    nicht befuerchtet. Register: MEIN-GUELTIGKEITSORAKEL-IST-SCHWAECHER-ALS-DAS-TOR-VIER-FELDER-01.

    DREI ZUSTAENDE, NICHT ZWEI. Das Tor unterscheidet ``absent`` / ``rejected`` / ``verified``, und
    die Nachsicht auf einem Pull Request gilt AUSSCHLIESSLICH der Abwesenheit (Fund L5-G6-01 vom
    05.09.2026). Ein Orakel mit nur zwei Zustaenden kann diese Zeile nicht pruefen — es hat die
    Unterscheidung schon verloren, bevor der Vergleich beginnt.

    DIESELBE MENGE WIE DAS TOR. Adressiert wird ueber ``_version_token`` und ``pyproject_version``
    des Tors, und gelesen wird JEDE ``*.json`` unter dem Versionsordner — nicht die eine Datei, die
    hier erwartet wird. Ein Orakel, das eine kleinere Menge betrachtet als der Prueflig, urteilt aus
    einer stillschweigend verkleinerten Population; das ist genau die Klasse von N17 und von
    L5G801, hier im eigenen Pruefwerkzeug vermieden. Adressierung ist nicht Urteil: das Urteil
    kommt aus ``pre_tag_receipt_lib.verify_receipt``, nicht aus dem Tor.
    """
    import hashlib
    import json
    for p in (REPO / "scripts", REPO / "src"):
        if str(p) not in sys.path:
            sys.path.insert(0, str(p))
    from pre_tag_audit_gate import _version_token, pyproject_version
    from pre_tag_receipt_lib import load_trusted_pubkeys, subject_tree_digest, verify_receipt

    version = pyproject_version(REPO)
    if not version:
        return "NICHT_MESSBAR"          # nie „abwesend" — Unmessbarkeit ist ein eigener Zustand
    # EIN UMGEBUNGSMANGEL IST KEINE ABLEHNUNG (Gegenlesung 06.09.2026). ``verify_receipt`` importiert
    # ``proofbundle.signature`` ERST BEIM AUFRUF. Fehlt ``src`` auf dem Pfad, wirft es
    # ModuleNotFoundError — und ein pauschales ``except Exception`` unten haette daraus ein
    # „ungueltig" gemacht: falsches FAIL aus einem fehlenden Import. Das Tor hat fuer genau diese
    # Klasse einen eigenen P1-A-Fix (pre_tag_audit_gate.py:276-284); hier wird sie NICHT als Urteil
    # verkleidet, sondern als das gemeldet, was sie ist.
    try:
        from proofbundle.signature import verify_ed25519  # noqa: F401
    except Exception:                   # noqa: BLE001
        return "NICHT_MESSBAR"
    ordner = REPO / "audit_artifacts" / _version_token(version)
    kandidaten = sorted(q for q in ordner.rglob("*.json") if q.is_file()) if ordner.is_dir() else []
    if not kandidaten:
        return "ABWESEND"
    tree = subject_tree_digest(REPO)
    gate_src = hashlib.sha256((REPO / "scripts" / "pre_tag_audit_gate.py").read_bytes()).hexdigest()
    trusted = load_trusted_pubkeys(REPO)
    for q in kandidaten:
        try:
            r = json.loads(q.read_text(encoding="utf-8", errors="ignore"))
        except (OSError, ValueError):
            continue                     # da, aber unlesbar: eine ABLEHNUNG, keine Abwesenheit
        if not isinstance(r, dict):
            continue
        try:
            ok, _grund = verify_receipt(r, trusted_pubkeys=trusted, expected_version=version,
                                        subject_tree_digest=tree, gate_source_digest=gate_src)
        except Exception:                # noqa: BLE001 — NICHT MESSBAR ist keine Gueltigkeit
            ok = False
        if ok:
            return "GUELTIG"
    return "ABGELEHNT"


@pytest.mark.parametrize("event", [None, "", "push", "release", "workflow_dispatch", "schedule",
                                   "Pull_Request", "pull-request", "pull_requestX"])
def test_ausserhalb_eines_pull_request_haengt_c12_1_an_der_GUELTIGKEIT(event):
    """DER MUTANT, praezisiert am 2026-09-06 auf Owner-Auflage — und STRENGER als vorher.

    DIE ALTE FASSUNG NAGELTE EINEN UEBERGANGSZUSTAND FEST. Sie sicherte zu, dass C12.1 ausserhalb
    eines Pull Requests UNTER FAIL steht. Das war wahr, solange keine Quittung existierte, und
    wurde in dem Augenblick falsch, in dem die Zeremonie GELANG: der Owner signierte die
    Pre-Tag-Quittung, sie lag im Baum, C12.1 bestand zu Recht — und der Test fiel zehnmal, ohne dass
    irgendetwas kaputt war. Ein Test, den der Erfolg der geprueften Sache rot macht, misst einen
    Weltzustand und keine Eigenschaft; von aussen ist er von einem echten Rueckfall nicht zu
    unterscheiden und lehrt jeden Leser, an Rot vorbeizugehen.

    DIE OWNER-AUFLAGE, woertlich: „C12.1 darf nur bestehen, wenn eine Quittung da ist UND sie
    gueltig ist, also Signatur prueft und diesen Kandidaten bindet. Sonst faellt sie."

    Das ist NICHT die weiche Fassung. Die weiche waere gewesen, nur noch zu pruefen, dass die
    Verengung nicht greift — damit haette eine UNGUELTIGE Quittung C12.1 bestehen lassen. Hier
    haengt das Urteil an der Gueltigkeit, gemessen von einem Orakel, das das Tor nicht fragt.

    ZWEI ZUSICHERUNGEN, beide in JEDEM Weltzustand wahr:
      1. ausserhalb der woertlichen Zeichenkette ``pull_request`` kollabiert C12.1 NIE auf ``n.a.``;
      2. C12.1 besteht GENAU DANN, wenn eine gueltige Quittung vorliegt — sonst faellt sie.
    """
    r = _lauf(event)
    zeilen = [z for z in r.stdout.splitlines() if "C12.1" in z]
    assert zeilen, f"C12.1 kommt im Bericht gar nicht vor\n{r.stdout[-600:]}"

    # 1 — DIE ZEILE SELBST, nicht irgendeine n.a.-Zeile: in einem Bericht, in dem ohnehin etwas
    # anderes `n.a.` ist, waere `"[ n.a.]" in stdout` auch dann wahr, wenn C12.1 scharf blieb.
    entschaerft = [z for z in zeilen if z.startswith("  [ n.a.]")]
    assert not entschaerft, (
        f"GITHUB_EVENT_NAME={event!r} hat C12.1 auf 'nicht anwendbar' verengt — die Verengung "
        f"gehoert AUSSCHLIESSLICH auf das woertliche 'pull_request'\n{entschaerft}")

    # 2 — das Urteil haengt an der GUELTIGKEIT, nicht an der Anwesenheit und nicht am Weltzustand.
    lage = _quittungslage()
    if lage == "NICHT_MESSBAR":
        pytest.skip("die Version ist hier nicht lesbar — dann ist die Lage NICHT MESSBAR, und ein "
                    "Urteil aus einer nicht messbaren Lage waere geraten")
    unter_fail = [z for z in zeilen if z.startswith("  [FAIL ]")]
    if lage == "GUELTIG":
        assert not unter_fail, (
            "eine GUELTIGE Quittung liegt vor (Signatur prueft, bindet diesen Baum) und C12.1 "
            f"faellt trotzdem — das Tor liest sie nicht\n{unter_fail}")
    else:
        assert unter_fail, (
            f"Lage {lage} — C12.1 MUSS fallen. Sie tut es nicht, also besteht ein Release-Tor "
            f"ohne Beleg\n{r.stdout[-600:]}")


def test_ANTI_PARITAET_das_orakel_unterscheidet_ueberhaupt():
    """OHNE DIESE HAELFTE waere ein Orakel, das IMMER dasselbe sagt, oben gruen — und die zweite
    Zusicherung wertlos. Geprueft wird an KOPIEN im Speicher, der Kandidatenbaum wird NICHT
    angefasst: ein Test, der den Baum mutiert, den er misst, ist der Fehler von heute frueh.

    DIE ERSTE FASSUNG BRAUCHTE EINE GUELTIGE QUITTUNG ALS BASISFALL — und war damit genau in dem
    Fenster rot, in dem die Zeremonie lebt. Gemessen am 06.09.2026 in der Vollsuite gegen den
    eingefrorenen Kandidaten: die Quittung im Baum band einen frueheren Kopf, `assert prueft(echt)`
    fiel, und der Test meldete einen Defekt an einer Stelle, an der keiner war. Das ist dieselbe
    Klasse, die dieser Umbau beseitigen sollte — ein Uebergangszustand als Invariante festgenagelt —,
    nur von der anderen Seite. Register: TEST-NAGELT-EINEN-UEBERGANGSZUSTAND-ALS-INVARIANTE-FEST-01.

    DIE FASSUNG HIER BRAUCHT KEINEN GUELTIGEN BASISFALL. Sie repariert die Vorlage in genau den
    Feldern, die NICHT die Signatur sind, und misst dann, ob die Regel fuer FUENF verschiedene
    Defekte FUENF verschiedene Gruende nennt. Ein konstantes Orakel — immer True, immer False, oder
    immer derselbe Grund — faellt hier in jedem Weltzustand. Das ist strenger als der alte
    Basisfall und haengt nicht mehr davon ab, ob der Owner schon signiert hat.
    """
    import base64
    import hashlib
    import json
    for p in (REPO / "scripts", REPO / "src"):
        if str(p) not in sys.path:
            sys.path.insert(0, str(p))
    from pre_tag_audit_gate import _version_token, pyproject_version
    from pre_tag_receipt_lib import load_trusted_pubkeys, subject_tree_digest, verify_receipt

    version = pyproject_version(REPO)
    if not version:
        pytest.skip("die Version ist hier nicht lesbar — ohne sie gibt es keine Vorlage")
    ordner = REPO / "audit_artifacts" / _version_token(version)
    vorlagen = sorted(q for q in ordner.rglob("*.json") if q.is_file()) if ordner.is_dir() else []
    echt = None
    for q in vorlagen:
        try:
            kandidat = json.loads(q.read_text(encoding="utf-8", errors="ignore"))
        except (OSError, ValueError):
            continue
        if isinstance(kandidat, dict) and "signature" in kandidat and "signer_pubkey" in kandidat:
            echt = kandidat
            break
    if echt is None:
        pytest.skip("keine Quittung im Baum — die Unterscheidungsprobe braucht eine echte Vorlage")

    tree = subject_tree_digest(REPO)
    gate_src = hashlib.sha256((REPO / "scripts" / "pre_tag_audit_gate.py").read_bytes()).hexdigest()
    trusted = load_trusted_pubkeys(REPO)

    def pruef(r: dict) -> tuple[bool, str]:
        try:
            return verify_receipt(r, trusted_pubkeys=trusted, expected_version=version,
                                  subject_tree_digest=tree, gate_source_digest=gate_src)
        except Exception as exc:  # noqa: BLE001
            return False, f"verify_receipt raised {type(exc).__name__}"

    # DIE BASIS: in allen Feldern ausser der Signatur auf DIESEN Baum gestellt. Sie muss fallen —
    # die Signatur deckt die geaenderten Felder nicht mehr —, und ihr Grund muss sich von jedem
    # Mutantengrund unterscheiden. Genau daran zeigt sich, dass die vorherigen Bedingungen alle
    # passiert wurden und die Regel wirklich der Reihe nach prueft.
    basis = dict(echt, subject_tree_digest=tree, version=version,
                 gate_source_digest=gate_src, audit_exit_code=0)
    ok_basis, grund_basis = pruef(basis)
    # DIE REPARATUR KANN EIN NO-OP SEIN, und dann ist die Annahme darueber falsch, nicht die Regel.
    # Gemessen am 07.09.2026 in der Vollsuite gegen den eingefrorenen Kandidaten: die Quittung im
    # Baum band GENAU diesen Kopf, diese Version, diesen Gate-Digest und `audit_exit_code=0`, also
    # war `basis` BITGLEICH mit `echt` — und `verify_receipt` akzeptierte sie voellig zu Recht.
    # Der Test meldete daraufhin „die Signatur deckt die Felder nicht" an einer Stelle, an der die
    # Signatur genau das tut. Gegenprobe im selben Lauf: ein einzelnes wirklich veraendertes Feld
    # (`subject_tree_digest` auf Nullen, als erwartet mitgegeben) liefert `False` mit dem Grund
    # „ed25519 signature does not verify over the canonical receipt bytes" — die Deckung besteht.
    # Dritte Form derselben Klasse in dieser Datei: ein Uebergangszustand als Invariante festgenagelt.
    # Register: TEST-NAGELT-EINEN-UEBERGANGSZUSTAND-ALS-INVARIANTE-FEST-01.
    if basis != echt:
        assert not ok_basis, (
            "eine Quittung, deren signierte Felder nachtraeglich auf diesen Baum gestellt wurden, "
            f"wird AKZEPTIERT — dann deckt die Signatur die Felder nicht, die sie decken soll\n"
            f"geaenderte Felder: {sorted(k for k in basis if echt.get(k) != basis.get(k))}")

    faelle = {
        "fremder Baum": dict(basis, subject_tree_digest="0" * 64),
        "nicht verankerter Signierer": dict(basis, signer_pubkey=base64.b64encode(b"\x01" * 32).decode()),
        "fehlgeschlagener Audit": dict(basis, audit_exit_code=1),
        "fremdes Schema": dict(basis, schema="nicht.unser.schema.v1"),
        "fremde Version": dict(basis, version="0.0.0"),
    }
    gruende: dict[str, str] = {}
    for name, r in faelle.items():
        ok, grund = pruef(r)
        assert not ok, f"{name}: die Regel hat eine erkennbar defekte Quittung AKZEPTIERT"
        gruende[name] = grund

    # DIE EIGENTLICHE ANTI-PARITAET: fuenf verschiedene Defekte, fuenf verschiedene Gruende, und
    # keiner davon der Grund der Basis. Ein Orakel, das immer dasselbe sagt, faellt hier — und ein
    # Orakel, das die Faelle zusammenwirft (etwa `audit_exit_code=1` gar nicht erst prueft), auch.
    alle = dict(gruende, __basis__=grund_basis)
    doppelt = {g for g in alle.values() if list(alle.values()).count(g) > 1}
    assert not doppelt, (
        "verschiedene Defekte fuehren zum SELBEN Grund — dann unterscheidet die Regel sie nicht:\n"
        + "\n".join(f"  {k}: {v}" for k, v in alle.items()))


def _fail_zeilen(stdout: str) -> list[str]:
    return [z for z in stdout.splitlines() if z.startswith("  [FAIL ]")]


def test_auf_einem_pull_request_ist_sie_nicht_anwendbar_statt_gebrochen():
    """DIE EIGENSCHAFT IST LOKAL, DER AUSGANGSCODE IST GLOBAL.

    Die erste Fassung pruefte `rc == 0`, um eine Aussage ueber EINE Zeile zu belegen. Im
    hermetischen Cleanroom faellt C12.2 (internal audit pack) aus einem ganz anderen Grund — die
    Registerdatei liegt dort nicht —, der Lauf endet zu Recht mit 1, und der Test meldete einen
    Defekt an einer Stelle, an der keiner ist. Gemessen am 04.09.2026 in der Cleanroom-Bahn von
    PR 181, an keinem anderen Ort reproduzierbar.

    DREI LAGEN, NICHT ZWEI (praezisiert am 06.09.2026). Die zweite Fassung sicherte UNBEDINGT zu,
    dass C12.1 auf einem Pull Request nie unter FAIL steht. Das Tor unterscheidet aber drei
    Zustaende, und die Nachsicht gilt AUSSCHLIESSLICH der Abwesenheit: eine ABGELEHNTE Quittung
    bleibt auch auf einem Pull Request FAIL — das ist Fund L5-G6-01 vom 05.09.2026, im Nachbartest
    woertlich als `# THE FINDING` kommentiert. Die unbedingte Zusicherung hat genau diese
    Unterscheidung wieder eingeebnet und ist in der Vollsuite gegen den eingefrorenen Kandidaten
    rot gefallen, waehrend das Tor voellig richtig arbeitete: die Quittung im Baum band einen
    frueheren Kopf, das Tor sagte `rejected`, und der Test nannte das einen Defekt.

    Geprueft wird deshalb die Entsprechung zwischen der LAGE der Quittungen und der Zeile:
      ABWESEND  -> `n.a.`, nicht FAIL   (das ist die Verengung, um die es geht)
      ABGELEHNT -> FAIL, nicht `n.a.`   (die Nachsicht gilt nicht einem bekannt schlechten Artefakt)
      GUELTIG   -> weder FAIL noch `n.a.`
    Der Ausgangscode wird nur dort geprueft, wo er ueberhaupt etwas ueber C12.1 sagt — naemlich
    wenn keine ANDERE Zeile faellt.
    """
    r = _lauf("pull_request")
    fails = _fail_zeilen(r.stdout)
    c121_fail = [z for z in fails if "C12.1" in z]
    c121_na = [z for z in r.stdout.splitlines() if z.startswith("  [ n.a.]") and "C12.1" in z]
    lage = _quittungslage()
    if lage == "NICHT_MESSBAR":
        pytest.skip("die Version ist hier nicht lesbar — ein Urteil aus einer nicht messbaren Lage "
                    "waere geraten")
    if lage == "ABWESEND":
        assert not c121_fail, f"KEINE Quittung, trotzdem faellt C12.1 auf einem PR:\n{fails}"
        assert c121_na, (
            "KEINE Quittung auf einem PR — dann MUSS C12.1 `n.a.` tragen statt zu fallen, das ist "
            f"der ganze Zweck der Verengung\n{r.stdout[-600:]}")
        assert "nicht anwendbar vor dem Tag" in r.stdout
    elif lage == "ABGELEHNT":
        assert c121_fail, (
            "eine ABGELEHNTE Quittung liegt im Baum — dann MUSS C12.1 auch auf einem Pull Request "
            "fallen. Die Nachsicht gilt der ABWESENHEIT, nie einem bekannt schlechten Artefakt "
            f"(Fund L5-G6-01)\n{r.stdout[-600:]}")
        assert not c121_na, (
            f"eine ABGELEHNTE Quittung wurde auf `n.a.` verengt — genau die Luecke aus L5-G6-01\n{c121_na}")
    else:
        assert not c121_fail, (
            "eine GUELTIGE Quittung liegt vor und C12.1 faellt trotzdem — das Tor liest sie nicht\n"
            f"{c121_fail}")
        assert not c121_na, (
            "eine GUELTIGE Quittung liegt vor — dann ist C12.1 anwendbar und BESTEHT; ein `n.a.` "
            "waere die Verengung an der falschen Stelle")
    # KEIN `assert r.returncode == 0` MEHR — er war der Rueckfall in genau den Fehler, den der
    # Kopf dieses Docstrings beschreibt. Gemessen am 07.09.2026: der Lauf endet mit 1, ohne dass
    # eine einzige Zeile faellt. Die Verdikte sind 31 PASS, ein DATA_BLOCKED (C6.3, der 24h-Soak
    # lief 300 s) und ein EXTERNAL_PENDING (EXT.1, das absichtlich offene Aussentor).
    # `main()` gewaehrt die Nachsicht nur, wenn `_na` NICHT LEER ist — es muss also mindestens eine
    # Zeile `NOT_APPLICABLE` tragen. Sobald die Zeremonie GELINGT und eine gueltige Quittung im
    # Baum liegt, ist C12.1 `[ ok ]` statt `n.a.`, `_na` wird leer, und der Lauf faellt auf 1
    # zurueck, obwohl nichts gebrochen ist. Das ist ein Befund AM TOR (falsches Rot, nie falsches
    # Gruen) und in dieser Runde ausdruecklich nicht angefasst; hier zaehlt nur, dass er nichts
    # ueber C12.1 aussagt. Die Eigenschaft, um die es geht, steht vollstaendig in den drei
    # Lage-Zweigen darueber. Register: MATRIX-IST-NUR-GRUEN-SOLANGE-ETWAS-NICHT-ANWENDBAR-IST-01.


def test_die_wahrheit_im_bericht_bleibt_unveraendert():
    """Der Ausgangscode sagt „blockiert diese Pruefung dieses Objekt", nicht „ist es fertig".
    Ein Arbeitszweig ist NICHT release-bereit, und das muss weiterhin dastehen — sonst haette
    die Aenderung eine Unwahrheit erzeugt statt eine Fehlbeschuldigung zu beenden."""
    r = _lauf("pull_request")
    assert "audit_candidate_ready=False" in r.stdout, r.stdout[-600:]


def test_nur_dieser_eine_fehlschlag_wird_umgedeutet():
    """ENGE. Ein kaputtes oder nicht vertrauenswuerdiges Receipt bleibt FAIL, auch auf einem PR —
    sonst waere aus einer Praezisierung eine Abschaltung geworden.

    ERSETZT (Tiefen-Gate 2026-09-05, Fund L5-G6-01, P2). Hier stand ein QUELLTEXT-Vergleich:

        assert '_laeuft_auf_pull_request() and "no valid pre-tag audit RECEIPT" in' in quelle

    Er behauptete die Enge und mass sie nicht. Genau die Zeile, die er als Beleg zitierte, WAR der
    Defekt: der Satz „no valid pre-tag audit RECEIPT" steht im Tor-Grund bei Abwesenheit UND bei
    Ablehnung, also wurden ein fremder Signierer, eine manipulierte Signatur, ein kopiertes
    5.0.0-Receipt und eine unlesbare Datei auf einem PR alle vier zu NOT_APPLICABLE — und dieser Test
    war dabei gruen, weil die zitierte Zeichenkette ja dastand. Ein Test, der den Prueflig nach dem
    Wortlaut absucht, den er abschaffen soll, kann nicht bemerken, dass der Wortlaut stimmt und das
    Verhalten falsch ist.

    Gemessen wird jetzt die Bindung an das TYPISIERTE Feld; das Verhalten ueber alle vier
    Ablehnungsformen steht in tests/test_pretag_gate_state_typed_l5_g6_01.py.
    """
    quelle = SKRIPT.read_text(encoding="utf-8")
    assert '_laeuft_auf_pull_request() and r.get("state") == "absent"' in quelle, (
        "die Umdeutung haengt nicht mehr am typisierten Zustand des Tors")
    # NUR CODE-ZEILEN, und der Grund ist beim Schreiben dieses Tests aufgetreten: der Kommentar, der
    # den Fund erklaert, ZITIERT die alte Regel woertlich. Ein Griff ueber die ganze Datei fand das
    # Zitat und meldete einen Rueckfall, den es nicht gibt — dieselbe Klasse wie der Fund selbst
    # (eine Entscheidung an einem Textvorkommen statt an der Sache), diesmal im Pruefwerkzeug.
    codezeilen = "\n".join(z for z in quelle.splitlines() if not z.lstrip().startswith("#"))
    assert '"no valid pre-tag audit RECEIPT" in' not in codezeilen, (
        "die Prosa-Verengung ist zurueck — ein abgelehntes Receipt erbt wieder die Nachsicht "
        "der Abwesenheit")


def test_jede_zeile_traegt_einen_namen_vor_ihrem_kuerzel():
    """Owner 04.09.2026: „was ist c12.1? das muessen wir umbenennen wenn das oefter kommt in
    menschenlesbar". MUTANT: eine Zeile ohne Namen macht diesen Test rot."""
    r = _lauf("pull_request")
    zeilen = [z for z in r.stdout.splitlines()
              if z.startswith("  [") and "] " in z and "(§" in z]
    assert zeilen, r.stdout[-600:]
    ohne = [z for z in zeilen if not __import__("re").search(r"\]\s+\S.*\((C\d+\.\d+|EXT\.\d+)\)\s+\(§", z)]
    assert not ohne, "Zeile(n) ohne Name vor dem Kuerzel:\n" + "\n".join(ohne[:5])
