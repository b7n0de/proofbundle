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


def _gueltige_quittung_liegt_vor() -> bool:
    """UNABHAENGIGES ORAKEL — es fragt NICHT das Tor, das hier geprueft wird.

    Es rechnet selbst nach, was „gueltig" heisst: die Datei existiert, ist lesbares JSON, ihr
    ``subject_tree_digest`` ist der DIESES Baums, ihr Signierschluessel steht im COMMITTETEN
    Vertrauensanker, und die Signatur verifiziert ueber genau die kanonischen Bytes. Faellt eine
    dieser Bedingungen, ist die Antwort False — nie „unbekannt, also ja".
    """
    import base64
    import json
    sys.path.insert(0, str(REPO / "scripts"))
    from pre_tag_receipt_lib import canonical_bytes, load_trusted_pubkeys, subject_tree_digest
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    p = REPO / "audit_artifacts" / "600" / "pre_tag_receipt_v6.0.0.json"
    if not p.is_file():
        return False
    try:
        r = json.loads(p.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return False
    if r.get("subject_tree_digest") != subject_tree_digest(REPO):
        return False                      # bindet einen ANDEREN Baum
    pub = r.get("signer_pubkey")
    if pub not in load_trusted_pubkeys(REPO):
        return False                      # fremder Signierer
    try:
        Ed25519PublicKey.from_public_bytes(base64.b64decode(pub)).verify(
            base64.b64decode(r["signature"]), canonical_bytes(r))
    except Exception:                     # noqa: BLE001 — jede Ablehnung ist eine Ablehnung
        return False
    return True


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
    unter_fail = [z for z in zeilen if z.startswith("  [FAIL ]")]
    if _gueltige_quittung_liegt_vor():
        assert not unter_fail, (
            "eine GUELTIGE Quittung liegt vor (Signatur prueft, bindet diesen Baum) und C12.1 "
            f"faellt trotzdem — das Tor liest sie nicht\n{unter_fail}")
    else:
        assert unter_fail, (
            "KEINE gueltige Quittung — C12.1 MUSS fallen. Sie tut es nicht, also besteht ein "
            f"Release-Tor ohne Beleg\n{r.stdout[-600:]}")


def test_ANTI_PARITAET_das_orakel_unterscheidet_ueberhaupt():
    """OHNE DIESE HAELFTE waere ein Orakel, das IMMER True sagt, oben gruen — und die zweite
    Zusicherung wertlos. Geprueft wird an KOPIEN im Speicher, der Kandidatenbaum wird NICHT
    angefasst: ein Test, der den Baum mutiert, den er misst, ist der Fehler von heute frueh."""
    import base64
    import json
    sys.path.insert(0, str(REPO / "scripts"))
    from pre_tag_receipt_lib import canonical_bytes, load_trusted_pubkeys, subject_tree_digest
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    p = REPO / "audit_artifacts" / "600" / "pre_tag_receipt_v6.0.0.json"
    if not p.is_file():
        pytest.skip("keine Quittung im Baum — die Unterscheidungsprobe braucht eine echte Vorlage")
    echt = json.loads(p.read_text(encoding="utf-8"))

    def prueft(r: dict) -> bool:
        if r.get("subject_tree_digest") != subject_tree_digest(REPO):
            return False
        pub = r.get("signer_pubkey")
        if pub not in load_trusted_pubkeys(REPO):
            return False
        try:
            Ed25519PublicKey.from_public_bytes(base64.b64decode(pub)).verify(
                base64.b64decode(r["signature"]), canonical_bytes(r))
        except Exception:  # noqa: BLE001
            return False
        return True

    assert prueft(echt), "die echte Quittung wird abgelehnt — dann misst das Orakel nichts"

    # a) ein veraendertes signiertes Feld: die Signatur deckt es nicht mehr
    manipuliert = dict(echt, produced_at="1999-01-01T00:00:00Z")
    assert not prueft(manipuliert), "ein veraendertes signiertes Feld wurde akzeptiert"

    # b) eine Quittung, die einen ANDEREN Baum bindet
    fremder_baum = dict(echt, subject_tree_digest="0" * 64)
    assert not prueft(fremder_baum), "eine Quittung fuer einen fremden Baum wurde akzeptiert"

    # c) ein fremder Signierer, dessen Schluessel nicht im Anker steht
    fremd = dict(echt, signer_pubkey=base64.b64encode(b"\x01" * 32).decode())
    assert not prueft(fremd), "ein nicht verankerter Signierer wurde akzeptiert"


def _fail_zeilen(stdout: str) -> list[str]:
    return [z for z in stdout.splitlines() if z.startswith("  [FAIL ]")]


def test_auf_einem_pull_request_ist_sie_nicht_anwendbar_statt_gebrochen():
    """DIE EIGENSCHAFT IST LOKAL, DER AUSGANGSCODE IST GLOBAL.

    Die erste Fassung pruefte `rc == 0`, um eine Aussage ueber EINE Zeile zu belegen. Im
    hermetischen Cleanroom faellt C12.2 (internal audit pack) aus einem ganz anderen Grund — die
    Registerdatei liegt dort nicht —, der Lauf endet zu Recht mit 1, und der Test meldete einen
    Defekt an einer Stelle, an der keiner ist. Gemessen am 04.09.2026 in der Cleanroom-Bahn von
    PR 181, an keinem anderen Ort reproduzierbar.

    Geprueft wird deshalb, was die Aenderung wirklich behauptet: C12.1 traegt `n.a.` und steht
    NICHT unter den FAIL-Zeilen. Der Ausgangscode wird nur dort geprueft, wo er ueberhaupt etwas
    ueber C12.1 sagt — naemlich wenn keine ANDERE Zeile faellt.
    """
    r = _lauf("pull_request")
    fails = _fail_zeilen(r.stdout)
    # DIESELBE PRAEZISIERUNG WIE OBEN, am 2026-09-06 aus demselben Anlass. Dieser Test nagelte den
    # Uebergangszustand von der ANDEREN Seite fest: er unterstellte, dass auf einem Pull Request
    # KEINE Quittung existiert, und verlangte deshalb unbedingt eine `n.a.`-Zeile. Sobald eine
    # GUELTIGE Quittung im Baum liegt, besteht C12.1 auch auf einem PR — es gibt dann gar kein
    # `n.a.` mehr, und der Test fiel, obwohl die Verengung genau richtig arbeitete.
    #
    # Die Eigenschaft ist in beiden Weltzustaenden dieselbe und wird hier so geschrieben:
    # auf einem Pull Request steht C12.1 NIE unter FAIL. OB sie `n.a.` traegt oder `ok`, entscheidet
    # die Quittung — `n.a.` genau dann, wenn keine gueltige vorliegt.
    assert not [z for z in fails if "C12.1" in z], f"C12.1 steht trotzdem unter FAIL:\n{fails}"
    if _gueltige_quittung_liegt_vor():
        assert not [z for z in r.stdout.splitlines()
                    if z.startswith("  [ n.a.]") and "C12.1" in z], (
            "eine GUELTIGE Quittung liegt vor — dann ist C12.1 anwendbar und BESTEHT; ein `n.a.` "
            "waere die Verengung an der falschen Stelle")
    else:
        assert [z for z in r.stdout.splitlines()
                if z.startswith("  [ n.a.]") and "C12.1" in z], (
            f"KEINE gueltige Quittung auf einem PR — dann MUSS C12.1 `n.a.` tragen statt zu "
            f"fallen, das ist der ganze Zweck der Verengung\n{r.stdout[-600:]}")
        assert "nicht anwendbar vor dem Tag" in r.stdout
    if not fails:
        assert r.returncode == 0, (
            f"keine FAIL-Zeile, trotzdem rc={r.returncode} — dann haelt C12.1 den Lauf an\n"
            + r.stdout[-900:])


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
