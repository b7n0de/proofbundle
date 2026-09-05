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


@pytest.mark.parametrize("event", [None, "", "push", "release", "workflow_dispatch", "schedule",
                                   "Pull_Request", "pull-request", "pull_requestX"])
def test_ausserhalb_eines_pull_request_bleibt_die_zeile_scharf(event):
    """DER MUTANT. Nur die woertliche Zeichenkette schaltet um — eine andere Schreibweise, ein
    leerer Wert, eine fehlende Variable und jedes andere Ereignis lassen die Pruefung scharf.
    Die Richtung ist Absicht: eine unbekannte Umgebung darf ein Release-Tor nicht abschalten."""
    r = _lauf(event)
    assert r.returncode == 1, (
        f"GITHUB_EVENT_NAME={event!r} hat die Pruefung entschaerft (rc={r.returncode})\n"
        + r.stdout[-600:])
    # DIE ZEILE SELBST, nicht irgendeine FAIL-Zeile: in einer Umgebung, in der ohnehin etwas
    # anderes faellt, waere `"[FAIL ]" in stdout` auch dann wahr, wenn C12.1 entschaerft ist.
    assert [z for z in r.stdout.splitlines()
            if z.startswith("  [FAIL ]") and "C12.1" in z], (
        f"C12.1 steht nicht unter FAIL — die Pruefung ist entschaerft\n{r.stdout[-600:]}")


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
    assert "[ n.a.]" in r.stdout, r.stdout[-600:]
    assert "nicht anwendbar vor dem Tag" in r.stdout
    fails = _fail_zeilen(r.stdout)
    assert not [z for z in fails if "C12.1" in z], f"C12.1 steht trotzdem unter FAIL:\n{fails}"
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
