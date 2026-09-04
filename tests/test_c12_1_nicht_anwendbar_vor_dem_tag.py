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
    assert "[FAIL ]" in r.stdout and "C12.1" in r.stdout


def test_auf_einem_pull_request_ist_sie_nicht_anwendbar_statt_gebrochen():
    r = _lauf("pull_request")
    assert r.returncode == 0, f"rc={r.returncode}\n{r.stdout[-900:]}"
    assert "[ n.a.]" in r.stdout, r.stdout[-600:]
    assert "nicht anwendbar vor dem Tag" in r.stdout


def test_die_wahrheit_im_bericht_bleibt_unveraendert():
    """Der Ausgangscode sagt „blockiert diese Pruefung dieses Objekt", nicht „ist es fertig".
    Ein Arbeitszweig ist NICHT release-bereit, und das muss weiterhin dastehen — sonst haette
    die Aenderung eine Unwahrheit erzeugt statt eine Fehlbeschuldigung zu beenden."""
    r = _lauf("pull_request")
    assert "audit_candidate_ready=False" in r.stdout, r.stdout[-600:]


def test_nur_dieser_eine_fehlschlag_wird_umgedeutet():
    """ENGE. Ein kaputtes oder nicht vertrauenswuerdiges Receipt bleibt FAIL, auch auf einem PR —
    sonst waere aus einer Praezisierung eine Abschaltung geworden. Gepruefte Eigenschaft: die
    Umdeutung haengt am Wortlaut des Tor-Grundes, nicht am Ereignis allein."""
    quelle = SKRIPT.read_text(encoding="utf-8")
    assert '_laeuft_auf_pull_request() and "no valid pre-tag audit RECEIPT" in' in quelle, (
        "die Umdeutung ist nicht mehr an den konkreten Grund gebunden")


def test_jede_zeile_traegt_einen_namen_vor_ihrem_kuerzel():
    """Owner 04.09.2026: „was ist c12.1? das muessen wir umbenennen wenn das oefter kommt in
    menschenlesbar". MUTANT: eine Zeile ohne Namen macht diesen Test rot."""
    r = _lauf("pull_request")
    zeilen = [z for z in r.stdout.splitlines()
              if z.startswith("  [") and "] " in z and "(§" in z]
    assert zeilen, r.stdout[-600:]
    ohne = [z for z in zeilen if not __import__("re").search(r"\]\s+\S.*\((C\d+\.\d+|EXT\.\d+)\)\s+\(§", z)]
    assert not ohne, "Zeile(n) ohne Name vor dem Kuerzel:\n" + "\n".join(ohne[:5])
