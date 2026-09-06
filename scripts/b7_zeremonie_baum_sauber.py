#!/usr/bin/env python3
"""Vor JEDER Zeremonie-Messung: der Baum muss sauber sein — auch ungetrackt.

WARUM ES DIESEN RIEGEL GIBT (Owner-Anordnung 2026-09-06, nach drei Instanzen an EINEM Tag):

  1. Ein ungetracktes ``scratchpad/`` lag im Kandidatenbaum, waehrend die Distributionen gebaut
     wurden. Es haette in ein Paket geraten koennen.
  2. Eine ABGEWIESENE ``pre_tag_receipt_v6.0.0.json`` lag ungetrackt im Baum und machte die
     Vollsuite ROT — das Tor liest die Platte, nicht den Index, und eine ABGELEHNTE Datei ist
     nicht ABWESEND. Am Objekt gemessen: mit der Datei 1 failed / 12 passed, ohne sie 13 passed.
  3. Ein ungetracktes Rust-Bauartefakt (``tools/pb_verify_rs/target/release/pb_verify_rs``,
     02:13:47) kippte C8.2 von ``DATA_BLOCKED`` auf ``FAIL``.

Alle drei sind dieselbe Verwechslung: „ungetrackt, also sieht es nicht wie Bestand aus" ist eine
Aussage ueber den INDEX. Jedes Werkzeug, das die Datei oeffnet, sieht die PLATTE.

WAS DIESER RIEGEL FAENGT UND WAS NICHT — gemessen, nicht behauptet:
Er faengt 1 und 2 vollstaendig. Er faengt 3 NICHT, aus zwei unabhaengigen Gruenden:
``git check-ignore -v`` liefert fuer diesen Pfad ``tools/pb_verify_rs/.gitignore:1:/target``, ein
ignorierter Pfad erscheint nicht in ``--porcelain``; und das Artefakt entstand WAEHREND des Laufs,
was eine Pruefung DAVOR strukturell nicht sehen kann. Der Owner-Satz „haette alle drei verhindert"
trifft damit auf zwei von drei zu. Ein blosses Ausweiten auf ``--ignored`` waere der falsche Fix:
dann schlaegt ``dist/``, jedes venv und jeder Cache an, und ein Riegel, der immer anschlaegt, wird
umgangen. Die andere Haelfte der Klasse braucht eine ANDERE Messung und ist als
``BAUMRIEGEL-SIEHT-IGNORIERTE-PFADE-NICHT-DIE-DRITTE-INSTANZ-BLEIBT-01`` fuer 6.1 offen.

Dieser Riegel ist damit die vollstaendige Antwort auf „ich habe etwas liegen lassen" und KEINE
Antwort auf „der Lauf erzeugt sich selbst seine Vorbedingung".

WAS GEPRUEFT WIRD: ``git status --porcelain`` muss LEER sein, ungetrackte Dateien eingeschlossen.
Nicht leer heisst Abbruch MIT NENNUNG DER DATEIEN — eine Meldung ohne Namen zwingt zum Suchen und
wird deshalb umgangen.

WAS AUSDRUECKLICH NICHT AUSGENOMMEN WIRD: nichts. Kein Muster, keine Allowlist, kein „nur
Dokumente". Eine Ausnahme ist genau die Tuer, durch die die naechste Instanz kommt; wer eine
braucht, raeumt stattdessen auf.
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


def unsauberkeiten(repo: Path) -> tuple[list[str] | None, str]:
    """``(zeilen, grund)`` — ``None`` heisst NICHT MESSBAR, nie „sauber"."""
    try:
        r = subprocess.run(["git", "-C", str(repo), "status", "--porcelain"],
                           capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError) as exc:
        return None, f"git ist hier nicht benutzbar ({type(exc).__name__}: {exc})"
    if r.returncode != 0:
        return None, f"git status endete mit rc={r.returncode}: {(r.stderr or '').strip()[:200]}"
    return [z for z in r.stdout.splitlines() if z.strip()], "gemessen"


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--repo", default=".")
    p.add_argument("--zweck", default="Zeremonie-Messung",
                   help="wofuer der Baum sauber sein muss — steht in der Meldung")
    a = p.parse_args()
    repo = Path(a.repo).resolve()

    zeilen, grund = unsauberkeiten(repo)
    if zeilen is None:
        print(f"BAUM NICHT MESSBAR: {grund}")
        print("NICHT MESSBAR ist keine Freigabe — Abbruch.")
        return 2
    if zeilen:
        print(f"BAUM NICHT SAUBER — {a.zweck} abgebrochen. {len(zeilen)} Eintrag/Eintraege:")
        for z in zeilen:
            print(f"    {z}")
        print()
        print("Auch UNGETRACKTES zaehlt: das Tor liest die Platte, nicht den Index.")
        print("Gemessen 06.09.2026: eine ungetrackte Receipt-Datei machte die Vollsuite rot.")
        return 1
    print(f"Baum sauber (git status --porcelain leer, ungetrackt eingeschlossen) — {a.zweck} frei.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
