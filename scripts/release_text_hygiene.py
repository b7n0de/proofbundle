#!/usr/bin/env python3
"""Formpruefer ueber RELEASE-NOTIZ und TAG-TEXT — dieselbe Anspruchshygiene wie fuer die Docs.

WARUM ES DIESES WERKZEUG GIBT. Der Release-Standard 6.0.0 (05.09.2026) nennt in seinem
fail-closed-Satz einen „Formpruefer und Benennungs-Gate ueber Release-Notiz und Tag-Text".
GEMESSEN am 2026-09-07: es gab keinen.

  * `scripts/claims_hygiene_check.py` scannt 49 Dokumente — und laeuft in `ci.yml` genau dort.
  * `.github/workflows/release.yml` erzeugt den Release-Text mit ``generate_release_notes: true``,
    also GitHub aus PR-Titeln und Commit-Betreffs. Dieser Text ist KEINE Datei im Baum und stand in
    keiner Scanmenge.
  * Der Tag-Text ebenso wenig.

Damit ging der eine Text, den ein Fremder als ERSTES liest, ungeprueft nach draussen, waehrend
jede README-Zeile durch 37 verbotene Wendungen (gemessen: len(claims_hygiene_check._FORBIDDEN_RE)) muss. Das ist die Luecke, nicht die Regel.

EINE REGELMENGE, ZWEI EINGAENGE. Dieses Werkzeug bringt KEINE eigenen Muster mit. Es ruft
``claims_hygiene_check.scan_text`` — dieselbe Liste, dieselbe Negationsbehandlung, dieselben
Abschnitts-Ausnahmen. Zwei Listen wuerden auseinanderdriften, und dann verbietet die eine Flaeche,
was die andere schreibt.

DREI EINGAENGE, und der erste ist der genaue:

  --stdin        den EXAKTEN Text pruefen. So kommt man an ihn:
                     gh api -X POST repos/<o>/<r>/releases/generate-notes \\
                       -f tag_name=v6.0.0 -f previous_tag_name=v5.1.0 --jq .body \\
                       | python scripts/release_text_hygiene.py --stdin --label release-notes
  --text-file F  eine Datei, etwa die Tag-Nachricht (`git tag -l --format='%(contents)' v6.0.0`)
  --since-tag T  VORPRUEFUNG auf die EINGABEN: die Commit-Betreffs seit T, aus denen GitHub den
                 Text spaeter komponiert. EHRLICHE GRENZE: GitHub nimmt PR-Titel, nicht
                 Commit-Betreffs. Bei Squash-Merges sind sie gleich, sonst nur nahe daran — diese
                 Form ist eine Frueherkennung, kein Ersatz fuer `--stdin` auf dem echten Text.

Exit 0 sauber, exit 1 bei jeder Verletzung. Read-only.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))

import claims_hygiene_check as chc  # noqa: E402  — nach dem sys.path-Eintrag

SCHEMA = "proofbundle.release_text_hygiene.v1"


def betreffs_seit(tag: str) -> str:
    """Die Commit-Betreffs seit ``tag`` als ein Text. Ein leerer Bereich ist ein FEHLER, keine
    saubere Menge: er hiesse, es gaebe nichts zu veroeffentlichen, und ein Pruefer, der daraus
    „keine Verletzung" macht, bestaende immer."""
    r = subprocess.run(["git", "-C", str(REPO), "log", f"{tag}..HEAD", "--format=%s"],
                       capture_output=True, text=True, timeout=30)
    if r.returncode != 0:
        raise SystemExit(f"release-text-hygiene: `git log {tag}..HEAD` schlug fehl: {r.stderr.strip()}")
    text = r.stdout.strip()
    if not text:
        raise SystemExit(
            f"release-text-hygiene: zwischen {tag} und HEAD liegt kein Commit. Das ist kein "
            f"sauberer Lauf, sondern eine leere Menge — ein Pruefer ueber nichts besteht immer.")
    return text


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    q = p.add_mutually_exclusive_group(required=True)
    q.add_argument("--stdin", action="store_true", help="den exakten Text von stdin lesen")
    q.add_argument("--text-file", type=Path, help="den Text aus einer Datei lesen")
    q.add_argument("--since-tag", help="Vorpruefung: die Commit-Betreffs seit diesem Tag")
    p.add_argument("--label", default=None, help="Name des Textes in der Meldung")
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)

    if args.stdin:
        text, label = sys.stdin.read(), args.label or "<stdin>"
    elif args.text_file:
        text, label = args.text_file.read_text(encoding="utf-8"), args.label or str(args.text_file)
    else:
        text, label = betreffs_seit(args.since_tag), args.label or f"commit-subjects {args.since_tag}..HEAD"

    if not text.strip():
        # LEER IST NICHT SAUBER. Ein Formpruefer, der ueber einen leeren Text „bestanden" meldet,
        # ist genau die leer-wahre Zusicherung, gegen die dieses Repo sonst antritt.
        raise SystemExit(f"release-text-hygiene: der Text {label!r} ist leer — nichts zu pruefen "
                         f"ist kein Bestehen, sondern ein fehlender Eingang.")

    violations = chc.scan_text(text, label)
    out = {"schema": SCHEMA, "verdict": "FAIL" if violations else "PASS",
           "label": label, "chars": len(text), "violations": violations}
    if args.json:
        print(json.dumps(out, indent=2, ensure_ascii=False))
    else:
        print(f"[release-text-hygiene] {out['verdict']} · {label} · {len(text)} Zeichen · "
              f"{len(violations)} Verletzung(en)")
        for v in violations:
            print(f"  Zeile {v['line']}: '{v['match']}' ({v['phrase']})  — {v['sentence']}")
    return 1 if violations else 0


if __name__ == "__main__":
    sys.exit(main())
