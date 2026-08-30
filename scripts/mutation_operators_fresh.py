#!/usr/bin/env python3
"""Stale-Operator-Vorpruefung — die Klasse hinter beiden Luecken vom 30.08.2026.

WARUM ES DAS GIBT. Die Operatoren in ``mutation_check.py`` zitieren Quelltext WOERTLICH. Wird die
zitierte Zeile veraendert — auch voellig zu Recht —, misst der Operator nichts mehr. Beide Luecken
des Laufs vom 30.08. waren genau das, und BEIDE wurden von einem KLASSENFIX ausgeloest:

  #58  38a672a  "mldsa" in (newest.sig_alg or "")  ->  "mldsa" in _sig_label
                (ein nicht-String sig_alg liess den Mitgliedstest mit rohem TypeError abstuerzen)
  #80  fd84e1d  rel0 in _SELF_ASSERTED_RETRACTORS  ->  is_member(rel0, _SELF_ASSERTED_RETRACTORS)
                ("27 Mitgliedstests hashten Angreiferdaten — die Klasse, nicht die 27 Zeilen")

Ein Klassenfix, der N Aufrufstellen verbessert, entwertet still jeden Pruefer, der diese Stellen
woertlich zitiert. Das ist die Klasse, und sie ist teurer als sie aussieht: das Tor bemerkt es erst
nach einem ~3-Stunden-Lauf, weil jeder Operator eine volle Testsuite kostet.

WAS DAS HIER AENDERT. Die Frage "passt jedes Muster noch auf seine Datei" ist REIN STATISCH und in
Sekunden zu beantworten — kein Testlauf noetig. Diese Vorpruefung beantwortet sie, bevor die teure
Arbeit beginnt. Sie ersetzt das Tor NICHT: sie sagt nichts darueber, ob ein Mutant getoetet wird.
Sie sagt nur, ob die Operatoren ueberhaupt noch auf den Code zeigen, den sie zu pruefen behaupten.

ZWEI FRAGEN, nicht eine. Aufgeworfen von der Gegenlesung am 30.08.2026:

  1. Findet jedes Muster seine Datei?            — sonst misst der Operator NICHTS.
  2. Findet es sie GENAU EINMAL?                 — sonst trifft `str.replace(alt, neu, 1)` die
                                                   ERSTE Fundstelle, und die muss nicht die
                                                   gemeinte sein. Der Operator mutiert dann still
                                                   den falschen Ort und misst etwas anderes, als
                                                   seine Bezeichnung sagt.

Die zweite Frage ist genauso statisch wie die erste und war vorher nicht gestellt. Gemessen am
30.08.2026: 0 von 88 Mustern sind mehrdeutig — der Fall tritt heute nicht auf, und genau deshalb
faellt er ohne Pruefung auch nicht auf, wenn er eintritt.

EHRLICHE GRENZE, und sie ist der wichtigste Satz hier. Diese Vorpruefung faengt SYNTAKTISCHE
Veralterung. Sie faengt NICHT den Fall, dass das Muster noch passt, waehrend die Logik DRUMHERUM
sich geaendert hat — etwa eine neue Bedingung neben der zitierten, die die mutierte Wache
kompensiert. Dann meldet sie OK, und der Operator misst trotzdem weniger, als er behauptet. Dagegen
hilft nur der volle Lauf.

  exit 0 = jedes Muster wird genau einmal gefunden
  exit 1 = mindestens eines fehlt oder ist mehrdeutig (mit Datei, Index und Bezeichnung)
"""
from __future__ import annotations

import importlib.util as _iu
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent


def _mutations():
    spec = _iu.spec_from_file_location("mutation_check", ROOT / "scripts" / "mutation_check.py")
    mod = _iu.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod.MUTATIONS


def stale_operators(repo: pathlib.Path | None = None) -> list[dict]:
    """Jeder Operator, dessen Muster fehlt ODER mehrdeutig ist. Leere Liste = alle frisch."""
    repo = repo or ROOT
    out: list[dict] = []
    for idx, (rel, old, _new, label, _expect) in enumerate(_mutations()):
        pfad = repo / rel
        if not pfad.is_file():
            out.append({"index": idx, "label": label, "file": rel, "reason": "Datei fehlt"})
            continue
        src = pfad.read_text(encoding="utf-8")
        pats = list(old) if isinstance(old, tuple) else [old]
        fehlend = [p for p in pats if p not in src]
        if fehlend:
            out.append({"index": idx, "label": label, "file": rel,
                        "reason": f"{len(fehlend)} von {len(pats)} Muster(n) nicht gefunden",
                        "missing": fehlend})
            continue
        # Mehrdeutig ist NICHT dasselbe wie fehlend, und es ist leiser: der Operator laeuft
        # durch, mutiert aber die erste Fundstelle statt der gemeinten.
        viele = [(p, src.count(p)) for p in pats if src.count(p) != 1]
        if viele:
            out.append({"index": idx, "label": label, "file": rel,
                        "reason": "; ".join(f"Muster kommt {n}x vor (erwartet genau 1x)" for _p, n in viele),
                        "missing": [p for p, _n in viele]})
    return out


def main() -> int:
    stale = stale_operators()
    gesamt = len(_mutations())
    if not stale:
        print(f"[mutation-operators-fresh] OK — alle {gesamt} Operatoren finden ihr Muster")
        return 0
    print(f"[mutation-operators-fresh] STALE — {len(stale)} von {gesamt} Operator(en) zeigen ins Leere:")
    for s in stale:
        print(f"  #{s['index']}  {s['label']}")
        print(f"      {s['file']}: {s['reason']}")
        for p in s.get("missing", [])[:2]:
            print(f"      erwartet: {p.strip()[:100]}")
    print("  Ein stale Operator misst NICHTS. Muster auf den heutigen Quelltext ziehen — und dabei")
    print("  den ERSATZ mitziehen, sonst mutiert er nebenbei etwas, das seine Bezeichnung nicht nennt.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
