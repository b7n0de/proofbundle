#!/usr/bin/env python3
"""Prueft Doku-Eigenschaften AUF DEM ZUSTAND, DER WIRKLICH VORLIEGT — Checkout wie sdist.

WARUM ES DIESE DATEI GIBT (gemessen am 01.09.2026):

`scripts/doc_link_check.py` ist ein guter Waechter, aber sein einziger Aufrufer ist
`tests/test_docs_truth.py`, und dort ueberspringen sich ALLE SIEBEN Pruefungen in der sdist mit
"repo-context test ... N/A outside a git checkout (PKG-2026-0718-01)". Fuer die meisten seiner
Zusicherungen ist das richtig — sie behaupten etwas ueber das Repo-Layout, das ausgeliefert nicht
existiert. Die Folge war trotzdem, dass genau der Zustand ungeprueft blieb, der beim Nutzer
ankommt: `docs/RECEIPT_ENVELOPE_PROFILE.md` verwies auf `NON_CLAIMS.md` und `SCITT_CPB_MAPPING.md`,
die nicht mitgeliefert werden — ausgeliefert also tote Links, ungemessen.

DIE KLASSE ist nicht "zwei kaputte Links", sondern: **ein Waechter, dessen einziger Aufrufer sich
im Auslieferungszustand ueberspringt, laesst genau den ausgelieferten Zustand ungeprueft.**

P1 wird DELEGIERT, nicht nachgebaut: `doc_link_check.check()` kennt bereits die Abgrenzungen
(`docs/archive/` eingefrorene Historie, `docs/upstream/` woertlicher Spiegel einer in-toto-
Einreichung, dessen Links im FREMDEN Baum aufloesen) und leert Code-Bloecke, damit ein Link in
einem Beispiel nicht als lebender Link zaehlt. Eine zweite Liste derselben Regel waere die naechste
Drift. Neu ist hier nur P2.

DREI ZUSTAENDE je Pruefung: `ok` · `verletzt` · `nicht_messbar`. Der dritte ist keine Freigabe.
"""
from __future__ import annotations

import importlib.util
import json
import pathlib


def _waechter(root: pathlib.Path):
    """Laedt den Link-Waechter, der UNTER DIESER WURZEL liegt.

    Bewusst ueber den Pfad statt per Import: `doc_link_check` loest seine Wurzel aus dem eigenen
    Ort auf, also prueft die Kopie in der sdist die sdist und die im Checkout den Checkout."""
    p = root / "scripts" / "doc_link_check.py"
    if not p.is_file():
        return None
    spec = importlib.util.spec_from_file_location("_dlc_unter_wurzel", p)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def tote_lokale_links(root: pathlib.Path) -> dict:
    """P1 — delegiert an den bestehenden Waechter unter derselben Wurzel."""
    mod = _waechter(root)
    if mod is None:
        return {"zustand": "nicht_messbar",
                "grund": "scripts/doc_link_check.py liegt nicht unter dieser Wurzel", "tote": []}
    e = mod.check()
    return {"zustand": "verletzt" if e.get("broken") else "ok",
            "geprueft": e.get("checked"), "tote": e.get("broken") or []}


def nicht_ausgelieferte_spezifikationen(root: pathlib.Path) -> dict:
    """P2 — jedes Dokument, das ein Konformitaetsfall NORMATIV nennt, liegt auch vor.

    `specRefs` ist die normative Nennung: der Fall beruft sich darauf. Ein Korpus, der auf ein
    Dokument verweist, das im selben Paket fehlt, verweist ins Leere — gemessen am 01.09.2026 war
    das fuer `docs/AGENT_REVIEW_PREDICATE.md` in 14 von 14 nennenden Faellen so."""
    wurzel = root / "conformance"
    if not wurzel.is_dir():
        return {"zustand": "nicht_messbar", "grund": "conformance/ fehlt unter dieser Wurzel",
                "fehlend": [], "genannt": 0}
    fehlend, genannt = [], 0
    for case in sorted(wurzel.rglob("case.json")):
        try:
            d = json.loads(case.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        for ref in d.get("specRefs") or []:
            if not isinstance(ref, str) or "://" in ref or not ref.endswith(".md"):
                continue
            genannt += 1
            if not (root / ref).exists():
                fehlend.append({"fall": case.parent.name, "specRef": ref})
    return {"zustand": "verletzt" if fehlend else "ok", "fehlend": fehlend, "genannt": genannt}


def luecke_beurteilen(ist: set, anzahl: int, grundlinie: dict) -> list[str]:
    """Das URTEIL ueber die gemessene Luecke — getrennt von der Messung, damit es pruefbar ist.

    Die Messung haengt an der Umgebung (im Checkout liegt jede Datei vor, in der sdist nicht), das
    Urteil nicht. Getrennt, weil ein Test der im Checkout laeuft sonst nichts sieht: dort ist die
    gemessene Menge leer und jede Behauptung darueber trivial wahr. Diese Funktion nimmt die Menge
    als Eingabe und ist damit ueberall gleich pruefbar.

    Gibt die Verletzungen zurueck, leere Liste heisst eingehalten."""
    erlaubt = set(grundlinie.get("dokumente") or {})
    verletzt: list[str] = []
    neu_dazu = sorted(ist - erlaubt)
    if neu_dazu:
        verletzt.append(f"neue nicht ausgelieferte Spezifikation(en): {neu_dazu}")
    obergrenze = grundlinie.get("anzahl_nennungen_offen")
    if isinstance(obergrenze, int) and anzahl > obergrenze:
        verletzt.append(f"die Luecke ist gewachsen: {anzahl} > {obergrenze}")
    for geschlossen in ("docs/AGENT_REVIEW_PREDICATE.md",):
        if geschlossen in ist:
            verletzt.append(f"{geschlossen} ist wieder aus dem Paket gefallen")
    return verletzt


def pruefe(root) -> dict:
    root = pathlib.Path(root)
    p1 = tote_lokale_links(root)
    p2 = nicht_ausgelieferte_spezifikationen(root)
    if "verletzt" in (p1["zustand"], p2["zustand"]):
        gesamt = "verletzt"
    elif p1["zustand"] == p2["zustand"] == "ok":
        gesamt = "ok"
    else:
        gesamt = "nicht_messbar"
    return {"schema": "proofbundle.shipped_docs_check.v1", "zustand": gesamt,
            "tote_links": p1, "spezifikationen": p2}


def main() -> int:
    e = pruefe(pathlib.Path(__file__).resolve().parents[1])
    p1, p2 = e["tote_links"], e["spezifikationen"]
    print(f"[shipped-docs] {e['zustand']} · Links {p1['zustand']} ({len(p1['tote'])} tot) "
          f"· Spezifikationen {p2['zustand']} ({len(p2['fehlend'])} von {p2.get('genannt', 0)} fehlend)")
    for t in p1["tote"]:
        print(f"  toter Link         {t['file']} -> {t['target']}")
    for f in p2["fehlend"]:
        print(f"  nicht ausgeliefert {f['specRef']}  (Fall {f['fall']})")
    return 1 if e["zustand"] == "verletzt" else 0


if __name__ == "__main__":
    raise SystemExit(main())
