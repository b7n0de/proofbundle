#!/usr/bin/env python3
"""How many lines of the release scope have landed, counted from the pull-request titles on main.

OWNER GO 2026-09-14 19:2x Berlin, order QITEM-CODEX-RUNDE-EINS-GEHOERT-DEM-ERSTELLER-01 part D:
every pull request carrying a scope line names that line's identifier in its title, and the
landing card of the day counts what landed of the 55 out of the titles on main, naming the number
at the top.

THE COUNTING UNIT IS THE LINE, not the identifier and not the branch. Measured on the 6.1.0 scope
the same day: 55 lines, 52 distinct leading identifiers, 46 branches of their own, 9 riders. Count
by identifier and three lines go missing; count by branch and nine do.

RETROACTIVELY, THE CARD CARRIES THE ASSIGNMENT, NOT THE TITLE. The order is explicit: pull
requests that landed before the rule get their identifier here, never by rewriting a merged title.
A witnessed commit is not rewritten to make a counter look tidy. The assignment file is therefore
an input, and every entry in it names the pull request it speaks for.

WHAT IS NOT COUNTED, said plainly. A rider has no branch of its own, so no pull request can carry
it, so it can never appear in a title. Riders are reported separately and are NOT part of the
landed count; folding them in would make the number rise without anything landing.

Exit: 0 measured, 2 not measurable.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))

#: Retroactive assignments, one entry per pull request that landed before the title rule.
ZUORDNUNG = REPO / "docs" / "release_scope" / "landed_before_the_rule.json"


def _gate():
    import importlib.util
    s = importlib.util.spec_from_file_location(
        "rsg", REPO / "scripts" / "b7_release_scope_title_gate.py")
    m = importlib.util.module_from_spec(s)
    s.loader.exec_module(m)
    return m


def _gelandete_titel(repo_slug: str, version: str) -> tuple[list[dict], str]:
    """Merged pull requests against main, newest first. ({}, reason) when the list is unreadable."""
    r = subprocess.run(
        ["gh", "pr", "list", "--repo", repo_slug, "--state", "merged", "--base", "main",
         "--limit", "300", "--json", "number,title,mergedAt"],
        capture_output=True, text=True, timeout=120)
    if r.returncode != 0:
        return [], f"NOT MEASURABLE: gh pr list failed ({r.stderr.strip()[:120]})"
    try:
        return json.loads(r.stdout), "measured"
    except ValueError as e:
        return [], f"NOT MEASURABLE: {type(e).__name__}: {e}"


def _nachtrag() -> tuple[dict[str, int], str]:
    """Identifier to pull-request number for what landed before the rule."""
    if not ZUORDNUNG.is_file():
        return {}, "not present"
    try:
        d = json.loads(ZUORDNUNG.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        return {}, f"NOT MEASURABLE: {type(e).__name__}: {e}"
    aus = {}
    for e in d.get("zuordnungen") or []:
        k, n = e.get("kennung"), e.get("pr")
        if k and isinstance(n, int):
            aus[k] = n
    return aus, "measured"


def karte(repo_slug: str = "b7n0de/proofbundle", version: str = "6.1.0") -> dict:
    G = _gate()
    pfad = REPO / "docs" / "release_scope" / f"{version}.md"
    zeilen, lage = G.fuehrende_kennungen(pfad)
    if lage != "measured" and not lage.startswith("gemessen"):
        return {"schema": "b7n0de.release_scope_landing_card.v1", "zustand": "NOT MEASURABLE",
                "grund": lage, "rc": 2}
    zu_zweig, mitlaeufer, _ = G.lies_umfang(pfad)
    mit = set(mitlaeufer)
    # A line WITH its own branch is countable, a rider line never.
    ohne_mitlaeufer = [(k, punkt) for k, punkt, zweig in zeilen if k not in mit]

    # AN IDENTIFIER THAT LEADS TWO LINES IS NOT COUNTABLE, and the first version of this file
    # counted it anyway. It collected landed lines in a dictionary keyed by the IDENTIFIER, while
    # the denominator ran over LINES. Measured on the 6.1.0 scope, A1 and A3 each lead two lines,
    # so the numerator could never reach the denominator, and the missing lines would have looked
    # like unfinished work instead of an ambiguous file. Exactly the mistake the gate's own
    # docstring warns against, here in the counter instead of in the gate.
    #
    # They are therefore their OWN set with its own name. A title with such an identifier is not
    # assignable, and that is a finding about the scope file, not about the author.
    von_kennung: dict[str, int] = {}
    for k, _punkt in ohne_mitlaeufer:
        von_kennung[k] = von_kennung.get(k, 0) + 1
    mehrdeutig = sorted(k for k, n in von_kennung.items() if n > 1)
    zaehlbar = [(k, punkt) for k, punkt in ohne_mitlaeufer if von_kennung[k] == 1]

    prs, plage = _gelandete_titel(repo_slug, version)
    if plage != "measured":
        return {"schema": "b7n0de.release_scope_landing_card.v1", "zustand": "NOT MEASURABLE",
                "grund": plage, "rc": 2}

    aus_titeln: dict[str, int] = {}
    for pr in prs:
        for k in G._JEDE_KLAMMER.findall(pr.get("title") or ""):
            kern = k.strip("[]").split()
            if len(kern) == 2 and kern[0] == version:
                aus_titeln.setdefault(kern[1], pr.get("number"))

    nach, nlage = _nachtrag()
    gelandet = {}
    for k, _punkt in zaehlbar:
        if k in aus_titeln:
            gelandet[k] = {"pr": aus_titeln[k], "quelle": "title"}
        elif k in nach:
            gelandet[k] = {"pr": nach[k], "quelle": "assignment"}

    return {
        "schema": "b7n0de.release_scope_landing_card.v1",
        "zustand": "gemessen", "rc": 0,
        "version": version,
        "zeilen_gesamt": len(zeilen),
        "zeilen_zaehlbar": len(zaehlbar),
        # LINES, NOT IDENTIFIERS, and that is the same mistake once more, one level deeper.
        # The first version reported the number of rider IDENTIFIERS, nine, while the denominator
        # counts in rider LINES, ten. A rider identifier leads two lines, so a reader landed on
        # 55 minus 9 minus 4 equals 42 and read 41. A number in your head that cannot be
        # recalculated is not a measurement, but a claim dressed in digits.
        "mitlaeufer_kennungen": sorted(mit),
        "mitlaeufer_zeilen": len(zeilen) - len(ohne_mitlaeufer),
        "kennung_mehrdeutig": mehrdeutig,
        "kennung_mehrdeutig_zeilen": len(ohne_mitlaeufer) - len(zaehlbar),
        "gelandet": len(gelandet),
        "aus_titeln": sum(1 for v in gelandet.values() if v["quelle"] == "title"),
        "aus_zuordnung": sum(1 for v in gelandet.values() if v["quelle"] == "assignment"),
        "zuordnungsdatei": nlage,
        "offen": sorted(k for k, _ in zaehlbar if k not in gelandet),
        "geprueft_wurden": f"{len(prs)} gemergte Pull Requests gegen main",
        "nicht_gezaehlt": ("Mitlaeufer haben keinen eigenen Zweig, koennen also in keinem Titel "
                           "stehen und zaehlen nie mit. Eine Kennung, die mehr als eine Zeile "
                           "anfuehrt, ist ebenfalls nicht zaehlbar: ein Titel mit ihr ist nicht "
                           "zuordenbar, und das gehoert der Umfangsdatei, nicht dem Autor"),
    }


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--repo", default="b7n0de/proofbundle")
    p.add_argument("--version", default="6.1.0")
    p.add_argument("--json", action="store_true")
    a = p.parse_args(argv)
    d = karte(a.repo, a.version)
    if a.json:
        print(json.dumps(d, ensure_ascii=False, indent=2))
    elif d["zustand"] != "gemessen":
        print(f"landing card: {d['zustand']} — {d.get('grund')}")
    else:
        # The header line names the entries so that the sum works out: total minus rider lines
        # minus ambiguous lines leaves the countable ones.
        print(f"landing card {d['version']}: {d['gelandet']} of {d['zeilen_zaehlbar']} countable "
              f"lines landed")
        print(f"  {d['zeilen_gesamt']} lines total, minus {d['mitlaeufer_zeilen']} rider lines "
              f"({len(d['mitlaeufer_kennungen'])} identifiers), minus "
              f"{d['kennung_mehrdeutig_zeilen']} lines under "
              f"{len(d['kennung_mehrdeutig'])} ambiguous identifiers "
              f"{d['kennung_mehrdeutig']}, leaves {d['zeilen_zaehlbar']}")
        print(f"  from titles {d['aus_titeln']} · from the assignment file {d['aus_zuordnung']} "
              f"({d['zuordnungsdatei']})")
        if d["offen"]:
            print(f"  open: {', '.join(d['offen'][:24])}"
                  + (f" ... and {len(d['offen']) - 24} more" if len(d["offen"]) > 24 else ""))
    return int(d["rc"])


if __name__ == "__main__":
    raise SystemExit(main())
