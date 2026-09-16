#!/usr/bin/env python3
"""New source lines are English. The existing tree is not touched.

OWNER DECISION OA-bba542170c, 2026-09-16: "B: only NEW material in English, the existing body
stays -- it costs nothing, and the share falls by itself over time."

AND THE CONDITION THAT CAME WITH IT, in the owner's words: "B without a guard is a statement of
intent." So this is the guard. It is scoped to the DIFF, never to the tree, and that scope is the
whole decision. A tree-wide check would go red on 2687 lines the decision explicitly keeps.

MEASURED 2026-09-16 on fix/anchor-verifier-zweischicht-phase2: 159 of 1577 Python files carry
German comment or docstring lines, 2687 lines in total. Those stay. What this refuses is the
2688th.

WHAT IT READS: added lines of the change range, comments and docstrings only. Code identifiers are
not prose, and a German variable name is a naming question, not a language one. The word list
lives in tests/_deutsche_prosa.py and is shared with the two existing contracts, because two lists
for one question drift and the weaker one decides wherever it stands.

HONEST LIMIT, carried over from that module: a word list catches known violations reliably, not
every unknown German phrase. This reports its reach; it does not claim the absence of German.

Exit: 0 clean, 1 German prose in added lines, 2 the range is not measurable.
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO))
from tests import _deutsche_prosa as DP  # noqa: E402

#: How many list words a line needs before it counts as prose. One word is noise: "die" appears in
#: English text as a verb, "auf" inside a quoted path. Two is the threshold the measurement of the
#: 2687 existing lines used, so the number a future reader compares against means the same thing.
SCHWELLE = 2

#: A comment, or a line inside a docstring. Everything else is code.
_KOMMENTAR = re.compile(r"^\s*#")
_DREIFACH = re.compile(r'"""|\'\'\'')


def _git(*args: str) -> tuple[int, str]:
    r = subprocess.run(["git", "-C", str(REPO), *args], capture_output=True, text=True)
    return r.returncode, r.stdout


def _neue_zeilen(basis: str, arbeitsbaum: bool = False) -> tuple[
        dict[str, list[tuple[int, str]]], str]:
    """Added lines per file. Returns ({} , reason) when the range cannot be read.

    WHICH STATE IS MEASURED IS A REAL QUESTION, and the first version of this tool answered it
    silently. It compared against HEAD, so an uncommitted fix in the working tree changed nothing
    in its verdict: the same lines were reported after they had been rewritten. For CI that is the
    correct state, because HEAD is what a run sees. For somebody fixing the findings it is the
    wrong one, and saying nothing about it turns a stale verdict into a wrong one.
    """
    ziel = "" if arbeitsbaum else "HEAD"
    rc, aus = _git("diff", "--unified=0", basis + ("..." if ziel else ""), *( [ziel] if ziel else [] ), "--", "*.py")
    if rc != 0:
        return {}, f"NOT MEASURABLE: git diff against {basis!r} failed"
    je_datei: dict[str, list[tuple[int, str]]] = {}
    datei, nr = None, 0
    for zeile in aus.splitlines():
        if zeile.startswith("+++ b/"):
            datei = zeile[6:]
            je_datei.setdefault(datei, [])
        elif zeile.startswith("@@"):
            m = re.search(r"\+(\d+)", zeile)
            nr = int(m.group(1)) if m else 0
        elif zeile.startswith("+") and not zeile.startswith("+++") and datei:
            je_datei[datei].append((nr, zeile[1:]))
            nr += 1
    return je_datei, "measured"


def _ist_prosa(datei: str, nr: int, text: str) -> bool:
    """Comment, or inside a docstring. The docstring test reads the FILE, not the diff.

    A diff hunk does not say whether its line sits inside a docstring, and guessing from the
    fragment would call a string literal a comment. The file at HEAD does say.
    """
    if _KOMMENTAR.search(text):
        return True
    p = REPO / datei
    try:
        zeilen = p.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return False
    if not (1 <= nr <= len(zeilen)):
        return False
    offen = False
    for z in zeilen[: nr - 1]:
        offen ^= (len(_DREIFACH.findall(z)) % 2 == 1)
    return offen


def pruefe(basis: str, arbeitsbaum: bool = False) -> dict:
    je_datei, lage = _neue_zeilen(basis, arbeitsbaum)
    if lage != "measured":
        return {"urteil": "NOT MEASURABLE", "grund": lage, "befunde": [], "rc": 2}
    befunde = []
    for datei, zeilen in sorted(je_datei.items()):
        for nr, text in zeilen:
            if not _ist_prosa(datei, nr, text):
                continue
            w = DP.treffer(text)
            if len(w) >= SCHWELLE:
                befunde.append({"datei": datei, "zeile": nr,
                                "woerter": sorted(set(x.lower() for x in w)),
                                "text": text.strip()[:110]})
    return {"urteil": "ROT" if befunde else "gruen", "befunde": befunde,
            "gemessener_stand": "working tree" if arbeitsbaum else "HEAD",
            "geprueft": sum(len(z) for z in je_datei.values()),
            "dateien": len(je_datei), "schwelle": SCHWELLE,
            "reichweite": ("a word list of German function words, at least "
                           f"{SCHWELLE} per line; not a proof that no German remains"),
            "rc": 1 if befunde else 0}


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--base", default="origin/main",
                   help="the base of the change range (default origin/main)")
    p.add_argument("--arbeitsbaum", action="store_true",
                   help="measure the working tree instead of HEAD (local fixing, not CI)")
    p.add_argument("--json", action="store_true")
    a = p.parse_args(argv)
    d = pruefe(a.base, a.arbeitsbaum)
    if a.json:
        import json
        print(json.dumps(d, ensure_ascii=False, indent=2))
    else:
        print(f"new-lines-english: {d['urteil']} · {d.get('geprueft', 0)} added lines in "
              f"{d.get('dateien', 0)} files · measured state: {d.get('gemessener_stand', '?')}")
        for b in d["befunde"][:20]:
            print(f"  {b['datei']}:{b['zeile']}  {b['woerter']}  {b['text']}")
        if len(d["befunde"]) > 20:
            print(f"  ... and {len(d['befunde']) - 20} more, not listed here (--json shows all)")
        if d.get("grund"):
            print(f"  ! {d['grund']}")
    return int(d["rc"])


if __name__ == "__main__":
    raise SystemExit(main())
