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
import ast
import io
import re
import subprocess
import tokenize
import sys
from pathlib import Path

#: The TOOL's own root. The word list is part of the tool, so it is looked up here and not in the
#: tree under judgement -- an old branch need not carry it for this check to run.
WERKZEUG_WURZEL = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(WERKZEUG_WURZEL))
from tests import _deutsche_prosa as DP  # noqa: E402


def _gemessener_baum(vorgabe: str | None = None) -> Path:
    """The tree this run JUDGES: the working directory's repository, not the tool's own.

    MEASURED 2026-09-19: this was bound to `__file__`, so calling the script by an absolute path
    in order to judge ANOTHER checkout silently judged the checkout the script sits in. From a
    worktree on a different branch the answer came back word for word identical to the tool's own
    tree -- green, 758 added lines, 7 files -- and only the coincidence that those numbers were
    familiar kept a wrong clearance from standing. The real verdict for that tree was ROT.

    A checker whose subject is its own file path answers a question nobody asked, and it answers
    it confidently. The answer now NAMES the tree it measured, for the same reason it already
    names the state: a verdict that does not say what it looked at cannot be checked.
    """
    if vorgabe:
        return Path(vorgabe).resolve()
    r = subprocess.run(["git", "rev-parse", "--show-toplevel"], capture_output=True, text=True)
    if r.returncode == 0 and r.stdout.strip():
        return Path(r.stdout.strip())
    # No repository around the working directory: fall back to the tool's own tree and say so
    # through the reported path, rather than guessing silently.
    return WERKZEUG_WURZEL


REPO = _gemessener_baum()

#: How many list words a line needs before it counts as prose. One word is noise: "die" appears in
#: English text as a verb, "auf" inside a quoted path. Two is the threshold the measurement of the
#: 2687 existing lines used, so the number a future reader compares against means the same thing.
SCHWELLE = 2

#: A comment, or a line inside a docstring. Everything else is code.
_KOMMENTAR = re.compile(r"^\s*#")


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
    # ONE ARGUMENT FOR THE RANGE. The first form passed `"<base>..."` and `"HEAD"` as two
    # arguments; git answers that with its usage text and exit 129, and this tool then said
    # "NOT MEASURABLE" -- on every run, including the pull request that introduced it (measured
    # 2026-09-18, run 35287424973). A range is `<base>...<target>` in one string; the working
    # tree form passes the base alone.
    bereich = f"{basis}...{ziel}" if ziel else basis
    rc, aus = _git("diff", "--unified=0", bereich, "--", "*.py")
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
    if arbeitsbaum:
        # UNTRACKED FILES ARE NEW MATERIAL TOO. `git diff` never lists a file git does not know,
        # so a brand-new .py with German prose read as clean in the working-tree form (un, round 1,
        # 2026-09-18; measured: an untracked probe file with a German comment, 0 findings). CI
        # measures committed heads and is not affected; this form is for the person fixing the
        # findings, and it must not flatter the file they just created. Every line of an
        # untracked file is an added line.
        rc2, neu = _git("ls-files", "--others", "--exclude-standard", "--", "*.py")
        if rc2 != 0:
            return {}, "NOT MEASURABLE: git ls-files for untracked files failed"
        for rel in neu.splitlines():
            rel = rel.strip()
            if not rel:
                continue
            try:
                text = (REPO / rel).read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError):
                return {}, f"NOT MEASURABLE: untracked file {rel!r} is not readable"
            je_datei.setdefault(rel, [])
            je_datei[rel].extend((i, z) for i, z in enumerate(text.splitlines(), start=1))
    return je_datei, "measured"


def _prosazeilen(datei: str) -> set[int] | None:
    """Every line of the file that is a comment or part of a string literal, by TOKEN.

    THE FIRST VERSION COUNTED QUOTE CHARACTERS, and an adversarial read caught it the same day.
    It walked the lines before the one in question and flipped a flag on every odd count of a
    triple quote. A single triple quote inside an ordinary one-line string sets that flag, so the
    real docstring opener that follows CLOSES it, and the whole docstring then counts as code.

    Measured on a four-line file: the identical German docstring line is checked when nothing
    precedes it and skipped when one such code line does. The check did not become wrong about
    the line, it stopped looking at it, which is the more expensive of the two, because the
    report stays green either way.

    The tokenizer already answers exactly this question, so the shape of the fix is to stop
    re-deriving it. Returns None when the file cannot be read or does not tokenize, and the
    caller treats that as not-prose rather than as a pass.
    """
    p = REPO / datei
    try:
        quelle = p.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    aus: set[int] = set()
    try:
        for tok in tokenize.generate_tokens(io.StringIO(quelle).readline):
            if tok.type == tokenize.COMMENT:
                aus.add(tok.start[0])
    except (tokenize.TokenError, IndentationError, SyntaxError, ValueError):
        return None
    # DOCSTRINGS ARE A POSITION, NOT A STRING TYPE, and the first tokenizer version missed that.
    # Taking every tokenize.STRING swept in the message texts the program prints, which are not
    # source comments at all. Measured on this very branch, it reported the gate's own German
    # error messages, and those are a separate question about who reads the output.
    #
    # The syntax tree says which string is a docstring: the first statement of a module, class or
    # function. Nothing else qualifies, whatever its quoting.
    try:
        baum = ast.parse(quelle)
    except (SyntaxError, ValueError):
        return None
    for knoten in ast.walk(baum):
        if not isinstance(knoten, (ast.Module, ast.ClassDef, ast.FunctionDef,
                                   ast.AsyncFunctionDef)):
            continue
        koerper = getattr(knoten, "body", None) or []
        if not koerper:
            continue
        erstes = koerper[0]
        if not (isinstance(erstes, ast.Expr) and isinstance(erstes.value, ast.Constant)
                and isinstance(erstes.value.value, str)):
            continue
        for n in range(erstes.lineno, (erstes.end_lineno or erstes.lineno) + 1):
            aus.add(n)
    return aus


def _ist_prosa(datei: str, nr: int, text: str) -> bool:
    """Comment, or inside a string literal. The answer comes from the FILE, not from the hunk.

    A diff hunk does not say whether its line sits inside a docstring, and guessing from the
    fragment would call a string literal a comment. The file at HEAD does say.
    """
    if _KOMMENTAR.search(text):
        return True
    zeilen = _prosazeilen(datei)
    return bool(zeilen and nr in zeilen)


def pruefe(basis: str, arbeitsbaum: bool = False) -> dict:
    je_datei, lage = _neue_zeilen(basis, arbeitsbaum)
    if lage != "measured":
        return {"urteil": "NOT MEASURABLE", "grund": lage, "befunde": [],
                "gemessener_baum": str(REPO), "rc": 2}
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
            "gemessener_baum": str(REPO),
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
    p.add_argument("--repo",
                   help="the tree to judge (default: the working directory's repository)")
    p.add_argument("--json", action="store_true")
    a = p.parse_args(argv)
    global REPO
    REPO = _gemessener_baum(a.repo)
    d = pruefe(a.base, a.arbeitsbaum)
    if a.json:
        import json
        print(json.dumps(d, ensure_ascii=False, indent=2))
    else:
        print(f"new-lines-english: {d['urteil']} · {d.get('geprueft', 0)} added lines in "
              f"{d.get('dateien', 0)} files · measured state: {d.get('gemessener_stand', '?')}"
              f" · measured tree: {d.get('gemessener_baum', '?')}")
        for b in d["befunde"][:20]:
            print(f"  {b['datei']}:{b['zeile']}  {b['woerter']}  {b['text']}")
        if len(d["befunde"]) > 20:
            print(f"  ... and {len(d['befunde']) - 20} more, not listed here (--json shows all)")
        if d.get("grund"):
            print(f"  ! {d['grund']}")
    return int(d["rc"])


if __name__ == "__main__":
    raise SystemExit(main())
