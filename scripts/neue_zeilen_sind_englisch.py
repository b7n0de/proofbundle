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

WHAT IT READS: added lines of the change range. In `.py` that is comments and docstrings only,
because code identifiers are not prose and a German variable name is a naming question rather than a
language one. In `.md` it is every line outside a fenced code block, because a Markdown file is
prose and the fence is where its commands and identifiers live.

`.md` JOINED ON 2026-09-19, by owner decision, as the fourth item of the 6.1.0 release step. Until
then the tool read `*.py` alone and said so nowhere: a cut that rewrote two `.md` scope files got
"0 added lines in 0 files", in green, over 106 lines it had never opened.

A VERBATIM QUOTATION can be marked and is then not judged, because quoted material keeps the wording
it is quoted from. The marker is narrow, visible in the diff, and an unbalanced pair makes the file
NOT MEASURABLE rather than clean. The word list
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
import os
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


def _diff_grammatik():
    """The decoder for a path in a diff header and the fixed form of the diff, taken from
    `scripts/mutant_signature_guard.py` in the tool's own tree and loaded by path, like the word list:
    one decoder and one form for one grammar, not a copy.

    THE FORM (counter-reading of pull request 415, F1 and F2, P2): with `diff.interHunkContext` and
    `diff.suppressBlankEmpty` set together, a German line after a joined hunk went to the file before
    it or nowhere, and the verdict was green; an external diff program, a text conversion or a `-diff`
    attribute gave "0 added lines in 0 files", green, and so did `color.ui=always`, because this gate
    asked without `--no-color`. The guard names the settings and switches that fix the form, and
    this gate asks git with the same ones.

    git quotes a path that holds a byte outside ASCII, a double quote, a backslash or a control
    character (`+++ "b/docs/pr\\303\\274fung.md"`). This parser knew only `+++ b/`, so the added lines
    of such a file went to the file before it in the diff, or nowhere when it came first. Measured
    2026-09-26 in throwaway repositories with one German line in `docs/prüfung.md`: after
    `docs/a.md` it was reported as `docs/a.md:1`; before `docs/z.md` the verdict was green over one
    added line."""
    import importlib.util as ilu  # noqa: PLC0415
    pfad = WERKZEUG_WURZEL / "scripts" / "mutant_signature_guard.py"
    spec = ilu.spec_from_file_location("_neue_zeilen_git_path", pfad)
    if spec is None or spec.loader is None:
        raise ImportError(f"no loader for {pfad}")
    modul = ilu.module_from_spec(spec)
    spec.loader.exec_module(modul)
    return modul


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
        return Path(vorgabe).resolve(), "vorgabe"
    # THE CALL ITSELF CAN FAIL, not only the command. An adversarial reading ran this with `git`
    # unresolvable and got a bare FileNotFoundError out of a module-level statement: traceback, no
    # answer, and exit 1 -- the SAME exit code this tool uses for a genuine ROT verdict. A caller
    # that only reads the exit code cannot tell a crash from a finding. So the exception is caught
    # and becomes the same typed refusal as a non-zero return.
    # THIS CALL RUNS IN THE GUARD'S BUILT ENVIRONMENT TOO (counter-reading of d017cd6b, H10): it was the one git call
    # of the gate that inherited the session's, and `GIT_TRACE=/dev/stdout` wrote into the path it answers. A grammar
    # that does not load leaves the inherited environment here; the diff below then says NOT MEASURABLE.
    try:
        umgebung = _diff_grammatik()._git_environment()
    except (OSError, ImportError, AttributeError, SyntaxError):
        umgebung = None
    try:
        r = subprocess.run(["git", "rev-parse", "--show-toplevel"],
                           capture_output=True, text=True, env=umgebung)
    except OSError as fehler:
        return WERKZEUG_WURZEL, f"rueckfall: git is not runnable here ({fehler.strerror})"
    if r.returncode == 0 and r.stdout.strip():
        return Path(r.stdout.strip()), "arbeitsverzeichnis"
    # NO REPOSITORY AROUND THE WORKING DIRECTORY, and this returns a NAMED fallback rather than a
    # usable answer. An earlier version fell back to the tool's own tree and reported a verdict:
    # called from a directory that is not a repository it printed `gruen`, 163 added lines, exit 0,
    # over the TOOL's tree. The tree was named in the output, so it was not silent -- but a caller
    # who asked whether THEIR tree is clean got a green verdict with exit 0, and only a careful
    # reader notices the name. That is the very shape this function was rewritten to remove: a
    # checker that answers a question nobody asked, confidently.
    #
    # A counter-reading from a different model family put it plainly: the caller cannot tell a
    # valid measurement from a fallback, so the fallback has to refuse rather than answer. The
    # tree still comes back, because the answer has to say WHICH tree it would have judged.
    #
    # WHY git's OWN WORDS travel with it. `rev-parse` returns non-zero for more than one reason,
    # and "there is no repository here" is only the most common of them: a bare repository has no
    # working tree to name, and a checkout whose ownership git distrusts refuses while a perfectly
    # real repository sits right there. The earlier version captured stderr and never read it, so
    # every cause collapsed into one sentence that asserted the most common one. The cause is now
    # carried rather than guessed.
    grund = (r.stderr or "").strip().splitlines()
    return WERKZEUG_WURZEL, ("rueckfall: " + grund[0]) if grund else "rueckfall"


REPO, REPO_HERKUNFT = _gemessener_baum()

#: How many list words a line needs before it counts as prose. One word is noise: "die" appears in
#: English text as a verb, "auf" inside a quoted path. Two is the threshold the measurement of the
#: 2687 existing lines used, so the number a future reader compares against means the same thing.
SCHWELLE = 2

#: A comment, or a line inside a docstring. Everything else is code.
_KOMMENTAR = re.compile(r"^\s*#")

#: WHICH FILES THIS READS, in ONE place. It was `*.py` written twice, in the diff call and in the
#: untracked-file call, and a third surface then went unmeasured in silence: a release cut on
#: 2026-09-19 rewrote two `.md` scope files and this tool reported "0 added lines in 0 files", in
#: green, over 106 added lines it never looked at. A gate that answers green about a surface it
#: does not read is worse than one that says it cannot measure.
#:
#: Owner decision 2026-09-19: new and re-cast files are English, and `.md` becomes the fourth item
#: of that release step. Two spellings of one list is how the first surface was forgotten, so the
#: list is a constant and both call sites take it from here.
_ENDUNGEN = ("*.py", "*.md")

#: A fenced code block in Markdown. CommonMark: the opener is three or more backticks or tildes,
#: the closer is at least as long and uses the SAME character.
_ZAUN = re.compile(r"^\s{0,3}(`{3,}|~{3,})")

#: A VERBATIM QUOTATION of existing material, which keeps the wording it is quoted from.
#:
#: It exists because two owner instructions met on 2026-09-19 and both are right. New and re-cast
#: files are English; and the 54 scope lines moving from 6.1.0 to 6.2.0 move UNCHANGED, with byte
#: equality checked rather than claimed. Rewriting a quotation would make that check meaningless,
#: and leaving it unmarked would make this gate red on material it is not meant to judge.
#:
#: NARROW ON PURPOSE. It skips only what stands between the two markers, never a file, never a
#: directory, never a suffix. A marker is one visible line that a reader sees in the diff, so
#: claiming an exemption costs more than fixing the language, which is the right way round.
#:
#: AND FAIL-CLOSED. An opener without a closer does not swallow the rest of the file in silence;
#: that is exactly the shape this module already paid for once. An unbalanced pair makes the file
#: NOT MEASURABLE, and not-measurable is a question rather than a pass.
_ZITAT_AUF = "<!-- proofbundle:verbatim-quote:begin -->"
_ZITAT_ZU = "<!-- proofbundle:verbatim-quote:end -->"


def _git(*args: str, env: dict | None = None) -> tuple[int, str]:
    """git's answer as bytes, decoded with surrogateescape, as in the mutant guard (second counter-reading of the fixed
    form, F1 and F3): under `--text` a binary file that is not UTF-8 ended the gate with a traceback and exit 1, the
    code of ROT, and `text=True` turned a lone CR into a line feed. `env` is the guard's built environment."""
    r = subprocess.run(["git", "-C", str(REPO), *args], capture_output=True, env=env)
    return r.returncode, r.stdout.decode("utf-8", "surrogateescape")


def _git_namen(*args: str, env: dict | None = None) -> tuple[int, list[str]]:
    """The paths a git command lists with -z, each as git names it: bytes split on NUL and decoded
    the way Python decodes a file name, so a name that is not UTF-8 is a name and not a crash."""
    r = subprocess.run(["git", "-C", str(REPO), *args], capture_output=True, env=env)
    return r.returncode, [os.fsdecode(n) for n in r.stdout.split(b"\0") if n]


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
    # THE HEADER PREFIXES ARE NAMED (counter-reading of pull request 375, the neighbour of F10a): with
    # `diff.mnemonicPrefix` set, the working-tree form gets `+++ w/...`, which the parser below does
    # not read, and every added line was dropped while the verdict stayed green.
    # AND THE ENVIRONMENT IS THE GUARD'S BUILT ONE (second counter-reading of the fixed form, F2): with
    # `GIT_LITERAL_PATHSPECS`, `GIT_GLOB_PATHSPECS` or `GIT_NOGLOB_PATHSPECS` set, the `*.md` pathspec matched
    # nothing, and the verdict was green over a German line.
    try:
        grammatik = _diff_grammatik()
        _git_path, form, schalter = grammatik._git_path, grammatik._DIFF_FORM, grammatik._DIFF_SWITCHES
        umgebung = grammatik._git_environment()
    except (OSError, ImportError, AttributeError, SyntaxError) as fehler:
        return {}, f"NOT MEASURABLE: the diff grammar is not loadable ({type(fehler).__name__})"
    rc, aus = _git(*form, "diff", "--unified=0", *schalter, "--src-prefix=a/", "--dst-prefix=b/",
                   bereich, "--", *_ENDUNGEN, env=umgebung)
    if rc != 0:
        return {}, f"NOT MEASURABLE: git diff against {basis!r} failed"
    je_datei: dict[str, list[tuple[int, str]]] = {}
    datei, nr = None, 0
    # A HEADER STANDS OUTSIDE A HUNK, AND THE DIFF IS SPLIT AT ITS LINE FEEDS ONLY, as in the mutant
    # guard (counter-reading of pull request 375, the neighbour of F10b and F10c in this parser). An
    # added line `++ b/x` stood in the diff as `+++ b/x` and moved every line after it to a file `x`,
    # and a form feed cut an added line off its `+`; in both a German line was dropped and the verdict
    # was green. The hunk header counts the lines of its hunk, and a line the open hunk cannot hold,
    # or a diff that ends inside a hunk, makes the range NOT MEASURABLE (415, F1): passed over, it
    # was the empty context line of `diff.suppressBlankEmpty`, and the count never closed again.
    alt = neu = 0
    for zeile in aus.split("\n"):
        if alt > 0 or neu > 0:
            if zeile.startswith("+"):
                if datei:
                    je_datei[datei].append((nr, zeile[1:]))
                nr += 1
                neu -= 1
            elif zeile.startswith("-"):
                alt -= 1
            elif zeile.startswith(" "):
                nr += 1
                alt -= 1
                neu -= 1
            elif not zeile.startswith("\\"):
                return {}, ("NOT MEASURABLE: the diff lost the count of a hunk, a line in an open "
                            "hunk is no line of it")
            continue
        if zeile.startswith(("+++ b/", '+++ "b/')):
            datei = _git_path(zeile[4:])[2:]
            je_datei.setdefault(datei, [])
        elif zeile.startswith("@@"):
            m = re.search(r"\+(\d+)", zeile)
            nr = int(m.group(1)) if m else 0
            k = re.match(r"@@ -\d+(?:,(\d+))? \+\d+(?:,(\d+))? @@", zeile)
            if k:
                alt, neu = (int(g) if g is not None else 1 for g in k.groups())
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
        # With -z: a quoted name opens no file, and the run said NOT MEASURABLE about a file it
        # could have read (2026-09-26, measured).
        rc2, neu = _git_namen("ls-files", "--others", "--exclude-standard", "-z", "--", *_ENDUNGEN,
                              env=umgebung)
        if rc2 != 0:
            return {}, "NOT MEASURABLE: git ls-files for untracked files failed"
        for rel in neu:
            try:
                text = (REPO / rel).read_bytes().decode("utf-8")
            except (OSError, UnicodeDecodeError):
                return {}, f"NOT MEASURABLE: untracked file {rel!r} is not readable"
            # In git's line space, as the file readers below count (counter-reading of d017cd6b, H2): lines end
            # at LF only; `read_text` turned a CR into one and `splitlines()` split at a form feed, U+2028 and more.
            zeilen = text.split("\n")
            if zeilen and zeilen[-1] == "":
                zeilen.pop()
            je_datei.setdefault(rel, [])
            je_datei[rel].extend((i, z) for i, z in enumerate(zeilen, start=1))
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

    THE LINES ARE GIT'S (counter-reading of d017cd6b, H2, P2). The number to compare comes from the
    diff, which counts LF only; `read_text` turned a lone CR into a line feed, so a German docstring
    after `a = 1<CR>b = 2` was checked as the line two below it, and a comment after a CR in the
    same git line was never seen. The file is read as bytes, and every line Python reports goes
    through the guard's table into git's line space.
    """
    p = REPO / datei
    try:
        roh = p.read_bytes().decode("utf-8", "replace")
        git_zeile = _diff_grammatik()._py2git(roh)
    except (OSError, ImportError, AttributeError, SyntaxError):
        return None
    quelle = roh.replace("\r\n", "\n").replace("\r", "\n")
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
    return {git_zeile[n] for n in aus if n < len(git_zeile)}


def _md_prosazeilen(datei: str) -> set[int] | None:
    """Every line of a Markdown file that is NOT inside a fenced code block.

    In Markdown there is no comment/code split to make: the file IS prose, and the exception is the
    fenced block, which carries commands, output and identifiers. That mirrors the rule one level
    up, where code identifiers are a naming question rather than a language one.

    THE FENCE IS DERIVED, NOT TOGGLED. A flag flipped on every fence line is the same defect this
    module already fixed once for docstrings: a stray marker then inverts the rest of the file, and
    the report stays green because the tool stopped looking rather than started being wrong. So the
    opener's character and length are remembered, and only a closer of at least that length in the
    SAME character ends the block, which is what CommonMark says.

    Returns None when the file cannot be read, and the caller treats that as not-prose rather than
    as a pass.

    SPLIT AT LF, LIKE GIT (counter-reading of d017cd6b, H2, P2): `splitlines()` also ends a line at
    CR, FF, VT, FS, GS, RS, NEL, U+2028 and U+2029. One such character before a fence moved every
    later line by one, and a German line after the closing fence was checked as the fence itself.
    """
    p = REPO / datei
    try:
        zeilen = p.read_bytes().decode("utf-8", "replace").split("\n")
    except OSError:
        return None
    # The quotation brackets first, because an unbalanced pair is a measurement failure and must
    # not be reported as a clean file.
    auf = [i for i, z in enumerate(zeilen, start=1) if z.strip() == _ZITAT_AUF]
    zu = [i for i, z in enumerate(zeilen, start=1) if z.strip() == _ZITAT_ZU]
    if len(auf) != len(zu) or any(a >= b for a, b in zip(auf, zu)):
        return None
    zitat: set[int] = set()
    for a, b in zip(auf, zu):
        zitat.update(range(a, b + 1))

    aus: set[int] = set()
    offen: str | None = None
    for i, z in enumerate(zeilen, start=1):
        if i in zitat:
            continue
        m = _ZAUN.match(z)
        if offen is None:
            if m:
                offen = m.group(1)
                continue          # the fence line itself is not prose
            aus.add(i)
        else:
            if m and m.group(1)[0] == offen[0] and len(m.group(1)) >= len(offen):
                offen = None
            # inside the block, and the closing line too, stay out
    return aus


def _ist_prosa(datei: str, nr: int, text: str, cache: dict | None = None) -> bool:
    """Comment, or inside a string literal. The answer comes from the FILE, not from the hunk.

    A diff hunk does not say whether its line sits inside a docstring, and guessing from the
    fragment would call a string literal a comment. The file at HEAD does say.
    """
    if datei.endswith(".md"):
        zeilen = _gelesen(_md_prosazeilen, datei, cache)
        return bool(zeilen and nr in zeilen)
    if _KOMMENTAR.search(text):
        return True
    zeilen = _gelesen(_prosazeilen, datei, cache)
    return bool(zeilen and nr in zeilen)


def _gelesen(fn, datei: str, cache: dict | None):
    if cache is None:
        return fn(datei)
    if (fn, datei) not in cache:
        cache[(fn, datei)] = fn(datei)
    return cache[(fn, datei)]


def pruefe(basis: str, arbeitsbaum: bool = False) -> dict:
    if REPO_HERKUNFT.startswith("rueckfall"):
        return {"urteil": "NOT MEASURABLE", "rc": 2, "befunde": [],
                "gemessener_baum": str(REPO), "baum_herkunft": REPO_HERKUNFT,
                "wortlisten_baum": str(WERKZEUG_WURZEL),
                "grund": ("no tree to judge here, and git's own reason is carried in "
                          f"baum_herkunft; name one with --repo instead of taking this tool's own "
                          f"({REPO_HERKUNFT})")}
    je_datei, lage = _neue_zeilen(basis, arbeitsbaum)
    if lage != "measured":
        return {"urteil": "NOT MEASURABLE", "grund": lage, "befunde": [],
                "gemessener_baum": str(REPO), "baum_herkunft": REPO_HERKUNFT,
                "wortlisten_baum": str(WERKZEUG_WURZEL), "rc": 2}
    befunde = []
    gelesen: dict = {}
    for datei, zeilen in sorted(je_datei.items()):
        for nr, text in zeilen:
            if not _ist_prosa(datei, nr, text, gelesen):
                continue
            w = DP.treffer(text)
            if len(w) >= SCHWELLE:
                befunde.append({"datei": datei, "zeile": nr,
                                "woerter": sorted(set(x.lower() for x in w)),
                                "text": text.strip()[:110]})
    return {"urteil": "ROT" if befunde else "gruen", "befunde": befunde,
            "gemessener_stand": "working tree" if arbeitsbaum else "HEAD",
            "gemessener_baum": str(REPO),
            "baum_herkunft": REPO_HERKUNFT,
            # WHOSE WORD LIST JUDGED THIS TREE. The list is imported from the TOOL's tree, while
            # the tree under judgement can be another one. If the judged tree carries its own list,
            # this run did not use it, and a term that is ordinary there can be flagged here. The
            # asymmetry is named rather than removed: importing a list out of the judged tree would
            # mean executing its code to check its prose.
            "wortlisten_baum": str(WERKZEUG_WURZEL),
            "geprueft": sum(len(z) for z in je_datei.values()),
            "dateien": len(je_datei), "schwelle": SCHWELLE,
            "reichweite": ("a word list of German function words, at least "
                           f"{SCHWELLE} per line; not a proof that no German remains"),
            "rc": 1 if befunde else 0}


def _gezeigt(text: str) -> str:
    """A name or a line as the text report shows it: backslash, CR and LF escaped, so neither begins a line."""
    return text.replace("\\", "\\\\").replace("\r", "\\r").replace("\n", "\\n")


def main(argv=None) -> int:
    # A path is read as git names it (-z, os.fsdecode), so a name that is not UTF-8 carries
    # surrogates, and a strict stdout raised on one with exit 1, the exit code of a finding
    # (measured 2026-09-26 on all four path readers). Backslash escapes instead. The JSON form writes
    # every character outside ASCII as its JSON escape (`ensure_ascii`), because a backslash escape of
    # `ü` or of an emoji is no JSON escape, and under an output encoding that is not UTF-8 the output
    # was no JSON, with exit 0 (counter-reading of pull request 375, F5).
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="backslashreplace")
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--base", default="origin/main",
                   help="the base of the change range (default origin/main)")
    p.add_argument("--arbeitsbaum", action="store_true",
                   help="measure the working tree instead of HEAD (local fixing, not CI)")
    p.add_argument("--repo",
                   help="the tree to judge (default: the working directory's repository)")
    p.add_argument("--json", action="store_true")
    a = p.parse_args(argv)
    global REPO, REPO_HERKUNFT
    REPO, REPO_HERKUNFT = _gemessener_baum(a.repo)
    d = pruefe(a.base, a.arbeitsbaum)
    if a.json:
        import json
        print(json.dumps(d, ensure_ascii=True, indent=2))
    else:
        print(f"new-lines-english: {d['urteil']} · {d.get('geprueft', 0)} added lines in "
              f"{d.get('dateien', 0)} files · measured state: {d.get('gemessener_stand', '?')}"
              f" · measured tree: {d.get('gemessener_baum', '?')}"
              f" ({d.get('baum_herkunft', '?')})"
              f" · word list from: {d.get('wortlisten_baum', '?')}")
        # A CR or LF in a name or a line would begin a line of the report, and `::error::` at the start of one is a
        # workflow command in a GitHub Actions log; the guard masks them, and so does this (counter-reading of
        # d017cd6b, H3).
        for b in d["befunde"][:20]:
            print(f"  {_gezeigt(b['datei'])}:{b['zeile']}  {b['woerter']}  {_gezeigt(b['text'])}")
        if len(d["befunde"]) > 20:
            print(f"  ... and {len(d['befunde']) - 20} more, not listed here (--json shows all)")
        if d.get("grund"):
            print(f"  ! {d['grund']}")
    return int(d["rc"])


if __name__ == "__main__":
    raise SystemExit(main())
