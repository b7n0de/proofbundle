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

WHAT IT READS: added lines of the change range. In `.py` that is comments, and strings that stand
alone as a statement (a docstring is one), because code identifiers are not prose and a German
variable name is a naming question rather than a language one; a string handed to a call or a name
is output or data, a separate question. In `.md` it is every line outside a fenced code block, because a Markdown file is
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
import functools
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
    try:
        r = subprocess.run(["git", "rev-parse", "--show-toplevel"],
                           capture_output=True, text=True)
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

#: A comment line. Strings that stand alone as statements come from the syntax tree.
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


def _git(*args: str) -> tuple[int, str]:
    """git's output as it wrote it: bytes decoded, with no newline translation. Text mode turned a
    lone CR into a line end, and the rest of that git line lost its `+` and was never read."""
    r = subprocess.run(["git", "-C", str(REPO), *args], capture_output=True)
    return r.returncode, r.stdout.decode("utf-8", "surrogateescape")


def _git_namen(*args: str) -> tuple[int, list[str]]:
    """The paths a git command lists with -z, each as git names it: bytes split on NUL and decoded
    the way Python decodes a file name, so a name that is not UTF-8 is a name and not a crash."""
    r = subprocess.run(["git", "-C", str(REPO), *args], capture_output=True)
    return r.returncode, [os.fsdecode(n) for n in r.stdout.split(b"\0") if n]


@functools.lru_cache(maxsize=1)
def _diff_leser():
    """The mutant guard's diff reader, loaded by path from the tool's own tree like the word list:
    its pinned diff grammar, its parser and its line numbering. One reader for one grammar, not a
    copy of it here.

    WHY THIS TOOL TAKES IT (measured 2026-09-26 in throwaway repositories, one German line each, a
    control with the same line in ROT). Its own parser read the diff by the shape of a line, in text
    mode and under the caller's configuration, and each of these judged the change green:
    - a quoted header (`+++ "b/docs/pr\\303\\274fung.md"`): the lines went to the file before it, or
      nowhere when it came first;
    - an added line `++ b/z.py`, valid Python, read as a header: the German docstring after it was
      judged against a file that does not exist;
    - a lone CR before a German comment: text mode split the git line and dropped the rest;
    - `diff.mnemonicPrefix` in the working-tree form, and `diff.external`: no header matched `b/`,
      or another program wrote the diff, and zero lines were read.
    """
    import importlib.util as ilu  # noqa: PLC0415
    pfad = WERKZEUG_WURZEL / "scripts" / "mutant_signature_guard.py"
    spec = ilu.spec_from_file_location("_neue_zeilen_diff_leser", pfad)
    if spec is None or spec.loader is None:
        raise ImportError(f"no loader for {pfad}")
    modul = ilu.module_from_spec(spec)
    spec.loader.exec_module(modul)
    return modul


def _python_zeilen(leser, text: str) -> list[str]:
    """A file's lines as Python and CommonMark end them (CRLF, CR, LF), without a last empty one."""
    zeilen, _ = leser._python_lines_of(text)
    return zeilen[:-1] if zeilen and zeilen[-1] == "" else zeilen


def _stand_leser(aus_head: bool):
    """The judged state's files, each read once per run: the blob at HEAD, or the file on disk.

    THE HEAD FORM READ THE DISK (a review lens on this change, measured 2026-09-26). The added lines
    came from `<base>...HEAD`, but the prose maps that say which of them are comments or docstrings,
    and the numbering that takes git's lines to Python's, were read from the working tree. A run
    over a tree that differs from HEAD judged HEAD's lines against another file. CI checks out HEAD,
    so there the two agree; the form is named HEAD, and it now reads HEAD. A blob is read once per
    file, not once per added line.
    """
    gelesen: dict[str, bytes | None] = {}

    def lies(datei: str) -> bytes | None:
        if datei not in gelesen:
            if aus_head:
                r = subprocess.run(["git", "-C", str(REPO), "cat-file", "blob", f"HEAD:{datei}"],
                                   capture_output=True)
                gelesen[datei] = r.stdout if r.returncode == 0 else None
            else:
                try:
                    gelesen[datei] = (REPO / datei).read_bytes()
                except OSError:
                    gelesen[datei] = None
        return gelesen[datei]
    return lies


def _neue_zeilen(basis: str, arbeitsbaum: bool = False, lies=None) -> tuple[
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
    try:
        leser = _diff_leser()
    except (OSError, ImportError, AttributeError, SyntaxError) as fehler:
        return {}, f"NOT MEASURABLE: the diff reader is not loadable ({type(fehler).__name__})"
    rc, aus = _git("diff", "--unified=0", *leser.DIFF_GRAMMAR, bereich, "--", *_ENDUNGEN)
    if rc != 0:
        return {}, f"NOT MEASURABLE: git diff against {basis!r} failed"
    try:
        je_git = leser._added_lines_by_file(aus)
    except ValueError as fehler:
        return {}, f"NOT MEASURABLE: the diff does not parse as git writes it ({fehler})"
    # FROM GIT'S NUMBERING TO PYTHON'S. git numbers lines at LF; the prose maps below number them
    # as Python and CommonMark do, where a lone CR ends a line too. Each added git line is cut at
    # its inner CRs, and the pieces take their numbers from the same file the prose maps read.
    lies = lies or _stand_leser(aus_head=not arbeitsbaum)
    je_datei: dict[str, list[tuple[int, str]]] = {}
    for datei, zeilen in je_git.items():
        inhalt = lies(datei)
        spannen = ([] if inhalt is None
                   else leser._python_lines_of(inhalt.decode("utf-8", "surrogateescape"))[1])
        for nr, text in zeilen:
            erste = spannen[nr - 1].start if nr <= len(spannen) else nr
            je_datei.setdefault(datei, []).extend(
                (erste + i, stueck) for i, stueck in enumerate(leser._python_lines_of(text)[0]))
    if arbeitsbaum:
        # UNTRACKED FILES ARE NEW MATERIAL TOO. `git diff` never lists a file git does not know,
        # so a brand-new .py with German prose read as clean in the working-tree form (un, round 1,
        # 2026-09-18; measured: an untracked probe file with a German comment, 0 findings). CI
        # measures committed heads and is not affected; this form is for the person fixing the
        # findings, and it must not flatter the file they just created. Every line of an
        # untracked file is an added line.
        # With -z: a quoted name opens no file, and the run said NOT MEASURABLE about a file it
        # could have read (2026-09-26, measured).
        rc2, neu = _git_namen("ls-files", "--others", "--exclude-standard", "-z", "--", *_ENDUNGEN)
        if rc2 != 0:
            return {}, "NOT MEASURABLE: git ls-files for untracked files failed"
        for rel in neu:
            try:
                text = (REPO / rel).read_bytes().decode("utf-8")
            except (OSError, UnicodeDecodeError):
                return {}, f"NOT MEASURABLE: untracked file {rel!r} is not readable"
            je_datei.setdefault(rel, [])
            je_datei[rel].extend(enumerate(_python_zeilen(leser, text), start=1))
    return je_datei, "measured"


def _prosazeilen(datei: str, lies=None) -> set[int] | None:
    """Every line of the file that is a comment, by TOKEN, or part of a string that stands alone as
    a statement, by the syntax tree.

    THE FIRST VERSION COUNTED QUOTE CHARACTERS, and an adversarial read caught it the same day.
    It walked the lines before the one in question and flipped a flag on every odd count of a
    triple quote. A single triple quote inside an ordinary one-line string sets that flag, so the
    real docstring opener that follows CLOSES it, and the whole docstring then counts as code.

    Measured on a four-line file: the identical German docstring line is checked when nothing
    precedes it and skipped when one such code line does. The check did not become wrong about
    the line, it stopped looking at it, which is the more expensive of the two, because the
    report stays green either way.

    The tokenizer already answers exactly this question, so the shape of the fix is to stop
    re-deriving it. Returns None when the file cannot be read, does not tokenize or does not
    parse, and the run then says NOT MEASURABLE for the file (`_ist_prosa`).
    """
    inhalt = (lies or _stand_leser(aus_head=False))(datei)
    if inhalt is None:
        return None
    # Decoded as `read_text` decoded the file before: universal newlines, undecodable bytes replaced.
    quelle = io.TextIOWrapper(io.BytesIO(inhalt), encoding="utf-8", errors="replace").read()
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
    # The syntax tree says which strings are notes rather than values.
    #
    # A STRING THAT STANDS ALONE AS A STATEMENT IS PROSE, wherever it stands and however it is
    # written: nothing runs it and nothing prints it, so its only reader is a person, as with a
    # comment. A docstring is one such string. Counting the docstring position alone let German
    # sentences through in green in every form of this gate (review lenses, measured 2026-09-26): an
    # f-string where a docstring stands, a bare string as a later statement, a bytes literal, a
    # string after `from __future__`, and two literals joined by `+`. A string handed to a call or
    # a name is not such a string and stays out.
    try:
        baum = ast.parse(quelle)
    except (SyntaxError, ValueError):
        return None
    for knoten in ast.walk(baum):
        if isinstance(knoten, ast.Expr) and _nur_text(knoten.value):
            aus.update(range(knoten.lineno, (knoten.end_lineno or knoten.lineno) + 1))
    return aus


def _nur_text(ausdruck: ast.AST) -> bool:
    """A str, bytes or f-string literal, or such literals joined by `+`: text and nothing else.
    A string built by another operator or by a call is code (named limit)."""
    if isinstance(ausdruck, ast.Constant):
        return isinstance(ausdruck.value, (str, bytes))
    if isinstance(ausdruck, ast.JoinedStr):
        return True
    return (isinstance(ausdruck, ast.BinOp) and isinstance(ausdruck.op, ast.Add)
            and _nur_text(ausdruck.left) and _nur_text(ausdruck.right))


def _md_prosazeilen(datei: str, lies=None) -> set[int] | None:
    """Every line of a Markdown file that is NOT inside a fenced code block.

    In Markdown there is no comment/code split to make: the file IS prose, and the exception is the
    fenced block, which carries commands, output and identifiers. That mirrors the rule one level
    up, where code identifiers are a naming question rather than a language one.

    THE FENCE IS DERIVED, NOT TOGGLED. A flag flipped on every fence line is the same defect this
    module already fixed once for docstrings: a stray marker then inverts the rest of the file, and
    the report stays green because the tool stopped looking rather than started being wrong. So the
    opener's character and length are remembered, and only a closer of at least that length in the
    SAME character ends the block, which is what CommonMark says.

    Returns None when the file cannot be read or its quotation pairs do not balance, and the run
    then says NOT MEASURABLE for the file (`_ist_prosa`).
    """
    inhalt = (lies or _stand_leser(aus_head=False))(datei)
    if inhalt is None:
        return None
    # Lines as CommonMark ends them (CRLF, CR, LF). `splitlines()` also ends one at U+2028, a form
    # feed and five more characters, and every line after such a character was numbered one higher
    # than the diff numbers it.
    try:
        zeilen = _python_zeilen(_diff_leser(), inhalt.decode("utf-8", "replace"))
    except (ImportError, AttributeError, SyntaxError):
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


def _ist_prosa(datei: str, nr: int, text: str, lies=None) -> bool | None:
    """Comment, or inside a string that stands alone as a statement. The answer comes from the FILE,
    not from the hunk.

    A diff hunk does not say whether its line sits inside a docstring, and guessing from the
    fragment would call a string literal a comment. The file in the judged state does say: the
    blob at HEAD, or the working tree in that form (`lies`; without it, the disk).

    None when the file gives no prose map (a .py file that does not tokenize or parse, a .md file
    with an unbalanced quotation pair): the line cannot be judged, and `pruefe` says NOT MEASURABLE.
    Read as False, a German docstring after a syntax error elsewhere in its file, and every line of
    a .md file after an unclosed quotation opener, passed as green in both forms (a review lens,
    measured 2026-09-26). A comment line needs no map and is judged as before.
    """
    if datei.endswith(".md"):
        zeilen = _md_prosazeilen(datei, lies)
        return None if zeilen is None else nr in zeilen
    if _KOMMENTAR.search(text):
        return True
    zeilen = _prosazeilen(datei, lies)
    return None if zeilen is None else nr in zeilen


def pruefe(basis: str, arbeitsbaum: bool = False) -> dict:
    if REPO_HERKUNFT.startswith("rueckfall"):
        return {"urteil": "NOT MEASURABLE", "rc": 2, "befunde": [],
                "gemessener_baum": str(REPO), "baum_herkunft": REPO_HERKUNFT,
                "wortlisten_baum": str(WERKZEUG_WURZEL),
                "grund": ("no tree to judge here, and git's own reason is carried in "
                          f"baum_herkunft; name one with --repo instead of taking this tool's own "
                          f"({REPO_HERKUNFT})")}
    lies = _stand_leser(aus_head=not arbeitsbaum)
    je_datei, lage = _neue_zeilen(basis, arbeitsbaum, lies)
    if lage != "measured":
        return {"urteil": "NOT MEASURABLE", "grund": lage, "befunde": [],
                "gemessener_baum": str(REPO), "baum_herkunft": REPO_HERKUNFT,
                "wortlisten_baum": str(WERKZEUG_WURZEL), "rc": 2}
    befunde, ohne_karte = [], set()
    for datei, zeilen in sorted(je_datei.items()):
        for nr, text in zeilen:
            prosa = _ist_prosa(datei, nr, text, lies)
            if prosa is None:
                ohne_karte.add(datei)
                continue
            if not prosa:
                continue
            w = DP.treffer(text)
            if len(w) >= SCHWELLE:
                befunde.append({"datei": datei, "zeile": nr,
                                "woerter": sorted(set(x.lower() for x in w)),
                                "text": text.strip()[:110]})
    if ohne_karte:
        # NOT MEASURABLE comes first, and the findings made elsewhere are still listed: an unjudged
        # file is a statement about the whole range, not a line to be weighed against the others.
        return {"urteil": "NOT MEASURABLE", "rc": 2, "befunde": befunde,
                "ohne_prosakarte": sorted(ohne_karte),
                "grund": ("no prose map for " + ", ".join(sorted(ohne_karte)) + ": a .py file that does "
                          "not tokenize or parse, or a .md file with an unbalanced quotation pair; its "
                          "added lines were not judged"),
                "gemessener_stand": "working tree" if arbeitsbaum else "HEAD",
                "gemessener_baum": str(REPO), "baum_herkunft": REPO_HERKUNFT,
                "wortlisten_baum": str(WERKZEUG_WURZEL),
                "geprueft": sum(len(z) for z in je_datei.values()), "dateien": len(je_datei)}
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


def main(argv=None) -> int:
    # A path is read as git names it (-z, os.fsdecode), so a name that is not UTF-8 carries
    # surrogates, and a strict stdout raised on one with exit 1, the exit code of a finding
    # (measured 2026-09-26 on all four path readers). Backslash escapes instead: in JSON they are
    # the escape of the same code point, so the name reads back as it was.
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
        print(json.dumps(d, ensure_ascii=False, indent=2))
    else:
        print(f"new-lines-english: {d['urteil']} · {d.get('geprueft', 0)} added lines in "
              f"{d.get('dateien', 0)} files · measured state: {d.get('gemessener_stand', '?')}"
              f" · measured tree: {d.get('gemessener_baum', '?')}"
              f" ({d.get('baum_herkunft', '?')})"
              f" · word list from: {d.get('wortlisten_baum', '?')}")
        for b in d["befunde"][:20]:
            print(f"  {b['datei']}:{b['zeile']}  {b['woerter']}  {b['text']}")
        if len(d["befunde"]) > 20:
            print(f"  ... and {len(d['befunde']) - 20} more, not listed here (--json shows all)")
        if d.get("grund"):
            print(f"  ! {d['grund']}")
    return int(d["rc"])


if __name__ == "__main__":
    raise SystemExit(main())
