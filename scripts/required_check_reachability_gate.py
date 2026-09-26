#!/usr/bin/env python3
"""Can the workflows produce every status check the branch ruleset requires?

WHY THIS EXISTS. A required status check has two failure modes, red and ABSENT, and only the
first is visible. A red check shows a red line. An absent one shows nothing at all: the pull
request stays BLOCKED with no check red on it, and GitHub offers no field that separates "still
running" from "will never be reported" -- `mergeStateStatus` is BLOCKED for both. Whoever looks
at the red lines therefore repairs exactly the checks that do not block.

Measured in this repository on 2026-09-16: pull requests 209, 210, 211 and 212 all stood at
BLOCKED with mergeable=MERGEABLE, no required check red, and four of the seven required contexts
absent -- not failing, not skipped, simply never created, because the test matrix produces five
Python versions only under a condition. Pull request 211 is the fix FOR the one red advisory
check, that check was green on it, and it was blocked all the same.

This is the third instance of one class here. The first was a missing `labeled` trigger, closed
2026-09-14 in commit 89301253. The second was a missing `merge_group` trigger in
fork-pr-isolation.yml, the second of two files that carry required contexts. Each was found by a
person reading, never by a mechanism. Hence this gate.

WHAT IT DOES NOT DO. It evaluates GitHub expressions only as far as the few atoms of `_ATOME`
reach, the ones this repository's conditions use. Anything it cannot read literally it reports
as NOT_MEASURABLE with the reason, and NOT_MEASURABLE is a failure, never a pass -- an unknown
must not read as fine; a condition it cannot evaluate is named as undecided in the report. In
particular it understands exactly one conditional matrix
shape, `${{ fromJSON( <condition> && '<json>' || '<json>' ) }}` as the whole value with one operand
before the `&&`, because that is the shape this repository uses; it takes the second literal as
the ordinary case and names the condition.

KNOWN TRAPS, from the survey of prior art on 2026-09-16, each guarded below:
  * A job skipped by `if:` reports Success, so a required check on a conditional job never blocks.
    An ABSENT context is stricter than a skipped one: it does not report at all.
  * A reusable workflow reports as `<caller job id> / <called job name>`, not as the called job's
    own name. Reading only the called file yields the wrong context name.
  * A job `name:` may interpolate matrix values, so the context name exists only after expansion.
  * `cond && A || B` falls through to B whenever A is falsy, regardless of cond. Empty or `[]` in
    the true arm silently disables the whole condition.

WHAT IT READS BEFORE IT CALLS A CONTEXT PRODUCED (lens on ac05d85d, 2026-09-26: five forms read as
produced with exit 0 that GitHub never produces). A workflow is read with YAML 1.2's core schema,
the one both of GitHub's readers use; PyYAML's default reads `on` as True and `010` as 8. Its `on:`
is read: a context is produced unconditionally only when its workflow runs on every pull request
into the declared branch, and on a live event only when its workflow runs on that event. A matrix
is expanded as GitHub documents it: every combination of its keys, `exclude`, then `include`, and
the name carries every value of a combination. An `if:` is read the way GitHub's template reader
splits `${{ }}`. A form it does not read is NOT MEASURABLE with its reason, never produced.

Exit 0 when every declared context is produced, either unconditionally or under a named
condition. Exit 1 when one is unreachable or not measurable.
"""
from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import os
import re
import string
import sys
from pathlib import Path

try:
    import yaml
except ImportError:                                    # pragma: no cover - guarded, see below
    yaml = None

REPO = Path(__file__).resolve().parents[1]
WORKFLOWS = REPO / ".github" / "workflows"
DECLARATION = REPO / ".github" / "required_status_checks.json"

ALWAYS = "produced"
GATED = "produced-only-if"
ABSENT = "never-produced"
UNKNOWN = "not-measurable"

#: `fromJSON( <condition> && '<true arm>' || '<false arm>' )`. The false arm is the ordinary case.
#: Matched against the WHOLE expression inside the value's one `${{ }}` (lens on ac05d85d, F5): a
#: search found the shape inside `true || X && '[..]' || '[..]'`, which GitHub reads as
#: `true || (X && '[..]') || '[..]'`, the bare `true`, since its `||` binds looser than `&&`. The
#: condition must also be one operand (`_ein_operand`). Its whitespace is ASCII: a character outside
#: ASCII there leaves the shape unread, which is not measurable, never another reading.
_TERNARY = re.compile(
    r"fromJSON\([ \t\n\r\f\v]*(?P<cond>.*?)&&[ \t\n\r\f\v]*'(?P<wahr>\[[^']*\])'[ \t\n\r\f\v]*\|\|"
    r"[ \t\n\r\f\v]*'(?P<sonst>\[[^']*\])'[ \t\n\r\f\v]*\)",
    re.S,
)
#: A status function called in an expression, in ASCII of any case. GitHub allows none in `strategy`
#: (docs.github.com, contexts, "Context availability": `jobs.<job_id>.strategy` lists no special
#: function, `jobs.<job_id>.if` lists always, cancelled, success and failure; read 2026-09-26), so a
#: matrix condition with one is not measurable. The first form read `always() && A || B` as A.
_STATUSAUFRUF = re.compile(r"(?<![\w.])(?:[aA][lL][wW][aA][yY][sS]|[sS][uU][cC][cC][eE][sS][sS]"
                           r"|[fF][aA][iI][lL][uU][rR][eE]|[cC][aA][nN][cC][eE][lL][lL][eE][dD])\s*\(")

#: A job condition made ONLY of a status function. `always()` and `!cancelled()` do not gate a job
#: on the event: the job runs whenever the workflow runs (the second one except on a cancelled
#: run, which produces no verdict at all). Such a job is the shape GitHub itself recommends for a
#: required check that summarises other jobs -- "Use always() with needs for required checks
#: that depend on other jobs" (docs, read 2026-09-17) -- and it must not read as `produced-only-if`.
#: Anything else with a status function in it (`success()`, `failure()`, `cancelled()` alone, or a
#: mix with event atoms) stays a named condition.
#: Case-insensitive like every GitHub expression (`Always()` is `always()`); lens C, 2026-09-17.
#: The `${{` and the `}}` come as a pair or not at all (lens on ac05d85d): each was optional on its
#: own, so `${{ always()`, which GitHub's template reader refuses as an expression not closed, read as
#: a status function and its job as produced.
#: CASE-INSENSITIVE IN ASCII ONLY (lens on ac05d85d, F4): `re.I` also folds `ı`, `İ`, `ſ` and the
#: Kelvin sign onto ASCII letters, so `faılure()` read as `failure()`. GitHub's lexer takes only ASCII
#: letters, digits, `_` and `-` into a keyword and looks a function up OrdinalIgnoreCase
#: (actions/runner at 15231bede4aa, ExpressionUtility.IsLegalKeyword, ExpressionConstants and
#: ExpressionParser, read 2026-09-26, not measured): a name with any other letter is no function
#: there, and the expression does not parse. Every status function below is spelled in ASCII classes.
_NUR_STATUSFUNKTION = re.compile(r"^\s*(?:\$\{\{\s*(?:[aA][lL][wW][aA][yY][sS]\(\s*\)"
                                 r"|!\s*[cC][aA][nN][cC][eE][lL][lL][eE][dD]\(\s*\))\s*\}\}"
                                 r"|[aA][lL][wW][aA][yY][sS]\(\s*\)"
                                 r"|!\s*[cC][aA][nN][cC][eE][lL][lL][eE][dD]\(\s*\))\s*$")
#: The GUARD question is wider than the bucketing question (lens A, 2026-09-17): GitHub replaces
#: the implicit `success()` as soon as ANY status function appears in the condition, so
#: `always() && x` or `!cancelled() || y` is guarded even though it is a named condition for
#: the event. THE TRAP IS A JOB THAT DOES NOT RUN WHEN A NEEDED JOB FAILED -- then it is
#: skipped, and skipped reads as passed. So a guard is a condition that can be TRUE on a failed
#: need: `always()`, `!cancelled()` and `failure()` (the job runs on failure and can go red). A
#: bare `cancelled()` is not one: the job runs only on a cancelled run and is skipped on every
#: ordinary failure (un, round 1, 2026-09-18 -- the first regex counted it as a guard).
#: `success()` is the default and guards nothing.
#:
#: SINCE 2026-09-26 THE GUARD IS EVALUATED, NOT SPELLED (review of follow-up 236): this pattern
#: found the `always()` inside `!always()`, so a job that never runs read as guarded. The
#: question is now asked of the evaluator (`laeuft_bei_fehlschlag`), with a needed job failed.
#: A negation is read by GitHub's semantics there: `!always()` is false on every run, `!failure()`
#: is false exactly when a need failed, so neither guards; `!success()` is true when a need
#: failed and guards like `failure()`; `!cancelled()` stays a guard. This pattern is the reading
#: for a condition the evaluator cannot read, and it counts a status function only where no `!`
#: stands directly before it, `!cancelled()` and `!success()` as the negated guard forms. A
#: negated group `!( ... )` is not read by it at all (see `_wache_nach_schreibweise`).
_TRAEGT_WACHE = re.compile(r"(?<![\w.!])(?<!! )"
                           r"(?:[aA][lL][wW][aA][yY][sS]\(\s*\)|[fF][aA][iI][lL][uU][rR][eE]\(\s*\)"
                           r"|!\s*(?:[cC][aA][nN][cC][eE][lL][lL][eE][dD]|[sS][uU][cC][cC][eE][sS][sS])\(\s*\))")
_VERNEINTE_GRUPPE = re.compile(r"!\s*\(")
#: A string literal of GitHub's expression grammar: single quotes, a quote inside it doubled.
#: A status function written INSIDE one is text, not a call: `message == 'always()'` has no
#: status function, so GitHub prepends `success()`, and the job is skipped when a need fails.
#: Searched as text, it read as guarded and the trap passed with exit 0 (a review lens, 2026-09-26).
_GITHUB_LITERAL = re.compile(r"'(?:[^']|'')*'")


def ohne_literale(bedingung: str) -> str:
    """The condition with every string literal emptied, so a search sees only the expression."""
    return _GITHUB_LITERAL.sub("''", bedingung)

#: The characters Python reads as whitespace and GitHub's expression lexer does not. The lexer skips
#: .NET `Char.IsWhiteSpace` (actions/runner, src/Sdk/DTExpressions2/Expressions2/Tokens/
#: LexicalAnalyzer.cs, read 2026-09-26); `str.split()`, `str.isspace()` and `\s` take four more,
#: U+001C to U+001F (on Python 3.10.12, Unicode 13.0.0, against the .NET definition applied to the
#: same tables, not against .NET itself). Folded the Python way, `if: "<U+001C>always()"` read as
#: `always()` and its job as produced, while the parser GitHub runs on a condition without `${{`
#: stops at that character (lens 236-B, 2026-09-26). A condition that carries one is not
#: measurable, before any pattern here reads it; on everything else Python's whitespace and
#: GitHub's are the same set, so `\s` and `split()` below read it as GitHub does.
_NICHT_GITHUBS_LEERRAUM = frozenset(map(chr, range(0x1C, 0x20)))


def fremder_leerraum(text: str) -> list[str]:
    """The characters of `text` that Python reads as whitespace and GitHub does not, as U+XXXX."""
    return sorted({f"U+{ord(c):04X}" for c in text if c in _NICHT_GITHUBS_LEERRAUM})


def ohne_wache_trotz_needs(job: dict) -> bool:
    """Does this job have `needs` and no guard, no condition that can run it when a need failed?

    Then it is SKIPPED whenever a needed job fails -- and a skipped required check reads as
    passed, so a required context on such a job can never block on the failure of what it needs.
    That is the exact trap a collector job is built to avoid, and the one shape in which it
    would silently fail at its purpose. `if: success()` is the default and changes nothing;
    `if: cancelled()` alone is skipped on every ordinary failure and guards nothing either, and
    neither does `!always()`, which is false on every run.

    A condition holding a character Python reads as whitespace and GitHub does not is checked
    before any pattern reads it: no guard is claimed for it. A condition the evaluator cannot read
    is read by its spelling (`_wache_nach_schreibweise`), and erhebe names it as undecided.
    """
    if not job.get("needs"):
        return False
    roh = str(job.get("if") or "")
    if fremder_leerraum(roh):
        return True
    bed = " ".join(roh.split())
    if not bed:
        return True
    try:
        return not laeuft_bei_fehlschlag(bed)
    except NichtAuswertbar:
        return not _wache_nach_schreibweise(bed)


def _wache_nach_schreibweise(bed: str) -> bool:
    """The guard read from the spelling, for a condition the evaluator cannot read. A negated group
    `!( ... )` may negate the guard inside it, and this reading cannot tell, so it claims none."""
    ohne = ohne_literale(bed)
    return not _VERNEINTE_GRUPPE.search(ohne) and bool(_TRAEGT_WACHE.search(ohne))


def _ganzzahl(lader, knoten) -> int:
    """An integer of YAML 1.2's core schema: decimal, `0o` octal or `0x` hexadecimal. PyYAML's own
    reads a leading zero as octal (`010` is 8), which YAML 1.2 reads as ten."""
    text = lader.construct_scalar(knoten)
    if text[:2] in ("0o", "0x"):
        return int(text[2:], 8 if text[1] == "o" else 16)
    return int(text, 10)


#: PyYAML reads YAML 1.1, and GitHub does not. Both of GitHub's workflow readers use YAML 1.2's core
#: schema (read 2026-09-26, not measured against GitHub: actions/runner at 15231bede4aa,
#: src/Sdk/DTPipelines/Pipelines/ObjectTemplating/YamlObjectReader.cs, MatchNull, MatchBoolean,
#: MatchInteger, MatchFloat, each commented "YAML 1.2 core schema"; and actions/languageservices,
#: workflow-parser/src/workflows/yaml-object-reader.ts, `parseDocument` with the `yaml` package's
#: defaults, which are version 1.2 and its core schema, eemeli/yaml at 528ef30d, src/schema/core).
#: Under YAML 1.1 `on` is True, `yes` and `off` are booleans, `010` is 8 and `1:20` is 80, so a
#: matrix value `on` named a job `true`, and the `on:` of a workflow was the key True. This loader
#: keeps the four implicit types of the core schema and nothing else: no merge key, no timestamp.
if yaml is not None:
    class _GitHubLader(yaml.SafeLoader):
        yaml_implicit_resolvers: dict = {}

    _GitHubLader.add_implicit_resolver(
        "tag:yaml.org,2002:null", re.compile(r"\A(?:~|null|Null|NULL|)\Z"), ["~", "n", "N", ""])
    _GitHubLader.add_implicit_resolver(
        "tag:yaml.org,2002:bool", re.compile(r"\A(?:true|True|TRUE|false|False|FALSE)\Z"), list("tTfF"))
    _GitHubLader.add_implicit_resolver(
        "tag:yaml.org,2002:int", re.compile(r"\A(?:[-+]?[0-9]+|0o[0-7]+|0x[0-9a-fA-F]+)\Z"),
        list("-+0123456789"))
    _GitHubLader.add_implicit_resolver(
        "tag:yaml.org,2002:float",
        re.compile(r"\A(?:[-+]?(?:\.[0-9]+|[0-9]+(?:\.[0-9]*)?)[eE][-+]?[0-9]+|[-+]?(?:\.[0-9]+|[0-9]+\.[0-9]*)"
                   r"|[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN))\Z"),
        list("-+.0123456789"))
    _GitHubLader.add_constructor("tag:yaml.org,2002:int", _ganzzahl)
else:                                                  # pragma: no cover - `_lade` refuses first
    _GitHubLader = None


def _lade(pfad: Path) -> dict:
    """Read one workflow, with YAML 1.2's core schema (`_GitHubLader`). A file that does not parse is
    NOT an empty file."""
    if yaml is None:
        raise RuntimeError(
            "PyYAML is missing, so no workflow can be read. That is not an empty result: without "
            "the parser this gate cannot tell a reachable context from an absent one, and it must "
            "not pretend otherwise. PyYAML is declared in the [test] extra of pyproject.toml.")
    d = yaml.load(pfad.read_text(encoding="utf-8"), Loader=_GitHubLader)  # noqa: S506 - a SafeLoader
    if not isinstance(d, dict):
        raise ValueError(f"{pfad.name}: top level is {type(d).__name__}, expected a mapping")
    return d


class NichtLesbar(ValueError):
    """A form of a workflow this gate does not read: a trigger, a matrix, a job name. Its message is the
    reason; the job or the file is reported as not measurable, never as producing a context."""


_ASCII_KLEIN = str.maketrans(string.ascii_uppercase, string.ascii_lowercase)


def _ascii_klein(text: str) -> str:
    """`text` with its ASCII capitals in lower case and every other character as it is."""
    return text.translate(_ASCII_KLEIN)


#: GitHub runs at most 256 jobs of one matrix (docs.github.com, workflow syntax,
#: `jobs.<job_id>.strategy.matrix`, read 2026-09-26); a matrix past that is refused, not expanded.
_HOECHSTENS_JOBS = 256


def matrix_lesung(job: dict) -> tuple[dict[str, list], dict[str, list], str | None, str | None, list[str]]:
    """`matrix_werte`, and why a matrix is not read: (ordinary values, gated values, condition, note,
    reasons). Each reason makes the matrix not measurable; a key that is not read has empty value
    lists. A `strategy` or a matrix that is not a mapping is such a reason too (a `strategy` written
    as an expression made the first form raise AttributeError out of the whole survey)."""
    strategie = job.get("strategy")
    if strategie is None:
        return {}, {}, None, None, []
    if not isinstance(strategie, dict):
        return {}, {}, None, None, [f"`strategy` is {type(strategie).__name__}, not a mapping"]
    m = strategie.get("matrix")
    if m is None:
        return {}, {}, None, None, []
    if not isinstance(m, dict):
        return {}, {}, None, None, [f"the matrix is {type(m).__name__}, not a mapping of keys to values"]
    gewoehnlich: dict[str, list] = {}
    gegated: dict[str, list] = {}
    bedingung: str | None = None
    hinweis: str | None = None
    gruende: list[str] = []
    for schluessel, wert in m.items():
        if schluessel in ("include", "exclude"):
            continue
        if isinstance(wert, list):
            gewoehnlich[schluessel] = list(wert)
            gegated[schluessel] = list(wert)
            if not wert:
                gruende.append(f"matrix key {schluessel!r} has no values, which GitHub refuses")
            continue
        gewoehnlich[schluessel] = []
        gegated[schluessel] = []
        if isinstance(wert, str) and fremder_leerraum(wert):
            gruende.append(f"matrix key {schluessel!r} carries {', '.join(fremder_leerraum(wert))}")
            continue
        if not (isinstance(wert, str) and "fromJSON" in wert):
            gruende.append(f"matrix key {schluessel!r} is {type(wert).__name__}, not a list")
            continue
        try:
            segmente = _vorlage(wert)
        except NichtLesbar as exc:
            gruende.append(f"matrix key {schluessel!r}: {exc}")
            continue
        t = (_TERNARY.fullmatch(segmente[0][1].strip())
             if len(segmente) == 1 and segmente[0][0] else None)
        if not t:
            gruende.append(f"matrix key {schluessel!r} is not the one conditional shape this gate reads")
            continue
        if not _ein_operand(t.group("cond")):
            gruende.append(f"matrix key {schluessel!r}: the text before `&&` is not one operand, and GitHub's "
                           f"`||` binds looser than `&&`, so the value is not `cond && A || B`")
            continue
        if _STATUSAUFRUF.search(ohne_literale(t.group("cond"))):
            gruende.append(f"matrix key {schluessel!r}: its condition calls a status function, which GitHub "
                           f"allows in no `strategy`")
            continue
        try:
            wahr = json.loads(t.group("wahr"))
            sonst = json.loads(t.group("sonst"))
        except json.JSONDecodeError:
            gruende.append(f"an arm of matrix key {schluessel!r} is not JSON")
            continue
        # cond && A || B falls through to B whenever A is falsy, condition or not.
        if not wahr:
            # `cond && '[]' || B` is B for every cond. The condition is dead, and the value
            # sets look exactly as they would without it -- only this note says so.
            gewoehnlich[schluessel] = list(sonst)
            gegated[schluessel] = list(sonst)
            hinweis = (f"matrix key {schluessel!r}: the true arm of the condition is empty, so "
                       f"`cond && '[]' || ...` falls through for every value of the condition. "
                       f"The condition is dead code and produces nothing.")
            if not sonst:
                gruende.append(f"matrix key {schluessel!r} has no values in either arm")
            continue
        bed = " ".join(t.group("cond").split())
        try:
            werte = wahrheitswerte(bed)
        except NichtAuswertbar:
            werte = set()                # not decided; erhebe names the condition as undecided
        if len(werte) == 1:
            immer = True in werte
            gewoehnlich[schluessel] = list(wahr if immer else sonst)
            gegated[schluessel] = list(wahr if immer else sonst)
            hinweis = (f"matrix key {schluessel!r}: the condition `{bed}` is "
                       f"{'true' if immer else 'false'} on every event, so `cond && A || B` "
                       f"always yields {'A' if immer else 'B'}. The condition is dead code, and "
                       f"the other arm produces nothing.")
            if not gewoehnlich[schluessel]:
                gruende.append(f"matrix key {schluessel!r} has no values in the arm it always takes")
            continue
        gewoehnlich[schluessel] = list(sonst)
        gegated[schluessel] = list(wahr)
        bedingung = bed
        if not sonst:
            gruende.append(f"matrix key {schluessel!r} has no values in its ordinary arm")
    return gewoehnlich, gegated, bedingung, hinweis, gruende


def _ein_operand(text: str) -> bool:
    """Is `text` one operand of GitHub's `&&`: parentheses balanced, and no `&&` or `||` outside them
    and outside string literals? Then `text && A || B` is `(text && A) || B` in GitHub's grammar (`&&`
    binds tighter than `||`); with a bare `||` in it, it is another expression. A bare `&&` would
    still be read the same, and is refused all the same: one shape, read one way."""
    ohne = ohne_literale(text).replace("''", "")
    if "'" in ohne or not ohne.strip():
        return False
    tiefe = 0
    for i, zeichen in enumerate(ohne):
        if zeichen == "(":
            tiefe += 1
        elif zeichen == ")":
            tiefe -= 1
            if tiefe < 0:
                return False
        elif tiefe == 0 and ohne.startswith(("&&", "||"), i):
            return False
    return tiefe == 0


def matrix_werte(job: dict, roh: str) -> tuple[dict[str, list], dict[str, list], str | None, str | None]:
    """Return (ordinary values, gated values, condition, note) per matrix key.

    The NOTE carries a defect the value sets alone cannot express. An empty true arm makes the
    whole condition dead: `cond && '[]' || B` yields B for every value of cond. The resulting
    context set is the same as if the condition had been deleted, so counting values would never
    reveal it -- the reader has to be told in words, or the dead condition sits there looking
    live. Measured as a surviving mutant against this gate's own contracts on 2026-09-16.

    Three shapes are understood. A literal list is both ordinary and gated. The one conditional
    shape this repository uses splits into the two arms. Anything else yields an empty ordinary
    set, which the caller turns into NOT_MEASURABLE rather than into a pass. A value holding a
    character Python reads as whitespace and GitHub does not is such a value, and it is recognised
    before any pattern reads it. Why a key was not read is in `matrix_lesung`, which erhebe asks.

    A condition with the same value on every event takes one arm always (review of follow-up 236,
    the constant-false job condition, and its sibling here): `false && A || B` is B and
    `true && A || B` is A, so the other arm is dead code, and the NOTE says so. Before, the dead arm
    of a constant-true condition read as the ordinary case, and its contexts as produced.
    """
    return matrix_lesung(job)[:4]


def _matrix_schluessel(schluessel) -> str:
    """A matrix key as GitHub compares it. The docs say a matrix variable's name is case insensitive
    (`OS` and `os` are one variable; docs.github.com, workflow syntax, read 2026-09-26). How a name
    with a character outside ASCII is folded was not read, so such a name is not read either."""
    if not isinstance(schluessel, str) or not schluessel or not schluessel.isascii():
        raise NichtLesbar(f"the matrix key {schluessel!r} is not an ASCII name, and how GitHub folds the "
                          f"case of any other was not read")
    return _ascii_klein(schluessel)


def _anzeige(wert, wo: str) -> str:
    """How a matrix value stands in a job name: a text as it is, an integer in decimal. A number with a
    fraction, a boolean, null, a list or a mapping is not read, since how GitHub spells it in a name was
    not read, and neither is a text holding an expression, which GitHub evaluates first."""
    if isinstance(wert, str) and "${{" not in wert:
        return wert
    if isinstance(wert, int) and not isinstance(wert, bool) and abs(wert) < 10 ** 15:
        return str(wert)
    raise NichtLesbar(f"{wo} holds {_einzeilig(repr(wert), 60)}, whose spelling in a job name this gate "
                      f"does not know")


def _gleich(a: str, b: str, wo: str) -> bool:
    """Do two matrix values match, for `exclude` and `include`? Equal texts do, different ones do not;
    two that differ only in case are not decided, since whether GitHub compares values with case was
    not read."""
    if a == b:
        return True
    if a.casefold() == b.casefold():
        raise NichtLesbar(f"{wo}: {a!r} and {b!r} differ only in case, and whether GitHub matches them "
                          f"was not read")
    return False


def _eintraege(roh, wo: str) -> list[dict[str, str]]:
    """The entries of `include` or `exclude`, each a mapping of folded key to displayed value."""
    if not isinstance(roh, list) or not roh:
        raise NichtLesbar(f"`{wo}` is not a list of combinations")
    aus = []
    for eintrag in roh:
        if not isinstance(eintrag, dict) or not eintrag:
            raise NichtLesbar(f"an entry of `{wo}` is not a mapping of keys to values")
        gelesen: dict[str, str] = {}
        for k, v in eintrag.items():
            kl = _matrix_schluessel(k)
            if kl in gelesen:
                raise NichtLesbar(f"an entry of `{wo}` names the key {k!r} twice")
            gelesen[kl] = _anzeige(v, f"`{wo}`")
        aus.append(gelesen)
    return aus


def _kombinationen(m: dict, werte: dict[str, list]) -> list[dict[str, str]]:
    """Every combination a matrix runs, as GitHub documents it (docs.github.com, "Running variations of
    jobs in a workflow" and the workflow syntax of `include` and `exclude`, read 2026-09-26): every
    combination of the values of its keys, in the order the keys are declared; then `exclude`, which
    removes a combination that matches an entry on every key the entry names ("only has to be a partial
    match"); then `include`, whose entry is added to every ORIGINAL combination it overwrites no original
    value of (a value an earlier entry added may be overwritten), and becomes a combination of its own
    when it fits none. An entry never adds to a combination another entry created. With no keys, every
    `include` entry is a combination. `werte` are the values of the keys, the chosen arm of a
    conditional one. Each combination maps a folded key to the value's text, keys in order."""
    schluessel: dict[str, list[str]] = {}
    for k, vs in werte.items():
        kl = _matrix_schluessel(k)
        if kl in ("include", "exclude") or kl in schluessel:
            raise NichtLesbar(f"the matrix key {k!r} is another spelling of a key GitHub reads as the same")
        texte = [_anzeige(v, f"matrix key {k!r}") for v in vs]
        if not texte:
            raise NichtLesbar(f"matrix key {k!r} has no values, which GitHub refuses")
        schluessel[kl] = texte
    anzahl = 1
    for texte in schluessel.values():
        anzahl *= len(texte)
        if anzahl > _HOECHSTENS_JOBS:
            raise NichtLesbar(f"the matrix has more than {_HOECHSTENS_JOBS} combinations, which GitHub refuses")
    kombinationen = ([dict(zip(schluessel, werte_))
                      for werte_ in itertools.product(*schluessel.values())] if schluessel else [])
    if "exclude" in m:
        for eintrag in _eintraege(m["exclude"], "exclude"):
            fremd = [k for k in eintrag if k not in schluessel]
            if fremd:
                raise NichtLesbar(f"`exclude` names {fremd[0]!r}, which is no key of the matrix")
            kombinationen = [c for c in kombinationen
                             if not all(_gleich(c[k], v, "exclude") for k, v in eintrag.items())]
    if "include" in m:
        original, neu = kombinationen, []
        for eintrag in _eintraege(m["include"], "include"):
            passt = False
            for c in original:
                if all(_gleich(c[k], v, "include") for k, v in eintrag.items() if k in schluessel):
                    c.update({k: v for k, v in eintrag.items() if k not in schluessel})
                    passt = True
            if not passt:
                neu.append(dict(eintrag))
        kombinationen = original + neu
    if not kombinationen:
        raise NichtLesbar("the matrix yields no combination")
    if len(kombinationen) > _HOECHSTENS_JOBS:
        raise NichtLesbar(f"the matrix has more than {_HOECHSTENS_JOBS} combinations, which GitHub refuses")
    return kombinationen


#: `matrix.<key>` inside `${{ }}` of a job name; `matrix` in any ASCII case, as GitHub looks up a context
#: name (OrdinalIgnoreCase, actions/runner at 15231bede4aa, src/Sdk/DTExpressions2/Expressions2/
#: ExpressionParser.cs, read 2026-09-26). Any other expression in a name is not read.
_MATRIX_REF = re.compile(r"[mM][aA][tT][rR][iI][xX]\.([A-Za-z0-9_-]+)")


def _vorlage(text: str) -> list[tuple[bool, str]]:
    """A value as GitHub's template reader splits it: (is an expression, text) segments. An expression
    runs from `${{` to the first `}}` outside a single-quoted string, and one that is not closed is an
    error (actions/runner at 15231bede4aa, src/Sdk/DTObjectTemplating/ObjectTemplating/
    TemplateReader.cs, ParseScalar and TemplateStrings.ExpressionNotClosed, read 2026-09-26, not
    measured). Plain string operations only, no pattern."""
    segmente: list[tuple[bool, str]] = []
    i = 0
    while True:
        anfang = text.find("${{", i)
        if anfang < 0:
            if i < len(text):
                segmente.append((False, text[i:]))
            return segmente
        if anfang > i:
            segmente.append((False, text[i:anfang]))
        j, in_text, ende = anfang + 3, False, -1
        while j < len(text):
            if text[j] == "'":
                in_text = not in_text
            elif not in_text and text[j] == "}" and text[j - 1] == "}":
                ende = j
                break
            j += 1
        if ende < 0:
            raise NichtLesbar("an expression opened with `${{` is not closed, which GitHub's template "
                              "reader refuses")
        segmente.append((True, text[anfang + 3:ende - 1]))
        i = ende + 1


def _ein_ausdruck(text: str) -> str:
    """The expression of an `if:` text as GitHub reads it: the text itself when it holds no `${{`, the
    inside when one `${{ }}` spans all of it. Anything else raises NichtLesbar: an expression not
    closed, or text beside an expression, which GitHub formats into one string (`format(...)`) that is
    true whenever it is not empty."""
    segmente = _vorlage(text)
    if not any(ist for ist, _t in segmente):
        return text
    if len(segmente) == 1:
        return segmente[0][1].strip()
    raise NichtLesbar("text stands beside a `${{ }}` expression, and GitHub formats the two into one "
                      "string, not the condition written")


def _name_einsetzen(name: str, kombination: dict[str, str]) -> str:
    """A job name with every `${{ matrix.<key> }}` replaced by the value of the combination."""
    teile = []
    for ist_ausdruck, text in _vorlage(name):
        if not ist_ausdruck:
            teile.append(text)
            continue
        m = _MATRIX_REF.fullmatch(text.strip())
        if not m or _ascii_klein(m.group(1)) not in kombination:
            raise NichtLesbar(f"the job name `{_einzeilig(name, 80)}` holds `${{{{{_einzeilig(text, 40)}}}}}`, "
                              f"which is no `matrix.<key>` of every combination")
        teile.append(kombination[_ascii_klein(m.group(1))])
    return "".join(teile)


def kontextnamen(job_id: str, job: dict, werte: dict[str, list]) -> list[str]:
    """The context names this job reports, after matrix expansion. Raises NichtLesbar for a form it does
    not read.

    Without a matrix the context is the job's `name:` or, lacking one, its id. With a matrix there is
    one name per combination (`_kombinationen`): a `name:` with its `${{ matrix.<key> }}` replaced, or
    the name or the id followed, in parentheses and comma-separated, by every value of the combination.

    EVERY VALUE, ONE NAME PER COMBINATION (lens on ac05d85d): the first form made one name per key and
    value and never read `include` or `exclude`, so `python: ['3.10']` beside `os: [ubuntu-latest]`, a
    `3.10` removed by `exclude`, and a `3.10` that `include` gave a second value each read as producing
    `test (3.10)`, with exit 0. The comma-separated form for several keys is the one that lens states;
    the docs read on 2026-09-26 do not document the default name of a matrix job (troubleshooting
    required status checks says `<job name>`), so for several keys it is neither read there nor
    measured here. For one key it is the form this repository's required contexts had (`test (3.10)`,
    measured 2026-09-16).
    """
    roh = job.get("name")
    if roh is not None and (isinstance(roh, bool) or not isinstance(roh, (str, int))):
        raise NichtLesbar(f"the job name is {type(roh).__name__}, not a text")
    name = None if roh is None else str(roh)
    strategie = job.get("strategy")
    m = strategie.get("matrix") if isinstance(strategie, dict) else None
    if m is None:
        if name is not None and "${{" in name:
            raise NichtLesbar(f"the job name `{_einzeilig(name, 80)}` holds an expression, and this gate "
                              f"evaluates none outside a matrix")
        return [name or job_id]
    if not isinstance(m, dict):
        raise NichtLesbar("the matrix is not a mapping of keys to values")
    namen = []
    for kombination in _kombinationen(m, werte):
        if name is not None and "${{" in name:
            namen.append(_name_einsetzen(name, kombination))
        else:
            namen.append(f"{name or job_id} ({', '.join(kombination.values())})")
    return namen


# --------------------------------------------------------------------------------------------
# THE TRIGGERS. A context is produced only on an event its workflow runs on, and the first form of
# this gate never read `on:` (lens on ac05d85d): a workflow with only `on: push` produced `guard` with
# exit 0, and the live step said it would arrive on a pull request. GitHub's docs say it plainly: a
# workflow skipped by its branch or path filter leaves its required checks "Pending", and the pull
# request is blocked (docs.github.com, workflow syntax, `branches` and `paths`, read 2026-09-26).
# --------------------------------------------------------------------------------------------

#: The events whose runs report checks on a pull request as a pull request.
_PR_EREIGNISSE = ("pull_request", "pull_request_target")
#: "By default, a workflow only runs when a pull_request event's activity type is opened, synchronize,
#: or reopened", and the same for pull_request_target (docs.github.com, events that trigger workflows,
#: read 2026-09-26). A `types` list without one of them leaves some head commit without a run.
_PR_STANDARDTYPEN = frozenset({"opened", "synchronize", "reopened"})
#: The characters that make a branch or tag filter a glob (docs.github.com, filter pattern cheat sheet,
#: read 2026-09-26: `*`, `**`, `+`, `?`, `!`, `[]`, and `\` to escape one). Such a filter is not matched.
_GLOB_ZEICHEN = frozenset("*?+[]!\\")
#: What the filter of each event may hold; a key outside it is not read. Any other event: `types`.
_FILTER = {
    "pull_request": {"types", "branches", "branches-ignore", "paths", "paths-ignore"},
    "pull_request_target": {"types", "branches", "branches-ignore", "paths", "paths-ignore"},
    "push": {"branches", "branches-ignore", "tags", "tags-ignore", "paths", "paths-ignore"},
    "merge_group": {"types", "branches", "branches-ignore"},
    "workflow_dispatch": {"inputs"},
    "workflow_call": {"inputs", "outputs", "secrets"},
}


def ausloeser(doc: dict) -> dict:
    """The events of a workflow's `on:`, each with its filter (None for none), in the three forms GitHub
    documents: one event, a list of events, a mapping of events to filters. Raises NichtLesbar for any
    other form and for a workflow without `on:`."""
    if "on" not in doc:
        raise NichtLesbar("the workflow has no `on:`, so no event is known to run it")
    roh = doc["on"]
    if isinstance(roh, str) and roh:
        return {roh: None}
    if isinstance(roh, list) and roh and all(isinstance(e, str) and e for e in roh):
        return {e: None for e in roh}
    if isinstance(roh, dict) and roh and all(isinstance(e, str) and e for e in roh):
        return dict(roh)
    raise NichtLesbar(f"`on:` is {_einzeilig(repr(roh), 60)}, not an event, a list or a mapping of events")


def _filter(ereignisse: dict, ereignis: str) -> dict:
    """The filter of one event as a mapping, its keys checked."""
    wert = ereignisse[ereignis]
    wo = f"on.{ereignis}"
    if wert is None:
        return {}
    if ereignis == "schedule" and isinstance(wert, list):
        return {}
    if not isinstance(wert, dict):
        raise NichtLesbar(f"`{wo}` is {type(wert).__name__}, not a mapping")
    fremd = sorted((str(k) for k in set(wert) - _FILTER.get(ereignis, {"types"})))
    if fremd:
        raise NichtLesbar(f"`{wo}` holds `{fremd[0]}`, which this gate does not read")
    for art in ("branches", "tags", "paths"):
        if art in wert and f"{art}-ignore" in wert:
            raise NichtLesbar(f"`{wo}` has both `{art}` and `{art}-ignore`, which GitHub refuses")
    return wert


def _liste(filter_: dict, schluessel: str, wo: str, woertlich: bool = True) -> list[str] | None:
    """A filter list, None when absent. With `woertlich`, only literal names are read, no glob."""
    if schluessel not in filter_:
        return None
    wert = filter_[schluessel]
    werte = [wert] if isinstance(wert, str) else wert
    if not isinstance(werte, list) or not werte or not all(isinstance(n, str) and n for n in werte):
        raise NichtLesbar(f"`{wo}.{schluessel}` is not a list of names")
    if woertlich:
        for n in werte:
            if any(z in _GLOB_ZEICHEN for z in n):
                raise NichtLesbar(f"`{wo}.{schluessel}` holds {n!r}, a pattern this gate does not match")
    return werte


def _laesst_zu(filter_: dict, art: str, name: str | None, wo: str, was: str) -> bool:
    """Does the `branches` (or `tags`) filter, or its `-ignore`, let `name` run the workflow? `was` says
    what the name is, for the reason when it is not known."""
    rein, raus = _liste(filter_, art, wo), _liste(filter_, f"{art}-ignore", wo)
    liste = rein if rein is not None else raus
    if liste is None:
        return True
    if not name:
        raise NichtLesbar(f"`{wo}` filters {art}, and {was} is not known")
    if name not in liste and any(n.casefold() == name.casefold() for n in liste):
        raise NichtLesbar(f"`{wo}` names {name!r} in another case, and whether GitHub matches it was not "
                          f"read")
    return (name in liste) == (rein is not None)


def _pr_lesung(ereignisse: dict, zweig: str | None) -> tuple[str, str | None]:
    """("immer", None) when a pull request event runs the workflow on every pull request into `zweig`
    (the declared branch); ("bedingt", the filter) when one runs it there only when a filter passes;
    ("nie", None) when none runs it there."""
    grenzen = []
    for ereignis in _PR_EREIGNISSE:
        if ereignis not in ereignisse:
            continue
        wo = f"on.{ereignis}"
        f = _filter(ereignisse, ereignis)
        if not _laesst_zu(f, "branches", zweig, wo, "the branch the declaration protects"):
            continue
        teile = []
        typen = _liste(f, "types", wo)
        if typen is not None and not _PR_STANDARDTYPEN <= set(typen):
            teile.append(f"`{wo}.types` {', '.join(typen)}")
        for art in ("paths", "paths-ignore"):
            pfade = _liste(f, art, wo, woertlich=False)
            if pfade is not None:
                teile.append(f"`{wo}.{art}` {', '.join(pfade)}")
        if not teile:
            return "immer", None
        grenzen.append("; ".join(teile))
    if grenzen:
        return "bedingt", " | ".join(grenzen)
    return "nie", None


def auf_pull_request(ereignisse: dict, zweig: str | None, datei: str) -> str | None:
    """None when the workflow runs on every pull request into the declared branch; otherwise the named
    condition under which its contexts reach one, for the report and the ratchet. Raises NichtLesbar."""
    art, grenze = _pr_lesung(ereignisse, zweig)
    if art == "immer":
        return None
    ziel = zweig or "the declared branch"
    if art == "bedingt":
        return f"`on:` of {datei} runs it on a pull request into {ziel} only when its filter passes: {grenze}"
    return (f"`on:` of {datei} runs it on no pull request into {ziel} (events: "
            f"{', '.join(sorted(ereignisse))}), so its checks reach one only from a run of another "
            f"event on the head commit")


def _push_laeuft(f: dict, ereignis: dict) -> bool:
    """Does `on: push` with filter `f` run on this push? "If you define only tags/tags-ignore or only
    branches/branches-ignore, the workflow won't run for events affecting the undefined Git ref"
    (docs.github.com, workflow syntax, read 2026-09-26)."""
    if any(k in f for k in ("paths", "paths-ignore")):
        raise NichtAuswertbar("`on.push` filters paths, and the event does not list the changed files")
    zweige = any(k in f for k in ("branches", "branches-ignore"))
    tags = any(k in f for k in ("tags", "tags-ignore"))
    if not (zweige or tags):
        return True
    art = ereignis.get("ref_type")
    if art not in ("branch", "tag"):
        raise NichtAuswertbar("`on.push` filters branches or tags, and the event does not say which it pushed")
    if art == "branch":
        return zweige and _laesst_zu(f, "branches", ereignis.get("ref_name"), "on.push", "the pushed branch")
    return tags and _laesst_zu(f, "tags", ereignis.get("ref_name"), "on.push", "the pushed tag")


def _push_lauf_auf_kopf(ereignisse: dict, ereignis: dict) -> bool:
    """On a pull request whose event does not run the workflow: can a run of its `on: push` carry the
    check? A required check is matched by name, whatever event made it ("Required status checks do not
    take workflow, matrix, or event trigger types into account", docs.github.com, troubleshooting
    rules, read 2026-09-26), and the head commit came by a push to the head branch of the head
    repository. False when that push cannot run it here; not decided when it may, since the event does
    not show that push run."""
    if "push" not in ereignisse:
        return False
    f = _filter(ereignisse, "push")
    if any(k in f for k in ("branches", "branches-ignore", "tags", "tags-ignore")):
        if not any(k in f for k in ("branches", "branches-ignore")):
            return False
        if not _laesst_zu(f, "branches", str(ereignis.get("head_ref") or ""), "on.push", "the head branch"):
            return False
    kopf, repo = _head_repo(ereignis), str(ereignis.get("repository") or "")
    if kopf and repo and _ascii_klein(kopf) != _ascii_klein(repo):
        return False                                   # a fork's push runs in the fork, not here
    raise NichtAuswertbar("its workflow does not run on this pull request event, and a run of its "
                          "`on: push` on the head commit may carry the check; the event does not show one")


def laeuft_am_ereignis(ereignisse: dict, ereignis: dict, zweig: str | None) -> bool:
    """Does a workflow with these `on:` events put its checks on the commit this live event judges?
    Raises NichtAuswertbar where that is not decided. On a pull request event its reading is the one
    of the survey (`_pr_lesung`), against the branch the declaration protects, since the required
    contexts bind a pull request only there."""
    name = str(ereignis.get("event_name") or "")
    try:
        if name in _PR_EREIGNISSE:
            art, grenze = _pr_lesung(ereignisse, zweig)
            if art == "immer":
                return True
            if art == "bedingt":
                raise NichtAuswertbar(f"its workflow runs on a pull request only when a filter passes "
                                      f"({grenze}), which the event does not show")
            return _push_lauf_auf_kopf(ereignisse, ereignis)
        if name not in ereignisse:
            return False
        f = _filter(ereignisse, name)
        if name == "push":
            return _push_laeuft(f, ereignis)
        if name == "merge_group":
            typen = _liste(f, "types", "on.merge_group")
            if typen is not None and "checks_requested" not in typen:
                return False
            return _laesst_zu(f, "branches", zweig, "on.merge_group", "the branch the declaration protects")
        if "types" in f:
            aktion = (ereignis.get("payload") or {}).get("action")
            if not isinstance(aktion, str):
                raise NichtAuswertbar(f"`on.{name}.types` filters the activity, and the event names none")
            return aktion in _liste(f, "types", f"on.{name}")
        return True
    except NichtLesbar as exc:
        raise NichtAuswertbar(str(exc)) from None


def _json_wert(wert):
    """A value read from a workflow as JSON holds it (keys as text)."""
    if isinstance(wert, dict):
        return {str(k): _json_wert(v) for k, v in wert.items()}
    if isinstance(wert, list):
        return [_json_wert(v) for v in wert]
    return wert if wert is None or isinstance(wert, (str, int, float, bool)) else str(wert)


def erhebe(verzeichnis: Path | None = None, zweig: str | None = None) -> dict:
    """Every context the workflows can report, with how it arises. `zweig` is the branch the declaration
    protects, against which a pull request trigger's branch filter is read; without it such a filter is
    not measurable."""
    wf = verzeichnis or WORKFLOWS
    gewoehnlich: dict[str, str] = {}
    quellen: dict[str, list[str]] = {}
    gegated: dict[str, tuple[str, str, str | None]] = {}
    unlesbar: list[str] = []
    dateien_unlesbar: list[str] = []
    hinweise: list[str] = []
    hinweise_status: list[str] = []
    needs_ohne_wache: dict[str, str] = {}
    ausloeser_je_datei: dict[str, dict] = {}
    # A condition the evaluator cannot read keeps the reading it had before 2026-09-26: a named
    # condition, its guard read from its spelling. That reading cannot tell a condition that is
    # false on every run from a live one, so the report says so instead of letting the context
    # stand as producible without a word (review of follow-up 236).
    unentschieden: list[str] = []
    for pfad in sorted(wf.glob("*.yml")) + sorted(wf.glob("*.yaml")):
        try:
            doc = _lade(pfad)
        except Exception as e:                          # noqa: BLE001
            unlesbar.append(f"{pfad.name}: {type(e).__name__}: {e}")
            # A FILE that could not be read is a different thing from a JOB with a known limit,
            # and the live judgement needs them apart: a context that is "absent" only because
            # its workflow file did not parse is NOT MEASURABLE, not "produced by nobody".
            # Measured 2026-09-17 by two lenses independently: with PyYAML missing, every
            # required context read as "WILL NOT ARRIVE, no workflow produces it", and the
            # advice pointed at the ruleset -- the one direction this gate exists to prevent.
            dateien_unlesbar.append(f"{pfad.name}: {type(e).__name__}: {e}")
            continue
        # THE TRIGGERS BEFORE ANY JOB: a workflow whose `on:` is not read produces nothing this gate
        # can name, so it is a file not read, and absence on the live event is not measurable.
        try:
            ereignisse = ausloeser(doc)
            nur_wenn = auf_pull_request(ereignisse, zweig, pfad.name)
        except NichtLesbar as exc:
            grund = f"{pfad.name}: `on:` not read: {exc}"
            unlesbar.append(grund)
            dateien_unlesbar.append(grund)
            continue
        ausloeser_je_datei[pfad.name] = _json_wert(ereignisse)

        def unbedingt(name: str, datei: str = pfad.name, nur_wenn: str | None = nur_wenn) -> None:
            """A context the job produces whenever it runs: produced, or named under the trigger."""
            if nur_wenn is None:
                gewoehnlich.setdefault(name, datei)
                if datei not in quellen.setdefault(name, []):
                    quellen[name].append(datei)
            elif name not in gewoehnlich:
                gegated.setdefault(name, (datei, nur_wenn, None))

        def bedingt(name: str, bed: str, datei: str = pfad.name, nur_wenn: str | None = nur_wenn) -> None:
            """A context the job produces under a condition of its own, and of the trigger if any."""
            if name not in gewoehnlich:
                gegated.setdefault(name, (datei, bed if nur_wenn is None else f"{nur_wenn}; and {bed}", bed))

        for job_id, job in (doc.get("jobs") or {}).items():
            if not isinstance(job, dict):
                continue
            if job.get("uses"):
                # A reusable workflow reports as "<caller job id> / <called job name>". Reading the
                # called file would give the wrong name on its own, so the caller id is carried.
                unlesbar.append(
                    f"{pfad.name}:{job_id}: calls a reusable workflow; its context is "
                    f"'{job_id} / <job name inside the called file>' and is not derived here")
                continue
            job_if = job.get("if")
            fremd = fremder_leerraum(str(job_if)) if job_if is not None else []
            if fremd:
                unlesbar.append(f"{pfad.name}:{job_id}: `if:` carries {', '.join(fremd)}, which Python reads "
                                f"as whitespace and GitHub's expression lexer does not")
                continue
            if job_if is not None:
                # `${{ always()` IS NOT A CONDITION (lens on ac05d85d): GitHub's template reader refuses
                # an expression that is not closed, and formats text beside one into a string. The
                # first form read the first as a status function and its job as produced.
                try:
                    _ein_ausdruck(" ".join(str(job_if).split()))
                except NichtLesbar as exc:
                    unlesbar.append(f"{pfad.name}:{job_id}: `if:` not read: {exc}")
                    continue
            gew, geg, bedingung, hinweis, gruende = matrix_lesung(job)
            if hinweis:
                hinweise.append(f"{pfad.name}:{job_id}: {hinweis}")
            if gruende:
                unlesbar.append(f"{pfad.name}:{job_id}: matrix values not readable literally "
                                f"({'; '.join(gruende)})")
                continue
            try:
                namen = kontextnamen(job_id, job, gew)
                namen_gegated = kontextnamen(job_id, job, geg) if bedingung else []
            except NichtLesbar as exc:
                unlesbar.append(f"{pfad.name}:{job_id}: {exc}")
                continue
            if bedingung:
                try:
                    wahrheitswerte(bedingung)
                except NichtAuswertbar as exc:
                    unentschieden.append(
                        f"{pfad.name}:{job_id}: whether its matrix condition has the same value on "
                        f"every event is not decided, so its false arm is read as the ordinary case "
                        f"and its true arm as produced under it. The evaluator did not read it "
                        f"({exc}): `{bedingung}`")
            # DIE `if:`-BEDINGUNG DES JOBS, und sie war bis 2026-09-16 ein blinder Fleck. Ein Job
            # hinter einem `if:` laeuft nicht immer, seine Kontexte sind also nicht unbedingt
            # erzeugt. Gefunden von einer fremden Modellfamilie in der Gegenlesung: ein
            # Pflicht-Job mit `if: false` wurde als `produced` gemeldet — ein STILLES
            # Falschurteil, nicht ein `not-measurable`. Dazu die Haerte dahinter: ein durch `if:`
            # uebersprungener Job meldet GitHub ein Success, ein Pflichtkontext auf ihm blockiert
            # also nie und beweist auch nichts.
            if job_if is not None and _NUR_STATUSFUNKTION.match(" ".join(str(job_if).split())):
                # `if: ${{ !cancelled() }}` or `if: always()` -- the job runs whenever the
                # workflow runs. Treated like no condition at all, and said so, because the
                # first draft of this gate would have called it `produced-only-if` and the
                # collector job would have been red from its first run for the wrong reason.
                hinweise_status.append(
                    f"{pfad.name}:{job_id}: `if: {' '.join(str(job_if).split())}` is a status "
                    f"function only; the job runs whenever the workflow runs")
                job_if = None
            if job.get("needs") and ohne_wache_trotz_needs(job):
                # EXPANDED like the produced path (lens A, 2026-09-17): with `{}` a matrix job
                # reported its bare id, the required context "test (3.10)" never matched, and
                # the trap was invisible exactly on a matrix job -- a silent green.
                for name in namen:
                    needs_ohne_wache.setdefault(
                        name, f"{pfad.name}:{job_id}: needs {list(job['needs']) if isinstance(job['needs'], list) else [job['needs']]} "
                              f"without a guard that runs it when a needed job failed (such as "
                              f"always(), !cancelled() or failure()) -- skipped when a needed job "
                              f"fails, and a skipped required check reads as passed")
            if job_if is not None:
                als_text = " ".join(str(job_if).split())
                # LITERAL `false` AND EVERY CONDITION THAT IS FALSE ON EVERY RUN (review of follow-up
                # 236): `!always()`, `always() && false`, `false && always()` never run their job
                # either. The evaluator decides it over every result of the status functions
                # (`always()` is true on every run) and every value of the event facts it reads.
                tot = _ascii_klein(als_text) in ("false", "${{ false }}")
                if not tot:
                    try:
                        tot = wahrheitswerte(als_text) == {False}
                    except NichtAuswertbar as exc:
                        unentschieden.append(
                            f"{pfad.name}:{job_id}: whether its `if:` can ever be true is not "
                            f"decided, so its contexts are named under it as a live condition"
                            + ("; whether it runs the job when a needed job failed was read from its "
                               "spelling" if job.get("needs") else "")
                            + f". The evaluator did not read it ({exc}): `if: {als_text}`")
                if tot:
                    hinweise.append(
                        f"{pfad.name}:{job_id}: `if: {als_text}` is false on every run — this job "
                        f"never runs, so its contexts arise under no condition")
                    continue
                for name in namen:
                    bedingt(name, f"job `if: {als_text}`")
                continue
            for name in namen:
                unbedingt(name)
            for name in namen_gegated:
                bedingt(name, bedingung)
    return {"gewoehnlich": gewoehnlich, "gegated": gegated, "unlesbar": unlesbar,
            "dateien_unlesbar": dateien_unlesbar, "hinweise": hinweise,
            "statusfunktion": hinweise_status, "needs_ohne_wache": needs_ohne_wache,
            "unentschieden": unentschieden, "quellen": quellen, "ausloeser": ausloeser_je_datei}


_HEX64 = re.compile(r"[0-9a-f]{64}")


def bedingungs_digest(text: str) -> str:
    """Der Digest EINER Bedingung, ueber genau der Form, die auch im Bericht steht.

    Normalisiert wird nur der Weissraum -- dieselbe Faltung, mit der die Bedingung gelesen und
    gedruckt wird. Waere hier eine zweite Normalisierung, haetten Bericht und Zusage zwei
    verschiedene Gegenstaende, und die Zusage bezoege sich auf etwas, das niemand sieht.
    """
    return hashlib.sha256(" ".join((text or "").split()).encode("utf-8")).hexdigest()


def _zusagen(roh, feld: str = "condition_sha256") -> tuple[dict[str, str], list[str]]:
    """Liest eine Zusagenliste. Gibt die BINDENDEN Zusagen und die unverbindlichen Eintraege.

    Bindend ist nur ein Eintrag der Form {"context": ..., <feld>: <64 hex>}. Eine nackte
    Zeichenkette ist die alte, namensgebundene Form; sie wird NICHT als Zusage gezaehlt, sondern
    beim Namen genannt, damit ihr Weiterleben auffaellt statt zu wirken.

    DAS FELD IST EIN PARAMETER, WEIL ES ZWEI ZUSAGEARTEN GIBT, und genau das war der naechste
    Fund. `accepted_gated` wurde am 2026-09-16 von der Namensbindung auf `condition_sha256`
    umgestellt -- und `accepted_unreadable` blieb eine nackte Praefixliste. Eine dritte Linse
    baute den Fall am selben Tag und mass ihn: derselbe Job wechselte von "ruft einen
    wiederverwendbaren Workflow" auf "Matrix nicht woertlich lesbar", zwei verschiedene
    Unmessbarkeiten mit demselben Praefix, und das Tor blieb still gruen. Ein Instanz-Fix, der
    den Nachbarn stehen laesst, verschiebt die Luecke nur.
    """
    bindend: dict[str, str] = {}
    lose: list[str] = []
    for eintrag in roh or []:
        if isinstance(eintrag, str):
            lose.append(eintrag)
            continue
        if not isinstance(eintrag, dict):
            lose.append(repr(eintrag))
            continue
        name, digest = eintrag.get("context"), eintrag.get(feld)
        if not name or not isinstance(digest, str) or not _HEX64.fullmatch(digest):
            lose.append(str(name or eintrag))
            continue
        bindend[name] = digest
    return bindend, lose


def pruefe(declaration: Path | None = None, verzeichnis: Path | None = None) -> dict:
    d = declaration or DECLARATION
    if not d.is_file():
        return {"verdict": UNKNOWN, "reason": f"{d} is missing; nothing declares what is required"}
    erklaert = json.loads(d.read_text(encoding="utf-8"))
    verlangt = list(erklaert.get("required_contexts") or [])
    if not verlangt:
        return {"verdict": UNKNOWN, "reason": f"{d.name} declares no required context"}
    zweig = erklaert.get("branch") if isinstance(erklaert.get("branch"), str) else None
    erhoben = erhebe(verzeichnis, zweig)
    je: list[dict] = []
    for k in verlangt:
        if k in erhoben["gewoehnlich"]:
            e = {"context": k, "state": ALWAYS, "from": erhoben["gewoehnlich"][k]}
            quellen = erhoben.get("quellen", {}).get(k) or []
            if len(quellen) > 1:
                e["sources"] = quellen
            je.append(e)
        elif k in erhoben["gegated"]:
            datei, bed, ausdruck = erhoben["gegated"][k]
            e = {"context": k, "state": GATED, "from": datei, "condition": bed}
            if ausdruck != bed:
                # The condition names the trigger too; the live step evaluates the trigger from the
                # workflow's `on:` and only this part as an expression (None: the trigger alone).
                e["expression"] = ausdruck
            je.append(e)
        else:
            je.append({"context": k, "state": ABSENT, "from": None})
    zahl = {ALWAYS: 0, GATED: 0, ABSENT: 0}
    for e in je:
        zahl[e["state"]] += 1
    verdict = ABSENT if zahl[ABSENT] else (GATED if zahl[GATED] else ALWAYS)
    # A REQUIRED context on a job that is skipped when its needs fail. It is produced, so it is
    # not absent; it is not conditional on the event, so it is not gated. It is worse than both
    # for its purpose: skipped reads as passed, so it never blocks on exactly the failures it
    # depends on. Named per context, and it turns the exit red below.
    ohne_wache = [{"context": k, "why": erhoben["needs_ohne_wache"][k]}
                  for k in verlangt if k in erhoben["needs_ohne_wache"]]
    # DIE ZUSAGE HAENGT AN DER BEDINGUNG, NICHT AM NAMEN. Die erste Fassung fuehrte
    # `accepted_gated` als blosse Namensliste, und zwei unabhaengige Gegenleser fanden am
    # 2026-09-16 dieselbe Luecke: ein Name, der einmal dort steht, ist dauerhaft immun. Ein
    # Kontext, der heute UNBEDINGT laeuft und morgen hinter einem `if:` verschwindet, rutschte
    # durch, solange sein Name schon gelistet war; und eine Bedingung durfte beliebig ENGER
    # werden -- von "Label landung" auf "Label landung UND ein nie gesetztes zweites Label" --
    # ohne dass sich etwas am Urteil aenderte. Beides ist genau die Verschlechterung, die diese
    # Sohle fangen soll, also bindet die Zusage jetzt an den Digest der normalisierten Bedingung.
    # Ein Eintrag ohne diesen Digest zaehlt NICHT als Zusage: fail closed, damit eine veraltete
    # Erklaerungsform nicht als Freibrief weiterlebt.
    hingenommen, unverbindlich = _zusagen(erklaert.get("accepted_gated"))
    hingenommen_unlesbar, unverbindlich_unlesbar = _zusagen(
        erklaert.get("accepted_unreadable"), "reason_sha256")
    neu_gegated, geaenderte_bedingung = [], []
    for e in je:
        if e["state"] != GATED:
            continue
        ist = bedingungs_digest(e.get("condition") or "")
        e["condition_sha256"] = ist
        soll = hingenommen.get(e["context"])
        if soll == ist:
            continue
        neu_gegated.append(e["context"])
        if soll is not None:
            geaenderte_bedingung.append({"context": e["context"], "declared": soll, "measured": ist})
    neu_gegated.sort()
    # DER GRUND, NICHT DER PRAEFIX. Wer eine Unmessbarkeit hinnimmt, nimmt EINE hin -- die, die
    # er gelesen hat. Derselbe Job kann morgen aus einem anderen Grund unlesbar sein, und dieser
    # Grund ist dann NICHT zugesagt. Gemessen (Linse 3, 2026-09-16): Wechsel von "calls a
    # reusable workflow" auf "matrix values not readable literally" -- gleicher Praefix, exit 0,
    # `newly_unreadable` leer.
    neu_unlesbar, geaenderter_grund = [], []
    for u in erhoben["unlesbar"]:
        soll, grund = None, None
        for name, dig in hingenommen_unlesbar.items():
            if u == name or u.startswith(f"{name}:"):
                soll, grund = dig, u[len(name):].lstrip(": ")
                break
        ist = bedingungs_digest(grund or "")
        if soll is not None and soll == ist:
            continue
        neu_unlesbar.append(u)
        if soll is not None:
            geaenderter_grund.append({"context": name, "declared": soll, "measured": ist})
    return {"verdict": verdict, "per_context": je, "counts": zahl,
            "accepted_gated": sorted(hingenommen), "newly_gated": neu_gegated,
            "changed_conditions": geaenderte_bedingung,
            "unbound_acceptances": sorted(unverbindlich),
            "newly_unreadable": neu_unlesbar, "changed_reasons": geaenderter_grund,
            "unbound_unreadable_acceptances": sorted(unverbindlich_unlesbar),
            "unreadable": erhoben["unlesbar"], "unreadable_files": erhoben["dateien_unlesbar"],
            "dead_conditions": erhoben["hinweise"],
            "status_function_conditions": erhoben["statusfunktion"],
            "undecided_conditions": erhoben["unentschieden"],
            "skipped_reads_as_passed": ohne_wache,
            "produced_contexts": sorted(erhoben["gewoehnlich"]),
            "triggers": erhoben.get("ausloeser", {}),
            "ruleset": erklaert.get("ruleset"), "branch": erklaert.get("branch")}


def erklaerung_gegen_regelsatz(declaration: Path | None = None, repo: str | None = None) -> dict:
    """Stimmt die ERKLAERUNG mit dem Regelsatz ueberein, den GitHub wirklich fuehrt?

    Die Erklaerung in `.github/required_status_checks.json` ist eine Kopie, und eine Kopie driftet.
    Wer den Regelsatz aendert und die Datei vergisst, bekommt vom Offline-Tor weiter ein Urteil, das
    sich auf gestrige Pflichten bezieht: alles gruen, gemessen an der falschen Menge. Diese Funktion
    holt die Wahrheit und vergleicht.

    SIE BRAUCHT DAS NETZ und ist deshalb ausdruecklich KEIN Teil des Offline-Tors. Ein Aufruf ohne
    Netz gibt `not-measurable` mit Grund zurueck, nie ein stilles Bestehen: ein Vergleich, der nicht
    stattfand, ist kein Vergleich.
    """
    d = declaration or DECLARATION
    if not d.is_file():
        return {"verdict": UNKNOWN, "reason": f"{d} is missing; there is nothing to compare"}
    erklaert = json.loads(d.read_text(encoding="utf-8"))
    rs_id = erklaert.get("ruleset_id")
    ziel = repo or erklaert.get("repo") or "b7n0de/proofbundle"
    if not rs_id:
        return {"verdict": UNKNOWN, "reason": f"{d.name} names no ruleset_id to compare against"}
    import subprocess  # noqa: PLC0415 - nur auf diesem, netzabhaengigen Pfad
    try:
        r = subprocess.run(["gh", "api", f"repos/{ziel}/rulesets/{rs_id}"],
                           capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError) as e:
        return {"verdict": UNKNOWN, "reason": f"gh could not be run ({type(e).__name__})"}
    if r.returncode != 0:
        return {"verdict": UNKNOWN,
                "reason": f"gh api exited {r.returncode}: {r.stderr.strip()[:200]}"}
    try:
        doc = json.loads(r.stdout)
    except json.JSONDecodeError as e:
        return {"verdict": UNKNOWN, "reason": f"the ruleset did not parse as JSON ({e})"}
    echt: list[str] = []
    for regel in doc.get("rules") or []:
        if regel.get("type") == "required_status_checks":
            echt = [c.get("context") for c
                    in (regel.get("parameters") or {}).get("required_status_checks") or []]
    erklaert_menge = set(erklaert.get("required_contexts") or [])
    echt_menge = set(echt)
    return {
        "verdict": ALWAYS if erklaert_menge == echt_menge else ABSENT,
        "ruleset": doc.get("name"), "ruleset_id": rs_id, "repo": ziel,
        "declared_only": sorted(erklaert_menge - echt_menge),
        "ruleset_only": sorted(echt_menge - erklaert_menge),
        "in_both": sorted(erklaert_menge & echt_menge),
    }


def _erklaerungs_digest(pfad: Path | None) -> str:
    """Der Digest der Erklaerungsdatei, an die ein Markerurteil gebunden wird.

    Ein Marker sagt sonst nur, DASS einmal geprueft wurde, nie WORAN. Drei Angriffe gelangen am
    2026-09-16 gegen die erste Fassung: ein Marker von 2020 meldete "checked"; einer ohne
    Zeitpunkt ebenso; einer mit fremdem Regelsatz wurde unbesehen zitiert. Alle drei fielen unter
    dieselbe Luecke - gebunden war die EXISTENZ der Datei, nicht der gepruefte ZUSTAND. Dieselbe
    Klasse wie die Namensbindung in `accepted_gated`, nur eine Ebene hoeher.
    """
    p = pfad or (Path(__file__).resolve().parents[1] / ".github" / "required_status_checks.json")
    try:
        return hashlib.sha256(Path(p).read_bytes()).hexdigest()
    except OSError:
        return ""


def _jetzt() -> str:
    from datetime import datetime, timezone  # noqa: PLC0415
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def drift_lage(marker: str | None, erklaerung: Path | None = None) -> dict:
    """Was der Netz-Lauf hinterlassen hat — oder dass er nichts hinterlassen hat.

    VIER ZUSTAENDE, und nur der erste ist eine bestandene Pruefung: `ran` (ein Urteil, das an
    GENAU DIESE Erklaerung gebunden ist), `stale` (ein Urteil ueber eine andere oder ungenannte
    Erklaerung), `unreadable` (Datei da, aber ohne Urteil oder ohne Zeitpunkt) und `absent`
    (nichts da). `absent` heisst NICHT `in Ordnung`: es heisst, dass dieser Lauf nichts darueber
    weiss, ob die Erklaerung noch zum Regelsatz passt.

    `stale` kam dazu, weil die erste Fassung an die EXISTENZ des Markers band statt an den
    geprueften ZUSTAND. Drei Angriffe gingen dagegen durch; sie stehen als Faelle in
    `TestTheOfflineRunSaysWhetherTheDriftCheckRan`.
    """
    if not marker:
        return {"state": "absent", "why": "no marker requested"}
    p = Path(marker)
    if not p.is_file():
        return {"state": "absent", "why": f"{marker} does not exist"}
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return {"state": "unreadable", "why": f"{marker}: {exc}"}
    # FORM VOR INHALT. Der Marker ist eine Datei, die jemand anders geschrieben hat; seine Felder
    # sind Eingabewerte, keine Zusicherungen. Gemessen 2026-09-16 (Linse 1): ein Marker mit
    # `"declaration_sha256": 123456` liess `war[:12]` mit `TypeError` abstuerzen -- MITTEN im
    # Bericht, nach den richtigen Zeilen, ohne Urteil fuer den Rest. Ein Werkzeug, das an seiner
    # Eingabe abstuerzt, urteilt nicht.
    if not isinstance(d, dict) or not isinstance(d.get("verdict"), str) or not d["verdict"].strip():
        return {"state": "unreadable", "why": f"{marker}: no verdict in the marker"}
    if not isinstance(d.get("at"), str) or not d["at"].strip():
        return {"state": "unreadable", "why": f"{marker}: no timestamp in the marker — without "
                                              "one, a run that happened cannot be told from one "
                                              "that never did"}
    ist = _erklaerungs_digest(erklaerung)
    war = d.get("declaration_sha256")
    if war is not None and not isinstance(war, str):
        return {"state": "unreadable",
                "why": f"{marker}: declaration_sha256 is {type(war).__name__}, not text"}
    if not war:
        return {"state": "stale", "verdict": d["verdict"], "at": d.get("at"),
                "why": "the marker does not say WHICH declaration was checked"}
    if not ist:
        # NICHT LESBAR IST NICHT GEBUNDEN. Waere hier ein Durchlass, koennte die Bindung
        # abgeschaltet werden, indem man die Erklaerung unlesbar macht - die unmessbare Seite
        # wuerde still zur bestandenen. Genau die Verwechslung, gegen die dieses Tor gebaut ist.
        return {"state": "stale", "verdict": d["verdict"], "at": d.get("at"),
                "why": "the declaration is not readable here, so the binding cannot be checked"}
    if war != ist:
        return {"state": "stale", "verdict": d["verdict"], "at": d.get("at"),
                "why": f"checked was {_kurz(war, 12)}\u2026, present here is {_kurz(ist, 12)}\u2026 — the "
                       "declaration changed after the check"}
    return {"state": "ran", "verdict": d["verdict"], "at": d.get("at"),
            "ruleset": d.get("ruleset"), "reason": d.get("reason")}


def _einzeilig(text: object, grenze: int = 160) -> str:
    """Ein Grund, der ueber Zeilen laeuft, zerschneidet den einzeiligen Bericht.

    GEMESSEN 2026-09-16 am eigenen Marker: die Fehlermeldung von `gh` traegt einen Zeilenumbruch,
    und die Berichtszeile brach mitten im Satz ab — der Leser sah die halbe Begruendung und hielt
    sie fuer die ganze. Gefaltet und gekappt, mit sichtbarer Kappmarke.

    ZWEITE RUNDE, und sie ist der eigentliche Punkt: die erste Fassung faltete NUR den Grund. Eine
    adversariale Linse legte am selben Tag einen Marker vor, dessen `ruleset` einen Zeilenumbruch
    trug — und erzeugte damit im Bericht zwei zusaetzliche Zeilen, die exakt wie echte Ausgabe des
    Werkzeugs aussahen, inklusive einer zweiten, erfundenen Kopfzeile mit dem Urteil `produced`.
    Ein Feld aus einer fremden Datei ist ein EINGABEWERT, kein Text. Seitdem laeuft JEDER Wert,
    der in eine Berichtszeile geht, hier durch; `str.split()` faengt Zeilenumbruch, Tabulator und
    Wagenruecklauf, aber KEIN NUL und keine anderen Steuerzeichen, darum die zweite Faltung.
    """
    roh = "".join(ch if ch.isprintable() or ch.isspace() else " " for ch in str(text))
    eins = " ".join(roh.split())
    return eins if len(eins) <= grenze else eins[: grenze - 1] + "\u2026"


def _kurz(wert: object, n: int) -> str:
    """Die ersten n Zeichen eines Feldes — als TEXT, nicht als Scheibe eines unbekannten Typs.

    `war[:12]` auf einer Zahl wirft `TypeError: 'int' object is not subscriptable`, und zwar
    mitten im Bericht: die Zeilen davor stehen da, alles danach fehlt, und der Ausgang ist ein
    Traceback statt eines Urteils. Gemessen 2026-09-16 an einem Marker mit
    `"declaration_sha256": 123456`. Ein Werkzeug, das an seiner Eingabe abstuerzt, urteilt nicht.

    ES IST EIN SCHNITT, KEINE KAPPUNG: `_einzeilig(x, n)` setzt eine Kappmarke INNERHALB der n
    Zeichen und liefert damit elf Zeichen plus `\u2026`, wo zwoelf erwartet werden. Der erste
    Anlauf tat genau das und machte aus `190648ee09c0` ein `190648ee09c\u2026`; der Vertrag, der
    den gemessenen Digest in der Zeile sucht, fiel zu Recht.
    """
    return _einzeilig(wert, 10 ** 9)[:n]


def _drift_zeile(marker: str | None, erklaerung: Path | None = None) -> str:
    """DIE ZEILE SAGT NICHT MEHR, ALS SIE WEISS.

    'ran' war die erste Fassung fuer JEDEN abgelegten Marker — auch fuer einen, dessen Lauf gar
    nichts messen konnte. Gemessen 2026-09-16 ohne Token: der Marker trug `not-measurable`, die
    Zeile begann trotzdem mit 'ran at ...', und wer nur den Zeilenanfang liest, haelt die
    Drift-Pruefung fuer erledigt. Das ist dieselbe Verwechslung, gegen die dieses ganze Tor steht:
    GELAUFEN ist nicht GEMESSEN. Ein Lauf ohne Messung wird darum als NOT MEASURABLE gefuehrt und
    nennt die Zeit trotzdem, damit sichtbar bleibt, dass es einen Versuch gab.
    """
    lage = drift_lage(marker, erklaerung)
    # KEIN ROHER WERT IN DIE ZEILE. Jedes Feld kommt aus einer Datei, die jemand anders geschrieben
    # hat; roh gedruckt faelscht ein Zeilenumbruch darin ganze Berichtszeilen (siehe _einzeilig).
    zeit = _einzeilig(lage.get("at"), 64)
    satz = _einzeilig(lage.get("ruleset"), 64)
    if lage["state"] == "ran":
        v = _einzeilig(lage["verdict"], 48)
        grund = f" ({_einzeilig(lage['reason'])})" if lage.get("reason") else ""
        if v == ALWAYS:
            return (f"drift-check        checked at {zeit}: declaration matches the live "
                    f"ruleset {satz}{grund}")
        if v == UNKNOWN:
            return (f"drift-check        NOT MEASURABLE — a run at {zeit} could not "
                    f"reach the live ruleset{grund}")
        return (f"drift-check        DRIFT — checked at {zeit} against ruleset "
                f"{satz}: {v}{grund}")
    if lage["state"] == "stale":
        return (f"drift-check        STALE — a run at {zeit} said "
                f"{_einzeilig(lage.get('verdict'), 48)}, but {_einzeilig(lage['why'])}")
    if lage["state"] == "unreadable":
        return f"drift-check        NOT MEASURABLE — {_einzeilig(lage['why'])}"
    return ("drift-check        NOT RUN — this verdict rests on a declaration that may have "
            f"drifted from the live ruleset ({_einzeilig(lage['why'])})")


# --------------------------------------------------------------------------------------------
# THE LIVE PULL REQUEST. Everything above answers "CAN the workflows produce this context under
# some named condition?", and the ratchet accepts the four version contexts behind their five-branch
# condition. On a pull request that is the wrong question. Measured 2026-09-17 on pull request
# 218: this gate reported green, the `landung` label was absent, and test (3.10), (3.11), (3.13)
# and (3.14) were never going to arrive -- the pull request stood BLOCKED with nothing red on it,
# which is the exact picture this file was written against. A guard that judges the structure
# while the instance in front of it is blocked has not caught its class at the live instance.
#
# So the live question is asked separately: does THIS event -- its name, its labels, its head ref,
# its head repository -- make each condition TRUE? The runner hands all of that over in its own
# variables (GITHUB_EVENT_NAME, GITHUB_EVENT_PATH, GITHUB_HEAD_REF, GITHUB_REF_NAME,
# GITHUB_REPOSITORY), so no network is needed. The evaluator understands exactly the atoms this
# repository's conditions use; anything else is NOT MEASURABLE, and NOT MEASURABLE is never a pass.
# GitHub compares strings case-insensitively in `==`, `contains` and `startsWith`, and so does this.
# --------------------------------------------------------------------------------------------

ARRIVES = "arrives"
WILL_NOT_ARRIVE = "will-not-arrive"


class NichtAuswertbar(Exception):
    """A condition fragment this evaluator does not understand. Reported, never guessed."""


def ereignis_aus_umgebung(env=None) -> dict | None:
    """The event of THIS run, from the runner's own variables. None when not under Actions."""
    env = os.environ if env is None else env
    name = (env.get("GITHUB_EVENT_NAME") or "").strip()
    pfad = (env.get("GITHUB_EVENT_PATH") or "").strip()
    if not name or not pfad:
        return None
    ereignis = {"event_name": name, "repository": env.get("GITHUB_REPOSITORY") or "",
                "head_ref": env.get("GITHUB_HEAD_REF") or "", "ref_name": env.get("GITHUB_REF_NAME") or "",
                # branch or tag: a push filter on one of them does not run the workflow for the other
                "ref_type": env.get("GITHUB_REF_TYPE") or ""}
    try:
        nutzlast = json.loads(Path(pfad).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        ereignis["fehler"] = f"{pfad}: {type(exc).__name__}: {exc}"
        return ereignis
    ereignis["payload"] = nutzlast if isinstance(nutzlast, dict) else {}
    return ereignis


def _labels(ereignis: dict) -> list[str]:
    pr = ((ereignis.get("payload") or {}).get("pull_request")) or {}
    aus = []
    for e in pr.get("labels") or []:
        if isinstance(e, dict) and isinstance(e.get("name"), str):
            aus.append(e["name"])
    return aus


def _head_repo(ereignis: dict) -> str:
    pr = ((ereignis.get("payload") or {}).get("pull_request")) or {}
    return str((((pr.get("head") or {}).get("repo")) or {}).get("full_name") or "")


def _faltungen(text: str) -> set:
    return {text.casefold(), text.lower(), text.upper()}


def _gleich_ohne_fall(a: str, b: str) -> bool:
    """`==` of two texts in a GitHub expression, which ignores case. Equal in ASCII case: equal. Equal
    only under a Unicode case mapping: not measurable, since GitHub compares OrdinalIgnoreCase in .NET
    and how that maps a letter outside ASCII (the Kelvin sign, the long s, the dotless i) was not read;
    Python's `.lower()` makes the Kelvin sign a `k` (lens on ac05d85d, F4). Otherwise: not equal."""
    if _ascii_klein(a) == _ascii_klein(b):
        return True
    if _faltungen(a) & _faltungen(b):
        raise NichtAuswertbar(f"{_einzeilig(repr(a), 40)} and {_einzeilig(repr(b), 40)} are equal only "
                              f"under a case mapping of letters outside ASCII, which GitHub's was not read")
    return False


def _beginnt_ohne_fall(text: str, anfang: str) -> bool:
    """`startsWith` as GitHub reads it, ignoring case, with the same three answers as `_gleich_ohne_fall`."""
    if _ascii_klein(text).startswith(_ascii_klein(anfang)):
        return True
    if any(f(text).startswith(f(anfang)) for f in (str.casefold, str.lower, str.upper)):
        raise NichtAuswertbar(f"{_einzeilig(repr(text), 40)} starts with {_einzeilig(repr(anfang), 40)} "
                              f"only under a case mapping of letters outside ASCII, which GitHub's was not read")
    return False


def _enthaelt_ohne_fall(namen: list, name: str) -> bool:
    """`contains` over a list of texts as GitHub reads it: an element equal to `name`, ignoring case."""
    offen = None
    for n in namen:
        try:
            if _gleich_ohne_fall(n, name):
                return True
        except NichtAuswertbar as exc:
            offen = exc
    if offen is not None:
        raise offen
    return False


def _vor_dem_lauf_offen(m, ev):
    raise NichtAuswertbar(f"`{m.group(0)}` depends on how the needed jobs end, which no event says "
                          f"before they run")


#: The atoms: (pattern, kind, is a comparison, value on a live event). The KIND says what an atom
#: depends on, and the enumeration in `wahrheitswerte` varies exactly that:
#:   "ereignis"  a fact of the event: its name, a label, the head ref, the head repository;
#:   "status"    `success()`, `failure()`, `cancelled()`: how the needed jobs ended;
#:   "immer"     `always()`, true on every run, a cancelled one included (GitHub's documentation);
#:   "literal"   `true` and `false`.
#: A COMPARISON may not stand right after a `!`: GitHub's `!` binds tighter than `==` (precedence
#: 16 against 10 in actions/runner, src/Sdk/DTExpressions2/Expressions2/Tokens/Token.cs, read
#: 2026-09-26), so `!github.event_name == 'push'` compares the negated name, and reading it as the
#: negated comparison would be another expression. Such a text is not measurable.
#: The status functions as GitHub documents them (expressions reference, read 2026-09-26): a
#: condition without one gets `success()` prepended, and `always()` is true even on a cancelled run.
#: On a live event `cancelled()` is false for a run that is judging itself, and `success()` and
#: `failure()` are not measurable: the event does not say how the needed jobs will end.
_ATOME = [
    (re.compile(r"github\.event_name\s*(==|!=)\s*'([^']*)'"), "ereignis", True,
     lambda m, ev: _gleich_ohne_fall(ev["event_name"], m.group(2)) == (m.group(1) == "==")),
    (re.compile(r"startsWith\(\s*github\.head_ref\s*,\s*'([^']*)'\s*\)"), "ereignis", False,
     lambda m, ev: _beginnt_ohne_fall(ev.get("head_ref", ""), m.group(1))),
    (re.compile(r"startsWith\(\s*github\.ref_name\s*,\s*'([^']*)'\s*\)"), "ereignis", False,
     lambda m, ev: _beginnt_ohne_fall(ev.get("ref_name", ""), m.group(1))),
    (re.compile(r"contains\(\s*github\.event\.pull_request\.labels\.\*\.name\s*,\s*'([^']*)'\s*\)"),
     "ereignis", False, lambda m, ev: _enthaelt_ohne_fall(_labels(ev), m.group(1))),
    (re.compile(r"github\.event\.pull_request\.head\.repo\.full_name\s*==\s*github\.repository"),
     "ereignis", True,
     lambda m, ev: bool(_head_repo(ev)) and _gleich_ohne_fall(_head_repo(ev), str(ev.get("repository", "")))),
    (re.compile(r"true\b"), "literal", False, lambda m, ev: True),
    (re.compile(r"false\b"), "literal", False, lambda m, ev: False),
    (re.compile(r"[aA][lL][wW][aA][yY][sS]\(\s*\)"), "immer", False, lambda m, ev: True),
    (re.compile(r"[cC][aA][nN][cC][eE][lL][lL][eE][dD]\(\s*\)"), "status", False, lambda m, ev: False),
    (re.compile(r"[sS][uU][cC][cC][eE][sS][sS]\(\s*\)"), "status", False, _vor_dem_lauf_offen),
    (re.compile(r"[fF][aA][iI][lL][uU][rR][eE]\(\s*\)"), "status", False, _vor_dem_lauf_offen),
]
#: `!` is a unary operator; `!=` belongs to a comparison atom and is never one.
_ZEICHEN = re.compile(r"\s*(\(|\)|&&|\|\||!(?!=))")


def _ausdruck(text: str) -> str:
    """The expression of a condition as the evaluator reads it: a character Python reads as
    whitespace and GitHub does not is refused FIRST, before anything is folded or any pattern reads
    the text; then the whitespace is folded, `job \\`if: ...\\`` around it is taken off, and `${{ }}`
    is read as GitHub's template reader reads it (`_ein_ausdruck`): one expression around the whole
    is taken off, one not closed or text beside one is not measurable."""
    text = text or ""
    fremd = fremder_leerraum(text)
    if fremd:
        raise NichtAuswertbar(f"the condition carries {', '.join(fremd)}, which Python reads as "
                              f"whitespace and GitHub's expression lexer does not")
    if text.startswith("job `if: ") and text.endswith("`"):
        text = text[len("job `if: "):-1]
    try:
        return _ein_ausdruck(" ".join(text.split()))
    except NichtLesbar as exc:
        raise NichtAuswertbar(str(exc)) from None


def _tokens(text: str) -> list:
    """Tokens: '(', ')', '&&', '||', '!' and atoms as (index into _ATOME, match). Unknown text
    raises."""
    aus: list = []
    i, n = 0, len(text)
    while i < n:
        while i < n and text[i].isspace():
            i += 1
        if i >= n:
            break
        z = _ZEICHEN.match(text, i)
        if z:
            aus.append(z.group(1))
            i = z.end()
            continue
        for index, (muster, _art, _vergleich, _wert) in enumerate(_ATOME):
            m = muster.match(text, i)
            if m:
                aus.append((index, m))
                i = m.end()
                break
        else:
            raise NichtAuswertbar(f"cannot evaluate: {_einzeilig(text[i:i + 60], 60)}")
    return aus


def _werte(t: list, wert) -> bool:
    """Parse the tokens and evaluate them, `wert(atom)` giving each atom's value. `!` binds tighter
    than `&&`, and `&&` tighter than `||`. Both sides of an operator are always evaluated, so an
    atom that is not measurable is never skipped by a short circuit."""
    pos = 0

    def ausdruck() -> bool:
        nonlocal pos
        w = glied()
        while pos < len(t) and t[pos] == "||":
            pos += 1
            rechts = glied()
            w = w or rechts
        return w

    def glied() -> bool:
        nonlocal pos
        w = faktor()
        while pos < len(t) and t[pos] == "&&":
            pos += 1
            rechts = faktor()
            w = w and rechts
        return w

    def faktor() -> bool:
        nonlocal pos
        if pos >= len(t):
            raise NichtAuswertbar("condition ends where an operand was expected")
        tok = t[pos]
        if tok == "!":
            pos += 1
            if pos < len(t) and isinstance(t[pos], tuple) and _ATOME[t[pos][0]][2]:
                raise NichtAuswertbar("a `!` right before a comparison negates its left operand in "
                                      "GitHub's grammar, not the comparison")
            return not faktor()
        if tok == "(":
            pos += 1
            w = ausdruck()
            if pos >= len(t) or t[pos] != ")":
                raise NichtAuswertbar("unbalanced parenthesis in the condition")
            pos += 1
            return w
        if isinstance(tok, tuple):
            pos += 1
            return bool(wert(tok))
        raise NichtAuswertbar(f"unexpected token {tok!r} in the condition")

    if not t:
        raise NichtAuswertbar("empty condition")
    w = ausdruck()
    if pos != len(t):
        raise NichtAuswertbar("trailing text in the condition")
    return w


def _schluessel(tok: tuple):
    """What an atom's value depends on, as a key of the enumeration; None for a constant.

    Folded in ASCII only, like the atom patterns (lens on ac05d85d, F4): two atoms get one key only
    when GitHub reads them as the same fact. With `.lower()`, `faılure()` had its own key beside
    `failure()`, so `failure() && !faılure()` read as satisfiable and as a guard. A text that differs
    outside ASCII keeps its own key, which can only widen the values enumerated, never narrow them."""
    index, m = tok
    art = _ATOME[index][1]
    if art == "ereignis":
        return ("ereignis", _ascii_klein(m.group(0)))
    if art == "status":
        return ("status", _ascii_klein("".join(m.group(0).split())))
    return None


#: How many free atoms `wahrheitswerte` enumerates: 2**12 evaluations at most. A condition with
#: more is not decided, and the report says so, rather than the enumeration being cut short.
_HOECHSTENS_FREI = 12
#: A needed job failed and the run was not cancelled: `success()` is false, `failure()` true.
_FEHLSCHLAG = {("status", "success()"): False, ("status", "failure()"): True,
               ("status", "cancelled()"): False}


def wahrheitswerte(text: str, fest: dict | None = None) -> set:
    """Every value a condition takes over every combination of what its atoms depend on.

    Each event fact and each status function is varied freely, as if independent: that includes
    combinations no run can have (`success()` and `failure()` both true, `event_name` equal to
    two names), so `{False}` means false on every run the gate knows, and a condition that is
    false only by such a combination stays a live one. `always()` is true on every run, `true`
    and `false` are themselves. `fest` pins some keys (see `_FEHLSCHLAG`). Raises NichtAuswertbar
    for a text the evaluator cannot read and for more than `_HOECHSTENS_FREI` free atoms.
    """
    t = _tokens(_ausdruck(text))
    fest = dict(fest or {})
    frei: list = []
    for tok in t:
        if isinstance(tok, tuple):
            k = _schluessel(tok)
            if k is not None and k not in fest and k not in frei:
                frei.append(k)
    if len(frei) > _HOECHSTENS_FREI:
        raise NichtAuswertbar(f"{len(frei)} free atoms, more than the {_HOECHSTENS_FREI} this "
                              f"evaluator enumerates")

    def belegt(tok, belegung):
        k = _schluessel(tok)
        return _ATOME[tok[0]][3](tok[1], {}) if k is None else belegung[k]

    werte: set = set()
    for kombi in itertools.product((False, True), repeat=len(frei)):
        belegung = {**dict(zip(frei, kombi)), **fest}
        werte.add(_werte(t, lambda tok, _b=belegung: belegt(tok, _b)))
        if len(werte) == 2:
            break
    return werte


def laeuft_bei_fehlschlag(text: str) -> bool:
    """Can this condition run its job when a needed job failed? That is what makes it a guard.

    GitHub prepends `success()` to a condition without a status function, and `success()` is false
    once a need failed: no. With one, the condition is read as written, at `_FEHLSCHLAG`, the event
    facts free. `!always()` never runs, `!failure()` not then, `!success()` and `!cancelled()` do.
    """
    t = _tokens(_ausdruck(text))
    if not any(isinstance(tok, tuple) and _ATOME[tok[0]][1] in ("status", "immer") for tok in t):
        return False
    return True in wahrheitswerte(text, _FEHLSCHLAG)


def bedingung_am_ereignis(text: str, ereignis: dict) -> bool:
    """Evaluate one workflow condition against a live event. `!` binds tighter than `&&`, and
    `&&` tighter than `||`. A character Python reads as whitespace and GitHub does not is refused
    before any pattern reads the text (`_ausdruck`)."""
    t = _tokens(_ausdruck(text))
    return _werte(t, lambda tok: _ATOME[tok[0]][3](tok[1], ereignis))


def lebend(ereignis: dict | None, declaration: Path | None = None, verzeichnis: Path | None = None) -> dict:
    """Will every required context ARRIVE on this event? Three states per context, never two."""
    if not ereignis:
        return {"verdict": UNKNOWN, "reason": "not running under GitHub Actions: GITHUB_EVENT_NAME or "
                                             "GITHUB_EVENT_PATH is missing, so there is no live event to judge"}
    if ereignis.get("fehler"):
        return {"verdict": UNKNOWN, "reason": f"the event payload is not readable ({ereignis['fehler']})"}
    r = pruefe(declaration, verzeichnis)
    if r["verdict"] == UNKNOWN:
        return {"verdict": UNKNOWN, "reason": r.get("reason")}
    unlesbare_dateien = list(r.get("unreadable_files") or [])
    ausloeser_je_datei = r.get("triggers") or {}
    zweig = r.get("branch") if isinstance(r.get("branch"), str) else None
    ereignis_name = _einzeilig(ereignis.get("event_name"), 32)

    def lauf(datei: str | None) -> bool:
        """Does the workflow `datei` run on this event? THE TRIGGER BEFORE THE CONDITION (lens on
        ac05d85d): the first form said `arrives` on a pull request for a context whose workflow runs
        on push only."""
        if datei not in ausloeser_je_datei:
            raise NichtAuswertbar(f"the `on:` of {datei} was not read")
        return laeuft_am_ereignis(ausloeser_je_datei[datei], ereignis, zweig)

    je: list[dict] = []
    for e in r["per_context"]:
        z = {"context": e["context"], "structure": e["state"]}
        if e["state"] in (ALWAYS, GATED):
            dateien = e.get("sources") or [e.get("from")]
            laeuft, offen = False, []
            for datei in dateien:
                try:
                    laeuft = lauf(datei)
                except NichtAuswertbar as exc:
                    offen.append(f"{datei}: {exc}")
                if laeuft:
                    break
            if not laeuft:
                if offen:
                    z["live"], z["why"] = UNKNOWN, "; ".join(offen)
                else:
                    z["live"], z["why"] = WILL_NOT_ARRIVE, (f"{', '.join(map(str, dateien))} does not run on "
                                                            f"a {ereignis_name} event")
                    z["not_triggered"] = True
                je.append(z)
                continue
        if e["state"] == ALWAYS:
            z["live"] = ARRIVES
        elif e["state"] == GATED:
            ausdruck = e["expression"] if "expression" in e else e.get("condition")
            if ausdruck is None:
                z["live"] = ARRIVES                    # the trigger was the whole condition, and it holds
                je.append(z)
                continue
            try:
                wahr = bedingung_am_ereignis(ausdruck or "", ereignis)
            except NichtAuswertbar as exc:
                z["live"], z["why"] = UNKNOWN, str(exc)
            else:
                z["live"] = ARRIVES if wahr else WILL_NOT_ARRIVE
                z["condition"] = ausdruck
        elif unlesbare_dateien or r.get("unreadable"):
            # "Absent" is only a verdict when every workflow file was READ. With a file that did
            # not parse, the context may well be produced there, and this run cannot tell.
            # THE SAME FOR A JOB (lens on ac05d85d): a job whose matrix, name or `if:` was not read
            # may produce the context under a name this run cannot derive, and "no workflow produces
            # it" pointed the advice at the ruleset.
            z["live"], z["why"] = UNKNOWN, ("a workflow file or job could not be read, so absence is not "
                                           "measurable: " + "; ".join(r.get("unreadable") or unlesbare_dateien))
        else:
            z["live"], z["why"] = WILL_NOT_ARRIVE, "no workflow produces it"
        je.append(z)
    fehlend = [z["context"] for z in je if z["live"] == WILL_NOT_ARRIVE]
    unklar = [z["context"] for z in je if z["live"] == UNKNOWN]
    verdict = ABSENT if fehlend else (UNKNOWN if unklar else ALWAYS)
    rat = None
    if fehlend:
        bedingt = [z for z in je if z["live"] == WILL_NOT_ARRIVE and z.get("condition")]
        # The label advice is for a PULL REQUEST. On a push or a dispatch there is nothing to
        # label; the generic sentence is the honest one there (lens 1, 2026-09-17).
        auf_pr = _ascii_klein(str(ereignis.get("event_name", ""))) in _PR_EREIGNISSE
        if bedingt and auf_pr and any("'landung'" in (z.get("condition") or "") for z in bedingt):
            rat = ("add the label `landung` to this pull request (gh pr edit <number> --add-label landung); "
                   "the `labeled` trigger starts the full matrix")
        elif bedingt:
            rat = "make one branch of the named condition true on this pull request, or change the ruleset"
        elif any(z.get("not_triggered") for z in je if z["live"] == WILL_NOT_ARRIVE):
            rat = ("a workflow that produces the missing context does not run on this event; add the event "
                   "to its `on:`, or change the ruleset")
        else:
            rat = "no workflow produces the missing context under any condition; the ruleset or the workflows must change"
    return {"verdict": verdict, "per_context": je, "missing": fehlend, "not_measurable": unklar,
            "unreadable_files": unlesbare_dateien,
            "event_name": ereignis.get("event_name"), "labels": _labels(ereignis),
            "head_ref": ereignis.get("head_ref"), "head_repo": _head_repo(ereignis),
            "repository": ereignis.get("repository"), "advice": rat}


def _lebend_bericht(d: dict) -> list[str]:
    """The live report, one line per context, every field folded (see _einzeilig)."""
    zeilen = []
    if d["verdict"] == UNKNOWN and "per_context" not in d:
        return [f"[live-checks] NOT MEASURABLE — {_einzeilig(d.get('reason'), 200)}"]
    kopf = (f"[live-checks] event {_einzeilig(d.get('event_name'), 32)}, labels "
            f"[{_einzeilig(', '.join(d.get('labels') or []), 80)}], head {_einzeilig(d.get('head_ref') or '-', 64)}: ")
    if d["verdict"] == ALWAYS:
        kopf += "every required context arrives on this event"
    elif d["verdict"] == ABSENT:
        kopf += f"{len(d['missing'])} required context(s) will NOT arrive on this event"
    else:
        kopf += f"NOT MEASURABLE for {len(d['not_measurable'])} context(s)"
    zeilen.append(kopf)
    for z in d.get("per_context", []):
        marke = {ARRIVES: "arrives          ", WILL_NOT_ARRIVE: "WILL NOT ARRIVE  ", UNKNOWN: "NOT MEASURABLE   "}[z["live"]]
        zeile = f"  {marke} {_einzeilig(z['context'], 80)}"
        if z["live"] == WILL_NOT_ARRIVE and z.get("condition"):
            zeile += f"   condition is false on this event: {_einzeilig(z['condition'], 200)}"
        elif z.get("why"):
            zeile += f"   {_einzeilig(z['why'], 200)}"
        zeilen.append(zeile)
    for u in d.get("unreadable_files") or []:
        zeilen.append(f"  unreadable-file   {_einzeilig(u, 200)}")
    if d.get("advice"):
        zeilen.append(f"  action: {_einzeilig(d['advice'], 220)}")
    return zeilen


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--declaration", type=Path, default=None)
    ap.add_argument("--workflows", type=Path, default=None)
    modus = ap.add_mutually_exclusive_group()
    modus.add_argument("--verify-declaration", action="store_true",
                       help="NETWORK: hold the declaration against the live ruleset and report "
                            "drift. Not part of the offline gate; with no network the verdict is "
                            "not-measurable, never a pass.")
    ap.add_argument("--repo", default=None, help="owner/name for --verify-declaration")
    modus.add_argument("--verify-live-pr", "--live", dest="verify_live_pr", action="store_true",
                       help="judge THIS run's event (GITHUB_EVENT_NAME/GITHUB_EVENT_PATH): will every "
                            "required context arrive on it? Exit 1 when one will not or cannot be "
                            "measured. The offline verdict answers CAN, this one answers WILL.")
    ap.add_argument("--drift-marker", default=".required-checks-drift.json",
                    help="where --verify-declaration puts its verdict and where the offline "
                         "run reads it. Empty means: no marker.")
    ap.add_argument("--allow-gated", action="store_true",
                    help="treat a context that is only produced under a NAMED condition as a pass. "
                         "Off by default: a condition nobody sets is a pull request nobody can merge.")
    a = ap.parse_args(argv)
    if a.verify_live_pr:
        d = lebend(ereignis_aus_umgebung(), a.declaration, a.workflows)
        if a.json:
            print(json.dumps(d, ensure_ascii=False, indent=2))
        else:
            for zeile in _lebend_bericht(d):
                print(zeile)
        return 0 if d["verdict"] == ALWAYS else 1
    if a.verify_declaration:
        d = erklaerung_gegen_regelsatz(a.declaration, a.repo)
        if a.json:
            print(json.dumps(d, ensure_ascii=False, indent=2))
        else:
            print(f"[declaration] {d.get('repo')} ruleset {d.get('ruleset')}: {d['verdict']}")
            if d.get("reason"):
                print(f"  reason: {d['reason']}")
            for k, wort in (("declared_only", "declared but NOT required"),
                            ("ruleset_only", "required but NOT declared")):
                for c in d.get(k) or []:
                    print(f"  {wort}: {c}")
        # DER MARKER. Eine Gegenlesung des gelandeten Standes hielt fest, dass das Offline-Tor
        # gruen melden kann, ohne zu wissen, OB die Drift-Pruefung ueberhaupt lief — und ein Urteil,
        # das nicht weiss, worauf es ruht, sagt mehr als es prueft. Der Netz-Lauf legt darum sein
        # Ergebnis ab, der Offline-Lauf liest es und NENNT es. Er blockt NICHT darauf: ein
        # fehlender Token oder ein totes Netz wuerden den beratenden Job sonst aus Umweltgruenden
        # rot faerben, also genau das Dauerrot herstellen, gegen das die Sohle gebaut ist. Gesagt
        # wird es trotzdem, weil eine Pruefung, die nicht lief, keine bestandene ist.
        if a.drift_marker:
            try:
                Path(a.drift_marker).write_text(json.dumps(
                    {"verdict": d["verdict"], "repo": d.get("repo"), "ruleset": d.get("ruleset"),
                     "reason": d.get("reason"), "at": _jetzt(),
                     # WORAUF SICH DAS URTEIL BEZIEHT. Ohne diesen Digest sagt der Marker nur, DASS
                     # einmal etwas geprueft wurde, nie WORAN — und ein Marker von gestern behauptet
                     # dann etwas ueber eine Erklaerung von heute. Gemessen 2026-09-16: ein Marker
                     # mit `at: 2020-01-01` meldete unveraendert "checked".
                     "declaration_sha256": _erklaerungs_digest(a.declaration)},
                    ensure_ascii=False), encoding="utf-8")
            except OSError as exc:
                print(f"  marker not written ({exc}) — the offline run will report it as NOT RUN")
        return 0 if d["verdict"] == ALWAYS else 1
    r = pruefe(a.declaration, a.workflows)
    if a.json:
        print(json.dumps(r, ensure_ascii=False, indent=2))
    else:
        print(f"[required-checks] ruleset {_einzeilig(r.get('ruleset'), 64)} on "
              f"{_einzeilig(r.get('branch'), 64)}: {_einzeilig(r['verdict'], 32)}")
        for e in r.get("per_context", []):
            zeile = f"  {_einzeilig(e['state'], 18):18} {_einzeilig(e['context'], 80)}"
            if e.get("condition"):
                # Der Digest steht IM BERICHT, weil die Zusage genau ihn nennen muss. Es gibt
                # bewusst kein `--accept-current`: ein Ein-Befehl-Freibrief waere keine Sohle,
                # sondern eine Selbstsegnung. Wer zusagt, kopiert den Wert und traegt ihn ein.
                zeile += (f"   [{_kurz(e.get('condition_sha256', '?'), 16)}…] "
                          f"only if: {_einzeilig(e['condition'], 220)}")
            elif e.get("from"):
                zeile += f"   from {_einzeilig(e['from'], 80)}"
            print(zeile)
        print("  " + _drift_zeile(a.drift_marker, a.declaration))
        for g in r.get("changed_conditions", []):
            print(f"  condition-changed   {_einzeilig(g['context'], 80)}: "
                  f"declared {_kurz(g['declared'], 16)}…, measured {_kurz(g['measured'], 16)}… — "
                  f"the acceptance was made for a DIFFERENT condition, so it does not carry")
        for u in r.get("unbound_acceptances", []):
            print(f"  unbound-acceptance  {_einzeilig(u, 80)}: listed by name only, without "
                  f"condition_sha256 — a name alone cannot say WHICH state was accepted, so it "
                  f"does not carry")
        for g in r.get("changed_reasons", []):
            print(f"  reason-changed      {_einzeilig(g['context'], 80)}: "
                  f"declared {_kurz(g['declared'], 16)}…, measured {_kurz(g['measured'], 16)}… — "
                  f"the acceptance was made for a DIFFERENT limit, so it does not carry")
        for u in r.get("unbound_unreadable_acceptances", []):
            print(f"  unbound-limit       {_einzeilig(u, 80)}: listed by name only, without "
                  f"reason_sha256 — a prefix alone cannot say WHICH limit was accepted, so it "
                  f"does not carry")
        for h in r.get("dead_conditions", []):
            print(f"  dead-condition     {_einzeilig(h, 160)}")
        for h in r.get("status_function_conditions", []):
            print(f"  status-function    {_einzeilig(h, 160)}")
        # SAID, NOT ACTED ON: a condition the evaluator cannot read keeps its named-condition
        # reading, which the ratchet already binds to its digest; the line says what was not decided.
        for h in r.get("undecided_conditions", []):
            print(f"  undecided          {_einzeilig(h, 240)}")
        for h in r.get("skipped_reads_as_passed", []):
            print(f"  skipped-is-passed  {_einzeilig(h['context'], 80)}: {_einzeilig(h['why'], 200)}")
        neu_u = set(r.get("newly_unreadable") or [])
        for u in r.get("unreadable", []):
            marke = "not-measurable" if u in neu_u else "known-limit   "
            # DER DIGEST DES GRUNDES STEHT IM BERICHT, genau wie der der Bedingung: wer eine
            # Unmessbarkeit hinnehmen will, muss SAGEN KOENNEN, welche. Ohne den Wert im Bericht
            # bliebe nur die Namensform, und die ist die Luecke, die hier gerade geschlossen wird.
            print(f"  {marke}     {_einzeilig(u, 200)}")
    if r.get("dead_conditions"):
        # A condition that can never take effect is a silent lie in the workflow, even when the
        # produced contexts happen to be right today.
        return 1
    if r.get("skipped_reads_as_passed"):
        # A required context that is skipped -- and therefore green -- whenever what it needs
        # fails is a check that cannot block on its own subject. Red, regardless of the rest.
        return 1
    # EINE VERSCHLECHTERUNG IST EINE VERSCHLECHTERUNG, AUCH WENN SONST ALLES LAEUFT. Diese drei
    # Zeilen standen frueher UNTER der Abkuerzung `verdict == ALWAYS`, und damit wirkten sie nur,
    # wenn ohnehin schon etwas bedingt war. Gemessen 2026-09-16 beim Schreiben des Falls fuer die
    # gebundene Grenz-Zusage: alle Pflichtkontexte unbedingt erzeugt, eine NEUE unmessbare Stelle
    # im Bericht, `reason-changed` gedruckt -- und exit 0. Die Erklaerung behauptete im selben
    # Atemzug "A NEW unmeasurable case still fails". Sie tat es nicht. Eine unmessbare Stelle kann
    # einen Pflichtkontext verdecken; das ist unabhaengig davon, wie die uebrigen dastehen.
    if (r.get("newly_unreadable") or r.get("unbound_acceptances")
            or r.get("unbound_unreadable_acceptances")):
        return 1
    if r["verdict"] == ALWAYS:
        return 0
    if r["verdict"] == GATED and a.allow_gated:
        return 0
    # THE RATCHET. An advisory job that is red from its first run teaches people to look away, and
    # a gate that is habitually stepped over checks nothing any more. The REPORT above still names
    # every conditional context together with its condition; only the exit code follows what the
    # declaration accepts today. It turns red as soon as things get WORSE: a context nobody
    # produces, something not measurable, or a NEWLY conditional one that is not declared.
    # `accepted_gated` is deliberately NOT tested again here. The first draft did test it, and it
    # was a dead condition: verdict GATED means at least one conditional context exists, so if
    # `newly_gated` is empty that context is in the list and the list cannot be empty. A condition
    # that can never decide anything makes mutants unkillable -- which is exactly what this tool
    # reports as `dead-condition` in other people's workflows. A mutant that pinned `newly_gated`
    # to empty survived the first contract because of it.
    # `unbound_unreadable_acceptances` steht hier aus demselben Grund wie `unbound_acceptances`:
    # eine Zusage in der alten Namensform ist keine Zusage, und wenn sie den Ausgang nicht
    # beruehrt, lebt die alte Form als stiller Freibrief weiter.
    if (r["verdict"] == GATED and not r.get("newly_gated")
            and not r.get("newly_unreadable") and not r.get("unbound_acceptances")
            and not r.get("unbound_unreadable_acceptances")):
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
