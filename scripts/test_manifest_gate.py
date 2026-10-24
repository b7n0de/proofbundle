#!/usr/bin/env python3
"""WP-B — pytest is the NORMATIVE runner + a locked test manifest (no silent test shrink).

The 3.6.0 acceptance (EXT-P1-06) has two halves and this gate enforces both mechanically:

  1. **pytest is the normative runner.** The historical `unittest discover` path silently MISSED
     the pytest-only modules (bare ``def test_*`` functions, parametrize, fixtures) — a real finding
     was 47 security tests invisible to the unittest gate. This gate re-derives, fresh each run, how
     many test modules carry NO ``unittest`` import (the pytest-only class) and asserts the locked
     floor is still met — so a regression that quietly drops pytest-only coverage is a CI FAIL, not a
     silent narrowing.

  2. **A locked test manifest.** The count of tests pytest COLLECTS must not fall below a committed
     floor (``tests/test_manifest_lock.json``) without an explicit, reviewed bump of that floor. An
     unintended drop (a module that stops collecting, a deleted suite, a broken import that silently
     de-selects a file) is exactly the "silent test schwund" EXT-P1-06 forbids.

No-Fake / fail-closed design:
  * The floor is a FLOOR, never an exact equality — adding tests is always fine; only a DROP fails.
  * The count is taken from pytest's own ``--collect-only`` (the normative runner), parsed from its
    "N tests collected" summary; a collection ERROR (not just a low count) is a hard FAIL, because a
    collection error is the classic way a whole file silently disappears from the run.
  * Raising the floor is a deliberate, committed edit to the lock file, surfaced in review — the gate
    prints the exact new floor to record when the live count exceeds the locked one.

CLI:
  python scripts/test_manifest_gate.py [--json] [--update] [--tests-dir tests]

``--update`` rewrites the lock file to the current live counts (a reviewed action, run by a human when
tests are intentionally added). Exit 0 iff every floor is met and collection is clean.
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
LOCK_PATH = REPO / "tests" / "test_manifest_lock.json"
_COLLECTED_RE = re.compile(r"(\d+)\s+tests?\s+collected")
_ERROR_RE = re.compile(r"(\d+)\s+errors?\b")


def _letzter_treffer(rx: "re.Pattern[str]", text: str):
    """Der LETZTE Treffer im Text, zeilenweise von hinten — nicht der erste im Blob.

    Eine Zahl, die ueber ein Gate entscheidet, gehoert in die Bilanzzeile des Laufs und nicht in
    irgendeine Zeile, die zufaellig dieselbe Form hat. `re.search` liest von vorn, und vor der
    Bilanz steht bei jedem Sammelfehler der Diagnosetext. Diese Funktion ist der Anker.
    """
    for zeile in reversed(text.splitlines()):
        treffer = rx.search(zeile)
        if treffer:
            return treffer
    return None


def _importiert_unittest_lexikalisch(text: str) -> bool:
    """Does the source import ``unittest``? Read from its TOKENS, not from the rest of a line.

    Codex on pull request 371, round one, P2, measured: the pattern below took the rest of the line
    after `import`, so `import os  # unittest is intentionally not used` and `import os as unittest`
    counted as an import of unittest, and a backslash continuation `import os, \\` + `unittest` did
    not. The syntax tree read all three the other way, and `evaluate()` refused valid modules.

    STILL A SECOND READER, and that is the point of the owner order of 2026-09-07: this one reads the
    token stream of `tokenize`, the other one the syntax tree of `ast`. A comment and a string are
    their own tokens here, a continuation is no line break, and the names of the statement are read
    as names, with `as` and its alias skipped. A source the tokenizer refuses counts as importing,
    so it falls out of the pytest-only set on both paths, the way the syntax tree handles a file it
    cannot parse.
    """
    import io  # noqa: PLC0415
    import tokenize  # noqa: PLC0415
    import unicodedata  # noqa: PLC0415
    # A NUL BYTE IS ANSWERED BEFORE THE TOKENIZER (counter-reading of pull request 371, F5, P3). No
    # Python compiles a source that holds one, but `tokenize` answers it by version: 3.11 reads on,
    # 3.13 raises `TokenError`, and 3.12 raises `SystemError` (measured on 3.12.3 and 3.12.13, in
    # the report on 3.12.15), which stopped the gate with a traceback.
    if "\x00" in text:
        return True
    try:
        toks = [t for t in tokenize.generate_tokens(io.StringIO(text).readline)
                if t.type not in (tokenize.COMMENT, tokenize.NL)]
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return True

    def name_at(i: int) -> tuple[str, int]:
        """A dotted name from position i: (its first part, the position after it).

        The part is read after NFKC, as Python reads an identifier and the syntax tree names it: a
        name written with the full-width `u` (U+FF55) imports unittest (counter-reading of pull
        request 371, F4, P3)."""
        erster = (unicodedata.normalize("NFKC", toks[i].string)
                  if i < len(toks) and toks[i].type == tokenize.NAME else "")
        while i < len(toks) and toks[i].type == tokenize.NAME:
            i += 1
            if i < len(toks) and toks[i].type == tokenize.OP and toks[i].string == ".":
                i += 1
            else:
                break
        return erster, i

    # A statement begins after a line, an indentation change, `;`, and after the `:` of a compound
    # statement written on one line (`if x: import unittest`). After `:` an `import` or `from` can
    # only be a statement: no expression holds either word in that place.
    anfang = True
    i = 0
    while i < len(toks):
        t = toks[i]
        if t.type in (tokenize.NEWLINE, tokenize.INDENT, tokenize.DEDENT) or (
                t.type == tokenize.OP and t.string in (";", ":")):
            anfang = True
            i += 1
            continue
        if anfang and t.type == tokenize.NAME and t.string == "import":
            i += 1
            while True:
                erster, i = name_at(i)
                if erster == "unittest":
                    return True
                if i < len(toks) and toks[i].type == tokenize.NAME and toks[i].string == "as":
                    i += 2
                if i < len(toks) and toks[i].type == tokenize.OP and toks[i].string == ",":
                    i += 1
                    continue
                break
            # No step past the token the statement ended on: it may be the NEWLINE or `;` that
            # opens the next statement.
            anfang = False
            continue
        if anfang and t.type == tokenize.NAME and t.string == "from":
            i += 1
            while i < len(toks) and toks[i].type == tokenize.OP and toks[i].string in (".", "..."):
                i += 1
            # The relative level is ignored, as `pytest_only_modules_ast` ignores it.
            erster, i = name_at(i)
            if erster == "unittest":
                return True
            anfang = False
            continue
        anfang = False
        i += 1
    return False


def pytest_only_modules(tests_dir: Path) -> list[str]:
    """Every ``tests/test_*.py`` whose SOURCE does not import ``unittest`` — the class the legacy
    unittest-discover runner cannot see. Re-derived fresh each run (no hand-maintained list)."""
    out: list[str] = []
    for path in sorted(tests_dir.glob("test_*.py")):
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        # EVERY NAME OF THE STATEMENT, not only the first. Codex r3999288389, measured and
        # confirmed: the old pattern required `unittest` DIRECTLY after `import` and did not see
        # `import os, unittest`. The syntax tree saw it, the two derivations DISAGREED, and the
        # equality check in `evaluate()` reported ok=False for a fully valid test module, so the
        # gate refused a correct addition.
        #
        # NOT the other way, and this corrects an earlier answer of this house: REPLACING the text
        # path with the AST path would have removed the second derivation, and that is no accident
        # but the owner order of 2026-09-07 (guard sweep P1). Two readers with different failure
        # geometry are the guard; whoever drops one keeps the count and loses the check. The right
        # remedy is that both measure THE SAME property, so that their difference is again a
        # statement about the subject instead of about the weaker reading.
        #
        # NAMES, NOT THE REST OF THE LINE (Codex on pull request 371, round one, P2). The pattern
        # that stood here, `^\s*(?:import\s+[^\n]*\bunittest\b|from\s+unittest\b)`, read a comment
        # and an alias as an import and missed a backslash continuation; the reader below takes the
        # names of each import statement from the token stream.
        if not _importiert_unittest_lexikalisch(text):
            out.append(path.name)
    return out


def pytest_only_modules_ast(tests_dir: Path) -> list[str]:
    """THE SAME set on an INDEPENDENT path: the syntax tree instead of the token stream.

    WARUM ES DIESE ZWEITE ABLEITUNG GIBT (Owner-Anordnung 2026-09-07, Riegel-Sweep P1): die
    Zusicherung ueber die pytest-only-Menge war ein BODEN — `len(pyonly) >= floor`, Boden 5 bei 62
    Modulen. Ein Boden mit 57 Kopffreiheit kann eine FEHLKLASSIFIKATION nicht bemerken: nimmt man
    das `not` aus der Regex, waehlt sie die exakte Gegenmenge (199 statt 62 Module), und
    `evaluate()` meldet weiter `ok=True`, weil 199 den Boden mit Leichtigkeit nimmt. Gemessen am
    selben Tag; alle Faelle blieben gruen.

    THE RULE IS THAT OF THE MUTATION RUN: the expectation comes from the TREE, not from a typed
    number, and two independent derivations must AGREE. One reads the source as a token stream
    (`tokenize`; until Codex on pull request 371 it was a regex), the other as a syntax tree (`ast`),
    where an import is an `Import` or `ImportFrom` node and no text pattern. An error in one reading
    cannot drag the other along; their difference is the bar, and it needs no number.

    A file that does not parse counts as NOT pytest-only here. It falls into the difference only when
    the token reader reads it (`x = = 1`); a source the tokenizer refuses counts as importing there as
    well, and both paths leave it out (counter-reading of pull request 371, F7). A collection error is
    a hard FAIL in the same gate anyway.
    """
    import ast  # noqa: PLC0415
    out: list[str] = []
    for path in sorted(tests_dir.glob("test_*.py")):
        try:
            baum = ast.parse(path.read_text(encoding="utf-8"))
        except (OSError, SyntaxError):
            continue
        traegt_unittest = False
        for knoten in ast.walk(baum):
            if isinstance(knoten, ast.Import):
                if any(a.name == "unittest" or a.name.startswith("unittest.") for a in knoten.names):
                    traegt_unittest = True
                    break
            elif isinstance(knoten, ast.ImportFrom):
                if (knoten.module or "") == "unittest" or (knoten.module or "").startswith("unittest."):
                    traegt_unittest = True
                    break
        if not traegt_unittest:
            out.append(path.name)
    return out


def collect_count(tests_dir: Path) -> tuple[int, int, str]:
    """Run pytest's own collection (the normative runner) and return (collected, errors, raw_tail).

    A non-zero error count OR an unparseable summary is surfaced to the caller as a FAIL condition —
    a collection error is how a file silently drops out of the run, the exact regression WP-B guards.
    """
    proc = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q", "-p", "no:cacheprovider",
         str(tests_dir)],
        cwd=str(REPO), capture_output=True, text=True,
        env={**_env()},
    )
    tail = "\n".join((proc.stdout or "").strip().splitlines()[-4:])
    # VON HINTEN, NICHT VON VORN — Klassen-Sweep 2026-09-07, dieselbe Klasse wie der Fund an
    # `mutation_check._rote_aus_text` (deep gate Lauf 5, Linse 5). `re.search` ueber den GANZEN
    # stdout nimmt den ERSTEN Treffer. Bei einem Sammelfehler steht vor der Bilanz der Traceback
    # samt Testkoerper und Docstring, und dieses Korpus traegt summary-foermige Zahlen in
    # Docstrings — eine davon entschiede dann ueber die Bodenpruefung dieses Tores. Die Bilanz
    # ist die LETZTE passende Zeile; alles davor ist Diagnosetext.
    m = _letzter_treffer(_COLLECTED_RE, proc.stdout or "")
    collected = int(m.group(1)) if m else -1
    em = _letzter_treffer(_ERROR_RE, proc.stdout or "")
    errors = int(em.group(1)) if em else 0
    # pytest exits non-zero on collection errors even with tests collected; treat that as errors>0.
    if proc.returncode not in (0,) and errors == 0 and collected >= 0:
        errors = max(errors, 1)
    return collected, errors, tail


def _env() -> dict:
    import os
    e = dict(os.environ)
    src = str(REPO / "src")
    e["PYTHONPATH"] = src + (":" + e["PYTHONPATH"] if e.get("PYTHONPATH") else "")
    return e


class LockUnreadable(ValueError):
    """The lock file holds no single reading of its floors."""


def load_lock(path: Path = LOCK_PATH) -> dict:
    """The lock, read once within the input budget and parsed strictly (CODEX-KLASSENSUCHE-631-01, D4, measured
    at f6ea5cc3): with `json.loads` the lock {"min_collected_tests":2,"min_collected_tests":1,...} kept the last
    floor, and one collected test passed a floor that also read 2. A member twice raises LockUnreadable, and so
    does a lock that is not there (E2): no floor is invented for it."""
    if not path.is_file():
        raise LockUnreadable(f"the lock {path.name} is missing")
    if str(REPO / "src") not in sys.path:
        sys.path.insert(0, str(REPO / "src"))
    from proofbundle._strict_json import loads_strict  # noqa: PLC0415
    from proofbundle.budget import DEFAULT_BUDGET  # noqa: PLC0415
    from proofbundle.errors import ProofBundleError  # noqa: PLC0415
    kappe = int(DEFAULT_BUDGET.input_bytes)
    with path.open("rb") as fh:
        roh = fh.read(kappe + 1)
    if len(roh) > kappe:
        raise LockUnreadable(f"the lock {path.name} holds more than the input_bytes budget of {kappe} bytes")
    try:
        return loads_strict(roh)
    except (ValueError, UnicodeDecodeError, RecursionError, ProofBundleError) as exc:
        raise LockUnreadable(f"the lock {path.name} is not valid strict JSON: {exc}") from None


def evaluate(tests_dir: Path | None = None, lock_path: Path = LOCK_PATH) -> dict:
    tests_dir = tests_dir or (REPO / "tests")
    problems: list[str] = []
    try:
        lock = load_lock(lock_path)
    except LockUnreadable as exc:
        lock = None
        problems.append(f"{exc}; a floor read from it is no floor, so no population verdict stands")
    # BOTH FLOORS ARE REQUIRED AND TYPED, NEVER DEFAULTED (CODEX-KLASSENSUCHE-631-01, E2, measured at f6ea5cc3):
    # a missing lock read as {} and `.get(..., 0)` made two zero floors, so a population of one test passed with
    # ok=True, and the guard against unnoticed test loss went away with its anchor. A floor is a JSON integer of
    # 0 or more, written out; 0 written out stays a floor, an absent one is none.
    floor_tests = floor_pytest_only = None
    if lock is not None and not isinstance(lock, dict):
        problems.append("the lock is no JSON object; no population verdict stands")
    elif lock is not None:
        floors = []
        for name in ("min_collected_tests", "min_pytest_only_modules"):
            value = lock.get(name)
            if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                floors.append(value)
            else:
                floors.append(None)
                problems.append(f"the lock names no {name} as an integer of 0 or more (it holds {value!r}); "
                                "a floor that is not written out is no floor, so no population verdict stands")
        floor_tests, floor_pytest_only = floors

    collected, errors, tail = collect_count(tests_dir)
    pyonly = pytest_only_modules(tests_dir)

    if collected < 0:
        problems.append(f"could not parse pytest collection summary; tail:\n{tail}")
    if errors:
        problems.append(f"pytest reported {errors} collection error(s) — a file silently dropped "
                        f"from the run is a FAIL (WP-B); tail:\n{tail}")
    if collected >= 0 and floor_tests is not None and collected < floor_tests:
        problems.append(f"collected {collected} tests < locked floor {floor_tests} "
                        "(unintended test shrink — a suite stopped collecting, or the floor needs a "
                        "reviewed bump via --update)")
    if floor_pytest_only is not None and len(pyonly) < floor_pytest_only:
        problems.append(f"{len(pyonly)} pytest-only module(s) < locked floor {floor_pytest_only} "
                        "(pytest-only coverage regressed — the unittest-invisible class shrank)")
    # DIE ERWARTUNG KOMMT AUS DEM BAUM, NICHT AUS EINER ZAHL (Owner 2026-09-07). Der Boden oben
    # prueft die GROESSE der Menge; er kann eine falsche Menge derselben oder groesserer Groesse
    # nicht bemerken. Zwei unabhaengige Ableitungen — Zeichenkette und Syntaxbaum — muessen
    # dieselben Module nennen. Ihre DIFFERENZ ist der Riegel und braucht keine getippte Zahl.
    pyonly_ast = pytest_only_modules_ast(tests_dir)
    nur_token = sorted(set(pyonly) - set(pyonly_ast))
    nur_ast = sorted(set(pyonly_ast) - set(pyonly))
    if nur_token or nur_ast:
        problems.append(
            f"die zwei Ableitungen der pytest-only-Menge sind UNEINIG: der Tokenleser nennt "
            f"{len(pyonly)} Module, der Syntaxbaum {len(pyonly_ast)}. Nur im Tokenleser: "
            f"{nur_token[:8]}; nur im "
            f"Syntaxbaum: {nur_ast[:8]}. Eine Klassifikation, die sich selbst widerspricht, ist "
            f"keine Klassifikation — und ein Boden ueber der Groesse haette es nicht bemerkt")

    return {
        "schema": "proofbundle.test_manifest_gate.v1",
        "ok": not problems,
        "collected": collected,
        "errors": errors,
        "min_collected_tests": floor_tests,
        "pytest_only_modules": len(pyonly),
        "pytest_only_modules_ast": len(pyonly_ast),
        "min_pytest_only_modules": floor_pytest_only,
        "headroom_tests": (collected - floor_tests) if collected >= 0 and floor_tests is not None else None,
        "problems": problems,
    }


def _write_lock(tests_dir: Path, lock_path: Path) -> dict:
    collected, errors, tail = collect_count(tests_dir)
    if collected < 0 or errors:
        raise SystemExit(f"refusing to lock an unclean collection (collected={collected}, "
                         f"errors={errors}); tail:\n{tail}")
    pyonly = pytest_only_modules(tests_dir)
    lock = {
        "schema": "proofbundle.test_manifest_lock.v1",
        "note": "WP-B locked test manifest. FLOORs, never exact counts: adding tests is always fine; "
                "a drop below these is a CI FAIL (no silent test schwund). Raising a floor is a "
                "deliberate, reviewed edit (run scripts/test_manifest_gate.py --update).",
        "min_collected_tests": collected,
        "min_pytest_only_modules": len(pyonly),
        "recorded_live_counts": {"collected": collected, "pytest_only_modules": len(pyonly)},
    }
    lock_path.write_text(json.dumps(lock, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return lock


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--json", action="store_true")
    p.add_argument("--update", action="store_true",
                   help="rewrite the lock file to the current live counts (a reviewed human action)")
    p.add_argument("--tests-dir", type=Path, default=REPO / "tests")
    args = p.parse_args(argv)

    if args.update:
        lock = _write_lock(args.tests_dir, LOCK_PATH)
        print(f"[test-manifest] locked floor: {lock['min_collected_tests']} tests, "
              f"{lock['min_pytest_only_modules']} pytest-only module(s) -> {LOCK_PATH.name}")
        return 0

    result = evaluate(args.tests_dir)
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(f"[test-manifest] collected={result['collected']} "
              f"(floor {result['min_collected_tests']}, headroom {result['headroom_tests']}) · "
              f"pytest-only={result['pytest_only_modules']} (floor {result['min_pytest_only_modules']}) · "
              f"{'OK' if result['ok'] else 'FAIL'}")
        for pr in result["problems"]:
            print("  -", pr)
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
