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


def pytest_only_modules(tests_dir: Path) -> list[str]:
    """Every ``tests/test_*.py`` whose SOURCE does not import ``unittest`` — the class the legacy
    unittest-discover runner cannot see. Re-derived fresh each run (no hand-maintained list)."""
    out: list[str] = []
    for path in sorted(tests_dir.glob("test_*.py")):
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        if not re.search(r"^\s*(?:import\s+unittest|from\s+unittest\b)", text, re.MULTILINE):
            out.append(path.name)
    return out


def pytest_only_modules_ast(tests_dir: Path) -> list[str]:
    """DIESELBE Menge, auf einem UNABHAENGIGEN Weg: der Syntaxbaum statt eines Regex.

    WARUM ES DIESE ZWEITE ABLEITUNG GIBT (Owner-Anordnung 2026-09-07, Riegel-Sweep P1): die
    Zusicherung ueber die pytest-only-Menge war ein BODEN — `len(pyonly) >= floor`, Boden 5 bei 62
    Modulen. Ein Boden mit 57 Kopffreiheit kann eine FEHLKLASSIFIKATION nicht bemerken: nimmt man
    das `not` aus der Regex, waehlt sie die exakte Gegenmenge (199 statt 62 Module), und
    `evaluate()` meldet weiter `ok=True`, weil 199 den Boden mit Leichtigkeit nimmt. Gemessen am
    selben Tag; alle Faelle blieben gruen.

    DIE REGEL IST DIE DES MUTATIONSLAUFS: die Erwartung kommt aus dem BAUM, nicht aus einer
    getippten Zahl, und zwei unabhaengige Ableitungen muessen EINIG sein. Hier liest die eine den
    Quelltext als Zeichenkette (Regex), die andere als Syntaxbaum (`ast`) — ein Import ist im Baum
    ein `Import`/`ImportFrom`-Knoten und kein Textmuster. Ein Fehler in der einen Lesart kann die
    andere nicht mitreissen; ihre Differenz ist der Riegel, und sie braucht keine Zahl.

    Eine Datei, die nicht parst, gilt hier als NICHT pytest-only und faellt damit in die Differenz
    auf — ein Sammelfehler ist ohnehin ein harter FAIL im selben Tor.
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


def load_lock(path: Path = LOCK_PATH) -> dict:
    if not path.is_file():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def evaluate(tests_dir: Path | None = None, lock_path: Path = LOCK_PATH) -> dict:
    tests_dir = tests_dir or (REPO / "tests")
    lock = load_lock(lock_path)
    floor_tests = int(lock.get("min_collected_tests", 0))
    floor_pytest_only = int(lock.get("min_pytest_only_modules", 0))

    collected, errors, tail = collect_count(tests_dir)
    pyonly = pytest_only_modules(tests_dir)

    problems: list[str] = []
    if collected < 0:
        problems.append(f"could not parse pytest collection summary; tail:\n{tail}")
    if errors:
        problems.append(f"pytest reported {errors} collection error(s) — a file silently dropped "
                        f"from the run is a FAIL (WP-B); tail:\n{tail}")
    if collected >= 0 and collected < floor_tests:
        problems.append(f"collected {collected} tests < locked floor {floor_tests} "
                        "(unintended test shrink — a suite stopped collecting, or the floor needs a "
                        "reviewed bump via --update)")
    if len(pyonly) < floor_pytest_only:
        problems.append(f"{len(pyonly)} pytest-only module(s) < locked floor {floor_pytest_only} "
                        "(pytest-only coverage regressed — the unittest-invisible class shrank)")
    # DIE ERWARTUNG KOMMT AUS DEM BAUM, NICHT AUS EINER ZAHL (Owner 2026-09-07). Der Boden oben
    # prueft die GROESSE der Menge; er kann eine falsche Menge derselben oder groesserer Groesse
    # nicht bemerken. Zwei unabhaengige Ableitungen — Zeichenkette und Syntaxbaum — muessen
    # dieselben Module nennen. Ihre DIFFERENZ ist der Riegel und braucht keine getippte Zahl.
    pyonly_ast = pytest_only_modules_ast(tests_dir)
    nur_regex = sorted(set(pyonly) - set(pyonly_ast))
    nur_ast = sorted(set(pyonly_ast) - set(pyonly))
    if nur_regex or nur_ast:
        problems.append(
            f"die zwei Ableitungen der pytest-only-Menge sind UNEINIG: Regex nennt {len(pyonly)} "
            f"Module, der Syntaxbaum {len(pyonly_ast)}. Nur im Regex: {nur_regex[:8]}; nur im "
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
        "headroom_tests": (collected - floor_tests) if collected >= 0 else None,
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
