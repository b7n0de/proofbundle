#!/usr/bin/env python3
"""Mutation check for verify_revocation.py.

Each line marked '# LOCK <name>' is one check. First the unchanged selftest must run completely
with exit 0. Then, for every lock, this script writes a copy of the verifier with that check
switched off ('if False:') and runs the complete selftest over all cases. A mutant counts as
caught only if that selftest ends completely, exits 1 and reports at least one real DIFF case.
A crash or an incomplete run is an error of this mutation check, never a caught mutant.
Exit 0 only if the unchanged selftest passes and every mutant is caught.
Run from this folder: python3 check_mutants.py
"""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = open(os.path.join(HERE, "verify_revocation.py"), encoding="utf-8").read().split("\n")
LOCK = re.compile(r"^(\s*)if .*:\s*# LOCK (\w+)\s*$")
SUMMARY = re.compile(r"cases ([0-9]+), mismatches ([0-9]+)")


def expected_count():
    with open(os.path.join(HERE, "cases", "expected.json"), "rb") as f:
        return len(json.loads(f.read())["cases"])


def run_selftest(lines):
    """Run the selftest of the given verifier source in a copy of this folder.
    Returns (exit code, number of DIFF lines, (cases, mismatches) or None, case ids that differ)."""
    tmp = tempfile.mkdtemp()
    try:
        for d in ("keys", "cases"):
            shutil.copytree(os.path.join(HERE, d), os.path.join(tmp, d))
        for f in ("revocation_customer_only.json", "revocation_countersigned.json"):
            shutil.copy(os.path.join(HERE, f), tmp)
        with open(os.path.join(tmp, "verify_revocation.py"), "w", encoding="utf-8") as f:
            f.write("\n".join(lines))
        r = subprocess.run([sys.executable, "-I", os.path.join(tmp, "verify_revocation.py"), "--selftest", tmp],
                           capture_output=True, text=True)
    finally:
        shutil.rmtree(tmp)
    out = r.stdout.splitlines()
    diffs = [line.split()[1] for line in out if line.startswith("DIFF")]
    summary = None
    if out:
        m = SUMMARY.fullmatch(out[-1])
        if m:
            summary = (int(m.group(1)), int(m.group(2)))
    return r.returncode, len(diffs), summary, diffs


def main():
    try:
        n = expected_count()
    except (OSError, ValueError, KeyError, TypeError) as e:
        print("error: cases/expected.json cannot be read: %s" % e)
        return 2
    code, ndiff, summary, _ = run_selftest(SRC)
    if not (code == 0 and ndiff == 0 and summary == (n, 0)):
        print("error: the unchanged selftest did not pass completely (exit %d, summary %s)" % (code, summary))
        return 2
    survivors, errors, rows = 0, 0, []
    for i, line in enumerate(SRC):
        m = LOCK.match(line)
        if not m:
            continue
        mutated = list(SRC)
        mutated[i] = m.group(1) + "if False:  # mutant " + m.group(2)
        code, ndiff, summary, diffs = run_selftest(mutated)
        complete = summary is not None and summary[0] == n and summary[1] == ndiff
        if not complete:
            result = "ERROR"
            errors += 1
        elif code == 1 and ndiff >= 1:
            result = "caught"
        else:
            result = "SURVIVED"
            survivors += 1
        rows.append((m.group(2), i + 1, result, code, ", ".join(diffs) or "-"))
    print("| lock | line | result | selftest exit | cases turned red |")
    print("|---|---|---|---|---|")
    for row in rows:
        print("| %s | %d | %s | %d | %s |" % row)
    print("mutants %d, survived %d, errors %d" % (len(rows), survivors, errors))
    if errors:
        return 2
    return 0 if rows and survivors == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
