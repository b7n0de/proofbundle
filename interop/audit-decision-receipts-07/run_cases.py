#!/usr/bin/env python3
"""Run a verifier of draft-gruszka-audit-decision-receipts-07 over the starter cases.

Usage:
    python3 run_cases.py [--cases DIR] [--accept-reject] [--timeout SECONDS] -- COMMAND [ARG ...]

For every file cases/<id>.json, in sorted order, the script runs COMMAND ARG ... <path of the case file>
and reads the first line of standard output, which must be one JSON object

    {"result": "pass" | "fail" | "refuse" | "auditor-fail", "step": "<step>" | null}

A case matches when result equals expected.result and, where expected.result is not "pass", step equals
expected.step. With --accept-reject a case matches when the verifier accepts exactly the cases whose
expected.result is "pass"; result "pass" counts as accept, any other result as reject, and the step is not
compared. The exit code of the verifier is not used. The script prints one line per case and a summary, and
exits with 0 only if every case matches. It uses the Python standard library only.

The answer is read strictly: the first line of standard output ends at the first line feed (a carriage return
before it is dropped), must be UTF-8, and must be exactly one JSON object with no member named twice and none of the
non-JSON constants NaN, Infinity and -Infinity. Both members must be there: result one of the four values, step null
for pass and otherwise one of the steps the README names, "3.2 step 1" to "3.2 step 10", "3.3 case 1" to "3.3 case
3", "3.4 step 1" to "3.4 step 7", "3.5 third check" or "4 item N". A verifier that reports no step answers null for
every result; --accept-reject measures it, and by result and step it matches only the cases whose expected result is
pass. Further members are allowed, and a number in them is read without a limit on its digits. What follows the first line feed is not read. Any other first line and an
object nested too deeply to read are no answer and so a mismatch; the run goes on with the next case.
"""
import argparse
import decimal
import json
import math
import os
import re
import subprocess
import sys

RESULTS = ("pass", "fail", "refuse", "auditor-fail")
STEP = re.compile(r"3\.2 step (?:[1-9]|10)|3\.3 case [1-3]|3\.4 step [1-7]|3\.5 third check|4 item [1-9][0-9]*")


def _no_duplicates(pairs):
    names = [name for name, _ in pairs]
    if len(set(names)) != len(names):
        raise ValueError("a member is named twice")
    return dict(pairs)


def _no_constant(name):
    raise ValueError(name + " is not JSON")


def read_answer(stdout):
    line = stdout.split(b"\n", 1)[0]
    if line.endswith(b"\r"):
        line = line[:-1]
    try:
        first = line.decode("utf-8")
    except UnicodeDecodeError:
        return None, "the first line is not UTF-8"
    if not first:
        return None, "no output"
    try:
        ans = json.loads(first, object_pairs_hook=_no_duplicates, parse_constant=_no_constant,
                         parse_int=decimal.Decimal)
    except (ValueError, RecursionError):
        return None, "first line is not one JSON object"
    if not isinstance(ans, dict) or not isinstance(ans.get("result"), str) or ans["result"] not in RESULTS:
        return None, "no valid result"
    if "step" not in ans:
        return None, "no step member"
    step = ans["step"]
    if ans["result"] == "pass":
        if step is not None:
            return None, "step is not null for pass"
    elif step is not None and (not isinstance(step, str) or not STEP.fullmatch(step)):
        return None, "step is not null or one of the steps the README names"
    return (ans["result"], step), ""


def timeout_seconds(value):
    try:
        t = float(value)
    except ValueError:
        raise argparse.ArgumentTypeError("not a number of seconds") from None
    if not (math.isfinite(t) and 0 < t <= 86400):
        raise argparse.ArgumentTypeError("must be above 0 and at most 86400 seconds")
    return t


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--cases", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "cases"))
    ap.add_argument("--accept-reject", action="store_true")
    ap.add_argument("--timeout", type=timeout_seconds, default=60.0)
    ap.add_argument("command", nargs=argparse.REMAINDER)
    a = ap.parse_args()
    cmd = a.command[1:] if a.command[:1] == ["--"] else a.command
    if not cmd:
        ap.error("give the verifier command after --")

    files = sorted(f for f in os.listdir(a.cases) if f.endswith(".json"))
    if not files:
        print("no cases found in " + a.cases)
        return 1
    rows = []
    for f in files:
        path = os.path.join(a.cases, f)
        with open(path, encoding="utf-8") as fh:
            case = json.load(fh)
        exp = case["expected"]
        try:
            p = subprocess.run(cmd + [path], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               timeout=a.timeout)
            got, why = read_answer(p.stdout)
        except subprocess.TimeoutExpired:
            got, why = None, "timeout"
        except OSError as e:
            got, why = None, "cannot run verifier: " + e.strerror
        if got is None:
            ok = False
        elif a.accept_reject:
            ok = (got[0] == "pass") == (exp["result"] == "pass")
        else:
            ok = got[0] == exp["result"] and (exp["result"] == "pass" or got[1] == exp["step"])
        want = exp["result"] + ("" if exp["step"] is None else " at " + exp["step"])
        if got is None:
            have = "(" + why + ")"
        else:
            have = got[0] + ("" if got[1] is None else " at " + got[1])
        rows.append((case["id"], want, have, "ok" if ok else "MISMATCH"))

    w = [max(len(r[i]) for r in rows + [("case", "expected", "verifier", "match")]) for i in range(4)]
    head = ("case", "expected", "verifier", "match")
    print("  ".join(h.ljust(w[i]) for i, h in enumerate(head)))
    for r in rows:
        print("  ".join(c.ljust(w[i]) for i, c in enumerate(r)))
    bad = [r[0] for r in rows if r[3] != "ok"]
    mode = "accept/reject" if a.accept_reject else "result and step"
    print("%d of %d cases match (%s)" % (len(rows) - len(bad), len(rows), mode))
    if bad:
        print("mismatch: " + ", ".join(bad))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
