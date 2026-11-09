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
"""
import argparse
import json
import os
import subprocess
import sys

RESULTS = ("pass", "fail", "refuse", "auditor-fail")


def read_answer(stdout):
    lines = stdout.decode("utf-8", "replace").splitlines()
    if not lines:
        return None, "no output"
    try:
        ans = json.loads(lines[0])
    except ValueError:
        return None, "first line is not JSON"
    if not isinstance(ans, dict) or ans.get("result") not in RESULTS:
        return None, "no valid result"
    step = ans.get("step")
    if step is not None and not isinstance(step, str):
        return None, "step is not a string or null"
    return (ans["result"], step), ""


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--cases", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "cases"))
    ap.add_argument("--accept-reject", action="store_true")
    ap.add_argument("--timeout", type=float, default=60.0)
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
