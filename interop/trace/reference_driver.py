"""Runs the TRACE reference verifier on a batch of cases. Executed ONLY by the reference interpreter.

This file is the one place that calls ``agentrust_trace``. It is started as a separate process by
``compare.py`` with ``python -I``, so the reference never shares an interpreter with proofbundle and
proofbundle's verifier never imports the reference.

Input, one JSON object per line on stdin: ``id``, ``raw_b64`` (the exact record bytes), ``jwk`` (the
relying party's key), ``now``, ``max_age_seconds``, ``max_future_skew_seconds``, ``expected_nonce``,
``accepted_profiles``. Output, one JSON object per line on stdout: ``id``, ``verdict`` (``accept`` or
``reject``), ``exception`` (class name), ``detail`` (message, truncated).

THE INPUT PATH IS STATED, because the reference has no byte-level API: the bytes are parsed with
``json.loads`` exactly as a caller of ``verify_record`` would, and the resulting object is passed on.
A duplicate member therefore reaches the reference as the LAST occurrence, which is ``json.loads``'s
behaviour, not something this driver chose.
"""
import base64
import json
import sys
import warnings

import agentrust_trace
from agentrust_trace import verify_record


def run(case):
    raw = base64.b64decode(case["raw_b64"])
    try:
        record = json.loads(raw)
    except Exception as exc:  # the reference never sees bytes it cannot parse
        return "reject", type(exc).__name__, str(exc)[:300]
    kwargs = {"now": case["now"], "max_future_skew_seconds": case["max_future_skew_seconds"],
              "max_age_seconds": case["max_age_seconds"]}
    if case.get("expected_nonce") is not None:
        kwargs["expected_nonce"] = case["expected_nonce"]
    if case.get("accepted_profiles") is not None:
        kwargs["accepted_profiles"] = case["accepted_profiles"]
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        try:
            verify_record(record, case["jwk"], **kwargs)
        except Exception as exc:
            return "reject", type(exc).__name__, str(exc)[:300]
    return "accept", None, None


def main():
    sys.stdout.write(json.dumps({"id": "__reference__", "version": agentrust_trace.__version__}) + "\n")
    for line in sys.stdin:
        if not line.strip():
            continue
        case = json.loads(line)
        verdict, exc, detail = run(case)
        sys.stdout.write(json.dumps({"id": case["id"], "verdict": verdict, "exception": exc,
                                     "detail": detail}) + "\n")


if __name__ == "__main__":
    main()
