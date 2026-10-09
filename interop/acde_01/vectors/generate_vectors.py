"""Write vectors/acde01_vectors.json from build.py. Deterministic: the same code gives the same bytes.

Usage: python vectors/generate_vectors.py [--check]
--check compares the committed file with a fresh generation and exits 1 on any difference.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import build  # noqa: E402
import vectorfile  # noqa: E402

OUT = os.path.join(HERE, "acde01_vectors.json")


def compact(vec, bp, bf):
    v = dict(vec)
    t, inp = v["type"], v["input"]
    if t == "profile":
        v["input"] = {"profile_patch": vectorfile.make_patch(bp, inp)}
        assert vectorfile.merge_patch(bp, v["input"]["profile_patch"]) == inp
    elif t == "run":
        v["input"] = vectorfile.compact_run(inp, bp, bf)
    elif t == "versions":
        v["input"] = {"run": vectorfile.compact_run(inp["run"], bp, bf), "cutoffs": inp["cutoffs"]}
    elif t in ("report_check", "render_check") and "from_run" in inp:
        v["input"] = dict(inp, from_run=vectorfile.compact_run(inp["from_run"], bp, bf))
    return v


def render() -> bytes:
    vs = build.all_vectors()
    bp, bf = build.example_profile(), build.frozen()
    head = {"draft": "draft-abak-agent-control-delivery-evidence-01",
            "draft_sha256": "2f0356fcb834ba6b80970721273cd8e2e0b2cc19ef1f89a0205a78991653fabf",
            "note": "Derived from the draft text alone. Not a wire format. Each vector input is a JSON Merge "
                    "Patch (RFC 7396) against base_profile and base_frozen; see README.md.",
            "base_profile": bp, "base_frozen": bf, "vector_count": len(vs)}
    dump = lambda x: json.dumps(x, separators=(",", ":"), ensure_ascii=True)  # noqa: E731
    parts = [dump(head)[:-1] + ',\n"vectors":[\n']
    parts.append(",\n".join(dump(compact(v, bp, bf)) for v in vs))
    parts.append("\n]}\n")
    return "".join(parts).encode("ascii")


def main(argv):
    data = render()
    if "--check" in argv:
        with open(OUT, "rb") as fh:
            same = fh.read() == data
        print("vectors file up to date" if same else "vectors file differs from a fresh generation")
        return 0 if same else 1
    with open(OUT, "wb") as fh:
        fh.write(data)
    print(f"wrote {OUT} ({len(data)} bytes, sha256 {hashlib.sha256(data).hexdigest()})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
