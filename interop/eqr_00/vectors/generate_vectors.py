"""Write vectors/eqr00_vectors.json from build.py. Deterministic: the same code gives the same bytes
(Ed25519 signatures are deterministic, RFC 8032).

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

OUT = os.path.join(HERE, "eqr00_vectors.json")


def render() -> bytes:
    vs = build.all_vectors()
    head = {"draft": "draft-watts-agent-evidence-boundary-00",
            "draft_sha256": "e9d47a647af3d1474f3c4fdcc286d6dae3d60a2a378e1f86741e4e95cb81bd5d",
            "note": "Derived from the draft text alone. Signed receipts are JWS compact with EdDSA over Ed25519 under "
                    "test keys derived from fixed labels; only their public keys appear. See README.md.",
            "vector_count": len(vs)}
    dump = lambda x: json.dumps(x, separators=(",", ":"), ensure_ascii=True, sort_keys=True)  # noqa: E731
    parts = [dump(head)[:-1] + ',\n"vectors":[\n', ",\n".join(dump(v) for v in vs), "\n]}\n"]
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
