"""Claims hygiene for the chia-datalayer/v1 surface — makes docs/ANCHORS.md's "forbidden claims" line a
REAL, enforced control (No-Fake: the mechanism that claims to catch overclaims must itself exist). The
chia-specific overclaims — "trustless"/"on-chain proven" for level i/ii, any "greener chain" comparison,
any XCH price claim — must never appear UN-caveated on this surface.

Exoneration (mirrors scripts/claims_hygiene_check.py): a match on a line that also carries a negation/caveat
marker ("forbidden", "never", "not", "no ", "own" [as in level-iii "your own node = trustless"], "caveat",
"observation", "inference") is allowed — that is the honest, documented usage, not an overclaim."""
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent

_SURFACE = [
    ROOT / "docs" / "ANCHORS.md",
    ROOT / "src" / "proofbundle" / "anchors_chia.py",
    ROOT / "src" / "proofbundle" / "anchors_chia_add.py",
    *sorted((ROOT / "examples" / "anchors").glob("chia-datalayer-*.json")),
]

_FORBIDDEN = [
    re.compile(r"\btrustless\b", re.I),
    re.compile(r"\bon-chain proven\b", re.I),
    re.compile(r"\bgreener chain\b", re.I),
    # an XCH amount presented as money/price (e.g. "0.0005 XCH, worth $0.02") — a bare fee observation is fine
    re.compile(r"XCH\b[^\n]*(?:\$|\bworth\b|\bprice\b|\bcosts?\b[^\n]*\$)", re.I),
]

_EXONERATE = re.compile(r"\b(?:forbidden|never|not|no|own|caveat|observation|inference|deliberately)\b", re.I)


class TestChiaClaimsHygiene(unittest.TestCase):
    def test_no_uncaveated_overclaim_on_the_chia_surface(self):
        for path in _SURFACE:
            lines = path.read_text(encoding="utf-8").splitlines()
            for i, line in enumerate(lines):
                for pat in _FORBIDDEN:
                    # a caveat/negation may sit on the wrapped continuation (or prior) line → 3-line window
                    window = " ".join(lines[max(0, i - 1):i + 2])
                    if pat.search(line) and not _EXONERATE.search(window):
                        self.fail(f"{path.name}:{i + 1} un-caveated overclaim "
                                  f"matching {pat.pattern!r}: {line.strip()!r}")

    def test_markovian_absent_on_chia_surface(self):
        for path in _SURFACE:
            self.assertNotIn("markovian", path.read_text(encoding="utf-8").lower(),
                             f"codename Markovian must not appear in {path.name}")


if __name__ == "__main__":
    unittest.main()
