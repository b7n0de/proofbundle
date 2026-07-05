"""Doc-truth guards — metrics in the docs must not be able to go stale (six-lens review F5/SH4)."""
import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]


class TestDocsTruth(unittest.TestCase):
    def test_readme_carries_no_hardcoded_test_count(self):
        # F5: the README stated "303 tests" while the suite had grown past it. A hardcoded count
        # goes stale on every added test. Removed (not tracked by hand) — this guard keeps it gone:
        # a "<N> tests" phrase in the README is a stale-metric regression.
        readme = (REPO / "README.md").read_text(encoding="utf-8")
        # ignore fenced code blocks (a CLI sample line is not a prose metric)
        prose = re.sub(r"```.*?```", "", readme, flags=re.DOTALL)
        hits = re.findall(r"\b\d+\s+tests?\b", prose, flags=re.IGNORECASE)
        self.assertEqual(hits, [], f"README carries a hardcoded, stale-prone test count: {hits}")


if __name__ == "__main__":
    unittest.main()
