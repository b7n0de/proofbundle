"""O4 claims hygiene for the in-toto surface: the new docs, examples, and source must not overclaim
(no 'standardized/official/proves-truth/guarantees' outside an explicit negation), and the codename
'Markovian' must appear NOWHERE in code, docs, or examples (it lives only in private notes)."""
import pathlib
import re
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent

# The in-toto surface this test governs (docs + examples + the export source).
_SURFACE = [
    ROOT / "docs" / "IN_TOTO_PROFILE.md",
    ROOT / "docs" / "NON_CLAIMS.md",
    ROOT / "src" / "proofbundle" / "intoto.py",
    *sorted((ROOT / "examples" / "intoto").glob("*.json")),
]

# Positive overclaims that must never appear. Each is checked as a whole phrase; the docs use the
# NEGATED forms ("not standardized", "PROPOSED, not standardized"), which these patterns do not match.
_FORBIDDEN = [
    re.compile(r"\bis standardized\b", re.I),
    re.compile(r"\bnow (?:an )?official\b", re.I),
    re.compile(r"\bproves (?:the |that the )?(?:result|number|score) is (?:true|correct)\b", re.I),
    re.compile(r"\bguarantees (?:safety|fairness|correctness)\b", re.I),
    re.compile(r"\bcertified (?:safe|fair|correct)\b", re.I),
]


class TestIntotoClaimsHygiene(unittest.TestCase):
    def test_no_overclaim_phrase_on_the_intoto_surface(self):
        for path in _SURFACE:
            text = path.read_text(encoding="utf-8")
            for pat in _FORBIDDEN:
                self.assertIsNone(pat.search(text),
                                  f"{path.name} contains a forbidden overclaim matching {pat.pattern!r}")

    def test_codename_markovian_absent_everywhere(self):
        # O4: the internal codename must not LEAK into an unrelated shipped artifact. The public
        # `markovian-provenance/v1` third-party anchor (external contributor MarkovianProtocol, PR #18)
        # legitimately carries the name in its OWN files, so those are exempt; the guard still catches the
        # name appearing anywhere it does not belong.
        for base in ("src", "docs", "examples"):
            for path in (ROOT / base).rglob("*"):
                if (path.is_file() and path.suffix in (".py", ".md", ".json")
                        and "markovian" not in path.name.lower()):
                    self.assertNotIn("Markovian", path.read_text(encoding="utf-8", errors="ignore"),
                                     f"codename 'Markovian' leaked into {path.relative_to(ROOT)}")

    def test_intoto_status_is_labelled_proposed(self):
        # The profile doc must state the honest status, not imply standardization.
        text = (ROOT / "docs" / "IN_TOTO_PROFILE.md").read_text(encoding="utf-8")
        self.assertIn("PROPOSED", text)
        self.assertIn("not standardized", text.lower())


if __name__ == "__main__":
    unittest.main()
