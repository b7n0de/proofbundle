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
        # third-party MarkovianProtocol anchor implementations legitimately carry the external contributor's
        # name in their OWN files: markovian-provenance/v1 (PR #18, anchors_markovian.py) and the rootcommit
        # v1+v2-sig verifier (corpus 9034202, anchors_rootcommit.py). Those files are exempt (they credit the
        # external contributor); the guard still catches the codename appearing anywhere it does not belong.
        _exempt = ("markovian", "rootcommit")   # MarkovianProtocol third-party anchor implementation files
        for base in ("src", "docs", "examples"):
            for path in (ROOT / base).rglob("*"):
                if (path.is_file() and path.suffix in (".py", ".md", ".json")
                        and not any(tok in path.name.lower() for tok in _exempt)):
                    self.assertNotIn("Markovian", path.read_text(encoding="utf-8", errors="ignore"),
                                     f"codename 'Markovian' leaked into {path.relative_to(ROOT)}")

    def test_intoto_status_is_labelled_proposed(self):
        # The profile doc must state the honest status, not imply standardization.
        text = (ROOT / "docs" / "IN_TOTO_PROFILE.md").read_text(encoding="utf-8")
        self.assertIn("PROPOSED", text)
        self.assertIn("not standardized", text.lower())


if __name__ == "__main__":
    unittest.main()
