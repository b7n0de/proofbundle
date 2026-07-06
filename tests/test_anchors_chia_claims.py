"""Claims hygiene for the chia-datalayer/v1 surface — makes docs/ANCHORS.md's "forbidden claims" line a
REAL, enforced control (No-Fake: the mechanism that claims to catch overclaims must itself work). The
chia-specific overclaims — "trustless"/"on-chain proven" for level i/ii, any "greener chain" comparison,
any XCH price claim — must never appear un-caveated on this surface.

Hardened after the 6-lens review (2026-07-06). The previous check exonerated a match whenever a bare token
(no/not/own) sat anywhere in a blind plus-minus-one-line window, which silently let a real overclaim
through about 44% of the time (measured by injecting an un-caveated "trustless ... on-chain proven"
sentence at every position of ANCHORS.md). Now exoneration is SENTENCE-scoped and reuses the canonical
scripts/claims_hygiene_check.py engine (code-fence stripping, sentence boundaries, negation set) so there
is one honest engine, plus a small allowlist for the level-iii "your own = trustless" phrasing whose
sentence deliberately carries no negation. The XCH-price pattern now matches in EITHER token order."""
import pathlib
import re
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from claims_hygiene_check import _strip_code  # noqa: E402 - needs sys.path above; SSOT code-fence engine

# Sentence boundary = end punctuation (.!?) OR a blank line (paragraph break). A SINGLE newline is a soft
# wrap, NOT a boundary — ANCHORS.md wraps one logical sentence across several lines, so the caveat
# ("... not producible with standard tooling", "... without the node-trust caveat") sits on a continuation
# line; a newline-as-boundary scoper (the canonical _sentence_around) would split it off and false-positive.
_BOUNDARY = re.compile(r"[.!?]|\n[ \t]*\n")


def _logical_sentence(text: str, start: int, end: int) -> str:
    """The logical sentence containing [start,end), soft-wrap aware (single newline = space, not a break)."""
    left = 0
    for m in _BOUNDARY.finditer(text, 0, start):
        left = m.end()
    rm = _BOUNDARY.search(text, end)
    right = rm.start() if rm else len(text)
    return text[left:right]

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
    # an XCH amount presented as money/price, in EITHER token order (currency before OR after XCH on the
    # same line). A bare fee observation without a currency token is fine.
    re.compile(r"\bXCH\b[^\n]*(?:\$|\bworth\b|\bprice\b|\bcosts?\b)"
               r"|(?:\$|\bworth\b|\bprice\b|\bcosts?\b)[^\n]*\bXCH\b", re.I),
]

# Caveat markers that make a level-i/ii mention honest. The bare high-frequency tokens no/not/own are
# DELIBERATELY excluded (the 6-lens finding: they exonerated ~44% of injected overclaims via a neighbouring
# clause); only caveat-specific phrasings count, so a nearby unrelated "no"/"not" cannot launder an
# overclaim. The legit negations the docs actually use ("does not prove", "without the node-trust caveat",
# "is not producible") are all covered here.
_CAVEAT = re.compile(
    r"\b(?:without|never|forbidden|caveat|observation|inference|deliberately|"
    r"does\s+not|do\s+not|is\s+not|are\s+not|was\s+not|not\s+prove|node[- ]trust|"
    r"pure\s+sha|offline|inclusion[- ]only)\b", re.I)

# The two documented-legit phrasings the chia docs deliberately carry (belt-and-suspenders next to _CAVEAT):
# level iii "the practical trust anchor is a full node (your own = trustless)" and the Paket-4 clause.
_ALLOWLIST = ("your own = trustless", "not producible with standard tooling")


def _violations(raw: str) -> list[tuple[int, str, str]]:
    """Sentence-scoped scan: a forbidden match is a violation unless its OWN sentence is negated
    (canonical _NEGATION_RE) or the sentence carries an allowlisted legit phrasing."""
    text = _strip_code(raw)
    out: list[tuple[int, str, str]] = []
    for pat in _FORBIDDEN:
        for m in pat.finditer(text):
            sentence = _logical_sentence(text, m.start(), m.end())
            if _CAVEAT.search(sentence):
                continue
            if any(a in sentence.lower() for a in _ALLOWLIST):
                continue
            line = raw.count("\n", 0, m.start()) + 1
            out.append((line, pat.pattern, sentence.strip()[:120]))
    return out


class TestChiaClaimsHygiene(unittest.TestCase):
    def test_no_uncaveated_overclaim_on_the_chia_surface(self):
        for path in _SURFACE:
            v = _violations(path.read_text(encoding="utf-8"))
            self.assertEqual(v, [], f"{path.name}: un-caveated overclaim(s): {v}")

    def test_markovian_absent_on_chia_surface(self):
        for path in _SURFACE:
            self.assertNotIn("markovian", path.read_text(encoding="utf-8").lower(),
                             f"codename Markovian must not appear in {path.name}")

    def test_gate_has_teeth_catches_injected_overclaim(self):
        """Anti-tautology / regression: an un-caveated overclaim of each forbidden class MUST be caught —
        the exact false-assurance gap the 6-lens review found (a green gate that catches nothing)."""
        for evil in ("The chia-datalayer anchor delivers on-chain proven, trustless guarantees.",
                     "Each anchor costs about $0.02, a few thousandths of an XCH.",
                     "At roughly $30 per XCH the fee is negligible.",
                     "proofbundle anchors to a greener chain than Bitcoin."):
            self.assertTrue(_violations(evil), f"gate failed to catch un-caveated overclaim: {evil!r}")

    def test_negated_and_allowlisted_usages_pass(self):
        """The documented honest usages must NOT trip the gate (no false positives)."""
        for ok in ("This does not prove the chain binding, so it is not trustless.",
                   "Forbidden: 'trustless' or 'on-chain proven' without the node-trust caveat.",
                   "the practical trust anchor is a full node (your own = trustless)."):
            self.assertEqual(_violations(ok), [], f"false positive on honest usage: {ok!r}")


if __name__ == "__main__":
    unittest.main()
