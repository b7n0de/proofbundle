"""A sentence about the statements released versions wrote says what was read, not every statement there is.

Before the tag v6.5.0 (step 982 of the release plan): docs/IN_TOTO_PROFILE.md, the CHANGELOG entries of the predicate
sweep, a comment of intoto.py and the docstrings of three tests said that every statement a released version wrote
keeps verifying. What was read is the writer of 6.4.0 and the 14 entries of tests/fixtures/eval_result_v0_1/corpus.json;
a statement a caller built with the public builders from a value of its own is not covered. Measured with the builders
of 6.3.0 against this tree: `to_test_result_statement` and `to_eval_result_statement` with a caller's sha256 digest in
capitals, of 63 characters or with a `sha256:` prefix gave statements that verified at 6.3.0 and do not verify since
the Statement rule of 2026-10-17 (6.3.1). The guard keeps the wide form out of the files that speak for this release:
the sources, the tests, the documentation and the unreleased section of the CHANGELOG. Released sections are history
and stay as they were.
"""
from __future__ import annotations

import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent
#: The wide form, in the spellings the tree used: every statement a released version wrote, and an attestation that
#: released versions wrote giving the same verdict as before.
_WIDE = re.compile(r"every\s+statement\s+a\s+released\s+version\s+wrote"
                   r"|attestations?\s+that\s+released\s+versions\s+wrote\s+gives?\s+the\s+same\s+verdict", re.IGNORECASE)


def _unreleased(changelog: str) -> str:
    """The text of the [Unreleased] section, up to the next level-two heading."""
    start = changelog.index("## [Unreleased]")
    end = changelog.find("\n## ", start + 1)
    return changelog[start:] if end < 0 else changelog[start:end]


def _texts() -> dict[str, str]:
    found = {}
    for folder, pattern in (("src", "*.py"), ("tests", "*.py"), ("docs", "*.md")):
        for path in sorted((ROOT / folder).rglob(pattern)):
            if path.resolve() != pathlib.Path(__file__).resolve():
                found[str(path.relative_to(ROOT))] = path.read_text(encoding="utf-8", errors="replace")
    found["CHANGELOG.md [Unreleased]"] = _unreleased((ROOT / "CHANGELOG.md").read_text(encoding="utf-8"))
    return found


def test_no_file_that_speaks_for_this_release_claims_every_statement_a_released_version_wrote():
    wide = [f"{name}: {m.group(0)!r}" for name, text in _texts().items() for m in _WIDE.finditer(text)]
    assert not wide, wide


def test_control_the_guard_finds_the_wide_form_across_a_line_end():
    assert _WIDE.search("so the Statement of every statement a released\nversion wrote verifies")
    assert _WIDE.search("verifying an SVR attestation\nthat released versions wrote gives the same verdict as before")
    assert not _WIDE.search("the 14 bundled corpus statements keep verifying")
