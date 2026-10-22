"""The requirement index is reproducible from the pinned draft copy, when that copy is available.

The draft text is not stored in this repository. Set EQR00_DRAFT_TXT to the path of the plain-text copy
(SHA-256 e9d47a64...bd5d) to re-extract and compare; without it these tests are skipped.
"""
from __future__ import annotations

import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path[:0] = [ROOT, os.path.join(ROOT, "tools")]

import extract_requirements  # noqa: E402
from eqr00.wire import decode_json  # noqa: E402

DRAFT = os.environ.get("EQR00_DRAFT_TXT")


def _committed():
    with open(os.path.join(ROOT, "requirements.json"), "rb") as fh:
        return decode_json(fh.read())


@pytest.mark.skipif(not DRAFT, reason="EQR00_DRAFT_TXT not set; the draft copy is not stored here")
def test_reextraction_equals_committed_index():
    assert extract_requirements.extract(DRAFT) == _committed()


@pytest.mark.skipif(not DRAFT, reason="EQR00_DRAFT_TXT not set")
def test_every_keyword_occurrence_outside_the_convention_is_in_a_requirement():
    """Upper-case BCP 14 key words in the body all fall inside an extracted sentence, except the six of the
    key-word convention in Section 2."""
    lines = open(DRAFT, encoding="ascii").read().split("\n")
    body = lines[lines.index("1.  Introduction"):lines.index("19.  Normative References")]
    n_doc = len(extract_requirements._KW_RE.findall("\n".join(body)))
    n_req = sum(len(r["keywords"]) for r in _committed()["requirements"])
    assert n_doc == n_req + 6


def test_refuses_a_different_copy(tmp_path):
    p = tmp_path / "other.txt"
    p.write_bytes(b"not the draft\n")
    with pytest.raises(SystemExit):
        extract_requirements.extract(str(p))
