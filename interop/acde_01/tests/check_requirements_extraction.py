"""The requirement index is reproducible from the pinned draft copy, when that copy is available.

The draft text is not stored in this repository. Set ACDE01_DRAFT_TXT to the path of the plain-text
copy (SHA-256 2f0356fc...fabf) to re-extract and compare; without it this test is skipped.
"""
from __future__ import annotations

import json
import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "tools"))

import extract_requirements  # noqa: E402

DRAFT = os.environ.get("ACDE01_DRAFT_TXT")


@pytest.mark.skipif(not DRAFT, reason="ACDE01_DRAFT_TXT not set; the draft copy is not stored here")
def test_reextraction_equals_committed_index():
    with open(os.path.join(ROOT, "requirements.json"), encoding="ascii") as fh:
        committed = json.load(fh)
    assert extract_requirements.extract(DRAFT) == committed


@pytest.mark.skipif(not DRAFT, reason="ACDE01_DRAFT_TXT not set")
def test_every_keyword_occurrence_is_in_a_requirement():
    """Upper-case BCP 14 key words outside Section 1.2 all fall inside an extracted sentence."""
    lines = open(DRAFT, encoding="ascii").read().split("\n")
    def at(heading):
        return lines.index(heading)            # the column-0 heading, not the table of contents line
    body = lines[at("1.  Introduction"):at("1.2.  Requirements Language")] + \
        lines[at("2.  Terminology"):at("17.  Normative References")] + \
        lines[at("Illustrative Multi-Target Reconciliation Record"):at("Author's Address")]
    n_doc = len(extract_requirements._KW_RE.findall("\n".join(body)))
    with open(os.path.join(ROOT, "requirements.json"), encoding="ascii") as fh:
        committed = json.load(fh)
    n_req = sum(len(r["keywords"]) for r in committed["requirements"])
    assert n_doc == n_req


def test_refuses_a_different_copy(tmp_path):
    p = tmp_path / "other.txt"
    p.write_bytes(b"not the draft\n")
    with pytest.raises(SystemExit):
        extract_requirements.extract(str(p))
