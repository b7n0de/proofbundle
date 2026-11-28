"""docs/NON_CLAIMS.md states what a timestamp does and does not show.

A trusted timestamp (RFC 3161, OpenTimestamps) shows that the stamped bytes existed no later than its
time T. It does not show from when a revocation takes effect. Measured on 19cadafc: the page named
time anchors only as optional and as producer-clock testimony without them, and said nothing about
revocation.
"""
from __future__ import annotations

import re
from pathlib import Path

PAGE = Path(__file__).resolve().parents[1] / "docs" / "NON_CLAIMS.md"


def _negative_list() -> str:
    text = PAGE.read_text(encoding="utf-8")
    start = text.index("does **not** prove:")
    end = text.index("It also does **not**:")
    return " ".join(text[start:end].split())


def test_the_negative_list_bounds_what_a_timestamp_shows():
    items = _negative_list()
    assert re.search(r"stamped bytes existed no later than its time T", items), items
    assert re.search(r"not from when a revocation takes effect", items), items
