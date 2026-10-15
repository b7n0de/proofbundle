"""Strict JSON for the vector files of this directory: a duplicate member name is a refusal, never a last-wins.

The vector files are evidence: `nachrechnen.py` recomputes them, `mint_indefinite.py` mints vector D from them
and `reader_matrix.py` feeds them to the libraries it measures. `json.load` keeps the LAST of two members with
one name, so a doubled `bytes_hex` would decide silently which bytes are recomputed (the repository's
strict decoding rule of 2026-10-14). Standard library only, like the rest of this directory.
"""
from __future__ import annotations

import json
from pathlib import Path


def _reject_duplicate_keys(pairs: list) -> dict:
    out: dict = {}
    for name, value in pairs:
        if name in out:
            raise ValueError(f"duplicate member name {name!r} in one JSON object, refused")
        out[name] = value
    return out


def load_json(path: Path):
    """The JSON value in the file at `path`, read strictly."""
    with open(path, encoding="utf-8") as f:
        return json.load(f, object_pairs_hook=_reject_duplicate_keys)
