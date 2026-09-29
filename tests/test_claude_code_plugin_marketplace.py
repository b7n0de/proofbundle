"""The repository's own marketplace file, .claude-plugin/marketplace.json.

It lists the one plugin under plugins/ so the plugin can be installed from this repository once it
lands. It publishes nothing.

Property checked: the marketplace names exactly the fields a marketplace needs, and its one entry
points at the plugin folder whose manifest carries the same name.
"""
from __future__ import annotations

import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent


def test_the_marketplace_lists_this_plugin_and_publishes_nothing():
    market = json.loads((ROOT / ".claude-plugin" / "marketplace.json").read_text(encoding="utf-8"))
    assert set(market) == {"name", "owner", "description", "plugins"}
    assert market["owner"]["name"]
    (entry,) = market["plugins"]
    assert entry["source"] == "./plugins/claude-code"
    manifest = json.loads((ROOT / entry["source"] / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8"))
    assert entry["name"] == manifest["name"] == "proofbundle"
