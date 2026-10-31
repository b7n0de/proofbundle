"""The repository's own marketplace file, .claude-plugin/marketplace.json.

It lists the plugins under plugins/ so they can be installed from this repository once they land. It
publishes nothing. Since D134 it has two entries: proofbundle, the verifier everyone installs, and
proofbundle-guard, the Guard of the house.

Property checked: the marketplace names exactly the fields a marketplace needs, and each entry points at
the plugin folder whose manifest carries the same name.
"""
from __future__ import annotations

import json
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent


def test_the_marketplace_lists_this_plugin_and_publishes_nothing():
    market = json.loads((ROOT / ".claude-plugin" / "marketplace.json").read_text(encoding="utf-8"))
    assert set(market) == {"name", "owner", "description", "plugins"}
    assert market["owner"]["name"]
    entries = market["plugins"]
    assert [e["source"] for e in entries] == ["./plugins/proofbundle", "./plugins/proofbundle-guard"]
    for entry, name in zip(entries, ("proofbundle", "proofbundle-guard"), strict=True):
        manifest = json.loads((ROOT / entry["source"] / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8"))
        assert entry["name"] == manifest["name"] == name
