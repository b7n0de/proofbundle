"""The repository's own marketplace file, .claude-plugin/marketplace.json.

It lists the one plugin everyone may install, proofbundle, so it can be installed from this repository once
it lands. It publishes nothing. Since D134 (owner choice N2 B) the Guard, proofbundle-guard, is in no public
catalog: its folder carries a house marketplace of its own, which the owner's machines add from a checkout.

Property checked: each marketplace names exactly the fields a marketplace needs, and its one entry points at
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
    (entry,) = market["plugins"]
    assert entry["source"] == "./plugins/proofbundle"
    manifest = json.loads((ROOT / entry["source"] / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8"))
    assert entry["name"] == manifest["name"] == "proofbundle"


def test_the_guard_has_a_house_marketplace_of_its_own_and_no_public_entry():
    folder = ROOT / "plugins" / "proofbundle-guard"
    house = json.loads((folder / ".claude-plugin" / "marketplace.json").read_text(encoding="utf-8"))
    assert set(house) == {"name", "owner", "description", "plugins"} and house["owner"]["name"]
    (entry,) = house["plugins"]
    assert entry["source"] == "./"
    manifest = json.loads((folder / ".claude-plugin" / "plugin.json").read_text(encoding="utf-8"))
    assert entry["name"] == manifest["name"] == "proofbundle-guard"
    public = json.loads((ROOT / ".claude-plugin" / "marketplace.json").read_text(encoding="utf-8"))
    assert house["name"] != public["name"]
