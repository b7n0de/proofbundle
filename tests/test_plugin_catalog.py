"""The plugin catalog (plugins/README.md) and the two places the repository README points at it.

Owner decision of 2026-09-29: one catalog lists every plugin, one row per host, with what it does, a
link, the version and the maturity; the repository README names no single plugin and links the catalog
from one task row and from the documentation row on integration.

Properties checked:
- every host manifest under plugins/ has exactly one catalog row, and every row has a manifest;
- a row's version is the version in that host's manifest, read from the file, not typed twice;
- a row's maturity is copied from the status line of the plugin's own README, never written apart
  from it, and the Codex hook run is marked as not yet measured there until it is measured;
- every link in the catalog resolves to a file in the tree;
- the catalog states the verification limit: a pass proves integrity, not truth;
- the repository README links the catalog from the task table and from the integration row, with the
  absolute URL form it uses everywhere, and names no plugin folder.
"""
from __future__ import annotations

import json
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
PLUGINS = ROOT / "plugins"
CATALOG = PLUGINS / "README.md"
REPO_README = ROOT / "README.md"
CATALOG_URL = "https://github.com/b7n0de/proofbundle/blob/main/plugins/README.md"
#: The manifest folder of each host, as the plugin folder carries it.
HOSTS = {"Claude Code": ".claude-plugin", "Codex": ".codex-plugin"}
STATUS_PREFIX = "**Status** · "


def _catalog_rows() -> list[dict]:
    lines = CATALOG.read_text(encoding="utf-8").split("\n")
    start = lines.index("| Host | What it does | Plugin | Version | Maturity |")
    assert lines[start + 1] == "|---|---|---|---|---|"
    rows = []
    for line in lines[start + 2:]:
        if not line.startswith("| "):
            break
        cells = [c.strip() for c in line.strip().strip("|").split(" | ")]
        assert len(cells) == 5, line
        link = re.fullmatch(r"\[([^\]]+)\]\(([^)]+)\)", cells[2])
        assert link, cells[2]
        rows.append({"host": cells[0], "what": cells[1], "name": link.group(1), "href": link.group(2),
                     "version": cells[3], "maturity": cells[4]})
    return rows


def _status(plugin_dir: pathlib.Path) -> dict[str, str]:
    lines = [ln for ln in (plugin_dir / "README.md").read_text(encoding="utf-8").split("\n")
             if ln.startswith(STATUS_PREFIX)]
    assert len(lines) == 1, "the plugin README carries exactly one status line"
    entries = {}
    for part in lines[0][len(STATUS_PREFIX):].split(" · "):
        host, _, value = part.partition(": ")
        assert host and value, part
        entries[host] = value
    return entries


def _manifests() -> set[tuple[str, str]]:
    found = set()
    for plugin_dir in sorted(p for p in PLUGINS.iterdir() if p.is_dir()):
        for host, folder in HOSTS.items():
            if (plugin_dir / folder / "plugin.json").is_file():
                found.add((plugin_dir.name, host))
    return found


def test_every_host_manifest_has_one_row_and_every_row_a_manifest():
    rows = _catalog_rows()
    listed = [((PLUGINS / r["href"]).parent.name, r["host"]) for r in rows]
    assert len(listed) == len(set(listed)), "a plugin is listed twice for one host"
    assert set(listed) == _manifests()


def test_a_row_names_the_version_of_its_host_manifest():
    for r in _catalog_rows():
        manifest = (PLUGINS / r["href"]).parent / HOSTS[r["host"]] / "plugin.json"
        data = json.loads(manifest.read_text(encoding="utf-8"))
        assert r["version"] == data["version"], (r["host"], r["version"], data["version"])
        assert r["name"] == data["name"]


def test_a_rows_maturity_is_the_plugin_readmes_status_for_that_host():
    for r in _catalog_rows():
        status = _status((PLUGINS / r["href"]).parent)
        assert r["maturity"] == status[r["host"]], (r["host"], r["maturity"], status)
    codex = _status(PLUGINS / "proofbundle")["Codex"]
    assert "not yet measured" in codex, "the Codex hook run stays marked until the owner's run"


def test_every_catalog_link_resolves():
    text = CATALOG.read_text(encoding="utf-8")
    for target in re.findall(r"\]\(([^)]+)\)", text):
        if target.startswith(("http://", "https://", "#")):
            continue
        assert (CATALOG.parent / target.split("#", 1)[0]).resolve().is_file(), target


def test_the_catalog_states_what_a_pass_proves():
    text = " ".join(CATALOG.read_text(encoding="utf-8").split())
    assert "not that any recorded value is true" in text


def test_the_readme_links_the_catalog_twice_and_names_no_plugin_folder():
    text = REPO_README.read_text(encoding="utf-8")
    task_rows = [ln for ln in text.split("\n") if ln.startswith("| Gate a push or pull request from an AI coding agent |")]
    assert len(task_rows) == 1 and CATALOG_URL in task_rows[0]
    integration = [ln for ln in text.split("\n") if ln.startswith("| How do I integrate my workflow? |")]
    assert len(integration) == 1 and CATALOG_URL in integration[0]
    assert "plugins/proofbundle" not in text
