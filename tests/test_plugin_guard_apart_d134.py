"""D134: the Guard is a plugin of its own, proofbundle-guard; proofbundle is the verifier everyone gets (owner choice F2 A).

The owner, 2026-10-31, on the release plan of plugin 0.4.0: separate them, the Guard only at the house. The reason in
the choice: the Guard runs before every Bash call and blocks every call when its program cannot run (`|| exit 2` in
the hook command), and --autonomous carries house rules (D85, D87, D93, D111) that say nothing to anyone else.

Measured with Claude Code 2.1.314 in a throwaway CLAUDE_CONFIG_DIR, from a local marketplace (2026-10-31): a hooks
field in plugin.json merges with hooks/hooks.json, and an entry with empty inline hooks still installs the six hook
events of the file. Only a plugin folder without hooks/hooks.json installs no hook. So the house's hooks live in a
second plugin folder, plugins/proofbundle-guard, listed as a second entry of the marketplace. Its programs and its
server are byte-equal copies of those of plugins/proofbundle, never links: Codex drops a link on install
(core-plugins/src/store.rs, as tests/test_codex_plugin.py records it), so a linked gate would be missing there and
every hook would block its call.

The properties held here, read from the marketplace and the two plugin folders:
- `claude plugin install proofbundle@proofbundle` and `codex plugin add proofbundle@proofbundle` register no hook: the
  entry's folder has no hooks/hooks.json, neither host manifest of it carries "hooks", and the entry adds none;
- the entry proofbundle-guard registers the house profile: a PreToolUse hook on Bash under Claude Code that starts
  the gate with --autonomous, and one under Codex that starts it with --host codex;
- every program a hook of the Guard starts is there in its folder as a regular file, byte-equal to the file of
  plugins/proofbundle/hooks, and so is the server the gate starts;
- the Guard folder adds no skill and no MCP server, so the house, which installs both, gets each once;
- each entry's name is its manifest's name, and both plugins carry one version.
Red at 193a66b9, where plugins/proofbundle registers the hooks and the marketplace has one entry.

Owner choice N2 B on delivery -2 of the release plan (2026-10-31): the Guard is in no public catalog. The public
marketplace lists proofbundle alone; the owner's machines add a house marketplace from a checkout, at the Guard's folder,
whose one entry has the source "./" (measured valid by delivery -2 with Claude Code 2.1.316). The source stays public.
Red at cebb7961 for that case, where the public marketplace lists the Guard as a second entry.
"""
from __future__ import annotations

import importlib.util
import json
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
MARKETPLACE = ROOT / ".claude-plugin" / "marketplace.json"
#: The house marketplace of the Guard (owner choice N2 B): the Guard's folder is its own marketplace root.
HOUSE = ROOT / "plugins" / "proofbundle-guard" / ".claude-plugin" / "marketplace.json"
VERIFY, GUARD = "proofbundle", "proofbundle-guard"
#: The programs a hook command starts, as both hosts write the plugin root.
_PROGRAM = re.compile(r"\$\{(?:CLAUDE_)?PLUGIN_ROOT\}/(hooks/[\w.-]+\.py)")


def _entries() -> dict[str, dict]:
    """Each plugin's entry and the folder its source names, the source read against the root of the marketplace that
    lists it: the public one at the repository root, and the house marketplace in the Guard's folder."""
    found = {}
    for market in (MARKETPLACE, HOUSE):
        if market.is_file():
            for entry in json.loads(market.read_text(encoding="utf-8"))["plugins"]:
                found[entry["name"]] = dict(entry, folder=(market.parent.parent / entry["source"]).resolve())
    return found


def _folder(name: str) -> pathlib.Path:
    return _entries()[name]["folder"]


def _json(path: pathlib.Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _hooks(name: str) -> dict[str, dict]:
    """The hook configuration each host registers for an installed plugin of this marketplace: Claude Code reads
    hooks/hooks.json (merged with a manifest field), Codex the manifest field."""
    folder = _folder(name)
    claude = _json(folder / "hooks" / "hooks.json")["hooks"] if (folder / "hooks" / "hooks.json").is_file() else {}
    return {"claude": claude | _json(folder / ".claude-plugin" / "plugin.json").get("hooks", {}),
            "codex": _json(folder / ".codex-plugin" / "plugin.json").get("hooks", {}).get("hooks", {})}


def _commands(groups: list, matcher: str | None) -> list[str]:
    return [h["command"] for g in groups if g.get("matcher") == matcher for h in g["hooks"]]


def test_the_public_marketplace_lists_only_the_verifier_and_the_house_marketplace_only_the_guard():
    """N2 B: no public catalog offers the house's hooks; the house adds its marketplace from a checkout."""
    public = _json(MARKETPLACE)
    assert [e["name"] for e in public["plugins"]] == [VERIFY], public["plugins"]
    house = _json(HOUSE)
    assert [(e["name"], e["source"]) for e in house["plugins"]] == [(GUARD, "./")], house["plugins"]
    assert house["name"] != public["name"]
    assert _folder(GUARD) == HOUSE.parent.parent.resolve()


def test_the_plugin_everyone_installs_registers_no_hook():
    entry = _entries()[VERIFY]
    assert "hooks" not in entry, entry
    assert not (_folder(VERIFY) / "hooks" / "hooks.json").exists()
    assert _hooks(VERIFY) == {"claude": {}, "codex": {}}


def test_the_guard_registers_the_house_profile_under_both_hosts():
    hooks = _hooks(GUARD)
    (claude,) = _commands(hooks["claude"]["PreToolUse"], "Bash")
    (codex,) = _commands(hooks["codex"]["PreToolUse"], "Bash")
    assert "/hooks/proofbundle_gate.py" in claude and "--autonomous" in claude, claude
    assert "/hooks/proofbundle_gate.py" in codex and "--host codex" in codex and "--autonomous" not in codex, codex


def test_every_program_of_the_guard_is_the_file_of_the_verifier():
    folder, programs = _folder(GUARD), set()
    for host in _hooks(GUARD).values():
        for groups in host.values():
            for group in groups:
                for hook in group["hooks"]:
                    programs.update(_PROGRAM.findall(hook["command"]))
    assert {"hooks/proofbundle_gate.py", "hooks/proofbundle_secrets.py", "hooks/proofbundle_answered.py"} <= programs
    for program in sorted(programs) + ["hooks/pin_state_schleuse.py", "server/proofbundle_mcp.py"]:
        mine, theirs = folder / program, _folder(VERIFY) / program
        assert mine.is_file() and not mine.is_symlink() and mine.read_bytes() == theirs.read_bytes(), program


def test_the_guard_adds_no_skill_and_no_server():
    folder = _folder(GUARD)
    assert not (folder / "skills").exists() and not (folder / ".mcp.json").exists()
    for manifest in (".claude-plugin/plugin.json", ".codex-plugin/plugin.json"):
        data = _json(folder / manifest)
        assert not {"skills", "mcpServers", "commands", "agents"} & set(data), (manifest, sorted(data))


def test_each_entry_is_its_manifest_and_both_carry_one_version():
    versions = set()
    for name in (VERIFY, GUARD):
        for manifest in (".claude-plugin/plugin.json", ".codex-plugin/plugin.json"):
            data = _json(_folder(name) / manifest)
            assert data["name"] == name, (name, manifest)
            versions.add(data["version"])
    assert len(versions) == 1, versions


def _server():
    spec = importlib.util.spec_from_file_location("proofbundle_mcp_d134", _folder(VERIFY) / "server" / "proofbundle_mcp.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_verifier_reads_the_gates_log_in_the_guards_data_directory(tmp_path, monkeypatch):
    """Claude Code gives each plugin ~/.claude/plugins/data/<id>/, <id> the plugin identifier with every character other
    than a letter, digit, _ or - as "-" (plugin manifest reference, read 2026-10-31). The gate runs in the Guard and logs
    into proofbundle-guard-<marketplace>; gate_status and the self-test of proofbundle read from that directory beside
    their own, proofbundle-<marketplace>. Red at 18451ad1, where they read their own and in the house said the hook did
    not run."""
    server = _server()
    data = tmp_path / "plugins" / "data"
    monkeypatch.delenv("PLUGIN_DATA", raising=False)
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(data / "proofbundle-proofbundle"))
    path, source = server._log_path()
    assert path == str(data / "proofbundle-guard-proofbundle" / server.LOG_NAME) and "D134" in source, (path, source)
    for own in ("data", "proofbundle-guard-proofbundle", "elsewhere-proofbundle"):   # controls: read as before
        monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(tmp_path / own))
        assert server._log_path()[0] == str(tmp_path / own / server.LOG_NAME), own
