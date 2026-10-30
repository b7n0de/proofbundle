"""The lock between Verify and Guard (Nachtrag 3, point 5, and Nachtrag 4, point 2; review of -1, K-1 and finding 1).

Verify lands as a release of its own, Guard Preview after it. A tree without the Guard's Claude Code registration,
plugins/proofbundle/hooks/hooks.json, is a Verify state: the Guard comes in with that file and the gate program
together. In a Verify state:
- the plugin folder holds no hooks/ folder, so no gate program and no hooks/hooks.json, which Claude Code would load
  without a manifest field, and neither host manifest carries a "hooks" field: a Verify-only install registers no
  Guard hook under Claude Code or under Codex;
- no text a user reads names hooks or the gate: the strings of both manifests and of the marketplace entry, the plugin
  catalog, the plugin's README, its skills, every other Markdown file in the plugin folder (DECISIONS.md among them),
  the string constants of its MCP server, and the lines of the repository README that link the catalog.
In a Guard state the gate program is there, and every hook either host registers starts a program of the plugin that
exists. The planted cases below show that each check finds what it is for.

Red first, measured on 2026-10-26 at the four Verify slices of review package -1: 01 has 72 findings (its hooks/
folder with the gate program, and 71 Guard words in the server and the skills); 02a and 08a 101 (the Codex manifest's
hooks as well, the selftest skill and the hooks sentences of both manifests); 13a 308 (with the catalog, the
marketplace entry, the plugin README and the repository README's task row). The re-cut 13a of owner answer 1, without
the Codex hooks block, still has 293 Guard words. The cut of delivery -2 has none at each of its four Verify slices, and
the top of the Guard slices of -1 is a whole Guard (0).
"""
from __future__ import annotations

import ast
import json
import pathlib
import re
import shutil

ROOT = pathlib.Path(__file__).resolve().parents[1]
PLUGIN = pathlib.Path("plugins") / "proofbundle"
CLAUDE_HOOKS = PLUGIN / "hooks" / "hooks.json"
GATE = PLUGIN / "hooks" / "proofbundle_gate.py"
MANIFESTS = (PLUGIN / ".claude-plugin" / "plugin.json", PLUGIN / ".codex-plugin" / "plugin.json")
MARKETPLACE = pathlib.Path(".claude-plugin") / "marketplace.json"
CATALOG = pathlib.Path("plugins") / "README.md"
#: The words that name the Guard in a text a user reads. The catalog's "Inspect AI hook" is the package's own hook for
#: Inspect AI, not the plugin's.
GUARD_WORDS = re.compile(r"(?<!Inspect AI )\bhooks?\b|\bgate[sd]?\b|\bgating\b|\bpre-push\b|\bdone check\b|"
                         r"\bself-?test\b", re.IGNORECASE)
#: A program of the plugin that a hook command starts, as both hosts write it.
_PROGRAM = re.compile(r"(?:\$\{CLAUDE_PLUGIN_ROOT\}/|(?<![\w/.-]))(hooks/[\w.-]+\.py)")


def _strings(value: object) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for v in value.values() for s in _strings(v)]
    if isinstance(value, list):
        return [s for v in value for s in _strings(v)]
    return []


def _texts(root: pathlib.Path) -> dict[str, str]:
    """Each text a user of the plugin reads, by the file it comes from."""
    texts = {}
    for manifest in MANIFESTS:
        if (root / manifest).is_file():
            texts[str(manifest)] = "\n".join(_strings(json.loads((root / manifest).read_text(encoding="utf-8"))))
    if (root / MARKETPLACE).is_file():
        market = json.loads((root / MARKETPLACE).read_text(encoding="utf-8"))
        texts[str(MARKETPLACE)] = "\n".join([market.get("description", "")] + _strings(market.get("plugins", [])))
    for doc in (CATALOG, PLUGIN / "README.md"):
        if (root / doc).is_file():
            texts[str(doc)] = (root / doc).read_text(encoding="utf-8")
    for skill in sorted((root / PLUGIN / "skills").rglob("*")) if (root / PLUGIN / "skills").is_dir() else []:
        if skill.is_file() and skill.suffix in (".md", ".yaml"):
            texts[str(skill.relative_to(root))] = skill.read_text(encoding="utf-8")
    # Every Markdown file the plugin folder ships, not a list of them: DECISIONS.md carried a Guard word the list never
    # read (review of G-1, line 3, F1).
    for doc in sorted((root / PLUGIN).rglob("*.md")) if (root / PLUGIN).is_dir() else []:
        texts.setdefault(str(doc.relative_to(root)), doc.read_text(encoding="utf-8"))
    server = root / PLUGIN / "server" / "proofbundle_mcp.py"
    if server.is_file():
        tree = ast.parse(server.read_text(encoding="utf-8"))
        texts[str(server.relative_to(root))] = "\n".join(
            node.value for node in ast.walk(tree) if isinstance(node, ast.Constant) and isinstance(node.value, str))
    if (root / "README.md").is_file():
        texts["README.md"] = "\n".join(line for line in (root / "README.md").read_text(encoding="utf-8").split("\n")
                                       if "plugins/README.md" in line)
    return texts


def verify_findings(root: pathlib.Path) -> list[str]:
    """What a Verify state may not carry: a hooks/ folder, a "hooks" field in a host manifest, a Guard word."""
    found = []
    if (root / PLUGIN / "hooks").exists():
        found.append(f"{PLUGIN / 'hooks'} holds " + ", ".join(sorted(p.name for p in (root / PLUGIN / "hooks").iterdir())))
    for manifest in MANIFESTS:
        if (root / manifest).is_file() and "hooks" in json.loads((root / manifest).read_text(encoding="utf-8")):
            found.append(f"{manifest} registers hooks")
    for name, text in _texts(root).items():
        for match in GUARD_WORDS.finditer(text):
            line = text[:match.start()].count("\n") + 1
            found.append(f"{name}:{line} names {match.group(0)!r}")
    return found


def guard_findings(root: pathlib.Path) -> list[str]:
    """What a Guard state must hold: the gate program, and for every hook either host registers the program it
    starts."""
    found = [] if (root / GATE).is_file() else [f"{CLAUDE_HOOKS} without {GATE}"]
    commands = _strings(json.loads((root / CLAUDE_HOOKS).read_text(encoding="utf-8")).get("hooks", {}))
    codex = root / MANIFESTS[1]
    if codex.is_file():
        commands += _strings(json.loads(codex.read_text(encoding="utf-8")).get("hooks", {}))
    for command in commands:
        for program in _PROGRAM.findall(command):
            if not (root / PLUGIN / program).is_file():
                found.append(f"a hook starts {program}, which the plugin does not hold")
    return found


def findings(root: pathlib.Path) -> list[str]:
    return guard_findings(root) if (root / CLAUDE_HOOKS).is_file() else verify_findings(root)


def test_the_tree_is_a_clean_verify_state_or_a_whole_guard():
    assert findings(ROOT) == []


# --- planted cases: each check finds what it is for ----------------------------------------------------------------

def _verify_copy(tmp_path: pathlib.Path) -> pathlib.Path:
    """A Verify state of its own: the manifests, the catalog and a README without a Guard word."""
    root = tmp_path / "tree"
    for manifest in MANIFESTS:
        (root / manifest).parent.mkdir(parents=True, exist_ok=True)
        (root / manifest).write_text(json.dumps({"name": "proofbundle", "description": "Verify receipts."}),
                                     encoding="utf-8")
    (root / CATALOG).write_text("The package's own pytest plugin and Inspect AI hook ship inside the package.\n",
                                encoding="utf-8")
    return root


def test_planted_a_clean_verify_state_has_no_finding(tmp_path):
    assert findings(_verify_copy(tmp_path)) == []


def test_planted_a_codex_manifest_with_hooks_is_found(tmp_path):
    root = _verify_copy(tmp_path)
    data = json.loads((root / MANIFESTS[1]).read_text(encoding="utf-8"))
    data["hooks"] = {"hooks": {"Stop": [{"hooks": [{"type": "command", "command": "python3 hooks/x.py"}]}]}}
    (root / MANIFESTS[1]).write_text(json.dumps(data), encoding="utf-8")
    assert any("registers hooks" in f for f in findings(root))


def test_planted_a_claude_hooks_file_without_the_gate_is_found(tmp_path):
    root = _verify_copy(tmp_path)
    (root / CLAUDE_HOOKS).parent.mkdir(parents=True)
    (root / CLAUDE_HOOKS).write_text(json.dumps({"hooks": {"Stop": [{"hooks": [
        {"type": "command", "command": 'python3 -I "${CLAUDE_PLUGIN_ROOT}/hooks/proofbundle_gate.py" stop'}]}]}}),
        encoding="utf-8")
    assert findings(root) == [f"{CLAUDE_HOOKS} without {GATE}",
                              "a hook starts hooks/proofbundle_gate.py, which the plugin does not hold"]


def test_planted_a_gate_program_without_its_registration_is_found(tmp_path):
    root = _verify_copy(tmp_path)
    (root / GATE).parent.mkdir(parents=True)
    (root / GATE).write_text("", encoding="utf-8")
    assert findings(root) == [f"{PLUGIN / 'hooks'} holds proofbundle_gate.py"]


def test_planted_a_text_that_names_hooks_or_the_gate_is_found(tmp_path):
    root = _verify_copy(tmp_path)
    (root / MANIFESTS[0]).write_text(json.dumps({"description": "Active hooks check declared evidence."}),
                                     encoding="utf-8")
    skill = root / PLUGIN / "skills" / "verify" / "SKILL.md"
    skill.parent.mkdir(parents=True)
    skill.write_text("Never state that the pre-push gate ran.\n", encoding="utf-8")
    found = findings(root)
    assert f"{MANIFESTS[0]}:1 names 'hooks'" in found
    assert f"{skill.relative_to(root)}:1 names 'pre-push'" in found and f"{skill.relative_to(root)}:1 names 'gate'" in found


def test_planted_a_guard_word_in_any_markdown_of_the_plugin_is_found(tmp_path):
    root = _verify_copy(tmp_path)
    decisions = root / PLUGIN / "DECISIONS.md"
    decisions.parent.mkdir(parents=True, exist_ok=True)
    decisions.write_text("Both manifests say 0.4.0, and the gate's GATE_VERSION follows.\n", encoding="utf-8")
    assert f"{PLUGIN / 'DECISIONS.md'}:1 names 'gate'" in findings(root)


def test_planted_a_whole_guard_has_no_finding_and_a_missing_program_is_found(tmp_path):
    root = _verify_copy(tmp_path)
    (root / GATE).parent.mkdir(parents=True)
    (root / GATE).write_text("", encoding="utf-8")
    command = 'python3 -I "${CLAUDE_PLUGIN_ROOT}/hooks/proofbundle_gate.py"'
    (root / CLAUDE_HOOKS).write_text(json.dumps({"hooks": {"PreToolUse": [{"hooks": [
        {"type": "command", "command": command}]}]}}), encoding="utf-8")
    assert findings(root) == []
    shutil.copy(root / CLAUDE_HOOKS, root / "hooks.json.bak")
    (root / CLAUDE_HOOKS).write_text((root / CLAUDE_HOOKS).read_text(encoding="utf-8").replace(
        "proofbundle_gate.py", "proofbundle_missing.py"), encoding="utf-8")
    assert findings(root) == ["a hook starts hooks/proofbundle_missing.py, which the plugin does not hold"]
