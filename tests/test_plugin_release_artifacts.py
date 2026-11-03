"""Counterprobes for scripts/plugin_release_artifacts.py and scripts/plugin_release_run_probe.sh.

Every repository here is built in a temporary folder from the files below; nothing touches the real clone. Each case is
written to fail on a tool that lacks the check it names, and a refusal is held to the reason the check gives, so a
refusal for another reason does not count.

Two layouts. "combined" is the tree of main b55d736d: one plugin root plugins/proofbundle holding the verifier and the
Guard, kept to reproduce the historical probe. "split" is the layout since pull request 472: plugins/proofbundle, the
public verifier without hooks and the only entry of the public marketplace, and plugins/proofbundle-guard, a root of its
own with its own house marketplace whose one entry is "./", no skill, no MCP server and a byte-equal copy of the server.

The tools under test are read from scripts/ of this repository. PRA_TOOLS names another folder, to run the same cases
against an earlier copy of the tools; a folder without plugin_release_run_probe.sh is read for run_probe.sh.
The generator reads script metadata with tomllib, so the module is skipped on Python 3.10, and it is skipped where the
generator is absent, as in the sdist. The verify cases need the proofbundle package, which the test run has.

Assisted by little helpers.
"""
from __future__ import annotations

import base64
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

from _plugin_env import plugin_env

REPO = pathlib.Path(__file__).resolve().parents[1]
TOOLS = pathlib.Path(os.environ.get("PRA_TOOLS") or REPO / "scripts")
GEN = TOOLS / "plugin_release_artifacts.py"
DRIVER = TOOLS / "plugin_release_run_probe.sh"
if not DRIVER.is_file():
    DRIVER = TOOLS / "run_probe.sh"
VERSION = "0.4.0"
PIN = "6.4.0"
OLD_PIN = "6.3.0"
EPOCH = "1793430223"
V = "plugins/proofbundle"
G = "plugins/proofbundle-guard"
HOUSE = G + "/.claude-plugin/marketplace.json"
TOOL_NAMES = ("receipt_template", "emit_receipt", "verify_receipt", "gate_status", "gate_selftest_prepare",
              "gate_selftest_check", "inspect_receipt")

GIT_ENV = {
    "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
    "LC_ALL": "C",
    "HOME": tempfile.gettempdir(),
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_CONFIG_GLOBAL": os.devnull,
    "GIT_AUTHOR_NAME": "fixture",
    "GIT_AUTHOR_EMAIL": "fixture@example.invalid",
    "GIT_COMMITTER_NAME": "fixture",
    "GIT_COMMITTER_EMAIL": "fixture@example.invalid",
    "GIT_AUTHOR_DATE": f"{EPOCH} +0000",
    "GIT_COMMITTER_DATE": f"{EPOCH} +0000",
}


def setUpModule():
    if not GEN.is_file():
        raise unittest.SkipTest(f"NOT MEASURED: {GEN.name} is not in this tree; the sdist does not ship it (MANIFEST.in)")
    if sys.version_info < (3, 11):
        raise unittest.SkipTest("the generator reads script metadata with tomllib, Python 3.11 or later")


def run(cmd, env=None, stdin=None):
    return subprocess.run(cmd, env=env or GIT_ENV, input=stdin, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          check=False)


def git(repo, *args, stdin=None):
    proc = run(["git", "-C", str(repo), *args], stdin=stdin)
    if proc.returncode != 0:
        raise RuntimeError(f"git {args}: {proc.stderr.decode()}")
    return proc.stdout.decode().strip()


def script_block(pin_line: str) -> str:
    return f'# /// script\n# requires-python = ">=3.10"\n{pin_line}\n# ///\n'


def server(pin: str = PIN, pin_line: str | None = None, tools: tuple[str, ...] = TOOL_NAMES) -> str:
    line = pin_line if pin_line is not None else f'# dependencies = ["proofbundle=={pin}"]'
    table = "".join(f'    "{name}": (None, {{}}),\n' for name in tools)
    return (script_block(line) + f'"""Fixture server."""\nSERVER_NAME = "proofbundle"\nSERVER_VERSION = "{VERSION}"\n'
            + "TOOLS = {\n" + table + "}\n")


def gate(pin: str = PIN, constant: bool = True, blocks: bool = True) -> str:
    dep = f'# dependencies = ["proofbundle=={pin}"]' if blocks else "# dependencies = []"
    text = f'"""Fixture gate."""\nimport pathlib\nGATE_VERSION = "{VERSION}"\n'
    if constant:
        text += f'PINNED_PROOFBUNDLE = "{pin}"\n'
    text += f'_SIGN_TOOL = """{script_block(dep)}import sys\n"""\n'
    text += f'_KEY_TOOL = """{script_block(dep)}import os\n"""\n'
    return text


def manifest(name: str, **extra) -> str:
    return json.dumps({"name": name, "version": VERSION, **extra}, indent=2) + "\n"


def marketplace(name: str, entries: list[tuple[str, str]]) -> str:
    return json.dumps({"name": name, "owner": {"name": "fixture"}, "description": "fixture",
                       "plugins": [{"name": n, "source": s, "description": "fixture"} for n, s in entries]},
                      indent=2) + "\n"


#: The registrations of the verifier's server as main c9ab65b1 writes them, for each host its own.
MCP_CLAUDE = {"proofbundle": {"command": "uv", "args": ["run", "--quiet", "--no-config", "--script",
                                                       "${CLAUDE_PLUGIN_ROOT}/server/proofbundle_mcp.py"]}}
MCP_CODEX = {"proofbundle": {"command": "uv", "args": ["run", "--quiet", "--no-config", "--script",
                                                      "server/proofbundle_mcp.py"], "cwd": ".",
                             "env": {"PROOFBUNDLE_PLUGIN_HOST": "codex"}}}
MCP = MCP_CODEX
def _tree_hooks(rel: str):
    """The member hooks of a file of the Guard in this tree, or None where the tree lacks it (the module is skipped
    there with the generator)."""
    try:
        return json.loads((REPO / G / rel).read_text(encoding="utf-8"))["hooks"]
    except (OSError, ValueError, KeyError):
        return None


#: The Guard's hook registrations of this tree, read from its own files and not from the generator, for each host its
#: own: hooks/hooks.json for Claude Code, the Codex manifest with the events under hooks.hooks. The fixture carries them
#: unchanged, so the split fixture registers what the tree registers, and test_n6r holds the generator's constant to
#: the same files.
TREE_CLAUDE_HOOKS = _tree_hooks("hooks/hooks.json")
TREE_CODEX_HOOKS = _tree_hooks(".codex-plugin/plugin.json")
CLAUDE_HOOKS = json.dumps({"hooks": TREE_CLAUDE_HOOKS}, indent=2)
CODEX_HOOKS = TREE_CODEX_HOOKS
#: What the build reports when a registration differs from main's.
REG = "the hook registration is not the one main c9ab65b1 writes"
CATALOG = ("# Plugins\n\n| Host | What it does | Plugin | Version | Maturity |\n|---|---|---|---|---|\n"
           "| Claude Code | fixture | [proofbundle](proofbundle/README.md) | 0.4.0 | Experimental |\n"
           "| Codex | fixture | [proofbundle](proofbundle/README.md) | 0.4.0 | Experimental |\n")


def combined_files(pin: str = PIN) -> dict[str, str]:
    return {
        "LICENSE": "MIT fixture licence\n",
        ".claude-plugin/marketplace.json": marketplace("proofbundle", [("proofbundle", "./" + V)]),
        "plugins/README.md": CATALOG,
        V + "/.claude-plugin/plugin.json": manifest("proofbundle"),
        V + "/.codex-plugin/plugin.json": manifest("proofbundle"),
        V + "/server/proofbundle_mcp.py": server(pin),
        V + "/hooks/hooks.json": "{}\n",
        V + "/hooks/proofbundle_gate.py": gate(pin),
        V + "/skills/verify/SKILL.md": "fixture skill\n",
    }


def split_files(pin: str = PIN) -> dict[str, str]:
    """The split as it landed: the public marketplace lists the verifier alone, the Guard is its own house
    marketplace."""
    return {
        "LICENSE": "MIT fixture licence\n",
        ".claude-plugin/marketplace.json": marketplace("proofbundle", [("proofbundle", "./" + V)]),
        "plugins/README.md": CATALOG,
        V + "/.claude-plugin/plugin.json": manifest("proofbundle"),
        V + "/.codex-plugin/plugin.json": manifest("proofbundle", mcpServers=MCP_CODEX),
        V + "/.mcp.json": json.dumps({"mcpServers": MCP_CLAUDE}, indent=2) + "\n",
        V + "/server/proofbundle_mcp.py": server(pin),
        V + "/skills/verify/SKILL.md": "fixture skill\n",
        HOUSE: marketplace("proofbundle-house", [("proofbundle-guard", "./")]),
        G + "/.claude-plugin/plugin.json": manifest("proofbundle-guard"),
        G + "/.codex-plugin/plugin.json": manifest("proofbundle-guard", hooks=CODEX_HOOKS),
        G + "/server/proofbundle_mcp.py": server(pin),
        G + "/hooks/hooks.json": CLAUDE_HOOKS + "\n",
        G + "/hooks/proofbundle_gate.py": gate(pin),
        G + "/hooks/proofbundle_answered.py": "# fixture program\n",
        G + "/hooks/proofbundle_secrets.py": "# fixture program\n",
    }


def make_repo(root: pathlib.Path, files: dict[str, str], links: dict[str, str] | None = None,
              executable: tuple[str, ...] = ()) -> tuple[pathlib.Path, str]:
    repo = root / "repo"
    repo.mkdir()
    git(repo, "init", "-q", "-b", "main")
    for rel, content in files.items():
        path = repo / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        if rel in executable:
            path.chmod(0o755)
    for rel, target in (links or {}).items():
        path = repo / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        os.symlink(target, path)
    git(repo, "add", "-A")
    git(repo, "-c", "commit.gpgsign=false", "commit", "-q", "-m", "fixture")
    return repo, git(repo, "rev-parse", "HEAD")


def build(repo, commit, out, version=VERSION, pin=PIN, layout="split", extra=()):
    cmd = [sys.executable, "-I", str(GEN), "build", "--repo", str(repo), "--commit", commit, "--out", str(out),
           "--version", version, "--expect-pin", pin, "--layout", layout, *extra]
    return run(cmd, env=plugin_env())


def drive(repo, commit, out, expect_pin, wrong_pin, layout):
    cmd = ["bash", str(DRIVER), "--repo", str(repo), "--commit", commit, "--out", str(out), "--version", VERSION,
           "--expect-pin", expect_pin, "--wrong-pin", wrong_pin, "--layout", layout]
    return run(cmd, env=plugin_env())


def text(proc) -> str:
    return proc.stdout.decode() + proc.stderr.decode()


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp(prefix="pra-test-"))
        self.out = self.tmp / "out"

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def assertBuilt(self, proc):
        self.assertEqual(proc.returncode, 0, text(proc))

    def assertRefused(self, proc, reason: str):
        """Exit 1, nothing written, and the failed check names REASON."""
        self.assertEqual(proc.returncode, 1, text(proc))
        self.assertFalse(self.out.exists() and any(self.out.iterdir()), "a refused build wrote artifacts")
        failed = [line for line in proc.stdout.decode().splitlines() if line.startswith("check FAILED")]
        self.assertTrue(failed and reason in failed[0], f"expected a refusal for {reason!r}, got {failed}")

    def split_refused(self, mutate, reason: str):
        files = split_files()
        mutate(files)
        repo, commit = make_repo(self.tmp, files)
        self.assertRefused(build(repo, commit, self.out), reason)


class CombinedCounterprobes(Base):
    """The historical layout of main b55d736d."""

    def test_c0_valid_combined_tree_builds(self):
        repo, commit = make_repo(self.tmp, combined_files())
        self.assertBuilt(build(repo, commit, self.out, layout="combined"))

    def test_c1_server_pin_removed_is_refused(self):
        files = combined_files()
        files[V + "/server/proofbundle_mcp.py"] = server(pin_line="# dependencies = []")
        repo, commit = make_repo(self.tmp, files)
        self.assertRefused(build(repo, commit, self.out, layout="combined"), "0 proofbundle dependencies")

    def test_c2_wrong_pin_in_a_multi_dependency_list_is_refused(self):
        files = combined_files()
        files[V + "/server/proofbundle_mcp.py"] = server(
            pin_line=f'# dependencies = ["proofbundle=={OLD_PIN}", "typing-extensions"]')
        repo, commit = make_repo(self.tmp, files)
        # since the reading of e05c0c9f a block lists the pin alone, so the second entry stops the build first
        self.assertRefused(build(repo, commit, self.out, layout="combined"), "besides the proofbundle pin")

    def test_c3_gate_pins_removed_is_refused(self):
        files = combined_files()
        files[V + "/hooks/proofbundle_gate.py"] = gate(constant=False, blocks=False)
        repo, commit = make_repo(self.tmp, files)
        self.assertRefused(build(repo, commit, self.out, layout="combined"), "PINNED_PROOFBUNDLE")

    def test_c4_missing_license_is_refused(self):
        files = combined_files()
        del files["LICENSE"]
        repo, commit = make_repo(self.tmp, files)
        self.assertRefused(build(repo, commit, self.out, layout="combined"), "LICENSE")


class SplitChecks(Base):
    """The split layout: versions, pins, archive contents and determinism."""

    def test_s1_archive_holds_licence_both_marketplaces_and_both_roots(self):
        repo, commit = make_repo(self.tmp, split_files())
        self.assertBuilt(build(repo, commit, self.out))
        with tarfile.open(self.out / f"proofbundle-plugin-{VERSION}.tar") as tar:
            names = set(tar.getnames())
        prefix = f"proofbundle-plugin-{VERSION}/"
        for rel in ("LICENSE", ".claude-plugin/marketplace.json", HOUSE, V + "/server/proofbundle_mcp.py",
                    G + "/hooks/proofbundle_gate.py", G + "/server/proofbundle_mcp.py"):
            self.assertIn(prefix + rel, names)
        self.assertNotIn(prefix + "plugins/README.md", names)

    def test_s1b_a_version_member_named_twice_is_refused(self):
        """The Codex pre-run of the reading of 99bdcf27: json.loads keeps the last of two equal members, so a manifest
        with "version" 0.3.0 and then 0.4.0 read as one place saying 0.4.0, while the scope file counts one member."""
        twice = manifest("proofbundle-guard").replace('"version": "0.4.0"', '"version": "0.3.0",\n  "version": "0.4.0"')
        self.assertEqual(twice.count('"version"'), 2)
        self.split_refused(lambda f: f.__setitem__(G + "/.claude-plugin/plugin.json", twice), "duplicate member")

    def test_s1c2_a_json_file_with_nan_or_infinity_is_refused(self):
        """Line 3 of the reading of 11cf1963: json.loads takes NaN and Infinity, which are no JSON, so an invalid
        marketplace or manifest was checked and archived. Every JSON reader of the generator refuses them."""
        for name, value in (("nan", "NaN"), ("infinity", "Infinity"), ("minus infinity", "-Infinity")):
            with self.subTest(name=name):
                files = split_files()
                files[".claude-plugin/marketplace.json"] = files[".claude-plugin/marketplace.json"].replace(
                    '"description": "fixture"', f'"description": {value}', 1)
                sub = self.tmp / name.replace(" ", "_")
                sub.mkdir()
                repo, commit = make_repo(sub, files)
                out = sub / "out"
                proc = build(repo, commit, out)
                self.assertEqual(proc.returncode, 1, text(proc))
                self.assertFalse(out.exists() and any(out.iterdir()), "a refused build wrote artifacts")
                failed = [x for x in proc.stdout.decode().splitlines() if x.startswith("check FAILED")]
                self.assertTrue(failed and "not JSON" in failed[0], failed)

    def test_s1c_a_marketplace_member_named_twice_is_refused(self):
        """The same reader for every JSON file the generator checks: a house marketplace whose name is written twice."""
        twice = marketplace("proofbundle-house", [("proofbundle-guard", "./")]).replace(
            '"name": "proofbundle-house"', '"name": "proofbundle",\n  "name": "proofbundle-house"')
        self.split_refused(lambda f: f.__setitem__(HOUSE, twice), "duplicate member")

    def test_s1d_a_read_name_changed_after_its_assignment_is_refused(self):
        """The Codex pre-run of the reading of e92b63a5: a constant read with ast was taken from its top-level
        assignment alone, so SERVER_VERSION += ".unexpected" passed. Every name the generator reads must be bound once,
        by that assignment, and otherwise only read; the TOOLS table may only be looked up or read by items, keys,
        values or get."""
        changes = {
            "augmented": ("/server/proofbundle_mcp.py", 'SERVER_VERSION += ".unexpected"\n', "SERVER_VERSION"),
            "global in a function": ("/server/proofbundle_mcp.py",
                                     'def f():\n    global SERVER_VERSION\n    SERVER_VERSION = "0.4.1"\n',
                                     "SERVER_VERSION"),
            "table item written": ("/server/proofbundle_mcp.py", 'TOOLS["extra"] = (None, {})\n', "TOOLS"),
            "table updated": ("/server/proofbundle_mcp.py", 'TOOLS.update(extra=(None, {}))\n', "TOOLS"),
            "table bound again": ("/server/proofbundle_mcp.py", 'ALIAS = TOOLS\n', "TOOLS"),
        }
        for name, (rel, line, reason) in changes.items():
            with self.subTest(name=name):
                files = split_files()
                for root in (V, G):
                    files[root + rel] += line
                sub = self.tmp / name.replace(" ", "_")
                sub.mkdir()
                repo, commit = make_repo(sub, files)
                out = sub / "out"
                proc = build(repo, commit, out)
                self.assertEqual(proc.returncode, 1, text(proc))
                self.assertFalse(out.exists() and any(out.iterdir()), "a refused build wrote artifacts")
                failed = [x for x in proc.stdout.decode().splitlines() if x.startswith("check FAILED")]
                self.assertTrue(failed and reason in failed[0] and "otherwise than read" in failed[0], failed)

    def test_s1f_a_read_name_bound_in_any_other_form_is_refused(self):
        """The Codex pre-run of the reading of 826521cb: a capture pattern binds a name without an ast.Name, so
        case SERVER_VERSION: passed, and TOOLS = ALIAS = {...} made a second name of the table that ALIAS.clear()
        empties. Since then every mention of a read name as a Python token has to be an ast.Name at that place, one
        of them the only target of the top-level assignment, the rest reads."""
        changes = {
            "capture pattern": ("SERVER_VERSION", None,
                                'match "9.9.9":\n    case SERVER_VERSION:\n        pass\n'),
            "star pattern": ("SERVER_VERSION", None, 'match ["9"]:\n    case [*SERVER_VERSION]:\n        pass\n'),
            "mapping rest": ("SERVER_VERSION", None, 'match {}:\n    case {**SERVER_VERSION}:\n        pass\n'),
            "chained alias": ("TOOLS", ("TOOLS = {\n", "TOOLS = ALIAS = {\n"), "ALIAS.clear()\n"),
            "keyword": ("SERVER_VERSION", None, "dict(SERVER_VERSION=1)\n"),
            # The Codex pre-run of the reading of 9830cdf1: Python reads identifiers in NFKC, so a fullwidth spelling
            # binds the same name; the tokens are compared in that form too.
            "fullwidth import": ("SERVER_VERSION", None, "import sys as \uff33\uff25\uff32\uff36\uff25\uff32_"
                                 "\uff36\uff25\uff32\uff33\uff29\uff2f\uff2e\n"),
            "fullwidth table import": ("TOOLS", None, "import sys as \uff34\uff2f\uff2f\uff2c\uff33\n"),
        }
        for name, (reason, replace, line) in changes.items():
            with self.subTest(name=name):
                files = split_files()
                for root in (V, G):
                    rel = root + "/server/proofbundle_mcp.py"
                    if replace:
                        self.assertIn(replace[0], files[rel])
                        files[rel] = files[rel].replace(replace[0], replace[1])
                    files[rel] += line
                sub = self.tmp / name.replace(" ", "_")
                sub.mkdir()
                repo, commit = make_repo(sub, files)
                out = sub / "out"
                proc = build(repo, commit, out)
                self.assertEqual(proc.returncode, 1, text(proc))
                self.assertFalse(out.exists() and any(out.iterdir()), "a refused build wrote artifacts")
                failed = [x for x in proc.stdout.decode().splitlines() if x.startswith("check FAILED")]
                self.assertTrue(failed and reason in failed[0], failed)

    def test_s1e_control_the_reads_the_server_writes_build(self):
        """The uses of the TOOLS table in the server at main c9ab65b1: a lookup, a membership test and items()."""
        reads = ("def call(name):\n    if name not in TOOLS:\n        return None\n    return TOOLS[name]\n\n\n"
                 "def listing():\n    return [n for n, _ in TOOLS.items()]\n")
        files = split_files()
        for root in (V, G):
            files[root + "/server/proofbundle_mcp.py"] += reads
        repo, commit = make_repo(self.tmp, files)
        self.assertBuilt(build(repo, commit, self.out))

    def test_s1g_control_a_read_after_a_non_ascii_character_on_its_line_builds(self):
        """The Codex pre-run of the reading of 023a7d8b: tokenize counts columns in characters and ast in UTF-8 bytes,
        so a read of SERVER_VERSION after an umlaut on the same line was taken for a mention without its name and the
        build refused a valid file. Both sides are now compared in bytes."""
        files = split_files()
        for root in (V, G):
            files[root + "/server/proofbundle_mcp.py"] += 'label = "\u00e4"; print(SERVER_VERSION, TOOLS["x"] if "x" in TOOLS else 0)\n'
        repo, commit = make_repo(self.tmp, files)
        self.assertBuilt(build(repo, commit, self.out))

    def test_s1h_a_python_file_with_cr_line_ends_is_refused_by_name(self):
        """The Codex pre-run of the reading of 7cf13c55: ast reads a lone CR as a line end and the token reader does not,
        so the places of a read name differed, and the PEP 723 reader finds no block in such a file either. The files
        the generator reads with ast have LF line ends at main c9ab65b1, so a CR in one of them stops the build with that
        reason."""
        for name, ending in (("cr", "\r"), ("crlf", "\r\n")):
            with self.subTest(name=name):
                files = split_files()
                for root in (V, G):
                    rel = root + "/server/proofbundle_mcp.py"
                    files[rel] = files[rel].replace("\n", ending)
                sub = self.tmp / name
                sub.mkdir()
                repo, commit = make_repo(sub, files)
                out = sub / "out"
                proc = build(repo, commit, out)
                self.assertEqual(proc.returncode, 1, text(proc))
                self.assertFalse(out.exists() and any(out.iterdir()), "a refused build wrote artifacts")
                failed = [x for x in proc.stdout.decode().splitlines() if x.startswith("check FAILED")]
                self.assertTrue(failed and "CR line ends" in failed[0], failed)

    def test_s1i_a_python_file_with_an_encoding_cookie_or_a_bom_is_refused(self):
        """Python decodes a file by its coding cookie (PEP 263) or BOM, while the generator decodes every file as UTF-8,
        so a cookie naming another encoding could make Python read a place otherwise. No file the generator reads with
        ast has either at main c9ab65b1, so both stop the build."""
        for name, head in (("cookie", "# -*- coding: latin-1 -*-\n"), ("bom", "\ufeff")):
            with self.subTest(name=name):
                files = split_files()
                for root in (V, G):
                    rel = root + "/server/proofbundle_mcp.py"
                    files[rel] = head + files[rel]
                sub = self.tmp / name
                sub.mkdir()
                repo, commit = make_repo(sub, files)
                out = sub / "out"
                proc = build(repo, commit, out)
                self.assertEqual(proc.returncode, 1, text(proc))
                self.assertFalse(out.exists() and any(out.iterdir()), "a refused build wrote artifacts")
                failed = [x for x in proc.stdout.decode().splitlines() if x.startswith("check FAILED")]
                self.assertTrue(failed and "encoding" in failed[0], failed)

    def test_s1j_a_catalog_row_with_another_version_is_refused_in_the_split_layout(self):
        """Line 3 of the reading of dfef187a: the scope file says the catalog plugins/README.md is checked, while the
        split layout's places held no catalog row; only the combined layout read it. The split layout now reads its two
        rows too."""
        self.split_refused(lambda f: f.__setitem__("plugins/README.md", CATALOG.replace("| 0.4.0 |", "| 0.3.0 |")),
                           "plugins/README.md")

    def test_s1k_a_catalog_without_one_row_per_host_is_refused(self):
        """The Codex pre-run of the reading of 149788f8: the catalog check counted matches, so two rows for Claude Code
        and a Codex row with a version the pattern does not read passed. Every row whose first cell names a host has to
        have the catalog form, and each host has exactly one."""
        head = "# Plugins\n\n| Host | What it does | Plugin | Version | Maturity |\n|---|---|---|---|---|\n"
        claude = "| Claude Code | fixture | [proofbundle](proofbundle/README.md) | 0.4.0 | Experimental |\n"
        codex = "| Codex | fixture | [proofbundle](proofbundle/README.md) | 0.4.0 | Experimental |\n"
        cases = {
            "claude twice, codex unread": head + claude + claude
            + "| Codex | fixture | [proofbundle](proofbundle/README.md) | 0.3.0-beta | Experimental |\n",
            "codex missing": head + claude,
            "codex twice": head + claude + codex + codex,
            # the Codex pre-run of the reading of c2ff7601: a host row with other blanks or another case of its first
            # cell is a row of that host too
            "codex without blank": head + claude + codex + "|Codex | fixture | proofbundle | 0.3.0 | Experimental |\n",
            "codex with more blanks": head + claude + codex + "|   Codex   | fixture | proofbundle | 0.3.0 | x |\n",
            "codex in lower case": head + claude + codex + "| codex | fixture | proofbundle | 0.3.0 | x |\n",
            # the Codex pre-run of the reading of 950d341d: the pattern read a later number of a row with one cell more
            # than the head, while the version cell under the head says 0.3.0
            "codex with a cell more": head + claude
            + "| Codex | fixture | [proofbundle](proofbundle/README.md) | 0.3.0 | 0.4.0 | Experimental |\n",
            "codex with a cell less": head + claude + "| Codex | fixture | 0.4.0 | Experimental |\n",
            # the Codex pre-run of the reading of e6cfbd9c: a row without its outer pipes belongs to the table too
            "codex row without outer pipes": head + claude + codex + "Codex | fixture | proofbundle | 0.3.0 | Experimental\n",
            "host row in a second table": head + claude + codex + "\n| Other | x |\n|---|---|\n| Codex | 0.3.0 |\n",
            # the Codex pre-run of the reading of cfbc30ca: a second table whose rows name a host only once rendered
            "second table with marked hosts": head + claude + codex
            + "\n| Alias | Version |\n|---|---|\n| **Codex** | 0.3.0 |\n| &#67;odex | 0.3.0 |\n",
            "a row of another kind": head + claude + codex + "| Cursor | fixture | proofbundle | 0.4.0 | x |\n",
            # the Codex pre-run of the reading of b0828838: a delimiter row narrower than the head makes no table
            "delimiter narrower than the head": head.replace("|---|---|---|---|---|", "|---|") + claude + codex,
            # the Codex pre-run of the reading of 92b47349: stripping every outer pipe dropped empty edge cells
            "empty edge cells": head + claude + "|| Codex | fixture | proofbundle | 0.4.0 | Experimental ||\n",
            # the Codex pre-run of the reading of 1bc66c8d: an escaped pipe is cell content to Markdown and a cell
            # border to a split on pipes, so the version column moved
            "escaped pipes": head + "| Claude Code | fixture | proofbundle \\| 0.4.0 | 0.3.0 |\n"
            + "| Codex | fixture | proofbundle \\| 0.4.0 | 0.3.0 |\n",
            # Markdown shows no table inside an HTML comment or a code block, so a catalog there is no catalog
            "table in a comment": "# Plugins\n\n<!--\n\n" + head[len("# Plugins\n\n"):] + claude + codex + "\n-->\n",
            "table in a fence": "# Plugins\n\n```\n\n" + head[len("# Plugins\n\n"):] + claude + codex + "\n```\n",
            # the Codex pre-run of the reading of 58ac91a2: an HTML block such as <pre> shows no table either; the
            # catalog holds no HTML at all
            "table in a pre block": "# Plugins\n\n<pre>\n\n" + head[len("# Plugins\n\n"):] + claude + codex + "\n</pre>\n",
            "table in a details block": "# Plugins\n\n<details>\n\n" + head[len("# Plugins\n\n"):] + claude + codex
            + "\n</details>\n",
            "table indented": "# Plugins\n\n" + "".join("    " + x + "\n" for x in (head[len("# Plugins\n\n"):]
                                                                              + claude + codex).splitlines()),
        }
        for name, catalog in cases.items():
            with self.subTest(name=name):
                files = split_files()
                files["plugins/README.md"] = catalog
                sub = self.tmp / name.replace(" ", "_").replace(",", "")
                sub.mkdir()
                repo, commit = make_repo(sub, files)
                out = sub / "out"
                proc = build(repo, commit, out)
                self.assertEqual(proc.returncode, 1, text(proc))
                self.assertFalse(out.exists() and any(out.iterdir()), "a refused build wrote artifacts")
                failed = [x for x in proc.stdout.decode().splitlines() if x.startswith("check FAILED")]
                self.assertTrue(failed and "plugins/README.md" in failed[0], failed)

    def test_s1l_a_script_block_with_a_dependency_besides_the_pin_is_refused(self):
        """Line 3 of the reading of e05c0c9f: a script block was read for its one proofbundle pin and every other
        entry passed over, so a server could depend on proofbundle-guard. Every script block the generator reads lists
        the pin alone at main c9ab65b1, so any other entry stops the build."""
        line = '# dependencies = ["proofbundle==6.4.0", "proofbundle-guard==0.4.0"]'
        files = split_files()
        for root in (V, G):
            files[root + "/server/proofbundle_mcp.py"] = server(pin_line=line)
        repo, commit = make_repo(self.tmp, files)
        self.assertRefused(build(repo, commit, self.out), "besides the proofbundle pin")

    def test_s1m_a_pin_in_another_spelling_is_refused(self):
        """The Codex pre-run of the reading of f842b7b4: the requirement pattern cut off an extras section and the pin
        check passed it over, so proofbundle[!!!]==6.4.0 read as the pin. The one entry has to be proofbundle==X.Y.Z
        exactly, as at main c9ab65b1."""
        for name, line, reason in (
                ("extras", '# dependencies = ["proofbundle[!!!]==6.4.0"]', "proofbundle==X.Y.Z"),
                # a marker was refused before by the check of an exact pin, for its own reason
                ("marker", '# dependencies = ["proofbundle==6.4.0; python_version < \'3\'"]', "not an exact == pin"),
                ("blanks", '# dependencies = ["proofbundle == 6.4.0"]', "proofbundle==X.Y.Z")):
            with self.subTest(name=name):
                files = split_files()
                for root in (V, G):
                    files[root + "/server/proofbundle_mcp.py"] = server(pin_line=line)
                sub = self.tmp / name
                sub.mkdir()
                repo, commit = make_repo(sub, files)
                out = sub / "out"
                proc = build(repo, commit, out)
                self.assertEqual(proc.returncode, 1, text(proc))
                self.assertFalse(out.exists() and any(out.iterdir()), "a refused build wrote artifacts")
                failed = [x for x in proc.stdout.decode().splitlines() if x.startswith("check FAILED")]
                self.assertTrue(failed and reason in failed[0], failed)

    def test_s1n_a_script_block_inside_a_string_is_refused_in_a_file(self):
        """Line 3 of the reading of c3dd68eb: the PEP 723 pattern found a block inside a triple-quoted string as well,
        so a server whose only block lies in a string literal passed as pinned. A block of a file is read only where
        every line of it is a comment, as the servers at main c9ab65b1 write it; the gate's blocks inside its string
        constants are read as before."""
        files = split_files()
        for root in (V, G):
            rel = root + "/server/proofbundle_mcp.py"
            block = script_block('# dependencies = ["proofbundle==6.4.0"]')
            self.assertTrue(files[rel].startswith(block))
            files[rel] = 'NOTE = """\n' + block + '"""\n' + files[rel][len(block):]
        repo, commit = make_repo(self.tmp, files)
        self.assertRefused(build(repo, commit, self.out), "not a comment")

    def test_s1o_a_script_block_inside_a_string_is_refused_in_a_constant(self):
        """The neighbor of s1n: the gate's constants are scripts the gate writes out and runs, and their blocks were read
        with the same pattern. At main c9ab65b1 the block of both constants is a comment of the constant's script, so a
        block written into a string literal inside the constant stops the build as well."""
        files = split_files()
        rel = G + "/hooks/proofbundle_gate.py"
        old = '_SIGN_TOOL = """# /// script'
        self.assertEqual(files[rel].count(old), 1)
        start = files[rel].index(old) + len('_SIGN_TOOL = """')
        end = files[rel].index("# ///\n", start + len("# /// script")) + len("# ///\n")
        files[rel] = files[rel][:start] + "X = '''\n" + files[rel][start:end] + "'''\n" + files[rel][end:]
        repo, commit = make_repo(self.tmp, files)
        self.assertRefused(build(repo, commit, self.out), "not a comment")

    def test_s1p_a_cr_in_a_constant_script_is_refused(self):
        """A constant's script is read with the PEP 723 pattern and the token reader like a file, and a file with a CR
        stops the build (python_text); the constants at main c9ab65b1 hold LF line ends only, so a CR in one stops it
        as well."""
        files = split_files()
        rel = G + "/hooks/proofbundle_gate.py"
        old = "import sys\n" + chr(34) * 3
        self.assertEqual(files[rel].count(old), 1)
        files[rel] = files[rel].replace(old, "import sys\\r\n" + chr(34) * 3)
        repo, commit = make_repo(self.tmp, files)
        self.assertRefused(build(repo, commit, self.out), "CR line ends")

    def test_s2_missing_guard_gate_pin_is_refused(self):
        self.split_refused(lambda f: f.__setitem__(G + "/hooks/proofbundle_gate.py", gate(constant=False)),
                           "PINNED_PROOFBUNDLE")

    def test_s3_wrong_pin_in_the_guard_server_is_refused(self):
        def mutate(files):
            files[G + "/server/proofbundle_mcp.py"] = server(pin=OLD_PIN)
            files[V + "/server/proofbundle_mcp.py"] = server(pin=OLD_PIN)
        self.split_refused(mutate, f"says {OLD_PIN}")

    def test_s4_unresolved_public_source_is_refused(self):
        self.split_refused(lambda f: f.__setitem__(".claude-plugin/marketplace.json", marketplace(
            "proofbundle", [("proofbundle", "./plugins/proofbundle-missing")])), "source")

    def test_s5_hooks_file_in_the_public_verifier_is_refused(self):
        self.split_refused(lambda f: f.__setitem__(V + "/hooks/hooks.json", "{}\n"), "hooks folder")

    def test_s6_hooks_field_in_a_public_manifest_is_refused(self):
        # no hooks member in the verifier's manifests at main c9ab65b1, so the member rule refuses it first (s8b)
        self.split_refused(lambda f: f.__setitem__(V + "/.claude-plugin/plugin.json", manifest("proofbundle", hooks={})),
                           "members ['hooks'] outside the members main c9ab65b1 writes")

    def test_s7_symbolic_link_is_refused(self):
        repo, commit = make_repo(self.tmp, split_files(), links={V + "/escape": "/etc/hostname"})
        self.assertRefused(build(repo, commit, self.out), "no regular file")

    def test_s8_verifier_depending_on_the_guard_is_refused(self):
        self.split_refused(lambda f: f.__setitem__(V + "/.claude-plugin/plugin.json", manifest(
            "proofbundle", dependencies=["proofbundle-guard"])), "members ['dependencies'] outside the members main")

    def test_s8b_a_member_outside_the_ones_main_writes_is_refused(self):
        """Line 3 of the reading of 02eb79ba: the check for a dependency on the Guard read the field of the public
        marketplace entry as a list, so "dependencies": "proofbundle-guard" passed character by character. A list of
        refused fields and their forms stays open; every marketplace, every entry and every host manifest of a root now
        holds only the members main c9ab65b1 writes for it, and any other member stops the build, the ones that change
        what a host loads or where it resolves a source among them."""
        def entry_member(path, name, member, value):
            def mutate(files):
                data = json.loads(files[path])
                for entry in data["plugins"]:
                    if entry["name"] == name:
                        entry[member] = value
                files[path] = json.dumps(data, indent=2) + "\n"
            return mutate

        def top_member(path, member, value):
            def mutate(files):
                data = json.loads(files[path])
                data[member] = value
                files[path] = json.dumps(data, indent=2) + "\n"
            return mutate

        cases = {
            "public entry dependencies as text": entry_member(".claude-plugin/marketplace.json", "proofbundle",
                                                              "dependencies", "proofbundle-guard"),
            "house entry strict": entry_member(HOUSE, "proofbundle-guard", "strict", False),
            "public marketplace plugin root": top_member(".claude-plugin/marketplace.json", "metadata",
                                                         {"pluginRoot": "./plugins"}),
            "verifier claude agents": top_member(V + "/.claude-plugin/plugin.json", "agents", ["./agents/x.md"]),
            "verifier codex dependencies as text": top_member(V + "/.codex-plugin/plugin.json", "dependencies",
                                                              "proofbundle-guard"),
            "guard claude commands": top_member(G + "/.claude-plugin/plugin.json", "commands", "./commands"),
        }
        for name, mutate in cases.items():
            with self.subTest(name=name):
                files = split_files()
                mutate(files)
                sub = self.tmp / name.replace(" ", "_")
                sub.mkdir()
                repo, commit = make_repo(sub, files)
                out = sub / "out"
                proc = build(repo, commit, out)
                self.assertEqual(proc.returncode, 1, text(proc))
                self.assertFalse(out.exists() and any(out.iterdir()), "a refused build wrote artifacts")
                failed = [x for x in proc.stdout.decode().splitlines() if x.startswith("check FAILED")]
                self.assertTrue(failed and "outside the members main c9ab65b1 writes" in failed[0], failed)

    def test_s9_two_builds_are_byte_identical_and_a2_is_the_full_object(self):
        repo, commit = make_repo(self.tmp, split_files(), executable=(G + "/hooks/proofbundle_gate.py",))
        first, second = self.tmp / "o1", self.tmp / "o2"
        for out in (first, second):
            self.assertBuilt(build(repo, commit, out))
        names = sorted(p.name for p in first.iterdir())
        self.assertEqual(names, sorted(p.name for p in second.iterdir()))
        for name in names:
            self.assertEqual((first / name).read_bytes(), (second / name).read_bytes(), name)
        a2 = (first / f"proofbundle-plugin-{VERSION}.release.json").read_bytes()
        obj = json.loads(a2)
        self.assertEqual(a2, json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode())
        self.assertEqual(set(obj), {"schema", "plugin", "version", "repository", "commit", "commit_tree",
                                    "plugin_tree", "marketplace_blob", "tag", "verifier_pin", "archive"})
        self.assertEqual(obj["verifier_pin"], f"proofbundle=={PIN}")

    def test_s10_export_ignore_does_not_change_the_raw_git_archive_rule(self):
        files = split_files()
        files[".gitattributes"] = V + "/skills/verify/SKILL.md export-ignore\n"
        repo, commit = make_repo(self.tmp, files)
        self.assertBuilt(build(repo, commit, self.out))
        with tarfile.open(self.out / f"proofbundle-plugin-{VERSION}.tar") as tar:
            self.assertIn(f"proofbundle-plugin-{VERSION}/{V}/skills/verify/SKILL.md", tar.getnames())

    def test_s11_other_expected_version_is_refused(self):
        repo, commit = make_repo(self.tmp, split_files())
        self.assertRefused(build(repo, commit, self.out, version="0.4.1"), "expected 0.4.1")


class HouseMarketplace(Base):
    """The public catalog lists the verifier alone; the Guard comes from its own house marketplace."""

    def test_n1_public_marketplace_listing_the_guard_is_refused(self):
        self.split_refused(lambda f: f.__setitem__(".claude-plugin/marketplace.json", marketplace(
            "proofbundle", [("proofbundle", "./" + V), ("proofbundle-guard", "./" + G)])),
            ".claude-plugin/marketplace.json: entries")

    def test_n2_missing_house_marketplace_is_refused(self):
        self.split_refused(lambda f: f.pop(HOUSE), HOUSE)

    def test_n3_house_entry_with_another_source_is_refused(self):
        self.split_refused(lambda f: f.__setitem__(HOUSE, marketplace(
            "proofbundle-house", [("proofbundle-guard", "./" + G)])), "entry proofbundle-guard source")

    def test_n4_house_marketplace_with_a_second_entry_is_refused(self):
        self.split_refused(lambda f: f.__setitem__(HOUSE, marketplace(
            "proofbundle-house", [("proofbundle-guard", "./"), ("proofbundle", "../proofbundle")])),
            HOUSE + ": entries")

    def test_n5_house_marketplace_with_another_name_is_refused(self):
        self.split_refused(lambda f: f.__setitem__(HOUSE, marketplace("proofbundle", [("proofbundle-guard", "./")])),
                           "marketplace name")


class GuardProfile(Base):
    """The Guard: each host's hook registration is main's, the programs it starts are present, it adds no skill and
    no MCP server, and its server is the verifier's."""

    def test_n6_hook_starting_a_program_the_guard_lacks_is_refused(self):
        """The registration as main writes it, and one of the programs it starts missing from the Guard."""
        self.split_refused(lambda f: f.pop(G + "/hooks/proofbundle_secrets.py"), "which the Guard does not hold")

    def test_n6b_hook_starting_a_nested_program_the_guard_lacks_is_refused(self):
        """The Codex pre-run of the reading of 99bdcf27: the pattern read a program directly under hooks/ only, so a
        hook that started hooks/sub/missing.py passed while another hook named the gate."""
        self.split_refused(lambda f: f.__setitem__(G + "/hooks/hooks.json", CLAUDE_HOOKS.replace(
            "hooks/proofbundle_gate.py", "hooks/sub/missing.py") + "\n"), REG)

    def test_n6c_hook_starting_a_shell_program_the_guard_lacks_is_refused(self):
        self.split_refused(lambda f: f.__setitem__(G + "/hooks/hooks.json", CLAUDE_HOOKS.replace(
            "hooks/proofbundle_gate.py", "hooks/missing.sh") + "\n"), REG)

    def test_n6d_codex_hook_starting_a_program_the_guard_lacks_is_refused(self):
        """The neighbour found while reading the finding: the Guard's Codex manifest writes ${PLUGIN_ROOT}, which the
        pattern did not read at all, so no Codex hook was checked."""
        gone = json.loads(json.dumps(CODEX_HOOKS).replace("proofbundle_gate.py", "proofbundle_gone.py"))
        self.split_refused(lambda f: f.__setitem__(G + "/.codex-plugin/plugin.json",
                                                   manifest("proofbundle-guard", hooks=gone)),
                           REG)

    def test_n6e_hook_command_naming_no_program_in_a_form_the_generator_reads_is_refused(self):
        """A command whose started program the generator cannot read is refused, not passed over."""
        self.split_refused(lambda f: f.__setitem__(G + "/hooks/hooks.json", CLAUDE_HOOKS.replace(
            'python3 -I \\"${CLAUDE_PLUGIN_ROOT}/hooks/proofbundle_gate.py\\"', "bash -c 'python3 hooks/x.py'")
            + "\n"), REG)

    def test_n6g_hook_program_joined_with_more_text_into_one_shell_word_is_refused(self):
        """The Codex pre-run of the reading of 2bcbf9f3: the pattern found the quoted path inside a longer shell word,
        so "${CLAUDE_PLUGIN_ROOT}/hooks/proofbundle_gate.py".missing passed with the gate present while the shell
        starts hooks/proofbundle_gate.py.missing. The quoted path has to be a whole word, before and after."""
        base = self.tmp
        try:
            for i, (before, after) in enumerate((('proofbundle_gate.py\\"', 'proofbundle_gate.py\\".missing'),
                                                 ('\\"${CLAUDE_PLUGIN_ROOT}', 'x\\"${CLAUDE_PLUGIN_ROOT}'))):
                with self.subTest(after=after):
                    changed = CLAUDE_HOOKS.replace(before, after)
                    self.assertNotEqual(changed, CLAUDE_HOOKS)
                    self.tmp = base / f"case{i}"
                    self.tmp.mkdir()
                    self.out = self.tmp / "out"
                    self.split_refused(lambda f: f.__setitem__(G + "/hooks/hooks.json", changed + "\n"),
                                       REG)
        finally:
            self.tmp, self.out = base, base / "out"

    def test_n6h_codex_hook_program_joined_with_more_text_is_refused(self):
        joined = json.loads(json.dumps(CODEX_HOOKS).replace('proofbundle_gate.py\\"', 'proofbundle_gate.py\\".missing'))
        self.assertNotEqual(joined, CODEX_HOOKS)
        self.split_refused(lambda f: f.__setitem__(G + "/.codex-plugin/plugin.json",
                                                   manifest("proofbundle-guard", hooks=joined)),
                           REG)

    def test_n6i_hook_program_joined_through_an_escaped_blank_is_refused(self):
        """The Codex pre-run of the reading of 03958484: an escaped blank joins text to the quoted path, so
        x\\ "${CLAUDE_PLUGIN_ROOT}/hooks/proofbundle_gate.py" passed while the shell starts "x <root>/hooks/...". The
        command is now read as the shell splits it into words, in both hosts' forms."""
        for host, root in (("claude", "CLAUDE_PLUGIN_ROOT"), ("codex", "PLUGIN_ROOT")):
            with self.subTest(host=host):
                command = 'python3 -I x\\ "${%s}/hooks/proofbundle_gate.py"' % root
                hooks = {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": command}]}]}
                files = split_files()
                if host == "claude":
                    files[G + "/hooks/hooks.json"] = json.dumps({"hooks": hooks}) + "\n"
                else:
                    files[G + "/.codex-plugin/plugin.json"] = manifest("proofbundle-guard", hooks={"hooks": hooks})
                sub = self.tmp / host
                sub.mkdir()
                repo, commit = make_repo(sub, files)
                out = sub / "out"
                proc = build(repo, commit, out)
                self.assertEqual(proc.returncode, 1, text(proc))
                self.assertFalse(out.exists() and any(out.iterdir()), "a refused build wrote artifacts")
                failed = [x for x in proc.stdout.decode().splitlines() if x.startswith("check FAILED")]
                self.assertTrue(failed and REG in failed[0], failed)

    def test_n6k_hook_program_joined_after_a_command_substitution_is_refused(self):
        """The Codex pre-run of the reading of af7c414d: shlex splits $(printf x) from the quoted path that follows it,
        while the shell joins both into one word and starts x<root>/hooks/proofbundle_gate.py. Since then a hook
        command is held to the two forms the Guard writes, read from the start of the command, not to a list of forms
        it must not have. Also a second mention of a plugin root and leading blanks are refused."""
        commands = {
            "substitution claude": 'python3 -I $(printf x)"${CLAUDE_PLUGIN_ROOT}/hooks/proofbundle_gate.py"',
            "substitution codex": 'python3 -I $(printf x)"${PLUGIN_ROOT}/hooks/proofbundle_gate.py"',
            "second root": 'python3 -I "${CLAUDE_PLUGIN_ROOT}/hooks/proofbundle_gate.py" "${CLAUDE_PLUGIN_ROOT}/x"',
            "leading blank": ' python3 -I "${CLAUDE_PLUGIN_ROOT}/hooks/proofbundle_gate.py"',
        }
        for name, command in commands.items():
            with self.subTest(name=name):
                hooks = {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": command}]}]}
                files = split_files()
                if "codex" in name:
                    files[G + "/.codex-plugin/plugin.json"] = manifest("proofbundle-guard", hooks={"hooks": hooks})
                else:
                    files[G + "/hooks/hooks.json"] = json.dumps({"hooks": hooks}) + "\n"
                sub = self.tmp / name.replace(" ", "_")
                sub.mkdir()
                repo, commit = make_repo(sub, files)
                out = sub / "out"
                proc = build(repo, commit, out)
                self.assertEqual(proc.returncode, 1, text(proc))
                self.assertFalse(out.exists() and any(out.iterdir()), "a refused build wrote artifacts")
                failed = [x for x in proc.stdout.decode().splitlines() if x.startswith("check FAILED")]
                self.assertTrue(failed and REG in failed[0], failed)

    def test_n6l_guard_hooks_outside_hooks_json_are_refused(self):
        """The Codex pre-run of the reading of e92b63a5: hooks in the Guard's Claude Code manifest were not read, so one
        there could start a program the Guard lacks. The Guard writes its Claude Code hooks in hooks/hooks.json alone,
        so a hooks field in its Claude Code manifest or in its house marketplace entry stops the build, and the Codex
        manifest's hooks have to be an object the generator reads. Since the member rule (s8b) neither field is a
        member main c9ab65b1 writes there, and that rule refuses both first."""
        missing = {"PreToolUse": [{"matcher": "Bash", "hooks": [
            {"type": "command", "command": 'python3 -I "${CLAUDE_PLUGIN_ROOT}/hooks/missing.py"'}]}]}
        cases = {
            "claude manifest": (G + "/.claude-plugin/plugin.json", manifest("proofbundle-guard", hooks=missing),
                                "members ['hooks'] outside the members main c9ab65b1 writes"),
            "house entry": (HOUSE, json.dumps({"name": "proofbundle-house", "owner": {"name": "fixture"},
                                               "description": "fixture", "plugins": [
                                                   {"name": "proofbundle-guard", "source": "./",
                                                    "description": "fixture", "hooks": missing}]}, indent=2) + "\n",
                            "entry proofbundle-guard: members ['hooks'] outside"),
            "codex path": (G + "/.codex-plugin/plugin.json", manifest("proofbundle-guard", hooks="hooks/other.json"),
                           REG),
        }
        for name, (path, content, reason) in cases.items():
            with self.subTest(name=name):
                files = split_files()
                files[path] = content
                sub = self.tmp / name.replace(" ", "_")
                sub.mkdir()
                repo, commit = make_repo(sub, files)
                out = sub / "out"
                proc = build(repo, commit, out)
                self.assertEqual(proc.returncode, 1, text(proc))
                self.assertFalse(out.exists() and any(out.iterdir()), "a refused build wrote artifacts")
                failed = [x for x in proc.stdout.decode().splitlines() if x.startswith("check FAILED")]
                self.assertTrue(failed and reason in failed[0], failed)

    def test_n6m_a_hook_with_the_plugin_root_of_the_other_host_is_refused(self):
        """Line 3 of the reading of 830dc0f9: both root variables were taken for both hosts, while Claude Code sets
        ${CLAUDE_PLUGIN_ROOT} and Codex ${PLUGIN_ROOT}; a Codex hook naming the other host's variable starts nothing
        there. hooks/hooks.json now starts its programs through ${CLAUDE_PLUGIN_ROOT}, the Codex manifest through
        ${PLUGIN_ROOT}."""
        swapped = {
            "codex with the claude root": (G + "/.codex-plugin/plugin.json", manifest(
                "proofbundle-guard", hooks=json.loads(json.dumps(CODEX_HOOKS).replace("${PLUGIN_ROOT}",
                                                                                      "${CLAUDE_PLUGIN_ROOT}")))),
            "claude with the codex root": (G + "/hooks/hooks.json",
                                           CLAUDE_HOOKS.replace("${CLAUDE_PLUGIN_ROOT}", "${PLUGIN_ROOT}") + "\n"),
        }
        for name, (rel, content) in swapped.items():
            with self.subTest(name=name):
                files = split_files()
                files[rel] = content
                sub = self.tmp / name.replace(" ", "_")
                sub.mkdir()
                repo, commit = make_repo(sub, files)
                out = sub / "out"
                proc = build(repo, commit, out)
                self.assertEqual(proc.returncode, 1, text(proc))
                failed = [x for x in proc.stdout.decode().splitlines() if x.startswith("check FAILED")]
                self.assertTrue(failed and REG in failed[0], failed)

    def test_n6n_a_hook_command_the_shell_does_not_parse_is_refused(self):
        """The Codex pre-run of the reading of 459d8f7e: a valid start followed by a rest the shell rejects passed,
        while the shell starts nothing of such a command. The whole command now has to parse, under sh and bash."""
        for name, command in (("open group", 'python3 -I "${CLAUDE_PLUGIN_ROOT}/hooks/proofbundle_gate.py" && ('),
                              ("open quote", 'python3 -I "${CLAUDE_PLUGIN_ROOT}/hooks/proofbundle_gate.py" || echo \'x')):
            with self.subTest(name=name):
                hooks = {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": command}]}]}
                files = split_files()
                files[G + "/hooks/hooks.json"] = json.dumps({"hooks": hooks}) + "\n"
                sub = self.tmp / name.replace(" ", "_")
                sub.mkdir()
                repo, commit = make_repo(sub, files)
                out = sub / "out"
                proc = build(repo, commit, out)
                self.assertEqual(proc.returncode, 1, text(proc))
                failed = [x for x in proc.stdout.decode().splitlines() if x.startswith("check FAILED")]
                # since the reading of 25e49d71 a registration is held to main's as a whole
                self.assertTrue(failed and REG in failed[0], failed)

    def test_n6j_control_the_registration_of_main_in_another_spelling_builds(self):
        """The registration is compared by value, as JSON reads it: the registrations of main with sorted keys and
        other indentation build, and the report names the three programs they start."""
        files = split_files()
        files[G + "/hooks/hooks.json"] = json.dumps({"hooks": TREE_CLAUDE_HOOKS}, indent=4, sort_keys=True) + "\n"
        files[G + "/.codex-plugin/plugin.json"] = json.dumps(
            {"version": VERSION, "hooks": TREE_CODEX_HOOKS, "name": "proofbundle-guard"}, sort_keys=True) + "\n"
        repo, commit = make_repo(self.tmp, files)
        proc = build(repo, commit, self.out)
        self.assertBuilt(proc)
        self.assertIn("(3: hooks/proofbundle_answered.py hooks/proofbundle_gate.py hooks/proofbundle_secrets.py)",
                      text(proc))

    def test_n6o_a_hook_command_with_a_redirection_is_refused(self):
        """The Codex pre-run of the reading of ae0b16e4: a valid start and a rest that parses still started nothing
        where an input redirection failed. Each hook command is now held whole to the forms the Guard writes."""
        command = 'python3 -I "${CLAUDE_PLUGIN_ROOT}/hooks/proofbundle_gate.py" < /missing-input'
        hooks = {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": command}]}]}
        self.split_refused(lambda f: f.__setitem__(G + "/hooks/hooks.json", json.dumps({"hooks": hooks}) + "\n"),
                           REG)

    def test_n6f_control_the_hook_forms_of_both_hosts_build(self):
        repo, commit = make_repo(self.tmp, split_files())
        proc = build(repo, commit, self.out)
        self.assertBuilt(proc)
        self.assertIn("(3: hooks/proofbundle_answered.py hooks/proofbundle_gate.py hooks/proofbundle_secrets.py)",
                      text(proc))

    def test_n6p_a_command_outside_the_registration_form_is_refused(self):
        """The Codex pre-run of the reading of f2f6007b: the commands were gathered from every member named command at any
        depth, so a command written directly under an event, which no host loads as a hook, counted as a started
        program. A registration is held to the form main c9ab65b1 writes for each host: under hooks the events the
        Guard registers for, each a list of groups with hooks and at most a matcher, each hook of type command with a
        command and at most a timeout; the Codex manifest holds the events under hooks.hooks."""
        gate_claude = 'python3 -I "${CLAUDE_PLUGIN_ROOT}/hooks/proofbundle_gate.py"'
        gate_codex = json.loads(json.dumps(CODEX_HOOKS))["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
        cases = {
            "claude command under an event": ("claude", {"PreToolUse": {"command": gate_claude}}),
            "claude command in a group": ("claude", {"PreToolUse": [{"matcher": "Bash", "command": gate_claude,
                                                                      "hooks": []}]}),
            "claude hook of another type": ("claude", {"PreToolUse": [{"matcher": "Bash", "hooks": [
                {"type": "prompt", "command": gate_claude}]}]}),
            "claude event the guard does not register": ("claude", {"NeverFires": [{"hooks": [
                {"type": "command", "command": gate_claude}]}]}),
            "codex events without the hooks member": ("codex", json.loads(json.dumps(CODEX_HOOKS))["hooks"]),
            "codex event of the other host": ("codex", {"hooks": {"SessionStart": [{"hooks": [
                {"type": "command", "command": gate_codex}]}]}}),
        }
        for name, (host, hooks) in cases.items():
            with self.subTest(name=name):
                files = split_files()
                if host == "claude":
                    files[G + "/hooks/hooks.json"] = json.dumps({"hooks": hooks}) + "\n"
                else:
                    files[G + "/.codex-plugin/plugin.json"] = manifest("proofbundle-guard", hooks=hooks)
                sub = self.tmp / name.replace(" ", "_")
                sub.mkdir()
                repo, commit = make_repo(sub, files)
                out = sub / "out"
                proc = build(repo, commit, out)
                self.assertEqual(proc.returncode, 1, text(proc))
                self.assertFalse(out.exists() and any(out.iterdir()), "a refused build wrote artifacts")
                failed = [x for x in proc.stdout.decode().splitlines() if x.startswith("check FAILED")]
                self.assertTrue(failed and REG in failed[0],
                                failed)

    def test_n6q_a_host_without_its_registration_or_with_a_swapped_form_is_refused(self):
        """The Codex pre-run of the reading of 25e49d71: the programs of both hosts were joined and only that union had
        to be non-empty, so a host whose registration was empty or missing passed while the other host started a
        program. The neighbor in the same form: any command form of a host was taken at any place, so the blocking
        form of a PreToolUse hook could be swapped for one that lets the call through. Each host's registration is now
        main's as a whole."""
        def claude_swapped():
            data = json.loads(CLAUDE_HOOKS)
            hook = data["hooks"]["PreToolUse"][0]["hooks"][0]
            self.assertIn("--autonomous || {", hook["command"])
            hook["command"] = 'python3 -I "${CLAUDE_PLUGIN_ROOT}/hooks/proofbundle_gate.py" || true'
            return json.dumps(data, indent=2) + "\n"

        def codex_swapped():
            data = json.loads(json.dumps(CODEX_HOOKS))
            hook = data["hooks"]["PreToolUse"][0]["hooks"][0]
            self.assertIn("--host codex || {", hook["command"])
            hook["command"] = 'python3 -I "${PLUGIN_ROOT}/hooks/proofbundle_gate.py"'
            return manifest("proofbundle-guard", hooks=data)

        cases = {
            "claude empty": (G + "/hooks/hooks.json", lambda: '{"hooks": {}}\n'),
            "codex empty": (G + "/.codex-plugin/plugin.json", lambda: manifest("proofbundle-guard", hooks={"hooks": {}})),
            "codex without hooks": (G + "/.codex-plugin/plugin.json", lambda: manifest("proofbundle-guard")),
            "claude blocking form swapped for || true": (G + "/hooks/hooks.json", claude_swapped),
            "codex blocking form swapped for the bare start": (G + "/.codex-plugin/plugin.json", codex_swapped),
        }
        for name, (rel, content) in cases.items():
            with self.subTest(name=name):
                files = split_files()
                files[rel] = content()
                sub = self.tmp / name.replace(" ", "_").replace("|", "")
                sub.mkdir()
                repo, commit = make_repo(sub, files)
                out = sub / "out"
                proc = build(repo, commit, out)
                self.assertEqual(proc.returncode, 1, text(proc))
                self.assertFalse(out.exists() and any(out.iterdir()), "a refused build wrote artifacts")
                failed = [x for x in proc.stdout.decode().splitlines() if x.startswith("check FAILED")]
                self.assertTrue(failed and REG in failed[0], failed)

    def test_n6r_the_registration_constant_is_the_one_of_this_tree(self):
        """The oracle of HOOK_REGISTRATIONS is the Guard's files of this tree, read here without the generator: the
        constant equals them, and HOOK_PROGRAMS is the set of programs their commands name, each once, through the
        root variable of its host. A change of the Guard's hooks without its change of the constant fails here."""
        import importlib.util
        import re

        spec = importlib.util.spec_from_file_location("plugin_release_artifacts_under_test", GEN)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertIsNotNone(TREE_CLAUDE_HOOKS, "hooks/hooks.json of the Guard is not in this tree")
        self.assertIsNotNone(TREE_CODEX_HOOKS, "the Guard's Codex manifest names no hooks in this tree")
        self.assertEqual(module.HOOK_REGISTRATIONS, {"/hooks/hooks.json": TREE_CLAUDE_HOOKS,
                                                     "/.codex-plugin/plugin.json": TREE_CODEX_HOOKS})

        def commands(value):
            if isinstance(value, dict):
                return [v for k, v in value.items() if k == "command"] + \
                    [c for k, v in value.items() if k != "command" for c in commands(v)]
            return [c for v in value for c in commands(v)] if isinstance(value, list) else []

        named = set()
        for registration, variable in ((TREE_CLAUDE_HOOKS, "CLAUDE_PLUGIN_ROOT"), (TREE_CODEX_HOOKS, "PLUGIN_ROOT")):
            for command in commands(registration):
                found = re.findall(r'"\$\{(CLAUDE_PLUGIN_ROOT|PLUGIN_ROOT)\}/([^"]+)"', command)
                self.assertEqual([v for v, _ in found], [variable], command)
                named.add(found[0][1])
        self.assertEqual(sorted(module.HOOK_PROGRAMS), sorted(named))

    def test_n7_guard_registering_an_mcp_server_is_refused(self):
        self.split_refused(lambda f: f.__setitem__(G + "/.mcp.json", json.dumps({"mcpServers": MCP}) + "\n"),
                           "the Guard registers the MCP servers")

    def test_n8_guard_carrying_a_skill_is_refused(self):
        self.split_refused(lambda f: f.__setitem__(G + "/skills/verify/SKILL.md", "fixture skill\n"),
                           "the Guard adds no skill")

    def test_n9_guard_server_differing_from_the_verifier_server_is_refused(self):
        self.split_refused(lambda f: f.__setitem__(G + "/server/proofbundle_mcp.py", server() + "# changed\n"),
                           "not byte-equal")


class VerifierServer(Base):
    """The public verifier declares exactly one MCP server, and that server lists the stated tools."""

    def test_n10b_a_registration_that_starts_another_program_is_refused(self):
        """Line 3 of the reading of 830dc0f9: the check compared the names of the registered MCP servers alone, so a
        registration named proofbundle could start another program than the server whose tools it read. Each host's
        registration now has to be the one main c9ab65b1 writes, and the verifier's Claude Code manifest registers no
        server of its own."""
        other_claude = json.loads(json.dumps(MCP_CLAUDE).replace("server/proofbundle_mcp.py", "server/other.py"))
        other_codex = json.loads(json.dumps(MCP_CODEX).replace("server/proofbundle_mcp.py", "server/other.py"))
        cases = {
            "mcp json": (V + "/.mcp.json", json.dumps({"mcpServers": other_claude}) + "\n", ".mcp.json"),
            "codex manifest": (V + "/.codex-plugin/plugin.json", manifest("proofbundle", mcpServers=other_codex),
                               ".codex-plugin/plugin.json"),
            "claude manifest": (V + "/.claude-plugin/plugin.json", manifest("proofbundle", mcpServers=MCP_CLAUDE),
                                ".claude-plugin/plugin.json"),
        }
        for name, (rel, content, reason) in cases.items():
            with self.subTest(name=name):
                files = split_files()
                files[rel] = content
                sub = self.tmp / name.replace(" ", "_")
                sub.mkdir()
                repo, commit = make_repo(sub, files)
                out = sub / "out"
                proc = build(repo, commit, out)
                self.assertEqual(proc.returncode, 1, text(proc))
                failed = [x for x in proc.stdout.decode().splitlines() if x.startswith("check FAILED")]
                self.assertTrue(failed and reason in failed[0], failed)

    def test_n10_other_tool_set_is_refused(self):
        def mutate(files):
            changed = server(tools=TOOL_NAMES[:-1])
            files[V + "/server/proofbundle_mcp.py"] = changed
            files[G + "/server/proofbundle_mcp.py"] = changed
        self.split_refused(mutate, "tools")

    def test_n11_verifier_without_its_mcp_declaration_is_refused(self):
        # the registration is compared whole since the reading of 830dc0f9, so a missing file reads as None
        self.split_refused(lambda f: f.pop(V + "/.mcp.json"), "MCP servers None")


class DriverChecks(Base):
    """The probe driver enforces the statuses it records, and two of its runs give the same bytes."""

    def test_d1_failing_positive_builds_fail_the_driver(self):
        files = split_files()
        files[V + "/.codex-plugin/plugin.json"] = json.dumps(
            {"name": "proofbundle", "version": "0.4.1", "mcpServers": MCP}) + "\n"
        repo, commit = make_repo(self.tmp, files)
        proc = drive(repo, commit, self.out, PIN, OLD_PIN, "split")
        self.assertNotEqual(proc.returncode, 0, text(proc))

    def test_d2_negative_build_on_a_final_head_uses_a_wrong_pin(self):
        repo, commit = make_repo(self.tmp, split_files())
        proc = drive(repo, commit, self.out, PIN, OLD_PIN, "split")
        log = (self.out / "determinism.txt").read_text(encoding="utf-8") if (self.out / "determinism.txt").exists() else ""
        self.assertEqual(proc.returncode, 0, text(proc))
        negative = [line for line in log.splitlines() if line.startswith("negative")]
        self.assertTrue(negative, log)
        self.assertTrue(all("UNEXPECTED" not in line for line in log.splitlines()), log)
        self.assertTrue(any("exit 1" in line for line in negative), log)

    def test_d3_two_driver_runs_give_the_same_bytes(self):
        repo, commit = make_repo(self.tmp, split_files())
        first, second = self.tmp / "p1", self.tmp / "p2"
        for out in (first, second):
            proc = drive(repo, commit, out, PIN, OLD_PIN, "split")
            self.assertEqual(proc.returncode, 0, text(proc))
        files = sorted(p.relative_to(first).as_posix() for p in first.rglob("*") if p.is_file())
        self.assertEqual(files, sorted(p.relative_to(second).as_posix() for p in second.rglob("*") if p.is_file()))
        self.assertIn(f"run1/proofbundle-plugin-{VERSION}.tar", files)
        for rel in files:
            self.assertEqual((first / rel).read_bytes(), (second / rel).read_bytes(), rel)


def sign(private_key, data: bytes) -> bytes:
    return base64.b64encode(private_key.sign(data)) + b"\n"


class SignatureChain(Base):
    """S1 over the exact A2 bytes, then A1 against A2, then A3 rebuilt, then the tag."""

    def setUp(self):
        super().setUp()
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        self.key = Ed25519PrivateKey.generate()
        self.other = Ed25519PrivateKey.generate()
        raw = self.key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        other_raw = self.other.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.pub = base64.b64encode(raw).decode()
        self.other_pub = base64.b64encode(other_raw).decode()
        self.repo, self.commit = make_repo(self.tmp, split_files())
        self.tagfile = self.tmp / "t1.tag"
        self.build_proc = build(self.repo, self.commit, self.out, extra=("--tag-out", str(self.tagfile)))
        self.a2 = self.out / f"proofbundle-plugin-{VERSION}.release.json"
        self.a1 = self.out / f"proofbundle-plugin-{VERSION}.tar"
        self.a3 = self.out / "SHA256SUMS"
        self.s1 = self.out / f"proofbundle-plugin-{VERSION}.release.json.sig"
        if self.build_proc.returncode == 0:
            self.s1.write_bytes(sign(self.key, self.a2.read_bytes()))

    def verify(self, pub=None, repo=None):
        cmd = [sys.executable, "-I", str(GEN), "verify", "--assets", str(self.out), "--public-key", pub or self.pub]
        if repo:
            cmd += ["--repo", str(repo)]
        return run(cmd, env=plugin_env())

    def _expect_fail(self, pub=None):
        self.assertEqual(self.build_proc.returncode, 0, text(self.build_proc))
        proc = self.verify(pub=pub)
        self.assertEqual(proc.returncode, 1, text(proc))

    def test_v1_positive(self):
        self.assertEqual(self.build_proc.returncode, 0, text(self.build_proc))
        proc = self.verify()
        self.assertEqual(proc.returncode, 0, text(proc))

    def test_v2_modified_a2_fails(self):
        if self.build_proc.returncode == 0:
            data = bytearray(self.a2.read_bytes())
            data[-2] = ord("1") if data[-2] != ord("1") else ord("2")
            self.a2.write_bytes(bytes(data))
        self._expect_fail()

    def test_v2b_a2_with_nan_signed_by_the_key_fails_as_not_json(self):
        """The neighbour of line 3 of the reading of 11cf1963 in the verify step: json.loads took NaN and json.dumps
        wrote it back, so an A2 with NaN read as canonical. The verify step reads A2 with the generator's strict reader;
        A2 is re-signed here so that only the reading decides."""
        if self.build_proc.returncode == 0:
            obj = json.loads(self.a2.read_bytes())
            obj["schema"] = float("nan")
            data = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
            self.assertIn(b"NaN", data)
            self.a2.write_bytes(data)
            self.s1.write_bytes(sign(self.key, data))
        self._expect_fail()
        self.assertIn("A2 is not JSON", text(self.verify()))

    def test_v3_other_a1_fails(self):
        if self.build_proc.returncode == 0:
            self.a1.write_bytes(self.a1.read_bytes() + b"\0" * 512)
        self._expect_fail()

    def test_v4_wrong_key_fails(self):
        self._expect_fail(pub=self.other_pub)

    def test_v5_signature_over_other_bytes_fails(self):
        if self.build_proc.returncode == 0:
            self.s1.write_bytes(sign(self.key, self.a2.read_bytes() + b"\n"))
        self._expect_fail()

    def test_v6_changed_a3_line_fails(self):
        if self.build_proc.returncode == 0:
            content = self.a3.read_text(encoding="ascii")
            self.a3.write_text(("0" if content[0] != "0" else "1") + content[1:], encoding="ascii")
        self._expect_fail()

    def test_v7_extra_a3_line_fails(self):
        if self.build_proc.returncode == 0:
            self.a3.write_text(self.a3.read_text(encoding="ascii") + "0" * 64 + "  extra\n", encoding="ascii")
        self._expect_fail()

    def test_v8_signature_file_not_in_the_s1_form_fails(self):
        if self.build_proc.returncode == 0:
            self.s1.write_bytes(self.s1.read_bytes().rstrip(b"\n"))
        self._expect_fail()

    def test_v9_tag_must_name_the_statement_commit(self):
        self.assertEqual(self.build_proc.returncode, 0, text(self.build_proc))
        oid = git(self.repo, "mktag", stdin=self.tagfile.read_bytes())
        git(self.repo, "update-ref", "refs/tags/proofbundle--v0.4.0", oid)
        ok = self.verify(repo=self.repo)
        self.assertEqual(ok.returncode, 0, text(ok))
        git(self.repo, "-c", "commit.gpgsign=false", "commit", "-q", "--allow-empty", "-m", "later")
        later = git(self.repo, "rev-parse", "HEAD")
        git(self.repo, "-c", "tag.gpgsign=false", "tag", "-f", "-a", "-m", "moved", "proofbundle--v0.4.0", later)
        moved = self.verify(repo=self.repo)
        self.assertEqual(moved.returncode, 1, text(moved))

    def test_v10_small_order_key_with_its_forged_signature_fails(self):
        """The identity point as the key, and R the identity with S zero as the signature, satisfy the plain
        Ed25519 equation for every message; only the check for a pinned key refuses them."""
        identity = b"\x01" + b"\x00" * 31
        if self.build_proc.returncode == 0:
            self.s1.write_bytes(base64.b64encode(identity + b"\x00" * 32) + b"\n")
        self._expect_fail(pub=base64.b64encode(identity).decode())


class TagObject(Base):
    """T1: fixed bytes and an expected object id before the approval."""

    def test_t2_an_optional_output_inside_the_output_folder_or_on_another_is_refused(self):
        """The Codex pre-run of the reading of 8682d4b4: --tag-out and --inventory-out were written after the three
        artifacts and not held apart from them, so --tag-out on the archive's path replaced it while the report named
        the archive's size and SHA-256 and said result OK. The driver writes both outside the output folder; each now
        has to lie outside it and apart from the other, after links are followed, before anything is written."""
        repo, commit = make_repo(self.tmp, split_files())
        archive = f"proofbundle-plugin-{VERSION}.tar"
        link = self.tmp / "into_the_archive"
        os.symlink(self.tmp / "o" / "link" / archive, link)
        cases = {
            "tag on the archive": lambda out: ("--tag-out", str(out / archive)),
            "inventory on SHA256SUMS": lambda out: ("--inventory-out", str(out / "SHA256SUMS")),
            "tag on the folder": lambda out: ("--tag-out", str(out)),
            "both on one path": lambda out: ("--tag-out", str(self.tmp / "same"), "--inventory-out",
                                             str(self.tmp / "same")),
            "link": lambda out: ("--tag-out", str(link)),
        }
        for name, extra in cases.items():
            with self.subTest(name=name):
                out = self.tmp / "o" / ("link" if name == "link" else name.replace(" ", "_"))
                proc = build(repo, commit, out, extra=extra(out))
                self.assertEqual(proc.returncode, 2, text(proc))
                self.assertFalse(out.exists() and any(out.iterdir()), "a refused build wrote artifacts")
                self.assertFalse((self.tmp / "same").exists())
                self.assertIn("lie outside the output folder and apart", proc.stderr.decode())

    def test_t1_tag_object_is_accepted_and_matches_git_tag(self):
        repo, commit = make_repo(self.tmp, split_files())
        tagfile = self.tmp / "t1.tag"
        proc = build(repo, commit, self.out, extra=("--tag-out", str(tagfile)))
        self.assertBuilt(proc)
        report = dict(line.split(" ", 1) for line in proc.stdout.decode().splitlines() if " " in line)
        expected = report.get("t1_expected_object_id", "").strip()
        oid = git(repo, "mktag", stdin=tagfile.read_bytes())
        self.assertEqual(oid, expected)
        body = tagfile.read_bytes().split(b"\n\n", 1)[1]
        msg = self.tmp / "msg"
        msg.write_bytes(body)
        env = dict(GIT_ENV, GIT_COMMITTER_NAME="b7n0de", GIT_COMMITTER_EMAIL="45888075+b7n0de@users.noreply.github.com",
                   GIT_COMMITTER_DATE=f"{git(repo, 'show', '-s', '--format=%ct', commit)} +0000")
        made = run(["git", "-C", str(repo), "-c", "tag.gpgsign=false", "tag", "-a", "-F", str(msg),
                    "proofbundle--v0.4.0", commit], env=env)
        self.assertEqual(made.returncode, 0, made.stderr.decode())
        self.assertEqual(git(repo, "rev-parse", "refs/tags/proofbundle--v0.4.0"), expected)


if __name__ == "__main__":
    unittest.main()
