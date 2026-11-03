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


MCP = {"proofbundle": {"command": "uv", "args": ["run", "--script", "server/proofbundle_mcp.py"]}}
CLAUDE_HOOKS = json.dumps({"hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [
    {"type": "command", "command": 'python3 -I "${CLAUDE_PLUGIN_ROOT}/hooks/proofbundle_gate.py"'}]}]}}, indent=2)
#: The form the Guard's Codex manifest writes since pull request 472: the host's plugin root, ${PLUGIN_ROOT}, in quotes.
CODEX_HOOKS = {"PreToolUse": [{"matcher": "Bash", "hooks": [
    {"type": "command", "command": 'python3 -I "${PLUGIN_ROOT}/hooks/proofbundle_gate.py" --host codex'}]}]}
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
        V + "/.codex-plugin/plugin.json": manifest("proofbundle", mcpServers=MCP),
        V + "/.mcp.json": json.dumps({"mcpServers": MCP}, indent=2) + "\n",
        V + "/server/proofbundle_mcp.py": server(pin),
        V + "/skills/verify/SKILL.md": "fixture skill\n",
        HOUSE: marketplace("proofbundle-house", [("proofbundle-guard", "./")]),
        G + "/.claude-plugin/plugin.json": manifest("proofbundle-guard"),
        G + "/.codex-plugin/plugin.json": manifest("proofbundle-guard", hooks=CODEX_HOOKS),
        G + "/server/proofbundle_mcp.py": server(pin),
        G + "/hooks/hooks.json": CLAUDE_HOOKS + "\n",
        G + "/hooks/proofbundle_gate.py": gate(pin),
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
        self.assertRefused(build(repo, commit, self.out, layout="combined"), f"says {OLD_PIN}")

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

    def test_s1c_a_marketplace_member_named_twice_is_refused(self):
        """The same reader for every JSON file the generator checks: a house marketplace whose name is written twice."""
        twice = marketplace("proofbundle-house", [("proofbundle-guard", "./")]).replace(
            '"name": "proofbundle-house"', '"name": "proofbundle",\n  "name": "proofbundle-house"')
        self.split_refused(lambda f: f.__setitem__(HOUSE, twice), "duplicate member")

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
        self.split_refused(lambda f: f.__setitem__(V + "/.claude-plugin/plugin.json", manifest("proofbundle", hooks={})),
                           "hooks field")

    def test_s7_symbolic_link_is_refused(self):
        repo, commit = make_repo(self.tmp, split_files(), links={V + "/escape": "/etc/hostname"})
        self.assertRefused(build(repo, commit, self.out), "no regular file")

    def test_s8_verifier_depending_on_the_guard_is_refused(self):
        self.split_refused(lambda f: f.__setitem__(V + "/.claude-plugin/plugin.json", manifest(
            "proofbundle", dependencies=["proofbundle-guard"])), "depends on proofbundle-guard")

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
    """The Guard: its hooks start programs it holds, it adds no skill and no MCP server, and its server is the
    verifier's."""

    def test_n6_hook_starting_a_program_the_guard_lacks_is_refused(self):
        self.split_refused(lambda f: f.__setitem__(G + "/hooks/hooks.json", CLAUDE_HOOKS.replace(
            "proofbundle_gate.py", "proofbundle_gone.py") + "\n"), "which the Guard does not hold")

    def test_n6b_hook_starting_a_nested_program_the_guard_lacks_is_refused(self):
        """The Codex pre-run of the reading of 99bdcf27: the pattern read a program directly under hooks/ only, so a
        hook that started hooks/sub/missing.py passed while another hook named the gate."""
        self.split_refused(lambda f: f.__setitem__(G + "/hooks/hooks.json", CLAUDE_HOOKS.replace(
            "hooks/proofbundle_gate.py", "hooks/sub/missing.py") + "\n"), "which the Guard does not hold")

    def test_n6c_hook_starting_a_shell_program_the_guard_lacks_is_refused(self):
        self.split_refused(lambda f: f.__setitem__(G + "/hooks/hooks.json", CLAUDE_HOOKS.replace(
            "hooks/proofbundle_gate.py", "hooks/missing.sh") + "\n"), "which the Guard does not hold")

    def test_n6d_codex_hook_starting_a_program_the_guard_lacks_is_refused(self):
        """The neighbour found while reading the finding: the Guard's Codex manifest writes ${PLUGIN_ROOT}, which the
        pattern did not read at all, so no Codex hook was checked."""
        gone = json.loads(json.dumps(CODEX_HOOKS).replace("proofbundle_gate.py", "proofbundle_gone.py"))
        self.split_refused(lambda f: f.__setitem__(G + "/.codex-plugin/plugin.json",
                                                   manifest("proofbundle-guard", hooks=gone)),
                           "which the Guard does not hold")

    def test_n6e_hook_command_naming_no_program_in_a_form_the_generator_reads_is_refused(self):
        """A command whose started program the generator cannot read is refused, not passed over."""
        self.split_refused(lambda f: f.__setitem__(G + "/hooks/hooks.json", CLAUDE_HOOKS.replace(
            'python3 -I \\"${CLAUDE_PLUGIN_ROOT}/hooks/proofbundle_gate.py\\"', "bash -c 'python3 hooks/x.py'")
            + "\n"), "in a form the generator reads")

    def test_n6f_control_the_hook_forms_of_both_hosts_build(self):
        repo, commit = make_repo(self.tmp, split_files())
        proc = build(repo, commit, self.out)
        self.assertBuilt(proc)
        self.assertIn("(1: hooks/proofbundle_gate.py)", text(proc))

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

    def test_n10_other_tool_set_is_refused(self):
        def mutate(files):
            changed = server(tools=TOOL_NAMES[:-1])
            files[V + "/server/proofbundle_mcp.py"] = changed
            files[G + "/server/proofbundle_mcp.py"] = changed
        self.split_refused(mutate, "tools")

    def test_n11_verifier_without_its_mcp_declaration_is_refused(self):
        self.split_refused(lambda f: f.pop(V + "/.mcp.json"), "MCP servers []")


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
