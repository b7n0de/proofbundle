"""The tree digest the plugin's gate binds evidence to: proofbundle-tree-sha256/v1.

A declared evidence item names the sha256 digest of the tree it speaks for. The gate computes that
digest from the commit at HEAD alone and denies an item whose subject differs. The digest covers every
file of the commit except the .proofbundle/ folder, where the declaration and the evidence live, so the
evidence never has to cover itself.

Properties checked:
- the same commit gives the same digest twice, from the gate's function and from its command line;
- the documented recipe in the plugin README, which uses only git and coreutils, gives the same digest,
  so a producer can compute it without the plugin;
- a one-byte change, a rename or a mode change in a covered file changes the digest;
- a change inside .proofbundle/ does not, and neither does the working tree;
- the digest is sha256 over file contents, not a git object id: a known tree gives a known digest, and
  it differs from the tree's git object id in length and value;
- a commit with a submodule has no digest; the gate says so instead of guessing.
"""
from __future__ import annotations

import hashlib
import os
import pathlib
import re
import shutil
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
PLUGIN = ROOT / "plugins" / "proofbundle"
GATE = PLUGIN / "hooks" / "proofbundle_gate.py"
README = PLUGIN / "README.md"

_bytecode, sys.dont_write_bytecode = sys.dont_write_bytecode, True
sys.path.insert(0, str(GATE.parent))
import proofbundle_gate as gate  # noqa: E402

sys.path.pop(0)
sys.dont_write_bytecode = _bytecode

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="git is not installed")

#: The tree the eval scaffold commits: one README.md, mode 100644, with this content.
KNOWN_TREE = {"README.md": "A project that publishes a release.\n"}


def _git(repo: pathlib.Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.org",
                           "-c", "commit.gpgsign=false", *args], check=True, capture_output=True).stdout.decode()


def _repo(tmp_path: pathlib.Path, files: dict[str, str | bytes], name: str = "repo") -> pathlib.Path:
    repo = tmp_path / name
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    for rel, content in files.items():
        target = repo / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content if isinstance(content, bytes) else content.encode())
    _commit(repo)
    return repo


def _commit(repo: pathlib.Path) -> str:
    _git(repo, "add", "-A")
    _git(repo, "commit", "-q", "--allow-empty", "-m", "c")
    return _git(repo, "rev-parse", "HEAD").strip()


def _recipe() -> str:
    """The shell recipe as the README prints it: the sh block whose first line names the algorithm."""
    blocks = re.findall(r"```sh\n(.*?)```", README.read_text(encoding="utf-8"), re.DOTALL)
    recipes = [b for b in blocks if b.startswith("# proofbundle-tree-sha256/v1")]
    assert len(recipes) == 1, "the README prints exactly one tree digest recipe"
    return recipes[0]


def _by_recipe(repo: pathlib.Path, rev: str = "HEAD") -> str:
    proc = subprocess.run(["bash", "-c", _recipe(), "recipe", rev], cwd=repo, capture_output=True, text=True,
                          check=False, env=dict(os.environ, LC_ALL="C"))
    assert proc.returncode == 0, proc.stderr
    return proc.stdout.strip()


def _by_command(repo: pathlib.Path, rev: str = "HEAD") -> str:
    proc = subprocess.run([sys.executable, str(GATE), "tree-digest", "--repo", str(repo), "--rev", rev],
                          capture_output=True, text=True, check=False)
    assert proc.returncode == 0, proc.stderr
    return proc.stdout.strip()


TRICKY = {
    "README.md": "readme\n",
    "a.b": "dot\n",
    "a/c": "slash\n",
    "a-b": "dash\n",
    "a0": "digit\n",
    "A": "upper\n",
    "dir with space/f g.txt": "space\n",
    "ümlaut.txt": "utf-8 name\n",
    "empty": "",
    "bin/tool.sh": "#!/bin/sh\necho hi\n",
    "crlf.txt": b"one\r\ntwo\r\n",
    ".proofbundle/evidence.json": "{}\n",
}


def test_the_same_commit_gives_the_same_digest_every_way(tmp_path):
    repo = _repo(tmp_path, TRICKY)
    (repo / "bin" / "tool.sh").chmod(0o755)
    (repo / "link").symlink_to("a.b")
    _commit(repo)
    first = gate.tree_digest(str(repo), "HEAD")
    assert re.fullmatch(r"[0-9a-f]{64}", first)
    assert gate.tree_digest(str(repo), "HEAD") == first
    assert _by_command(repo) == first
    assert _by_recipe(repo) == first


def test_the_digest_is_sha256_over_the_manifest_and_not_a_git_object_id(tmp_path):
    repo = _repo(tmp_path, KNOWN_TREE)
    manifest = gate.tree_manifest(str(repo), "HEAD")
    blob = hashlib.sha256(KNOWN_TREE["README.md"].encode()).hexdigest()
    assert manifest == b"proofbundle-tree-sha256/v1\n100644 " + blob.encode() + b" README.md\x00"
    assert gate.tree_digest(str(repo), "HEAD") == hashlib.sha256(manifest).hexdigest()
    # The known answer the eval fixtures are signed over. A change here breaks every signed subject.
    assert gate.tree_digest(str(repo), "HEAD") == "ce97e4507660203d647b60b304f351ea6680276a26014b117cbc4e8dea402f31"
    git_tree = _git(repo, "rev-parse", "HEAD^{tree}").strip()
    assert len(git_tree) == 40 and gate.tree_digest(str(repo), "HEAD") != git_tree


def test_a_one_byte_change_in_a_covered_file_changes_the_digest(tmp_path):
    repo = _repo(tmp_path, TRICKY)
    before = gate.tree_digest(str(repo), "HEAD")
    content = bytearray((repo / "a" / "c").read_bytes())
    content[0] ^= 1
    (repo / "a" / "c").write_bytes(bytes(content))
    _commit(repo)
    after = gate.tree_digest(str(repo), "HEAD")
    assert after != before
    assert _by_recipe(repo) == after


def test_a_rename_or_a_mode_change_changes_the_digest(tmp_path):
    repo = _repo(tmp_path, TRICKY)
    before = gate.tree_digest(str(repo), "HEAD")
    _git(repo, "mv", "a.b", "a.c")
    _commit(repo)
    renamed = gate.tree_digest(str(repo), "HEAD")
    assert renamed != before
    (repo / "README.md").chmod(0o755)
    _commit(repo)
    assert gate.tree_digest(str(repo), "HEAD") not in (before, renamed)


def test_a_change_inside_the_evidence_folder_does_not_change_the_digest(tmp_path):
    repo = _repo(tmp_path, TRICKY)
    before = gate.tree_digest(str(repo), "HEAD")
    (repo / ".proofbundle" / "evidence.json").write_text('{"changed": true}\n', encoding="utf-8")
    (repo / ".proofbundle" / "build.bundle.json").write_text("{}\n", encoding="utf-8")
    _commit(repo)
    assert gate.tree_digest(str(repo), "HEAD") == before
    assert _by_recipe(repo) == before


def test_the_digest_reads_the_commit_not_the_working_tree(tmp_path):
    repo = _repo(tmp_path, TRICKY)
    before = gate.tree_digest(str(repo), "HEAD")
    (repo / "README.md").write_text("uncommitted\n", encoding="utf-8")
    (repo / "untracked.txt").write_text("x\n", encoding="utf-8")
    assert gate.tree_digest(str(repo), "HEAD") == before


def test_a_file_named_like_the_folder_outside_the_root_is_covered(tmp_path):
    repo = _repo(tmp_path, {"README.md": "r\n"})
    before = gate.tree_digest(str(repo), "HEAD")
    (repo / "sub" / ".proofbundle").mkdir(parents=True)
    (repo / "sub" / ".proofbundle" / "x.json").write_text("{}\n", encoding="utf-8")
    _commit(repo)
    assert gate.tree_digest(str(repo), "HEAD") != before, "only the top-level .proofbundle/ is left out"


def test_a_submodule_has_no_digest(tmp_path):
    inner = _repo(tmp_path, {"f": "x\n"}, name="inner")
    repo = _repo(tmp_path, {"README.md": "r\n"})
    subprocess.run(["git", "-C", str(repo), "-c", "protocol.file.allow=always", "submodule", "add", "-q",
                    str(inner), "vendor/inner"], check=True, capture_output=True)
    _commit(repo)
    with pytest.raises(gate.GateError, match="submodule|commit"):
        gate.tree_digest(str(repo), "HEAD")
    proc = subprocess.run(["bash", "-c", _recipe(), "recipe", "HEAD"], cwd=repo, capture_output=True, text=True,
                          check=False, env=dict(os.environ, LC_ALL="C"))
    assert proc.returncode != 0, "the recipe must fail, not print a digest, for a submodule"
