"""Review round 12 of 2026-10-13, B-17 (owner: fix now): a tree that names one path twice has no
proofbundle-tree-sha256/v1 digest.

Measured at 7588fe4a (FIX-11 class list B-17, confirmed by the reviewer): a code folder src/ that names app.py twice gave
two manifest records for one path; git's lookup `<commit>:src/app.py` gave the first entry, a checkout wrote the last,
and with evidence signed over the gate's digest of that tree the CI mode passed. The reviewer recommends one rejection of
ambiguous trees where the digest is made and where it is checked, with one catch case.

Property (DECISIONS.md D2): a tree that names a path twice, a file or a folder at any depth, the .proofbundle folder
included, has no digest, as a tree with a submodule has none; every place that makes or checks the digest refuses it the
same way: the gate's function, its tree-digest command and so its CI mode and run-evidence, and the README's bash recipe.
The digest of every valid tree stays byte-equal. Red against c6061a5a.
"""
from __future__ import annotations

import hashlib
import json
import os
import pathlib
import subprocess
import sys

import pytest

import test_claude_code_plugin_gate as cg
import test_plugin_tree_digest as td
from _plugin_env import plugin_env

pytestmark = td.pytestmark
_clean_git_config = cg._clean_git_config
gate = td.gate
TWICE = "twice"


def _raw(repo: pathlib.Path, kind: str, data: bytes) -> str:
    return subprocess.run(["git", "-C", str(repo), "hash-object", "--literally", "-t", kind, "-w", "--stdin"],
                          input=data, capture_output=True, check=True).stdout.decode().strip()


def _entry(mode: bytes, name: bytes, oid: str) -> bytes:
    return mode + b" " + name + b"\0" + bytes.fromhex(oid)


def _commit(repo: pathlib.Path, tree: str) -> str:
    commit = td._git(repo, "commit-tree", tree, "-m", "dup").strip()
    td._git(repo, "update-ref", "refs/heads/main", commit)
    return commit


def _ambiguous(tmp_path: pathlib.Path, shape: str) -> tuple[pathlib.Path, str]:
    repo = td._repo(tmp_path, {"README.md": "r\n"})
    readme = _raw(repo, "blob", b"r\n")
    first, last = _raw(repo, "blob", b"print('first')\n"), _raw(repo, "blob", b"print('last')\n")
    if shape == "a file twice in a code folder":
        src = _raw(repo, "tree", _entry(b"100644", b"app.py", first) + _entry(b"100644", b"app.py", last))
        root = _entry(b"100644", b"README.md", readme) + _entry(b"40000", b"src", src)
    elif shape == "a folder twice":
        a = _raw(repo, "tree", _entry(b"100644", b"a.py", first))
        b = _raw(repo, "tree", _entry(b"100644", b"b.py", last))
        root = _entry(b"100644", b"README.md", readme) + _entry(b"40000", b"src", a) + _entry(b"40000", b"src", b)
    elif shape == "a file and a folder of one name":
        folder = _raw(repo, "tree", _entry(b"100644", b"y", last))
        root = _entry(b"100644", b"README.md", readme) + _entry(b"100644", b"x", first) + _entry(b"40000", b"x", folder)
    else:   # the .proofbundle folder twice
        one = _raw(repo, "tree", _entry(b"100644", b"evidence.json", first))
        root = (_entry(b"40000", b".proofbundle", one) + _entry(b"40000", b".proofbundle", _raw(repo, "tree", b""))
                + _entry(b"100644", b"README.md", readme))
    return repo, _commit(repo, _raw(repo, "tree", root))


SHAPES = ["a file twice in a code folder", "a folder twice", "a file and a folder of one name",
          "the .proofbundle folder twice"]


@pytest.mark.parametrize("shape", SHAPES)
def test_the_gate_gives_no_digest_for_a_tree_that_names_a_path_twice(tmp_path, shape):
    repo, commit = _ambiguous(tmp_path, shape)
    with pytest.raises(gate.GateError, match=TWICE):
        gate.tree_digest(str(repo), commit)
    command = subprocess.run([sys.executable, str(td.GATE), "tree-digest", "--repo", str(repo), "--rev", commit],
                             capture_output=True, text=True, check=False)
    assert command.returncode != 0 and command.stdout == "" and TWICE in command.stderr, command


@pytest.mark.parametrize("shape", SHAPES)
def test_the_readme_recipe_gives_no_digest_for_it_either(tmp_path, shape):
    repo, commit = _ambiguous(tmp_path, shape)
    proc = subprocess.run(["bash", "-c", td._recipe(), "recipe", commit], cwd=repo, capture_output=True, text=True,
                          check=False, env=plugin_env(LC_ALL="C"))
    assert proc.returncode != 0 and proc.stdout == "" and TWICE in proc.stderr, proc


def test_the_ci_mode_does_not_pass_evidence_signed_over_such_a_tree(tmp_path):
    """The case of the class list: evidence signed over the manifest the gate made of that tree, two records for one
    path; the CI mode passed it (exit 0)."""
    repo, commit = _ambiguous(tmp_path, "a file twice in a code folder")
    listing = td._git(repo, "ls-tree", "-r", "-z", "--full-tree", commit).split("\0")
    records = []
    for record in filter(None, listing):
        meta, path = record.split("\t", 1)
        mode, _kind, oid = meta.split()
        data = subprocess.run(["git", "-C", str(repo), "cat-file", "blob", oid], capture_output=True, check=True).stdout
        records.append((path.encode(), mode.encode(), hashlib.sha256(data).hexdigest().encode()))
    records.sort(key=lambda r: r[0])
    manifest = gate.TREE_HEADER + b"".join(m + b" " + d + b" " + p + b"\0" for p, m, d in records)
    assert manifest.count(b" src/app.py\0") == 2
    digest = hashlib.sha256(manifest).hexdigest()
    signer = cg.generate_signer()
    for rel, content in ((cg.BUNDLE, cg.emit_bundle(cg._statement(digest), signer)), (cg.POLICY, cg._pinned_policy(signer)),
                         (gate.DECLARATION, {"schema": gate.DECLARATION_SCHEMA, "evidence": [
                             {"kind": "bundle", "path": cg.BUNDLE, "policy": cg.POLICY, "subject": cg._subject(digest)}]})):
        target = repo / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content if isinstance(content, str) else json.dumps(content), encoding="utf-8")
    blobs = {name: _raw(repo, "blob", (repo / gate.EVIDENCE_DIR / name).read_bytes())
             for name in ("build.bundle.json", "evidence.json", "policy.json")}
    folder = _raw(repo, "tree", b"".join(_entry(b"100644", n.encode(), o) for n, o in sorted(blobs.items())))
    code = td._git(repo, "rev-parse", f"{commit}^{{tree}}").strip()
    root = subprocess.run(["git", "-C", str(repo), "cat-file", "tree", code], capture_output=True, check=True).stdout
    declared = _commit(repo, _raw(repo, "tree", _entry(b"40000", b".proofbundle", folder) + root))
    td._git(repo, "reset", "-q", "--hard", declared)
    proc = subprocess.run([sys.executable, str(td.GATE), "ci-check", "--repo", str(repo), "--require-declaration",
                           "true"], capture_output=True, text=True, check=False, env=cg_env())
    assert proc.returncode == 1 and TWICE in proc.stdout + proc.stderr, (proc.returncode, proc.stdout, proc.stderr)


def cg_env() -> dict:
    """The verifier the CI mode starts: this interpreter with this checkout's package, through a `uv` on PATH."""
    import tempfile
    folder = pathlib.Path(tempfile.mkdtemp(prefix="b17-uv-"))
    (folder / "uv").write_text(f'#!/bin/sh\nwhile [ "$1" != "--script" ]; do shift; done\nshift\n'
                               f'exec "{sys.executable}" "$@"\n', encoding="utf-8")
    (folder / "uv").chmod(0o755)
    package_root = str(pathlib.Path(cg.proofbundle.__file__).resolve().parent.parent)
    return plugin_env(PATH=os.pathsep.join([str(folder), os.environ.get("PATH", "")]),
                PYTHONPATH=os.pathsep.join(p for p in (package_root, os.environ.get("PYTHONPATH")) if p))


def test_control_a_folder_of_the_evidence_name_deeper_in_the_tree_is_covered_once(tmp_path):
    repo = td._repo(tmp_path, {"README.md": "r\n", "deep/.proofbundle/x": "covered\n"})
    digest = gate.tree_digest(str(repo), "HEAD")
    assert td._by_recipe(repo) == digest == td._by_command(repo)
    assert b" deep/.proofbundle/x\0" in gate.tree_manifest(str(repo), "HEAD")


def test_control_the_known_answer_stays(tmp_path):
    repo = td._repo(tmp_path, td.KNOWN_TREE)
    assert gate.tree_digest(str(repo), "HEAD") == "ce97e4507660203d647b60b304f351ea6680276a26014b117cbc4e8dea402f31"
