"""Three P1 findings of the reading of bundle G-2 (slice 02b-gate-core), line 3, each held by a case that fails on the
code as read.

- Part 7, D104: GNU rm takes any unambiguous abbreviation of a long option, so `rm --rec <dir>` deletes recursively,
  and the gate saw a recursive rm only in the exact spelling `--recursive`.
- Part 8, D119: the shell joins quoted and unquoted parts of a word, so `s''udo` runs sudo, and the door check split
  the line at the quotes and saw `s` and `udo`.
- Part 9: the key signer read the private key file through a plain open, so a symbolic link or a file that other
  accounts may read or write was taken as the key.
- Part 10: the secrets hook normalised `..` away before it walked the links, so `<link>/../config` with the link into
  a folder of keys read `.ssh/config` while the check looked at `<folder>/config` (owner answer A on OA-0e0ebea093).
"""
from __future__ import annotations

import importlib.util
import os
import pathlib
import subprocess
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
GATE = ROOT / "plugins" / "proofbundle" / "hooks" / "proofbundle_gate.py"
SIGNER = ROOT / "plugins" / "proofbundle" / "pilot" / "key_signer.py"
SECRETS = ROOT / "plugins" / "proofbundle" / "hooks" / "proofbundle_secrets.py"


def _load(path: pathlib.Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def gate():
    return _load(GATE, "proofbundle_gate_under_test")


@pytest.mark.parametrize("option", ["--recursive"[:n] for n in range(3, len("--recursive") + 1)])
def test_every_abbreviation_of_recursive_is_a_recursive_rm(gate, option):
    assert gate._rm_targets(["rm", option, "/somewhere/else"]) == [2]


@pytest.mark.parametrize("option", ["--force", "--dir", "--verbose", "--one-file-system", "--preserve-root"])
def test_control_other_long_options_do_not_recurse(gate, option):
    assert gate._rm_targets(["rm", option, "/somewhere/else"]) is None


def test_gnu_rm_does_recurse_with_an_abbreviation(tmp_path):
    """The premise of the case above, measured on the rm of this machine; only GNU rm is asked."""
    version = subprocess.run(["rm", "--version"], capture_output=True, text=True)
    if version.returncode != 0 or "GNU coreutils" not in version.stdout:
        pytest.skip("not GNU rm; the abbreviation rule is GNU getopt_long's")
    target = tmp_path / "target" / "below"
    target.mkdir(parents=True)
    (target / "file").write_text("x", encoding="utf-8")
    assert subprocess.run(["rm", "--rec", str(tmp_path / "target")]).returncode == 0
    assert not (tmp_path / "target").exists()


@pytest.mark.parametrize("spelling", ["s''udo", 's""udo', "\\sudo", "su\\do", "'sudo'", '"sudo"', "s'u'do", "/usr/bin/s''udo"])
def test_a_root_program_spelled_with_quotes_or_backslashes_is_the_door_root(gate, spelling):
    assert gate._release_door_words(f"{spelling} -n true") == "root"


@pytest.mark.parametrize("line", ["pseudo -n true", "git status", "gh pr view 41"])
def test_control_a_line_without_a_root_program_names_no_root_door(gate, line):
    assert gate._release_door_words(line) != "root"


@pytest.fixture()
def signer():
    pytest.importorskip("cryptography")
    return _load(SIGNER, "key_signer_under_test")


def _key_file(tmp_path: pathlib.Path, mode: int) -> pathlib.Path:
    key = tmp_path / "key"
    key.write_text("11" * 32 + "\n", encoding="ascii")
    os.chmod(key, mode)
    return key


def test_control_a_private_key_file_of_mode_600_is_read(signer, tmp_path):
    assert signer.private_key({"key_file": str(_key_file(tmp_path, 0o600))}) is not None


@pytest.mark.parametrize("mode", [0o644, 0o640, 0o604, 0o620, 0o602])
def test_a_key_file_other_accounts_may_read_or_write_is_refused(signer, tmp_path, mode):
    with pytest.raises((ValueError, OSError)):
        signer.private_key({"key_file": str(_key_file(tmp_path, mode))})


def test_a_key_file_reached_through_a_symbolic_link_is_refused(signer, tmp_path):
    link = tmp_path / "link"
    link.symlink_to(_key_file(tmp_path, 0o600))
    with pytest.raises((ValueError, OSError)):
        signer.private_key({"key_file": str(link)})


def test_a_key_path_that_is_a_folder_is_refused(signer, tmp_path):
    folder = tmp_path / "folder"
    folder.mkdir(mode=0o700)
    with pytest.raises((ValueError, OSError)):
        signer.private_key({"key_file": str(folder)})


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="no named pipes on this platform")
def test_a_key_path_that_is_a_fifo_is_refused_without_blocking(signer, tmp_path):
    """A plain open of a FIFO with no writer blocks (the class of R18-2), so the read runs in a process of its own
    under a time limit: a refusal ends it at once, a block ends it at the limit and fails the case."""
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo, 0o600)
    probe = ("import importlib.util, sys\n"
             "s = importlib.util.spec_from_file_location('k', sys.argv[1]); m = importlib.util.module_from_spec(s)\n"
             "s.loader.exec_module(m)\n"
             "try:\n    m.private_key({'key_file': sys.argv[2]})\nexcept (ValueError, OSError):\n    sys.exit(3)\n"
             "sys.exit(0)\n")
    try:
        r = subprocess.run([sys.executable, "-c", probe, str(SIGNER), str(fifo)], capture_output=True, timeout=20)
    except subprocess.TimeoutExpired:
        pytest.fail("reading a FIFO as the key file blocked")
    assert r.returncode == 3, r.stderr


@pytest.fixture(scope="module")
def secrets():
    return _load(SECRETS, "proofbundle_secrets_under_test")


def _tree(tmp_path: pathlib.Path) -> pathlib.Path:
    """<tmp>/.ssh/child/, <tmp>/.ssh/config, <tmp>/other/, and the links alias -> .ssh/child, plain -> other."""
    (tmp_path / ".ssh" / "child").mkdir(parents=True)
    (tmp_path / ".ssh" / "config").write_text("Host x\n", encoding="utf-8")
    (tmp_path / "other").mkdir()
    (tmp_path / "alias").symlink_to(tmp_path / ".ssh" / "child")
    (tmp_path / "plain").symlink_to(tmp_path / "other")
    return tmp_path


def test_a_link_followed_by_dotdot_into_a_folder_of_keys_is_found(secrets, tmp_path):
    root = _tree(tmp_path)
    path = f"{root}/alias/../config"
    assert os.path.realpath(path) == str(root / ".ssh" / "config")
    assert secrets.secret_problem(path, "/", str(root / "home")) is not None


def test_a_relative_link_and_dotdot_from_cwd_is_found(secrets, tmp_path):
    root = _tree(tmp_path)
    assert secrets.secret_problem("alias/../config", str(root), str(root / "home")) is not None


def test_control_a_link_and_dotdot_outside_any_folder_of_keys_stays_free(secrets, tmp_path):
    root = _tree(tmp_path)
    (root / "x").write_text("x", encoding="utf-8")
    assert secrets.secret_problem(f"{root}/plain/../x", "/", str(root / "home")) is None
    assert secrets.secret_problem(f"{root}/other/../x", "/", str(root / "home")) is None


def test_control_the_direct_paths_keep_their_answer(secrets, tmp_path):
    root = _tree(tmp_path)
    assert secrets.secret_problem(f"{root}/.ssh/config", "/", str(root / "home")) is not None
    assert secrets.secret_problem(f"{root}/alias/key", "/", str(root / "home")) is not None
    assert secrets.secret_problem(f"{root}/other/notes.txt", "/", str(root / "home")) is None
