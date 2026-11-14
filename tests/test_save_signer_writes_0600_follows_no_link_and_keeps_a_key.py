"""`save_signer` writes a private seed: mode 0600 after every write, no link followed, no key silently replaced.

Found by the deep gate of 6.6.0 at 41959070 (lenses L2 and L4, confirmed by delta in three clones, staged P2 by the
third reading): the docstring of `save_signer` promised "mode 0600 ... never world-readable", but `os.open` with
`O_CREAT | O_TRUNC` sets the mode only when it creates the file. An existing file kept its mode (0644 measured), a
symbolic link at the path was followed and its target received the seed, and `--new-key` in seven commands
replaced an existing key file and exited 0 without a word.

What holds now, and what each case catches:

- the library writes the seed into a fresh file and moves it into place, so the path carries mode 0600 after the
  write whatever the file there had before (catches: the mode set only at creation);
- a symbolic link at the path is replaced, not followed, so the file it pointed to keeps its bytes (catches: a write
  through the link);
- with ``overwrite=False`` an existing path, a link included, is refused with ``FileExistsError`` and keeps its bytes
  (catches: a check that is made, but not at the moment of the write);
- every ``--new-key`` command refuses a path that exists or is a link, names it, writes no key and no output and ends
  with exit 2 (catches: the silent replacement through the command line);
- a fresh path still works from the command line and carries mode 0600 (the control).
"""

from __future__ import annotations

import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from proofbundle.emit import generate_signer, load_signer, save_signer

REPO = Path(__file__).resolve().parents[1]

pytestmark = pytest.mark.skipif(os.name != "posix", reason="file modes and symbolic links are POSIX properties")


def _modus(p: Path) -> int:
    return stat.S_IMODE(os.lstat(p).st_mode)


def _cli(*args: str, cwd: Path) -> subprocess.CompletedProcess:
    env = dict(os.environ, PYTHONPATH=str(REPO / "src"))
    return subprocess.run([sys.executable, "-m", "proofbundle.cli", *args], cwd=cwd, env=env,
                          capture_output=True, text=True, timeout=180)


def test_an_existing_file_with_a_wider_mode_carries_0600_after_the_write(tmp_path):
    p = tmp_path / "signer.key"
    p.write_bytes(b"old")
    os.chmod(p, 0o644)
    key = generate_signer()
    save_signer(key, str(p))
    assert _modus(p) == 0o600, oct(_modus(p))
    assert load_signer(str(p)).private_bytes_raw() == key.private_bytes_raw()


def test_a_link_at_the_path_is_replaced_and_its_target_keeps_its_bytes(tmp_path):
    ziel = tmp_path / "victim.txt"
    ziel.write_bytes(b"not a key")
    os.chmod(ziel, 0o644)
    p = tmp_path / "signer.key"
    os.symlink(ziel, p)
    save_signer(generate_signer(), str(p))
    assert ziel.read_bytes() == b"not a key"
    assert _modus(ziel) == 0o644
    assert not p.is_symlink() and p.is_file()
    assert _modus(p) == 0o600


def test_overwrite_false_refuses_an_existing_path_and_a_link_and_keeps_the_bytes(tmp_path):
    p = tmp_path / "signer.key"
    p.write_bytes(b"keep me")
    with pytest.raises(FileExistsError):
        save_signer(generate_signer(), str(p), overwrite=False)
    assert p.read_bytes() == b"keep me"
    link = tmp_path / "dangling.key"
    os.symlink(tmp_path / "nowhere", link)
    with pytest.raises(FileExistsError):
        save_signer(generate_signer(), str(link), overwrite=False)
    assert not (tmp_path / "nowhere").exists()
    frisch = tmp_path / "fresh.key"
    save_signer(generate_signer(), str(frisch), overwrite=False)
    assert _modus(frisch) == 0o600
    assert [x.name for x in tmp_path.iterdir() if x.name.startswith(".")] == []


@pytest.mark.parametrize("vorhanden", ["file", "link"])
def test_new_key_refuses_an_existing_path_writes_nothing_and_exits_2(tmp_path, vorhanden):
    payload = tmp_path / "payload.txt"
    payload.write_text("x", encoding="utf-8")
    out = tmp_path / "bundle.json"
    p = tmp_path / "signer.key"
    ziel = tmp_path / "elsewhere.txt"
    if vorhanden == "file":
        p.write_bytes(b"an older key")
    else:
        os.symlink(ziel, p)
    r = _cli("emit", "--payload-file", str(payload), "--out", str(out), "--new-key", str(p), cwd=tmp_path)
    assert r.returncode == 2, (r.returncode, r.stderr)
    assert "already exists" in r.stderr and str(p) in r.stderr, r.stderr
    assert "Traceback" not in r.stderr
    assert not out.exists()
    if vorhanden == "file":
        assert p.read_bytes() == b"an older key"
    else:
        assert p.is_symlink() and not ziel.exists()


def test_new_key_on_a_fresh_path_still_works_and_carries_0600(tmp_path):
    payload = tmp_path / "payload.txt"
    payload.write_text("x", encoding="utf-8")
    out = tmp_path / "bundle.json"
    p = tmp_path / "signer.key"
    r = _cli("emit", "--payload-file", str(payload), "--out", str(out), "--new-key", str(p), cwd=tmp_path)
    assert r.returncode == 0, r.stderr
    assert out.exists()
    assert _modus(p) == 0o600
