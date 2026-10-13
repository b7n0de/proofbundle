"""Review round 12 of 2026-10-13, R12-3: a path read byte for byte never puts invalid UTF-8 into the server's JSON.

Measured by the reviewer at 7588fe4a with git 2.51.1 and 2.43.0 under Linux: a hooks folder whose last name byte is 0xff,
with a post-receive in it; the same raw path as the global core.hooksPath of an isolated configuration; the server started
in an ordinary UTF-8 environment (Python 3.12.14, LANG, LC_ALL and LC_CTYPE C.UTF-8, no PYTHONIOENCODING);
gate_selftest_prepare over JSON-RPC, stdout decoded strictly as UTF-8. Prepare found the hook and refused rightly, but the
answer held a raw 0xff, exit 0, stderr empty, UnicodeDecodeError on decoding; both JSON outputs used ensure_ascii=False.

Property: a cautious refusal of the self-test gives a readable protocol answer; the check reads the path byte for byte,
and the message shows name bytes that are no Unicode text unambiguously and printably (a backslash as \\\\, such a byte as
\\xNN). Whatever string a reply carries, the JSON on stdout is valid UTF-8. The test decodes the server's real output
bytes strictly. Red against 3a1c4a3a.
"""
from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys

import pytest

import test_plugin_gate_log as gl

pytestmark = [gl.pytestmark, pytest.mark.skipif(sys.platform != "linux", reason="raw name bytes need Linux")]
env = gl.env
_clean_git_config = gl._clean_git_config

RESET = '#!/bin/sh\nwhile read old new ref; do git update-ref "$ref" "$old"; done\n'


def _raw_server(environ: dict, calls: list[tuple[str, dict]]) -> tuple[bytes, list[dict]]:
    """The server's stdout as bytes, then every reply decoded strictly as UTF-8 and read as JSON."""
    lines = [{"jsonrpc": "2.0", "id": 0, "method": "initialize", "params": {}}]
    lines += [{"jsonrpc": "2.0", "id": n + 1, "method": "tools/call", "params": {"name": name, "arguments": args}}
              for n, (name, args) in enumerate(calls)]
    proc = subprocess.run([sys.executable, str(gl.SERVER)], input="".join(json.dumps(m) + "\n" for m in lines).encode(),
                          capture_output=True, env=environ, timeout=120, check=True)
    text = proc.stdout.decode("utf-8")   # strict: an invalid byte raises here
    return proc.stdout, [json.loads(line) for line in text.splitlines()]


def _utf8_env(env: dict, tmp_path: pathlib.Path, home: pathlib.Path) -> dict:
    environ = {k: v for k, v in env.items() if k not in ("GIT_CONFIG_GLOBAL", "PYTHONIOENCODING", "PYTHONUTF8")}
    temp = tmp_path / "temp"
    temp.mkdir(exist_ok=True)
    return dict(environ, HOME=str(home), TMPDIR=str(temp), LANG="C.UTF-8", LC_ALL="C.UTF-8", LC_CTYPE="C.UTF-8",
                CLAUDE_PLUGIN_DATA=str(tmp_path / "data"))


def _hooks_home(tmp_path: pathlib.Path, folder_name: bytes) -> tuple[pathlib.Path, bytes]:
    folder = os.fsencode(tmp_path) + b"/" + folder_name
    os.mkdir(folder)
    hook = folder + b"/post-receive"
    with open(hook, "w", encoding="utf-8") as handle:
        handle.write(RESET)
    os.chmod(hook, 0o755)
    home = tmp_path / "home"
    home.mkdir()
    escaped = folder.replace(b"\\", b"\\\\").replace(b'"', b'\\"')
    (home / ".gitconfig").write_bytes(b'[core]\n\thooksPath = "' + escaped + b'"\n')
    return home, folder


@pytest.mark.parametrize("name, shown", [(b"hk\xff", "hk\\xff"), (b"hk\\xff\xfe", "hk\\\\xff\\xfe")],
                         ids=["the reviewers byte", "a backslash beside an undecodable byte"])
def test_a_refused_hooks_folder_with_undecodable_bytes_gives_a_readable_answer(env, tmp_path, name, shown):
    home, folder = _hooks_home(tmp_path, name)
    raw, replies = _raw_server(_utf8_env(env, tmp_path, home), [("gate_selftest_prepare", {})])
    (prepared,) = [r for r in replies if r.get("id") == 1]
    assert prepared["result"]["isError"] is True, prepared
    error = json.loads(prepared["result"]["content"][0]["text"])["error"]
    assert error.startswith("NOT MEASURABLE: the hooks folder "), error
    assert f"{os.fsdecode(os.fsencode(tmp_path))}/{shown} of the throwaway remote holds a post-receive hook" in error, error
    assert b"\xff" not in raw and b"\xfe" not in raw


def test_git_takes_the_folder_with_the_undecodable_byte(tmp_path):
    """Non-vacuous: git names the folder with its raw last byte."""
    home, folder = _hooks_home(tmp_path, b"hk\xff")
    bare = tmp_path / "bare.git"
    subprocess.run(["git", "init", "-q", "--bare", str(bare)], check=True)
    environ = dict({k: v for k, v in os.environ.items() if k != "GIT_CONFIG_GLOBAL"}, HOME=str(home))
    answer = subprocess.run(["git", "-C", str(bare), "rev-parse", "--path-format=absolute", "--git-path", "hooks"],
                            capture_output=True, env=environ, check=True).stdout
    assert answer == folder + b"\n"


def test_a_throwaway_folder_whose_path_is_no_utf8_text_is_refused_readably(env, tmp_path):
    """The class, measured at 3a1c4a3a: with TMPDIR holding a 0xff byte, prepare stopped on a strict decoding of git's
    answer and the server answered only "internal error". Its command could not be handed out as text either."""
    temp = os.fsencode(tmp_path) + b"/temp\xff"
    os.mkdir(temp)
    home = tmp_path / "home"
    home.mkdir()
    environ = _utf8_env(env, tmp_path, home)
    environ["TMPDIR"] = os.fsdecode(temp)
    raw, replies = _raw_server(environ, [("gate_selftest_prepare", {})])
    (prepared,) = [r for r in replies if r.get("id") == 1]
    assert b"\xff" not in raw
    assert prepared["result"]["isError"] is True, prepared
    error = json.loads(prepared["result"]["content"][0]["text"])["error"]
    assert error.startswith("NOT MEASURABLE: the self-test's throwaway folder "), error
    assert "/temp\\xff/" in error and "is not UTF-8 text" in error, error
    assert os.listdir(temp) == []   # prepare left no throwaway folder behind
