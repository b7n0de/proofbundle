"""Who reads the files the plugin writes, and the mode each one is made with (CodeQL alerts 147 to 153).

CodeQL named seven places where the plugin makes a file that other accounts may read (py/overly-permissive-file).
The readers were measured per file in the code on 2026-10-31; this machine holds no account of the pilot, so the code
and the pilot's contract are the measurement.

Read under the account of the session alone, now made with mode 600:
- the gate log, gate-log.jsonl in the plugin data directory (the gate's write_log, alert 150, and
  proofbundle_answered.append_log, alert 149): the gate's bilanz and the plugin's server read it, both under the
  session's account; asks-pending.json and open-prs.json beside it were already made through mkstemp, mode 600;
- the done check's own files in .proofbundle/ (_write_done_file, alert 151): only the Stop hook reads them back, and
  git ignores them.

Read by another account on purpose, kept, each with the reader in READERS:
- pin-state.json in the gate directory (pin_state_schleuse._write_atomic, alert 148, 644);
- the decision receipts of the pilot (_pilot_issue, alert 152, 644);
- the pre-push hook (install_pre_push, alert 153, 755);
- the key signer's export into the records (key_signer._replace, alert 147, 644);
- and, not among the seven, the .proofbundle folder of a work tree (_evidence_folder, 755).

The guard reads every literal mode the plugin's code hands os.open, os.chmod, os.fchmod, os.mkdir, os.makedirs and
os.mkfifo, the mode of a chmod, mkdir or touch of another object, and the default of a parameter named mode. Each
one that lets another account in must stand in READERS, and each entry there must still be found. It does not read a
mode that is no literal at the call (a variable, open(), pathlib's write_text, makedirs without a mode): the umask
decides those.
"""
from __future__ import annotations

import ast
import importlib.util
import os
import pathlib
import sys

import pytest

from _gate_answer import skip_where_the_gate_is_not_shipped

ROOT = pathlib.Path(__file__).resolve().parents[1]
PLUGIN = ROOT / "plugins" / "proofbundle"
GATE = PLUGIN / "hooks" / "proofbundle_gate.py"
ANSWERED = PLUGIN / "hooks" / "proofbundle_answered.py"

skip_where_the_gate_is_not_shipped(GATE, ROOT)

#: (file, function, call, mode) -> (the account that reads it, and a text of the code that shows the reader).
READERS = {
    ("plugins/proofbundle/hooks/pin_state_schleuse.py", "_write_atomic", "default mode", 0o644): (
        "the pilot's signer service decides with the gate directory under an account of its own (D58)",
        ("plugins/proofbundle/pilot/signer_service.py", '"PROOFBUNDLE_GATE_DIR": config["gate_dir"]')),
    ("plugins/proofbundle/hooks/proofbundle_gate.py", "_pilot_issue", "os.open", 0o644): (
        "the observer and the reconciliation read the decisions from the records under the operator's accounts (D56)",
        ("plugins/proofbundle/pilot/pilot_records.py", '(self.folder / "decisions").glob("*.json")')),
    ("plugins/proofbundle/hooks/proofbundle_gate.py", "install_pre_push", "os.chmod", 0o755): (
        "git runs the hook at a push, and the pin check reads its bytes under the signer service's account too",
        ("plugins/proofbundle/hooks/proofbundle_gate.py", '_hooks_now(paths["hooks"]) != entry["haken"]')),
    ("plugins/proofbundle/pilot/key_signer.py", "_replace", "os.open", 0o644): (
        "the reconciliation reads keysigner/ of the records under an account other than the key account (D65)",
        ("plugins/proofbundle/pilot/pilot_records.py", 'KEY_JOURNAL_FOLDER = "keysigner"')),
    ("plugins/proofbundle/hooks/proofbundle_gate.py", "_evidence_folder", "os.mkdir", 0o755): (
        "a folder of the work tree that holds the committed declaration, made as git makes a folder at a checkout",
        ("plugins/proofbundle/hooks/proofbundle_gate.py", 'DECLARATION = EVIDENCE_DIR + "evidence.json"')),
}

#: The calls of os whose mode the guard reads, with the position of the mode.
_OS_MODE = {"open": 2, "chmod": 1, "fchmod": 1, "mkdir": 1, "makedirs": 1, "mkfifo": 1}
#: The same calls on another object, as pathlib has them: the mode first.
_OBJECT_MODE = {"chmod": 0, "mkdir": 0, "touch": 0}


def _others_may(node: ast.AST | None) -> bool:
    return isinstance(node, ast.Constant) and type(node.value) is int and bool(node.value & 0o077)


def wide_modes(source: str) -> list[tuple[str, str, int]]:
    """(function, call, mode) for each literal mode of the source that lets another account read, write or run."""
    found: list[tuple[str, str, int]] = []

    def visit(node: ast.AST, function: str) -> None:
        for child in ast.iter_child_nodes(node):
            inner = function
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                inner = child.name
                positional = child.args.posonlyargs + child.args.args
                defaults = dict(zip([a.arg for a in positional][len(positional) - len(child.args.defaults):],
                                    child.args.defaults))
                defaults.update({a.arg: d for a, d in zip(child.args.kwonlyargs, child.args.kw_defaults)})
                if _others_may(defaults.get("mode")):
                    found.append((inner, "default mode", defaults["mode"].value))
            elif isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute):
                on_os = isinstance(child.func.value, ast.Name) and child.func.value.id == "os"
                table = _OS_MODE if on_os else _OBJECT_MODE
                if child.func.attr in table:
                    at = table[child.func.attr]
                    mode = child.args[at] if len(child.args) > at else \
                        next((k.value for k in child.keywords if k.arg == "mode"), None)
                    if _others_may(mode):
                        found.append((function, f"os.{child.func.attr}" if on_os else f".{child.func.attr}",
                                      mode.value))
            visit(child, inner)

    visit(ast.parse(source), "<module>")
    return found


def _plugin_sources() -> list[pathlib.Path]:
    return sorted(p for p in PLUGIN.rglob("*.py") if "__pycache__" not in p.parts)


def _load(path: pathlib.Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def gate():
    return _load(GATE, "proofbundle_gate_readers_under_test")


@pytest.fixture()
def no_umask():
    """The mode the code asks for, not what the umask of the caller leaves of it."""
    before = os.umask(0)
    try:
        yield
    finally:
        os.umask(before)


def _mode(path: pathlib.Path) -> int:
    return path.stat().st_mode & 0o777


def test_the_gate_log_is_made_for_the_session_account_alone(gate, tmp_path, monkeypatch, no_umask):
    data = tmp_path / "data"
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(data))
    written = gate.write_log({"ts": "2026-10-31T00:00:00Z", "decision": "none"}, "claude")
    assert written == str(data / gate.LOG_NAME)
    assert _mode(data / gate.LOG_NAME) == 0o600


def test_the_answer_hook_makes_the_gate_log_for_the_session_account_alone(tmp_path, no_umask):
    answered = _load(ANSWERED, "proofbundle_answered_readers_under_test")
    answered.append_log(str(tmp_path), {"decision": "answered"})
    assert _mode(tmp_path / answered.LOG_NAME) == 0o600


@pytest.mark.parametrize("name", ["DONE_STATE", "DONE_METRICS", "DONE_BLOCKER"])
def test_the_done_check_files_are_made_for_the_session_account_alone(gate, tmp_path, no_umask, name):
    repo = tmp_path / "repo"
    repo.mkdir()
    assert gate._write_done_file(str(repo), getattr(gate, name), {"schema": "x"}) is None
    assert _mode(repo / getattr(gate, name)) == 0o600


def test_control_a_log_line_still_lands_where_the_gate_reads_it(gate, tmp_path, monkeypatch, no_umask):
    data = tmp_path / "data"
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(data))
    gate.write_log({"decision": "none", "n": 1}, "claude")
    gate.write_log({"decision": "none", "n": 2}, "claude")
    assert [line for line in (data / gate.LOG_NAME).read_text(encoding="utf-8").splitlines()] == [
        '{"decision": "none", "n": 1}', '{"decision": "none", "n": 2}']


def test_every_mode_that_lets_another_account_in_names_its_reader():
    found = {(p.relative_to(ROOT).as_posix(), *entry) for p in _plugin_sources()
             for entry in wide_modes(p.read_text(encoding="utf-8"))}
    assert sorted(found - set(READERS)) == [], "a mode other accounts may use, with no reader named in READERS"
    assert sorted(set(READERS) - found) == [], "an entry of READERS the code no longer has"


@pytest.mark.parametrize("key", sorted(READERS))
def test_each_kept_mode_points_at_a_reader_the_code_still_has(key):
    _why, (path, text) = READERS[key]
    assert text in (ROOT / path).read_text(encoding="utf-8")


def test_the_guard_finds_each_form_it_reads_and_none_it_does_not():
    planted = (
        "import os, pathlib\n"
        "def wide(p, fd, mode=0o644):\n"
        "    os.open(p, os.O_CREAT, 0o644)\n"
        "    os.open(p, os.O_CREAT, mode=0o640)\n"
        "    os.chmod(p, 0o755)\n"
        "    os.fchmod(fd, 0o604)\n"
        "    os.makedirs(p, mode=0o750, exist_ok=True)\n"
        "    os.mkdir(p, 0o711)\n"
        "    pathlib.Path(p).chmod(0o664)\n"
        "    pathlib.Path(p).mkdir(mode=0o775)\n"
        "def narrow(p, fd, st, mode=0o600):\n"
        "    os.open(p, os.O_CREAT, 0o600)\n"
        "    os.chmod(p, 0o700)\n"
        "    os.makedirs(p, exist_ok=True)\n"
        "    os.chmod(p, mode)\n"
        "    return st.st_mode & 0o022, 0o644\n"
    )
    assert wide_modes(planted) == [
        ("wide", "default mode", 0o644), ("wide", "os.open", 0o644), ("wide", "os.open", 0o640),
        ("wide", "os.chmod", 0o755), ("wide", "os.fchmod", 0o604), ("wide", "os.makedirs", 0o750),
        ("wide", "os.mkdir", 0o711), ("wide", ".chmod", 0o664), ("wide", ".mkdir", 0o775)]
