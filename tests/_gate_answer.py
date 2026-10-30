"""How a plugin test reads the gate's answer since D53 (DECISIONS.md D53).

Since D53 a pass prints nothing, like a call the gate does not gate, and every other answer shows the user one short line
(systemMessage) while the model gets the long reason (additionalContext). A test that ran the gate and saw no output
could no longer tell a pass from a call the gate left alone, so `run_hook` gives the gate a plugin data directory of its
own (unless the environment names one) and returns the log line of the call with the output: the log line says which
it was (D21). `parsed` turns the two into what the test reads: the answer as printed, `Silent` for a judged call that
printed nothing, None for a call the gate did not judge.

`skip_where_the_gate_is_not_shipped` is for a module that imports the gate when it loads: where a distribution leaves
the gate out, the module is one skip that names the path, and anywhere else the import stays loud.
"""
from __future__ import annotations

import json
import pathlib
import re
import subprocess
import tempfile

import pytest

SHORT_LINE_MAX = 160
_D_NUMBER = re.compile(r"\(D[0-9]{1,3}[A-Z]?\)\.")
_LOG_NAME = "gate-log.jsonl"


class Silent(dict):
    """The answer of a call the gate judged and answered with nothing (a pass, D53): an empty mapping that carries the
    log line of the call, so a test reads the verdict and the reason ids there."""

    def __init__(self, entry: dict):
        super().__init__()
        self.entry = entry

    def __repr__(self) -> str:
        return f"Silent(verdict={self.entry.get('verdict')!r}, reason_ids={self.entry.get('reason_ids')!r})"


def _lines(directory: str) -> list[dict]:
    path = pathlib.Path(directory) / _LOG_NAME
    if not path.exists():
        return []
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines() if x.strip()]


def run_hook(argv: list[str], event_text: str, env: dict, *, cwd=None, timeout: int = 120):
    """Run the gate as the host runs it; (the finished process, the log line this call wrote or None). The gate gets a
    plugin data directory of its own unless env names one; then the line this call added there is read."""
    with tempfile.TemporaryDirectory() as data:
        env = dict(env)
        env.setdefault("CLAUDE_PLUGIN_DATA", data)
        before = len(_lines(env["CLAUDE_PLUGIN_DATA"]))
        proc = subprocess.run(argv, input=event_text, capture_output=True, text=True, env=env, cwd=cwd,
                              timeout=timeout, check=False)
        after = _lines(env["CLAUDE_PLUGIN_DATA"])
        entry = after[-1] if len(after) > before else None
    return proc, entry


def parsed(proc: subprocess.CompletedProcess, entry: dict | None):
    """The answer as printed; Silent for a pass the log names that printed nothing; None for everything else that
    printed nothing: a call the gate did not judge (no log line, or the verdict not_gated), and an inactive gate that
    already showed its line in the session or at a Stop without a done check, as before D53."""
    if proc.stdout.strip():
        return json.loads(proc.stdout)
    if entry is None or entry.get("verdict") != "pass":
        return None
    return Silent(entry)


def long_text(answer: dict) -> str:
    """What the model gets: the long reason (additionalContext)."""
    return answer["hookSpecificOutput"]["additionalContext"]


def short_text(answer: dict) -> str:
    """What the user sees, checked against its form (D53): one line, at most 160 characters, with a D number."""
    line = answer["systemMessage"]
    assert "\n" not in line and len(line) <= SHORT_LINE_MAX and _D_NUMBER.search(line), line
    return line


def skip_where_the_gate_is_not_shipped(gate: pathlib.Path, root: pathlib.Path) -> None:
    """Skip the calling module, at module level, where a distribution leaves the gate out; else return, and the
    module's own import of the gate stays loud.

    Measured on 2026-10-30 in hermetic-cleanroom of pull request 441 (heads 07a2ebcf and 8f433322): MANIFEST.in prunes
    plugins/, and four modules that import the gate when they load ended as collection errors in the extracted sdist.
    conftest turns a failed import into a skip only where the distribution ships something in the same first folder,
    and it ships nothing of plugins/. The rule here is the one test_strict_decoding_guard judges a path by: absent from
    a distribution (conftest's `baumkontext`, positive evidence) whose MANIFEST.in does not promise it is NOT MEASURED;
    absent from a checkout, from a tree that shows neither, or from a distribution that promises it, it stays loud."""
    if gate.is_file():
        return
    try:
        import conftest  # noqa: PLC0415 - tests/ is on sys.path under both runners
    except Exception:  # noqa: BLE001 - without conftest there is no basis, and no basis stays loud
        return
    art, _why = conftest.baumkontext(root)
    rel = gate.relative_to(root).as_posix()
    if art == "distribution" and not conftest._manifest_verspricht(rel, root):
        pytest.skip(f"NOT MEASURED: {rel} is not in this distribution, whose MANIFEST.in does not ship it",
                    allow_module_level=True)
