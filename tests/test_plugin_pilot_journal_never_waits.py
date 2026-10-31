"""N4-4 (external review of -1, PILOT finding 1, KERN finding 5, K-3): the pilot's journal never holds the answer.

The gate attempts its receipts after its verdict and before its answer (D55). _pilot_journal opened
<receipts>/journal.jsonl with a blocking open(..., "a"). With a valid pilot.json whose signer is /bin/false the receipt
fails, the gate journals why, and a FIFO named journal.jsonl without a reader held the hook in that open before it
printed its permission answer, with no deadline: the reviewer measured a two-second wait on both shipped host forms,
released by opening a reader. The owner's order on it (addendum 4, point 4): journal access does not block, only a
regular file at the opened descriptor is written, and the gate's answer stands under every receipt-side failure. The
owner's releases of D119, which wait for a signed ALLOW by design, are the one exception and are named apart.

Each case runs the hook as a subprocess, as a host starts it, in three forms: Claude Code without a flag, Claude Code
with --autonomous, and Codex (--host codex). The event is the data of a `gh pr comment ... --repo
b7n0de/review-local-only` call in a temporary repository; nothing runs it and nothing reaches GitHub. The pilot's ids
are dummies and its signer is /bin/false, so every case journals. A case compares the answer (exit code, stdout,
stderr and the log line without its time) with the answer to the same event without pilot.json, each run with plugin
data of its own. A run that gives no answer within ANSWER_SECONDS is released (each FIFO is opened without blocking),
killed and failed, so no case hangs, and every FIFO is removed after its case.

RED at 16cffca, 14 of 35 cases: the hook gives no answer within ANSWER_SECONDS where the journal is a FIFO without a
reader or a link to one, in each of the three forms, and the pre-push hook gives none either; a FIFO with a reader gets
the journal line, a link to a regular file is followed, and the policy digest waits on a FIFO in the place of the gate's
own file. The other receipt-side failures and the ordinary journal leave the answer as it is there too; those cases
hold that it stays so.
"""
from __future__ import annotations

import contextlib
import json
import os
import pathlib
import shutil
import stat
import subprocess
import sys

import pytest

import test_plugin_gate_n2c_push_done as pd
import test_plugin_z405_decision_receipt as p1
from _plugin_env import plugin_env

gate = p1.gate
GATE = p1.GATE
pytestmark = [pd.pytestmark, pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="no FIFOs here")]

#: Seconds within which a run must answer here: generous for a slow runner, far below the hook's 120 s.
ANSWER_SECONDS = 20
COMMAND = "gh pr comment 1 --body probe --repo b7n0de/review-local-only"
#: The hook commands of the manifests, without the interpreter and the gate's path.
HOSTS = {"claude": [], "claude --autonomous": [gate.AUTONOMOUS_FLAG], "codex": ["--host", "codex"]}
#: Receipt-side failures other than the FIFO journal without a reader (PILOT finding 1, its class).
SIDES = ["journal_folder", "journal_link_to_fifo", "receipts_fifo", "receipts_file", "decisions_fifo",
         "receipt_slot_fifo"]


@pytest.fixture(autouse=True)
def _clean_git_environment(monkeypatch):
    pd._clean_git_environment.__wrapped__(monkeypatch)


@pytest.fixture
def world(tmp_path):
    made = World(tmp_path)
    try:
        yield made
    finally:
        _remove_fifos(tmp_path)


def _remove_fifos(folder: pathlib.Path) -> None:
    for parent, dirs, files in os.walk(folder):
        for name in dirs + files:
            path = os.path.join(parent, name)
            if stat.S_ISFIFO(os.lstat(path).st_mode):
                os.unlink(path)


def _run(argv: list[str], stdin: str, env: dict, cwd: pathlib.Path,
         fifos: list[pathlib.Path]) -> subprocess.CompletedProcess:
    """argv as a host or git starts it. A run without an answer within ANSWER_SECONDS fails: a reader and then a writer
    open each FIFO without blocking, so an open waiting on either end returns, and the run is killed."""
    proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                            env=env, cwd=str(cwd))
    try:
        try:
            out, err = proc.communicate(stdin, timeout=ANSWER_SECONDS)
        except subprocess.TimeoutExpired:
            ends = []
            try:
                for fifo in fifos:
                    for flags in (os.O_RDONLY, os.O_WRONLY):
                        with contextlib.suppress(OSError):
                            ends.append(os.open(fifo, flags | os.O_NONBLOCK))
                proc.kill()
                proc.communicate(timeout=ANSWER_SECONDS)
            finally:
                for fd in ends:
                    os.close(fd)
            pytest.fail(f"no answer within {ANSWER_SECONDS} s: the run waited until a FIFO was opened for it")
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.communicate(timeout=ANSWER_SECONDS)
    return subprocess.CompletedProcess(argv, proc.returncode, out, err)


class World:
    """A temporary repository, a gate directory and plugin data; the hook runs with pilot.json or without it."""

    def __init__(self, tmp_path: pathlib.Path):
        self.tmp = tmp_path
        self.repo, self.gate_dir, self.data, home = (tmp_path / n for n in ("repo", "gate", "data", "home"))
        for folder in (self.repo, self.gate_dir, home):
            folder.mkdir()
        self.receipts = tmp_path / "receipts"
        self.journal = self.receipts / "journal.jsonl"
        self.env = plugin_env(HOME=str(home), PROOFBUNDLE_GATE_DIR=str(self.gate_dir),
                              CLAUDE_PLUGIN_DATA=str(self.data), PLUGIN_DATA=str(self.data))
        subprocess.run(["git", "init", "-q", str(self.repo)], env=self.env, capture_output=True, check=True,
                       timeout=60)
        self.event = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": str(self.repo),
                      "tool_input": {"command": COMMAND}}

    def pilot(self, signer: list[str] | None = None, public_key: str = "00" * 32) -> dict:
        """pilot.json with dummy ids; the signer /bin/false fails each receipt."""
        config = {"profile": "github-write/1", "gate_id": "operator:gate", "observer_id": "operator:observer",
                  "agent_id": "agent:probe", "principal_id": "operator", "validity_seconds": 600,
                  "receipts": str(self.receipts), "signer": signer or ["/bin/false"], "public_key": public_key,
                  "closing_rules": None}
        (self.gate_dir / "pilot.json").write_text(json.dumps(config), encoding="utf-8")
        return config

    def hook(self, host: str, fifos: list[pathlib.Path] = ()) -> tuple:
        """One run in the form `host`, with empty plugin data: exit code, stdout, stderr, the log lines without time."""
        shutil.rmtree(self.data, ignore_errors=True)
        self.data.mkdir()
        proc = _run([sys.executable, "-I", str(GATE), *HOSTS[host]], json.dumps(self.event), self.env, self.repo,
                    list(fifos))
        log = self.data / gate.LOG_NAME
        lines = [json.loads(x) for x in log.read_text(encoding="utf-8").splitlines()] if log.exists() else []
        return proc.returncode, proc.stdout, proc.stderr, [{k: v for k, v in e.items() if k != "ts"} for e in lines]

    def journal_lines(self) -> list[tuple]:
        if not (self.journal.is_file() and not self.journal.is_symlink()):
            return []
        return [(e["issued"], e.get("why")) for e in map(json.loads, self.journal.read_text("utf-8").splitlines())]

    def side(self, name: str, config: dict) -> list[pathlib.Path]:
        """Put one receipt-side failure in place; the FIFOs it made."""
        if name == "receipts_fifo":
            os.mkfifo(self.receipts)
            return [self.receipts]
        if name == "receipts_file":
            self.receipts.write_text("a file where the receipt folder belongs\n", encoding="utf-8")
            return []
        self.receipts.mkdir()
        if name == "journal_fifo":
            os.mkfifo(self.journal)
            return [self.journal]
        if name == "journal_folder":
            self.journal.mkdir()
            return []
        if name == "journal_link_to_fifo":
            target = self.tmp / "elsewhere.fifo"
            os.mkfifo(target)
            self.journal.symlink_to(target)
            return [target]
        decisions = self.receipts / "decisions"
        if name == "decisions_fifo":
            os.mkfifo(decisions)
            return [decisions]
        if name == "receipt_slot_fifo":   # the file the first receipt of this call would take
            action, key = gate._pilot_tool_action(self.event)
            decisions.mkdir()
            slot = decisions / f"{gate._pilot_action_id(config, action, key)}-1.json"
            os.mkfifo(slot)
            return [slot]
        raise AssertionError(name)


def _same_answer(world: World, host: str, name: str) -> list[pathlib.Path]:
    baseline = world.hook(host)
    config = world.pilot()
    fifos = world.side(name, config)
    assert world.hook(host, fifos) == baseline
    return fifos


@pytest.mark.parametrize("host", HOSTS)
def test_N4_4_a_fifo_journal_without_a_reader_does_not_hold_the_answer(world, host):
    """PILOT finding 1, the reviewer's reproduction under each shipped hook form: the answer comes within the bound
    and is the answer without the pilot; nothing is written into the FIFO and it stays a FIFO."""
    (fifo,) = _same_answer(world, host, "journal_fifo")
    assert stat.S_ISFIFO(os.lstat(fifo).st_mode)


@pytest.mark.parametrize("host", HOSTS)
@pytest.mark.parametrize("name", SIDES)
def test_N4_4_a_receipt_side_failure_leaves_the_answer_as_it_is(world, host, name):
    fifos = _same_answer(world, host, name)
    assert all(stat.S_ISFIFO(os.lstat(f).st_mode) for f in fifos)
    if name == "journal_folder":
        assert list(world.journal.iterdir()) == []
    if name == "receipts_file":
        assert world.receipts.read_text(encoding="utf-8") == "a file where the receipt folder belongs\n"
    if name == "decisions_fifo":   # the journal names the failure as before, by its fixed name
        assert world.journal_lines() == [(False, "internal_FileExistsError")]
    if name == "receipt_slot_fifo":   # the slot is passed over without waiting; the signer then fails
        assert world.journal_lines() == [(False, "signer_failed")]
        assert sorted(p.name for p in (world.receipts / "decisions").iterdir()) == [fifos[0].name]


@pytest.mark.parametrize("host", HOSTS)
def test_N4_4_a_fifo_journal_with_a_reader_gets_no_line(world, host):
    """Only a regular file at the opened descriptor is written: a FIFO that has a reader opens, and gets nothing."""
    baseline = world.hook(host)
    world.pilot()
    world.receipts.mkdir()
    os.mkfifo(world.journal)
    reader = os.open(world.journal, os.O_RDONLY | os.O_NONBLOCK)
    try:
        assert world.hook(host, [world.journal]) == baseline
        assert os.read(reader, 65536) == b""
    finally:
        os.close(reader)


@pytest.mark.parametrize("host", HOSTS)
def test_N4_4_a_journal_that_is_a_link_is_not_followed(world, host):
    baseline = world.hook(host)
    world.pilot()
    world.receipts.mkdir()
    target = world.tmp / "elsewhere.jsonl"
    target.write_text("", encoding="utf-8")
    world.journal.symlink_to(target)
    assert world.hook(host) == baseline
    assert target.read_text(encoding="utf-8") == ""


@pytest.mark.parametrize("host", HOSTS)
def test_N4_4_a_regular_journal_still_gets_its_line(world, host):
    """The ordinary path: the folder is made where it is missing and the journal names why no receipt was issued."""
    baseline = world.hook(host)
    world.pilot()
    assert world.hook(host) == baseline
    assert world.journal_lines() == [(False, "signer_failed")]
    assert list((world.receipts / "decisions").iterdir()) == []


@pytest.mark.parametrize("host", HOSTS)
def test_N4_4_an_issued_receipt_is_still_journaled(world, host):
    baseline = world.hook(host)
    world.pilot(signer=[sys.executable, str(p1.PROBE_SIGNER), "--label", p1.GATE_LABEL], public_key=p1.public_key())
    assert world.hook(host) == baseline
    (issued,) = (json.loads(x) for x in world.journal.read_text(encoding="utf-8").splitlines())
    (receipt,) = (world.receipts / "decisions").iterdir()
    assert issued["issued"] is True and issued["file"] == f"decisions/{receipt.name}"
    assert issued["verdict"] == ("DENY" if host == "codex" else "ESCALATE")   # the gate asks; Codex denies an ask


def test_N4_4_the_pre_push_hook_does_not_wait_on_a_fifo_journal(tmp_path):
    """Level 2 journals through the same function: a push the gate denies (no done receipt) gets its exit code and its
    text on stderr with a FIFO journal without a reader, as without the pilot."""
    repo = pd.Repo(tmp_path)
    env = plugin_env(HOME=str(tmp_path), PROOFBUNDLE_GATE_DIR=str(tmp_path / "gate"),
                     CLAUDE_PLUGIN_DATA=str(tmp_path / "data"), PLUGIN_DATA=str(tmp_path / "data"))
    line = f"refs/heads/main {pd._rev(repo.path, 'HEAD')} refs/heads/main {pd._rev(repo.path, 'origin/main')}\n"
    argv = [sys.executable, "-I", str(GATE), "pre-push", "origin", str(tmp_path / "remote.git")]
    try:
        off = _run(argv, line, env, repo.path, [])
        (tmp_path / "gate").mkdir()
        receipts = tmp_path / "receipts"
        receipts.mkdir()
        (tmp_path / "gate" / "pilot.json").write_text(json.dumps(
            {"profile": "github-write/1", "gate_id": "operator:gate", "observer_id": "operator:observer",
             "agent_id": "agent:probe", "principal_id": "operator", "validity_seconds": 600,
             "receipts": str(receipts), "signer": ["/bin/false"], "public_key": "00" * 32, "closing_rules": None}),
            encoding="utf-8")
        os.mkfifo(receipts / "journal.jsonl")
        on = _run(argv, line, env, repo.path, [receipts / "journal.jsonl"])
        assert off.returncode == 1 and "no test run left a receipt" in off.stderr, off.stderr
        assert (on.returncode, on.stdout, on.stderr) == (off.returncode, off.stdout, off.stderr)
        assert stat.S_ISFIFO(os.lstat(receipts / "journal.jsonl").st_mode)
    finally:
        _remove_fifos(tmp_path)


#: The policy digest of a receipt, in a process of its own with the gate's own file named by argv[2].
POLICY_DIGEST = """
import importlib.util, sys
spec = importlib.util.spec_from_file_location("proofbundle_gate", sys.argv[1])
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
gate.__file__ = sys.argv[2]
try:
    print(gate._pilot_policy_digest({}))
except OSError as exc:
    print("OSError")
"""


def test_N4_4_the_policy_digest_does_not_wait_on_a_fifo_in_the_place_of_the_gate_file(tmp_path):
    """The receipt names the sha256 of the gate's own file; a FIFO where that file is read is refused at once, and the
    receipt fails as an OSError does (the journal names it), while the gate's own file gives the digest it gave."""
    fifo = tmp_path / "proofbundle_gate.py"
    os.mkfifo(fifo)
    try:
        argv = [sys.executable, "-I", "-c", POLICY_DIGEST, str(GATE)]
        assert _run(argv + [str(fifo)], "", plugin_env(), tmp_path, [fifo]).stdout == "OSError\n"
        assert _run(argv + [str(GATE)], "", plugin_env(), tmp_path, []).stdout == gate._pilot_policy_digest({}) + "\n"
    finally:
        _remove_fifos(tmp_path)
