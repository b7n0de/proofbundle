"""D64, owner choice O405S-6 of 2026-10-17: deciding and signing run under two accounts.

The signer service of D58 ran git, the gate's decision code and the verifier on repositories the agent writes, in the
account that read the gate key: the read hardening of the gate was the only wall between a configuration the agent
planted there and the key. Now the service decides under an account that holds no key and hands the canonical bytes,
and nothing else, to the key signer (plugins/proofbundle/pilot/key_signer.py), the one program that reads the key,
under a second account. The key signer runs neither git nor any code of the gate, starts no process and reads nothing
of a repository; it checks the form of the statement, its gate and its window, and signs.

Here the service and the key signer run under the account of the test, with a key from a public label (a probe key,
never a key of the pilot); the three accounts with their sudo rules are measured by the probe of the delivery. RED at
8fbf85ce, the head of Z405 over the quick round: no key signer there, and the service reads the key itself.
"""
from __future__ import annotations

import ast
import base64
import hashlib
import importlib
import json
import pathlib
import sys
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

import test_plugin_gate_n2c_push_done as pd
import test_plugin_z405_decision_receipt as p1
import test_plugin_z405_observer as o
import test_plugin_z405_signer_service as s

gate = pd.gate
ROOT = p1.ROOT
PILOT = ROOT / "plugins" / "proofbundle" / "pilot"
KEY_SIGNER = PILOT / "key_signer.py"
SERVICE = PILOT / "signer_service.py"


class _Module:
    """A module of the pilot folder, imported when a test first reads it, so each test is red on its own where the
    module or the name is missing."""

    def __init__(self, name: str):
        self._name = name

    def __getattr__(self, attr: str):
        sys.path.insert(0, str(PILOT))
        try:
            module = importlib.import_module(self._name)
        finally:
            sys.path.remove(str(PILOT))
        return getattr(module, attr)


k = _Module("key_signer")
service_module = _Module("signer_service")


@pytest.fixture(autouse=True)
def _clean_git_environment(monkeypatch):
    pd._clean_git_environment.__wrapped__(monkeypatch)


@pytest.fixture
def env(tmp_path, monkeypatch):
    return pd.env.__wrapped__(tmp_path, monkeypatch)


def run_key_signer(config: pathlib.Path, request: object, cwd: pathlib.Path | None = None):
    import subprocess
    raw = request if isinstance(request, bytes) else json.dumps(request).encode("utf-8")
    return subprocess.run([sys.executable, "-I", str(KEY_SIGNER), "--config", str(config)], input=raw,
                          capture_output=True, timeout=60, check=False, cwd=str(cwd) if cwd else None)


def all_key_lines(journal: pathlib.Path) -> list[dict]:
    return [json.loads(x) for x in journal.read_text(encoding="utf-8").splitlines()] if journal.exists() else []


def key_lines(journal: pathlib.Path) -> list[dict]:
    """The decision lines of the key signer's journal; since D65 a signed one is followed by its handedOut line."""
    return [x for x in all_key_lines(journal) if "signed" in x]


class Key:
    """A key signer of its own: its configuration, its journal and the key from a public label."""

    def __init__(self, tmp_path: pathlib.Path, label: str = s.SERVICE_LABEL, gate_id: str = p1.GATE_ID,
                 window: int = 30):
        self.folder = tmp_path / f"key_{hashlib.sha256(label.encode()).hexdigest()[:8]}"
        self.folder.mkdir()
        (self.folder / "key.hex").write_text(o.probe_signer.probe_key(label).private_bytes_raw().hex() + "\n",
                                             encoding="ascii")
        (self.folder / "key.hex").chmod(0o600)   # the key signer reads no key file another account may read
        self.config = self.folder / "config.json"
        self.journal = self.folder / "journal.jsonl"
        self.config.write_text(json.dumps({"schema": "proofbundle/pilot-key-config/v1",
                                           "key_file": str(self.folder / "key.hex"), "journal": str(self.journal),
                                           "gate_id": gate_id, "window_seconds": window}), encoding="utf-8")
        self.public = o.probe_signer.public_hex(o.probe_signer.probe_key(label))

    def argv(self) -> list[str]:
        return [sys.executable, "-I", str(KEY_SIGNER), "--config", str(self.config)]


def statement(env: dict, *, verdict: str = "ESCALATE", decided_ns: int | None = None, gate_id: str | None = None,
              repo: pathlib.Path | None = None) -> dict:
    """A statement as the gate builds one, for the comment of the probes."""
    pilot = {"gate_id": gate_id or p1.GATE_ID, "observer_id": p1.OBSERVER_ID, "agent_id": p1.AGENT_ID,
             "principal_id": "operator", "validity_seconds": 600, "closing_rules": None}
    event = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": str(repo or "/"),
             "tool_input": {"command": p1.COMMENT}}
    action, key = gate._pilot_tool_action(event)
    decision_id = gate._pilot_action_id(pilot, action, key) + "#1"
    return gate._pilot_statement(pilot, env, action, verdict, ["net_unmodeled_git"], decision_id,
                                 decided_ns or time.time_ns())


def request_of(body: bytes) -> dict:
    return {"schema": k.KEY_SIGN_REQUEST, "statement": base64.b64encode(body).decode("ascii")}


def pae(body: bytes) -> bytes:
    return b"DSSEv1 %d %s %d %s" % (len(k.PAYLOAD_TYPE), k.PAYLOAD_TYPE, len(body), body)


# --- the service holds no key ---------------------------------------------------------------------------------------

def test_the_service_holds_no_key():
    tree = ast.parse(SERVICE.read_text(encoding="utf-8"))
    names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)} | \
        {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)} | \
        {a.name for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) for a in n.names}
    assert "Ed25519PrivateKey" not in names and "private_key" not in names and "sign" not in names
    assert "key_file" not in service_module.CONFIG_KEYS and "key_signer" in service_module.CONFIG_KEYS
    assert service_module.CONFIG_SCHEMA == "proofbundle/pilot-signer-config/v2"


def test_a_configuration_of_v1_with_a_key_file_is_no_configuration_of_the_service(env, tmp_path):
    import subprocess
    key = Key(tmp_path)
    config = tmp_path / "v1.json"
    config.write_text(json.dumps({"schema": "proofbundle/pilot-signer-config/v1", "gate_file": str(s.GATE_FILE),
                                  "records": str(tmp_path), "gate_dir": str(tmp_path),
                                  "key_file": str(key.folder / "key.hex"), "journal": str(tmp_path / "j.jsonl"),
                                  "environment": {}, "window_seconds": 10}), encoding="utf-8")
    for args in ([], ["--public"]):
        proc = subprocess.run([sys.executable, "-I", str(SERVICE), "--config", str(config), *args], input=b"{}",
                              capture_output=True, timeout=60, check=False)
        assert proc.returncode != 0 and proc.stdout == b"", proc
    assert not (tmp_path / "j.jsonl").exists()


def test_a_receipt_is_signed_by_the_key_signer_and_both_journals_name_it(env, tmp_path):
    repo = pd.Repo(tmp_path).path
    service = s.Service(env, tmp_path)
    assert p1.level1(env, repo, p1.COMMENT).returncode == 0
    (envelope,) = p1.receipts_in(service.records)
    predicate = s.signed_by(envelope, service.public)
    (line,) = service.lines()
    (key_line,) = service.key_lines()
    assert line["signed"] is True and key_line["signed"] is True and key_line["reason"] is None
    assert key_line["decisionId"] == line["decisionId"] == predicate["decisionId"]
    assert key_line["statementSha256"] == hashlib.sha256(base64.b64decode(envelope["payload"])).hexdigest()


def test_the_service_hands_the_key_signer_the_canonical_bytes_and_nothing_else(env, tmp_path):
    """The key signer's place is taken by a program that keeps what it is handed and refuses: the request holds the
    schema and the statement the gate would sign, and it runs from the root folder with no value of the service's
    environment (an agent's repository is no working directory of the key account)."""
    repo = pd.Repo(tmp_path).path
    captured = tmp_path / "captured.json"
    code = ("import json, os, sys; json.dump({'request': json.loads(sys.stdin.read()), 'cwd': os.getcwd(), "
            "'environ': dict(os.environ)}, open(sys.argv[1], 'w')); print('captured'); sys.exit(3)")
    service = s.Service(env, tmp_path, key_signer=[sys.executable, "-I", "-c", code, str(captured)])
    assert p1.level1(env, repo, p1.COMMENT).returncode == 0
    assert p1.receipts_in(service.records) == []
    assert p1.journal(service.records)[-1]["why"] == "signer_refused_key_captured"
    seen = json.loads(captured.read_text(encoding="utf-8"))
    assert set(seen["request"]) == {"schema", "statement"} and seen["request"]["schema"] == k.KEY_SIGN_REQUEST
    body = base64.b64decode(seen["request"]["statement"])
    assert gate._pilot_canonical(json.loads(body)) == body
    assert json.loads(body)["predicate"]["decision"]["verdict"] == "ESCALATE"
    assert seen["cwd"] == "/"
    assert seen["environ"]["PATH"] == __import__("os").defpath
    assert set(seen["environ"]) <= {"PATH", "LANG", "LC_CTYPE"}, seen["environ"]


def test_a_key_signer_with_another_key_gives_no_receipt(env, tmp_path):
    """The key signer signs with a key that is not the gate key of pilot.json: the service checks the answer with that
    public key and passes nothing on (key_differs)."""
    repo = pd.Repo(tmp_path).path
    other = Key(tmp_path, label="another key, not the gate key")
    service = s.Service(env, tmp_path, key_signer=other.argv())
    assert p1.level1(env, repo, p1.COMMENT).returncode == 0
    assert p1.receipts_in(service.records) == []
    assert p1.journal(service.records)[-1]["why"] == "signer_refused_key_differs"
    (line,) = service.lines()
    assert (line["signed"], line["reason"]) == (False, "key_differs")


def test_a_refusal_of_the_key_signer_reaches_the_gate_by_its_name(env, tmp_path):
    repo = pd.Repo(tmp_path).path
    other = Key(tmp_path, gate_id="operator:another-gate")
    service = s.Service(env, tmp_path, key_signer=other.argv())
    assert p1.level1(env, repo, p1.COMMENT).returncode == 0
    assert p1.receipts_in(service.records) == []
    assert p1.journal(service.records)[-1]["why"] == "signer_refused_key_gate_differs"
    assert [x["reason"] for x in key_lines(other.journal)] == ["gate_differs"]


@pytest.mark.parametrize("argv, reason", [
    ([sys.executable, "-c", "import sys; sys.exit(1)"], "key_signer_failed"),
    ([sys.executable, "-c", "print('not base64!')"], "key_signer_answer"),
    ([sys.executable, "-c", "import base64; print(base64.b64encode(bytes(64)).decode())"], "key_differs"),
    (["/nonexistent/key_signer"], "key_signer_failed")])
def test_a_key_signer_that_fails_gives_no_receipt(env, tmp_path, argv, reason):
    repo = pd.Repo(tmp_path).path
    service = s.Service(env, tmp_path, key_signer=argv)
    assert p1.level1(env, repo, p1.COMMENT).returncode == 0
    assert p1.receipts_in(service.records) == []
    assert p1.journal(service.records)[-1]["why"] == f"signer_refused_{reason}"


def test_a_key_signer_that_does_not_answer_in_time_is_stopped(env, tmp_path):
    """The key signer gets the time up to PILOT_SIGNER_SECONDS - KEY_MARGIN_SECONDS; here the margin leaves it about
    three seconds, and it sleeps: key_signer_timeout, never a late signature."""
    import subprocess
    repo = pd.Repo(tmp_path).path
    service = s.Service(env, tmp_path, key_signer=[sys.executable, "-c", "import time; time.sleep(30)"])
    request = s.proposal(env, service, s.comment_event(repo), "claude", "ESCALATE")
    code = ("import sys; sys.path.insert(0, sys.argv[1]); import signer_service as s; "
            "s.KEY_MARGIN_SECONDS = 7.0; sys.exit(s.main(['--config', sys.argv[2]]))")
    started = time.monotonic()
    proc = subprocess.run([sys.executable, "-I", "-c", code, str(PILOT), str(service.config)],
                          input=json.dumps(request).encode("utf-8"), capture_output=True, timeout=60, check=False)
    assert (proc.returncode, proc.stdout.decode().strip()) == (3, "key_signer_timeout"), proc
    assert time.monotonic() - started < 6


# --- what the key signer signs and refuses --------------------------------------------------------------------------

def test_the_key_signer_signs_a_statement_of_its_gate_in_its_window(env, tmp_path):
    key = Key(tmp_path)
    body = gate._pilot_canonical(statement(env))
    proc = run_key_signer(key.config, request_of(body))
    assert proc.returncode == 0, proc
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(key.public)).verify(base64.b64decode(proc.stdout.strip()), pae(body))
    import subprocess
    public = subprocess.run([sys.executable, "-I", str(KEY_SIGNER), "--config", str(key.config), "--public"],
                            capture_output=True, text=True, timeout=60, check=True).stdout.strip()
    assert public == key.public


def _with_subject(value: dict) -> bytes:
    predicate = value["predicate"]
    value["subject"] = [{"name": f"decision:{predicate['decisionId']}",
                         "digest": {"sha256": hashlib.sha256(gate._pilot_canonical(predicate)).hexdigest()}}]
    return gate._pilot_canonical(value)


def _changed(env, change) -> object:
    value = statement(env)
    return change(value)


CASES = {
    "another field in the request": (lambda env: {**request_of(gate._pilot_canonical(statement(env))), "level": 1},
                                     "request_malformed"),
    "another schema": (lambda env: {**request_of(gate._pilot_canonical(statement(env))), "schema": "x/v1"},
                       "request_malformed"),
    "no JSON": (lambda env: b"not json", "request_malformed"),
    "not base64": (lambda env: {"schema": k.KEY_SIGN_REQUEST, "statement": "not base64!"}, "statement_malformed"),
    "a byte outside ASCII": (lambda env: request_of(gate._pilot_canonical(statement(env)).replace(
        b'"preActionAuthorization"', '"préActionAuthorization"'.encode("utf-8"))), "statement_malformed"),
    "too large": (lambda env: request_of(b" " * (k.MAX_STATEMENT_BYTES + 1)), "statement_malformed"),
    "a repeated key": (lambda env: request_of(b'{"_type":"a","_type":"b"}'), "statement_malformed"),
    "spaces": (lambda env: request_of(json.dumps(statement(env), sort_keys=True).encode("ascii")),
               "statement_not_canonical"),
    "keys unsorted": (lambda env: request_of(json.dumps(dict(reversed(list(statement(env).items()))),
                                                        separators=(",", ":")).encode("ascii")),
                      "statement_not_canonical"),
    "another predicate type": (lambda env: request_of(_changed(env, lambda v: _with_subject(
        {**v, "predicateType": "https://example.org/other/v1"}))), "statement_type"),
    "another statement type": (lambda env: request_of(_changed(env, lambda v: _with_subject(
        {**v, "_type": "https://in-toto.io/Statement/v0.1"}))), "statement_type"),
    "a field the gate does not write": (lambda env: request_of(_changed(env, lambda v: _with_subject(
        {**v, "predicate": {**v["predicate"], "approvedBy": "agent"}}))), "statement_type"),
    "a malformed decision id": (lambda env: request_of(_changed(env, lambda v: _with_subject(
        {**v, "predicate": {**v["predicate"], "decisionId": "x#1"}}))), "statement_malformed"),
    "a subject of another predicate": (lambda env: request_of(_changed(env, lambda v: gate._pilot_canonical(
        {**v, "predicate": {**v["predicate"], "decision": {"verdict": "ALLOW", "reasonCodes": ["x"]}}}))),
        "subject_differs"),
    "another gate": (lambda env: request_of(gate._pilot_canonical(statement(env, gate_id="operator:other"))),
                     "gate_differs"),
    "decided two minutes ago": (lambda env: request_of(gate._pilot_canonical(
        statement(env, decided_ns=time.time_ns() - 120 * 10**9))), "outside_window"),
    "decided a minute from now": (lambda env: request_of(gate._pilot_canonical(
        statement(env, decided_ns=time.time_ns() + 60 * 10**9))), "outside_window"),
}


@pytest.mark.parametrize("name", list(CASES))
def test_the_key_signer_refuses_what_is_not_a_statement_of_its_gate_in_its_window(env, tmp_path, name):
    make, reason = CASES[name]
    key = Key(tmp_path)
    proc = run_key_signer(key.config, make(env))
    assert (proc.returncode, proc.stdout.decode().strip()) == (3, reason), proc
    (line,) = key_lines(key.journal)
    assert (line["signed"], line["reason"]) == (False, reason)
    assert run_key_signer(key.config, request_of(gate._pilot_canonical(statement(env)))).returncode == 0   # control


def test_the_key_signer_does_not_judge_the_verdict(env, tmp_path):
    """Whether the verdict is the gate's is the deciding account's to judge (D58): the key signer signs a statement of
    its gate in its window whatever its verdict, an ALLOW the gate never gave included. What the second account
    closes is the key, not the verdict: whoever holds the deciding account gets signatures within the window, one line
    of the key signer's journal each, and never the key (D64)."""
    key = Key(tmp_path)
    body = gate._pilot_canonical(statement(env, verdict="ALLOW"))
    proc = run_key_signer(key.config, request_of(body))
    assert proc.returncode == 0, proc
    (line,) = key_lines(key.journal)
    assert line["signed"] is True and line["statementSha256"] == hashlib.sha256(body).hexdigest()


# --- what the key signer runs and reads ----------------------------------------------------------------------------

_PROCESS = ("subprocess", "multiprocessing", "pty", "ctypes", "importlib", "runpy", "shutil")
_PROCESS_CALLS = {"system", "popen", "fork", "forkpty", "posix_spawn", "posix_spawnp", "execv", "execve", "execvp",
                  "execvpe", "execl", "execle", "execlp", "execlpe", "spawnv", "spawnve", "spawnvp", "spawnvpe",
                  "spawnl", "spawnle", "spawnlp", "spawnlpe", "startfile", "chdir"}


def test_the_key_signer_imports_nothing_that_starts_a_process_and_no_gate():
    tree = ast.parse(KEY_SIGNER.read_text(encoding="utf-8"))
    imported = {a.name.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names} | \
        {n.module.split(".")[0] for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
    assert imported <= {"__future__", "argparse", "base64", "binascii", "calendar", "hashlib", "json", "os", "re", "stat",
                        "sys", "time", "cryptography"}, imported
    assert not imported & set(_PROCESS)
    called = {n.func.attr for n in ast.walk(tree) if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)}
    assert not called & _PROCESS_CALLS, called & _PROCESS_CALLS
    strings = {n.value for n in ast.walk(tree) if isinstance(n, ast.Constant) and isinstance(n.value, str)}
    assert not any("proofbundle_gate" in x or "signer_service" in x for x in strings if not x.startswith("The "))


def test_the_key_signer_starts_no_process_and_opens_nothing_of_the_repository_it_runs_in(env, tmp_path):
    """Measured with Python's audit hooks: the key signer, started in a repository whose configuration names a program
    for git to run, opens its configuration, its key, its journal and the files of its own Python, nothing else, and
    starts no process."""
    import subprocess
    r = pd.Repo(tmp_path)
    marker = tmp_path / "fsmonitor_ran"
    (r.path / ".git" / "fsmonitor.sh").write_text(f"#!/bin/sh\ntouch {marker}\n", encoding="ascii")
    (r.path / ".git" / "fsmonitor.sh").chmod(0o755)
    pd._git(r.path, "config", "core.fsmonitor", str(r.path / ".git" / "fsmonitor.sh"))
    key = Key(tmp_path)
    events = tmp_path / "events.json"
    hooked = ("import json, sys\nseen = []\n"
              "def hook(name, args):\n"
              "    if name == 'open' and isinstance(args[0], (str, bytes)):\n"
              "        seen.append(['open', args[0] if isinstance(args[0], str) else args[0].decode()])\n"
              "    elif name.startswith(('subprocess.', 'os.system', 'os.exec', 'os.posix_spawn', 'os.spawn', "
              "'os.fork', 'os.startfile', 'pty.', 'os.chdir', 'ctypes.')):\n"
              "        seen.append([name, ''])\n"
              "sys.addaudithook(hook)\n"
              "sys.path.insert(0, sys.argv[1])\n{call}\n"
              "out = list(seen)\njson.dump(out, open(sys.argv[3], 'w'))\nsys.exit(code)\n")
    body = gate._pilot_canonical(statement(env, repo=r.path))

    def seen_by_the_hook(call: str) -> tuple[int, list]:
        proc = subprocess.run([sys.executable, "-I", "-c", hooked.replace("{call}", call), str(PILOT), str(key.config),
                               str(events)], input=json.dumps(request_of(body)).encode("ascii"), capture_output=True,
                              timeout=60, check=False, cwd=str(r.path))
        return proc.returncode, json.loads(events.read_text(encoding="utf-8"))

    # control: the hook sees a process start and an open in the repository
    code, control = seen_by_the_hook("import subprocess; open('.git/config').close(); "
                                     "code = subprocess.run(['git', 'status'], capture_output=True).returncode")
    assert code == 0 and ["subprocess.Popen", ""] in control and ["open", ".git/config"] in control
    assert marker.exists()   # git ran the program the repository's configuration names
    marker.unlink()
    code, seen = seen_by_the_hook("import key_signer\ncode = key_signer.main(['--config', sys.argv[2]])")
    assert code == 0, seen
    assert [e for e in seen if e[0] != "open"] == []
    opened = {pathlib.Path(e[1]) for e in seen}
    own = {key.config, key.folder / "key.hex", key.journal, KEY_SIGNER}
    opened.discard(key.folder)   # its journal's folder, opened once to sync the new file's name to the disk (D65)
    assert own - {KEY_SIGNER} <= opened, opened
    python = [pathlib.Path(p) for p in {sys.prefix, sys.base_prefix, sys.exec_prefix, sys.base_exec_prefix}]
    others = {p for p in opened if p not in own and not any(p.is_relative_to(x) for x in python)
              and not p.is_relative_to(PILOT / "__pycache__")}
    assert others == set(), others
    assert not any(p.is_relative_to(r.path) for p in opened) and not any(p.name == "proofbundle_gate.py" for p in opened)
    assert not marker.exists()


def test_the_journal_of_the_key_signer_names_no_path_and_no_value(env, tmp_path):
    key = Key(tmp_path)
    run_key_signer(key.config, request_of(gate._pilot_canonical(statement(env))))
    run_key_signer(key.config, {"schema": k.KEY_SIGN_REQUEST, "statement": "not base64!"})
    text = key.journal.read_text(encoding="utf-8")
    assert str(tmp_path) not in text and "Round four of five" not in text and "gh pr comment" not in text
    assert set().union(*(set(x) for x in all_key_lines(key.journal))) <= {"at", "signed", "reason", "elapsedMs",
                                                                           "decisionId", "statementSha256", "handedOut"}


def test_the_key_signer_keeps_the_types_and_the_form_of_the_gate(env):
    value = statement(env)
    assert k.STATEMENT_TYPE == gate.INTOTO_STATEMENT_TYPE and k.PAYLOAD_TYPE == gate.INTOTO_PAYLOAD_TYPE.encode()
    assert k.DECISION_RECEIPT_TYPE == gate.DECISION_RECEIPT_TYPE
    assert k.PREDICATE_KEYS == set(value["predicate"]) and k.STATEMENT_KEYS == set(value)
    assert k.canonical(value) == gate._pilot_canonical(value)
    assert k.KEY_SIGN_REQUEST == service_module.KEY_SIGN_REQUEST and k.REFUSED == service_module.REFUSED
    assert service_module.PAYLOAD_TYPE == k.PAYLOAD_TYPE


def test_the_key_signer_has_the_rest_of_the_services_time():
    """D64: the decision ends by PILOT_SIGNER_SECONDS - MARGIN_SECONDS (9 s, D58), the key signer's answer by
    PILOT_SIGNER_SECONDS - KEY_MARGIN_SECONDS (9.5 s): at least 0.5 s for it, and 0.5 s for the journal and the answer."""
    assert (gate.PILOT_SIGNER_SECONDS, service_module.MARGIN_SECONDS, service_module.KEY_MARGIN_SECONDS) == \
        (10.0, 1.0, 0.5)
    assert service_module.MARGIN_SECONDS - service_module.KEY_MARGIN_SECONDS == 0.5
