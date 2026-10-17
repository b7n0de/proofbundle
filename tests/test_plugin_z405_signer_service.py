"""D58, Z405 follow-up part 1 (owner choice O405-1 of 2026-10-17): the signer decides the call again and signs only its
own verdict.

Before, the gate handed the DSSE bytes of a receipt to a signer that signed whatever it got: a receipt showed that the
operator's signer signed, not that the gate decided so. Now the gate hands the signer service a request with the call
as the hook saw it and the statement it proposes, and the service (plugins/proofbundle/pilot/signer_service.py) decides
the call with its own copy of the gate, whose sha256 pilot_start.json keeps, and signs only where its own statement is
the same byte for byte and decidedAt lies within its window. Else it signs nothing and names one reason.

Here the service runs under the same account as the test, with a key from a public label (a probe key, never a key of
the pilot); the two accounts of the pilot, with a sudo rule onto the one program, are measured by the probe of the
delivery. RED at 5840e5aa, the head of Nachtrag 21, where the gate hands the signer bytes and no request.
"""
from __future__ import annotations

import base64
import json
import os
import pathlib
import shutil
import subprocess
import sys
import time

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

import test_plugin_gate_n2c_push_done as pd
import test_plugin_z405_decision_receipt as p1
import test_plugin_z405_observer as o

gate = pd.gate
ROOT = p1.ROOT
SERVICE = ROOT / "plugins" / "proofbundle" / "pilot" / "signer_service.py"
GATE_FILE = ROOT / "plugins" / "proofbundle" / "hooks" / "proofbundle_gate.py"
SERVICE_LABEL = "z405 signer service probe"
PAYLOAD_TYPE = b"application/vnd.in-toto+json"


@pytest.fixture(autouse=True)
def _clean_git_environment(monkeypatch):
    pd._clean_git_environment.__wrapped__(monkeypatch)


@pytest.fixture
def env(tmp_path):
    return pd.env.__wrapped__(tmp_path)


class Service:
    """The records as the runbook starts them, with the service's key as the gate key, the service's configuration and
    pilot.json naming the service as the signer."""

    def __init__(self, env: dict, tmp_path: pathlib.Path, gate_file: pathlib.Path = GATE_FILE, window: int = 30):
        self.folder = tmp_path / "signer"
        self.folder.mkdir()
        seed = o.probe_signer.probe_key(SERVICE_LABEL).private_bytes_raw()
        (self.folder / "key.hex").write_text(seed.hex() + "\n", encoding="ascii")
        self.config = self.folder / "config.json"
        self.records = tmp_path / "records"
        self.journal = self.folder / "journal.jsonl"
        environment = {k: v for k, v in env.items() if k != "PROOFBUNDLE_GATE_DIR"}
        self.config.write_text(json.dumps({
            "schema": "proofbundle/pilot-signer-config/v1", "gate_file": str(gate_file), "records": str(self.records),
            "gate_dir": env["PROOFBUNDLE_GATE_DIR"], "key_file": str(self.folder / "key.hex"),
            "journal": str(self.journal), "environment": environment, "window_seconds": window}), encoding="utf-8")
        self.public = subprocess.run([sys.executable, str(SERVICE), "--config", str(self.config), "--public"],
                                     capture_output=True, text=True, check=True, timeout=60).stdout.strip()
        sources = tmp_path / "sources"
        sources.mkdir()
        (sources / "closing_rules.json").write_text(json.dumps(p1.CLOSING_RULES, sort_keys=True), encoding="utf-8")
        (sources / "roster.json").write_text(json.dumps(o.ROSTER), encoding="utf-8")
        (sources / "verifier.txt").write_text("the verifier's distribution file is kept here in the pilot\n")
        (sources / "environment.json").write_text(json.dumps({"python": sys.version.split()[0]}), encoding="utf-8")
        o.pr.start(self.records, contract=ROOT / "docs" / "pilot" / "pilot_contract.md",
                   profile=ROOT / "tools" / "pilot" / "github_write_profile.py", agents=ROOT / "AGENTS.md",
                   closing_rules=sources / "closing_rules.json", roster=sources / "roster.json",
                   gate_public=self.public, observer_public=o.probe_signer.public_hex(o.observer_key()),
                   verifier=sources / "verifier.txt", environment=sources / "environment.json",
                   gate_id=p1.GATE_ID, observer_id=p1.OBSERVER_ID, gate=GATE_FILE)
        p1.pilot_on(env, tmp_path, signer=[sys.executable, str(SERVICE), "--config", str(self.config)])
        pilot = pathlib.Path(env["PROOFBUNDLE_GATE_DIR"]) / "pilot.json"
        settings = json.loads(pilot.read_text(encoding="utf-8"))
        settings.update(receipts=str(self.records), closing_rules=str(self.records / "closing_rules.json"),
                        public_key=self.public)
        pilot.write_text(json.dumps(settings), encoding="utf-8")

    def lines(self) -> list[dict]:
        return [json.loads(x) for x in self.journal.read_text(encoding="utf-8").splitlines()] \
            if self.journal.exists() else []

    def ask(self, request: dict) -> subprocess.CompletedProcess:
        """The service called directly, as the agent can call the one program."""
        return subprocess.run([sys.executable, str(SERVICE), "--config", str(self.config)],
                              input=json.dumps(request).encode("utf-8"), capture_output=True, timeout=60, check=False)


def signed_by(envelope: dict, public_hex: str) -> dict:
    """The predicate of a receipt whose signature verifies with the service's key over its DSSE PAE."""
    body = base64.b64decode(envelope["payload"])
    message = b"DSSEv1 %d %s %d %s" % (len(PAYLOAD_TYPE), PAYLOAD_TYPE, len(body), body)
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_hex)).verify(
        base64.b64decode(envelope["signatures"][0]["sig"]), message)
    return json.loads(body)["predicate"]


def comment_event(repo: pathlib.Path) -> str:
    return json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": str(repo),
                       "tool_input": {"command": p1.COMMENT}})


def proposal(env: dict, service: Service, event_text: str, host: str, verdict: str, *, decided_ns: int | None = None,
             reasons: list[str] | None = None) -> dict:
    """A request as an agent could send it: the statement built with the gate's own function for the verdict it
    claims."""
    pilot = json.loads((pathlib.Path(env["PROOFBUNDLE_GATE_DIR"]) / "pilot.json").read_text(encoding="utf-8"))
    environ = {**env}
    event = json.loads(event_text)
    action, key = gate._pilot_tool_action(event)
    decision_id = gate._pilot_action_id(pilot, action, key) + "#1"
    statement = gate._pilot_statement(pilot, environ, action, verdict, reasons or ["net_unmodeled_git"], decision_id,
                                      decided_ns or time.time_ns())
    return {"schema": gate.PILOT_SIGN_REQUEST, "level": 1, "host": host, "event": event_text,
            "statement": base64.b64encode(gate._pilot_canonical(statement)).decode("ascii")}


# --- what the service signs -------------------------------------------------------------------------------------

@pytest.mark.parametrize("host, verdict", [("claude", "ESCALATE"), ("codex", "DENY")])
def test_a_verdict_the_service_reaches_too_is_signed_and_verifies_with_its_key(env, tmp_path, host, verdict):
    repo = pd.Repo(tmp_path).path
    service = Service(env, tmp_path)
    proc = p1.level1(env, repo, p1.COMMENT, host=host)
    assert proc.returncode == 0
    (envelope,) = p1.receipts_in(service.records)
    pred = signed_by(envelope, service.public)
    assert pred["decision"]["verdict"] == verdict
    (line,) = service.lines()
    assert line["signed"] is True and line["verdict"] == verdict and line["surface"] == "github.conversationComment"
    assert line["elapsedMs"] < gate.PILOT_SIGNER_SECONDS * 1000, line


def test_an_allowed_push_at_level_2_is_signed_after_the_service_verified_the_evidence_itself(env, tmp_path):
    r = pd.Repo(tmp_path)
    r.make("valid")
    service = Service(env, tmp_path)
    proc = p1.level2(env, r.path)
    assert proc.returncode == 0, proc.stderr
    (envelope,) = p1.receipts_in(service.records)
    assert signed_by(envelope, service.public)["decision"]["verdict"] == "ALLOW"
    (line,) = service.lines()
    assert (line["signed"], line["level"], line["surface"]) == (True, 2, "git.push"), line


def test_the_records_reconcile_with_the_service_as_the_signer(env, tmp_path):
    repo = pd.Repo(tmp_path).path
    service = Service(env, tmp_path)
    p1.level1(env, repo, p1.COMMENT)
    (envelope,) = p1.receipts_in(service.records)
    assert envelope["signatures"][0]["keyid"] == gate._pilot_keyid(bytes.fromhex(service.public))
    assert (service.records / "gate" / "proofbundle_gate.py").read_bytes() == GATE_FILE.read_bytes()


def test_the_service_decides_in_its_own_environment_not_in_its_callers(env, tmp_path):
    """The request of an allowed push, as the gate hands it over, replayed by a caller whose environment names another
    GIT_DIR: the service decides in the environment of its configuration, so it reaches ALLOW and signs. sudo resets the
    environment as well (env_reset); a socket or a direct call does not, so the service does it itself."""
    r = pd.Repo(tmp_path)
    r.make("valid")
    service = Service(env, tmp_path)
    pilot = pathlib.Path(env["PROOFBUNDLE_GATE_DIR"]) / "pilot.json"
    settings = json.loads(pilot.read_text(encoding="utf-8"))
    captured = tmp_path / "request.json"
    pilot.write_text(json.dumps({**settings, "signer": [
        sys.executable, "-c", "import sys; open(sys.argv[1], 'wb').write(sys.stdin.buffer.read()); print('captured'); "
        "sys.exit(3)", str(captured)]}), encoding="utf-8")
    assert p1.level2(env, r.path).returncode == 0
    elsewhere = {**env, "GIT_DIR": str(tmp_path / "nowhere"), "GIT_WORK_TREE": str(tmp_path)}
    proc = subprocess.run([sys.executable, str(SERVICE), "--config", str(service.config)], input=captured.read_bytes(),
                          capture_output=True, env=elsewhere, timeout=60, check=False)
    assert proc.returncode == 0 and len(base64.b64decode(proc.stdout.strip())) == 64, proc
    assert service.lines()[-1]["verdict"] == "ALLOW"


def test_a_reader_of_the_records_checks_the_kept_gate_file_too(env, tmp_path):
    service = Service(env, tmp_path)
    assert o.pr.Records(service.records).files["gate"]["file"] == "gate/proofbundle_gate.py"
    kept = service.records / "gate" / "proofbundle_gate.py"
    kept.write_bytes(kept.read_bytes() + b"# changed after the start\n")
    with pytest.raises(o.pr.RecordsError, match="kept gate"):
        o.pr.Records(service.records)


# --- what the service refuses -------------------------------------------------------------------------------------

@pytest.mark.parametrize("host", ["claude", "codex"])
def test_a_direct_call_with_allow_for_an_action_the_gate_does_not_allow_gets_no_signature(env, tmp_path, host):
    """Under Claude Code the gate asks the comment, under Codex it refuses it; the agent claims ALLOW for it."""
    repo = pd.Repo(tmp_path).path
    service = Service(env, tmp_path)
    proc = service.ask(proposal(env, service, comment_event(repo), host, "ALLOW"))
    assert (proc.returncode, proc.stdout.decode().strip()) == (3, "verdict_differs"), proc
    (line,) = service.lines()
    assert line["signed"] is False and line["verdict"] == ("ESCALATE" if host == "claude" else "DENY"), line


def test_a_true_claim_made_directly_is_signed_as_well(env, tmp_path):
    """The service signs its own verdict, whoever asks: the agent can reach the program, and a true statement is one
    the gate would have issued."""
    repo = pd.Repo(tmp_path).path
    service = Service(env, tmp_path)
    proc = service.ask(proposal(env, service, comment_event(repo), "claude", "ESCALATE"))
    assert proc.returncode == 0 and len(base64.b64decode(proc.stdout.strip())) == 64, proc


def test_other_reasons_than_the_gate_names_get_no_signature(env, tmp_path):
    repo = pd.Repo(tmp_path).path
    service = Service(env, tmp_path)
    proc = service.ask(proposal(env, service, comment_event(repo), "claude", "ESCALATE", reasons=["approved_by_rule"]))
    assert (proc.returncode, proc.stdout.decode().strip()) == (3, "reasons_differ"), proc


def test_a_working_directory_the_service_cannot_read_gets_no_signature(env, tmp_path):
    """Under one account a folder that is gone stands in for one the signer account may not read; the probe of the
    delivery measures the second account."""
    repo = pd.Repo(tmp_path).path
    service = Service(env, tmp_path)
    request = proposal(env, service, comment_event(repo), "claude", "ESCALATE")
    shutil.rmtree(repo)
    proc = service.ask(request)
    assert (proc.returncode, proc.stdout.decode().strip()) == (3, "workdir_unreadable"), proc


def test_a_decision_outside_the_window_gets_no_signature(env, tmp_path):
    repo = pd.Repo(tmp_path).path
    service = Service(env, tmp_path, window=30)
    old = time.time_ns() - 120 * 1_000_000_000
    proc = service.ask(proposal(env, service, comment_event(repo), "claude", "ESCALATE", decided_ns=old))
    assert (proc.returncode, proc.stdout.decode().strip()) == (3, "outside_window"), proc
    future = time.time_ns() + 60 * 1_000_000_000
    proc = service.ask(proposal(env, service, comment_event(repo), "claude", "ESCALATE", decided_ns=future))
    assert (proc.returncode, proc.stdout.decode().strip()) == (3, "outside_window"), proc


def test_a_service_whose_gate_file_is_not_the_one_the_records_keep_signs_nothing(env, tmp_path):
    repo = pd.Repo(tmp_path).path
    other = tmp_path / "other_gate.py"
    other.write_text(GATE_FILE.read_text(encoding="utf-8") + "\n# another file\n", encoding="utf-8")
    service = Service(env, tmp_path, gate_file=other)
    proc = service.ask(proposal(env, service, comment_event(repo), "claude", "ESCALATE"))
    assert (proc.returncode, proc.stdout.decode().strip()) == (3, "gate_file_differs"), proc


@pytest.mark.parametrize("change, reason", [
    (('_PILOT_VERDICTS = {"pass": "ALLOW", "deny": "DENY", "ask": "ESCALATE"}',
      '_PILOT_VERDICTS = {"pass": "ALLOW", "deny": "DENY", "ask": "ALLOW"}'), "verdict_differs"),
    (('PILOT_SIGNER_SECONDS = 10.0', 'PILOT_SIGNER_SECONDS = 10.0  # a copy of the agent, changed'),
     "policy_differs")])
def test_another_gate_file_on_the_agents_side_changes_nothing_in_the_services_verdict(env, tmp_path, change, reason):
    """The agent runs a changed copy of the plugin: one that records an ask as ALLOW, and one changed in a comment only,
    whose statement names another gate digest. The service decides with its own copy: ESCALATE either way, and it
    signs neither."""
    repo = pd.Repo(tmp_path).path
    service = Service(env, tmp_path)
    copy = tmp_path / "agent_plugin"
    shutil.copytree(ROOT / "plugins" / "proofbundle", copy, ignore=shutil.ignore_patterns("__pycache__"))
    agent_gate = copy / "hooks" / "proofbundle_gate.py"
    text = agent_gate.read_text(encoding="utf-8")
    assert text.count(change[0]) == 1
    agent_gate.write_text(text.replace(change[0], change[1]), encoding="utf-8")
    event = comment_event(repo)
    proc = subprocess.run([sys.executable, "-I", str(agent_gate)], input=event, capture_output=True, text=True,
                          env=env, timeout=180, check=False)
    assert proc.returncode == 0 and json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecision"] == "ask"
    assert p1.receipts_in(service.records) == []
    assert p1.journal(service.records)[-1] == {**p1.journal(service.records)[-1], "issued": False,
                                               "why": f"signer_refused_{reason}"}
    (line,) = service.lines()
    assert line["signed"] is False and line["reason"] == reason and line["verdict"] == "ESCALATE", line


def test_a_request_that_is_no_request_gets_no_signature(env, tmp_path):
    repo = pd.Repo(tmp_path).path
    service = Service(env, tmp_path)
    good = proposal(env, service, comment_event(repo), "claude", "ESCALATE")
    statement = json.loads(base64.b64decode(good["statement"]))
    statement["predicate"]["decisionId"] = "x#1"
    for request, reason in (({}, "request_malformed"),
                            ({**good, "schema": "proofbundle/pilot-sign-request/v0"}, "request_malformed"),
                            ({**good, "level": 7}, "request_malformed"),
                            ({**good, "host": "another host"}, "request_malformed"),
                            ({**good, "statement": "not base64!"}, "statement_malformed"),
                            ({**good, "statement": base64.b64encode(gate._pilot_canonical(statement)).decode("ascii")},
                             "statement_malformed")):
        proc = service.ask(request)
        assert (proc.returncode, proc.stdout.decode().strip()) == (3, reason), (request, proc)
    assert all(line["signed"] is False for line in service.lines())
    assert service.ask(good).returncode == 0   # control: the same request unchanged is signed


def test_a_decision_id_of_another_action_gets_no_signature(env, tmp_path):
    """The statement is the service's own for this call, byte for byte, but its decisionId names another action: the
    id of a comment with other words. The id binds a receipt to its action (D55), so the service refuses it."""
    repo = pd.Repo(tmp_path).path
    service = Service(env, tmp_path)
    pilot = json.loads((pathlib.Path(env["PROOFBUNDLE_GATE_DIR"]) / "pilot.json").read_text(encoding="utf-8"))
    other = json.loads(comment_event(repo).replace("four", "five"))
    action, key = gate._pilot_tool_action(other)
    request = proposal(env, service, comment_event(repo), "claude", "ESCALATE")
    statement = json.loads(base64.b64decode(request["statement"]))
    own_action, _ = gate._pilot_tool_action(json.loads(comment_event(repo)))
    forged = gate._pilot_statement(pilot, {**env}, own_action, "ESCALATE", statement["predicate"]["decision"]["reasonCodes"],
                                   gate._pilot_action_id(pilot, action, key) + "#1", time.time_ns())
    proc = service.ask({**request, "statement": base64.b64encode(gate._pilot_canonical(forged)).decode("ascii")})
    assert (proc.returncode, proc.stdout.decode().strip()) == (3, "action_differs"), proc


def test_records_of_another_pilot_get_no_signature(env, tmp_path):
    """pilot.json names another gate than the records the service checks against: no receipt of this pilot."""
    repo = pd.Repo(tmp_path).path
    service = Service(env, tmp_path)
    pilot = pathlib.Path(env["PROOFBUNDLE_GATE_DIR"]) / "pilot.json"
    pilot.write_text(json.dumps({**json.loads(pilot.read_text(encoding="utf-8")), "gate_id": "operator:other-gate"}),
                     encoding="utf-8")
    p1.level1(env, repo, p1.COMMENT)
    assert p1.receipts_in(service.records) == []
    assert p1.journal(service.records)[-1]["why"] == "signer_refused_ids_differ"


def test_a_service_out_of_its_own_time_signs_nothing(env, tmp_path):
    """The service decides within PILOT_SIGNER_SECONDS - MARGIN_SECONDS; here its margin is the whole time, so the
    decision ends after its deadline: out_of_time, never a late signature."""
    repo = pd.Repo(tmp_path).path
    service = Service(env, tmp_path)
    request = proposal(env, service, comment_event(repo), "claude", "ESCALATE")
    code = ("import sys; sys.path.insert(0, sys.argv[1]); import signer_service as s; s.MARGIN_SECONDS = 10.0; "
            "sys.exit(s.main(['--config', sys.argv[2]]))")
    proc = subprocess.run([sys.executable, "-I", "-c", code, str(SERVICE.parent), str(service.config)],
                          input=json.dumps(request).encode("utf-8"), capture_output=True, timeout=60, check=False)
    assert (proc.returncode, proc.stdout.decode().strip()) == (3, "out_of_time"), proc
    assert service.ask(request).returncode == 0   # control: with its margin the same request is signed


def test_each_ref_line_of_a_push_gets_its_own_receipt_from_the_service(env, tmp_path):
    """Two ref lines: the service decides the push once per line and signs the action of that line, not the first."""
    r = pd.Repo(tmp_path)
    r.make("valid")
    service = Service(env, tmp_path)
    head, base = pd._rev(r.path, "HEAD"), pd._rev(r.path, "origin/main")
    lines = f"refs/heads/main {head} refs/heads/main {base}\nrefs/heads/main {head} refs/heads/other {'0' * 40}\n"
    proc = subprocess.run([sys.executable, "-I", str(GATE_FILE), "pre-push", "origin", p1.PUSH_URL], input=lines,
                          capture_output=True, text=True, cwd=str(r.path), env=env, timeout=180, check=False)
    receipts = p1.receipts_in(service.records)
    assert len(receipts) == 2, (proc.stderr, p1.journal(service.records))
    targets = sorted(signed_by(e, service.public)["proposedAction"]["target"]["uri"] for e in receipts)
    assert targets == ["https://github.com/b7n0de/pilot-probe#refs/heads/main",
                       "https://github.com/b7n0de/pilot-probe#refs/heads/other"]
    assert [(x["signed"], x["level"]) for x in service.lines()] == [(True, 2), (True, 2)]


def test_the_journal_of_the_service_names_no_path_no_command_and_no_value(env, tmp_path):
    repo = pd.Repo(tmp_path).path
    service = Service(env, tmp_path)
    p1.level1(env, repo, p1.COMMENT)
    service.ask(proposal(env, service, comment_event(repo), "claude", "ALLOW"))
    text = service.journal.read_text(encoding="utf-8")
    for word in (str(tmp_path), "Round four of five", "gh pr comment", env["PATH"]):
        assert word not in text, word
    assert set().union(*(set(line) for line in service.lines())) <= {"at", "signed", "reason", "elapsedMs", "level",
                                                                     "decisionId", "surface", "verdict"}


def test_a_service_slower_than_pilot_signer_seconds_is_stopped_and_named(monkeypatch):
    """N405-b: the gate stops the service after PILOT_SIGNER_SECONDS; the journal names it signer_timeout, never an
    internal error, and the receipt is not written."""
    monkeypatch.setattr(gate, "PILOT_SIGNER_SECONDS", 0.5)
    slow = {"signer": [sys.executable, "-c", "import time; time.sleep(5)"]}
    started = time.monotonic()
    with pytest.raises(gate.GateError, match=r"\Asigner_timeout\Z"):
        gate._pilot_sign(slow, b"{}", {"level": 1})
    assert time.monotonic() - started < 4


@pytest.mark.skipif(not hasattr(os, "geteuid") or os.geteuid() != 0, reason="needs root to give the repository to another account")
def test_a_repository_git_refuses_for_the_service_is_named_so(env, tmp_path):
    """The repository belongs to another account; the agent's git configuration names it safe.directory, the service's
    does not. The agent's gate allows the push; the service, whose git refuses the repository, decides otherwise and
    names why: repository_not_safe, not a verdict it judged differently. The probe of the delivery measures the same
    with two accounts."""
    r = pd.Repo(tmp_path)
    r.make("valid")
    service = Service(env, tmp_path)
    line = f"refs/heads/main {pd._rev(r.path, 'HEAD')} refs/heads/main {pd._rev(r.path, 'origin/main')}\n"
    for path in [r.path, *r.path.rglob("*")]:
        os.lchown(path, 65534, 65534)
    safe = tmp_path / "agent.gitconfig"
    safe.write_text(f"[safe]\n\tdirectory = {r.path}\n", encoding="utf-8")
    proc = subprocess.run([sys.executable, "-I", str(GATE_FILE), "pre-push", "origin", p1.PUSH_URL], input=line,
                          capture_output=True, text=True, cwd=str(r.path), env={**env, "GIT_CONFIG_GLOBAL": str(safe)},
                          timeout=180, check=False)
    assert proc.returncode == 0, proc.stderr
    assert p1.receipts_in(service.records) == []
    (line,) = service.lines()
    assert (line["signed"], line["reason"], line["verdict"]) == (False, "repository_not_safe", "DENY"), line
    assert p1.journal(service.records)[-1]["why"] == "signer_refused_repository_not_safe"
