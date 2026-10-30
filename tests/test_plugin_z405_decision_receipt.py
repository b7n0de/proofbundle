"""Z405 part 1 (DECISIONS.md D55): the gate issues a signed decision receipt for each GitHub write it decides.

The pilot is on when a person wrote pilot.json into the gate directory. Then each decision of the gate on a write to
GitHub that the pilot reads (a push at Level 2 with its ref lines, a plain push at Level 1, a comment, a reply in a
review thread, a pull request body, a merge, and the gated MCP tools) gets a decision-receipt/v0.1 of the profile
github-write/1, for an approval as for a refusal, with decidedAt before the write. The receipt changes nothing the gate
answers. It carries no value from the configuration, the environment or a credential, only the names of the pilot's
roles, digests and a target in the one GitHub form. The key is the operator's: the gate hands the bytes to the signer
pilot.json names. Here that signer is plugins/proofbundle/pilot/probe_signer.py with a key derived from a public label,
a probe and never a key of the pilot.

Red at 6459ff53, where the gate writes no receipt; the tests that compare the answers with and without the pilot are
controls and green there too.
"""
from __future__ import annotations

import base64
import datetime
import json
import pathlib
import subprocess
import sys
import time

import pytest

import test_plugin_gate_n2c_push_done as pd
from proofbundle.decision import verify_decision_receipt

gate = pd.gate
ROOT = pathlib.Path(__file__).resolve().parent.parent
GATE = pd.GATE
PROBE_SIGNER = ROOT / "plugins" / "proofbundle" / "pilot" / "probe_signer.py"
GATE_LABEL = "z405 probe gate"
GATE_ID, OBSERVER_ID, AGENT_ID = "operator:outbound-gate", "operator:github-observer", "agent:session-a"
PUSH_URL = "https://github.com/b7n0de/pilot-probe.git"
PUSH_TARGET = "https://github.com/b7n0de/pilot-probe#refs/heads/main"
COMMENT = 'gh pr comment 279 --body "Round four of five." --repo b7n0de/proofbundle'
CLOSING_RULES = {"github.conversationComment": "Written by an AI session of b7n0de under owner review.",
                 "github.reviewThreadReply": None, "github.pullRequestBody": "Measurement, not certification.",
                 "git.push": None, "github.merge": None}


@pytest.fixture(autouse=True)
def _clean_git_environment(monkeypatch):
    pd._clean_git_environment.__wrapped__(monkeypatch)


@pytest.fixture
def env(tmp_path, monkeypatch):
    return pd.env.__wrapped__(tmp_path, monkeypatch)


def public_key(label: str = GATE_LABEL) -> str:
    return subprocess.run([sys.executable, str(PROBE_SIGNER), "--label", label, "--public"], capture_output=True,
                          text=True, check=True, timeout=60).stdout.strip()


def pilot_on(env: dict, tmp_path: pathlib.Path, *, signer: list[str] | None = None) -> pathlib.Path:
    """Write pilot.json into the gate directory and return the receipt folder it names."""
    gate_dir = pathlib.Path(env["PROOFBUNDLE_GATE_DIR"])
    gate_dir.mkdir(parents=True, exist_ok=True)
    rules = tmp_path / "closing_rules.json"
    rules.write_text(json.dumps(CLOSING_RULES, sort_keys=True), encoding="utf-8")
    receipts = tmp_path / "receipts"
    config = {"profile": "github-write/1", "gate_id": GATE_ID, "observer_id": OBSERVER_ID, "agent_id": AGENT_ID,
              "principal_id": "operator", "validity_seconds": 600, "receipts": str(receipts),
              "signer": signer or [sys.executable, str(PROBE_SIGNER), "--label", GATE_LABEL],
              "public_key": public_key(), "closing_rules": str(rules)}
    (gate_dir / "pilot.json").write_text(json.dumps(config), encoding="utf-8")
    return receipts


def receipts_in(folder: pathlib.Path) -> list[dict]:
    return [json.loads(p.read_text(encoding="utf-8")) for p in sorted((folder / "decisions").glob("*.json"))]


def journal(folder: pathlib.Path) -> list[dict]:
    path = folder / "journal.jsonl"
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines()] if path.exists() else []


def predicate_of(envelope: dict) -> dict:
    return json.loads(base64.b64decode(envelope["payload"]))["predicate"]


def verified(envelope: dict) -> dict:
    """The predicate of a receipt that verifies with the probe key in strict mode, its subject derived from the
    predicate, addressed to the observer, with the decisionId as its nonce."""
    pred = predicate_of(envelope)
    result = verify_decision_receipt(envelope, bytes.fromhex(public_key()), strict=True, expected_audience=OBSERVER_ID,
                                     expected_nonce=pred["decisionId"], require_derived_subject=True)
    assert result["ok"] is True and result["crypto_ok"] is True and result["subject_derived_ok"] is True, result
    return pred


def level1(env: dict, cwd: pathlib.Path, command: str, host: str = "claude") -> subprocess.CompletedProcess:
    event = json.dumps({"hook_event_name": "PreToolUse", "tool_name": "Bash", "cwd": str(cwd),
                        "tool_input": {"command": command}})
    return subprocess.run([sys.executable, "-I", str(GATE), "--host", host], input=event, capture_output=True,
                          text=True, env=env, timeout=180, check=False)


def mcp(env: dict, cwd: pathlib.Path, tool: str, tool_input: dict) -> subprocess.CompletedProcess:
    event = json.dumps({"hook_event_name": "PreToolUse", "tool_name": tool, "cwd": str(cwd), "tool_input": tool_input})
    return subprocess.run([sys.executable, "-I", str(GATE)], input=event, capture_output=True, text=True, env=env,
                          timeout=180, check=False)


def level2(env: dict, repo: pathlib.Path, url: str = PUSH_URL) -> subprocess.CompletedProcess:
    """The pre-push hook as git starts it for a push to `url`: in the repository, with git's ref line on stdin."""
    line = f"refs/heads/main {pd._rev(repo, 'HEAD')} refs/heads/main {pd._rev(repo, 'origin/main')}\n"
    return subprocess.run([sys.executable, "-I", str(GATE), "pre-push", "origin", url], input=line,
                          capture_output=True, text=True, cwd=str(repo), env=env, timeout=180, check=False)


def log_lines(env: dict) -> list[dict]:
    path = pathlib.Path(env["CLAUDE_PLUGIN_DATA"]) / gate.LOG_NAME
    return [json.loads(x) for x in path.read_text(encoding="utf-8").splitlines()] if path.exists() else []


def instant(text: str) -> float:
    whole = datetime.datetime.strptime(text[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=datetime.timezone.utc)
    return whole.timestamp() + float("0." + text[20:-1])


# --- Level 1 -----------------------------------------------------------------------------------------------------

def test_an_asked_comment_gets_a_receipt_that_says_escalate_and_verifies(env, tmp_path):
    repo = pd.Repo(tmp_path).path
    receipts = pilot_on(env, tmp_path)
    before = time.time()
    proc = level1(env, repo, COMMENT)
    after = time.time()
    assert proc.returncode == 0 and json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecision"] == "ask"
    (envelope,) = receipts_in(receipts)
    pred = verified(envelope)
    assert pred["decision"]["verdict"] == "ESCALATE" and pred["decisionType"] == "preActionAuthorization"
    assert pred["proposedAction"] == {"actionType": "github.conversationComment", "method": "write",
                                      "target": {"name": "https://github.com/b7n0de/proofbundle/pull/279",
                                                 "uri": "https://github.com/b7n0de/proofbundle/pull/279"},
                                      "parametersDigest": {"sha256": gate.hashlib.sha256(
                                          b"Round four of five.").hexdigest()}}
    assert pred["decisionMaker"] == {"id": GATE_ID} and pred["agent"] == {"id": AGENT_ID}
    assert pred["policyBoundary"]["policyEngine"] == "proofbundle-pilot/github-write"
    assert pred["policyBoundary"]["bundleRevision"] == "1"
    assert pred["decision"]["reasonCodes"] == ["net_unmodeled_git"]
    assert before <= instant(pred["decidedAt"]) <= after   # decided before the call ran, which is after the hook
    assert instant(pred["validity"]["expiresAt"]) - instant(pred["decidedAt"]) == pytest.approx(600)
    action, attempt = pred["decisionId"].split("#")
    assert attempt == "1" and pred["validity"]["nonce"] == pred["decisionId"]
    closing = [s for s in pred["inputSnapshot"] if s["name"] == "closing rules"]
    assert closing == [{"name": "closing rules", "mediaType": "application/json",
                        "digest": {"sha256": gate.hashlib.sha256((tmp_path / "closing_rules.json").read_bytes())
                                   .hexdigest()}}]
    assert journal(receipts)[-1]["issued"] is True and journal(receipts)[-1]["decisionId"] == pred["decisionId"]


def test_under_codex_the_same_comment_is_refused_and_the_receipt_says_deny(env, tmp_path):
    repo = pd.Repo(tmp_path).path
    receipts = pilot_on(env, tmp_path)
    proc = level1(env, repo, COMMENT, host="codex")
    assert json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecision"] == "deny"
    (envelope,) = receipts_in(receipts)
    pred = verified(envelope)
    assert pred["decision"]["verdict"] == "DENY"
    assert [s["name"] for s in pred["inputSnapshot"]] == ["proposed bytes", "closing rules"]


def test_a_retried_action_keeps_its_action_id_and_counts_the_attempt(env, tmp_path):
    repo = pd.Repo(tmp_path).path
    receipts = pilot_on(env, tmp_path)
    level1(env, repo, COMMENT)
    level1(env, repo, COMMENT)
    level1(env, repo, COMMENT.replace("four", "five"))
    ids = sorted(predicate_of(e)["decisionId"] for e in receipts_in(receipts))
    actions = [i.split("#")[0] for i in ids]
    assert sorted(i.split("#")[1] for i in ids) == ["1", "1", "2"]
    assert len(set(actions)) == 2 and sorted(actions.count(a) for a in set(actions)) == [1, 2]


@pytest.mark.parametrize(("command", "surface", "target", "body"), [
    ("gh api repos/b7n0de/proofbundle/pulls/279/comments/4121766394/replies -f body=Fixed.",
     "github.reviewThreadReply", "https://github.com/b7n0de/proofbundle/pull/279", b"Fixed."),
    ("gh pr edit https://github.com/b7n0de/proofbundle/pull/279 --body 'New text.'", "github.pullRequestBody",
     "https://github.com/b7n0de/proofbundle/pull/279", b"New text."),
    ("gh pr merge 279 --squash --repo b7n0de/proofbundle", "github.merge",
     "https://github.com/b7n0de/proofbundle/pull/279", b""),
    ("gh pr create --title T --body Body. --head feature --base main --repo b7n0de/proofbundle",
     "github.pullRequestBody", "https://github.com/b7n0de/proofbundle/compare/main...feature", b"Body."),
])
def test_each_surface_the_pilot_reads_gets_its_target_and_bytes(env, tmp_path, command, surface, target, body):
    repo = pd.Repo(tmp_path).path
    receipts = pilot_on(env, tmp_path)
    level1(env, repo, command)
    (envelope,) = receipts_in(receipts)
    pred = verified(envelope)
    assert pred["proposedAction"]["actionType"] == surface and pred["proposedAction"]["target"]["uri"] == target
    assert pred["proposedAction"]["parametersDigest"]["sha256"] == gate.hashlib.sha256(body).hexdigest()


def test_an_mcp_pull_request_gets_a_receipt_from_its_own_arguments(env, tmp_path):
    repo = pd.Repo(tmp_path).path
    receipts = pilot_on(env, tmp_path)
    proc = mcp(env, repo, "mcp__github__create_pull_request",
               {"owner": "b7n0de", "repo": "proofbundle", "title": "T", "body": "Body.", "head": "f", "base": "main"})
    assert json.loads(proc.stdout)["hookSpecificOutput"]["permissionDecision"] == "ask"
    (envelope,) = receipts_in(receipts)
    pred = verified(envelope)
    assert (pred["proposedAction"]["actionType"], pred["proposedAction"]["target"]["uri"]) == \
        ("github.pullRequestBody", "https://github.com/b7n0de/proofbundle/compare/main...f")


def test_a_push_at_level_1_is_recorded_without_target_and_bytes(env, tmp_path):
    """The gate does not resolve what a push sends at Level 1 (D3); the receipt says so, and Level 2 names them. The
    pushed commit carries its done check, so the push asks for its destination (R9-1)."""
    r = pd.Repo(tmp_path)
    r.make("valid")
    repo = r.path
    receipts = pilot_on(env, tmp_path)
    level1(env, repo, "git push origin main")
    (envelope,) = receipts_in(receipts)
    pred = verified(envelope)
    assert pred["decision"]["verdict"] == "ESCALATE" and pred["proposedAction"]["actionType"] == "git.push"
    assert pred["proposedAction"]["target"] == {"name": "not resolved by the gate"}
    assert "parametersDigest" not in pred["proposedAction"] and pred["inputSnapshot"][0]["name"] == "closing rules"


@pytest.mark.parametrize("command", [
    "gh pr comment 279 --body-file note.md --repo b7n0de/proofbundle",   # bytes from a file the gate does not read
    "gh pr comment 279 -bText --repo b7n0de/proofbundle",               # a spelling the pilot does not read
    "cd . && gh pr comment 279 --body x --repo b7n0de/proofbundle",      # not one simple command
    'gh pr comment 279 --body "$TEXT" --repo b7n0de/proofbundle',        # an expansion
    "gh pr view 279",                                                    # a read
    "gh api repos/b7n0de/proofbundle/pulls/279/comments/1/replies -X PATCH -f body=x",
])
def test_a_form_the_pilot_does_not_read_gets_no_receipt_and_the_same_answer(env, tmp_path, command):
    repo = pd.Repo(tmp_path).path
    off = level1(env, repo, command)
    receipts = pilot_on(env, tmp_path)
    on = level1(env, repo, command)
    assert (on.returncode, on.stdout, on.stderr) == (off.returncode, off.stdout, off.stderr)
    assert receipts_in(receipts) == [] if (receipts / "decisions").exists() else True


# --- Level 2 -----------------------------------------------------------------------------------------------------

def test_an_allowed_push_gets_an_allow_receipt_that_names_the_commit_it_sends(env, tmp_path):
    r = pd.Repo(tmp_path)
    r.make("valid")
    receipts = pilot_on(env, tmp_path)
    before = time.time()
    proc = level2(env, r.path)
    assert proc.returncode == 0, proc.stderr
    (envelope,) = receipts_in(receipts)
    pred = verified(envelope)
    sent = pd._rev(r.path, "HEAD")
    assert pred["decision"]["verdict"] == "ALLOW" and pred["proposedAction"]["actionType"] == "git.push"
    assert pred["proposedAction"]["target"]["uri"] == PUSH_TARGET
    assert pred["proposedAction"]["parametersDigest"]["sha256"] == gate.hashlib.sha256(f"{sent}\n".encode()).hexdigest()
    assert pred["inputSnapshot"][0] == {"name": "approved bytes", "mediaType": "text/plain",
                                        "digest": pred["proposedAction"]["parametersDigest"]}
    assert before <= instant(pred["decidedAt"])


def test_a_refused_push_gets_a_deny_receipt_and_is_still_refused(env, tmp_path):
    r = pd.Repo(tmp_path)
    r.make("missing")
    receipts = pilot_on(env, tmp_path)
    proc = level2(env, r.path)
    assert proc.returncode == 1
    (envelope,) = receipts_in(receipts)
    pred = verified(envelope)
    assert pred["decision"] == {"verdict": "DENY", "reasonCodes": ["no_receipt"]}
    assert pred["inputSnapshot"][0]["name"] == "proposed bytes"


def test_a_push_through_git_writes_the_receipt_before_git_updates_the_remote(env, tmp_path):
    """git runs the hook before it sends anything: the receipt exists, and the remote has not moved, while the hook
    runs. A hook that records the remote's ref after the gate answered shows the order."""
    r = pd.Repo(tmp_path)
    r.make("valid")
    receipts = pilot_on(env, tmp_path)
    hooks = tmp_path / "hooks"
    hooks.mkdir()
    probe = tmp_path / "seen.txt"
    (hooks / "pre-push").write_text(
        f'#!/bin/sh\n"{sys.executable}" -I "{GATE}" pre-push "$@" || exit 1\n'
        f'git --git-dir "{tmp_path / "remote.git"}" rev-parse refs/heads/main > "{probe}"\n'
        f'ls "{receipts / "decisions"}" >> "{probe}"\n', encoding="utf-8")
    (hooks / "pre-push").chmod(0o755)
    pd._git(r.path, "config", "core.hooksPath", str(hooks))
    before = pd._git(tmp_path / "remote.git", "rev-parse", "refs/heads/main").stdout.strip()
    proc = pd._git(r.path, "push", "origin", "main", env=env, check=False)
    assert proc.returncode == 0, proc.stderr
    seen = probe.read_text(encoding="utf-8").split()
    assert seen[0] == before and len(seen) == 2 and seen[1].endswith("-1.json")
    assert pd._git(tmp_path / "remote.git", "rev-parse", "refs/heads/main").stdout.strip() == pd._rev(r.path, "HEAD")
    (envelope,) = receipts_in(receipts)
    assert predicate_of(envelope)["proposedAction"]["target"] == {"name": "not resolved by the gate"}   # a local URL


# --- what the receipt does not change, and what it does not carry ------------------------------------------------

COMMANDS = ["git status", "git log -1", COMMENT, "gh pr view 279", "git push origin main", "ls",
            "gh pr merge 279 --squash --repo b7n0de/proofbundle", "git push --no-verify origin main"]


@pytest.mark.parametrize("host", ["claude", "codex"])
def test_the_answer_and_the_log_are_the_same_with_and_without_the_pilot(env, tmp_path, host):
    repo = pd.Repo(tmp_path).path
    off = [level1(env, repo, c, host=host) for c in COMMANDS]
    logged_off = log_lines(env)
    pilot_on(env, tmp_path)
    on = [level1(env, repo, c, host=host) for c in COMMANDS]
    logged_on = log_lines(env)[len(logged_off):]
    assert [(p.returncode, p.stdout, p.stderr) for p in on] == [(p.returncode, p.stdout, p.stderr) for p in off]
    assert [{k: v for k, v in e.items() if k != "ts"} for e in logged_on] == \
        [{k: v for k, v in e.items() if k != "ts"} for e in logged_off]


@pytest.mark.parametrize("case", ["valid", "missing"])
def test_the_pre_push_answer_is_the_same_with_and_without_the_pilot(env, tmp_path, case):
    r = pd.Repo(tmp_path)
    r.make(case)
    off = level2(env, r.path)
    pilot_on(env, tmp_path)
    on = level2(env, r.path)
    assert (on.returncode, on.stdout, on.stderr) == (off.returncode, off.stdout, off.stderr)


def test_a_signer_that_fails_leaves_no_receipt_a_journal_line_and_the_same_answer(env, tmp_path):
    repo = pd.Repo(tmp_path).path
    off = level1(env, repo, COMMENT)
    receipts = pilot_on(env, tmp_path, signer=["/bin/false"])
    on = level1(env, repo, COMMENT)
    assert (on.returncode, on.stdout, on.stderr) == (off.returncode, off.stdout, off.stderr)
    assert receipts_in(receipts) == []
    assert [(e["issued"], e["why"]) for e in journal(receipts)] == [(False, "signer_failed")]


def test_without_pilot_json_nothing_is_written(env, tmp_path):
    r = pd.Repo(tmp_path)
    r.make("valid")
    level1(env, r.path, COMMENT)
    level2(env, r.path)
    assert not any(p.name in ("receipts", "journal.jsonl") for p in tmp_path.rglob("*"))


def test_no_value_of_the_configuration_or_the_environment_reaches_a_receipt(env, tmp_path):
    """The rule of D49 for the receipt: a credential in the push URL, a token in the environment and the paths of the
    pilot's own configuration appear in no receipt and no journal line; the push URL with a credential names no target."""
    r = pd.Repo(tmp_path)
    r.make("valid")
    receipts = pilot_on(env, tmp_path)
    planted = {**env, "GITHUB_TOKEN": "ghs_PLANTEDtokenZ405", "GH_TOKEN": "PLANTED-gh-token-z405"}
    level2(planted, r.path, url="https://x-access-token:PLANTED-url-secret@github.com/b7n0de/pilot-probe.git")
    level1(planted, r.path, COMMENT)
    texts = [p.read_bytes() for p in receipts.rglob("*") if p.is_file()]
    decoded = [base64.b64decode(json.loads(t)["payload"]) for t in texts if t.startswith(b"{\"payload\"")]
    assert len(decoded) == 2
    for blob in texts + decoded:
        for value in (b"PLANTED", str(tmp_path).encode(), str(PROBE_SIGNER).encode(), sys.executable.encode()):
            assert value not in blob, (value, blob[:200])
    pushed = [predicate_of(json.loads(t)) for t in texts if t.startswith(b"{\"payload\"")]
    assert {p["proposedAction"]["target"].get("uri") for p in pushed} == \
        {None, "https://github.com/b7n0de/proofbundle/pull/279"}


# --- the forms, read in process ----------------------------------------------------------------------------------

@pytest.mark.parametrize(("url", "target"), [
    ("https://github.com/b7n0de/pilot-probe.git", PUSH_TARGET),
    ("https://github.com/b7n0de/pilot-probe", PUSH_TARGET),
    ("git@github.com:b7n0de/pilot-probe.git", PUSH_TARGET),
    ("ssh://git@github.com/b7n0de/pilot-probe.git", PUSH_TARGET),
    ("https://user:secret@github.com/b7n0de/pilot-probe.git", None),
    ("https://github.com:443/b7n0de/pilot-probe.git", None),
    ("https://github.com/b7n0de/pilot-probe.git?x=1", None),
    ("https://example.org/b7n0de/pilot-probe.git", None),
    ("/tmp/remote.git", None),
    (None, None),
])
def test_the_push_target_is_read_only_from_a_plain_github_url(url, target):
    sha = "1" * 40
    ((action, _key),) = gate._pilot_push_actions(url, [("refs/heads/main", sha, "refs/heads/main", "0" * 40)])
    assert action["target"] == target and action["bytes"] == f"{sha}\n".encode()


def test_a_deletion_names_no_bytes():
    ((action, _key),) = gate._pilot_push_actions(PUSH_URL, [("(delete)", "0" * 40, "refs/heads/old", "2" * 40)])
    assert action["target"] == "https://github.com/b7n0de/pilot-probe#refs/heads/old" and action["bytes"] is None


def test_a_push_the_gate_leaves_inactive_gets_no_receipt(env, tmp_path):
    """A repository that declares nothing: Level 2 lets the push through as NOT MEASURED (D5), which is no decision on
    the write, so no receipt is written (found by mutant I09 of the first mutation run)."""
    repo = tmp_path / "plain"
    repo.mkdir()
    pd._git(repo, "init", "-q", "-b", "main")
    (repo / "f.txt").write_text("x\n", encoding="utf-8")
    pd._git(repo, "add", "-A")
    pd._git(repo, "commit", "-q", "-m", "one")
    remote = pd._rev(repo, "HEAD")   # a ref the remote holds already; creating one is asked (D3)
    (repo / "f.txt").write_text("y\n", encoding="utf-8")
    pd._git(repo, "commit", "-q", "-am", "two")
    receipts = pilot_on(env, tmp_path)
    line = f"refs/heads/main {pd._rev(repo, 'HEAD')} refs/heads/main {remote}\n"
    proc = subprocess.run([sys.executable, "-I", str(GATE), "pre-push", "origin", PUSH_URL], input=line,
                          capture_output=True, text=True, cwd=str(repo), env=env, timeout=180, check=False)
    assert proc.returncode == 0 and "NOT MEASURED" in proc.stderr, proc.stderr
    assert not (receipts / "decisions").exists() or receipts_in(receipts) == []
