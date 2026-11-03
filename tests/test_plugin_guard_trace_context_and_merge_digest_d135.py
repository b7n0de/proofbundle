"""D135 (owner choice of 2026-11-03, in the scope of Agent Guard 0.4.0): every receipt of Level 1 names the call it
decides in traceContext, and the receipt of a merge binds the merge by its bytes.

Section 2 of draft-gruszka-audit-decision-receipts-06 maps trace_id and parent_id of the architecture onto
traceContext.traceId and traceContext.parentId. The gate wrote no traceContext, so a reader of a session record could
not tell which tool call a receipt decides. Now traceId is the session_id and parentId the tool_use_id of the hook
event, both of which Claude Code and Codex send with every PreToolUse event.

A merge had the empty bytes as its approved bytes (D55), so two different merges of one pull request carried the same
parametersDigest and the digest bound nothing. Now its bytes are the RFC 8785 form of the merge as the call names it:
the repository, the pull request, the head commit the call requires and the merge method, and the title and the body of
the merge commit where the call writes them. A call that does not name the head commit or the method is recorded as a
push at Level 1 is, with a parametersRef and no digest. The empty bytes are hashed for no surface any more.

Level 2 gets no traceContext. git hands the pre-push hook no session and no tool call, and the session the hook's
environment names is a value of the environment, which no receipt carries (D49, D55). Its receipt says so in notChecked.

RED at main 55890d01, where no receipt carries traceContext and every merge hashes the empty bytes.
"""
from __future__ import annotations

import base64
import hashlib
import json
import pathlib
import subprocess
import sys
import time

import pytest

import test_plugin_gate_n2c_push_done as pd
import test_plugin_z405_decision_receipt as p1
import test_plugin_z405_observer as o
import test_plugin_z405_signer_service as s

gate = pd.gate
GATE = pd.GATE
SESSION = "5f1d2c3b-7a4e-4a5b-8c9d-0123456789ab"
CALL = "toolu_01ABCdefGHIjklMNOpqrSTU"
HEAD = "4339361a" + "0" * 32
OTHER_HEAD = "34f5b0f0" + "1" * 32
EMPTY = hashlib.sha256(b"").hexdigest()
REPO = "b7n0de/proofbundle"
MERGE = f"gh pr merge 279 --repo {REPO} --squash --match-head-commit {HEAD}"


@pytest.fixture(autouse=True)
def _clean_git_environment(monkeypatch):
    pd._clean_git_environment.__wrapped__(monkeypatch)


@pytest.fixture
def env(tmp_path, monkeypatch):
    return pd.env.__wrapped__(tmp_path, monkeypatch)


def event(cwd: pathlib.Path, command: str | None = None, *, tool: str = "Bash", tool_input: dict | None = None,
          session: object = SESSION, call: object = CALL) -> str:
    """A PreToolUse event as Claude Code and Codex send it, with session_id and tool_use_id unless left out (None)."""
    data = {"hook_event_name": "PreToolUse", "tool_name": tool, "cwd": str(cwd),
            "tool_input": tool_input if tool_input is not None else {"command": command}}
    if session is not None:
        data["session_id"] = session
    if call is not None:
        data["tool_use_id"] = call
    return json.dumps(data)


def hook(env: dict, text: str, host: str = "claude") -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-I", str(GATE), "--host", host], input=text, capture_output=True,
                          text=True, env=env, timeout=180, check=False)


def descriptor(**over) -> dict:
    """The merge of MERGE as D135 writes it, before its RFC 8785 form."""
    return {"surface": "github.merge", "repository": REPO, "pullRequest": "279", "headCommit": HEAD,
            "mergeMethod": "squash", **over}


def jcs(value: dict) -> bytes:
    """The RFC 8785 form by the package's canonicalizer, the rfc8785 library: an oracle the gate does not use."""
    pytest.importorskip("rfc8785")
    from proofbundle.canonical import canonicalize_statement
    return canonicalize_statement(value)


def statement_bytes(action: dict, verdict: str = "ALLOW") -> bytes:
    config = {"gate_id": p1.GATE_ID, "observer_id": p1.OBSERVER_ID, "agent_id": p1.AGENT_ID, "principal_id": "operator",
              "validity_seconds": 600, "closing_rules": None}
    return gate._pilot_canonical(gate._pilot_statement(config, {}, action, verdict, ["rule"], "a-" + "0" * 32 + "#1",
                                                       time.time_ns()))


# --- traceContext at Level 1 -----------------------------------------------------------------------------------------

READ_FORMS = [
    p1.COMMENT,
    "gh api repos/b7n0de/proofbundle/pulls/279/comments/4121766394/replies -f body=Fixed.",
    "gh pr edit https://github.com/b7n0de/proofbundle/pull/279 --body 'New text.'",
    MERGE,
    "gh pr merge 279 --repo b7n0de/proofbundle --squash",
    "gh pr create --title T --body Body. --head feature --base main --repo b7n0de/proofbundle",
]


@pytest.mark.parametrize("host", ["claude", "codex"])
@pytest.mark.parametrize("command", READ_FORMS)
def test_every_receipt_of_level_1_names_the_session_and_the_tool_call(env, tmp_path, command, host):
    repo = pd.Repo(tmp_path).path
    receipts = p1.pilot_on(env, tmp_path)
    hook(env, event(repo, command), host)
    (envelope,) = p1.receipts_in(receipts)
    pred = p1.verified(envelope)
    assert pred["traceContext"] == {"traceId": SESSION, "parentId": CALL}
    assert "traceContext" not in [n["field"] for n in pred["notChecked"]]


def test_a_push_at_level_1_names_the_call_as_well(env, tmp_path):
    r = pd.Repo(tmp_path)
    r.make("valid")
    receipts = p1.pilot_on(env, tmp_path)
    hook(env, event(r.path, "git push origin main"))
    (envelope,) = p1.receipts_in(receipts)
    assert p1.verified(envelope)["traceContext"] == {"traceId": SESSION, "parentId": CALL}


@pytest.mark.parametrize(("tool", "tool_input"), [
    ("mcp__github__create_pull_request",
     {"owner": "b7n0de", "repo": "proofbundle", "title": "T", "body": "Body.", "head": "f", "base": "main"}),
    ("mcp__github__merge_pull_request",
     {"owner": "b7n0de", "repo": "proofbundle", "pullNumber": 279, "merge_method": "squash", "expectedHeadSha": HEAD}),
])
def test_an_mcp_write_names_the_session_and_the_tool_call(env, tmp_path, tool, tool_input):
    repo = pd.Repo(tmp_path).path
    receipts = p1.pilot_on(env, tmp_path)
    hook(env, event(repo, tool=tool, tool_input=tool_input))
    (envelope,) = p1.receipts_in(receipts)
    assert p1.verified(envelope)["traceContext"] == {"traceId": SESSION, "parentId": CALL}


@pytest.mark.parametrize(("session", "call", "trace"), [
    (None, None, None),
    (None, CALL, {"parentId": CALL}),
    (SESSION, None, {"traceId": SESSION}),
    ("", CALL, {"parentId": CALL}),
    ("two words", CALL, {"parentId": CALL}),
    (SESSION, "töol", {"traceId": SESSION}),
    (SESSION, "x" * 129, {"traceId": SESSION}),
    (7, ["toolu"], None),
])
def test_an_id_the_event_lacks_or_names_in_another_form_is_not_copied_and_notchecked_says_so(
        env, tmp_path, session, call, trace):
    repo = pd.Repo(tmp_path).path
    receipts = p1.pilot_on(env, tmp_path)
    hook(env, event(repo, p1.COMMENT, session=session, call=call))
    (envelope,) = p1.receipts_in(receipts)
    pred = p1.verified(envelope)
    assert pred.get("traceContext") == trace
    (note,) = [n for n in pred["notChecked"] if n["field"] == "traceContext"]
    assert "tool_use_id" in note["reason"] and note["impact"]


def test_the_trace_does_not_change_the_action_id_so_a_retried_call_counts_as_its_second_attempt(env, tmp_path):
    repo = pd.Repo(tmp_path).path
    receipts = p1.pilot_on(env, tmp_path)
    hook(env, event(repo, p1.COMMENT, call="toolu_01first"))
    hook(env, event(repo, p1.COMMENT, call="toolu_01second"))
    ids = sorted(p1.predicate_of(e)["decisionId"] for e in p1.receipts_in(receipts))
    assert [i.split("#")[1] for i in ids] == ["1", "2"] and len({i.split("#")[0] for i in ids}) == 1


# --- Level 2: no value of the environment reaches a receipt ----------------------------------------------------------

def test_a_receipt_of_level_2_names_no_session_of_the_environment_and_says_why(env, tmp_path):
    r = pd.Repo(tmp_path)
    r.make("valid")
    receipts = p1.pilot_on(env, tmp_path)
    proc = p1.level2({**env, "CLAUDE_CODE_SESSION_ID": SESSION}, r.path)
    assert proc.returncode == 0, proc.stderr
    (envelope,) = p1.receipts_in(receipts)
    pred = p1.verified(envelope)
    assert "traceContext" not in pred and SESSION.encode() not in base64.b64decode(envelope["payload"])
    (note,) = [n for n in pred["notChecked"] if n["field"] == "traceContext"]
    assert "git" in note["reason"] and note["impact"]


# --- the bytes of a merge ----------------------------------------------------------------------------------------------

def merge_bytes(command: str) -> bytes | None:
    action = gate._pilot_shell_action(command)
    assert action is not None and action["surface"] == "github.merge", command
    return action["bytes"]


def test_a_merge_hashes_the_rfc_8785_form_of_what_it_merges():
    assert merge_bytes(MERGE) == jcs(descriptor())
    action = gate._pilot_shell_action(MERGE)
    assert action["target"] == f"https://github.com/{REPO}/pull/279" and action["media"] == "application/json"


def test_the_same_merge_twice_gives_the_same_digest_in_every_spelling_the_pilot_reads():
    spellings = [MERGE, MERGE, f"gh pr merge 279 -R {REPO} -s --match-head-commit {HEAD}",
                 f"gh pr merge --match-head-commit {HEAD} --squash 279 --repo={REPO}",
                 f"gh pr merge https://github.com/{REPO}/pull/279 --squash --match-head-commit={HEAD}"]
    assert {merge_bytes(c) for c in spellings} == {jcs(descriptor())}


DIFFERENT = [
    (MERGE.replace(HEAD, OTHER_HEAD), {"headCommit": OTHER_HEAD}),
    (MERGE.replace("--squash", "--merge"), {"mergeMethod": "merge"}),
    (MERGE.replace("--squash", "--rebase"), {"mergeMethod": "rebase"}),
    (MERGE.replace("279", "280"), {"pullRequest": "280"}),
    (MERGE.replace(REPO, "b7n0de/other"), {"repository": "b7n0de/other"}),
    (MERGE + " --subject 'Land 279'", {"commitTitle": "Land 279"}),
    (MERGE + " -b 'Merged after review.'", {"commitMessage": "Merged after review."}),
]


@pytest.mark.parametrize(("command", "differs_in"), DIFFERENT)
def test_two_different_merges_give_different_digests(command, differs_in):
    other = merge_bytes(command)
    assert other == jcs(descriptor(**differs_in))
    assert hashlib.sha256(other).hexdigest() != hashlib.sha256(merge_bytes(MERGE)).hexdigest()


def test_the_merges_of_the_table_are_pairwise_different():
    commands = [MERGE] + [command for command, _ in DIFFERENT]
    assert len({merge_bytes(c) for c in commands}) == len(commands)


def test_a_merge_by_gh_and_the_same_merge_by_the_mcp_tool_have_one_digest():
    mcp = gate._pilot_mcp_action("mcp__github__merge_pull_request",
                                 {"owner": "b7n0de", "repo": "proofbundle", "pullNumber": 279,
                                  "merge_method": "squash", "expectedHeadSha": HEAD})
    assert mcp["bytes"] == merge_bytes(MERGE)
    titled = gate._pilot_mcp_action("mcp__github__merge_pull_request",
                                    {"owner": "b7n0de", "repo": "proofbundle", "pullNumber": "279",
                                     "merge_method": "squash", "expectedHeadSha": HEAD,
                                     "commit_title": "Größe — ok", "commit_message": "line\nnext"})
    assert titled["bytes"] == jcs(descriptor(commitTitle="Größe — ok", commitMessage="line\nnext"))
    assert titled["bytes"] == merge_bytes(MERGE + " -t 'Größe — ok' --body 'line\nnext'")


@pytest.mark.parametrize("command", [
    f"gh pr merge 279 --repo {REPO} --squash",                                   # no head commit
    f"gh pr merge 279 --repo {REPO} --match-head-commit {HEAD}",                 # no method
    f"gh pr merge 279 --repo {REPO} --squash --match-head-commit {HEAD[:39]}",   # not an object id
    f"gh pr merge 279 --repo {REPO} --squash --match-head-commit {HEAD.upper()}",
    f"gh pr merge 279 --repo {REPO} --squash --match-head-commit main",
])
def test_a_merge_that_does_not_name_its_head_commit_and_its_method_names_no_bytes(command):
    assert merge_bytes(command) is None


@pytest.mark.parametrize("tool_input", [
    {"pullNumber": 279, "merge_method": "squash"},
    {"pullNumber": 279, "expectedHeadSha": HEAD},
    {"pullNumber": 279, "merge_method": "fast-forward", "expectedHeadSha": HEAD},
    {"pullNumber": 279, "merge_method": "squash", "expectedHeadSha": HEAD, "commit_title": 5},
    {"pullNumber": 279, "merge_method": "squash", "expectedHeadSha": HEAD, "commit_message": None},
])
def test_an_mcp_merge_that_does_not_name_its_head_commit_and_its_method_names_no_bytes(tool_input):
    action = gate._pilot_mcp_action("mcp__github__merge_pull_request", {"owner": "b7n0de", "repo": "proofbundle",
                                                                       **tool_input})
    assert action["surface"] == "github.merge" and action["target"] == f"https://github.com/{REPO}/pull/279"
    assert action["bytes"] is None


def test_a_merge_through_the_hook_gets_the_digest_of_its_bytes_and_a_second_merge_another_one(env, tmp_path):
    repo = pd.Repo(tmp_path).path
    receipts = p1.pilot_on(env, tmp_path)
    hook(env, event(repo, MERGE))
    hook(env, event(repo, MERGE))
    hook(env, event(repo, MERGE.replace(HEAD, OTHER_HEAD)))
    preds = sorted((p1.verified(e) for e in p1.receipts_in(receipts)), key=lambda p: p["decisionId"])
    digests = [p["proposedAction"]["parametersDigest"]["sha256"] for p in preds]
    assert sorted(set(digests)) == sorted({hashlib.sha256(jcs(descriptor())).hexdigest(),
                                           hashlib.sha256(jcs(descriptor(headCommit=OTHER_HEAD))).hexdigest()})
    assert sorted(digests.count(d) for d in set(digests)) == [1, 2]
    assert {p["inputSnapshot"][0]["mediaType"] for p in preds} == {"application/json"}
    assert EMPTY not in digests


def test_a_merge_without_its_head_commit_is_recorded_without_a_digest_like_a_push_at_level_1(env, tmp_path):
    repo = pd.Repo(tmp_path).path
    receipts = p1.pilot_on(env, tmp_path)
    hook(env, event(repo, f"gh pr merge 279 --repo {REPO} --squash"))
    (envelope,) = p1.receipts_in(receipts)
    pred = p1.verified(envelope)
    assert "parametersDigest" not in pred["proposedAction"]
    assert pred["proposedAction"]["parametersRef"] == {"uri": "urn:proofbundle:pilot:not-resolved"}
    assert pred["proposedAction"]["target"]["uri"] == f"https://github.com/{REPO}/pull/279"
    assert "proposedAction" in [n["field"] for n in pred["notChecked"]]


# --- the empty bytes are hashed for no surface ---------------------------------------------------------------------

EMPTY_FORMS = [
    f"gh pr comment 279 --body '' --repo {REPO}",
    "gh pr edit https://github.com/b7n0de/proofbundle/pull/279 --body ''",
    "gh api repos/b7n0de/proofbundle/pulls/279/comments/4121766394/replies -f body=",
    f"gh pr create --title T --body '' --head feature --base main --repo {REPO}",
    f"gh pr merge 279 --repo {REPO} --squash",
]


@pytest.mark.parametrize("command", EMPTY_FORMS)
def test_no_surface_hashes_the_empty_bytes(command):
    action = gate._pilot_shell_action(command)
    assert action is not None, command
    body = statement_bytes(action)
    assert EMPTY.encode() not in body and b'"parametersDigest"' not in body
    assert gate._pilot_action_id({"agent_id": p1.AGENT_ID}, action, "key-1") != \
        gate._pilot_action_id({"agent_id": p1.AGENT_ID}, action, "key-2")   # the unresolved form, keyed by the call


@pytest.mark.parametrize("surface", gate.PILOT_SURFACES)
def test_no_surface_hashes_the_empty_bytes_whatever_form_gave_them(surface):
    """The rule at the one place every receipt passes: an action of any surface with the empty bytes is unresolved."""
    action = {"surface": surface, "target": f"https://github.com/{REPO}/pull/279", "bytes": b"", "media": "text/plain"}
    body = statement_bytes(action)
    assert EMPTY.encode() not in body and b'"parametersDigest"' not in body
    control = dict(action, bytes=b"x")
    assert hashlib.sha256(b"x").hexdigest().encode() in statement_bytes(control)


# --- the observer: no stored bytes it cannot rebuild ------------------------------------------------------------------

def test_the_observer_names_no_stored_bytes_for_a_merge():
    """GitHub's event of a merge names neither the merge method nor the title of the merge commit, so the observer
    cannot rebuild the bytes of D135 from it. It names none, so a merge is never matched by the empty bytes."""
    effect = o.pr._event_effect({"id": "1", "type": "PullRequestEvent", "created_at": "2026-11-03T16:47:23Z",
                                 "actor": {"id": o.AGENT_GITHUB_ID}, "repo": {"id": 1, "name": REPO},
                                 "payload": {"action": "closed", "number": 279,
                                             "pull_request": {"number": 279, "merged": True,
                                                              "merge_commit_sha": "c" * 40}}})
    assert (effect["surface"], effect["target"], effect["stored"]) == \
        ("github.merge", f"https://github.com/{REPO}/pull/279", None)


# --- the signer service builds the same trace from the event -----------------------------------------------------------

def test_the_signer_service_signs_a_receipt_with_the_trace_of_its_event(env, tmp_path):
    repo = pd.Repo(tmp_path).path
    service = s.Service(env, tmp_path)
    proc = hook(env, event(repo, MERGE))
    assert proc.returncode == 0
    (envelope,) = p1.receipts_in(service.records)
    pred = s.signed_by(envelope, service.public)
    assert pred["traceContext"] == {"traceId": SESSION, "parentId": CALL}
    assert pred["proposedAction"]["parametersDigest"]["sha256"] == hashlib.sha256(jcs(descriptor())).hexdigest()
    (line,) = service.lines()
    assert line["signed"] is True and line["surface"] == "github.merge"


def test_the_signer_service_refuses_a_trace_of_another_call(env, tmp_path):
    repo = pd.Repo(tmp_path).path
    service = s.Service(env, tmp_path)
    text = event(repo, p1.COMMENT)
    request = s.proposal(env, service, text, "claude", "ESCALATE")
    forged = json.loads(base64.b64decode(request["statement"]))
    forged["predicate"]["traceContext"]["parentId"] = "toolu_01another"
    forged["subject"][0]["digest"]["sha256"] = hashlib.sha256(gate._pilot_canonical(forged["predicate"])).hexdigest()
    request["statement"] = base64.b64encode(gate._pilot_canonical(forged)).decode("ascii")
    proc = service.ask(request)
    assert (proc.returncode, proc.stdout.decode().strip()) == (3, "statement_differs")
    control = service.ask(s.proposal(env, service, text, "claude", "ESCALATE"))
    assert control.returncode == 0, control.stdout


# --- the receipts of D55 stay valid ------------------------------------------------------------------------------------

def _profile():
    import importlib.util
    pytest.importorskip("rfc8785")
    spec = importlib.util.spec_from_file_location("_github_write_profile_d135",
                                                  p1.ROOT / "tools" / "pilot" / "github_write_profile.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("trace", [None, {"traceId": SESSION, "parentId": CALL}])
def test_a_receipt_of_d55_and_one_of_d135_both_verify_and_read_under_the_profile(trace):
    """A merge receipt as D55 wrote it, over the empty bytes and without traceContext, verifies as before; one with a
    traceContext verifies too. decision-receipt/v0.1 keeps traceContext an open object, and the profile reads neither."""
    from proofbundle.decision import verify_decision_receipt
    g = _profile()
    key = g.test_key("gate")
    pred = g.decision_predicate(action_id="a-" + "1" * 32, attempt=1, decided_at="2026-11-03T17:00:00Z",
                                expires_at="2026-11-03T17:10:00Z", surface="github.merge",
                                target=f"https://github.com/{REPO}/pull/279", approved=b"", verdict="ALLOW",
                                reasons=["rule"], gate_id=g.GATE_ID, agent_id=p1.AGENT_ID, principal_id="operator",
                                policy_digest="0" * 64, nonce="a-" + "1" * 32 + "#1", audience=g.OBSERVER_ID)
    if trace is not None:
        pred["traceContext"] = trace
    envelope = g.sign_decision(pred, key)
    result = verify_decision_receipt(envelope, g._pub(key), strict=True, expected_audience=g.OBSERVER_ID,
                                     expected_nonce=pred["decisionId"], require_derived_subject=True,
                                     now=g.instant("2026-11-03T17:00:00Z")[0] - 1)
    assert result["ok"] is True, result
    answer = g.reconcile(envelope, None, None, gate_key=g._pub(key), gate_id=g.GATE_ID, observer_key=g._pub(key),
                         observer_id=g.OBSERVER_ID)
    assert answer["verdict"] == g.UNKNOWN and answer["reasons"] == ["approved, and no effect was observed"]


# --- the key signer signs a traceContext only in the gate's form -------------------------------------------------------

def _key_signer():
    import test_plugin_z405_key_signer as ks
    return ks


def _statement_with(env: dict, trace: object, drop: bool = False) -> bytes:
    """A statement of the gate with `trace` as its traceContext and its subject derived again, in the key signer's
    canonical form, which writes a byte outside ASCII as it stands (the key signer refuses such a statement)."""
    ks = _key_signer()
    value = ks.statement(env)
    if drop:
        value["predicate"].pop("traceContext", None)
    else:
        value["predicate"]["traceContext"] = trace
    predicate = value["predicate"]
    value["subject"] = [{"name": f"decision:{predicate['decisionId']}",
                         "digest": {"sha256": hashlib.sha256(ks.k.canonical(predicate)).hexdigest()}}]
    return ks.k.canonical(value)


def test_the_key_signer_keeps_the_trace_form_of_the_gate(env):
    ks = _key_signer()
    assert ks.k._TRACE_ID.pattern == gate._PILOT_TRACE_ID.pattern
    assert ks.k.OPTIONAL_PREDICATE_KEYS == {"traceContext"} and ks.k.TRACE_KEYS == {"traceId", "parentId"}
    action, _key = gate._pilot_tool_action(json.loads(event(pathlib.Path("/"), p1.COMMENT)))
    pilot = {"gate_id": p1.GATE_ID, "observer_id": p1.OBSERVER_ID, "agent_id": p1.AGENT_ID, "principal_id": "operator",
             "validity_seconds": 600, "closing_rules": None}
    written = gate._pilot_statement(pilot, env, action, "ESCALATE", ["rule"], "a-" + "0" * 32 + "#1", time.time_ns())
    assert set(written["predicate"]) == ks.k.PREDICATE_KEYS | ks.k.OPTIONAL_PREDICATE_KEYS


@pytest.mark.parametrize("trace", [{"traceId": SESSION, "parentId": CALL}, {"traceId": SESSION}, {"parentId": CALL}])
def test_the_key_signer_signs_a_trace_the_gate_writes(env, tmp_path, trace):
    ks = _key_signer()
    key = ks.Key(tmp_path)
    proc = ks.run_key_signer(key.config, ks.request_of(_statement_with(env, trace)))
    assert proc.returncode == 0, proc


@pytest.mark.parametrize("trace", [{}, {"traceId": SESSION, "parentId": CALL, "traceparent": "00-x"}, {"traceId": 7},
                                   {"traceId": "two words"}, {"parentId": "töol"}, [SESSION], SESSION, None])
def test_the_key_signer_refuses_a_trace_the_gate_does_not_write(env, tmp_path, trace):
    ks = _key_signer()
    key = ks.Key(tmp_path)
    body = _statement_with(env, trace)
    proc = ks.run_key_signer(key.config, ks.request_of(body))
    assert proc.returncode == 3 and proc.stdout.decode().strip() in ("statement_type", "statement_malformed"), proc
    control = ks.run_key_signer(key.config, ks.request_of(_statement_with(env, None, drop=True)))
    assert control.returncode == 0, control
