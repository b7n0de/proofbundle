"""D52, addendum 2 to follow-up note 20, part 6: remote.<name>.pushurl and remote.<name>.push do not count for the fetch of
D45 from that remote.

Measured by the review session over account A's key list (names only): the clone pr31_strict_decoding carries remote.origin.pushurl,
and the fetch profile of a8ca017a asked for every key of the remote but url and fetch.

Ground truth at the stand-in for github.com (truth_n20_fetch.py of the delivery, git 2.43.0 under strace -f): a fetch
with a pushurl on another host, with a push rule, with both and with a pushurl that names a user started the same
programs, opened the same connection, made the same requests and wrote the same refs as without them.

The rule: the fetch profile does not count remote.<remote>.pushurl and remote.<remote>.push; every other key of the
remote asks as in D45. A push later in the same command stays a gated step that is not the first (D33, D45).
RED at a8ca017a for each freed case; the asking cases are controls.
"""
from __future__ import annotations

import pytest

import _worktree_layout as w
import test_plugin_fetch_github_profile as f

pytestmark = w.d.pytestmark
FETCH = "git -C {a} fetch -q origin main"
FREE = {"pushurl on another host": [("remote.origin.pushurl", "https://other.example/o/r")],
        "push rule": [("remote.origin.push", "refs/heads/main:refs/heads/other")],
        "pushurl and push rule": [("remote.origin.pushurl", "https://other.example/o/r"),
                                  ("remote.origin.push", "refs/heads/main:refs/heads/other")],
        "pushurl with a user": [("remote.origin.pushurl", "https://u@other.example/o/r")],
        "two pushurls": [("remote.origin.pushurl", "https://github.com/o/r"),
                         ("remote.origin.pushurl", "https://other.example/o/r")]}


@pytest.fixture(autouse=True)
def _clean(monkeypatch, tmp_path):
    f._clean.__wrapped__(monkeypatch, tmp_path)


@pytest.fixture
def repo(tmp_path):
    return f.repo.__wrapped__(tmp_path)


def _set(repo, entries):
    for key, value in entries:
        w.git(repo, "config", "--add", key, value)


@pytest.mark.parametrize("case", sorted(FREE))
def test_N20_a_push_setting_of_the_remote_leaves_the_fetch_free(tmp_path, repo, case):
    _set(repo, FREE[case])
    out = f._decide(repo, FETCH)
    assert f._fetch_free(out), (case, out and out.text)


@pytest.mark.parametrize("key, value", [("remote.origin.proxy", "http://127.0.0.1:3128"),
                                        ("remote.origin.vcs", "probe"), ("remote.origin.uploadpack", "/x"),
                                        ("remote.origin.tagOpt", "--tags"), ("remote.origin.skipFetchAll", "true")])
def test_N20_control_every_other_key_of_the_remote_asks(tmp_path, repo, key, value):
    _set(repo, [(key, value)])
    assert f._asked(f._decide(repo, FETCH)), key


def test_N20_control_a_push_of_another_remote_keeps_its_rules(tmp_path, repo):
    _set(repo, [("remote.upstream.url", "https://github.com/o/r"), ("remote.upstream.pushurl", "https://x.example/r")])
    assert f._fetch_free(f._decide(repo, FETCH))


def test_N20_a_later_push_in_the_same_command_stays_a_gated_step(tmp_path, repo):
    _set(repo, FREE["pushurl on another host"])
    out = f._decide(repo, "git -C {a} fetch -q origin main; git -C {a} push origin main")
    assert out is not None and out.decision in ("ask", "deny"), out and out.text
    assert "push" in out.text.split(".", 1)[0], out.text


def test_N20_control_under_codex_the_fetch_keeps_its_ask(tmp_path, repo):
    _set(repo, FREE["pushurl on another host"])
    assert f._asked(f._decide(repo, FETCH, host="codex"))
