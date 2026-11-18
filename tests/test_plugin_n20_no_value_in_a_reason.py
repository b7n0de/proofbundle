"""D49, follow-up note 20 part 3: no reason of the gate names a value from the configuration, the environment or a file.

Found by the review session reading a8ca017a: two reasons of the fetch profile gave a value word for word, the URL of the remote
(`… is not https://github.com/<owner>/<repo>: {url!r}`) and the value of a credential helper (`{value!r}`). A URL can
carry a user and a token (`https://name:token@…`), and the reason is text the session reads. The class, searched over
every f-string of the gate (fstring_scan_n20.py of the delivery), had more members: the fetch rules, the URL in the pass
of the fetch profile, the filter an attribute names, the declaration's paths, a push setting, the URL rewrites of a
push, the programs and URLs of the transport binding, the URLs and the exec path of the Level 2 hand-over, the value of
an include, the pytest arguments and PYTEST_ADDOPTS of a receipt, the counts of a test report; and the key itself where
its subsection is a URL with a user (url.<base>.insteadOf, credential.<url>.*). Each now names the key, its scope and
its file, never the value; a key that holds an @ is named without its subsection.

Each case sets a value that holds a token-like word and checks that no reason of the gate holds it, under Claude Code
and under Codex. RED at a8ca017a where a8ca017a named the value; the cases where a8ca017a named only the key are
controls, green at both.
"""
from __future__ import annotations

import pytest

import _worktree_layout as w
import test_plugin_fetch_github_profile as f

pytestmark = w.d.pytestmark
TOKEN = "tok3n-7f1e9c2a5b8d4e6f0a1b"
HOSTS = ["claude", "codex"]


@pytest.fixture(autouse=True)
def _clean(monkeypatch, tmp_path):
    f._clean.__wrapped__(monkeypatch, tmp_path)


@pytest.fixture
def repo(tmp_path):
    return f.repo.__wrapped__(tmp_path)


def _texts(out) -> str:
    if out is None:
        return ""
    return "\n".join([out.text] + [v.text() for v in out.verdicts])


def _no_token(repo, command: str, host: str) -> str:
    out = f._decide(repo, command, host=host)
    text = _texts(out)
    assert TOKEN not in text and "name:" + TOKEN not in text, text
    return text


@pytest.mark.parametrize("host", HOSTS)
def test_N20_a_url_with_a_user_and_a_token_is_not_named(tmp_path, repo, host):
    w.git(repo, "remote", "set-url", "origin", f"https://name:{TOKEN}@github.com/o/r")
    text = _no_token(repo, "git -C {a} fetch -q origin main", host)
    if host == "claude":
        assert "remote.origin.url in the local configuration" in text, text


@pytest.mark.parametrize("host", HOSTS)
def test_N20_a_credential_helper_with_a_token_like_word_is_not_named(tmp_path, repo, host):
    w.git(repo, "config", "credential.helper", f"!/usr/bin/probe --token {TOKEN}")
    text = _no_token(repo, "git -C {a} fetch -q origin main", host)
    if host == "claude":
        assert "a credential helper the fetch profile does not know: credential.helper" in text, text


@pytest.mark.parametrize("host", HOSTS)
def test_N20_a_fetch_rule_is_not_named(tmp_path, repo, host):
    w.git(repo, "config", "--replace-all", "remote.origin.fetch", f"+refs/heads/{TOKEN}:refs/remotes/origin/main")
    text = _no_token(repo, "git -C {a} fetch -q origin main", host)
    if host == "claude":
        assert "remote.origin.fetch in the local configuration" in text, text


@pytest.mark.parametrize("host", HOSTS)
@pytest.mark.parametrize("key", [f"url.https://name:{TOKEN}@github.com/.insteadOf",
                                 f"credential.https://name:{TOKEN}@github.com.username"])
def test_N20_a_key_whose_subsection_names_a_user_is_named_without_it(tmp_path, repo, host, key):
    w.git(repo, "config", key, "https://github.com/")
    text = _no_token(repo, "git -C {a} fetch -q origin main", host)
    if host == "claude":
        assert "<a subsection that names a user>" in text, text


@pytest.mark.parametrize("host", HOSTS)
@pytest.mark.parametrize("command", ["git -C {a} log -1", "git -C {a} add README.md"])
def test_N20_the_read_profile_and_the_state_check_name_no_key_subsection_with_a_user(tmp_path, repo, host, command):
    w.git(repo, "config", f"http.https://name:{TOKEN}@github.com/.extraHeader", "X: y")
    w.git(repo, "config", f"probe.https://name:{TOKEN}@github.com/.value", "x")
    (repo / "README.md").write_text("changed\n")
    _no_token(repo, command, host)


@pytest.mark.parametrize("host", HOSTS)
@pytest.mark.parametrize("name, value", [("HTTPS_PROXY", f"http://name:{TOKEN}@127.0.0.1:3128"),
                                         ("GIT_SSH_COMMAND", f"ssh -o User={TOKEN}"),
                                         ("GIT_TRACE", TOKEN)])
def test_N20_control_an_environment_value_is_not_named(tmp_path, repo, monkeypatch, host, name, value):
    monkeypatch.setenv(name, value)
    text = _no_token(repo, "git -C {a} fetch -q origin main", host)
    if host == "claude":
        assert name in text, text


@pytest.mark.parametrize("host", HOSTS)
def test_N20_a_push_with_a_url_rewrite_names_no_url(tmp_path, repo, host):
    w.git(repo, "config", f"url.https://name:{TOKEN}@github.com/.insteadOf", "https://github.com/")
    _no_token(repo, "git -C {a} push origin HEAD:refs/heads/x", host)
    _no_token(repo, "git push origin HEAD:refs/heads/x", host)


@pytest.mark.parametrize("host", HOSTS)
def test_N20_an_unknown_key_of_the_read_profile_names_no_value(tmp_path, repo, host):
    w.git(repo, "config", "probe.secret", TOKEN)
    _no_token(repo, "git -C {a} log -1", host)


def test_N20_the_hook_output_holds_no_token(tmp_path, repo):
    w.git(repo, "remote", "set-url", "origin", f"https://name:{TOKEN}@github.com/o/r")
    w.git(repo, "config", "credential.helper", f"!/usr/bin/probe --token {TOKEN}")
    code, decision, reason = f._hook(tmp_path, f"git -C {repo} fetch -q origin main")
    assert (code, decision) == (0, "ask") and TOKEN not in reason, reason
