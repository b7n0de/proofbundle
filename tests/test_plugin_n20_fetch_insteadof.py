"""D51, addendum 1 to follow-up note 20, part 5: url.<base>.insteadOf counts for the fetch of D45 only where it acts on it.

Measured on account A at a8ca017a: `git -C /home/<nutzer>/<repo> fetch -q github main` asked for
url.https://github.com/.insteadof in the global configuration /home/<nutzer>/.gitconfig.

Ground truth at the stand-in for github.com (truth_n20_fetch.py of the delivery, git 2.43.0 under strace -f): git puts
the base in place of the longest insteadOf value that is a prefix of the URL. A value that is no prefix of
https://github.com/o/r (git@github.com:, ssh://git@github.com/, both, account A's global form) left the fetch as it was:
the same programs, connection, requests and refs. A matching prefix took it to another host or to o/s on github.com;
an empty base and a base without a scheme made the URL a local path that git served with upload-pack through a shell;
pushInsteadOf on a matching prefix left the fetch as it was.

The rule: an insteadOf entry counts only where its value is a prefix of the remote's URL, or its base is empty or has
no scheme; pushInsteadOf never counts for the fetch; every other url.* key asks. The profile reads the values and
names none of them in a reason (D49). RED at a8ca017a for each freed case; the asking cases are controls.
"""
from __future__ import annotations

import pytest

import _worktree_layout as w
import test_plugin_fetch_github_profile as f

pytestmark = w.d.pytestmark
FETCH = "git -C {a} fetch -q origin main"
FREE = {"git@github.com: (account A's form)": [("url.https://github.com/.insteadOf", "git@github.com:")],
        "ssh://git@github.com/": [("url.https://github.com/.insteadOf", "ssh://git@github.com/")],
        "both values": [("url.https://github.com/.insteadOf", "git@github.com:"),
                        ("url.https://github.com/.insteadOf", "ssh://git@github.com/")],
        "another host's form": [("url.https://other.example/.insteadOf", "git@other.example:")],
        "a longer URL": [("url.https://other.example/.insteadOf", "https://github.com/o/r/more")],
        "pushInsteadOf on a prefix": [("url.https://other.example/.pushInsteadOf", "https://github.com/")],
        "pushInsteadOf without a scheme": [("url.github.com/.pushInsteadOf", "https://github.com/")]}
ASK = {"a prefix to another host": [("url.https://other.example/.insteadOf", "https://github.com/")],
       "a prefix to another repository on github.com": [("url.https://github.com/o/s.insteadOf", "https://github.com/o/r")],
       "the whole URL": [("url.https://other.example/x.insteadOf", "https://github.com/o/r")],
       "a prefix onto itself": [("url.https://github.com/.insteadOf", "https://github.com/")],
       "an empty value": [("url.https://other.example/.insteadOf", "")],
       "an empty base": [("url..insteadOf", "git@github.com:")],
       "a base without a scheme": [("url.github.com/.insteadOf", "git@github.com:")],
       "a free and an acting entry": [("url.https://github.com/.insteadOf", "git@github.com:"),
                                      ("url.https://other.example/.insteadOf", "https://github.com/")],
       "another url.* key": [("url.https://github.com/.probe", "x")]}


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
def test_N20_an_entry_that_does_not_act_on_the_fetch_leaves_it_free(tmp_path, repo, case):
    _set(repo, FREE[case])
    out = f._decide(repo, FETCH)
    assert f._fetch_free(out), (case, out and out.text)


def test_N20_deltas_global_entry_leaves_the_fetch_free(tmp_path, repo, monkeypatch):
    glob = tmp_path / "global.gitconfig"
    glob.write_text('[url "https://github.com/"]\n\tinsteadOf = git@github.com:\n')
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(glob))
    out = f._decide(repo, FETCH)
    assert f._fetch_free(out), out and out.text


@pytest.mark.parametrize("case", sorted(ASK))
def test_N20_control_an_entry_that_acts_on_the_fetch_asks_and_names_no_value(tmp_path, repo, case):
    _set(repo, ASK[case])
    out = f._decide(repo, FETCH)
    assert f._asked(out), (case, out and out.text)
    assert "github.com/o/r" not in out.text.replace("https://github.com/<owner>/<repo>", ""), out.text


def test_N20_control_an_entry_without_a_value_asks(tmp_path, repo):
    with open(repo / ".git" / "config", "a") as fh:
        fh.write('[url "https://other.example/"]\n\tinsteadOf\n')
    assert f._asked(f._decide(repo, FETCH))


@pytest.mark.parametrize("case", ["git@github.com: (account A's form)", "pushInsteadOf on a prefix"])
def test_N20_control_under_codex_the_fetch_keeps_its_ask(tmp_path, repo, case):
    _set(repo, FREE[case])
    assert f._asked(f._decide(repo, FETCH, host="codex"))
