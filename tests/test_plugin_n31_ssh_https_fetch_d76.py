"""D76, Nachtrag 31, R3: an ssh setting alone does not hold the ask of the fetch of D45 from https on github.com.

Owner choice of 2026-10-18, 15:3x Berlin: where every URL of the remote, with insteadOf applied, is
https://github.com/<owner>/<repo>, core.sshCommand, GIT_SSH or GIT_SSH_COMMAND alone does not hold the ask of D45.
Measured with git 2.43.0 under strace against a stand-in for github.com (truth_remote_n31.py of the delivery): the fetch
with each of them, with all three and with an ssh push URL beside the https URL started no ssh and connected only to
github.com:443; with an ssh URL, an ssh:// URL or an insteadOf rule onto ssh it started the ssh program.

RED at 44db2056 (the head of Nachtrag 30): the free fetches under Claude Code. The counter cases, ls-remote and the
answers under Codex are controls, green at both. No case reaches a network.
"""
from __future__ import annotations

import os
import time

import pytest

import test_plugin_n29_work_profile_d71 as d71

gate = d71.gate
pytestmark = d71.pytestmark

FETCHES = ["git -C {R} fetch origin", "git -C {R} fetch -q --prune origin", "git -C {R} fetch --no-tags origin main"]


@pytest.fixture(autouse=True)
def _clean(monkeypatch, tmp_path):
    """The hook's environment of the tests of D71: no GH_* or GIT_* name but the two empty configuration files."""
    for key in [k for k in os.environ if k.startswith(("GH_", "GIT_")) or k in ("PAGER", "GITHUB_ENTERPRISE_TOKEN",
                                                                               "XDG_CONFIG_HOME", "AI_AGENT")]:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", os.devnull)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("LC_ALL", "C")
    monkeypatch.setenv("PROOFBUNDLE_GATE_DIR", str(tmp_path / "gatedir"))
    (tmp_path / "home" / ".config" / "gh").mkdir(parents=True)
    (tmp_path / "bin").mkdir()
    d71._fake_gh(tmp_path / "bin")
    monkeypatch.setenv("PATH", os.pathsep.join([str(tmp_path / "bin"), "/usr/local/bin", "/usr/bin", "/bin"]))


def _decide(repo, form, tmp_path, host="claude"):
    out = gate.decide(d71._command(form, repo, tmp_path), str(repo), time.monotonic() + 60, host)
    return out


#: The ssh settings of the order, each alone and all three, with an https URL; set in the configuration of the repository
#: or in the hook's environment.
SETTINGS = {
    "core.sshCommand": ({"core.sshCommand": "ssh -i /nonexistent"}, {}),
    "GIT_SSH": ({}, {"GIT_SSH": "/usr/bin/ssh"}),
    "GIT_SSH_COMMAND": ({}, {"GIT_SSH_COMMAND": "ssh -o BatchMode=yes"}),
    "all three": ({"core.sshCommand": "ssh"}, {"GIT_SSH": "ssh", "GIT_SSH_COMMAND": "ssh"}),
    "all three, an https push URL": ({"core.sshCommand": "ssh",
                                      "remote.origin.pushurl": "https://github.com/b7n0de/proofbundle"},
                                     {"GIT_SSH_COMMAND": "ssh"}),
}


def _apply(repo, monkeypatch, keys, env):
    for key, value in keys.items():
        d71._git(repo, "config", key, value)
    for name, value in env.items():
        monkeypatch.setenv(name, value)


@pytest.mark.parametrize("setting", sorted(SETTINGS))
@pytest.mark.parametrize("form", FETCHES)
def test_D76_an_ssh_setting_does_not_hold_the_https_fetch(tmp_path, monkeypatch, form, setting):
    repo = d71._repo(tmp_path, declaration=None)
    _apply(repo, monkeypatch, *SETTINGS[setting])
    out = _decide(repo, form, tmp_path)
    assert (out.decision, [v.reason_id for v in out.verdicts]) == ("pass", ["free_after_fetch_profile"]), out.text
    assert "An ssh setting is named" in out.text and "(DECISIONS.md D76)" in out.text, out.text


@pytest.mark.parametrize("setting", sorted(SETTINGS))
@pytest.mark.parametrize("form", FETCHES)
def test_D76_control_under_codex_the_fetch_is_not_free(tmp_path, monkeypatch, form, setting):
    repo = d71._repo(tmp_path, declaration=None)
    _apply(repo, monkeypatch, *SETTINGS[setting])
    out = _decide(repo, form, tmp_path, "codex")
    assert out.decision in ("ask", "deny") and not any(v.reason_id.startswith("free_") for v in out.verdicts)


#: Counter cases: a URL of the remote that is not https on github.com once git rewrites it, a setting beside the three,
#: and a form beside the fetch of D45. Each keeps its ask under Claude Code.
KEEP = {
    "an ssh URL": ({"remote.origin.url": "git@github.com:b7n0de/proofbundle.git", "core.sshCommand": "ssh"}, {}),
    "an ssh:// URL": ({"remote.origin.url": "ssh://git@github.com/b7n0de/proofbundle.git"},
                      {"GIT_SSH_COMMAND": "ssh"}),
    "insteadOf onto ssh": ({"url.git@github.com:.insteadOf": "https://github.com/", "core.sshCommand": "ssh"}, {}),
    "an ssh push URL": ({"remote.origin.pushurl": "git@github.com:b7n0de/proofbundle.git", "core.sshCommand": "ssh"},
                        {}),
    "a push URL of another host": ({"remote.origin.pushurl": "https://example.org/b7n0de/proofbundle"},
                                   {"GIT_SSH": "ssh"}),
    "insteadOf onto the push URL": ({"remote.origin.pushurl": "https://github.com/b7n0de/proofbundle",
                                     "url.git@github.com:.insteadOf": "https://github.com/b7n0de/proofbundle",
                                     "core.sshCommand": "ssh"}, {}),
    "pushInsteadOf onto ssh": ({"url.git@github.com:.pushInsteadOf": "https://github.com/", "core.sshCommand": "ssh"},
                               {}),
    "GIT_SSH_VARIANT": ({}, {"GIT_SSH_VARIANT": "ssh"}),
    "core.askPass": ({"core.askPass": "/bin/true"}, {}),
    "GIT_ASKPASS": ({}, {"GIT_ASKPASS": "/bin/true"}),
}


@pytest.mark.parametrize("case", sorted(KEEP))
def test_D76_control_a_counter_case_keeps_its_ask(tmp_path, monkeypatch, case):
    repo = d71._repo(tmp_path, declaration=None)
    _apply(repo, monkeypatch, *KEEP[case])
    out = _decide(repo, "git -C {R} fetch origin", tmp_path)
    assert out.decision == "ask" and "free_after_fetch_profile" not in [v.reason_id for v in out.verdicts], (case,
                                                                                                           out.text)


@pytest.mark.parametrize("form", ["git -C {R} ls-remote origin", "git -C {R} ls-remote --heads origin"])
def test_D76_control_ls_remote_keeps_its_rule(tmp_path, form):
    """The order names the fetch of D45; ls-remote (D59) keeps its rule for an ssh setting."""
    repo = d71._repo(tmp_path, declaration=None)
    d71._git(repo, "config", "core.sshCommand", "ssh")
    out = _decide(repo, form, tmp_path)
    assert out.decision == "ask", out.text


def test_D76_control_an_ssh_push_url_alone_stays_free_as_before(tmp_path):
    """D52: a fetch reads no push URL; without an ssh setting the push URL keeps no ask, as at the base."""
    repo = d71._repo(tmp_path, declaration=None)
    d71._git(repo, "config", "remote.origin.pushurl", "git@github.com:b7n0de/proofbundle.git")
    out = _decide(repo, "git -C {R} fetch origin", tmp_path)
    assert (out.decision, [v.reason_id for v in out.verdicts]) == ("pass", ["free_after_fetch_profile"]), out.text
    assert "An ssh setting is named" not in out.text
