"""D63, follow-up note 23 part 3: the four sites of the class of R25-1, O22-2 to O22-5 of its report, each with a marker case.

The class (D49, as review round 25 read it in R25-1): a reason gives a value the gate read, also as a fixed text that
appears only where the value is that text. Found in the class search of R25-1 (klasse/ of PLUGIN_R25_1_20261017):
- O22-2: the push check said `The configuration contains submodule.recurse=true; …`, the wording owner choice B: A of
  2026-10-10 took from review round 8 (R8-5); now `The configuration sets submodule.recurse; …`;
- O22-3: it said `… contains push.recurseSubmodules=<value>; …`; now `… sets push.recurseSubmodules to a value that
  recurses; …`;
- O22-4: the gh profile named the first entry of gh's extension folder; now `an entry in <the folder by its role>`;
- O22-5: it named the key path of an unknown key of hosts.yml, with the host and the user read from the file; now
  `<host>` and `<user>` stand in for them.
The verdicts do not change. Each case puts MARK where the value or name is read and finds it in no text, under Claude
Code and under Codex. RED at 9f578c2a and ab14e1ae: every marker case.
"""
from __future__ import annotations

import os
import time

import pytest

import test_plugin_ask_load_b_gh as b
import test_plugin_review_fix8_r5_recursion_reason as r8

gate = b.gate
pytestmark = b.pytestmark
MARK = "mrk23q"


# --- O22-2, O22-3: the push check ------------------------------------------------------------------------------------

def test_D63_submodule_recurse_is_named_by_its_key(tmp_path):
    r = r8._repo(tmp_path, ("submodule.recurse", "true"))
    reason = r8._reason(r.path)
    assert reason == "The configuration sets submodule.recurse; submodule push behavior is NOT MEASURED.", reason
    assert "=true" not in reason and "true" not in reason


@pytest.mark.parametrize("value", ["on-demand", "only"])
def test_D63_push_recurse_submodules_is_named_by_its_key(tmp_path, value):
    r = r8._repo(tmp_path, ("push.recurseSubmodules", value))
    reason = r8._reason(r.path)
    assert reason == ("The configuration sets push.recurseSubmodules to a value that recurses; submodule push behavior "
                      "is NOT MEASURED."), reason
    assert value not in reason


# --- O22-4, O22-5: the gh profile ------------------------------------------------------------------------------------

@pytest.fixture
def gh_env(monkeypatch, tmp_path):
    for key in [k for k in os.environ if k.startswith(("GH_", "GIT_", "XDG_")) or k in (
            "PAGER", "GITHUB_ENTERPRISE_TOKEN", "AI_AGENT", "DO_NOT_TRACK")]:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", os.devnull)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("LC_ALL", "C")
    (tmp_path / "home" / ".config" / "gh").mkdir(parents=True)
    (tmp_path / "bin").mkdir()
    b._fake_gh(tmp_path / "bin", "gh version 2.92.0 (2026-04-28)")
    monkeypatch.setenv("PATH", os.pathsep.join([str(tmp_path / "bin"), "/usr/local/bin", "/usr/bin", "/bin"]))
    monkeypatch.setenv("GH_TELEMETRY", "0")
    return tmp_path


def _gh(tmp_path, host):
    return gate.decide("gh pr view 41", str(b._repo(tmp_path)), time.monotonic() + 120, host)


@pytest.mark.parametrize("host", ["claude", "codex"])
def test_D63_an_extension_entry_is_not_named(gh_env, host):
    (gh_env / "home" / ".local" / "share" / "gh" / "extensions" / f"gh-{MARK}").mkdir(parents=True)
    out = _gh(gh_env, host)
    assert out.decision in ("ask", "deny") and "an entry in ~/.local/share/gh/extensions" in out.text, out.text
    assert MARK not in out.text, out.text


@pytest.mark.parametrize("host", ["claude", "codex"])
def test_D63_a_host_and_a_user_of_hosts_yml_are_not_named(gh_env, host):
    (gh_env / "home" / ".config" / "gh" / "hosts.yml").write_text(
        f"{MARK}h.example:\n    users:\n        {MARK}u:\n            other: x\n")
    out = _gh(gh_env, host)
    assert out.decision in ("ask", "deny") and "a key the gh profile does not know: <host>.users.<user>.other" in \
        out.text, out.text
    assert MARK not in out.text, out.text


def test_D63_a_pager_of_a_host_names_neither_the_host(gh_env):
    (gh_env / "home" / ".config" / "gh" / "hosts.yml").write_text(f"{MARK}h.example:\n    pager: less\n")
    out = _gh(gh_env, "claude")
    assert out.decision == "ask" and "a pager: <host>.pager" in out.text, out.text
    assert MARK not in out.text, out.text


def test_D63_a_key_of_config_yml_keeps_its_name(gh_env):
    """Control: a key of config.yml is the name of a key and stays, as D49 names keys."""
    (gh_env / "home" / ".config" / "gh" / "config.yml").write_text("probe_unknown: x\n")
    out = _gh(gh_env, "claude")
    assert "a key the gh profile does not know: probe_unknown in gh's config.yml" in out.text, out.text
