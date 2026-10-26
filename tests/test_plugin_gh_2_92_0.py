"""D43, Ergänzung 2 to Nachtrag 18: gh 2.92.0 is a checked version of the gh profile, with a condition per deviation.

At delta, gh 2.92.0 at /usr/bin/gh made every gh read ask with "the gh on PATH ... is version 2.92.0, whose read forms
the gate has not measured". Measured like 2.89.0 for D36 (the release binary from github.com/cli/cli, its checksum the
release's): the three measurements of class b gave the same requests, tokens, exit codes, local writes and help for
every read form, with two deviations, each measured on its own:

* on every command, `--version` included, it starts `git -C <folder> config remote.origin.url` for each gh-* folder of
  its extension folder ($XDG_DATA_HOME/gh/extensions, else $HOME/.local/share/gh/extensions); 2.89.0 starts none;
* its telemetry is on unless turned off: each command writes gh/device-id into gh's state folder, and a sample of
  commands starts `gh send-telemetry`, which sends the command, its flags and the device id to GitHub.

So a read form under 2.92.0 is free only with an empty or missing extension folder and with telemetry off as gh
documents it: GH_TELEMETRY false or 0 (it decides when set), else DO_NOT_TRACK true or 1, else `telemetry: disabled` in
config.yml. The gate's own `gh --version` runs with GH_TELEMETRY=false and XDG_DATA_HOME=/dev/null, under which 2.92.0
started no git and wrote no device id. gh 2.89.0 has no telemetry: GH_TELEMETRY and the key `telemetry` no longer ask
there.

The gh is a script that answers `--version` with the line of 2.92.0 (tests/test_plugin_ask_load_b_gh.py). RED at
ba65da56 (and d8849ef8): every free case, the probe's environment, 2.89.0 with a telemetry setting, and the asks for an
extension folder by their text (there the version was named); the other asks are controls, green at every head.
"""
from __future__ import annotations

import os
import time

import pytest

import test_plugin_ask_load_b_gh as b

pytestmark = b.pytestmark
gate = b.gate
LINE_2_92_0 = "gh version 2.92.0 (2026-04-28)"
READS = ["gh pr view 41", "gh pr list --state open", "gh run list -L 5", "gh issue view 3 --comments",
         "gh pr diff 41 --name-only"]
#: The ways gh documents to turn its telemetry off, each with (environment, config.yml).
OFF = {"GH_TELEMETRY=false": ({"GH_TELEMETRY": "false"}, None),
       "GH_TELEMETRY=0": ({"GH_TELEMETRY": "0"}, None),
       "DO_NOT_TRACK=1": ({"DO_NOT_TRACK": "1"}, None),
       "DO_NOT_TRACK=true": ({"DO_NOT_TRACK": "true"}, None),
       "config disabled": ({}, "telemetry: disabled\n"),
       "config quoted disabled": ({}, 'telemetry: "disabled"\n'),
       # gh's order, measured: GH_TELEMETRY before DO_NOT_TRACK before the configuration
       "GH_TELEMETRY=false over config enabled": ({"GH_TELEMETRY": "false"}, "telemetry: enabled\n"),
       "GH_TELEMETRY=0 over DO_NOT_TRACK=0": ({"GH_TELEMETRY": "0", "DO_NOT_TRACK": "0"}, None),
       "DO_NOT_TRACK=1 over config enabled": ({"DO_NOT_TRACK": "1"}, "telemetry: enabled\n"),
       "config disabled beside DO_NOT_TRACK=0": ({"DO_NOT_TRACK": "0"}, "telemetry: disabled\n")}
#: Telemetry on, or off only by a value gh does not document: each keeps the ask.
ON = {"nothing set": ({}, None),
      "GH_TELEMETRY=true": ({"GH_TELEMETRY": "true"}, None),
      "GH_TELEMETRY=1": ({"GH_TELEMETRY": "1"}, None),
      "GH_TELEMETRY=log": ({"GH_TELEMETRY": "log"}, None),
      "GH_TELEMETRY=off": ({"GH_TELEMETRY": "off"}, None),
      "GH_TELEMETRY empty": ({"GH_TELEMETRY": ""}, None),
      "GH_TELEMETRY=FALSE": ({"GH_TELEMETRY": "FALSE"}, None),
      "DO_NOT_TRACK=0": ({"DO_NOT_TRACK": "0"}, None),
      "DO_NOT_TRACK empty": ({"DO_NOT_TRACK": ""}, None),
      "DO_NOT_TRACK=yes": ({"DO_NOT_TRACK": "yes"}, None),
      "DO_NOT_TRACK=TRUE": ({"DO_NOT_TRACK": "TRUE"}, None),
      "config enabled": ({}, "telemetry: enabled\n"),
      "config log": ({}, "telemetry: log\n"),
      "config false": ({}, "telemetry: false\n"),
      "GH_TELEMETRY=true over config disabled": ({"GH_TELEMETRY": "true"}, "telemetry: disabled\n"),
      "GH_TELEMETRY=true over DO_NOT_TRACK=1": ({"GH_TELEMETRY": "true", "DO_NOT_TRACK": "1"}, None),
      "telemetry under a host in hosts.yml": ({}, None)}


@pytest.fixture(autouse=True)
def _clean(monkeypatch, tmp_path):
    """The hook's environment of tests/test_plugin_ask_load_b_gh.py with the stand-in gh as 2.92.0 first on PATH, and
    no telemetry, data folder or host name of the caller."""
    for key in [k for k in os.environ if k.startswith(("GH_", "GIT_", "XDG_")) or k in (
            "PAGER", "GITHUB_ENTERPRISE_TOKEN", "AI_AGENT", "DO_NOT_TRACK")]:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", os.devnull)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("LC_ALL", "C")
    (tmp_path / "home" / ".config" / "gh").mkdir(parents=True)
    (tmp_path / "bin").mkdir()
    b._fake_gh(tmp_path / "bin", LINE_2_92_0)
    monkeypatch.setenv("PATH", os.pathsep.join([str(tmp_path / "bin"), "/usr/local/bin", "/usr/bin", "/bin"]))


def _set(tmp_path, monkeypatch, env: dict, config: str | None) -> None:
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    if config is not None:
        (tmp_path / "home" / ".config" / "gh" / "config.yml").write_text(config)


def _decide(tmp_path, command: str = "gh pr view 41", host: str = "claude"):
    repo = tmp_path / "r" if (tmp_path / "r").exists() else b._repo(tmp_path)
    return gate.decide(command, str(repo), time.monotonic() + 120, host)


def _free(out) -> bool:
    return out.decision in b.FREE and [v.reason_id for v in out.verdicts] == ["free_after_gh_profile"]


def _extension(folder, name: str = "gh-foo") -> None:
    (folder / name).mkdir(parents=True)
    (folder / name / name).write_text("#!/bin/sh\n")
    (folder / name / name).chmod(0o755)


@pytest.mark.parametrize("command", READS)
@pytest.mark.parametrize("way", list(OFF))
def test_E2_a_read_form_under_2_92_0_with_telemetry_off_is_free(tmp_path, monkeypatch, way, command):
    _set(tmp_path, monkeypatch, *OFF[way])
    out = _decide(tmp_path, command)
    assert _free(out), (way, command, out.decision, out.text)


def test_E2_the_case_measured_at_delta_is_free_with_telemetry_off(tmp_path, monkeypatch):
    """At delta every gh read asked with this text; with telemetry off and no extension it is gone."""
    out = _decide(tmp_path)
    assert out.decision == "ask" and "version 2.92.0" in out.text, out.text
    monkeypatch.setenv("GH_TELEMETRY", "0")
    out = _decide(tmp_path)
    assert _free(out) and "whose read forms the gate has not measured" not in out.text, out.text


def test_E2_the_pass_names_the_version_and_its_conditions(tmp_path, monkeypatch):
    _set(tmp_path, monkeypatch, {}, "telemetry: disabled\n")
    detail = _decide(tmp_path).verdicts[0].detail
    for named in ("gh 2.92.0", "its telemetry is off (telemetry in gh's config.yml)",   # the key, not its value (R25-1)
                  "no extension is installed", "D43"):
        assert named in detail, (named, detail)


@pytest.mark.parametrize("way", list(ON))
def test_E2_telemetry_on_keeps_the_ask(tmp_path, monkeypatch, way):
    env, config = ON[way]
    _set(tmp_path, monkeypatch, env, config)
    if way == "telemetry under a host in hosts.yml":
        (tmp_path / "home" / ".config" / "gh" / "hosts.yml").write_text("github.com:\n    telemetry: disabled\n")
    out = _decide(tmp_path)
    assert out.decision == "ask" and "telemetry" in out.text.lower(), (way, out.text)


@pytest.mark.parametrize("place", ["home", "xdg", "xdg_file_entry", "xdg_other_folder", "xdg_link"])
def test_E2_an_entry_in_the_extension_folder_keeps_the_ask(tmp_path, monkeypatch, place):
    monkeypatch.setenv("GH_TELEMETRY", "false")
    if place == "home":
        folder = tmp_path / "home" / ".local" / "share" / "gh" / "extensions"
        _extension(folder)
    else:
        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
        folder = tmp_path / "data" / "gh" / "extensions"
        if place == "xdg":
            _extension(folder, "gh-bar")
        elif place == "xdg_file_entry":
            folder.mkdir(parents=True)
            (folder / "gh-file").write_text("#!/bin/sh\n")
        elif place == "xdg_other_folder":
            (folder / "notgh").mkdir(parents=True)
        else:
            _extension(tmp_path / "elsewhere")
            folder.mkdir(parents=True)
            (folder / "gh-link").symlink_to(tmp_path / "elsewhere" / "gh-foo")
    out = _decide(tmp_path)
    # D49 as sharpened by Nachtrag 21: the folder by the setting that places it, never its path
    named = ("in ~/.local/share/gh/extensions" if place == "home"
             else "in gh/extensions in the folder XDG_DATA_HOME names")
    assert out.decision == "ask" and named in out.text and "starts git" in out.text, (place, out.text)
    assert str(folder) not in out.text, (place, out.text)


def test_E2_xdg_data_home_decides_where_the_extensions_are(tmp_path, monkeypatch):
    """Measured: with XDG_DATA_HOME set, 2.92.0 looked only there; set and empty, it looked under HOME."""
    monkeypatch.setenv("GH_TELEMETRY", "false")
    _extension(tmp_path / "home" / ".local" / "share" / "gh" / "extensions")
    (tmp_path / "data" / "gh" / "extensions").mkdir(parents=True)
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    assert _free(_decide(tmp_path))
    monkeypatch.setenv("XDG_DATA_HOME", "")
    assert _decide(tmp_path).decision == "ask"


@pytest.mark.parametrize("case", ["relative_xdg", "no_home", "extension_folder_is_a_file"])
def test_E2_an_extension_folder_the_gate_cannot_read_keeps_the_ask(tmp_path, monkeypatch, case):
    monkeypatch.setenv("GH_TELEMETRY", "false")
    if case == "relative_xdg":
        monkeypatch.setenv("XDG_DATA_HOME", "data")
    elif case == "no_home":
        monkeypatch.setenv("GH_CONFIG_DIR", str(tmp_path / "home" / ".config" / "gh"))
        monkeypatch.delenv("HOME")
    else:
        (tmp_path / "data" / "gh").mkdir(parents=True)
        (tmp_path / "data" / "gh" / "extensions").write_text("x")
        monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    out = _decide(tmp_path)
    assert out.decision == "ask" and "extension folder" in out.text, (case, out.text)


def test_E2_the_version_probe_runs_with_telemetry_off_and_no_extension_folder(tmp_path, monkeypatch):
    """The gate's own `gh --version` (measured for 2.92.0: without these two settings it started git in each
    extension folder and wrote gh/device-id)."""
    log = tmp_path / "probe_env.log"
    (tmp_path / "bin" / "gh").write_text(
        f'#!/bin/sh\nif [ "$1" = "--version" ]; then echo "GH_TELEMETRY=$GH_TELEMETRY XDG_DATA_HOME=$XDG_DATA_HOME" '
        f'>> {log}; echo "{LINE_2_92_0}"; exit 0; fi\nexit 0\n')
    monkeypatch.setenv("DO_NOT_TRACK", "1")
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    assert _free(_decide(tmp_path))
    assert set(log.read_text().splitlines()) == {f"GH_TELEMETRY=false XDG_DATA_HOME={os.devnull}"}


@pytest.mark.parametrize("line", ["gh version 2.91.0 (2026-04-14)", "gh version 2.93.0 (2026-05-12)",
                                  "gh version 2.92.1 (2026-05-02)", "gh version 2.92.0-rc1 (2026-04-20)"])
def test_E2_control_other_versions_keep_the_ask(tmp_path, monkeypatch, line):
    b._fake_gh(tmp_path / "bin", line)
    monkeypatch.setenv("DO_NOT_TRACK", "1")      # off for 2.92.0, a name the profile reads at no head
    out = _decide(tmp_path)
    assert out.decision == "ask" and ("has not measured" in out.text or "named no gh version" in out.text), out.text


@pytest.mark.parametrize("way", ["extension", "GH_TELEMETRY=false", "GH_TELEMETRY=0", "config enabled",
                                 "config disabled"])
def test_E2_under_2_89_0_extensions_and_telemetry_do_not_count(tmp_path, monkeypatch, way):
    """gh 2.89.0 starts no git for an extension (measured, control) and has no telemetry (no GH_TELEMETRY, DO_NOT_TRACK
    or send-telemetry in its binary, and `telemetry:` in config.yml changed none of its starts): the telemetry
    settings are red at ba65da56, where GH_TELEMETRY and the key were unknown to the profile."""
    b._fake_gh(tmp_path / "bin", b.VERSION_LINE)
    if way == "extension":
        _extension(tmp_path / "home" / ".local" / "share" / "gh" / "extensions")
    elif way.startswith("GH_TELEMETRY"):
        monkeypatch.setenv(*way.split("="))
    else:
        _set(tmp_path, monkeypatch, {}, f"telemetry: {way.split()[1]}\n")
    out = _decide(tmp_path)
    assert _free(out), (way, out.text)
    assert "D43" not in out.verdicts[0].detail


@pytest.mark.parametrize("name", ["GH_TELEMETRY_SAMPLE_RATE", "GH_TELEMETRY_ENDPOINT_URL"])
def test_E2_control_the_telemetry_tuning_names_keep_the_ask(tmp_path, monkeypatch, name):
    """Measured: GH_TELEMETRY_SAMPLE_RATE=100 made every command start `gh send-telemetry` to
    GH_TELEMETRY_ENDPOINT_URL; the profile knows neither name, for either version."""
    monkeypatch.setenv("DO_NOT_TRACK", "1")
    monkeypatch.setenv(name, "100" if name.endswith("RATE") else "http://127.0.0.1:9/t")
    for line in (LINE_2_92_0, b.VERSION_LINE):
        b._fake_gh(tmp_path / "bin", line)
        out = _decide(tmp_path)
        assert out.decision == "ask" and name in out.text, (line, out.text)


def test_E2_under_the_bound_host_the_pager_and_the_conditions_are_named(tmp_path, monkeypatch):
    """D41 and D43 together: under Claude Code with a host of the series 2.1.x a pager does not count, and the pass
    names both."""
    monkeypatch.setenv("AI_AGENT", "claude-code_2-1-302_harness")
    monkeypatch.setenv("PAGER", "less")
    monkeypatch.setenv("DO_NOT_TRACK", "1")
    out = _decide(tmp_path)
    assert _free(out), out.text
    detail = out.verdicts[0].detail
    # D49 as sharpened by Nachtrag 21: the variable, not its value
    assert "D41" in detail and "DO_NOT_TRACK in the hook's environment" in detail, detail
