"""R25-1 of review round 25: the pass of a gh read form under gh 2.92.0 names the telemetry setting of config.yml by its
key and file, never by the value it read (D49).

Found by the reviewer at a8dc8f70: `_gh_telemetry_off` answered `telemetry: disabled in gh's config.yml` where
config.yml holds `telemetry: disabled`, and `_gh_read_free_verdict` took that text into the long reason. D49 forbids the
value read even as a fixed text. The fix names the source, `telemetry in gh's config.yml`; the comparison with
`disabled` and the decision stay.

The gh is the stand-in of tests/test_plugin_ask_load_b_gh.py answering `--version` as 2.92.0, config.yml holds exactly
`telemetry: disabled`, nothing else turns telemetry off. RED at a8dc8f70: the value in the long reason, under Claude
Code and under Codex. The verdict is the control, the same at both heads.
"""
from __future__ import annotations

import os
import time

import pytest

import test_plugin_ask_load_b_gh as b

pytestmark = b.pytestmark
gate = b.gate
LINE_2_92_0 = "gh version 2.92.0 (2026-04-28)"


@pytest.fixture(autouse=True)
def _clean(monkeypatch, tmp_path):
    """The environment of tests/test_plugin_gh_2_92_0.py: the stand-in gh as 2.92.0 first on PATH, no telemetry, data
    folder or host name of the caller, and config.yml with the one value under test."""
    for key in [k for k in os.environ if k.startswith(("GH_", "GIT_", "XDG_")) or k in (
            "PAGER", "GITHUB_ENTERPRISE_TOKEN", "AI_AGENT", "DO_NOT_TRACK")]:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", os.devnull)
    monkeypatch.setenv("GIT_CONFIG_SYSTEM", os.devnull)
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("LC_ALL", "C")
    (tmp_path / "home" / ".config" / "gh").mkdir(parents=True)
    (tmp_path / "home" / ".config" / "gh" / "config.yml").write_text("telemetry: disabled\n")
    (tmp_path / "bin").mkdir()
    b._fake_gh(tmp_path / "bin", LINE_2_92_0)
    monkeypatch.setenv("PATH", os.pathsep.join([str(tmp_path / "bin"), "/usr/local/bin", "/usr/bin", "/bin"]))


@pytest.mark.parametrize("host", ["claude", "codex"])
def test_R25_1_the_long_reason_names_the_source_not_the_value(tmp_path, host):
    repo = b._repo(tmp_path)
    out = gate.decide("gh pr view 41", str(repo), time.monotonic() + 120, host)
    # the verdict is unchanged: free after the gh profile, as at a8dc8f70
    assert out.decision in b.FREE and [v.reason_id for v in out.verdicts] == ["free_after_gh_profile"], out.text
    detail = out.verdicts[0].detail
    for text in (detail, out.text):
        assert "its telemetry is off (telemetry in gh's config.yml)" in text, text   # the source
        assert "disabled" not in text, text                                          # never the value read
