"""R20-5 of review round 20: the gh configuration reader does not block on a special file.

The gh profile (class b, D36) read config.yml and hosts.yml with a blocking open, so a FIFO without a writer in the
place of either file held the hook past its deadline (measured by the reviewer: no answer after about 1.5 s with 0.2 s
left). It now reads with the reader of R18-2: opened without blocking, the type checked at the descriptor, a special
file refused. A regular file, and a link to one, still pass.

RED at b34ba9a2 (the decision process does not answer before its timeout), green after. Each decision runs in a process
of its own, as the hook does.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time

import pytest

import test_plugin_ask_load_b_gh as b
from _plugin_env import plugin_env

pytestmark = [b.pytestmark, pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="no FIFOs here")]
_clean = b._clean

DECIDE = """
import importlib.util, json, sys, time
spec = importlib.util.spec_from_file_location("proofbundle_gate", sys.argv[1])
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)
try:
    out = gate.decide("gh pr view 1", sys.argv[2], time.monotonic() + float(sys.argv[3]), "claude")
    print(json.dumps(None if out is None else [out.decision, [v.reason_id for v in out.verdicts],
                                               " ".join(v.text() for v in out.verdicts)]))
except gate.GateError as exc:
    print(json.dumps(["error", [], str(exc)]))
"""


def _decide_in_process(tmp_path, repo, left: float, timeout: float = 20):
    started = time.monotonic()
    proc = subprocess.run([sys.executable, "-I", "-c", DECIDE, str(b.gate.__file__), str(repo), str(left)],
                          capture_output=True, text=True, env=plugin_env(), timeout=timeout, check=False)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout), time.monotonic() - started


@pytest.mark.parametrize("name", ["config.yml", "hosts.yml"])
@pytest.mark.parametrize("left", [30.0, 0.2])
def test_R20_5_a_fifo_in_the_place_of_a_gh_configuration_file_is_refused_without_blocking(tmp_path, name, left):
    repo = b._repo(tmp_path)
    os.mkfifo(tmp_path / "home" / ".config" / "gh" / name)
    answer, took = _decide_in_process(tmp_path, repo, left)
    assert took < 15, took
    assert answer is not None and answer[0] != "pass", answer
    if left > 1:
        assert answer[1] == ["gh_form_not_free"] and "not a regular file" in answer[2], answer


@pytest.mark.parametrize("name", ["config.yml", "hosts.yml"])
@pytest.mark.parametrize("link", [False, True])
def test_R20_5_control_a_regular_file_and_a_link_to_one_stay_free(tmp_path, name, link):
    repo = b._repo(tmp_path)
    regular = tmp_path / f"regular-{name}"
    regular.write_text("" if name == "config.yml" else "github.com:\n", encoding="utf-8")
    place = tmp_path / "home" / ".config" / "gh" / name
    if link:
        place.symlink_to(regular)
    else:
        place.write_text(regular.read_text(encoding="utf-8"), encoding="utf-8")
    answer, _took = _decide_in_process(tmp_path, repo, 30.0)
    assert answer[0] == "pass" and answer[1] == ["free_after_gh_profile"], answer
