"""Follow-up note 51, point 3: the test gap C10 that the review session's mutants of PLUGIN_N46 found.

The gate hashes at most MAX_PINNED_CONFIG_BYTES (1 MiB) of a pinned .git/config, and a larger one is never the pinned
one. No case had a larger configuration, so the mutant without the limit lived. Here the configuration holds more than
1 MiB of comment lines and the pin names its sha256, of the whole file and of the bytes the gate reads; the call keeps
its answer and pin-state refuses the clone.

The gate does not change in this point. RED against the mutants (measured, mutants_n51.py): _pinned_config_digest
without the size check, and a limit of 64 MiB. Green at d3ce27a2 and at the head. The control shows that the same clone
with a configuration of exactly 1 MiB is free.
"""
from __future__ import annotations

import contextlib
import hashlib
import io

import pytest

import test_plugin_n29_work_profile_d71 as d71
import test_plugin_n46_pinned_state_d114_d115 as d114

gate = d71.gate
pytestmark = d71.pytestmark
_clean = d71._clean

#: The limit of follow-up note 46 for a pinned .git/config, written here and not read from the gate, so that a change of the
#: limit in the gate is caught.
MIB = 1024 * 1024


def _grow_config(repo, size: int) -> None:
    """Fill .git/config with comment lines to exactly size bytes; git reads a comment as nothing."""
    config = repo / ".git" / "config"
    raw = config.read_bytes()
    line = b"# " + b"x" * 97 + b"\n"
    lines, rest = divmod(size - len(raw), len(line))
    raw += line * lines + (b"#" + b"y" * (rest - 2) + b"\n" if rest >= 2 else b"\n" * rest)
    config.write_bytes(raw)
    assert len(raw) == size


@pytest.mark.parametrize("digest_of", ["whole file", "bytes the gate reads"])
def test_C10_a_pinned_config_larger_than_1_mib_is_never_the_pinned_one(tmp_path, digest_of):
    repo = d114._repo(tmp_path)
    _grow_config(repo, MIB + 4096)
    raw = (repo / ".git" / "config").read_bytes()
    assert d71._git(repo, "config", "frob.knob").strip() == "1"   # git reads the file as before
    entry = d114._entry(repo)
    entry["konfig"] = hashlib.sha256(raw if digest_of == "whole file"
                                     else raw[:MIB + 1]).hexdigest()
    d114._pin([entry])
    answer = d114.answered(repo, "git commit -m work")
    assert not d114._free(answer), (digest_of, answer)


def test_C10_pin_state_refuses_a_config_larger_than_1_mib(tmp_path):
    repo = d114._repo(tmp_path)
    _grow_config(repo, MIB + 1)
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = gate.pin_state_command([str(repo)])
    assert code == 1 and out.getvalue() == "" and "cannot be pinned" in err.getvalue(), (code, err.getvalue())


def test_C10_the_limit_is_1_mib():
    assert gate.MAX_PINNED_CONFIG_BYTES == MIB


def test_C10_control_a_config_of_exactly_1_mib_is_pinned(tmp_path):
    repo = d114._repo(tmp_path)
    _grow_config(repo, MIB)
    d114._pin([d114._entry(repo)])
    assert d114._free(d114.answered(repo, "git commit -m work"))
