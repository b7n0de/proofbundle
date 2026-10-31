"""Owner choice of 2026-10-13, 15:1x Berlin, on C-5 of review round 14: promisor configuration is refused, and the refusal
claims no partial clone.

Measured at 947d9f26 with git 2.43.0 (class search of R14-3, C-5): remote.origin.promisor=false gave deny/gate_error with
"... is a partial clone (remote.origin.promisor)". Measured by the reviewer: true followed by false still starts the
transport program at an object read, and so do a filter, extensions.partialClone and another remote's promisor key; the
gate reads the keys' presence, not their last boolean value.

Property: under any of these keys the gate reads no object and denies, with the owner's wording, which says that the gate
does not evaluate this configuration and claims no partial clone. Red against 240220c2.
"""
from __future__ import annotations

import pytest

import test_plugin_owner_choice1_undeclared_push as w1

pytestmark = w1.pytestmark
env = w1.env
_clean_git_environment = w1._clean_git_environment
gate = w1.gate

WORDING = ("This repository has promisor-related configuration that this gate does not evaluate. The gate refuses "
           "object reads under this configuration. Use a full repository without that configuration for this check")
CONFIGS = {
    "promisor_false": [("remote.origin.promisor", "false")],
    "promisor_true_then_false": [("remote.origin.promisor", "true"), ("remote.origin.promisor", "false")],
    "filter": [("remote.origin.partialclonefilter", "blob:none")],
    "extension": [("extensions.partialClone", "origin")],
    "another_remote": [("remote.mirror.url", "MIRROR"), ("remote.mirror.promisor", "true")],
}


@pytest.mark.parametrize("config", sorted(CONFIGS))
def test_promisor_configuration_is_refused_without_claiming_a_partial_clone(env, tmp_path, config):
    work, remote, _a = w1._undeclared(tmp_path)
    for key, value in CONFIGS[config]:
        w1._git(work, "config", "--add", key, str(remote) if value == "MIRROR" else value)
    answer, entry, text = w1._l1(env, work)
    assert answer["hookSpecificOutput"].get("permissionDecision") == "deny", answer
    assert entry["verdict"] == "deny" and entry["reason_ids"] == ["gate_error"], entry
    assert WORDING in text and f"{WORDING}.." not in text, text
    assert "partial clone" not in text, text
