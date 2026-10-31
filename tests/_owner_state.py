"""D124: the hook's environment where a channel the session cannot write protects the gate directory.

Since D124 the gate reads the owner files of its directory (mode and rules.json of D25, transports.json of D35,
hook-state.json of D106, pin-state.json of D114, the releases in freigaben/ of D111 and work-folders.json of D104) only
where PROOFBUNDLE_OWNER_STATE is `protected`. A test module that tests what a person's file there does imports
`owner_state_protected`, so each of its cases runs with that setting, as a house with such a channel would run the
hook. tests/test_plugin_owner_state_session_written_d124.py holds Guard Preview's default without it.
"""
from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def owner_state_protected(monkeypatch):
    monkeypatch.setenv("PROOFBUNDLE_OWNER_STATE", "protected")
