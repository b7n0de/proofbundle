"""D129: the hook's environment where the house states its consent to the standing GO of D87.

Since D129 the standing GO of D87 frees a push to the own work branch, in the autonomous answer, only where the hook's
environment also sets PROOFBUNDLE_STANDING_GO to `protected`; --autonomous alone no longer does. A test module that
tests what the GO does imports `standing_go_consented`, so each of its cases runs with that setting, as a house that
consents to the GO would run the hook; a helper that builds the hook's environment by name carries the setting from
os.environ where it is set. tests/test_plugin_standing_go_consent_d129.py holds the answer without it.
"""
from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def standing_go_consented(monkeypatch):
    monkeypatch.setenv("PROOFBUNDLE_STANDING_GO", "protected")
