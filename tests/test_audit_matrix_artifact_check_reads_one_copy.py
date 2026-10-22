"""B1 of CODEX-KLASSENSUCHE-631-01 (class B, at f6ea5cc3): the anchor's validity window binds the signed value.

Measured at f6ea5cc3: `_artifact_signature_ok` canonicalized the body built from `artifact.items()` and verified its
signature, then read `signer_role` and `produced_at` again through `artifact.get`. The input form of
`tests/test_release_tooling_refuses_weak_pinned_keys.py:124-129`, with the seed of
`tests/test_zeitsemantik_policy_und_supersession.py:23`: the body ``{"schema":"x","signer_role":role,
"produced_at":"2100-01-01T00:00:00Z"}`` correctly signed, and an anchor holding the same test key with
``not_after="2099-12-31"``. A dict subclass whose ``get`` answers ``produced_at`` with 2026-09-26 gave `verified`;
the same stored document as a plain dict gave `untrusted`. Controls: with the fitting external window 2100-12-31 the
subclass and the plain dict both verify in the same call.
"""
from __future__ import annotations

import base64
import importlib.util
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

REPO = Path(__file__).resolve().parents[1]
if str(REPO / "src") not in sys.path:
    sys.path.insert(0, str(REPO / "src"))
from proofbundle import canonical  # noqa: E402

KEY = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))              # the repository's test seed
PUB_B64 = base64.b64encode(KEY.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()


def _matrix():
    spec = importlib.util.spec_from_file_location("acm_one_copy", REPO / "scripts" / "audit_candidate_matrix.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


M = _matrix()
ROLE = next(iter(M._ANKER_ROLLEN))
OTHER_ROLE = "not-a-bound-role"


def _signed(role: str = ROLE) -> dict:
    body = {"schema": "x", "signer_role": role, "produced_at": "2100-01-01T00:00:00Z"}
    return dict(body, signature={"alg": "ed25519", "public_key_b64": PUB_B64,
                                 "sig_b64": base64.b64encode(KEY.sign(canonical.canonicalize_statement(body))).decode()})


def _anchor(not_after: str) -> dict:
    return {PUB_B64: {"role": ROLE, "not_after": not_after}}


class ReReadTime(dict):
    def get(self, key, default=None):
        return "2026-09-26T00:00:00Z" if key == "produced_at" else super().get(key, default)


class ReReadRole(dict):
    def get(self, key, default=None):
        return ROLE if key == "signer_role" else super().get(key, default)


class ReReadAnchor(dict):
    def __getitem__(self, key):
        return {"role": ROLE, "not_after": "2100-12-31"}

    def get(self, key, default=None):
        return self[key] if dict.__contains__(self, key) else default


def _state(artifact, anchor) -> str:
    return M._artifact_signature_ok(artifact, anchor, "ok")[0]


def test_a_second_reading_of_produced_at_does_not_meet_the_window():
    assert _state(ReReadTime(_signed()), _anchor("2099-12-31")) == M.ART_UNTRUSTED


def test_a_second_reading_of_signer_role_does_not_bind_the_role():
    assert _state(dict(_signed(OTHER_ROLE)), _anchor("2100-12-31")) == M.ART_UNTRUSTED, "precondition"
    assert _state(ReReadRole(_signed(OTHER_ROLE)), _anchor("2100-12-31")) == M.ART_UNTRUSTED


def test_a_second_reading_of_the_anchor_does_not_widen_its_window():
    assert _state(_signed(), ReReadAnchor(_anchor("2099-12-31"))) == M.ART_UNTRUSTED


@pytest.mark.parametrize("artifact", [ReReadTime, ReReadRole, dict], ids=["time subclass", "role subclass", "plain"])
def test_control_the_fitting_window_verifies_every_form(artifact):
    assert _state(artifact(_signed()), _anchor("2100-12-31")) == M.ART_VERIFIED


def test_control_the_plain_document_outside_the_window_is_untrusted():
    assert _state(dict(_signed()), _anchor("2099-12-31")) == M.ART_UNTRUSTED
