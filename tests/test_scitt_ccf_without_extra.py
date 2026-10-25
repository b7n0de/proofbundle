"""Without the [scitt] extra the scitt-ccf reader refuses, it does not fall back (ADR 0009, owner Q1 b).

Runs in both environments. Where cbor2 is installed, its absence is simulated by making the import
fail; where it is not installed, the same cases run against the real absence. Either way the module
must import, and every entry point must refuse with ``no_lib`` or ``ScittUnavailable``.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from proofbundle import scitt_ccf as S

REPO = Path(__file__).resolve().parents[1]
CONTROL_LIKE = bytes.fromhex("d28443a10126a0582000000000000000000000000000000000000000000000000000000000000000"
                             "0040")


@pytest.fixture
def no_cbor2(monkeypatch):
    monkeypatch.setitem(sys.modules, "cbor2", None)      # `import cbor2` now raises ImportError


def test_the_module_imports_without_cbor2():
    # THE CHILD IMPORTS THIS TREE (witness at 2b2cf082, 25.10.2026): pytest's pythonpath reaches no child
    # process, and the witness's interpreter carries an installed proofbundle without this module, so the
    # child failed there and passed where PYTHONPATH was inherited. It sets the path itself and names the
    # file it loaded, so an installed copy can neither fail nor pass this test in the tree's place.
    code = ("import sys; sys.modules['cbor2'] = None; import proofbundle.scitt_ccf as m; "
            "print(m.PROFILE); print(m.__file__)")
    env = dict(os.environ, PYTHONPATH=str(REPO / "src"), PYTHONDONTWRITEBYTECODE="1")
    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, timeout=60, env=env)
    assert out.returncode == 0, out.stderr
    profile, loaded = out.stdout.strip().splitlines()
    assert profile == "scitt-ccf/v1"
    assert Path(loaded).resolve() == (REPO / "src" / "proofbundle" / "scitt_ccf.py").resolve()


def test_verify_refuses_with_no_lib(no_cbor2):
    r = S.verify_transparent_statement(CONTROL_LIKE, canonical_root=b"\x00" * 32, rp_trust={})
    assert (r.status, r.readable, r.signature_valid, r.profile_satisfied) == ("no_lib", False, False, False)
    assert "[scitt]" in r.detail
    assert S.verify_statement_signature(CONTROL_LIKE, statement_keys=[b"x"]) == ("no_lib", None)
    c = S.verify_consistency_receipt(CONTROL_LIKE, older_root=b"\x00" * 32, older_issuer="x", rp_trust={})
    assert (c.status, c.readable, c.signature_valid) == ("no_lib", False, None)


@pytest.mark.parametrize("fn", [S.decode_cose_sign1, S.recompute_data_hash, S.load_cose_keyset])
def test_parsers_raise_scitt_unavailable(no_cbor2, fn):
    with pytest.raises(S.ScittUnavailable):
        fn(CONTROL_LIKE)


def test_a_cbor2_without_the_strict_options_is_refused(monkeypatch):
    class Old:                                           # the shape of cbor2 5.9.0: no strict options
        @staticmethod
        def loads(data, **kw):
            if kw:
                raise TypeError("'allow_duplicate_keys' is an invalid keyword argument for this function")
            return {}
    monkeypatch.setitem(sys.modules, "cbor2", Old)
    with pytest.raises(S.ScittUnavailable, match="cannot reject duplicate keys"):
        S.decode_cose_sign1(CONTROL_LIKE)
    assert S.verify_transparent_statement(CONTROL_LIKE, canonical_root=b"\x00" * 32).status == "no_lib"
