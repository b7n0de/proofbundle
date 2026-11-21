"""Counter-cases for the proofs of a CCF receipt: refused before any root is computed, by both verifiers.

draft-ietf-scitt-receipts-ccf-profile, section 3.2 (Inclusion Proof Verification Algorithm): after decoding each
inclusion-proof byte string the verifier MUST check its shape and MUST reject the proof before compute_root is
called if a check fails. The byte string is valid CBOR without duplicate map keys, internal-evidence is a text
string of 1 to 1024 bytes, and every path element is a boolean and a byte string of exactly 32 bytes. Without
the checks an oversized path element lets an existing leaf be recomputed as if it were an interior node.

The expected verdicts below come from those sentences, not from the reader. Receipts are built by the
independent builder of tests/test_scitt_ccf_profile.py. Each case runs through
`proofbundle.scitt_ccf.verify_transparent_statement` and through `pb_verify_rs verify-scitt-transparent-statement`
over the same bytes (AGENTS.md: both verifiers agree on the same bytes).
"""
from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import tempfile
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(importlib.util.find_spec("cbor2") is None,
                                reason="the scitt-ccf reader needs the [scitt] extra")

try:
    import _pb_verify_rs  # tests/_pb_verify_rs.py, the one way to the binary
except ModuleNotFoundError:  # pragma: no cover - `python -m unittest tests.<module>`
    from tests import _pb_verify_rs

import test_scitt_ccf_profile as P  # noqa: E402  the independent builder

ITX = hashlib.sha256(b"itx").digest()
EVIDENCE = P.Rcpt().evidence
PATH = [[i % 2 == 0, hashlib.sha256(bytes([i])).digest()] for i in range(4)]


def _proof(*, path=None, evidence=None) -> bytes:
    st = P.Stmt()
    return P.enc({1: [ITX, EVIDENCE if evidence is None else evidence, P.dh_of(st)],
                  2: PATH if path is None else path})


def _duplicate_key_proof() -> bytes:
    """A proof map whose head says three pairs and whose key 1 stands twice (RFC 8949 section 5.6)."""
    st = P.Stmt()
    good = _proof()
    assert good[0] == 0xA2
    return b"\xa3" + good[1:] + P.enc(1) + P.enc([ITX, EVIDENCE, P.dh_of(st)])


def _duplicate_vdp_receipt(st) -> bytes:
    """A receipt whose vdp map (396) holds key -1 twice, the same proofs under both (RFC 8949 section 5.6)."""
    good = P.Rcpt(data_hash=P.dh_of(st)).build()
    one = P.enc({-1: [P.enc({1: [ITX, EVIDENCE, P.dh_of(st)], 2: PATH})]})
    assert good.count(one) == 1
    return good.replace(one, b"\xa2" + one[1:] + one[1:], 1)


#: (name, inclusion proofs or None for the builder's own, consistency beside them or None)
REFUSED = [
    ("a path element of 33 bytes", lambda: [_proof(path=PATH[:-1] + [[True, b"\x11" * 33]])], None),
    ("a path element of 64 bytes", lambda: [_proof(path=PATH[:-1] + [[True, b"\x11" * 64]])], None),
    ("internal-evidence of 0 bytes", lambda: [_proof(evidence="")], None),
    ("internal-evidence of 1025 bytes", lambda: [_proof(evidence="x" * 1025)], None),
    ("internal-evidence of 1025 bytes in 2-byte characters", lambda: [_proof(evidence="x" + "é" * 512)], None),
    ("a duplicate key in the proof map", lambda: [_duplicate_key_proof()], None),
    ("a duplicate key -1 in the vdp map", "duplicate vdp", None),
]


def _statement(inclusion, consistency, **rkw) -> bytes:
    st = P.Stmt()
    if inclusion == "duplicate vdp":
        return P.transparent(st, [_duplicate_vdp_receipt(st)])
    rc = P.Rcpt(data_hash=P.dh_of(st), proofs_override=None if inclusion is None else inclusion(),
                consistency=None if consistency is None else consistency(), **rkw)
    return P.transparent(st, [rc.build()])


def _rust(statement: bytes) -> tuple:
    binary = _pb_verify_rs.binary_or_skip()
    trust = {"scitt_statement_keys": [P.spki(P.STMT_KEY).hex()],
             "scitt_ccf_services": {P.ISSUER: [P.spki(P.SERVICE_KEY).hex()]}}
    with tempfile.TemporaryDirectory() as tmp:
        (Path(tmp) / "s.cbor").write_bytes(statement)
        (Path(tmp) / "t.json").write_text(json.dumps(trust), encoding="utf-8")
        p = subprocess.run([str(binary), "verify-scitt-transparent-statement", str(Path(tmp) / "s.cbor"),
                            P.ROOT.hex(), str(Path(tmp) / "t.json")], capture_output=True, text=True, timeout=60)
    assert p.stdout.strip(), p.stderr
    return json.loads(p.stdout), p.returncode


class _Spy:
    """hashlib as scitt_ccf sees it, recording every input to sha256."""

    def __init__(self, real):
        self._real = real
        self.inputs: list = []

    def sha256(self, data=b"", **kw):
        self.inputs.append(bytes(data))
        return self._real.sha256(data, **kw)

    def __getattr__(self, name):
        return getattr(self._real, name)


@pytest.mark.parametrize("name, inclusion, consistency", REFUSED, ids=[c[0] for c in REFUSED])
def test_python_refuses_the_proof_before_any_root(monkeypatch, name, inclusion, consistency):
    from proofbundle import scitt_ccf as S
    statement = _statement(inclusion, consistency)
    spy = _Spy(hashlib)
    monkeypatch.setattr(S, "hashlib", spy)
    r = P.verify(statement)
    rc = r.receipts[0]
    assert (r.status, rc.status, rc.readable, rc.merkle_root) == ("malformed", "malformed", False, None), name
    assert not r.profile_satisfied
    # compute_root starts from the leaf hash, sha256(internal-transaction-hash || ...); no input starts there
    assert not [d for d in spy.inputs if d.startswith(ITX) and len(d) == 96], name


@pytest.mark.parametrize("name, inclusion, consistency", REFUSED, ids=[c[0] for c in REFUSED])
def test_rust_refuses_the_same_bytes(name, inclusion, consistency):
    out, code = _rust(_statement(inclusion, consistency))
    rc = out["receipts"][0]
    assert (out["status"], rc["status"], rc["readable"], rc.get("merkle_root")) == (
        "malformed", "malformed", False, None), name
    assert code == 3, name


@pytest.mark.parametrize("rkw", [dict(evidence="x" * 1024), dict(evidence="x")],
                         ids=["internal-evidence of 1024 bytes", "internal-evidence of 1 byte"])
def test_the_edges_inside_the_shape_still_confirm(rkw):
    """The other side of each bound: the cases above are refused for the bound, not for being built by hand."""
    st = P.Stmt()
    statement = P.transparent(st, [P.Rcpt(data_hash=P.dh_of(st), **rkw).build()])
    r = P.verify(statement)
    assert (r.status, r.receipts[0].readable) == ("confirmed", True)
    out, code = _rust(statement)
    assert (out["status"], code) == ("confirmed", 0)
