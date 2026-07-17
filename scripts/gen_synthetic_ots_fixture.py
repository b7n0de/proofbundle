#!/usr/bin/env python3
"""Generate the SYNTHETIC, ripemd160-free upgraded OpenTimestamps confirmed-path fixture (WP-D1).

Why this exists. The only vendored UPGRADED external vector (``hello-world.txt.ots``) walks an op DAG
that uses RIPEMD160 (Bitcoin's OP_HASH160-style commitment). RIPEMD160 needs OpenSSL's *legacy*
provider, which is OFF by default on OpenSSL 3.x, so ``hashlib.new("ripemd160")`` raises and the whole
confirmed-path external-vector test is honestly ``@skipUnless(ripemd160 available)`` — skipped in the
3.6.0 cleanroom pytest. That left the confirmed/self-contained OTS lifecycle WITHOUT an unconditional
regression.

This fixture closes that gap. It is a proofbundle-GENERATED synthetic proof (NOT an external vector):
a ``DetachedTimestampFile`` whose op path is SHA-256 only and which carries a single
``BitcoinBlockHeaderAttestation``. It deserializes and verifies WITHOUT ripemd160, so a confirmed-path
test built on it runs on every interpreter. Honest scope: it exercises proofbundle's OWN verifier
lifecycle (structural binding + upgraded classification + RP-header confirmation), it does NOT prove
anything about a real Bitcoin block.

Null-Op hardening (2026-07-17). The attestation sits at the end of a REAL op chain
(``OpAppend`` a nonce, then ``OpSHA256`` twice, Bitcoin double-SHA style) BELOW the file digest, so the
attested "block merkle root" is ``sha256(sha256(file_digest ‖ nonce))`` and DIFFERS from the file digest,
exactly as a genuine Bitcoin merkle path does. The earlier version planted the attestation directly on the
file digest (leaf == root, zero ops); ``verify_opentimestamps`` now refuses such a Null-Op branch
(``status: null_op``), because a producer could freely set ``file_digest == canonicalRoot == the attested
value`` with no hashing at all. The relying-party header the confirmed-path test supplies is this attested
merkle root (recorded in the ``.block.json``), not the file digest.

Re-generate (deterministic; the bytes are pinned in tests/fixtures/ots/PROVENANCE.json):

    PYTHONPATH=src python scripts/gen_synthetic_ots_fixture.py

The three emitted files:
  * synthetic-upgraded-sha256.txt        — the target bytes (the thing "stamped")
  * synthetic-upgraded-sha256.txt.ots    — the detached, upgraded (Bitcoin-attested) OTS proof
  * synthetic-upgraded-sha256.block.json — the relying-party trust header for the attested height
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

FIXTURE_DIR = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "ots"
STEM = "synthetic-upgraded-sha256"
# Fixed, human-readable target bytes so the whole fixture is reproducible byte-for-byte.
TARGET_BYTES = (b"proofbundle synthetic upgraded OpenTimestamps vector "
                b"(SHA-256 only, ripemd160-free confirmed-path fixture)\n")
HEIGHT = 800000


def _serialize(dtf) -> bytes:
    from opentimestamps.core.serialize import BytesSerializationContext
    ctx = BytesSerializationContext()
    dtf.serialize(ctx)
    return ctx.getbytes()


NONCE = b"\x00"   # a fixed synthetic calendar-style nonce (deterministic, byte-for-byte reproducible)


def build() -> None:
    from opentimestamps.core.notary import BitcoinBlockHeaderAttestation
    from opentimestamps.core.op import OpAppend, OpSHA256
    from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp

    digest = hashlib.sha256(TARGET_BYTES).digest()
    ts = Timestamp(digest)
    # Null-Op hardening (2026-07-17): a REAL op chain below the file digest — append a nonce, then double
    # SHA-256 (Bitcoin merkle style) — so the Bitcoin-attested "merkle root" DIFFERS from the file digest
    # (leaf != root), all SHA-256, no ripemd160 anywhere. A leaf==root Null-Op branch would now be refused
    # by the verifier (status: null_op).
    leaf = ts.ops.add(OpAppend(NONCE)).ops.add(OpSHA256()).ops.add(OpSHA256())
    block_merkle_root = leaf.msg
    leaf.attestations.add(BitcoinBlockHeaderAttestation(HEIGHT))
    proof = _serialize(DetachedTimestampFile(OpSHA256(), ts))

    FIXTURE_DIR.mkdir(parents=True, exist_ok=True)
    (FIXTURE_DIR / f"{STEM}.txt").write_bytes(TARGET_BYTES)
    (FIXTURE_DIR / f"{STEM}.txt.ots").write_bytes(proof)
    block = {
        "height": HEIGHT,
        "merkle_root_internal_le_hex": block_merkle_root.hex(),
        "synthetic": True,
        "note": ("SYNTHETIC relying-party trust header — NOT a real Bitcoin block. The value is the "
                 "attestation's committed message at the END of a real SHA-256 op chain below the file "
                 "digest (append a nonce, then double SHA-256), which the confirmed-path test supplies as "
                 "rp_trust.bitcoin_block_headers to reach status=confirmed offline."),
    }
    (FIXTURE_DIR / f"{STEM}.block.json").write_text(
        json.dumps(block, indent=2) + "\n", encoding="utf-8")

    for name in (f"{STEM}.txt", f"{STEM}.txt.ots", f"{STEM}.block.json"):
        p = FIXTURE_DIR / name
        print(f"{name}: sha256={hashlib.sha256(p.read_bytes()).hexdigest()}")


if __name__ == "__main__":
    build()
