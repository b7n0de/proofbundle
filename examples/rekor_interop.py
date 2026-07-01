#!/usr/bin/env python3
"""Verify a real Sigstore Rekor inclusion proof with proofbundle's Merkle logic — offline.

Rekor (the Sigstore transparency log) is an RFC 6962 log, exactly the primitive
proofbundle checks. So the same `verify_inclusion` that checks a proofbundle bundle
also checks a real proof fetched from the world's largest public transparency log.
This turns "RFC-conformant in theory" into "verifies a real proof from the world".

The committed fixture tests/fixtures/rekor_inclusion_25579.json was fetched from
    https://rekor.sigstore.dev/api/v1/log/entries?logIndex=25579
(public log data). No network access is needed to run this — everything is offline.

Field mapping, Rekor v1 `inclusionProof` → proofbundle `merkle`:

    Rekor bundle field        proofbundle merkle field    note
    ----------------------    ------------------------    ------------------------------
    body (base64 entry)       (the leaf DATA)             leaf = the canonical entry bytes
    inclusionProof.logIndex   leaf_index                  0-based leaf position
    inclusionProof.treeSize   tree_size                   tree size at proof time
    inclusionProof.hashes[]   inclusion_proof_b64         sibling hashes, leaf→root (hex vs base64)
    inclusionProof.rootHash   root_b64                    the tree head root (hex vs base64)
    inclusionProof.checkpoint (out of band trust anchor)  C2SP signed-note / tlog-checkpoint

The checkpoint is a C2SP signed-note (https://github.com/C2SP/C2SP/blob/main/tlog-checkpoint.md):
    <origin>\n<tree_size>\n<base64(root_hash)>\n\n— <key-name> <base64(keyhash||signature)>
Its body line 3 is base64(rootHash); a relying party checks the note signature out of band
to trust the root, then proofbundle proves inclusion under that root. proofbundle deliberately
does not fetch or verify the note signature (no network, keeps the trusted core tiny).
"""
from __future__ import annotations

import base64
import json
from pathlib import Path

from proofbundle import merkle

FIXTURE = Path(__file__).resolve().parent.parent / "tests" / "fixtures" / "rekor_inclusion_25579.json"


def verify_rekor_fixture(path: Path = FIXTURE) -> bool:
    f = json.loads(path.read_text(encoding="utf-8"))
    leaf_data = base64.b64decode(f["body_b64"])        # the Merkle leaf = canonical entry bytes
    proof = [bytes.fromhex(h) for h in f["hashes"]]    # Rekor hashes are hex, leaf→root
    root = bytes.fromhex(f["rootHash"])
    return merkle.verify_inclusion(leaf_data, f["logIndex"], f["treeSize"], proof, root)


def main() -> int:
    ok = verify_rekor_fixture()
    f = json.loads(FIXTURE.read_text(encoding="utf-8"))
    print(f"Rekor entry logIndex={f['logIndex']} in a tree of {f['treeSize']} entries")
    print(f"  root {f['rootHash']}")
    print(f"  [{'PASS' if ok else 'FAIL'}] merkle-inclusion: proofbundle verified a real "
          f"Sigstore Rekor proof, fully offline")
    print("=> OK" if ok else "=> FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
