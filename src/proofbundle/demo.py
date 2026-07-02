"""Self-contained offline demo (v1.6.1) — `proofbundle demo`.

Zero files, zero network, zero optional extras beyond the core `cryptography` dependency: this
runs the whole trust story in memory so a reviewer with nothing but `pip install proofbundle` can
see, in five seconds, (1) a receipt verify OK, (2) six independent tampers each verify FAILED,
and (3) the per-sample audit protocol catch a swapped sample. It exits non-zero iff any tamper
*verifies* — i.e. the demo doubles as a smoke test of the fail-closed guarantees.

Nothing here is imported by the library core; it exists purely for the CLI `demo` command.
"""

from __future__ import annotations

import base64
import copy
import json
from typing import Callable, List, Tuple

from .bundle import verify_bundle
from .emit import emit_bundle, generate_signer
from .errors import ProofBundleError


def _raw_pub(signer) -> bytes:
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # noqa: PLC0415
    return signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _honest_receipt() -> Tuple[dict, object]:
    """Emit a signed eval receipt in memory (a real Ed25519 key + RFC 6962 anchor)."""
    from .evalclaim import build_eval_claim, emit_eval_receipt  # noqa: PLC0415
    signer = generate_signer()
    claim, _salts = build_eval_claim(
        suite="demo-safety-suite", suite_version="1.0", metric="accuracy",
        comparator=">=", threshold="0.80", score="0.91", n=250,
        model_id="demo-model-v3", dataset_id="demo-benchmark",
        issuer="", timestamp="2026-07-02T12:00:00Z", prereg_sha256="a" * 64)
    return emit_eval_receipt(claim, signer), signer


def _tampers() -> List[Tuple[str, Callable[[dict], dict]]]:
    """Six independent, orthogonal tampers — each mutates ONE dimension and must FAIL."""

    def t_payload(b: dict) -> dict:
        b = copy.deepcopy(b)
        b["payload_b64"] = _b64(b'{"passed": false, "forged": true}')   # rewrite the claim bytes
        return b

    def t_signature(b: dict) -> dict:
        b = copy.deepcopy(b)
        other = emit_bundle(b'{"unrelated": 1}', generate_signer())      # graft a foreign signature
        b["signature"] = other["signature"]
        return b

    def t_public_key(b: dict) -> dict:
        b = copy.deepcopy(b)
        b["signature"]["public_key_b64"] = _b64(_raw_pub(generate_signer()))  # attacker key
        return b

    def t_root(b: dict) -> dict:
        b = copy.deepcopy(b)
        import hashlib  # noqa: PLC0415
        b["merkle"]["root_b64"] = _b64(hashlib.sha256(b"wrong-root").digest())
        return b

    def t_leaf_index(b: dict) -> dict:
        b = copy.deepcopy(b)
        b["merkle"]["leaf_index"] = b["merkle"]["leaf_index"] + 1        # claim a different slot
        return b

    def t_drop_hash_alg(b: dict) -> dict:
        b = copy.deepcopy(b)
        b["merkle"].pop("hash_alg", None)                               # non-canonical: must reject
        return b

    return [
        ("payload rewrite (passed:true→false)", t_payload),
        ("signature graft from another key", t_signature),
        ("public-key swap to attacker key", t_public_key),
        ("Merkle root replacement", t_root),
        ("leaf-index shift", t_leaf_index),
        ("drop merkle.hash_alg (non-canonical)", t_drop_hash_alg),
    ]


def _verifies(bundle: dict) -> bool:
    """True iff the bundle verifies OK. A malformed bundle (raises) is NOT a pass."""
    try:
        return verify_bundle(bundle).ok
    except ProofBundleError:
        return False


def _run_persample() -> Tuple[bool, str]:
    """Build a 6-sample tree, open one sample honestly (OK), then swap it (FAIL)."""
    from .persample import (audit_challenge, build_sample_tree, sample_opening,  # noqa: PLC0415
                            verify_sample_opening)
    import os  # noqa: PLC0415
    records = [{"id": i, "epoch": 1, "success": i % 2 == 0, "score": str(i % 2)} for i in range(6)]
    tree = build_sample_tree(records, os.urandom(32))
    idx = audit_challenge(tree["root_b64"], tree["n"], 1, nonce=b"demo-nonce-16byte")[0]
    honest = verify_sample_opening(sample_opening(tree["disclosures"], idx),
                                   tree["root_b64"], tree["n"])
    # swap: present a DIFFERENT sample's disclosure under the challenged index
    other = (idx + 1) % tree["n"]
    swapped = sample_opening(tree["disclosures"], idx)
    swapped["disclosure"] = tree["disclosures"][other]
    swap_res = verify_sample_opening(swapped, tree["root_b64"], tree["n"])
    ok = honest["ok"] and not swap_res["ok"]
    return ok, (f"challenged index {idx}: honest opening OK={honest['ok']}, "
                f"swapped-sample opening OK={swap_res['ok']} (must be False)")


def run_demo(as_json: bool = False) -> int:
    """Run the full offline demo. Returns 0 iff every guarantee held."""
    receipt, _signer = _honest_receipt()
    honest_ok = _verifies(receipt)

    tamper_rows = []
    all_tampers_failed = True
    for name, mutate in _tampers():
        verified = _verifies(mutate(receipt))
        caught = not verified            # a good tamper must NOT verify
        all_tampers_failed = all_tampers_failed and caught
        tamper_rows.append((name, caught))

    persample_ok, persample_detail = _run_persample()
    overall = honest_ok and all_tampers_failed and persample_ok

    if as_json:
        print(json.dumps({
            "honest_receipt_ok": honest_ok,
            "tampers": [{"name": n, "caught": c} for n, c in tamper_rows],
            "persample_audit_ok": persample_ok,
            "overall_ok": overall}, indent=2))
        return 0 if overall else 1

    print("proofbundle offline demo — in memory, no files, no network\n")
    print(f"[{'PASS' if honest_ok else 'FAIL'}] honest receipt verifies  => {'OK' if honest_ok else 'FAILED'}")
    print("\ntamper matrix (each must be caught → verify FAILED):")
    for name, caught in tamper_rows:
        print(f"  [{'caught' if caught else '*** MISSED ***'}] {name}")
    print(f"\n[{'PASS' if persample_ok else 'FAIL'}] per-sample audit: {persample_detail}")
    print("\n=> OK — every guarantee held" if overall
          else "\n=> FAILED — a guarantee did not hold")
    return 0 if overall else 1
