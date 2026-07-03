#!/usr/bin/env python3
"""TEE-attestation bridge demo (v2.0 preview) — fully offline, throwaway keys.

Shows the RATS Passport flow end to end: a receipt is bound into a Verifier-signed EAT, a relying
party verifies it offline, and an attestation for a DIFFERENT receipt is rejected. In production
the Verifier appraises real Intel TDX / NVIDIA GPU evidence; here `issue_enclave_attestation`
stands in for the Verifier so the flow is runnable without hardware.

Run:  python examples/experimental_enclave.py
"""
from __future__ import annotations

import base64
import os
import sys
import warnings

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat  # noqa: E402

from proofbundle import emit_bundle, generate_signer  # noqa: E402

with warnings.catch_warnings():
    warnings.simplefilter("ignore")  # silence the one-time ExperimentalWarning for the demo
    from proofbundle.experimental.enclave import (  # noqa: E402
        enclave_binding_for, issue_enclave_attestation, verify_enclave_attestation)

PROFILE = "https://b7n0de.com/proofbundle/eat-profile/tdx-gpu/v1"


def raw(k):
    return k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def main() -> int:
    # 1. an eval receipt (the enclave produced this while running the eval)
    receipt = emit_bundle(b'{"suite": "safety-refusal", "passed": true}', generate_signer())
    binding = enclave_binding_for(receipt)
    print(f"receipt binding (goes in the TEE quote user-data): {binding}")

    # 2. a RATS Verifier appraised the raw TDX/GPU evidence out of band and signs an EAT result
    verifier = generate_signer()
    eat = issue_enclave_attestation(binding, verifier, profile=PROFILE, tier="affirming",
                                    ueid="tdx:demo-enclave", iat=1_780_000_000, exp=1_780_003_600)

    # 3. a relying party verifies the EAT offline against the Verifier key + the receipt binding
    ok = verify_enclave_attestation(eat, verifier_pubkey=raw(verifier),
                                    expected_binding=binding, expected_profile=PROFILE,
                                    now=1_780_000_060)
    print(f"[{'PASS' if ok['ok'] else 'FAIL'}] enclave attestation: tier={ok['tier']} fresh={ok['fresh']}")

    # 4. an attestation for a DIFFERENT receipt must be rejected
    other = emit_bundle(b'{"forged": true}', generate_signer())
    bad = verify_enclave_attestation(eat, verifier_pubkey=raw(verifier),
                                     expected_binding=enclave_binding_for(other))
    print(f"[{'PASS' if not bad['ok'] else 'FAIL'}] attestation for another receipt is rejected")

    good = ok["ok"] and not bad["ok"]
    print("\n=> OK" if good else "\n=> FAILED")
    return 0 if good else 1


if __name__ == "__main__":
    raise SystemExit(main())
