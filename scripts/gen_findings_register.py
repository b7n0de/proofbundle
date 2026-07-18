#!/usr/bin/env python3
"""Ceremony: build + ed25519-SIGN the structured findings register (RT-10 / PB-2026-0718-14).

The register is the SINGLE STRUCTURED SOURCE for "how many open P0/P1" — replacing the old lexical
"0 open P0/P1" substring scan of a stale .md that granted a FALSE PASS (audit_candidate_matrix C12.2)
while current open P0/P1 existed. It carries, per finding, STRUCTURED fields (id, severity, status,
superseded_by) plus an ed25519 signature over the canonical (RFC-8785 / JCS) bytes of the register
WITHOUT its signature block. The private key is loaded from ``PB_FINDINGS_REGISTER_KEY_B64`` (env) or the
gitignored ``audit_artifacts/.findings_register_key.ed25519`` (0600); ONLY the committed signed register +
the pinned public key travel in git — a self-attested receipt (tamper-evident + independently verifiable,
NOT an external attester; whoever holds the key can sign, exactly like un_review_signer / ProofbundleSigner).

Usage:
  python scripts/gen_findings_register.py            # sign with the existing/new key, write the register
  python scripts/gen_findings_register.py --print-pubkey   # print the pinned public key (for the gate)
"""
from __future__ import annotations

import argparse
import base64
import json
import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))

from proofbundle import canonical  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

REGISTER_REL = "audit_artifacts/findings_register_361.json"
KEY_REL = "audit_artifacts/.findings_register_key.ed25519"

# The HONEST current status of every Teil-2..Teil-5 finding on branch fix/subject-pin-361-P0, verified by
# the conformance/relation/packaging/budget test suites + the direct RT-09 acceptance probes. "closed" means
# the fix is implemented AND verified here; open would list the still-broken ones (No-Fake: a P0/P1 shown
# closed while actually open is exactly the false-pass this register exists to prevent).
VERSION = "3.6.1"
FINDINGS = [
    {"id": "PB-2026-0718-01", "severity": "P0", "status": "closed",
     "note": "lineage target-subject-digest: 6 invalid states fail-closed (relation._target_subject_pin_error, 4 wire codes); conformance green"},
    {"id": "PB-2026-0718-06", "severity": "P0", "status": "closed",
     "note": "decision canonicality fail-closed (canonicality_ok = canonical_ok is True); minimal-env rfc8785-absent rejects"},
    {"id": "PB-2026-0718-02", "severity": "P1", "status": "closed",
     "note": "sdist ships tests/schemas/examples/conformance/formal; repo-context tests skip outside checkout; packaging suite green"},
    {"id": "PB-2026-0718-04", "severity": "P1", "status": "closed",
     "note": "relation same-key requires verified_under; RELATION_SIGNER_UNAUTHORIZED fail-closed; conformance green"},
    {"id": "PB-2026-0718-05", "severity": "P1", "status": "closed",
     "note": "relation conformance carries the missing-subject negative state (present-equal..absent..ambiguous)"},
    {"id": "PB-2026-0718-07", "severity": "P1", "status": "closed",
     "note": "malformed untrusted json to the verify API yields a fail-closed verdict, never a raw exception (never-raise sweep clean)"},
    {"id": "PB-2026-0718-08", "severity": "P1", "status": "closed",
     "note": "decision legacy proven-digest presence deprecated/coupled, no longer overstates assurance"},
    {"id": "PB-2026-0718-11", "severity": "P1", "status": "closed",
     "note": "cross-format singleton groups fail-closed (no vacuous pass); every xfmt id linked decision<->outcome"},
    {"id": "PB-2026-0718-14", "severity": "P1", "status": "closed",
     "note": "audit-candidate stale-zero false-pass fixed: this signed structured register + C12.2 rewrite (current-wins, evaluated_count>0, contradiction=ERROR)"},
    {"id": "PB-2026-0718-17", "severity": "P1", "status": "closed",
     "note": "RecursionError never-raise: structural depth budget enforced on the direct-dict path (RT-09), 0 raw RecursionError across public verify surfaces at recursionlimit 3000"},
    # P2 findings — tracked honestly; they do NOT gate the '0 open P0/P1' audit-candidate obligation.
    {"id": "PB-2026-0718-16", "severity": "P2", "status": "closed",
     "note": "structural budgets (depth/nodes/merkle_path) enforced on the direct-dict verify path (RT-09), per-dimension direct-dict acceptance verified"},
    {"id": "PB-2026-0718-03", "severity": "P2", "status": "open",
     "note": "published wheel/sdist not yet byte-reproducibility-attested (Sigstore bundle/Rekor); follow-up"},
    {"id": "PB-2026-0718-09", "severity": "P2", "status": "open",
     "note": "rust relation parity not yet dynamically replayable from the published artifact; follow-up"},
    {"id": "PB-2026-0718-10", "severity": "P2", "status": "open",
     "note": "formal lineage model not yet refined to the release implementation; follow-up"},
    {"id": "PB-2026-0718-12", "severity": "P2", "status": "open",
     "note": "rust verifier has zero native unit tests for boundary states; follow-up"},
    {"id": "PB-2026-0718-13", "severity": "P2", "status": "open",
     "note": "dev typecheck pq-mldsa version floor mismatch (mypy gate); follow-up"},
    {"id": "PB-2026-0718-15", "severity": "P2", "status": "closed",
     "note": "rust cargo fmt/clippy green with a pinned toolchain (tools/pb_verify_rs/rust-toolchain.toml 1.95.0); deterministic CI fmt/clippy gate wired"},
]


def _load_or_create_key() -> Ed25519PrivateKey:
    env = os.environ.get("PB_FINDINGS_REGISTER_KEY_B64")
    if env:
        return Ed25519PrivateKey.from_private_bytes(base64.b64decode(env))
    kp = REPO / KEY_REL
    if kp.is_file():
        return Ed25519PrivateKey.from_private_bytes(kp.read_bytes())
    key = Ed25519PrivateKey.generate()
    from cryptography.hazmat.primitives import serialization
    raw = key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption())
    kp.parent.mkdir(parents=True, exist_ok=True)
    kp.write_bytes(raw)
    kp.chmod(0o600)
    return key


def _pubkey_b64(key: Ed25519PrivateKey) -> str:
    from cryptography.hazmat.primitives import serialization
    raw = key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode("ascii")


def build_register(generated_at: str) -> dict:
    return {
        "schema": "proofbundle.findings_register.v1",
        "version": VERSION,
        "generated_at": generated_at,
        "findings": FINDINGS,
    }


def sign_register(register: dict, key: Ed25519PrivateKey) -> dict:
    body = {k: register[k] for k in register if k != "signature"}
    msg = canonical.canonicalize_statement(body)
    sig = key.sign(msg)
    out = dict(body)
    out["signature"] = {
        "alg": "ed25519",
        "public_key_b64": _pubkey_b64(key),
        "sig_b64": base64.b64encode(sig).decode("ascii"),
    }
    return out


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--print-pubkey", action="store_true")
    p.add_argument("--generated-at", default="2026-07-18T00:00:00Z",
                   help="frozen ISO timestamp (deterministic; Date.now is unavailable in the sandbox)")
    args = p.parse_args(argv)
    key = _load_or_create_key()
    if args.print_pubkey:
        print(_pubkey_b64(key))
        return 0
    register = sign_register(build_register(args.generated_at), key)
    out = REPO / REGISTER_REL
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(register, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote {REGISTER_REL} ({len(FINDINGS)} findings, "
          f"pubkey {register['signature']['public_key_b64']})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
