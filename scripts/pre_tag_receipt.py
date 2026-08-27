#!/usr/bin/env python3
"""Produce a SIGNED pre-tag audit receipt (makellose-500 Phase 3, reviewer F6). Run by the RUNNER
(CI / owner) AFTER the adversarial pre-tag audit succeeds. Signs with an ed25519 key whose PUBLIC half
is pinned in ``audit_artifacts/pre_tag_trusted_pubkeys.txt`` and whose PRIVATE half is a release
secret held OUTSIDE the agent's reach. The gate (pre_tag_audit_gate.py) verifies what this writes.

Usage:
  pre_tag_receipt.py --repo . --version 5.0.0 --audit-command "<cmd>" --audit-exit 0 \
      --audit-output-file <path> --runner-identity <id> --privkey-file <path> [--out <path>]
"""
from __future__ import annotations

import argparse
import base64
import json
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pre_tag_receipt_lib import RECEIPT_SCHEMA, canonical_bytes, sha256_text  # noqa: E402


def _tree_digest(repo: Path) -> str:
    r = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD:src/proofbundle"],
                       capture_output=True, text=True, timeout=10)
    return r.stdout.strip()


def _gate_source_digest(repo: Path) -> str:
    import hashlib
    return hashlib.sha256((repo / "scripts" / "pre_tag_audit_gate.py").read_bytes()).hexdigest()


def _version_token(v: str) -> str:
    return v.replace(".", "")


def build_and_sign(repo: Path, version: str, audit_command: str, audit_exit: int,
                   audit_output: str, runner_identity: str, produced_at: str, privkey_b64: str) -> dict:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    priv = Ed25519PrivateKey.from_private_bytes(base64.b64decode(privkey_b64))
    pub_b64 = base64.b64encode(priv.public_key().public_bytes_raw()).decode()
    receipt = {
        "schema": RECEIPT_SCHEMA,
        "version": version,
        "subject_tree_digest": _tree_digest(repo),
        "gate_source_digest": _gate_source_digest(repo),
        "audit_command": audit_command,
        "audit_exit_code": audit_exit,
        "audit_output_digest": sha256_text(audit_output),
        "runner_identity": runner_identity,
        "produced_at": produced_at,
    }
    sig = priv.sign(canonical_bytes(receipt))
    receipt["signature"] = base64.b64encode(sig).decode()
    receipt["signer_pubkey"] = pub_b64
    return receipt


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--repo", type=Path, default=Path("."))
    p.add_argument("--version", required=True)
    p.add_argument("--audit-command", required=True)
    p.add_argument("--audit-exit", type=int, required=True)
    p.add_argument("--audit-output-file", type=Path, required=True)
    p.add_argument("--runner-identity", required=True)
    p.add_argument("--produced-at", required=True, help="UTC timestamp, measured by the runner")
    p.add_argument("--privkey-file", type=Path, required=True,
                   help="base64 ed25519 private key (32 bytes) — a runner secret, never in the repo")
    p.add_argument("--out", type=Path, default=None)
    args = p.parse_args(argv)
    repo = args.repo.resolve()
    receipt = build_and_sign(
        repo, args.version, args.audit_command, args.audit_exit,
        args.audit_output_file.read_text(encoding="utf-8", errors="ignore"),
        args.runner_identity, args.produced_at,
        args.privkey_file.read_text(encoding="utf-8").strip())
    out = args.out or (repo / "audit_artifacts" / _version_token(args.version)
                       / f"pre_tag_receipt_{args.version}.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(receipt, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"wrote signed receipt -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
