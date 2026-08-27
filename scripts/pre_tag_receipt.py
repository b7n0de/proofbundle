#!/usr/bin/env python3
"""Produce a SIGNED pre-tag audit receipt (makellose-500 Phase 3, reviewer F6). Run by the RUNNER
(CI / owner) AFTER the adversarial pre-tag audit succeeds. Signs with an ed25519 key whose PUBLIC half
is pinned in ``audit_artifacts/pre_tag_trusted_pubkeys.txt`` and whose PRIVATE half is a release
secret held OUTSIDE the agent's reach. The gate (pre_tag_audit_gate.py) verifies what this writes.

THREE modes. The signed 9-field CONTEXT is identical in all three; only WHERE the signature comes from
differs. The security-deciding core (``canonical_bytes`` / ``verify_receipt`` in pre_tag_receipt_lib.py)
is byte-identical and untouched by this file:

  inline   (default, --privkey-file): build the context, sign it here, write the receipt. The runner
           holds the key. Unchanged from before the keyless modes existed.
  emit     (--emit-payload P --context-out C): write ``canonical_bytes(context)`` to P and the context
           JSON to C. NO private key is read. This is the Farmer half of the two-half keyless handshake:
           the Farmer emits, the key-holder (Mac) signs P, the Farmer assembles. The private key never
           reaches the Farmer.
  assemble (--assemble --context-in C --sig-file S --signer-pubkey B --out R): wrap the context C + the
           base64 signature in S (over ``canonical_bytes(C)``) + the pubkey B into a receipt R.
           Self-checks the signature under B and REFUSES on a mismatch (fail-closed: a bad sig/context
           pair never becomes a receipt on disk).

Usage (inline, unchanged):
  pre_tag_receipt.py --repo . --version 5.0.0 --audit-command "<cmd>" --audit-exit 0 \
      --audit-output-file <path> --runner-identity <id> --produced-at <iso> --privkey-file <path> [--out <path>]
"""
from __future__ import annotations

import argparse
import base64
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from pre_tag_receipt_lib import RECEIPT_SCHEMA, canonical_bytes, sha256_text, subject_tree_digest  # noqa: E402


def _tree_digest(repo: Path) -> str:
    return subject_tree_digest(repo)


def _gate_source_digest(repo: Path) -> str:
    import hashlib
    return hashlib.sha256((repo / "scripts" / "pre_tag_audit_gate.py").read_bytes()).hexdigest()


def _version_token(v: str) -> str:
    return v.replace(".", "")


def build_context(repo: Path, version: str, audit_command: str, audit_exit: int,
                  audit_output: str, runner_identity: str, produced_at: str) -> dict:
    """The 9 SIGNED fields — identical across inline / emit / assemble. Exactly what canonical_bytes covers."""
    return {
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


def build_and_sign(repo: Path, version: str, audit_command: str, audit_exit: int,
                   audit_output: str, runner_identity: str, produced_at: str, privkey_b64: str) -> dict:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    priv = Ed25519PrivateKey.from_private_bytes(base64.b64decode(privkey_b64))
    pub_b64 = base64.b64encode(priv.public_key().public_bytes_raw()).decode()
    receipt = build_context(repo, version, audit_command, audit_exit, audit_output, runner_identity, produced_at)
    sig = priv.sign(canonical_bytes(receipt))
    receipt["signature"] = base64.b64encode(sig).decode()
    receipt["signer_pubkey"] = pub_b64
    return receipt


def assemble_receipt(context: dict, sig_b64: str, signer_pubkey_b64: str) -> dict:
    """Two-half keyless: wrap a context (the 9 signed fields) + an externally produced signature over
    ``canonical_bytes(context)`` into a receipt. Self-checks the signature under signer_pubkey — a mismatch
    REFUSES (fail-closed), so a bad sig/context pair never becomes a receipt on disk. The bytes signed here
    are byte-identical to what verify_receipt reconstructs, so the assembled receipt verifies at the gate."""
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(signer_pubkey_b64))
    try:
        pub.verify(base64.b64decode(sig_b64), canonical_bytes(context))
    except InvalidSignature:
        raise SystemExit("assemble: signature does not verify over canonical_bytes(context) — refusing (fail-closed)")
    receipt = dict(context)
    receipt["signature"] = sig_b64
    receipt["signer_pubkey"] = signer_pubkey_b64
    return receipt


def _need(args, names: list[str], mode: str) -> None:
    missing = [n for n in names if getattr(args, n.replace("-", "_")) is None]
    if missing:
        raise SystemExit(f"{mode} mode needs: {', '.join('--' + m for m in missing)}")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--repo", type=Path, default=Path("."))
    # context (inline + emit)
    p.add_argument("--version", default=None)
    p.add_argument("--audit-command", default=None)
    p.add_argument("--audit-exit", type=int, default=None)
    p.add_argument("--audit-output-file", type=Path, default=None)
    p.add_argument("--runner-identity", default=None)
    p.add_argument("--produced-at", default=None, help="UTC timestamp, measured by the runner")
    p.add_argument("--privkey-file", type=Path, default=None,
                   help="base64 ed25519 private key (32 bytes) — a runner secret, never in the repo (inline mode)")
    p.add_argument("--out", type=Path, default=None)
    # keyless emit
    p.add_argument("--emit-payload", type=Path, default=None,
                   help="keyless: write canonical_bytes(context) here (no privkey); needs --context-out")
    p.add_argument("--context-out", type=Path, default=None)
    # keyless assemble
    p.add_argument("--assemble", action="store_true",
                   help="keyless: build a receipt from --context-in + --sig-file + --signer-pubkey")
    p.add_argument("--context-in", type=Path, default=None)
    p.add_argument("--sig-file", type=Path, default=None)
    p.add_argument("--signer-pubkey", default=None)
    args = p.parse_args(argv)
    repo = args.repo.resolve()

    # ── assemble mode (keyless second half) ──────────────────────────────────────────────────────
    if args.assemble:
        _need(args, ["context-in", "sig-file", "signer-pubkey", "out"], "assemble")
        context = json.loads(args.context_in.read_text(encoding="utf-8"))
        sig_b64 = args.sig_file.read_text(encoding="utf-8").strip()
        receipt = assemble_receipt(context, sig_b64, args.signer_pubkey.strip())
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(receipt, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"assembled receipt -> {args.out}")
        return 0

    # context is needed for both emit and inline
    _need(args, ["version", "audit-command", "audit-exit", "audit-output-file", "runner-identity", "produced-at"],
          "emit/inline")
    audit_output = args.audit_output_file.read_text(encoding="utf-8", errors="ignore")

    # ── emit mode (keyless first half) ───────────────────────────────────────────────────────────
    if args.emit_payload is not None:
        _need(args, ["context-out"], "emit")
        context = build_context(repo, args.version, args.audit_command, args.audit_exit,
                                audit_output, args.runner_identity, args.produced_at)
        args.emit_payload.parent.mkdir(parents=True, exist_ok=True)
        args.emit_payload.write_bytes(canonical_bytes(context))
        args.context_out.parent.mkdir(parents=True, exist_ok=True)
        args.context_out.write_text(json.dumps(context, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"emitted payload -> {args.emit_payload}  context -> {args.context_out}")
        return 0

    # ── inline mode (default, unchanged) ─────────────────────────────────────────────────────────
    _need(args, ["privkey-file"], "inline")
    receipt = build_and_sign(
        repo, args.version, args.audit_command, args.audit_exit,
        audit_output, args.runner_identity, args.produced_at,
        args.privkey_file.read_text(encoding="utf-8").strip())
    out = args.out or (repo / "audit_artifacts" / _version_token(args.version)
                       / f"pre_tag_receipt_{args.version}.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(receipt, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"wrote signed receipt -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
