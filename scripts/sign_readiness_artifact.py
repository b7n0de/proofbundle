#!/usr/bin/env python3
"""Produce a SIGNED, CANDIDATE-BOUND release-evidence artifact — the producer half of the admission
path in ``scripts/audit_candidate_matrix.py`` (deep gate 2026-09-05, finding L5-G7-02, class A).

WHY THIS SCRIPT EXISTS. The gate now refuses evidence that is unsigned, version-free or unbound to
the release candidate. A refusal mechanism without a way to PRODUCE admissible evidence would be a
gate nobody can ever pass — a mechanism without a caller. This is the caller.

WHAT IT ADDS to a raw measurement artifact (e.g. what ``fuzz_soak.py`` writes):

    version        the release under test, read from pyproject.toml unless given
    candidate      commit + tree_digest + sdist_sha256 + wheel_sha256 — the exact candidate
    producer       tool + tool_version — WHO measured
    input_digest   the corpus/input the measurement consumed
    produced_at    when, RFC-3339 UTC, measured by the runner
    signer_role    the role the signing key speaks for
    signature      ed25519 over the RFC-8785 canonical bytes of everything above

``tree_digest`` is the same quantity a pre-tag receipt binds: sha256 over the sorted
``git ls-tree HEAD`` lines EXCLUDING ``audit_artifacts/`` — so signed evidence can live inside that
directory without binding itself.

THREE MODES, the same signed body in all three (mirrors scripts/pre_tag_receipt.py, and for the same
reason: the release private key lives on the owner's machine, never on the build host).

  inline    --privkey-file: build the body, sign here, write the artifact.
  emit      --emit-payload P --context-out C: write the canonical bytes to P and the body to C.
            NO private key is read. The key holder signs P; the build host assembles.
  assemble  --assemble --context-in C --sig-file S --signer-pubkey B --out A: wrap body + signature.
            Self-checks the signature and REFUSES on a mismatch, so a bad pair never reaches disk.

Usage (inline):
  sign_readiness_artifact.py --in audit_artifacts/600/fuzz_soak_latest.json \\
      --out audit_artifacts/600/fuzz_soak_latest.json \\
      --producer-tool scripts/fuzz_soak.py --producer-tool-version 6.0.0 \\
      --input-digest <sha256 of the corpus> --signer-role release-runner \\
      --sdist dist/proofbundle-6.0.0.tar.gz --wheel dist/proofbundle-6.0.0-py3-none-any.whl \\
      --privkey-file /secrets/readiness_ed25519.b64
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
if str(REPO / "src") not in sys.path:
    sys.path.insert(0, str(REPO / "src"))

#: The unsigned wrapper. Everything else in the artifact is inside the signed body.
SIGNATURE_KEY = "signature"


def pyproject_version(repo: Path) -> str | None:
    try:
        roh = (repo / "pyproject.toml").read_text(encoding="utf-8")
    except OSError:
        return None
    m = re.search(r'(?m)^\s*version\s*=\s*["\']([^"\']+)["\']', roh)
    return m.group(1) if m else None


def head_commit(repo: Path) -> str:
    r = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"],
                       capture_output=True, text=True, timeout=10)
    if r.returncode != 0:
        raise SystemExit(f"cannot read HEAD in {repo}: {r.stderr.strip()}")
    return r.stdout.strip()


def tree_digest(repo: Path) -> str:
    """The quantity the gate recomputes: sha256 over sorted `git ls-tree HEAD`, minus audit_artifacts."""
    r = subprocess.run(["git", "-C", str(repo), "ls-tree", "HEAD"],
                       capture_output=True, text=True, timeout=10)
    if r.returncode != 0:
        raise SystemExit(f"cannot read the tree in {repo}: {r.stderr.strip()}")
    zeilen = [ln for ln in r.stdout.splitlines() if not ln.endswith("\taudit_artifacts")]
    return hashlib.sha256("\n".join(sorted(zeilen)).encode("utf-8")).hexdigest()


def file_sha256(p: Path) -> str:
    return hashlib.sha256(Path(p).read_bytes()).hexdigest()


def canonical_bytes(body: dict) -> bytes:
    """The exact bytes signed and verified: RFC-8785 over the body WITHOUT the signature wrapper.

    Everything else is inside — so a field the gate reads is a field the signature covers. That is
    the structural half of property P-A7 ("every line derives its statement from the SIGNED fields");
    an artifact cannot smuggle an unsigned field past the gate, because there is no room for one.
    """
    from proofbundle import canonical  # noqa: PLC0415
    return canonical.canonicalize_statement({k: v for k, v in body.items() if k != SIGNATURE_KEY})


def build_body(measurement: dict, *, repo: Path, version: str, producer_tool: str,
               producer_tool_version: str, input_digest: str, signer_role: str,
               sdist_sha256: str, wheel_sha256: str, produced_at: str) -> dict:
    """The signed body: the measurement plus its provenance and its candidate binding."""
    body = {k: v for k, v in measurement.items() if k != SIGNATURE_KEY}
    body["version"] = version
    body["candidate"] = {
        "commit": head_commit(repo),
        "tree_digest": tree_digest(repo),
        "sdist_sha256": sdist_sha256,
        "wheel_sha256": wheel_sha256,
    }
    body["producer"] = {"tool": producer_tool, "tool_version": producer_tool_version}
    body["input_digest"] = input_digest
    body["signer_role"] = signer_role
    body["produced_at"] = produced_at
    return body


def sign_body(body: dict, privkey_b64: str) -> dict:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: PLC0415
    priv = Ed25519PrivateKey.from_private_bytes(base64.b64decode(privkey_b64))
    pub_b64 = base64.b64encode(priv.public_key().public_bytes_raw()).decode()
    out = dict(body)
    out[SIGNATURE_KEY] = {"alg": "ed25519", "public_key_b64": pub_b64,
                          "sig_b64": base64.b64encode(priv.sign(canonical_bytes(body))).decode()}
    return out


def assemble(body: dict, sig_b64: str, signer_pubkey_b64: str) -> dict:
    """Wrap an externally produced signature. REFUSES on a mismatch — fail-closed, so a bad
    signature/body pair never becomes an artifact on disk."""
    from cryptography.exceptions import InvalidSignature  # noqa: PLC0415
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey  # noqa: PLC0415
    pub = Ed25519PublicKey.from_public_bytes(base64.b64decode(signer_pubkey_b64))
    try:
        pub.verify(base64.b64decode(sig_b64), canonical_bytes(body))
    except InvalidSignature:
        raise SystemExit("assemble: the signature does not verify over the canonical body — refusing")
    out = dict(body)
    out[SIGNATURE_KEY] = {"alg": "ed25519", "public_key_b64": signer_pubkey_b64, "sig_b64": sig_b64}
    return out


#: Flaggen, deren Ablage anders heisst als die Flagge (``--in`` ist in Python kein Name).
_ABLAGE = {"in": "quelle"}


def _need(args, namen: list[str], modus: str) -> None:
    """Fehlende Pflichtflaggen NENNEN, statt spaeter an einem AttributeError zu sterben.

    GEMESSEN 2026-09-05 vom Erzeuger-gegen-Verbraucher-Test: hier stand
    ``getattr(args, n.replace("-", "_"))``, und fuer ``--in`` (Ablage ``quelle``) gibt es kein
    Attribut ``in`` — das Werkzeug brach mit einem Stacktrace ab, statt zu sagen, was fehlt. Ein
    Erzeuger, den nur sein Autor bedienen kann, ist so gut wie keiner.
    """
    fehlt = [n for n in namen
             if getattr(args, _ABLAGE.get(n, n.replace("-", "_")), None) is None]
    if fehlt:
        raise SystemExit(f"{modus} mode needs: {', '.join('--' + m for m in fehlt)}")


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--repo", type=Path, default=REPO)
    p.add_argument("--in", dest="quelle", type=Path, default=None,
                   help="the raw measurement artifact to bind and sign")
    p.add_argument("--out", type=Path, default=None)
    p.add_argument("--version", default=None, help="default: the version in pyproject.toml")
    p.add_argument("--producer-tool", default=None)
    p.add_argument("--producer-tool-version", default=None)
    p.add_argument("--input-digest", default=None, help="sha256 (hex) of the corpus/input consumed")
    p.add_argument("--signer-role", default=None, help="e.g. release-runner")
    p.add_argument("--sdist", type=Path, default=None, help="the candidate sdist (digested here)")
    p.add_argument("--wheel", type=Path, default=None, help="the candidate wheel (digested here)")
    p.add_argument("--sdist-sha256", default=None, help="instead of --sdist, when only the digest is at hand")
    p.add_argument("--wheel-sha256", default=None)
    p.add_argument("--produced-at", default=None, help="RFC-3339 UTC; default: now, measured here")
    p.add_argument("--privkey-file", type=Path, default=None,
                   help="base64 ed25519 private key (32 raw bytes) — a runner secret, never in the repo")
    p.add_argument("--emit-payload", type=Path, default=None,
                   help="keyless: write the canonical bytes here (needs --context-out)")
    p.add_argument("--context-out", type=Path, default=None)
    p.add_argument("--assemble", action="store_true")
    p.add_argument("--context-in", type=Path, default=None)
    p.add_argument("--sig-file", type=Path, default=None)
    p.add_argument("--signer-pubkey", default=None)
    args = p.parse_args(argv)
    repo = args.repo.resolve()

    if args.assemble:
        _need(args, ["context-in", "sig-file", "signer-pubkey", "out"], "assemble")
        body = json.loads(args.context_in.read_text(encoding="utf-8"))
        artefakt = assemble(body, args.sig_file.read_text(encoding="utf-8").strip(),
                            args.signer_pubkey.strip())
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(artefakt, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
        print(f"assembled signed evidence -> {args.out}")
        return 0

    _need(args, ["in", "producer-tool", "producer-tool-version", "input-digest", "signer-role"],
          "emit/inline")
    version = args.version or pyproject_version(repo)
    if not version:
        raise SystemExit("cannot read the release version from pyproject.toml — pass --version")
    sdist = args.sdist_sha256 or (file_sha256(args.sdist) if args.sdist else None)
    wheel = args.wheel_sha256 or (file_sha256(args.wheel) if args.wheel else None)
    if not sdist or not wheel:
        raise SystemExit("the candidate binding needs both distributions: pass --sdist/--wheel "
                         "(or --sdist-sha256/--wheel-sha256)")
    produced_at = args.produced_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    body = build_body(json.loads(args.quelle.read_text(encoding="utf-8")), repo=repo, version=version,
                      producer_tool=args.producer_tool,
                      producer_tool_version=args.producer_tool_version,
                      input_digest=args.input_digest, signer_role=args.signer_role,
                      sdist_sha256=sdist, wheel_sha256=wheel, produced_at=produced_at)

    if args.emit_payload is not None:
        _need(args, ["context-out"], "emit")
        args.emit_payload.parent.mkdir(parents=True, exist_ok=True)
        args.emit_payload.write_bytes(canonical_bytes(body))
        args.context_out.parent.mkdir(parents=True, exist_ok=True)
        args.context_out.write_text(json.dumps(body, indent=2, ensure_ascii=False) + "\n",
                                    encoding="utf-8")
        print(f"emitted payload -> {args.emit_payload}  body -> {args.context_out}")
        return 0

    _need(args, ["privkey-file"], "inline")
    artefakt = sign_body(body, args.privkey_file.read_text(encoding="utf-8").strip())
    out = args.out or args.quelle
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(artefakt, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"wrote signed, candidate-bound evidence -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
