#!/usr/bin/env python3
"""WP-G §6 — SHA-256 manifest of the readiness pack + a proofbundle self-receipt (dogfood, advisory).

The pack claims "every result is recomputable to a cryptographic root". This script makes that literal
FOR THE PACK ITSELF: it writes a SHA-256 manifest of every pack file, and it dogfoods proofbundle to
emit a verifiable proofbundle/v0.1 receipt over that manifest. The reviewer can recompute both.

Honest scope (No-Fake): the self-receipt is ADVISORY. It is signed with an EPHEMERAL key generated at
build time (anyone can make one), so it proves the pack CAN be receipted and that the receipt verifies
offline with `proofbundle verify` — it is NOT an attestation of authorship by a pinned identity. The
public key is written alongside so the receipt is self-verifying without insider knowledge.

CLI:
  python scripts/readiness_pack_manifest.py [--generate] [--check] [--json]

Default (no flag) is --generate. --check recomputes the manifest and verifies the self-receipt, exiting
non-zero on any drift.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "src"))
PACK = REPO / "docs" / "readiness_pack"
MANIFEST = PACK / "MANIFEST.sha256"
RECEIPT_DIR = PACK / "proofbundle"
RECEIPT = RECEIPT_DIR / "readiness_pack.bundle.json"
PUBKEY = RECEIPT_DIR / "readiness_pack.pub.b64"

# Files that are OUTPUTS of this script are excluded from the manifest to avoid a self-reference loop.
_EXCLUDE = {MANIFEST.name}


def _pack_files() -> list[Path]:
    files = []
    for p in sorted(PACK.rglob("*")):
        if not p.is_file():
            continue
        rel = p.relative_to(PACK)
        if rel.parts and rel.parts[0] == RECEIPT_DIR.name:
            continue  # the proofbundle receipt subdir is not manifested (it commits to the manifest, not vice versa)
        if p.name in _EXCLUDE:
            continue
        files.append(p)
    return files


def compute_manifest() -> str:
    lines = []
    for p in _pack_files():
        digest = hashlib.sha256(p.read_bytes()).hexdigest()
        lines.append(f"{digest}  {p.relative_to(PACK).as_posix()}")
    return "\n".join(lines) + "\n"


def generate() -> dict:
    manifest_text = compute_manifest()
    MANIFEST.write_text(manifest_text, encoding="utf-8")

    # Dogfood: a proofbundle/v0.1 self-receipt over the manifest bytes (advisory, ephemeral key).
    from proofbundle.emit import emit_bundle, generate_signer, _raw_pub  # noqa: PLC0415
    signer = generate_signer()
    payload = manifest_text.encode("utf-8")
    bundle = emit_bundle(payload, signer)
    RECEIPT_DIR.mkdir(parents=True, exist_ok=True)
    RECEIPT.write_text(json.dumps(bundle, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    import base64  # noqa: PLC0415
    PUBKEY.write_text(base64.b64encode(_raw_pub(signer)).decode() + "\n", encoding="utf-8")

    return {"ok": True, "files": len(_pack_files()), "manifest": str(MANIFEST.relative_to(REPO)),
            "receipt": str(RECEIPT.relative_to(REPO)), "advisory": True,
            "note": "self-receipt is ADVISORY (ephemeral key); it proves the pack verifies offline, "
                    "not authorship by a pinned identity"}


def check() -> dict:
    problems: list[str] = []
    if not MANIFEST.is_file():
        return {"ok": False, "problems": ["MANIFEST.sha256 missing — run --generate"]}
    live = compute_manifest()
    recorded = MANIFEST.read_text(encoding="utf-8")
    if live != recorded:
        problems.append("manifest drift: a pack file changed but MANIFEST.sha256 was not regenerated")
    receipt_ok = None
    if RECEIPT.is_file():
        try:
            from proofbundle import verify_bundle  # noqa: PLC0415
            bundle = json.loads(RECEIPT.read_text(encoding="utf-8"))
            r = verify_bundle(bundle)
            receipt_ok = bool(r.get("ok")) if isinstance(r, dict) else bool(r)
            if not receipt_ok:
                problems.append("proofbundle self-receipt does not verify")
        except Exception as exc:  # noqa: BLE001
            problems.append(f"self-receipt verify errored: {type(exc).__name__}: {exc}")
    else:
        problems.append("proofbundle self-receipt missing — run --generate")
    return {"ok": not problems, "manifest_matches": live == recorded, "receipt_verifies": receipt_ok,
            "problems": problems}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("--generate", action="store_true")
    p.add_argument("--check", action="store_true")
    p.add_argument("--json", action="store_true")
    args = p.parse_args(argv)
    if args.check:
        result = check()
    else:
        result = generate()
    if args.json:
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        if args.check:
            print(f"[readiness-manifest] {'OK' if result['ok'] else 'DRIFT'} · "
                  f"manifest_matches={result.get('manifest_matches')} "
                  f"receipt_verifies={result.get('receipt_verifies')}")
            for pr in result["problems"]:
                print("  -", pr)
        else:
            print(f"[readiness-manifest] generated: {result['files']} file(s) hashed -> "
                  f"{result['manifest']}; advisory self-receipt -> {result['receipt']}")
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
