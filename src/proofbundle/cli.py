"""Command line interface: ``proofbundle verify`` and ``proofbundle emit``."""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .bundle import verify_bundle
from .emit import emit_bundle, generate_signer, load_signer, save_signer
from .errors import ProofBundleError


def _cmd_verify(args: argparse.Namespace) -> int:
    try:
        result = verify_bundle(args.bundle)
    except ProofBundleError as exc:
        if args.json:
            print(json.dumps({"ok": False, "error": str(exc)}))
        else:
            print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(json.dumps(result.as_dict(), indent=2))
    else:
        for check in result.checks:
            print(str(check))
        print("=> OK" if result.ok else "=> FAILED")
    return 0 if result.ok else 1


def _cmd_emit(args: argparse.Namespace) -> int:
    if args.new_key and args.key:
        print("ERROR: use either --key or --new-key, not both", file=sys.stderr)
        return 2
    if args.new_key:
        signer = generate_signer()
        save_signer(signer, args.new_key)
        print(f"wrote new signing key to {args.new_key} (keep this secret)", file=sys.stderr)
    elif args.key:
        signer = load_signer(args.key)
    else:
        print("ERROR: provide --key <file> or --new-key <file>", file=sys.stderr)
        return 2

    with open(args.payload_file, "rb") as handle:
        payload = handle.read()

    bundle = emit_bundle(payload, signer)
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(bundle, handle, indent=2)
        handle.write("\n")
    print(f"wrote {args.out}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="proofbundle",
        description="Emit and verify portable cryptographic evidence bundles, offline.",
    )
    parser.add_argument("--version", action="version", version=f"proofbundle {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    verify = sub.add_parser("verify", help="verify an evidence bundle JSON file")
    verify.add_argument("bundle", help="path to the bundle JSON file")
    verify.add_argument("--json", action="store_true", help="machine readable output")
    verify.set_defaults(func=_cmd_verify)

    emit = sub.add_parser("emit", help="sign and anchor a payload into a bundle")
    emit.add_argument("--payload-file", required=True, help="file whose bytes become the payload")
    emit.add_argument("--out", required=True, help="path to write the bundle JSON")
    emit.add_argument("--key", help="use an existing 32 byte raw Ed25519 seed file")
    emit.add_argument("--new-key", help="generate a signing key and save it to this file")
    emit.set_defaults(func=_cmd_emit)

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
