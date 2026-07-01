"""Command line interface: ``proofbundle verify <bundle.json>``."""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .bundle import verify_bundle
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="proofbundle",
        description="Offline verifier for portable cryptographic evidence bundles.",
    )
    parser.add_argument("--version", action="version", version=f"proofbundle {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    verify = sub.add_parser("verify", help="verify an evidence bundle JSON file")
    verify.add_argument("bundle", help="path to the bundle JSON file")
    verify.add_argument("--json", action="store_true", help="machine readable output")
    verify.set_defaults(func=_cmd_verify)

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
