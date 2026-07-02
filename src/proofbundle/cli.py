"""Command line interface: ``proofbundle`` verify / emit / emit-eval / show-eval."""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from .bundle import recompute_merkle_root_b64, verify_bundle
from .emit import emit_bundle, generate_signer, load_signer, save_signer
from .errors import ProofBundleError


def _resolve_signer(args):
    """Shared signer resolution for emit / emit-eval. Returns a signer or None (with an error)."""
    if getattr(args, "new_key", None) and getattr(args, "key", None):
        print("ERROR: use either --key or --new-key, not both", file=sys.stderr)
        return None
    if getattr(args, "new_key", None):
        signer = generate_signer()
        save_signer(signer, args.new_key)
        print(f"wrote new signing key to {args.new_key} (keep this secret)", file=sys.stderr)
        return signer
    if getattr(args, "key", None):
        return load_signer(args.key)
    print("ERROR: provide --key <file> or --new-key <file>", file=sys.stderr)
    return None


def _cmd_emit_eval(args: argparse.Namespace) -> int:
    from .evalclaim import EvalClaimError, emit_eval_receipt, load_claim_text  # noqa: PLC0415
    signer = _resolve_signer(args)
    if signer is None:
        return 2
    try:
        with open(args.claim, encoding="utf-8") as handle:
            claim = load_claim_text(handle.read())
        bundle = emit_eval_receipt(claim, signer)
    except (EvalClaimError, OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(bundle, handle, indent=2)
        handle.write("\n")
    print(f"wrote eval receipt {args.out}")
    return 0


def _cmd_show_eval(args: argparse.Namespace) -> int:
    from .evalclaim import (  # noqa: PLC0415
        DEFAULT_ASSURANCE, check_freshness, claim_warnings, decode_eval_claim, sd_jwt_hidden_count,
    )
    try:
        claim = decode_eval_claim(args.receipt)
    except (OSError, ValueError, ProofBundleError) as exc:   # missing/invalid receipt file → clean exit, not a traceback
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    if claim is None:
        print("=> FAILED: not a valid, issuer-bound eval receipt", file=sys.stderr)
        return 1
    print(f"suite      {claim['suite']} ({claim['suite_version']})")
    print(f"metric     {claim['metric']} {claim['comparator']} {claim['threshold']}")
    print(f"passed     {claim['passed']}   (n={claim['n']})")
    print(f"assurance  {claim.get('assurance_level', DEFAULT_ASSURANCE)}")
    print(f"model      commit {claim['model_id_commit']}")
    print(f"dataset    commit {claim['dataset_id_commit']}")
    print(f"issuer     {claim['issuer']}")
    print(f"timestamp  {claim['timestamp']}")
    hidden = sd_jwt_hidden_count(args.receipt)
    if hidden is not None:
        print(f"sd-jwt     {hidden} field(s) withheld (selective disclosure)")
    fresh = check_freshness(claim)
    if fresh["parsed"]:
        print(f"age        {fresh['age_seconds']}s")
    for w in claim_warnings(claim):
        print(f"WARNING    {w}")
    print("=> OK")
    return 0


def _cmd_verify(args: argparse.Namespace) -> int:
    try:
        result = verify_bundle(args.bundle, expected_aud=getattr(args, "aud", None),
                               expected_nonce=getattr(args, "nonce", None))
        roots = recompute_merkle_root_b64(args.bundle) if args.verbose else None
    except (ProofBundleError, OSError, ValueError) as exc:   # file/JSON/format errors → clean exit, never a raw traceback
        if args.json:
            print(json.dumps({"ok": False, "error": str(exc)}))
        else:
            print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    if args.json:
        out = result.as_dict()
        if roots is not None:
            out["merkle_root"] = roots
        print(json.dumps(out, indent=2))
    else:
        for check in result.checks:
            print(str(check))
        if roots is not None:
            print(f"    stated root      {roots['stated_b64']}")
            recomputed = roots["recomputed_b64"]
            print(f"    recomputed root  {recomputed if recomputed is not None else '(not computable: ' + roots['detail'] + ')'}")
        print("=> OK" if result.ok else "=> FAILED")
    return 0 if result.ok else 1


def _cmd_emit(args: argparse.Namespace) -> int:
    signer = _resolve_signer(args)
    if signer is None:
        return 2

    with open(args.payload_file, "rb") as handle:
        payload = handle.read()

    bundle = emit_bundle(payload, signer)
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(bundle, handle, indent=2)
        handle.write("\n")
    print(f"wrote {args.out}")
    return 0


def _cmd_verify_proof(args: argparse.Namespace) -> int:
    from .tlogproof import verify_tlog_proof  # noqa: PLC0415
    try:
        with open(args.proof, encoding="utf-8") as handle:
            text = handle.read()
        with open(args.payload_file, "rb") as handle:
            leaf = handle.read()
        res = verify_tlog_proof(text, leaf, args.log_vkey,
                                args.witness_vkey or (), threshold=args.threshold)
    except (ProofBundleError, OSError) as exc:
        if args.json:
            print(json.dumps({"ok": False, "error": str(exc)}))
        else:
            print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    if args.json:
        out = {k: res[k] for k in ("ok", "log_ok", "witnesses_ok", "inclusion_ok",
                                   "origin", "tree_size", "index")}
        out["witnesses"] = {n: {"ok": w["ok"], "alg": w["alg"], "timestamp": w["timestamp"]}
                            for n, w in res["witnesses"].items()}
        print(json.dumps(out, indent=2))
    else:
        print(f"[{'PASS' if res['log_ok'] else 'FAIL'}] log-signature: {res['origin']}")
        n_ok = sum(1 for w in res["witnesses"].values() if w["ok"])
        print(f"[{'PASS' if res['witnesses_ok'] else 'FAIL'}] witness-quorum: "
              f"{n_ok} valid of {len(res['witnesses'])} known (threshold {args.threshold})")
        print(f"[{'PASS' if res['inclusion_ok'] else 'FAIL'}] merkle-inclusion: "
              f"index {res['index']} of {res['tree_size']}")
        print("=> OK" if res["ok"] else "=> FAILED")
    return 0 if res["ok"] else 1


def _cmd_hf_token(args: argparse.Namespace) -> int:
    from .bundle import load_bundle  # noqa: PLC0415
    from .hf_evals import receipt_token, verify_receipt_token  # noqa: PLC0415
    try:
        if args.verify:
            token = args.bundle_or_token
            if token.endswith(".txt") or "/" in token:
                with open(token, encoding="utf-8") as handle:
                    token = handle.read().strip()
            result, _bundle = verify_receipt_token(token)
            for check in result.checks:
                print(str(check))
            print("=> OK" if result.ok else "=> FAILED")
            return 0 if result.ok else 1
        token = receipt_token(load_bundle(args.bundle_or_token))
        print(token)
        return 0
    except (ProofBundleError, OSError, ValueError) as exc:   # file/JSON/format errors → clean exit
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


def _cmd_audit_challenge(args: argparse.Namespace) -> int:
    from .persample import audit_challenge  # noqa: PLC0415
    try:
        nonce = bytes.fromhex(args.nonce) if args.nonce else b""
        indices = audit_challenge(args.root, args.n, args.k, nonce)
    except (ProofBundleError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps({"indices": indices, "n": args.n, "k": args.k,
                          "mode": "auditor-nonce" if args.nonce else "self-challenge"}))
    else:
        if not args.nonce:
            print("WARNING: self-challenge mode (no --nonce) is a sanity check only — "
                  "a producer can grind by re-salting; real audits supply a fresh nonce",
                  file=sys.stderr)
        print(" ".join(str(i) for i in indices))
    return 0


def _cmd_verify_opening(args: argparse.Namespace) -> int:
    from .persample import verify_sample_opening  # noqa: PLC0415
    try:
        with open(args.opening, encoding="utf-8") as handle:
            opening = json.load(handle)
        res = verify_sample_opening(opening, args.root, args.n)
    except (ProofBundleError, OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(res))
    else:
        print(f"[{'PASS' if res['ok'] else 'FAIL'}] sample-opening: {res['detail']}")
        if res["ok"]:
            print(json.dumps(res["record"], indent=2))
        print("=> OK" if res["ok"] else "=> FAILED")
    return 0 if res["ok"] else 1


def _cmd_demo(args: argparse.Namespace) -> int:
    from .demo import run_demo  # noqa: PLC0415
    return run_demo(as_json=args.json)


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
    verify.add_argument("--verbose", action="store_true",
                        help="print the recomputed Merkle root next to the stated root")
    verify.add_argument("--aud", default=None,
                        help="expected KB-JWT audience (RFC 9901 §7.3 replay/audience binding); required to "
                             "bind a Key Binding JWT presentation to this verifier")
    verify.add_argument("--nonce", default=None,
                        help="expected KB-JWT nonce (RFC 9901 §7.3 replay binding)")
    verify.set_defaults(func=_cmd_verify)

    emit = sub.add_parser("emit", help="sign and anchor a payload into a bundle")
    emit.add_argument("--payload-file", required=True, help="file whose bytes become the payload")
    emit.add_argument("--out", required=True, help="path to write the bundle JSON")
    emit.add_argument("--key", help="use an existing 32 byte raw Ed25519 seed file")
    emit.add_argument("--new-key", help="generate a signing key and save it to this file")
    emit.set_defaults(func=_cmd_emit)

    emit_eval = sub.add_parser("emit-eval", help="emit a signed eval receipt from a claim JSON")
    emit_eval.add_argument("--claim", required=True, help="path to the eval-claim JSON")
    emit_eval.add_argument("--out", required=True, help="path to write the receipt bundle JSON")
    emit_eval.add_argument("--key", help="use an existing 32 byte raw Ed25519 seed file")
    emit_eval.add_argument("--new-key", help="generate a signing key and save it to this file")
    emit_eval.set_defaults(func=_cmd_emit_eval)

    show_eval = sub.add_parser("show-eval", help="verify an eval receipt and print the claim")
    show_eval.add_argument("receipt", help="path to the eval receipt bundle JSON")
    show_eval.set_defaults(func=_cmd_show_eval)

    verify_proof = sub.add_parser(
        "verify-proof", help="verify a C2SP .tlog-proof file offline (v1.3)")
    verify_proof.add_argument("proof", help="path to the .tlog-proof file")
    verify_proof.add_argument("--payload-file", required=True,
                              help="file with the exact logged leaf bytes (the bundle payload)")
    verify_proof.add_argument("--log-vkey", required=True,
                              help="the log's verifier key (0x01 vkey)")
    verify_proof.add_argument("--witness-vkey", action="append",
                              help="a witness verifier key (0x04 Ed25519 or 0x06 ML-DSA-44); repeatable")
    verify_proof.add_argument("--threshold", type=int, default=0,
                              help="required number of distinct valid witnesses (default 0)")
    verify_proof.add_argument("--json", action="store_true", help="machine readable output")
    verify_proof.set_defaults(func=_cmd_verify_proof)

    hf_token = sub.add_parser(
        "hf-token",
        help="pack a receipt into a pb1. token for HF eval_results, or verify one (v1.4)")
    hf_token.add_argument("bundle_or_token",
                          help="bundle JSON path (emit) or pb1. token / token file (--verify)")
    hf_token.add_argument("--verify", action="store_true",
                          help="verify a pb1. token instead of emitting one")
    hf_token.set_defaults(func=_cmd_hf_token)

    challenge = sub.add_parser(
        "audit-challenge",
        help="derive k audit indices from a samples root (v1.5; supply --nonce for real audits)")
    challenge.add_argument("root", help="the receipt's samples root (base64)")
    challenge.add_argument("n", type=int, help="committed sample count")
    challenge.add_argument("k", type=int, help="number of samples to challenge")
    challenge.add_argument("--nonce", help="fresh auditor nonce (hex, >=32 hex chars recommended)")
    challenge.add_argument("--json", action="store_true", help="machine readable output")
    challenge.set_defaults(func=_cmd_audit_challenge)

    verify_opening = sub.add_parser(
        "verify-opening", help="verify one sample opening against a samples root (v1.5)")
    verify_opening.add_argument("opening", help="opening JSON file (index/disclosure/proof_b64)")
    verify_opening.add_argument("--root", required=True, help="the receipt's samples root (base64)")
    verify_opening.add_argument("--n", required=True, type=int, help="committed sample count")
    verify_opening.add_argument("--json", action="store_true", help="machine readable output")
    verify_opening.set_defaults(func=_cmd_verify_opening)

    demo = sub.add_parser(
        "demo",
        help="run the whole trust story in memory (pip-only, offline): honest receipt verifies, "
             "six tampers fail, a swapped sample is caught")
    demo.add_argument("--json", action="store_true", help="machine readable output")
    demo.set_defaults(func=_cmd_demo)

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
