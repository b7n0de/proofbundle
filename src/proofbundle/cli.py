"""Command line interface: ``proofbundle`` verify / emit / emit-eval / show-eval."""

from __future__ import annotations

import argparse
import json
import sys

from . import SPEC_REVISION, __version__
from ._strict_json import loads_strict
from .bundle import SCHEMA, recompute_merkle_root_b64, verify_bundle
from .emit import emit_bundle, generate_signer, load_signer, save_signer
from .errors import ProofBundleError


# The honest "what => OK means / does not mean" block — surfaced in `verify --matrix` and always in
# `verify --json`. Verification proves authenticity + integrity of the bytes, never the truth of the
# result (see docs/NON_CLAIMS.md). Kept as data so the human text and the JSON say exactly the same thing.
VERIFY_MEANING = (
    "these exact bytes were signed by the stated Ed25519 key and are anchored unchanged in an "
    "RFC 6962 Merkle tree — authenticity and integrity of the claim")
VERIFY_NON_MEANING = (
    "NOT that the result is true, the eval well designed, the model safe/fair, or that the score "
    "generalizes (see NON_CLAIMS.md); and NOT when it happened, unless an external time anchor is present")

# WP-B2: the LIMITATIONS surfaced in the labelled verify block and the `limitations[]` JSON field.
# A list so 2.1 can append without breaking the single-string field; today it is the one meaning line.
VERIFY_LIMITATIONS = [VERIFY_NON_MEANING]


def _policy_line(policy_ok, reason: str = "") -> str:
    """The POLICY: … line / JSON reason (WP-B2). Without a supplied trust policy `verify` makes NO
    trust decision, so the human output MUST say so explicitly (NOT_EVALUATED) — never a bare OK that
    could be logged as a passed policy check. WP-B3 fills the OK / FAIL(<reason>) branches."""
    if policy_ok is None:
        return "NOT_EVALUATED (no trust policy supplied)"
    if policy_ok:
        return "OK"
    return f"FAIL ({reason})" if reason else "FAIL"


def _verify_exit_code(crypto_ok: bool, policy_ok, anchor_required_ok=None) -> int:
    """verify's exit-code contract (WP-B2; see ``proofbundle verify --help``): 0 = crypto OK and
    (policy satisfied OR none supplied) and (anchor requirement met OR none requested); 1 =
    crypto/verification failure; 3 = crypto OK but a supplied trust policy was NOT satisfied OR a
    ``--require-anchor`` requirement was NOT met. Malformed input (2) is returned earlier, before this
    is reached. `policy_ok` is None when no --policy was given; `anchor_required_ok` is None when no
    --require-anchor was given — both are relying-party gates layered OVER the crypto result, so a
    crypto failure (exit 1) always dominates. This pure function encodes every code so the contract is
    tested independently of the wiring."""
    if not crypto_ok:
        return 1
    if policy_ok is False or anchor_required_ok is False:
        return 3
    return 0


def _safe_line(s: str) -> str:
    """Neutralise control characters (newline, CR, tab, …) in an issuer-/policy-controlled string
    before it is printed on its own labelled line, so it can never forge additional
    CRYPTO:/POLICY:/ASSURANCE: lines (verify-lens L3, 2026-07-09). Defense-in-depth: the ASSURANCE
    value is already enum-restricted by decode_eval_claim and WP-B3's _policy_line(reason=…) will
    carry bundle-derived text — both go through here. Printable content is unchanged."""
    return "".join(ch if ch.isprintable() else " " for ch in s)


# The machine-readable field names of the verify --json single-field contract (WP-B2). Kept in ONE
# place so _error_verify_fields and _derive_verify_fields cannot drift (a test pins the union).
_VERIFY_NULLABLE_FIELDS = (
    "schema_ok", "signature_ok", "merkle_ok", "sd_jwt_ok", "sd_jwt_issuer_verified",
    "key_binding_ok", "audience_ok", "nonce_ok", "freshness_ok", "anchor_ok", "witness_ok",
    "status_ok", "assurance_policy_ok", "policy_ok", "assurance", "assurance_declared_by")


def _error_verify_fields(error: str) -> dict:
    """The stable single-field contract on the malformed-input (exit 2) path (verify-lens L2,
    2026-07-09): crypto could not even be evaluated, so crypto_ok is False and every check field is
    null. Keeps `verify --json`'s field set stable so an integrator can always read e.g. crypto_ok
    without a KeyError on the error path."""
    fields: dict[str, object] = {k: None for k in _VERIFY_NULLABLE_FIELDS}
    fields["crypto_ok"] = False
    fields["warnings"] = [error]
    fields["limitations"] = list(VERIFY_LIMITATIONS)
    return fields


def _assurance_from_bundle(bundle) -> str | None:
    """Best-effort, VERBATIM read of an eval receipt's signed `assurance_level` for the ASSURANCE line
    (WP-B2) — displayed as-is, never interpreted, never a trust decision. Only attempted for a bundle
    that cryptographically decodes as an issuer-bound eval receipt (`decode_eval_claim` re-checks the
    Ed25519 + issuer binding); a plain emit bundle or anything undecodable yields None → the CLI shows
    `ASSURANCE: n/a`. Fail-safe: any error returns None, never a traceback (this is display, not a
    verification step — the crypto verdict already came from verify_bundle)."""
    try:
        from .evalclaim import DEFAULT_ASSURANCE, decode_eval_claim  # noqa: PLC0415
        claim = decode_eval_claim(bundle)
        if claim is None:
            return None
        return claim.get("assurance_level", DEFAULT_ASSURANCE)
    except Exception:  # noqa: BLE001 — display best-effort, never fatal
        return None


def _derive_verify_fields(result, *, aud_requested: bool, nonce_requested: bool,
                          assurance, policy_ok) -> dict:
    """Derive the stable, machine-readable single-field contract (WP-B2) from the core
    VerificationResult. A field for a check that did NOT run in the offline core `verify` path
    (freshness/anchor/witness/status/assurance-policy — those live in separate subcommands or the
    WP-B3 policy layer) is `None` (not applicable), NEVER silently `True`. Field names mirror the
    SPEC/CLI vocabulary so integrators can key off them stably across releases."""
    by_name = {c.name: c.ok for c in result.checks}
    warnings = [f"{c.name}: {c.detail}" for c in result.checks if not c.ok]

    # sd_jwt_ok is fail-closed against the "reading OK as truth" trap (verify-lens L1/L2, 2026-07-09;
    # WP-C1/C2, 2026-07-11): `sd_jwt_vc` lives OUTSIDE payload_b64, so the Ed25519 signature does NOT cover
    # it — only the SD-JWT's ISSUER signature authenticates its disclosures. Since WP-C2 a present sd_jwt_vc
    # ALWAYS runs sd-jwt-issuer-signature (it FAILS with reason `unsigned` when no issuer key is supplied),
    # so sd_iss is never None once an SD-JWT is present. sd_jwt_issuer_verified carries the granular truth
    # (True checked+valid / False checked+invalid / None no SD-JWT) so the single sd_jwt_ok cannot be misread.
    sd_disc = by_name.get("sd-jwt-disclosures")
    sd_iss = by_name.get("sd-jwt-issuer-signature")   # present (True/False) whenever an sd_jwt_vc is present
    sd_jwt_issuer_verified = sd_iss
    if sd_disc is None:
        sd_jwt_ok = None                              # no SD-JWT → not applicable
    elif not sd_disc:
        sd_jwt_ok = False                             # disclosure structure malformed → definitely failed
    else:
        sd_jwt_ok = bool(sd_iss)                      # structure ok → the issuer-signature verdict…
        # WP-C1: …folded with every further sd-jwt sub-check that actually ran. A valid issuer signature is
        # not enough if the SD-JWT binds a DIFFERENT bundle (sd-jwt-bundle-binding=False), was signed by a
        # key that is not the disclosed issuer (sd-jwt-issuer-identity=False, forged identity), or its holder
        # key-binding is invalid (sd-jwt-key-binding=False) — none of those may read as sd_jwt_ok=True
        # (No-Fake). `is False` only, so a not-applicable (None) sub-check never downgrades.
        if any(by_name.get(n) is False for n in
               ("sd-jwt-bundle-binding", "sd-jwt-issuer-identity", "sd-jwt-key-binding")):
            sd_jwt_ok = False

    key_binding_ok = by_name.get("sd-jwt-key-binding")   # None when no KB-JWT / no cnf binding in play

    # audience_ok / nonce_ok: the aud/nonce EQUALITY is enforced INSIDE the key-binding check
    # (kbjwt.verify_key_binding), and bundle.verify_bundle fails closed (F4) when aud/nonce were
    # requested but no verifiable KB-JWT exists. We surface them as separate fields only when the
    # relying party actually requested that binding (--aud/--nonce); the outcome then equals the
    # key-binding result. None when not requested (never silently True).
    audience_ok = key_binding_ok if aud_requested else None
    nonce_ok = key_binding_ok if nonce_requested else None

    fields = {
        "schema_ok": True,             # reaching here means schema == SCHEMA passed (else exit 2)
        "signature_ok": by_name.get("ed25519-signature"),
        "merkle_ok": by_name.get("merkle-inclusion"),
        "sd_jwt_ok": sd_jwt_ok,
        "sd_jwt_issuer_verified": sd_jwt_issuer_verified,
        "key_binding_ok": key_binding_ok,
        "audience_ok": audience_ok,
        "nonce_ok": nonce_ok,
        "freshness_ok": None,          # core verify is payload-agnostic; freshness lives in show-eval
        "anchor_ok": None,             # anchors[] is a separate (experimental) verification path
        "witness_ok": None,            # witness quorum lives in verify-proof
        "status_ok": None,             # status snapshots live in verify_status_snapshot
        "assurance_policy_ok": None,   # assurance-vs-policy is evaluated in the WP-B3 policy layer
        "crypto_ok": result.ok,
        "policy_ok": policy_ok,        # None unless a trust policy was supplied (WP-B3)
        "assurance": assurance,        # verbatim eval-claim level, or None (not an eval receipt)
        # WP-N2: the assurance level is the ISSUER's own self-declared value — carried verbatim in the
        # signed claim, never appraised by verify. Said explicitly so a log line cannot read it as an
        # independent assessment. None when there is no assurance level to attribute.
        "assurance_declared_by": "issuer" if assurance is not None else None,
        "warnings": warnings,
        "limitations": list(VERIFY_LIMITATIONS),
    }
    return fields


# WP-B1 (closes #28): `--version` additionally reports the pinned SPEC.md revision (SPEC_REVISION,
# kept in sync by tests/test_docs_truth.py) and which optional extras are actually usable in THIS
# install. Detection is best-effort and fail-safe: a missing/broken extra is silently omitted, never
# a traceback — this is informational output, not a capability gate. `proofbundle.experimental` warns
# once on import (by design, so nobody depends on the preview by accident); that warning is suppressed
# here since merely probing availability for --version is not "using" the preview.
def _detect_features() -> list:
    # Jede probe ist fail-safe: ein fehlendes ODER kaputtes Extra darf NIE einen Traceback in
    # `--version` ausloesen (informational output, kein capability gate). Ein present-but-broken
    # Extra kann mehr als ImportError werfen — AttributeError (mldsa-Modul da, MLDSA44PublicKey-
    # Klasse fehlt bei cryptography>=48 ohne PQ-Backend) oder RuntimeError/andere aus einem
    # ABI-Mismatch/partiellen Install — daher faengt JEDE probe breit `Exception` (Verify-Linse 2,
    # 2026-07-09: vorher fingen 5 der 6 probes nur ImportError, exakt die Crash-Klasse die fuer `pq`
    # bereits gefixt war).
    features = []
    try:
        import rfc8785  # noqa: F401,PLC0415
        features.append("eval")
    except Exception:  # noqa: BLE001 — fail-safe by design
        pass
    try:
        from . import sdjwt as _sdjwt  # noqa: F401,PLC0415
        features.append("sdjwt")
    except Exception:  # noqa: BLE001 — fail-safe by design
        pass
    try:
        import opentimestamps  # noqa: F401,PLC0415
        import rfc3161_client  # noqa: F401,PLC0415
        import rfc8785  # noqa: F401,PLC0415
        features.append("anchors[beta]")
    except Exception:  # noqa: BLE001 — fail-safe by design
        pass
    try:
        # cryptography>=48 ohne PQ-Backend hat das `mldsa`-Modul, aber nicht die Klasse
        # (AttributeError, nicht ImportError) — dokumentierter realer Fall.
        from cryptography.hazmat.primitives.asymmetric import mldsa  # noqa: PLC0415
        mldsa.MLDSA44PublicKey  # noqa: B018
        features.append("pq")
    except Exception:  # noqa: BLE001 — fail-safe by design
        pass
    try:
        import inspect_ai  # noqa: F401,PLC0415
        features.append("inspect")
    except Exception:  # noqa: BLE001 — fail-safe by design
        pass
    try:
        import warnings  # noqa: PLC0415
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            from .experimental import enclave as _enclave  # noqa: F401,PLC0415
        features.append("experimental")
    except Exception:  # noqa: BLE001 — fail-safe by design
        pass
    return features


def _version_string() -> str:
    feature_line = ", ".join(_detect_features()) or "(none detected)"
    return (
        f"proofbundle {__version__}\n"
        f"spec-revision: {SCHEMA} (rev {SPEC_REVISION})\n"
        f"schema: proofbundle_v0_1\n"
        f"features: {feature_line}\n"
        f"predicates: eval-result/v0.1 decision-receipt/v0.1"
    )


class _VersionAction(argparse.Action):
    """Like argparse's built-in ``action='version'``, but prints the raw 4-line block verbatim.
    The built-in action runs the string through HelpFormatter, which collapses embedded newlines
    into a single space-joined line — wrong for this multi-line output. Same external contract:
    ``nargs=0``, exits via ``parser.exit()`` (SystemExit(0)) before argparse checks the otherwise-
    required subcommand, so ``proofbundle --version`` keeps working with no subcommand given."""

    def __init__(self, option_strings, dest=argparse.SUPPRESS, default=argparse.SUPPRESS,
                help="show the package version, spec revision, and detected optional features"):
        super().__init__(option_strings=option_strings, dest=dest, default=default, nargs=0, help=help)

    def __call__(self, parser, namespace, values, option_string=None):
        print(_version_string())
        parser.exit()


def _check_matrix(result) -> list:
    """Per-check status rows for the verify matrix. Core verify produces PASS/FAIL; WARN/SKIP are
    surfaced by the optional anchor layer (proofbundle.anchors), never faked here."""
    return [{"check": c.name, "status": "PASS" if c.ok else "FAIL", "detail": c.detail}
            for c in result.checks]


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
    from .bundle import load_bundle  # noqa: PLC0415
    from .evalclaim import (  # noqa: PLC0415
        DEFAULT_ASSURANCE, check_freshness, claim_warnings, decode_eval_claim, sd_jwt_hidden_count,
    )
    try:
        # Resolve the path to a dict ONCE and pass that object to every reader — a second per-function re-read of
        # the same path would reopen a TOCTOU window (CWE-367) between the reads. Release-review fix 2026-07-02.
        bundle = load_bundle(args.receipt)
        claim = decode_eval_claim(bundle, expected_context=getattr(args, "context", None))
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
    hidden = sd_jwt_hidden_count(bundle)
    if hidden is not None:
        print(f"sd-jwt     {hidden} field(s) withheld (selective disclosure)")
    fresh = check_freshness(claim)
    if fresh["parsed"]:
        print(f"age        {fresh['age_seconds']}s")
    for w in claim_warnings(claim):
        print(f"WARNING    {w}")
    print("=> OK")
    return 0


def _evaluate_anchor_requirement(bundle: dict, *, require: str, allow_pending: bool,
                                 require_target=None, rp_trust=None) -> dict:
    """Evaluate a ``--require-anchor`` gate over a receipt's ``anchors`` (WP4), wired to the existing
    ``proofbundle.anchors`` layer — never a parallel reimplementation. Returns
    ``{ok, status, detail, results}`` where ``ok`` is the anchor layer's ``require_met`` verdict: True
    iff at least one anchor of the required type actually verifies (or, with ``allow_pending``, is
    pending). This is deliberately SEPARATE from the aggregate ``status``: an UNRELATED broken /
    unregistered anchor makes ``status`` FAIL (surfaced in ``anchor_status`` / ``anchor_results``) but
    does NOT fail a requirement a DIFFERENT anchor satisfies — exactly as anchors are advisory-only when
    no ``--require-anchor`` is given (deriving ``ok`` from ``status != FAIL`` was the WP4 aggregation
    bug). A receipt with no ``anchors`` → the layer reports the requirement unmet (``ok=False``), which
    maps to exit 3, exactly like an unsatisfied trust policy.

    Target roots are computed ONLY when anchors are actually present (so the common no-anchor case needs
    no extra dependency): the ``receipt`` root is the canonical root of the bundle WITHOUT its own
    ``anchors`` (detached evidence — an anchor stamps the pre-anchor bundle), and the ``preRegistration``
    root is the receipt's signed ``prereg_sha256``. If a needed root cannot be computed (e.g. the
    RFC 8785 canonicalizer from the ``[anchors]``/``[eval]`` extra is absent), that target is simply
    omitted → an anchor for it fails closed with a clear reason, never a silent pass."""
    from .anchors import (  # noqa: PLC0415
        prereg_canonical_root, receipt_canonical_root, verify_anchors,
    )
    anchors_list = bundle.get("anchors")
    target_roots: dict = {}
    if anchors_list:
        try:
            receipt_only = {k: v for k, v in bundle.items() if k != "anchors"}
            target_roots["receipt"] = receipt_canonical_root(receipt_only)
        except ProofBundleError:
            pass   # canonicalizer extra absent → no receipt target; a receipt anchor then fails closed
        try:
            from .evalclaim import decode_eval_claim  # noqa: PLC0415
            claim = decode_eval_claim(bundle)
            if claim and claim.get("prereg_sha256"):
                target_roots["preRegistration"] = prereg_canonical_root(claim["prereg_sha256"])
        except (ProofBundleError, ValueError):
            pass
    try:
        res = verify_anchors(anchors_list, target_roots=target_roots, require=require,
                             require_target=require_target, allow_pending=allow_pending,
                             rp_trust=rp_trust)
    except ProofBundleError as exc:   # malformed anchors[] → fail-closed (never a silent pass)
        return {"ok": False, "status": "FAIL", "detail": str(exc), "results": []}
    # WP4 fix (aggregation bug): the requirement verdict follows the anchor layer's `require_met` signal
    # ("at least one anchor of the required type verifies"), NOT the global `status`. An unrelated broken
    # anchor makes `status` FAIL (still reported in anchor_status / anchor_results) but must not fail a
    # requirement a different anchor satisfies. Fail-closed: a missing signal defaults to not-met.
    return {"ok": bool(res.get("require_met", False)), "status": res["status"], "detail": res["detail"],
            "results": res.get("results", [])}


def _build_rp_trust(args: argparse.Namespace) -> dict | None:
    """WP-A1: assemble the relying party's anchor trust material from CLI flags. Returns None when the
    relying party supplied nothing (→ a required time anchor is unmet, exit 3 — never a silent frozen
    pass). Malformed input raises ValueError → the documented malformed-input exit 2."""
    import base64 as _b64  # noqa: PLC0415
    rp: dict = {}
    roots = getattr(args, "trusted_tsa_root", None) or []
    if roots:
        from cryptography import x509  # noqa: PLC0415
        der_b64: list = []
        for path in roots:
            try:
                raw = open(path, "rb").read()  # noqa: SIM115
            except OSError as exc:
                raise ValueError(f"--trusted-tsa-root {path!r}: cannot read ({exc})") from exc
            try:   # accept PEM or DER; normalize to base64 DER (what the verifier loads)
                cert = x509.load_pem_x509_certificate(raw) if b"-----BEGIN" in raw \
                    else x509.load_der_x509_certificate(raw)
            except Exception as exc:
                raise ValueError(f"--trusted-tsa-root {path!r}: not a valid certificate ({exc})") from exc
            from cryptography.hazmat.primitives.serialization import Encoding  # noqa: PLC0415
            der_b64.append(_b64.b64encode(cert.public_bytes(Encoding.DER)).decode("ascii"))
        rp["trusted_tsa_roots"] = der_b64
    headers = getattr(args, "bitcoin_header", None) or []
    if headers:
        by_height: dict = {}
        for spec in headers:
            if ":" not in spec:
                raise ValueError(f"--bitcoin-header {spec!r}: expected HEIGHT:MERKLEROOT_HEX")
            height, _, root_hex = spec.partition(":")
            height, root_hex = height.strip(), root_hex.strip().lower()
            if not height.isdigit():
                raise ValueError(f"--bitcoin-header {spec!r}: height must be a non-negative integer")
            try:
                if len(bytes.fromhex(root_hex)) != 32:
                    raise ValueError
            except ValueError as exc:
                raise ValueError(f"--bitcoin-header {spec!r}: merkle root must be 32-byte hex") from exc
            by_height[height] = root_hex
        rp["bitcoin_block_headers"] = by_height
    return rp or None


def _cmd_verify(args: argparse.Namespace) -> int:
    from .bundle import load_bundle  # noqa: PLC0415
    from .policy import (  # noqa: PLC0415
        evaluate_policy, load_policy, policy_anchor_trust, policy_expected_aud,
    )

    flag_aud = getattr(args, "aud", None)
    flag_nonce = getattr(args, "nonce", None)
    # WP4 (additive): resolve the anchor requirement to the value the anchor layer expects — None (no
    # requirement) | "any" | a specific type string. --anchor-type narrows and implies --require-anchor.
    anchor_type = getattr(args, "anchor_type", None)
    anchor_target = getattr(args, "anchor_target", None)   # WP-A1: implies --require-anchor
    require_anchor = anchor_type if anchor_type else (
        "any" if (getattr(args, "require_anchor", False) or anchor_target) else None)
    allow_pending = bool(getattr(args, "allow_pending", False))
    policy = None
    try:
        # --allow-pending only means anything alongside a requirement: reject the lone flag loudly
        # (a silent no-op would hide a mistaken invocation) → the documented malformed-input exit 2.
        if allow_pending and require_anchor is None:
            raise ValueError("--allow-pending only applies together with --require-anchor / --anchor-type")
        # WP-A1: build the relying-party anchor trust material INSIDE the try so a malformed
        # --trusted-tsa-root / --bitcoin-header is a clean exit 2 (not a raw traceback), like every other
        # malformed flag. Built once, used at the anchor-requirement site (which is outside this try).
        rp_trust_material = _build_rp_trust(args)
        # Resolve the path to a dict ONCE and pass it to both verify_bundle and recompute — a second per-function
        # re-read of the same path reopens a TOCTOU window (release-review consistency fix, mirrors show-eval).
        bundle = load_bundle(args.bundle)
        # WP-B3: crypto FIRST, policy over the crypto result. Load + structurally validate the policy
        # (fail-closed) before verifying, and reconcile the aud VALUE: if BOTH --aud and the policy's
        # expected_aud are set and DIFFER, that is ambiguous → exit 2 (never a silent override).
        effective_aud = flag_aud
        if getattr(args, "policy", None):
            policy = load_policy(args.policy)
            pol_aud = policy_expected_aud(policy)
            if pol_aud is not None and flag_aud is not None and pol_aud != flag_aud:
                from .policy import PolicyError  # noqa: PLC0415
                raise PolicyError(
                    f"--aud {flag_aud!r} conflicts with the policy's sd_jwt.expected_aud {pol_aud!r} "
                    "— ambiguous; supply only one, or make them equal")
            effective_aud = flag_aud if flag_aud is not None else pol_aud
            # WP-A1: the policy's anchors section supplies the anchor requirement when no CLI flag
            # does; a CONFLICTING flag/policy pair is ambiguous → exit 2 (mirrors expected_aud).
            pol_anc = policy.get("anchors") or {}
            if pol_anc:
                from .policy import PolicyError  # noqa: PLC0415
                p_req = pol_anc.get("require_anchor")
                p_tgt = pol_anc.get("require_anchor_target")
                if p_req is not None and require_anchor is not None and p_req != require_anchor:
                    raise PolicyError(
                        f"anchor requirement conflict: CLI wants {require_anchor!r}, the policy's "
                        f"anchors.require_anchor is {p_req!r} — ambiguous; align them")
                if p_tgt is not None and anchor_target is not None and p_tgt != anchor_target:
                    raise PolicyError(
                        f"anchor target conflict: CLI wants {anchor_target!r}, the policy's "
                        f"anchors.require_anchor_target is {p_tgt!r} — ambiguous; align them")
                require_anchor = require_anchor if require_anchor is not None else p_req
                anchor_target = anchor_target if anchor_target is not None else p_tgt
                if anchor_target and require_anchor is None:
                    require_anchor = "any"
                if pol_anc.get("allow_pending"):
                    allow_pending = True
            # WP-A1: union the policy's anchor TRUST material with the CLI's (a CLI value wins per key).
            pol_trust = policy_anchor_trust(policy)
            if pol_trust:
                merged = dict(pol_trust)
                merged.update(rp_trust_material or {})   # CLI flags take precedence on the same key
                rp_trust_material = merged
        result = verify_bundle(bundle, expected_aud=effective_aud, expected_nonce=flag_nonce)
        roots = recompute_merkle_root_b64(bundle) if args.verbose else None
    except (ProofBundleError, OSError, ValueError, RecursionError) as exc:   # file/JSON/format/policy errors → clean exit 2, never a raw traceback
        # RecursionError: deeply-nested JSON overflows json.load's recursion; catch it here too so it
        # maps to the documented exit 2, never a raw traceback (verify-lens L3; load_bundle also guards
        # it centrally). PolicyError (a ProofBundleError) — malformed policy or aud ambiguity — also
        # exits 2. The error JSON carries the full field contract so an integrator can always read
        # crypto_ok without a KeyError on the error path (verify-lens L2).
        if args.json:
            print(json.dumps({"ok": False, "error": str(exc), **_error_verify_fields(str(exc))}))
        else:
            print(f"ERROR: {exc}", file=sys.stderr)
        return 2

    crypto_ok = result.ok
    # WP-B3: evaluate the policy OVER the crypto result — but ONLY when crypto passed. A policy is
    # never a reason to trust bytes whose signature/merkle failed (fail-closed): policy_ok stays None
    # (NOT_EVALUATED) and exit 1 dominates.
    policy_ok = None
    policy_result = None
    if policy is not None and crypto_ok:
        policy_result = evaluate_policy(bundle, result, policy)
        policy_ok = policy_result["policy_ok"]
    # WP4: the --require-anchor gate is a relying-party requirement layered OVER the crypto result,
    # exactly like --policy — evaluated ONLY when crypto passed (fail-closed; a crypto failure dominates
    # and exits 1). Unmet → anchor_required_ok False → exit 3. Without the flag it stays None and nothing
    # about the anchors is looked at (default behaviour unchanged).
    anchor_required_ok = None
    anchor_report = None
    if require_anchor is not None and crypto_ok:
        anchor_report = _evaluate_anchor_requirement(
            bundle, require=require_anchor, allow_pending=allow_pending,
            require_target=anchor_target, rp_trust=rp_trust_material)
        anchor_required_ok = anchor_report["ok"]
    # ASSURANCE is a verbatim display read, only meaningful (and only attempted) for a receipt that
    # cryptographically verified — a crypto FAIL means the level cannot be trusted, so show n/a.
    assurance = _assurance_from_bundle(bundle) if crypto_ok else None
    fields = _derive_verify_fields(
        result,
        aud_requested=effective_aud is not None,
        nonce_requested=flag_nonce is not None,
        assurance=assurance, policy_ok=policy_ok)
    if policy is not None:
        fields["policy_id"] = policy.get("policy_id")
        # WP-TP1: non-fatal honesty warnings (e.g. "attributes to nobody") — exit code unchanged.
        # Mirror the human line (six-lens review): the warning is meaningful only for a PASSING
        # policy (a POLICY: OK that attributes to nobody); on FAIL / crypto-FAIL the FAIL is the
        # message, so the JSON field is empty too — the key stays present for contract stability.
        from .policy import policy_warnings  # noqa: PLC0415
        fields["policy_warnings"] = policy_warnings(policy) if policy_ok else []
    if policy_result is not None:
        fields["policy_checks"] = policy_result["checks"]
    if anchor_report is not None:
        # anchor_ok was None (not evaluated) in the core contract; now it carries the real gate verdict,
        # with the anchor layer's aggregate status + per-entry results for transparency (additive keys).
        fields["anchor_ok"] = anchor_required_ok
        fields["anchor_status"] = anchor_report["status"]
        fields["anchor_detail"] = anchor_report["detail"]
        fields["anchor_results"] = anchor_report["results"]

    if args.json:
        out = result.as_dict()
        if roots is not None:
            out["merkle_root"] = roots
        # additive, non-breaking: existing keys (ok/checks) unchanged; new honest meaning block + matrix.
        out["matrix"] = _check_matrix(result)
        out["meaning"] = VERIFY_MEANING
        out["nonMeaning"] = VERIFY_NON_MEANING
        out.update(fields)   # WP-B2 stable single-field contract (additive; existing keys untouched)
        print(json.dumps(out, indent=2))
    else:
        for check in result.checks:
            print(str(check))
        if roots is not None:
            print(f"    stated root      {roots['stated_b64']}")
            recomputed = roots["recomputed_b64"]
            print(f"    recomputed root  {recomputed if recomputed is not None else '(not computable: ' + roots['detail'] + ')'}")
        if getattr(args, "matrix", False):
            print("  ── check matrix ──")
            for row in _check_matrix(result):
                print(f"    [{row['status']:<4}] {row['check']}")
            print(f"  proves      {VERIFY_MEANING}")
            print(f"  proves NOT  {VERIFY_NON_MEANING}")
        # WP-B2 labelled result block. The bare `=> OK` is gone: every line is context-labelled so a
        # crypto success can never be read as a policy pass or a truth verdict. CRYPTO is the only
        # thing the offline core proves; POLICY says NOT_EVALUATED until a trust policy is supplied
        # (WP-B3); ASSURANCE is the issuer's own verbatim self-declared level; LIMITATIONS restates
        # what a valid signature does NOT mean.
        if assurance is not None:
            # WP-N2: name the source — the level is the issuer's own declaration, not an appraisal.
            assurance_line = f"{_safe_line(assurance)} (issuer-declared)"   # issuer-controlled → control-chars neutralised
        elif not crypto_ok:
            assurance_line = "n/a (crypto verification failed)"   # a real receipt whose crypto broke
        else:
            assurance_line = "n/a (not an eval receipt)"    # a well-verified bundle that is not an eval receipt
        print(f"CRYPTO: {'OK' if crypto_ok else 'FAILED'}")
        if policy is not None and not crypto_ok:
            print("POLICY: NOT_EVALUATED (crypto failed — policy not checked)")
        else:
            reason = _safe_line(policy_result["reason"]) if policy_result else ""
            line = _policy_line(policy_ok, reason)
            # WP-TP1: a passing policy that pins no signer says so INLINE — never a bare OK that
            # reads as an attribution. Exit code unchanged (warning, not failure).
            warns = fields.get("policy_warnings") or []
            if policy_ok and warns:
                line += f" (WARNING: {_safe_line(warns[0].split(':', 1)[0])})"
            print(f"POLICY: {line}")
        print(f"ASSURANCE: {assurance_line}")
        print(f"LIMITATIONS: {VERIFY_NON_MEANING}")
        # WP4: the ANCHOR line is printed ONLY when --require-anchor was given (default output unchanged).
        if require_anchor is not None:
            if not crypto_ok:
                print("ANCHOR: NOT_EVALUATED (crypto failed — anchor requirement not checked)")
            else:
                # crypto passed AND a requirement was set → the gate above ran, so anchor_report exists
                # (narrows the dict|None for the type checker; behaviour is unchanged).
                assert anchor_report is not None
                if anchor_required_ok:
                    print(f"ANCHOR: OK ({_safe_line(anchor_report['detail'])})")
                else:
                    print(f"ANCHOR: REQUIRED_NOT_MET ({_safe_line(anchor_report['detail'])})")
    return _verify_exit_code(crypto_ok, policy_ok, anchor_required_ok)


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
    except (ProofBundleError, OSError, ValueError) as exc:  # ValueError stopgap: never a raw traceback (D-1)
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
    # No silent downgrade: partial beacon flags must not fall through to the weakest self-challenge mode, and the
    # two strong modes (auditor nonce vs beacon) must not be silently mixed with beacon quietly winning.
    _beacon_flags = (args.beacon_randomness, args.beacon, args.round)
    if any(f is not None for f in _beacon_flags) and not all(f is not None for f in _beacon_flags):
        print("ERROR: beacon mode needs --beacon-randomness, --beacon and --round together "
              "(partial flags would silently downgrade to the grindable self-challenge mode)", file=sys.stderr)
        return 2
    if args.beacon_randomness is not None and args.nonce is not None:
        print("ERROR: --nonce and --beacon-randomness are mutually exclusive — pick one challenge mode",
              file=sys.stderr)
        return 2
    try:
        if args.beacon_randomness is not None:
            from .beacon import beacon_audit_challenge  # noqa: PLC0415
            req = beacon_audit_challenge(
                args.root, args.n, args.k,
                pulse_randomness=bytes.fromhex(args.beacon_randomness),
                beacon=args.beacon, round_=args.round)
            indices, mode = req.indices, "beacon"
        else:
            nonce = bytes.fromhex(args.nonce) if args.nonce else b""
            indices = audit_challenge(args.root, args.n, args.k, nonce)
            mode = "auditor-nonce" if args.nonce else "self-challenge"
    except (ProofBundleError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    if args.json:
        out = {"indices": indices, "n": args.n, "k": args.k, "mode": mode}
        if mode == "beacon":
            out["beacon"] = args.beacon
            out["round"] = args.round
        print(json.dumps(out))
    else:
        if mode == "self-challenge":
            print("WARNING: self-challenge mode (no --nonce/--beacon) is a sanity check only — "
                  "a producer can grind by re-salting; real audits supply a fresh nonce or a "
                  "public beacon pulse from a round AFTER the receipt timestamp", file=sys.stderr)
        print(" ".join(str(i) for i in indices))
    return 0


def _cmd_verify_opening(args: argparse.Namespace) -> int:
    from .persample import verify_sample_opening  # noqa: PLC0415
    try:
        with open(args.opening, encoding="utf-8") as handle:
            opening = loads_strict(handle.read())   # WP-C1: duplicate keys rejected
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


def _cmd_prereg(args: argparse.Namespace) -> int:
    from .prereg import prereg_hash, verify_prereg  # noqa: PLC0415
    try:
        if args.check is not None:
            from .evalclaim import decode_eval_claim  # noqa: PLC0415
            # Release-review CRITICAL: --check MUST verify the receipt (Ed25519 + Merkle) BEFORE trusting its
            # prereg_sha256 — the old load_bundle+manual-decode read an UNAUTHENTICATED claim, so a forged/unsigned
            # bundle with a doctored prereg_sha256 got a false PASS (the exact anti-cherry-picking bypass this guards).
            claim = decode_eval_claim(args.check)
            if claim is None:
                print("=> FAILED: not a valid, issuer-bound eval receipt", file=sys.stderr)
                return 1
            res = verify_prereg(args.protocol, claim)
            if args.json:
                print(json.dumps(res))
            else:
                print(f"[{'PASS' if res['ok'] else 'FAIL'}] prereg: {res['detail']}")
            return 0 if res["ok"] else 1
        h = prereg_hash(args.protocol)
        if args.json:
            print(json.dumps({"prereg_sha256": h}))
        else:
            print(h)
            print("place this in the eval claim's prereg_sha256 BEFORE running the eval",
                  file=sys.stderr)
        return 0
    except (ProofBundleError, OSError, ValueError, KeyError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


def _cmd_verify_enclave(args: argparse.Namespace) -> int:
    import base64 as _b64  # noqa: PLC0415
    from .bundle import load_bundle  # noqa: PLC0415
    from .experimental.enclave import (enclave_binding_for,  # noqa: PLC0415
                                       verify_enclave_attestation)
    try:
        bundle = load_bundle(args.receipt)
        with open(args.eat, encoding="utf-8") as handle:
            eat = handle.read().strip()
        verifier_pub = _b64.b64decode(args.verifier_key, validate=True)
        res = verify_enclave_attestation(
            eat, verifier_pubkey=verifier_pub, expected_binding=enclave_binding_for(bundle),
            expected_profile=args.profile)
    except (ProofBundleError, OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps({k: res[k] for k in ("ok", "tier", "profile", "ueid", "nonce_ok",
                                              "fresh", "detail")}))
    else:
        print(f"[{'PASS' if res['ok'] else 'FAIL'}] enclave-attestation: {res['detail']}")
        if res["ok"]:
            print(f"    tier    {res['tier']}")
            print(f"    profile {res['profile']}")
        print("=> OK" if res["ok"] else "=> FAILED")
    return 0 if res["ok"] else 1


def _cmd_intoto(args: argparse.Namespace) -> int:
    import base64  # noqa: PLC0415

    from .bundle import load_bundle  # noqa: PLC0415
    from .intoto import (  # noqa: PLC0415
        EVAL_RESULT_PREDICATE_TYPE, export_eval_result_dsse, verify_eval_result_dsse,
    )
    if args.verify:
        try:
            with open(args.receipt, encoding="utf-8") as handle:
                envelope = loads_strict(handle.read())   # WP-C1: duplicate keys rejected
            pub = base64.b64decode(args.pub)
            res = verify_eval_result_dsse(envelope, pub)
        except (OSError, ValueError, ProofBundleError) as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2
        pt = res.get("predicate_type")
        note = "" if pt == EVAL_RESULT_PREDICATE_TYPE else f"  (predicateType {pt!r})"
        print(f"[{'PASS' if res['ok'] else 'FAIL'}] eval-result attestation{note}")
        print("=> OK" if res["ok"] else "=> FAILED")
        return 0 if res["ok"] else 1

    from .evalclaim import decode_eval_claim  # noqa: PLC0415
    signer = _resolve_signer(args)
    if signer is None:
        return 2
    try:
        bundle = load_bundle(args.receipt)
        claim = decode_eval_claim(bundle)
        if claim is None:
            print("=> FAILED: not a valid, issuer-bound eval receipt", file=sys.stderr)
            return 1
        roots = recompute_merkle_root_b64(bundle)
        envelope = export_eval_result_dsse(
            claim, signer, subject_profile=args.subject_profile, subject_name=args.subject_name,
            subject_sha256=args.subject_sha256, root_b64=roots.get("stated_b64"))
    except (OSError, ValueError, ProofBundleError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(envelope, handle, indent=2)
        handle.write("\n")
    print(f"wrote in-toto eval-result attestation {args.out} (subject profile: {args.subject_profile})")
    return 0


def _cmd_svr(args: argparse.Namespace) -> int:
    import base64  # noqa: PLC0415

    from .intoto import SVR_PREDICATE_TYPE, export_svr_dsse, verify_svr_dsse  # noqa: PLC0415
    if args.verify:
        try:
            with open(args.receipt, encoding="utf-8") as handle:
                envelope = loads_strict(handle.read())   # WP-C1: duplicate keys rejected
            res = verify_svr_dsse(envelope, base64.b64decode(args.pub))
        except (OSError, ValueError, ProofBundleError) as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2
        pt = res.get("predicate_type")
        note = "" if pt == SVR_PREDICATE_TYPE else f"  (predicateType {pt!r})"
        print(f"[{'PASS' if res['ok'] else 'FAIL'}] SVR attestation{note}")
        if res["ok"]:
            for p in res["statement"].get("predicate", {}).get("properties", []):
                print(f"    {p}")
        print("=> OK" if res["ok"] else "=> FAILED")
        return 0 if res["ok"] else 1

    from .bundle import load_bundle  # noqa: PLC0415
    signer = _resolve_signer(args)
    if signer is None:
        return 2
    policy = None
    if args.policy_uri:
        policy = {"uri": args.policy_uri}
        if args.policy_sha256:
            policy["digest"] = {"sha256": args.policy_sha256}
    try:
        bundle = load_bundle(args.receipt)
        envelope = export_svr_dsse(bundle, signer, policy=policy)
    except (OSError, ValueError, ProofBundleError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(envelope, handle, indent=2)
        handle.write("\n")
    print(f"wrote in-toto SVR attestation {args.out}")
    return 0


def _cmd_decision_emit(args: argparse.Namespace) -> int:
    from .decision import DecisionReceiptError, emit_decision_receipt  # noqa: PLC0415
    signer = _resolve_signer(args)
    if signer is None:
        return 2
    try:
        with open(args.predicate, encoding="utf-8") as handle:
            predicate = loads_strict(handle.read())   # WP-C1: a duplicate key must never be signed
        env = emit_decision_receipt(predicate, signer, strict=not args.lenient)
    except (DecisionReceiptError, ProofBundleError, OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(env, handle, indent=2)
        handle.write("\n")
    print(f"wrote decision receipt {args.out}")
    return 0


def _cmd_decision_verify(args: argparse.Namespace) -> int:
    import base64  # noqa: PLC0415
    from .decision import verify_decision_receipt  # noqa: PLC0415
    if not args.pub:
        print("ERROR: --pub <base64 Ed25519 public key> is required", file=sys.stderr)
        return 2
    policy = None
    if args.policy:
        from .policy import PolicyError, load_policy  # noqa: PLC0415
        try:
            policy = load_policy(args.policy)
        except PolicyError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2
    anchors = None
    if getattr(args, "anchors", None):
        try:
            with open(args.anchors, encoding="utf-8") as handle:
                anchors = loads_strict(handle.read())   # WP-C1
        except (ProofBundleError, OSError, ValueError) as exc:
            print(f"ERROR: cannot read --anchors: {exc}", file=sys.stderr)
            return 2
    try:
        with open(args.envelope, encoding="utf-8") as handle:
            env = loads_strict(handle.read())   # WP-C1: duplicate keys rejected
        pub = base64.b64decode(args.pub)
        # WP-A1: relying-party anchor trust for a statement time anchor (CLI flags ∪ policy anchors section;
        # a CLI value wins per key). Built here so a malformed --trusted-tsa-root/--bitcoin-header is exit 2.
        rp_trust = _build_rp_trust(args)
        if policy is not None:
            from .policy import policy_anchor_trust  # noqa: PLC0415
            pol_trust = policy_anchor_trust(policy)
            if pol_trust:
                merged = dict(pol_trust)
                merged.update(rp_trust or {})
                rp_trust = merged
        result = verify_decision_receipt(env, pub, strict=args.strict, expected_audience=args.aud,
                                         expected_nonce=args.nonce, policy=policy, anchors=anchors,
                                         rp_trust=rp_trust)
    except (ProofBundleError, OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    if args.json:
        # Emit an explicit report projection (all check fields; booleans + static/field-derived strings — never
        # key material). Mirrors _cmd_verify/_cmd_verify_enclave: build a fresh dict instead of dumping the
        # opaque verify object verbatim, so a public-key value cannot flow into a clear-text log (CodeQL
        # py/clear-text-logging-sensitive-data).
        report = {k: result[k] for k in (
            "ok", "crypto_ok", "structure_ok", "predicate_type_ok", "signer_trusted", "policy_ok",
            "evidence_bound", "audience_ok", "nonce_ok", "freshness_ok", "anchors_ok",
            "action_outcome_proven", "warnings", "errors",
        )}
        print(json.dumps(report, indent=2))
    else:
        print(f"CRYPTO: {'OK' if result['crypto_ok'] else 'FAIL'}")
        if result["policy_ok"] is None:
            print("POLICY: NOT_EVALUATED (no decision policy supplied)")
        else:
            print(f"POLICY: {'OK' if result['policy_ok'] else 'FAIL'}")
        print(f"STRUCTURE: {'OK' if result['structure_ok'] else 'FAIL'}")
        if result["audience_ok"] is not None:
            print(f"AUDIENCE: {'OK' if result['audience_ok'] else 'MISMATCH'}")
        if result["nonce_ok"] is not None:
            print(f"NONCE: {'OK' if result['nonce_ok'] else 'MISMATCH'}")
        if result["anchors_ok"] is not None:
            print(f"ANCHORS: {'OK' if result['anchors_ok'] else 'FAIL'}")
        if result["action_outcome_proven"] is False:
            print("ASSURANCE: actionOutcome=executed is self-asserted (no signed outcomeRef)")
        for e in result["errors"]:
            print(f"  - {e}", file=sys.stderr)
        for w in result["warnings"]:
            print(f"  ! {w}", file=sys.stderr)
        # No-Overclaim (§7.4 / lens 1): only assert integrity when crypto actually held — on a crypto FAIL
        # the CRYPTO: FAIL line already says it, and a positive trailer would itself be an overclaim.
        if result["crypto_ok"]:
            print("\nThis proves the signed decision claim has not been altered. It does not prove the decision "
                  "was correct, legal, safe, or that the action was executed.")
        else:
            print("\nThis receipt did NOT verify (crypto failure); nothing about the decision is attested.")
    # Exit contract (Phase B): 1 crypto fail · 2 malformed/confusion · 3 crypto OK but policy not satisfied.
    if not result["crypto_ok"]:
        return 1
    if not result["structure_ok"]:
        return 2
    # A requested --aud/--nonce binding that does NOT match is a replay / wrong-context failure — fail-closed
    # like the eval verify path, never a silent exit 0 (lens 3 defect).
    if result["audience_ok"] is False or result["nonce_ok"] is False:
        return 2
    # A supplied anchor that FAILS to verify (broken / root-mismatched / unknown type) is a tamper
    # signal — fail-closed, never a silent exit 0 (fix-review Finding 3). None = no anchor supplied.
    if result["anchors_ok"] is False:
        return 1
    if result["policy_ok"] is False:
        return 3
    return 0


def _cmd_decision_inspect(args: argparse.Namespace) -> int:
    import base64  # noqa: PLC0415
    try:
        with open(args.receipt, encoding="utf-8") as handle:
            obj = loads_strict(handle.read())   # WP-C1
    except (ProofBundleError, OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    try:
        statement = loads_strict(base64.b64decode(obj["payload"])) if isinstance(obj, dict) and "payload" in obj else obj
    except (ProofBundleError, ValueError, TypeError) as exc:   # bad base64 / dup key / not JSON → clean exit, not a traceback
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    predicate = statement.get("predicate", statement) if isinstance(statement, dict) else statement
    print(json.dumps(predicate, indent=2, ensure_ascii=False))
    return 0


def _cmd_decision_init(args: argparse.Namespace) -> int:
    template = {
        "schemaVersion": "0.1.0",
        "decisionId": "urn:uuid:00000000-0000-0000-0000-000000000000",
        "decisionType": "preActionAuthorization",
        "decidedAt": "2026-01-01T00:00:00Z",
        "decisionMaker": {"id": "https://example.org/decision-platform/gate/v1", "version": {"proofbundle": __version__}},
        "agent": {"id": "agent://example/agent", "version": "0"},
        "principal": {"id": "workload://example/principal"},
        "proposedAction": {"actionType": "tool.call", "target": {"name": "mcp://example/action", "uri": "mcp://example/action"}, "method": "POST", "parametersDigest": {"sha256": "0" * 64}},
        "inputSnapshot": [{"name": "input", "uri": "urn:proofbundle:input:0", "digest": {"sha256": "0" * 64}, "mediaType": "application/json"}],
        "policyBoundary": {"policyEngine": "opa", "policyId": "https://example.org/policy/v1", "policyDigest": {"sha256": "0" * 64}, "decisionPath": "data.example.allow"},
        "evidenceRefs": [],
        "decision": {"verdict": "DENY", "reasonCodes": ["example.reason"], "humanReadableSummary": "", "obligations": [], "allowedScope": []},
        "notChecked": [{"field": "example", "reason": "template", "impact": ""}],
        "decisionChangeConditions": [{"conditionType": "additionalApproval", "description": "", "requiredEvidenceType": "approvalReceipt"}],
        "privacy": {"rawInputsIncluded": False, "redactionProfile": "https://example.org/redaction/v1", "erased": [], "masked": []},
    }
    out = json.dumps(template, indent=2, ensure_ascii=False)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(out + "\n")
        print(f"wrote decision predicate template {args.out}")
    else:
        print(out)
    return 0


def _cmd_policy_explain(args: argparse.Namespace) -> int:
    from .policy import PolicyError, explain_policy, load_policy, policy_warnings  # noqa: PLC0415
    try:
        policy = load_policy(args.policy)
    except PolicyError as exc:   # malformed policy → exit 2; in --json emit an error object (six-lens
        if args.json:            # review: an empty stdout on the error path breaks a JSON consumer)
            print(json.dumps({"ok": False, "policy_id": None, "error": str(exc)}))
        else:
            print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    pins = explain_policy(policy)
    warns = policy_warnings(policy)
    if args.json:
        print(json.dumps({"policy_id": policy.get("policy_id"), "schema": policy.get("schema"),
                          "pins": pins, "warnings": warns}, indent=2, ensure_ascii=False))
        return 0
    print(f"policy   {policy.get('policy_id')}  ({policy.get('schema')})")
    if pins:
        for line in pins:
            print(f"  pins   {line}")
    else:
        print("  pins   (none — this policy is wirkungslos; see `policy lint`)")
    for w in warns:
        print(f"  WARN   {w}")
    return 0


def _cmd_policy_lint(args: argparse.Namespace) -> int:
    from .policy import PolicyError, lint_policy, load_policy  # noqa: PLC0415
    try:
        policy = load_policy(args.policy)
    except PolicyError as exc:   # malformed policy is a lint failure too, with the parse reason
        if args.json:            # emit an error object in --json (mirror _cmd_verify; exit 2 unchanged)
            print(json.dumps({"ok": False, "policy_id": None, "error": str(exc)}))
        else:
            print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    res = lint_policy(policy, strict=args.strict)
    if args.json:
        print(json.dumps({"policy_id": policy.get("policy_id"), **res}, indent=2, ensure_ascii=False))
    else:
        print(f"[policy-lint] {'PASS' if res['ok'] else 'FAIL'} · {len(res['pins'])} pin(s) · "
              f"{len(res['errors'])} error(s) · {len(res['warnings'])} warning(s)")
        for e in res["errors"]:
            print(f"  ERROR {e}")
        for w in res["warnings"]:
            print(f"  WARN  {w}")
    return 0 if res["ok"] else 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="proofbundle",
        description="Emit and verify portable cryptographic evidence bundles, offline.",
    )
    parser.add_argument("--version", action=_VersionAction)
    sub = parser.add_subparsers(dest="command", required=True)

    verify = sub.add_parser(
        "verify", help="verify an evidence bundle JSON file",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Exit codes (verify contract):\n"
               "  0  CRYPTO OK, and the trust policy was satisfied or none was supplied, and the\n"
               "     --require-anchor requirement was met or none was requested\n"
               "  1  crypto / verification failure (a signature, merkle or key-binding check FAILED)\n"
               "  2  malformed input (unreadable file, bad JSON, malformed policy, or aud/policy ambiguity)\n"
               "  3  CRYPTO OK but a supplied --policy was NOT satisfied, or a --require-anchor\n"
               "     requirement was NOT met\n"
               "Without --policy the output shows 'POLICY: NOT_EVALUATED' and without --require-anchor\n"
               "the receipt's anchors are not evaluated at all — verify makes NO trust decision on its own.")
    verify.add_argument("bundle", help="path to the bundle JSON file")
    verify.add_argument("--json", action="store_true", help="machine readable output")
    verify.add_argument("--matrix", action="store_true",
                        help="print the per-check status matrix + the honest 'what => OK proves / does "
                             "not prove' block (always present in --json)")
    verify.add_argument("--verbose", action="store_true",
                        help="print the recomputed Merkle root next to the stated root")
    verify.add_argument("--aud", default=None,
                        help="expected KB-JWT audience (RFC 9901 §7.3 replay/audience binding); required to "
                             "bind a Key Binding JWT presentation to this verifier")
    verify.add_argument("--nonce", default=None,
                        help="expected KB-JWT nonce (RFC 9901 §7.3 replay binding)")
    verify.add_argument("--policy", default=None,
                        help="path to a trust-policy JSON (proofbundle/trust-policy/v0.1). Applies a "
                             "fail-closed, offline trust decision OVER the crypto result: without it "
                             "POLICY reads NOT_EVALUATED; a policy failure is exit 3, distinct from a "
                             "crypto failure (exit 1)")
    verify.add_argument("--require-anchor", action="store_true",
                        help="require a verifying external time anchor on the receipt (a relying-party "
                             "gate OVER the crypto result, like --policy): ANY verifying anchor "
                             "satisfies it unless --anchor-type narrows it. A receipt with no such "
                             "anchor → exit 3 (a policy failure, distinct from a crypto failure). "
                             "Without this flag (and without --anchor-type) the receipt's anchors are "
                             "not evaluated at all (default behaviour unchanged)")
    verify.add_argument("--anchor-type", default=None, metavar="TYPE",
                        help="require a verifying anchor of THIS type specifically (e.g. rfc3161-tsa, "
                             "opentimestamps); implies --require-anchor")
    verify.add_argument("--anchor-target", default=None,
                        choices=("receipt", "preRegistration", "statement"),
                        help="require the verifying anchor to stamp THIS target (WP-A1; implies "
                             "--require-anchor). Without it --require-anchor matches the TYPE only — "
                             "a receipt anchor stamped today would satisfy a relying party who meant "
                             "backdating protection (preRegistration)")
    verify.add_argument("--allow-pending", action="store_true",
                        help="with --require-anchor / --anchor-type, also accept a PENDING anchor (e.g. "
                             "an un-upgraded OpenTimestamps proof) as satisfying the requirement — "
                             "weaker, since a pending proof is not yet a full external-time anchor")
    verify.add_argument("--trusted-tsa-root", action="append", default=None, metavar="PATH",
                        help="WP-A1: a relying-party-supplied TSA root certificate (DER or PEM), repeatable. "
                             "This is the ONLY trust source for an rfc3161-tsa anchor — the bundle's own "
                             "frozen root is producer-controlled evidence, never trusted. Without it a "
                             "required rfc3161 anchor is unmet (exit 3)")
    verify.add_argument("--bitcoin-header", action="append", default=None, metavar="HEIGHT:MERKLEROOT_HEX",
                        help="WP-A1: a relying-party-supplied Bitcoin block header merkle root for a height "
                             "(internal/node byte order, as bitcoind returns it), repeatable. The ONLY "
                             "trust source that CONFIRMS an OpenTimestamps anchor — the bundle's frozen "
                             "header is never trusted. Without it a required OTS anchor is unmet (exit 3)")
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
    show_eval.add_argument("--context", dest="context", default=None,
                           help="require the receipt's signed context_binding to equal this (cross-context replay guard)")
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
    challenge.add_argument("--beacon-randomness",
                           help="raw randomness (hex) of a public beacon pulse — non-interactive, "
                                "publicly re-derivable (use a round AFTER the receipt timestamp)")
    challenge.add_argument("--beacon", help="beacon id (e.g. 'drand:<chain-hash>' or 'nist')")
    challenge.add_argument("--round", type=int, help="the beacon round/pulse index")
    challenge.add_argument("--json", action="store_true", help="machine readable output")
    challenge.set_defaults(func=_cmd_audit_challenge)

    verify_opening = sub.add_parser(
        "verify-opening", help="verify one sample opening against a samples root (v1.5)")
    verify_opening.add_argument("opening", help="opening JSON file (index/disclosure/proof_b64)")
    verify_opening.add_argument("--root", required=True, help="the receipt's samples root (base64)")
    verify_opening.add_argument("--n", required=True, type=int, help="committed sample count")
    verify_opening.add_argument("--json", action="store_true", help="machine readable output")
    verify_opening.set_defaults(func=_cmd_verify_opening)

    verify_enclave = sub.add_parser(
        "verify-enclave",
        help="[EXPERIMENTAL v2.0] verify a TEE Attestation Result (EAT) bound to a receipt")
    verify_enclave.add_argument("eat", help="path to the EAT (compact JWS) file")
    verify_enclave.add_argument("--receipt", required=True, help="the receipt bundle JSON the EAT must bind")
    verify_enclave.add_argument("--verifier-key", required=True,
                                help="the RATS Verifier's Ed25519 public key (base64)")
    verify_enclave.add_argument("--profile", help="pin an expected eat_profile URI (optional)")
    verify_enclave.add_argument("--json", action="store_true", help="machine readable output")
    verify_enclave.set_defaults(func=_cmd_verify_enclave)

    demo = sub.add_parser(
        "demo",
        help="run the whole trust story in memory (pip-only, offline): honest receipt verifies, "
             "six tampers fail, a swapped sample is caught")
    demo.add_argument("--json", action="store_true", help="machine readable output")
    demo.set_defaults(func=_cmd_demo)

    intoto = sub.add_parser(
        "intoto",
        help="[PROPOSED] export an eval receipt as a DSSE-signed in-toto eval-result attestation "
             "(in-toto/attestation#565), or verify one with --verify")
    intoto.add_argument("receipt", help="the eval receipt bundle JSON (export) or the attestation JSON (--verify)")
    intoto.add_argument("--out", help="path to write the DSSE attestation JSON (export)")
    intoto.add_argument("--key", help="issuer's 32 byte raw Ed25519 seed file to sign the attestation")
    intoto.add_argument("--new-key", help="generate a signing key and save it to this file")
    intoto.add_argument("--subject-profile", choices=("receipt", "public-model", "release-gate"),
                        default="receipt",
                        help="what the Statement subject IS (default: receipt — binds without revealing the model)")
    intoto.add_argument("--subject-name", help="subject name (required for public-model / release-gate)")
    intoto.add_argument("--subject-sha256", help="subject artifact sha256, 64-char hex "
                                                 "(required for public-model / release-gate)")
    intoto.add_argument("--verify", action="store_true",
                        help="verify an exported attestation instead of emitting one (needs --pub)")
    intoto.add_argument("--pub", help="issuer Ed25519 public key (base64) to verify against")
    intoto.set_defaults(func=_cmd_intoto)

    svr = sub.add_parser(
        "svr",
        help="[PROPOSED] emit an in-toto Summary Verification Result (svr/v0.1) for a PASSING receipt, "
             "or verify one with --verify")
    svr.add_argument("receipt", help="the eval receipt bundle JSON (emit) or the SVR JSON (--verify)")
    svr.add_argument("--out", help="path to write the SVR attestation JSON (emit)")
    svr.add_argument("--key", help="the verifier's 32 byte raw Ed25519 seed file to sign the SVR")
    svr.add_argument("--new-key", help="generate a signing key and save it to this file")
    svr.add_argument("--policy-uri", help="optional verifier.policy URI (SVR v0.1 extension field)")
    svr.add_argument("--policy-sha256", help="optional verifier.policy digest (sha256 hex)")
    svr.add_argument("--verify", action="store_true", help="verify an SVR instead of emitting one (needs --pub)")
    svr.add_argument("--pub", help="verifier Ed25519 public key (base64) to verify against")
    svr.set_defaults(func=_cmd_svr)

    policy_cmd = sub.add_parser(
        "policy", help="inspect a trust policy: explain its effective pins, lint for vacuousness")
    psub = policy_cmd.add_subparsers(dest="policy_command", required=True)
    p_explain = psub.add_parser(
        "explain", help="list the effective pins a trust policy makes (what POLICY: OK will mean)")
    p_explain.add_argument("policy", help="path to the trust-policy JSON")
    p_explain.add_argument("--json", action="store_true", help="machine readable output")
    p_explain.set_defaults(func=_cmd_policy_explain)
    p_lint = psub.add_parser(
        "lint", help="fail (exit 1) on a WIRKUNGSLOSE policy that would produce a vacuous "
                     "POLICY: OK; --strict also fails on attributes-to-nobody")
    p_lint.add_argument("policy", help="path to the trust-policy JSON")
    p_lint.add_argument("--strict", action="store_true",
                        help="promote warnings (attributes to nobody) to lint failures")
    p_lint.add_argument("--json", action="store_true", help="machine readable output")
    p_lint.set_defaults(func=_cmd_policy_lint)

    prereg = sub.add_parser(
        "prereg",
        help="hash an eval protocol file to commit to it BEFORE the run (--check verifies a receipt)")
    prereg.add_argument("protocol", help="path to the protocol/plan file to hash")
    prereg.add_argument("--check", metavar="RECEIPT",
                        help="verify the protocol matches a receipt's prereg_sha256 instead of hashing")
    prereg.add_argument("--json", action="store_true", help="machine readable output")
    prereg.set_defaults(func=_cmd_prereg)

    # decision-receipt/v0.1 predicate (vendored). Nested group: init / emit / verify / inspect.
    decision = sub.add_parser("decision", help="decision-receipt/v0.1: init/emit/verify/inspect an agent decision")
    dsub = decision.add_subparsers(dest="decision_command", required=True)

    d_init = dsub.add_parser("init", help="print a template decision predicate (fill in and sign with 'decision emit')")
    d_init.add_argument("--out", default=None, help="write the template to a file instead of stdout")
    d_init.set_defaults(func=_cmd_decision_init)

    d_emit = dsub.add_parser("emit", help="sign a decision predicate into a DSSE receipt")
    d_emit.add_argument("predicate", help="path to the decision predicate JSON")
    d_emit.add_argument("--out", required=True, help="output path for the signed decision receipt")
    d_emit.add_argument("--key", help="load an existing Ed25519 signing key from file")
    d_emit.add_argument("--new-key", dest="new_key", help="generate a new signing key and write it to file")
    d_emit.add_argument("--lenient", action="store_true", help="allow non-strict predicates (skip strict-mode required fields)")
    d_emit.set_defaults(func=_cmd_decision_emit)

    d_verify = dsub.add_parser(
        "verify", help="verify a decision receipt (crypto + structure; optional audience/nonce)",
        description=("Exit codes: 0 crypto+structure OK · 1 crypto/verification failure · 2 malformed input or "
                     "predicateType confusion. Without a decision policy the output shows POLICY: NOT_EVALUATED "
                     "and never exits 3. A verified ALLOW receipt is a record of a decision, NOT an "
                     "authorization or bearer token — the executing system makes its own authorization "
                     "check. --aud/--nonce bind a receipt that CARRIES validity.audience/validity.nonce "
                     "to this context; a receipt without a validity object is not checked against them, "
                     "so require their presence via a v0.2 policy's require_audience/require_nonce "
                     "(see docs/NON_CLAIMS.md)."))
    d_verify.add_argument("envelope", help="path to the DSSE decision receipt")
    d_verify.add_argument("--pub", required=True, help="issuer Ed25519 public key (base64) to verify against")
    d_verify.add_argument("--policy", default=None,
                          help="trust policy JSON (v0.2 decision_receipt section); a policy violation exits 3")
    d_verify.add_argument("--json", action="store_true", help="machine readable output")
    d_verify.add_argument("--strict", action="store_true", help="enforce strict-v0.1 required fields")
    d_verify.add_argument("--aud", default=None, help="expected audience (checks validity.audience against replay)")
    d_verify.add_argument("--nonce", default=None, help="expected nonce (checks validity.nonce against replay)")
    d_verify.add_argument("--anchors", default=None,
                          help="path to a JSON array of DETACHED anchor evidence for the statement's own "
                               "content root (anchors are never inside the signed predicate)")
    d_verify.add_argument("--trusted-tsa-root", action="append", default=None, metavar="PATH",
                          help="WP-A1: a relying-party-supplied TSA root certificate (DER/PEM) that confirms "
                               "an rfc3161 statement anchor — the bundle's frozen root is never trusted")
    d_verify.add_argument("--bitcoin-header", action="append", default=None, metavar="HEIGHT:MERKLEROOT_HEX",
                          help="WP-A1: a relying-party-supplied Bitcoin block header (internal byte order) "
                               "that confirms an OpenTimestamps statement anchor — frozen is never trusted")
    d_verify.set_defaults(func=_cmd_decision_verify)

    d_inspect = dsub.add_parser("inspect", help="print a decision receipt's predicate (no crypto verification)")
    d_inspect.add_argument("receipt", help="path to a DSSE receipt or a raw in-toto Statement")
    d_inspect.set_defaults(func=_cmd_decision_inspect)

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
