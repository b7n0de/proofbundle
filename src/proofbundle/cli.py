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
    "status_ok", "assurance_policy_ok", "policy_ok", "assurance", "assurance_declared_by",
    "root_authenticity")


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
        DEFAULT_ASSURANCE, check_freshness, claim_warnings, decode_eval_claim, enclave_assurance_proven,
        eval_evidence_class, sd_jwt_hidden_count,
    )
    try:
        # Resolve the path to a dict ONCE and pass that object to every reader — a second per-function re-read of
        # the same path would reopen a TOCTOU window (CWE-367) between the reads. Release-review fix 2026-07-02.
        bundle = load_bundle(args.receipt)
        claim = decode_eval_claim(bundle, expected_context=getattr(args, "context", None))
        # [EXPERIMENTAL v2.0] optional TEE-attestation corroboration for assurance_level=enclave_attested
        # (see enclave_assurance_proven). Parsed here so a bad --eat/--verifier-key gets the SAME clean
        # ERROR+exit-2 handling as the receipt itself, never a raw traceback.
        eat_jws = None
        if getattr(args, "eat", None):
            with open(args.eat, encoding="utf-8") as handle:
                eat_jws = handle.read().strip()
        verifier_pubkey = None
        if getattr(args, "verifier_key", None):
            import base64 as _b64  # noqa: PLC0415
            verifier_pubkey = _b64.b64decode(args.verifier_key, validate=True)
    except (OSError, ValueError, ProofBundleError) as exc:   # missing/invalid receipt file → clean exit, not a traceback
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    if claim is None:
        print("=> FAILED: not a valid, issuer-bound eval receipt", file=sys.stderr)
        return 1
    print(f"suite      {claim['suite']} ({claim['suite_version']})")
    print(f"metric     {claim['metric']} {claim['comparator']} {claim['threshold']}")
    print(f"passed     {claim['passed']}   (n={claim['n']})")
    ev = eval_evidence_class(claim)
    print(f"evidence   {ev['score_evidence']} ({ev['detail']})")
    print(f"note       {ev['methodology']} (the receipt never judges whether the suite is well designed)")
    print(f"assurance  {claim.get('assurance_level', DEFAULT_ASSURANCE)}")
    proven = enclave_assurance_proven(claim, bundle, eat_jws=eat_jws, verifier_pubkey=verifier_pubkey,
                                      expected_profile=getattr(args, "profile", None))
    if proven is True:
        print("attested   PROVEN — a verified TEE Attestation Result binds this receipt (EXPERIMENTAL v2.0)")
    elif proven is False and eat_jws is not None:
        print("attested   NOT corroborated — the supplied EAT did not verify / bind this receipt (EXPERIMENTAL v2.0)")
    elif proven is False:
        print("attested   NOT corroborated — issuer-declared only; supply --eat/--verifier-key to check (EXPERIMENTAL v2.0)")
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
    from .policy_profiles import resolve_policy_source  # noqa: PLC0415

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
        # A-P0-2 §6.3: historical verification only via an EXPLICIT instant — never silent backdating.
        verification_time = None
        if getattr(args, "verification_time", None) is not None:
            from .policy import _parse_iso_utc  # noqa: PLC0415
            if not getattr(args, "policy", None):
                raise ValueError("--verification-time only applies together with --policy (it sets "
                                 "the instant the policy lifecycle is evaluated at)")
            verification_time = _parse_iso_utc(args.verification_time)
            if verification_time is None:
                raise ValueError(f"--verification-time {args.verification_time!r} is not an "
                                 "ISO-8601 timestamp (e.g. 2026-01-01T00:00:00Z)")
            # It is HISTORICAL: a FUTURE instant is not a historical query and would let a policy that
            # is not-yet-valid TODAY be forward-dated into force (Lens-2/3/4/6 review). Reject it — the
            # honest present-tense verdict for a not-yet-valid policy is exit 3 in current mode.
            from datetime import datetime, timezone  # noqa: PLC0415
            if verification_time >= datetime.now(timezone.utc):
                raise ValueError("--verification-time must be in the past — it evaluates the policy AS "
                                 "OF a historical instant; a future instant is not a historical query")
        # A-P0-1: a signed C2SP checkpoint is the ONE authenticated source of BOTH the expected root
        # AND the expected tree size (the atomic tree context). Both flags belong together; a note
        # that parses but does not verify is a verification failure (exit 1), a malformed note is
        # malformed input (exit 2), and an explicit flag conflicting with the checkpoint is ambiguous.
        cp_supplied = getattr(args, "trusted_checkpoint", None) is not None
        cp_vkey = getattr(args, "checkpoint_vkey", None)
        if cp_supplied != (cp_vkey is not None):
            raise ValueError("--trusted-checkpoint and --checkpoint-vkey belong together (the "
                             "signed note and the key that authenticates it)")
        cp_ok = None
        cp_detail = ""
        expected_root = getattr(args, "expected_root", None)
        expected_tree_size = getattr(args, "expected_tree_size", None)
        if cp_supplied:
            assert cp_vkey is not None   # the guard above ties cp_supplied ⇔ cp_vkey present (mypy narrowing)
            import base64 as _b64mod  # noqa: PLC0415
            from .checkpoint import verify_checkpoint  # noqa: PLC0415
            with open(args.trusted_checkpoint, encoding="utf-8") as handle:
                note = handle.read()
            cp_res = verify_checkpoint(note, cp_vkey)   # malformed note/vkey → BundleFormatError → exit 2
            cp_ok = bool(cp_res["ok"])
            if cp_ok:
                cp_root_b64 = _b64mod.b64encode(cp_res["root"]).decode("ascii")
                if expected_root is not None:
                    try:
                        explicit_root = _b64mod.b64decode(expected_root, validate=True)
                    except (ValueError, TypeError) as exc:
                        raise ValueError("--expected-root is not valid base64") from exc
                    if explicit_root != cp_res["root"]:
                        raise ValueError("--expected-root conflicts with the trusted checkpoint's "
                                         "root — ambiguous; supply only one, or make them equal")
                if expected_tree_size is not None and expected_tree_size != cp_res["tree_size"]:
                    raise ValueError("--expected-tree-size conflicts with the trusted checkpoint's "
                                     "tree size — ambiguous; supply only one, or make them equal")
                expected_root = cp_root_b64
                expected_tree_size = cp_res["tree_size"]
                cp_detail = (f"checkpoint origin {cp_res['origin']!r} authenticates "
                             f"(root, tree_size={cp_res['tree_size']}) atomically")
            else:
                cp_detail = ("checkpoint signature does not verify under the supplied vkey — the "
                             "expected root/tree size could not be authenticated (fail-closed)")
        # Resolve the path to a dict ONCE and pass it to both verify_bundle and recompute — a second per-function
        # re-read of the same path reopens a TOCTOU window (release-review consistency fix, mirrors show-eval).
        bundle = load_bundle(args.bundle)
        # WP-B3: crypto FIRST, policy over the crypto result. Load + structurally validate the policy
        # (fail-closed) before verifying, and reconcile the aud VALUE: if BOTH --aud and the policy's
        # expected_aud are set and DIFFER, that is ambiguous → exit 2 (never a silent override).
        effective_aud = flag_aud
        if getattr(args, "policy", None):
            policy = load_policy(resolve_policy_source(args.policy))
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
        result = verify_bundle(bundle, expected_aud=effective_aud, expected_nonce=flag_nonce,
                               expected_root_b64=expected_root,
                               expected_tree_size=expected_tree_size)
        if cp_supplied:
            # a real verification step: a non-verifying checkpoint fails the crypto verdict (exit 1).
            result.add("checkpoint-authenticity", bool(cp_ok), cp_detail)
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
    policy_result = None       # HISTORICAL evaluation (now=verification_time): drives the exit code + POLICY line
    policy_result_now = None   # CURRENT evaluation (now=None): drives safeForAutomation + the tree-context inputs
    if policy is not None and crypto_ok:
        # A-P0-2 §6.3: in historical mode `now` is the explicit --verification-time — the POLICY verdict +
        # exit code answer "was it valid THEN". But safeForAutomation is a PRESENT-tense "safe to act on now"
        # verdict, so its inputs (lifecycle, tree-context, checkpoint validity) MUST use the real current time
        # (Lens-2/3/4/6 review: a not-yet-valid policy or an expired-today checkpoint must never read
        # automation-safe just because a past instant was supplied). We therefore evaluate TWICE in historical
        # mode; in current mode the two coincide (one evaluation, no behaviour change).
        policy_result = evaluate_policy(bundle, result, policy, now=verification_time)
        policy_ok = policy_result["policy_ok"]
        policy_result_now = (policy_result if verification_time is None
                             else evaluate_policy(bundle, result, policy, now=None))
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
    # P0-A §6.3: structured root-authenticity verdicts, folding the policy layer's trusted_roots verdict
    # in when no --expected-root was given. Always separate, so merkle-inclusion is never read as root
    # authentication (additive JSON field + a human line).
    from .bundle import root_authenticity_summary  # noqa: PLC0415
    # P0-B (audit 2026-07-13): thread the vacuous-policy lint into the summary — a PASSING policy that
    # pins no signer ('attributes to nobody') must NOT set safeForAutomation. Computed once here, reused
    # for fields["policy_warnings"] below (no double lint).
    from .policy import policy_warnings as _policy_warnings  # noqa: PLC0415
    # safeForAutomation is a PRESENT-tense verdict, so it reads the CURRENT-time policy evaluation
    # (policy_result_now); in current mode that IS policy_result (Lens-2/3/4/6 review). policy_ok_now is
    # the current-time policy verdict; the exit code + POLICY line keep using the historical policy_ok.
    policy_ok_now = (policy_result_now or {}).get("policy_ok")
    pol_warns = _policy_warnings(policy) if (policy is not None and policy_ok_now) else []
    # AP-1 §5 (+ L2 pre-land review fix): signer_trusted requires an ACTUALLY-PASSED signer-binding check
    # on THIS (eval/verify) path — a passing `policy:signer_allowed` from evaluate_policy — NOT merely the
    # absence of the 'attributes to nobody' warning. That warning counts
    # decision_receipt.trusted_decision_makers as a signer pin, but evaluate_policy (the verify path) never
    # matches the bundle signer against it (that is the verify-decision path); keying off the warning would
    # let a decision-maker-only policy FAKE a trusted signer and yield safeForAutomation:true against an
    # unpinned bundle signer (fail-open). Key off the positive verdict instead.
    # AP-2 §6.2: a RAW template (requiresIdentityOverlay:true) never qualifies (no identity overlay applied).
    _signer_checks = [c for c in (policy_result_now or {}).get("checks", [])
                      if c.get("name") == "policy:signer_allowed"]
    signer_matched = bool(_signer_checks) and all(c.get("ok") for c in _signer_checks)
    signer_trusted = bool(policy_ok_now) and signer_matched
    # AP-2 §6.2/§6.4 (L2 pre-land audit): a RAW template (requiresIdentityOverlay:true) and an EXPIRED policy
    # each force safeForAutomation:false with their OWN honest blocker (TEMPLATE_NOT_INSTANTIATED /
    # POLICY_EXPIRED) — not a mislabelled SIGNER_NOT_PINNED. signer_trusted now reflects ONLY whether a signer
    # was actually matched; the template/expiry conditions are surfaced as distinct blockers.
    _requires_overlay = (policy or {}).get("requiresIdentityOverlay") is True
    from .policy import policy_expired as _policy_expired  # noqa: PLC0415
    from .policy import policy_not_yet_valid as _policy_not_yet_valid  # noqa: PLC0415
    pol_expired = bool(policy is not None and _policy_expired(policy))          # at the REAL current time
    pol_not_yet_valid = bool(policy is not None and _policy_not_yet_valid(policy))  # A-P0-2 not-before mirror
    # A-P0-1 §5.3/§5.4: the atomic tree context. True via (a) a verified --trusted-checkpoint whose
    # (root, size) both match, (b) a policy trusted_checkpoints match at CURRENT time (policy_result_now,
    # so an expired-today checkpoint never authenticates even in historical mode), or (c) an RP-supplied
    # --expected-root + --expected-tree-size PAIR that both passed. A naked root pin stays
    # ROOT_BYTES_ONLY and never authorises automation.
    _by_rs = {c.name: c.ok for c in result.checks}
    _pair_requested = expected_root is not None and expected_tree_size is not None
    _pair_passed = bool(_by_rs.get("root-authenticity")) and bool(_by_rs.get("tree-size"))
    _pol_ctx = (policy_result_now or {}).get("tree_context_authenticated")
    # Any authenticated source that DISAGREES dominates (fail-closed, No-Fake, Lens-1 review F1): if a
    # pinned policy checkpoint says the (root, tree_size) do not match, treeContextAuthenticity is FALSE
    # even when a separately-supplied --expected-root/--expected-tree-size pair happens to pass — the
    # relying party contradicted their own trusted inputs, and the safe verdict is "not authenticated".
    _ctx_false = ((_pol_ctx is False) or (cp_supplied and not cp_ok)
                  or (_pair_requested and not _pair_passed))
    _ctx_true = ((_pol_ctx is True)
                 or (_pair_requested and _pair_passed and (not cp_supplied or cp_ok)))
    if _ctx_false:
        tree_ctx = False
    elif _ctx_true:
        tree_ctx = True
    else:
        tree_ctx = None
    # checkpointAuthenticity reports whether a checkpoint authenticated AND MATCHED this bundle's
    # (root, tree_size) — NOT merely that some pinned checkpoint's signature verified (Lens-3/4 review:
    # a verified-but-non-matching checkpoint must not read PASS, else rootTrustLevel would overclaim
    # CHECKPOINT). PASS only when the checkpoint is the source of a PASS tree context; FAIL when a
    # checkpoint was supplied/pinned but did not authenticate-and-match; NOT_EVALUATED when none supplied.
    _cli_cp_matched = cp_supplied and cp_ok and _pair_passed
    _pol_cp_matched = (policy_result_now or {}).get("tree_context_authenticated") is True
    _cp_present = cp_supplied or ((policy_result_now or {}).get("checkpoint_authenticity") in ("PASS", "FAIL"))
    if not _cp_present:
        cpa = None
    elif _cli_cp_matched or _pol_cp_matched:
        cpa = "PASS"
    else:
        cpa = "FAIL"
    root_summary = root_authenticity_summary(
        result, policy_authenticated_root=(policy_result_now or {}).get("root_authenticated"),
        policy_ok=policy_ok_now, anchor_ok=anchor_required_ok,
        signer_trusted=signer_trusted, policy_warnings=pol_warns, policy_expired=pol_expired,
        policy_not_yet_valid=pol_not_yet_valid,
        requires_identity_overlay=_requires_overlay,
        tree_context_authenticated=tree_ctx, checkpoint_authenticity=cpa)
    fields["root_authenticity"] = root_summary
    # A-P0-2 §6.3: the labelled historical-verification report (additive; absent in current mode).
    verification_time_report = None
    if verification_time is not None:
        # CURRENT_POLICY_STATUS is the present-tense lifecycle verdict (why safeForAutomation can be NO
        # even when the historical verification passes). Expiry and not-before are BOTH surfaced now
        # (Lens-2/3/4/6: not-yet-valid was previously reported as NO_EXPIRY, hiding the real state).
        if pol_expired:
            current_status = "EXPIRED"
        elif pol_not_yet_valid:
            current_status = "NOT_YET_VALID"
        elif policy is not None and _policy_expired(policy) is None and _policy_not_yet_valid(policy) is None:
            current_status = "NO_LIFECYCLE_WINDOW"
        else:
            current_status = "VALID"
        verification_time_report = {
            "mode": "HISTORICAL",
            "time": args.verification_time,
            "current_policy_status": current_status,
            "historical_policy_status": ("PASS" if policy_ok
                                         else "FAIL" if policy_ok is False else "NOT_EVALUATED"),
        }
        fields["verification_time"] = verification_time_report
    # P0-A (audit 2026-07-13): surface --expected-tree-size as a machine-readable object. The check
    # itself already runs INDEPENDENTLY in verify_bundle (never gated on --expected-root), so a mismatch
    # already fails the crypto verdict; this makes status/expected/actual explicit so an integrator can
    # confirm the gate ran rather than inferring it from a check name. NOT_REQUESTED when the flag is absent.
    _ets = expected_tree_size   # effective: an explicit flag OR the checkpoint-derived size (A-P0-1)
    _tsc = next((c for c in result.checks if c.name == "tree-size"), None)
    # A tree-size authentication WAS requested via a checkpoint whose signature did not verify: the
    # checkpoint never yielded an expected size, so no `tree-size` check ran — but reporting
    # NOT_REQUESTED would be dishonest (a request was made, it could not be evaluated). Report FAIL, the
    # honest "requested but unauthenticated" verdict (Lens-3 review; the run already exits 1 on the
    # checkpoint-authenticity failure).
    if _tsc is not None:
        _ts_status = "PASS" if _tsc.ok else "FAIL"
    elif cp_supplied and not cp_ok:
        _ts_status = "FAIL"
    else:
        _ts_status = "NOT_REQUESTED"
    fields["treeSizeExpectation"] = {
        "status": _ts_status,
        "expected": _ets,
        "actual": (bundle.get("merkle") or {}).get("tree_size") if isinstance(bundle, dict) else None,
    }
    if policy is not None:
        fields["policy_id"] = policy.get("policy_id")
        # WP-TP1: non-fatal honesty warnings (e.g. "attributes to nobody") — exit code unchanged.
        # Mirror the human line (six-lens review): the warning is meaningful only for a PASSING
        # policy (a POLICY: OK that attributes to nobody); on FAIL / crypto-FAIL the FAIL is the
        # message, so the JSON field is empty too — the key stays present for contract stability.
        fields["policy_warnings"] = pol_warns   # P0-B: computed once above (no double lint)
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
        # P0-A §6.3: separate the root-authenticity verdicts — merkle-inclusion proves CONSISTENCY under
        # the STATED root, never that the root is authentic. safe-for-automation is true only when the
        # root was affirmatively authenticated (--expected-root or a policy trusted_roots).
        print(f"ROOT-AUTHENTICITY: {root_summary['rootAuthenticity']} "
              f"(payload-signature {root_summary['payloadSignature']}, "
              f"merkle-consistency {root_summary['merkleConsistency']}, "
              f"tree-context {root_summary['treeContextAuthenticity']}, "
              f"root-trust-level {root_summary['rootTrustLevel']}, "
              f"safe-for-automation {str(root_summary['safeForAutomation']).lower()})")
        # AP-1 §5.3: a dedicated, human-legible automation verdict — YES, or NO with the reason(s). The
        # reasons are derived one-for-one from root_summary['automationBlockers'] via the SSOT map, so the
        # human and JSON forms of safeForAutomation can never disagree (Iteration F).
        from .bundle import AUTOMATION_BLOCKER_REASONS  # noqa: PLC0415
        if root_summary["safeForAutomation"]:
            print("SAFE_FOR_AUTOMATION: YES")
        else:
            print("SAFE_FOR_AUTOMATION: NO")
            print("Reason:")
            for _blk in root_summary["automationBlockers"]:
                print(f"  {AUTOMATION_BLOCKER_REASONS.get(_blk, _blk)}")
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
        if verification_time_report is not None:
            # A-P0-2 §6.3: historical mode is LABELLED — the current and the as-of status both show.
            print(f"VERIFICATION_TIME: HISTORICAL ({_safe_line(str(args.verification_time))})")
            print(f"CURRENT_POLICY_STATUS: {verification_time_report['current_policy_status']}")
            print(f"HISTORICAL_POLICY_STATUS: {verification_time_report['historical_policy_status']}")
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
    from .evalclaim import EvalClaimError  # noqa: PLC0415
    try:
        return run_demo(as_json=args.json)
    except EvalClaimError as exc:
        # F10 (2026-07-12): `demo` emits an eval receipt, which needs the RFC 8785 canonicalizer from the
        # [eval] extra. On a bare install that raised a raw traceback; surface the clean, actionable message
        # (it already names the install command) with a non-zero exit instead.
        print(f"proofbundle demo: {exc}", file=sys.stderr)
        return 2


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


def _cmd_evalcard(args: argparse.Namespace) -> int:
    from .evalcard import evaluation_card_hash, verify_evaluation_card  # noqa: PLC0415
    try:
        if args.check is not None:
            from .evalclaim import decode_eval_claim  # noqa: PLC0415
            # Mirrors _cmd_prereg's release-review CRITICAL fix: --check MUST verify the receipt
            # (Ed25519 + Merkle) BEFORE trusting its evaluation_card_sha256 — reading an
            # UNAUTHENTICATED claim would let a forged/unsigned bundle with a doctored digest PASS.
            claim = decode_eval_claim(args.check)
            if claim is None:
                print("=> FAILED: not a valid, issuer-bound eval receipt", file=sys.stderr)
                return 1
            res = verify_evaluation_card(args.card, claim)
            if args.json:
                print(json.dumps(res))
            else:
                print(f"[{'PASS' if res['ok'] else 'FAIL'}] evalcard: {res['detail']}")
            return 0 if res["ok"] else 1
        h = evaluation_card_hash(args.card)
        if args.json:
            print(json.dumps({"evaluation_card_sha256": h}))
        else:
            print(h)
            print("place this in the eval claim's evaluation_card_sha256 BEFORE signing the receipt",
                  file=sys.stderr)
        return 0
    except (ProofBundleError, OSError, ValueError, KeyError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


# ── anchor operations (WP-A/B/C): OpenTimestamps evidence-pack lifecycle ─────────────────────────────
def _resolve_canonical_root(args: argparse.Namespace) -> bytes:
    """The exact 32-byte root the OTS proof must commit to: SHA-256 of ``--target-file`` OR the raw
    ``--canonical-root-hex``. Exactly one is required (malformed input → ValueError → exit 2)."""
    import hashlib  # noqa: PLC0415
    tf = getattr(args, "target_file", None)
    rh = getattr(args, "canonical_root_hex", None)
    if tf and rh:
        raise ValueError("give either --target-file or --canonical-root-hex, not both")
    if tf:
        with open(tf, "rb") as handle:
            return hashlib.sha256(handle.read()).digest()
    if rh:
        root = bytes.fromhex(rh.strip().lower())
        if len(root) != 32:
            raise ValueError("--canonical-root-hex must be a 32-byte (64 hex char) SHA-256")
        return root
    raise ValueError("need --target-file or --canonical-root-hex (the exact bytes the proof stamps)")


def _parse_bundled_headers(specs) -> dict:
    """Parse repeatable ``HEIGHT:MERKLEROOT_HEX`` into a ``{height: root_hex}`` map for the pack's frozen
    EVIDENCE block (WP-A1: producer-controlled, never trusted at verify). Malformed → ValueError."""
    out: dict = {}
    for spec in specs or []:
        if ":" not in spec:
            raise ValueError(f"--bundled-header {spec!r}: expected HEIGHT:MERKLEROOT_HEX")
        height, _, root_hex = spec.partition(":")
        height, root_hex = height.strip(), root_hex.strip().lower()
        if not height.isdigit():
            raise ValueError(f"--bundled-header {spec!r}: height must be a non-negative integer")
        try:
            if len(bytes.fromhex(root_hex)) != 32:
                raise ValueError
        except ValueError as exc:
            raise ValueError(f"--bundled-header {spec!r}: merkle root must be 32-byte hex") from exc
        out[height] = root_hex
    return out


def _cmd_anchor_upgrade(args: argparse.Namespace) -> int:
    """WP-A1: bundle an UPGRADED OpenTimestamps proof into a self-contained, calendar-independent
    evidence pack. A still-PENDING proof is refused (exit 3, never a fake pass): upgrading it (embedding
    the Bitcoin block-header path) needs the OpenTimestamps client + a Bitcoin confirmation, which is
    time-gated and outside this tool. Structural binding is fail-closed here (exit 2 on unbound)."""
    from .anchors_ots import verify_opentimestamps  # noqa: PLC0415
    from .evidence_pack import (  # noqa: PLC0415
        build_evidence_pack, describe_proof, ots_upgraded_proof_is_self_contained,
    )
    try:
        with open(args.proof, "rb") as handle:
            proof = handle.read()
        canonical_root = _resolve_canonical_root(args)
        # fail-closed structural binding: the proof MUST commit to exactly this root (a mismatch is a
        # malformed request, not a lifecycle state). needs_rp_trust/pending here are fine — they mean
        # bound-but-not-yet-confirmed; only unbound/malformed are hard binding errors.
        binding = verify_opentimestamps(proof, canonical_root, frozen={})
        if binding["status"] in ("unbound", "malformed", "no_lib"):
            print(f"ERROR: {binding['detail']}", file=sys.stderr)
            return 2
        info = describe_proof(proof)
        if not ots_upgraded_proof_is_self_contained(proof):
            # §7.1 invariant at the CLI: PENDING (or empty) is never a pass and never gets a pack.
            msg = {"schema": "proofbundle.anchor_upgrade.v1", "ok": False, "wrote": None,
                   "state": info["state"], "selfContained": False,
                   "detail": ("proof is not upgraded yet — no self-contained pack written. Upgrading a "
                              "pending proof embeds the Bitcoin block-header path and needs the "
                              "OpenTimestamps client after a Bitcoin confirmation (time-gated): run "
                              "`ots upgrade <proof>.ots`, then re-run `proofbundle anchor upgrade`."),
                   "provenCalendars": info["provenCalendars"],
                   "provenCalendarOperators": info["provenCalendarOperators"]}
            if getattr(args, "json", False):
                print(json.dumps(msg, indent=2, ensure_ascii=False))
            else:
                print(f"[anchor upgrade] NOT UPGRADED ({info['state']}) — {msg['detail']}")
                if info["provenCalendars"]:
                    print(f"  calendars carrying it: {', '.join(info['provenCalendars'])} "
                          f"(operators: {', '.join(info['provenCalendarOperators'])})")
            return 3
        declared = list(getattr(args, "calendar_declared", None) or [])
        bundled = _parse_bundled_headers(getattr(args, "bundled_header", None))
        pack = build_evidence_pack(canonical_root, proof, declared_calendars=declared or None,
                                   bundled_headers=bundled or None)
        with open(args.out, "w", encoding="utf-8") as handle:
            json.dump(pack, handle, indent=2, ensure_ascii=False)
            handle.write("\n")
        report = {"schema": "proofbundle.anchor_upgrade.v1", "ok": True, "wrote": args.out,
                  "state": "upgraded", "selfContained": True,
                  "bitcoinHeights": info["bitcoinHeights"],
                  # provenCalendars = read from the proof's own attestations — an embedded-but-UNVERIFIED
                  # transparency hint (a PendingAttestation URI is unauthenticated, offline-constructible),
                  # NOT cryptographic evidence; declared = producer testimony (verified:false)
                  "provenCalendars": pack["provenCalendars"],
                  "provenCalendarOperators": pack["provenCalendarOperators"],
                  "operatorRedundancy": pack["operatorRedundancy"],
                  "declaredCalendars": pack.get("declaredCalendars", []),
                  "declaredCalendarsVerified": pack.get("declaredCalendarsVerified", False),
                  "bundledHeaderEvidence": pack["bundledHeaderEvidence"],
                  "detail": ("self-contained evidence pack written — verifiable OFFLINE against a "
                             "relying-party Bitcoin header, no calendar needed")}
        if getattr(args, "json", False):
            print(json.dumps(report, indent=2, ensure_ascii=False))
        else:
            print(f"[anchor upgrade] OK — self-contained pack written to {args.out}")
            print(f"  Bitcoin height(s): {report['bitcoinHeights']}  ·  "
                  f"operator redundancy embedded in the proof (UNVERIFIED transparency hint, "
                  f"not audit evidence): {report['operatorRedundancy']} "
                  f"{report['provenCalendarOperators']}")
            if report["declaredCalendars"]:
                print(f"  declared calendars (producer-claimed, UNVERIFIED, not audit evidence): "
                      f"{', '.join(report['declaredCalendars'])}")
            print("  verify offline:  proofbundle anchor verify-pack "
                  f"{args.out} --bitcoin-header <HEIGHT:MERKLEROOT_HEX>")
        return 0
    except (ProofBundleError, OSError, ValueError, KeyError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


def _cmd_anchor_verify_pack(args: argparse.Namespace) -> int:
    """WP-A2/WP-C: verify an evidence pack OFFLINE (no network, no calendar). Confirms only against a
    relying-party Bitcoin header (``--bitcoin-header``; the pack's own bundled header is never trusted).
    Exit 0 confirmed · 3 pending / needs-relying-party-header (honest not-pass) · 1 hard fail
    (unbound / block mismatch / malformed pack) · 2 malformed input."""
    import base64 as _b64  # noqa: PLC0415

    from .evidence_pack import describe_proof, verify_evidence_pack  # noqa: PLC0415
    try:
        with open(args.pack, encoding="utf-8") as handle:
            pack = json.load(handle)
        if not isinstance(pack, dict):
            raise ValueError("evidence pack must be a JSON object")
        rp = _build_rp_trust(args)   # bitcoin headers (relying-party trust material)
        res = verify_evidence_pack(pack, rp_trust=rp)
        # No-Fake (Berkeley audit follow-up, 2026-07-17): NEVER echo the pack's own calendar/self-contained
        # fields into the authoritative report — a hand-edited pack can set operatorRedundancy /
        # provenCalendars / selfContained to anything (live repro: operatorRedundancy=3 with fabricated
        # operators under exit 0). RECOMPUTE them from the PROOF BYTES, exactly as `anchor inspect` does, so
        # the report reflects what the proof actually carries, not what the JSON claims. (These embedded
        # calendar figures remain UNVERIFIED transparency hints — a PendingAttestation URI is unauthenticated
        # and offline-constructible — NOT cryptographic redundancy evidence; see build_evidence_pack.)
        recomputed = {"selfContained": False, "provenCalendars": [],
                      "provenCalendarOperators": [], "operatorRedundancy": 0}
        try:
            info = describe_proof(_b64.b64decode(pack["proof"], validate=True))
            recomputed = {"selfContained": bool(info["selfContained"]),
                          "provenCalendars": info["provenCalendars"],
                          "provenCalendarOperators": info["provenCalendarOperators"],
                          "operatorRedundancy": int(info["operatorRedundancy"])}
        except (KeyError, ValueError, TypeError):
            pass   # malformed/absent proof — verify_evidence_pack already returns a non-pass; keep safe zeros
        out = {"schema": "proofbundle.anchor_verify_pack.v1", "ok": bool(res.get("ok")),
               "status": res.get("status"), "warn": bool(res.get("warn")),
               "selfContained": recomputed["selfContained"],
               "provenCalendars": recomputed["provenCalendars"],
               "provenCalendarOperators": recomputed["provenCalendarOperators"],
               "operatorRedundancy": recomputed["operatorRedundancy"],
               # declaredCalendars are producer testimony, surfaced as documentation, never as evidence.
               # declaredCalendarsVerified is FORCED False (never mirrored from the pack): declared is
               # unverified BY DEFINITION, and a hand-edited pack must not flip it true — same
               # recompute-over-echo principle as the calendar fields above (No-Fake, 2026-07-17).
               "declaredCalendars": pack.get("declaredCalendars", []),
               "declaredCalendarsVerified": False,
               "detail": res.get("detail", "")}
        for f in ("rp_trusted", "needs_rp_trust", "frozenEvidence", "trustedTime"):
            if f in res:
                out[f] = res[f]
        if getattr(args, "json", False):
            print(json.dumps(out, indent=2, ensure_ascii=False))
        else:
            verdict = "CONFIRMED" if out["ok"] else out["status"].upper()
            print(f"[anchor verify-pack] {verdict} — {out['detail']}")
        if out["ok"]:
            return 0
        # pending / needs-RP-header: not corruption, but the relying-party gate is unmet (mirrors
        # verify --require-anchor exit 3). A hard fail (unbound/mismatch/malformed pack) is exit 1.
        if res.get("warn") or res.get("status") in ("needs_rp_trust", "upgraded_unverified", "pending"):
            return 3
        return 1
    except (ProofBundleError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2


def _cmd_anchor_inspect(args: argparse.Namespace) -> int:
    """WP-B1 transparency: print the lifecycle state (pending/upgraded/self-contained) and the
    calendars/operators carrying an OpenTimestamps proof (.ots) or evidence pack. Read-only, no crypto
    trust — it reports state, it never confirms. Exit 0 unless the file cannot be read (exit 2)."""
    import base64 as _b64  # noqa: PLC0415
    from .evidence_pack import describe_proof  # noqa: PLC0415
    try:
        with open(args.path, "rb") as handle:
            raw = handle.read()
        pack = None
        try:
            maybe = json.loads(raw.decode("utf-8"))
            if isinstance(maybe, dict) and maybe.get("type") == "opentimestamps-evidence-pack":
                pack = maybe
        except (ValueError, UnicodeDecodeError):
            pack = None
        if pack is not None:
            proof = _b64.b64decode(pack["proof"], validate=True)
            info = describe_proof(proof)
            info["source"] = "evidence_pack"
            # No-Fake (2026-07-17): do NOT mirror the pack's own selfContained claim. `describe_proof`
            # already returns the AUTHORITATIVE `selfContained`, recomputed from the proof bytes; echoing a
            # second, raw, hand-editable `packSelfContained` field only invites a producer to contradict the
            # recomputed truth (the old field is dropped — the recomputed `info["selfContained"]` stands).
            # No-Fake (Berkeley audit 2026-07-16): the PROVEN calendars come from describe_proof (the proof
            # itself). An upgraded proof retains none, and we do NOT borrow the producer's declared list into
            # operatorRedundancy — that would surface unverified testimony as evidence. Declared calendars are
            # shown SEPARATELY, always flagged unverified.
            declared = list(pack.get("declaredCalendars") or [])
            if declared:
                info["declaredCalendars"] = declared
                info["declaredCalendarOperators"] = list(pack.get("declaredCalendarOperators") or [])
                # declaredCalendarsVerified is FORCED False, never mirrored from the pack: declared is
                # unverified BY DEFINITION, and a hand-edited pack must not flip it true — consistent with
                # verify-pack (which forces it False for the same reason).
                info["declaredCalendarsVerified"] = False
        else:
            info = describe_proof(raw)
            info["source"] = "ots_proof"
        info["schema"] = "proofbundle.anchor_inspect.v1"
        if getattr(args, "json", False):
            print(json.dumps(info, indent=2, ensure_ascii=False))
        else:
            print(f"[anchor inspect] state={info['state']}  self-contained={info['selfContained']}  "
                  f"heights={info['bitcoinHeights']}")
            if info["provenCalendars"]:
                print(f"  calendars embedded in the proof (UNVERIFIED transparency hint, not audit "
                      f"evidence): {', '.join(info['provenCalendars'])}")
                print(f"  distinct operators (UNVERIFIED transparency hint): "
                      f"{', '.join(info['provenCalendarOperators'])} "
                      f"(operator redundancy {info['operatorRedundancy']})")
            else:
                print("  calendars embedded in the proof: none retained "
                      "(an upgraded proof no longer needs a calendar to verify)")
            if info.get("declaredCalendars"):
                print(f"  declared calendars (producer-claimed, UNVERIFIED, not audit evidence): "
                      f"{', '.join(info['declaredCalendars'])}")
        return 0
    except (OSError, KeyError, ValueError, TypeError) as exc:
        # TypeError: fail-closed on a non-string declaredCalendars item reaching str.join (a
        # hand-edited pack could carry [123]) — exit 2, never a raw traceback (No-Fake, 2026-07-17).
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


def _load_related(paths, pub: bytes, related_pubs=None) -> tuple[dict, list[str]]:
    """relation/v0.1 (--with-related): load DSSE envelopes of RELATED receipts, verify each one
    STANDALONE and key it by its computed content root. Same-key is the default v0.1 contract; WP-A
    (3.4.0) adds POSITION-PAIRED per-target keys via ``--related-pub`` so cross-issuer chains can be
    verified: the i-th ``--related-pub`` is the key the i-th ``--with-related`` target verifies under
    (an empty/absent entry falls back to the main ``pub`` = same-key). Each entry records
    ``verified_under`` (the base64 key the target ACTUALLY verified under — relation_signer checks
    against this, never a claim) and ``subject_digest`` (the target's subject digest — WP-A2/O2
    gegenprobe). A file that fails to load is a usage error (exit 2); an envelope that loads but does
    NOT verify is kept with verified=False, so an attached-but-wrong target FAILS lineage."""
    import base64  # noqa: PLC0415
    from . import anchors as _anchors_mod  # noqa: PLC0415
    from . import dsse as _dsse  # noqa: PLC0415
    from .relation import _SHA256_HEX as _RELATION_SHA256_HEX  # noqa: PLC0415
    related: dict = {}
    errs: list[str] = []
    paths = paths or []
    related_pubs = related_pubs or []
    for i, path in enumerate(paths):
        # position-paired per-target key; empty string or missing = same-key (main pub).
        rp_b64 = related_pubs[i] if i < len(related_pubs) else None
        try:
            verify_key = base64.b64decode(rp_b64, validate=True) if rp_b64 else pub
        except (ValueError, TypeError) as exc:
            errs.append(f"cannot decode --related-pub for {path}: {exc}")
            continue
        try:
            with open(path, encoding="utf-8") as handle:
                env = loads_strict(handle.read())   # WP-C1: duplicate keys rejected
            body = _dsse.load_payload(env)
            root_hex = _anchors_mod.statement_content_root(body).hex()
            # L3-audit fix: inside the try so a malformed-envelope error names the offending file too.
            verified = bool(_dsse.verify_envelope(env, verify_key,
                                                  payload_type="application/vnd.in-toto+json"))
        except (ProofBundleError, OSError, ValueError) as exc:
            errs.append(f"cannot read --with-related {path}: {exc}")
            continue
        rels = None
        subject_digest = None
        # PB-2026-0717-01: classify the target's actual subject state so the verifier fails closed
        # on absent/ambiguous/malformed. NEVER silently pick subject[0] from a multi-subject
        # statement (that was the resolver half of the subject-pin fail-open). "absent" is the
        # fail-closed default if the statement cannot even be parsed.
        subject_digest_state = "absent"
        try:
            stmt = loads_strict(body.decode("utf-8"))
            if isinstance(stmt, dict) and isinstance(stmt.get("predicate"), dict):
                rels = stmt["predicate"].get("relationships")
            # WP-A2/O2: the target statement's own subject digest (subject[0].digest.sha256) — the
            # ground truth the edge's optional targetSubjectDigest is gegengeprueft against.
            subj = stmt.get("subject") if isinstance(stmt, dict) else None
            if not isinstance(subj, list) or not subj:
                subject_digest_state = "absent"
            elif len(subj) != 1:
                subject_digest_state = "ambiguous"   # multiple subjects — do NOT bind subject[0]
            elif (isinstance(subj[0], dict) and isinstance(subj[0].get("digest"), dict)
                  and isinstance(subj[0]["digest"].get("sha256"), str)
                  and _RELATION_SHA256_HEX.match(subj[0]["digest"]["sha256"])):
                subject_digest = subj[0]["digest"]["sha256"]
                subject_digest_state = "present"
            else:
                subject_digest_state = "malformed"   # single subject but no well-formed sha-256
        except (ProofBundleError, ValueError):
            rels = None
            subject_digest_state = "absent"
        related[root_hex] = {
            "verified": verified, "relationships": rels,
            "verified_under": base64.b64encode(verify_key).decode(),
            "subject_digest": subject_digest,
            "subject_digest_state": subject_digest_state,
        }
    return related, errs


def _cmd_decision_verify(args: argparse.Namespace) -> int:
    import base64  # noqa: PLC0415
    from .decision import verify_decision_receipt  # noqa: PLC0415
    if not args.pub:
        print("ERROR: --pub <base64 Ed25519 public key> is required", file=sys.stderr)
        return 2
    policy = None
    if args.policy:
        from .policy import PolicyError, load_policy  # noqa: PLC0415
        from .policy_profiles import resolve_policy_source  # noqa: PLC0415
        try:
            # parity with the eval verify path (L5 audit L5-F3): accept a packaged profile NAME
            # (e.g. decision-receipt-template-v1), not only a file path, via resolve_policy_source.
            policy = load_policy(resolve_policy_source(args.policy))
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
        related, rel_errs = _load_related(getattr(args, "with_related", None), pub,
                                          getattr(args, "related_pub", None))
        if rel_errs:
            for e in rel_errs:
                print(f"ERROR: {e}", file=sys.stderr)
            return 2
        result = verify_decision_receipt(env, pub, strict=args.strict, expected_audience=args.aud,
                                         expected_nonce=args.nonce, policy=policy, anchors=anchors,
                                         rp_trust=rp_trust,
                                         require_derived_subject=args.require_derived_subject,
                                         related=related or None)
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
            "action_outcome_proven", "subject_binding", "subject_derived_ok",
            # Findings 01/03 (crypto-review X2): the uniform automation verdict + EvidenceLevel ladder are
            # part of the library result; a pipeline doing `... --json | jq .automation.safeForAutomation`
            # must not get null (indistinguishable from a real "not evaluated"). Emit them here too.
            "automation", "evidence_levels", "lineage", "relations_policy_codes", "warnings", "errors",
        ) if k in result}
        print(json.dumps(report, indent=2, default=str))
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
        if result["subject_binding"] is not None:
            print(f"SUBJECT: {result['subject_binding']['mode']}")
        if result["subject_derived_ok"] is not None:
            print(f"SUBJECT_DERIVED: {'OK' if result['subject_derived_ok'] else 'FAIL'}")
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
    # Finding 05: a caller who explicitly requests --require-derived-subject is asking for the same kind of
    # fail-closed binding as --aud/--nonce — an EXTERNAL_ATTESTED subject then must not exit 0.
    if result["subject_derived_ok"] is False:
        return 2
    # A supplied anchor that FAILS to verify (broken / root-mismatched / unknown type) is a tamper
    # signal — fail-closed, never a silent exit 0 (fix-review Finding 3). None = no anchor supplied.
    if result["anchors_ok"] is False:
        return 1
    # relation/v0.1: a REQUESTED lineage check (edges present or --with-related supplied) that FAILs
    # (cycle, depth, malformed ancestor, attached-but-unverified target) is a tamper/structure signal —
    # fail-closed exit 2, never a silent exit 0. DECLARED_UNRESOLVED stays exit 0 (declared-only is honest).
    if isinstance(result.get("lineage"), dict) and result["lineage"].get("lineage") == "FAIL":
        return 2
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


# ── Action Outcome Receipt (3.2.0, action-outcome/v0.1, EXPERIMENTAL) ──────────
def _cmd_outcome_init(args: argparse.Namespace) -> int:
    template = {
        "schemaVersion": "0.1.0",
        "outcomeId": "urn:uuid:00000000-0000-0000-0000-000000000000",
        "decisionRef": {"sha256": "0" * 64},
        "executor": {"id": "executor://example/runner", "keyId": ""},
        "requestedActionDigest": {"sha256": "0" * 64},
        "actualActionDigest": {"sha256": "0" * 64},
        "responseDigest": {"sha256": "0" * 64},
        "effectDigest": {"sha256": "0" * 64},
        "status": "executed",
        "performedAt": "2026-01-01T00:00:00Z",
        "policyPurpose": "outcome",
        "traceContext": {"traceparent": ""},
        "limitations": [],
    }
    out = json.dumps(template, indent=2, ensure_ascii=False)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(out + "\n")
        print(f"wrote outcome predicate template {args.out}")
    else:
        print(out)
    return 0


def _cmd_outcome_emit(args: argparse.Namespace) -> int:
    from .outcome import OutcomeReceiptError, emit_outcome_receipt  # noqa: PLC0415
    signer = _resolve_signer(args)
    if signer is None:
        return 2
    try:
        with open(args.predicate, encoding="utf-8") as handle:
            predicate = loads_strict(handle.read())   # WP-C1: a duplicate key must never be signed
        env = emit_outcome_receipt(predicate, signer, strict=not args.lenient)
    except (OutcomeReceiptError, ProofBundleError, OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(env, handle, indent=2)
        handle.write("\n")
    print(f"wrote outcome receipt {args.out}")
    return 0


def _cmd_outcome_verify(args: argparse.Namespace) -> int:
    import base64  # noqa: PLC0415
    from .outcome import verify_outcome_receipt  # noqa: PLC0415
    if not args.pub:
        print("ERROR: --pub <base64 Ed25519 public key> is required", file=sys.stderr)
        return 2
    policy = None
    if getattr(args, "policy", None):
        # WP-B (3.4.0): the outcome path enforces the trust-policy `relations` section identically to
        # the decision path (require_relation_resolution / reject_superseded / relation_signer /
        # require_relation_target). trust_pack role auth is separate and unchanged.
        from .policy import PolicyError, load_policy  # noqa: PLC0415
        from .policy_profiles import resolve_policy_source  # noqa: PLC0415
        try:
            policy = load_policy(resolve_policy_source(args.policy))
        except PolicyError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2
    try:
        with open(args.envelope, encoding="utf-8") as handle:
            env = loads_strict(handle.read())   # WP-C1: duplicate keys rejected
        pub = base64.b64decode(args.pub)
        related, rel_errs = _load_related(getattr(args, "with_related", None), pub,
                                          getattr(args, "related_pub", None))
        if rel_errs:
            for e in rel_errs:
                print(f"ERROR: {e}", file=sys.stderr)
            return 2
        result = verify_outcome_receipt(
            env, pub, strict=args.strict,
            expected_decision_ref=args.expected_decision_ref, decision_maker_id=args.decision_maker_id,
            expected_audience=args.aud, expected_nonce=args.nonce,
            require_derived_subject=args.require_derived_subject, related=related or None,
            policy=policy)
    except (ProofBundleError, OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    if args.json:
        report = {k: result[k] for k in (
            "ok", "crypto_ok", "structure_ok", "predicate_type_ok", "decision_bound", "role_separation_ok",
            "execution_proven", "audience_ok", "nonce_ok", "subject_binding", "subject_derived_ok",
            # Findings 01/03/16 (crypto-review X2): uniform automation verdict + EvidenceLevel ladder +
            # receiver-corroboration fields are part of the library result — emit them so a --json consumer
            # is not silently blind to them (a jq filter on an absent key is indistinguishable from a real
            # None). executor_role_trusted/receiver_* are None unless the caller supplied a trust_pack.
            "automation", "evidence_levels", "executor_role_trusted", "receiver_bound", "receiver_role_trusted",
            # WP-B: the relations trust-policy verdict on the outcome path (mirrors decision --json).
            "lineage", "policy_ok", "relations_policy_codes", "warnings", "errors",
        ) if k in result}
        print(json.dumps(report, indent=2, default=str))
    else:
        print(f"CRYPTO: {'OK' if result['crypto_ok'] else 'FAIL'}")
        print(f"STRUCTURE: {'OK' if result['structure_ok'] else 'FAIL'}")
        if result["policy_ok"] is not None:
            print(f"POLICY: {'OK' if result['policy_ok'] else 'FAIL'}")
        if result["decision_bound"] is not None:
            print(f"DECISION_BINDING: {'OK' if result['decision_bound'] else 'MISMATCH'}")
        if result["role_separation_ok"] is not None:
            print(f"ROLE_SEPARATION: {'OK' if result['role_separation_ok'] else 'VIOLATED'}")
        if result["audience_ok"] is not None:
            print(f"AUDIENCE: {'OK' if result['audience_ok'] else 'MISMATCH'}")
        if result["nonce_ok"] is not None:
            print(f"NONCE: {'OK' if result['nonce_ok'] else 'MISMATCH'}")
        if result["execution_proven"] is False:
            print("ASSURANCE: status=executed is self-asserted (no effectDigest/actualActionDigest)")
        if result["subject_binding"] is not None:
            print(f"SUBJECT: {result['subject_binding']['mode']}")
        if result["subject_derived_ok"] is not None:
            print(f"SUBJECT_DERIVED: {'OK' if result['subject_derived_ok'] else 'FAIL'}")
        for e in result["errors"]:
            print(f"  - {e}", file=sys.stderr)
        for w in result["warnings"]:
            print(f"  ! {w}", file=sys.stderr)
        if result["crypto_ok"]:
            print("\nThis proves who signed what happened, bound to the referenced decision. It does not prove "
                  "the effect was good, correct or desired.")
        else:
            print("\nThis receipt did NOT verify (crypto failure); nothing about the outcome is attested.")
    # Exit contract mirrors decision verify: 1 crypto · 2 malformed/confusion/binding-mismatch · 3 policyPurpose.
    if not result["crypto_ok"]:
        return 1
    if not result["structure_ok"]:
        return 2
    if result["decision_bound"] is False or result["role_separation_ok"] is False:
        return 2
    if result["audience_ok"] is False or result["nonce_ok"] is False:
        return 2
    # Finding 05: a caller who explicitly requests --require-derived-subject is asking for the same kind of
    # fail-closed binding as --aud/--nonce — an EXTERNAL_ATTESTED subject then must not exit 0.
    if result["subject_derived_ok"] is False:
        return 2
    # relation/v0.1 (adversarial-review finding, 2026-07-16): mirror of the decision-verify gate —
    # a REQUESTED lineage check (--with-related / edges present) that FAILs must never exit 0.
    if isinstance(result.get("lineage"), dict) and result["lineage"].get("lineage") == "FAIL":
        return 2
    # WP-B: the relations trust-policy gate is exit-3 class, IDENTICAL to the decision path
    # (RELATION_SIGNER_UNAUTHORIZED / RELATION_TARGET_MISMATCH / LINEAGE_REQUIREMENT_FAILED).
    if result["policy_ok"] is False:
        return 3
    return 0


def _cmd_outcome_inspect(args: argparse.Namespace) -> int:
    import base64  # noqa: PLC0415
    try:
        with open(args.receipt, encoding="utf-8") as handle:
            obj = loads_strict(handle.read())   # WP-C1
    except (ProofBundleError, OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    try:
        statement = loads_strict(base64.b64decode(obj["payload"])) if isinstance(obj, dict) and "payload" in obj else obj
    except (ProofBundleError, ValueError, TypeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    predicate = statement.get("predicate", statement) if isinstance(statement, dict) else statement
    print(json.dumps(predicate, indent=2, ensure_ascii=False))
    return 0


# ── relation-statement (3.5.0, relation-statement/v0.1, EXPERIMENTAL) ──────────
def _cmd_relation_statement_init(args: argparse.Namespace) -> int:
    template = {
        "schemaVersion": "0.1.0",
        "statementId": "urn:uuid:00000000-0000-0000-0000-000000000000",
        "relationships": [{
            "relation": "retracts",
            "targetReceiptDigest": {"digestAlgorithm": "jcs-sha256-v1", "digest": "0" * 64},
            "reasonCode": "withdrawal",
            "reason": "",
            "declaredAt": "2026-01-01T00:00:00Z",
        }],
    }
    out = json.dumps(template, indent=2, ensure_ascii=False)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(out + "\n")
        print(f"wrote relation-statement predicate template {args.out}")
    else:
        print(out)
    return 0


def _cmd_relation_statement_emit(args: argparse.Namespace) -> int:
    from .relation_statement import RelationStatementError, emit_relation_statement  # noqa: PLC0415
    signer = _resolve_signer(args)
    if signer is None:
        return 2
    try:
        with open(args.predicate, encoding="utf-8") as handle:
            predicate = loads_strict(handle.read())   # WP-C1: a duplicate key must never be signed
        env = emit_relation_statement(predicate, signer)
    except (RelationStatementError, ProofBundleError, OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(env, handle, indent=2)
        handle.write("\n")
    print(f"wrote relation statement {args.out}")
    return 0


def _cmd_relation_statement_verify(args: argparse.Namespace) -> int:
    import base64  # noqa: PLC0415
    from .relation_statement import verify_relation_statement  # noqa: PLC0415
    if not args.pub:
        print("ERROR: --pub <base64 Ed25519 public key> is required", file=sys.stderr)
        return 2
    policy = None
    if getattr(args, "policy", None):
        from .policy import PolicyError, load_policy  # noqa: PLC0415
        from .policy_profiles import resolve_policy_source  # noqa: PLC0415
        try:
            policy = load_policy(resolve_policy_source(args.policy))
        except PolicyError as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 2
    try:
        with open(args.envelope, encoding="utf-8") as handle:
            env = loads_strict(handle.read())   # WP-C1: duplicate keys rejected
        pub = base64.b64decode(args.pub)
        related, rel_errs = _load_related(getattr(args, "with_related", None), pub,
                                          getattr(args, "related_pub", None))
        if rel_errs:
            for e in rel_errs:
                print(f"ERROR: {e}", file=sys.stderr)
            return 2
        result = verify_relation_statement(
            env, pub, strict=args.strict,
            require_derived_subject=args.require_derived_subject,
            related=related or None, policy=policy)
    except (ProofBundleError, OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    if args.json:
        report = {k: result[k] for k in (
            "ok", "crypto_ok", "structure_ok", "predicate_type_ok", "subject_binding",
            "subject_derived_ok", "lineage", "policy_ok", "relations_policy_codes",
            "warnings", "errors",
        ) if k in result}
        print(json.dumps(report, indent=2, default=str))
    else:
        print(f"CRYPTO: {'OK' if result['crypto_ok'] else 'FAIL'}")
        print(f"STRUCTURE: {'OK' if result['structure_ok'] else 'FAIL'}")
        if result["policy_ok"] is not None:
            print(f"POLICY: {'OK' if result['policy_ok'] else 'FAIL'}")
        if isinstance(result.get("lineage"), dict):
            print(f"LINEAGE: {result['lineage'].get('lineage')}")
        if result["subject_binding"] is not None:
            print(f"SUBJECT: {result['subject_binding']['mode']}")
        if result["subject_derived_ok"] is not None:
            print(f"SUBJECT_DERIVED: {'OK' if result['subject_derived_ok'] else 'FAIL'}")
        for e in result["errors"]:
            print(f"  - {e}", file=sys.stderr)
        for w in result["warnings"]:
            print(f"  ! {w}", file=sys.stderr)
        if result["crypto_ok"]:
            print("\nThis proves the issuer DECLARED the relation over exact bytes. It does not "
                  "retract the target's cryptographic validity, and whether the issuer may declare "
                  "it is a relying-party policy decision.")
        else:
            print("\nThis statement did NOT verify (crypto failure); nothing about the relation is "
                  "attested.")
    # Exit contract mirrors decision/outcome verify: 1 crypto · 2 malformed/confusion/lineage-FAIL · 3 policy.
    if not result["crypto_ok"]:
        return 1
    if not result["structure_ok"]:
        return 2
    if result["subject_derived_ok"] is False:
        return 2
    if isinstance(result.get("lineage"), dict) and result["lineage"].get("lineage") == "FAIL":
        return 2
    if result["policy_ok"] is False:
        return 3
    return 0


def _cmd_relation_statement_inspect(args: argparse.Namespace) -> int:
    import base64  # noqa: PLC0415
    try:
        with open(args.receipt, encoding="utf-8") as handle:
            obj = loads_strict(handle.read())   # WP-C1
    except (ProofBundleError, OSError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    try:
        statement = loads_strict(base64.b64decode(obj["payload"])) if isinstance(obj, dict) and "payload" in obj else obj
    except (ProofBundleError, ValueError, TypeError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    predicate = statement.get("predicate", statement) if isinstance(statement, dict) else statement
    print(json.dumps(predicate, indent=2, ensure_ascii=False))
    return 0


def _cmd_policy_explain(args: argparse.Namespace) -> int:
    from .policy import PolicyError, explain_policy, load_policy, policy_warnings  # noqa: PLC0415
    from .policy_profiles import resolve_policy_source  # noqa: PLC0415
    try:
        policy = load_policy(resolve_policy_source(args.policy))
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
    from .policy_profiles import resolve_policy_source  # noqa: PLC0415
    try:
        policy = load_policy(resolve_policy_source(args.policy))
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


def _cmd_policy_list_profiles(args: argparse.Namespace) -> int:
    from .policy import explain_policy, load_policy  # noqa: PLC0415
    from .policy_profiles import list_profiles, profile_aliases, profile_path  # noqa: PLC0415
    aliases = profile_aliases()
    # canonical -> [deprecated old names] so each canonical row can list what still resolves to it.
    canonical_aliases: dict = {}
    for old, canonical in aliases.items():
        canonical_aliases.setdefault(canonical, []).append(old)
    rows = []
    for name in list_profiles():   # AP-2 §6.1: canonical names FIRST
        # load via the packaged file directly (no alias, no deprecation line) for the metadata
        policy = load_policy(profile_path(name))
        rows.append({"name": name, "policy_id": policy.get("policy_id"),
                     "schema": policy.get("schema"), "pin_count": len(explain_policy(policy)),
                     "deploymentReady": policy.get("deploymentReady"),
                     "requiresIdentityOverlay": policy.get("requiresIdentityOverlay"),
                     "is_template": policy.get("requiresIdentityOverlay") is True
                                    or policy.get("deploymentReady") is False,
                     "deprecated_aliases": sorted(canonical_aliases.get(name, []))})
    if args.json:
        print(json.dumps(rows, indent=2, ensure_ascii=False))
        return 0
    for row in rows:
        kind = "template" if row["is_template"] else "profile "
        print(f"{row['name']:44} {kind} {row['schema']:32} {row['pin_count']} pin(s)   {row['policy_id']}")
        if row["deprecated_aliases"]:
            print(f"{'':44} (deprecated aliases: {', '.join(row['deprecated_aliases'])})")
    return 0


def _read_pubkey_line(text: str) -> str:
    """Extract a base64 Ed25519 public key from a key file's content: accepts a bare base64 string, an
    ``ed25519:<b64>`` issuer string, or a JSON object with ``public_key_b64`` / ``issuer_public_key_b64``.
    Returns the base64 string (empty if none found — the caller fail-closes on that)."""
    s = text.strip()
    if s.startswith("{"):
        try:
            obj = json.loads(s)
        except ValueError:
            return ""
        return obj.get("public_key_b64") or obj.get("issuer_public_key_b64") or ""
    if s.startswith("ed25519:"):
        return s[len("ed25519:"):].strip()
    return s


def _cmd_policy_instantiate(args: argparse.Namespace) -> int:
    """AP-2 §6.3: turn a shipped template into a deployment-ready org policy, offline. Reads the issuer
    key file(s) and optional expected-root file, pins them, and writes the instantiated policy JSON."""
    from .policy import PolicyError  # noqa: PLC0415
    from .policy_profiles import instantiate_template  # noqa: PLC0415
    try:
        keys = []
        for kf in args.issuer_key:
            with open(kf, encoding="utf-8") as fh:
                key = _read_pubkey_line(fh.read())
            if not key:
                raise PolicyError(f"issuer key file {kf!r} carries no public key")
            keys.append(key)
        expected_root = None
        if args.expected_root_file:
            with open(args.expected_root_file, encoding="utf-8") as fh:
                expected_root = fh.read().strip()
        inst = instantiate_template(args.template, issuer_keys=keys, policy_id=args.policy_id,
                                    expected_root=expected_root, valid_until=args.valid_until)
    except (PolicyError, OSError, ValueError) as exc:
        if getattr(args, "json", False):
            print(json.dumps({"ok": False, "error": str(exc)}))
        else:
            print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    out = json.dumps(inst, indent=2, ensure_ascii=False)
    if not inst.get("deploymentReady"):
        # honest, loud: the instance is missing a required field (e.g. an authenticated-root template
        # instantiated without --expected-root-file). It is written so it can be completed, but it is NOT
        # production-ready and `policy lint --strict` will refuse it (No-Fake).
        print("[policy-instantiate] WARNING: result is deploymentReady=false — a required field is "
              "missing (this template needs --expected-root-file); complete it before deploying.",
              file=sys.stderr)
    if args.output and args.output != "-":
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(out + "\n")
        print(f"[policy-instantiate] {args.template} -> {args.output}  "
              f"deploymentReady={inst.get('deploymentReady')}  policy_id={inst.get('policy_id')}",
              file=sys.stderr)
    else:
        print(out)
    return 0


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
    verify.add_argument("--expected-root", dest="expected_root", default=None, metavar="B64",
                        help="authenticate the merkle root against a base64 value the relying party "
                             "obtained OUT OF BAND (a pinned root, a signed checkpoint). The stated root "
                             "is NOT signed, so a coherent one-leaf rewrap verifies under a different "
                             "root; supplying this closes it — a mismatch FAILS (exit 1). Without it, "
                             "root authenticity reads NOT_EVALUATED")
    verify.add_argument("--expected-tree-size", dest="expected_tree_size", default=None, type=int,
                        metavar="N", help="require the merkle tree_size to equal N (guards tree-size "
                             "substitution); a mismatch FAILS")
    verify.add_argument("--trusted-checkpoint", dest="trusted_checkpoint", default=None, metavar="FILE",
                        help="A-P0-1: a signed C2SP checkpoint note file (SPEC §7c) as the ONE "
                             "authenticated source of BOTH the expected root AND tree size — the "
                             "atomic tree context. Needs --checkpoint-vkey. A bundle whose root or "
                             "tree_size differs from the checkpoint FAILS (exit 1); a checkpoint "
                             "that does not verify under the vkey FAILS (exit 1). Only this (or a "
                             "policy trusted_checkpoints match, or supplying BOTH --expected-root "
                             "and --expected-tree-size) reaches TREE_CONTEXT_AUTHENTICITY: PASS")
    verify.add_argument("--checkpoint-vkey", dest="checkpoint_vkey", default=None, metavar="VKEY",
                        help="the checkpoint log's C2SP verifier key (name+hexKeyID+base64KeyMaterial) "
                             "for --trusted-checkpoint")
    verify.add_argument("--verification-time", dest="verification_time", default=None, metavar="ISO8601",
                        help="A-P0-2 §6.3: verify the supplied --policy AS OF this explicit PAST "
                             "instant (e.g. 2026-01-01T00:00:00Z; a future instant is a usage error). "
                             "Output is labelled VERIFICATION_TIME: HISTORICAL with both the CURRENT and "
                             "the HISTORICAL policy status — never a silent backdating. safeForAutomation "
                             "is a present-tense verdict and stays false for a policy expired OR "
                             "not-yet-valid TODAY (or an expired-today checkpoint), even in historical "
                             "mode. Requires --policy")
    verify.add_argument("--policy", default=None,
                        help="path to a trust-policy JSON (proofbundle/trust-policy/v0.1), OR the name "
                             "of a packaged profile (WP3, e.g. strict-eval-v1 — see "
                             "docs/POLICY_PROFILES.md; `policy list-profiles` lists them all). Applies a "
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
    show_eval.add_argument("--eat", default=None,
                           help="[EXPERIMENTAL v2.0] path to a TEE Attestation Result (EAT) that corroborates "
                                "assurance_level=enclave_attested (see verify-enclave); with --verifier-key, "
                                "show-eval reports whether the level is PROVEN or merely issuer-declared")
    show_eval.add_argument("--verifier-key", default=None,
                           help="[EXPERIMENTAL v2.0] the RATS Verifier's Ed25519 public key (base64), used with --eat")
    show_eval.add_argument("--profile", default=None,
                           help="[EXPERIMENTAL v2.0] pin an expected eat_profile URI (optional, used with --eat)")
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
    _profile_help = ("path to a trust-policy JSON, OR the name of a packaged profile (WP3, "
                     "see docs/POLICY_PROFILES.md) such as strict-eval-v1 — a real file of the "
                     "same name always wins over a packaged profile")
    p_explain = psub.add_parser(
        "explain", help="list the effective pins a trust policy makes (what POLICY: OK will mean)")
    p_explain.add_argument("policy", help=_profile_help)
    p_explain.add_argument("--json", action="store_true", help="machine readable output")
    p_explain.set_defaults(func=_cmd_policy_explain)
    p_lint = psub.add_parser(
        "lint", help="fail (exit 1) on a WIRKUNGSLOSE policy that would produce a vacuous "
                     "POLICY: OK; --strict also fails on attributes-to-nobody")
    p_lint.add_argument("policy", help=_profile_help)
    p_lint.add_argument("--strict", action="store_true",
                        help="promote warnings (attributes to nobody) to lint failures")
    p_lint.add_argument("--json", action="store_true", help="machine readable output")
    p_lint.set_defaults(func=_cmd_policy_lint)
    p_list = psub.add_parser(
        "list-profiles", help="list the named trust-policy profiles shipped with this package (WP3); "
                              "canonical template names first, deprecated aliases marked")
    p_list.add_argument("--json", action="store_true", help="machine readable output")
    p_list.set_defaults(func=_cmd_policy_list_profiles)
    p_inst = psub.add_parser(
        "instantiate", help="AP-2 §6.3: turn a shipped TEMPLATE into a deployment-ready org policy by "
                            "pinning your signer identity (and root, when required); offline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Example:\n"
               "  proofbundle policy instantiate strict-eval-template-v1 \\\n"
               "    --issuer-key org-eval.pub --policy-id org/strict-eval-v1 \\\n"
               "    --output org-strict-eval-v1.json\n"
               "The result pins the issuer key(s), sets requiresIdentityOverlay=false, and is\n"
               "deploymentReady=true only when every required field is filled (an authenticated-root\n"
               "template also needs --expected-root-file). Exit 0 on success, 2 on any error.")
    p_inst.add_argument("template", help="a template profile name, e.g. strict-eval-template-v1 "
                                         "(deprecated aliases resolve with a warning)")
    p_inst.add_argument("--issuer-key", action="append", required=True, metavar="FILE",
                        help="file with a base64 Ed25519 public key to pin (repeat to pin several)")
    p_inst.add_argument("--policy-id", required=True,
                        help="the new policy_id in YOUR organisation namespace (must differ from the "
                             "template's)")
    p_inst.add_argument("--expected-root-file", metavar="FILE",
                        help="file with a base64 merkle root to pin as trusted_roots — REQUIRED for a "
                             "template that sets merkle.require_authenticated_root, optional otherwise")
    p_inst.add_argument("--valid-until", metavar="ISO8601",
                        help="optional expiry stamped onto the instance (e.g. 2027-01-01T00:00:00Z); "
                             "policy lint --strict fails once it is in the past")
    p_inst.add_argument("--output", "-o", metavar="FILE",
                        help="write the instantiated policy JSON here (default: stdout)")
    p_inst.add_argument("--json", action="store_true",
                        help="on error, emit a JSON error object instead of a stderr line")
    p_inst.set_defaults(func=_cmd_policy_instantiate)

    prereg = sub.add_parser(
        "prereg",
        help="hash an eval protocol file to commit to it BEFORE the run (--check verifies a receipt)")
    prereg.add_argument("protocol", help="path to the protocol/plan file to hash")
    prereg.add_argument("--check", metavar="RECEIPT",
                        help="verify the protocol matches a receipt's prereg_sha256 instead of hashing")
    prereg.add_argument("--json", action="store_true", help="machine readable output")
    prereg.set_defaults(func=_cmd_prereg)

    evalcard = sub.add_parser(
        "evalcard",
        help="hash an external Eval Card document to reference it from a claim (--check verifies a receipt)")
    evalcard.add_argument("card", help="path to the Eval Card document to hash")
    evalcard.add_argument("--check", metavar="RECEIPT",
                          help="verify the card matches a receipt's evaluation_card_sha256 instead of hashing")
    evalcard.add_argument("--json", action="store_true", help="machine readable output")
    evalcard.set_defaults(func=_cmd_evalcard)

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
    d_verify.add_argument("--with-related", dest="with_related", action="append", default=None, metavar="PATH",
                          help="relation/v0.1 (EXPERIMENTAL): attach a RELATED receipt's DSSE envelope for "
                               "offline lineage resolution (repeatable). Each target is verified standalone "
                               "under the SAME --pub (same-key contract) unless a position-paired "
                               "--related-pub is given; an attached target that does not verify FAILS lineage "
                               "— relationship declared by issuer, not a statement of correctness")
    d_verify.add_argument("--related-pub", dest="related_pub", action="append", default=None, metavar="B64",
                          help="WP-A (3.4.0): position-paired issuer key (base64) for the i-th --with-related "
                               "target, enabling cross-issuer chains. Empty/absent = same-key (--pub). The "
                               "trust policy's relation_signer pin decides WHO may replace")
    d_verify.add_argument("--require-derived-subject", dest="require_derived_subject", action="store_true",
                          help="Finding 05: fail closed (exit 2) unless the Statement subject is a DERIVED "
                               "commitment to the predicate (subject_binding.classify_subject) — rejects a "
                               "self-attested/rehung subject_sha256 override. Default off: an "
                               "EXTERNAL_ATTESTED subject is still warned, never silent")
    d_verify.set_defaults(func=_cmd_decision_verify)

    d_inspect = dsub.add_parser("inspect", help="print a decision receipt's predicate (no crypto verification)")
    d_inspect.add_argument("receipt", help="path to a DSSE receipt or a raw in-toto Statement")
    d_inspect.set_defaults(func=_cmd_decision_inspect)

    # ── Action Outcome Receipt (3.2.0, action-outcome/v0.1, EXPERIMENTAL) ──
    outcome = sub.add_parser("outcome", help="action-outcome/v0.1 (EXPERIMENTAL): init/emit/verify/inspect an action outcome")
    osub = outcome.add_subparsers(dest="outcome_command", required=True)

    o_init = osub.add_parser("init", help="print a template outcome predicate (fill in and sign with 'outcome emit')")
    o_init.add_argument("--out", default=None, help="write the template to a file instead of stdout")
    o_init.set_defaults(func=_cmd_outcome_init)

    o_emit = osub.add_parser("emit", help="sign an outcome predicate into a DSSE receipt")
    o_emit.add_argument("predicate", help="path to the outcome predicate JSON")
    o_emit.add_argument("--out", required=True, help="output path for the signed outcome receipt")
    o_emit.add_argument("--key", help="load an existing Ed25519 signing key from file")
    o_emit.add_argument("--new-key", dest="new_key", help="generate a new signing key and write it to file")
    o_emit.add_argument("--lenient", action="store_true", help="allow non-strict predicates")
    o_emit.set_defaults(func=_cmd_outcome_emit)

    o_verify = osub.add_parser(
        "verify", help="verify an outcome receipt (crypto + structure; decision binding + role separation)",
        description=("Exit codes: 0 OK · 1 crypto/verification failure · 2 malformed / predicateType confusion "
                     "/ decision-binding or role-separation mismatch. --expected-decision-ref binds the outcome "
                     "to a specific decision content root (replay across decisions fails). --decision-maker-id "
                     "enforces role separation (executor must differ from the decision maker). status=executed "
                     "without an effect/actual digest is a self-asserted claim, not proof of the effect."))
    o_verify.add_argument("envelope", help="path to the DSSE outcome receipt")
    o_verify.add_argument("--pub", required=True, help="executor Ed25519 public key (base64) to verify against")
    o_verify.add_argument("--expected-decision-ref", dest="expected_decision_ref", default=None,
                          help="expected decision content root (sha256 hex); a mismatch is a cross-decision replay, fail-closed")
    o_verify.add_argument("--decision-maker-id", dest="decision_maker_id", default=None,
                          help="the bound decision's maker id; executor==maker violates role separation (fail-closed)")
    o_verify.add_argument("--json", action="store_true", help="machine readable output")
    o_verify.add_argument("--strict", action="store_true", help="enforce strict-v0.1 required fields")
    o_verify.add_argument("--aud", default=None, help="expected audience (checks validity.audience against replay)")
    o_verify.add_argument("--nonce", default=None, help="expected nonce (checks validity.nonce against replay)")
    o_verify.add_argument("--policy", default=None,
                          help="WP-B (3.4.0): trust policy JSON — the `relations` section is enforced on the "
                               "outcome path identically to decision verify; a violation exits 3")
    o_verify.add_argument("--with-related", dest="with_related", action="append", default=None, metavar="PATH",
                          help="relation/v0.1 (EXPERIMENTAL): attach a RELATED receipt's DSSE envelope for "
                               "offline lineage resolution (repeatable; same-key unless --related-pub given)")
    o_verify.add_argument("--related-pub", dest="related_pub", action="append", default=None, metavar="B64",
                          help="WP-A (3.4.0): position-paired issuer key (base64) for the i-th --with-related "
                               "target (cross-issuer); empty/absent = same-key (--pub)")
    o_verify.add_argument("--require-derived-subject", dest="require_derived_subject", action="store_true",
                          help="Finding 05: fail closed (exit 2) unless the Statement subject is a DERIVED "
                               "commitment to the predicate (subject_binding.classify_subject) — rejects a "
                               "self-attested/rehung subject_sha256 override. Default off: an "
                               "EXTERNAL_ATTESTED subject is still warned, never silent")
    o_verify.set_defaults(func=_cmd_outcome_verify)

    o_inspect = osub.add_parser("inspect", help="print an outcome receipt's predicate (no crypto verification)")
    o_inspect.add_argument("receipt", help="path to a DSSE receipt or a raw in-toto Statement")
    o_inspect.set_defaults(func=_cmd_outcome_inspect)

    # relation-statement/v0.1 (3.5.0, EXPERIMENTAL): a standalone signed statement OVER a target
    # receipt (retroactive retraction/supersession without touching the original).
    relstmt = sub.add_parser(
        "relation-statement",
        help="relation-statement/v0.1 (EXPERIMENTAL): init/emit/verify/inspect a standalone signed "
             "relation OVER a target receipt (retract/supersede without touching the original)")
    rsub = relstmt.add_subparsers(dest="relation_statement_command", required=True)

    rs_init = rsub.add_parser("init", help="print a template relation-statement predicate (fill in and sign with 'emit')")
    rs_init.add_argument("--out", default=None, help="write the template to a file instead of stdout")
    rs_init.set_defaults(func=_cmd_relation_statement_init)

    rs_emit = rsub.add_parser("emit", help="sign a relation-statement predicate into a DSSE statement")
    rs_emit.add_argument("predicate", help="path to the relation-statement predicate JSON")
    rs_emit.add_argument("--out", required=True, help="output path for the signed relation statement")
    rs_emit.add_argument("--key", help="load an existing Ed25519 signing key from file")
    rs_emit.add_argument("--new-key", dest="new_key", help="generate a new signing key and write it to file")
    rs_emit.set_defaults(func=_cmd_relation_statement_emit)

    rs_verify = rsub.add_parser(
        "verify",
        help="verify a relation statement (crypto + structure + offline lineage + relations policy)",
        description=("Exit codes: 0 OK · 1 crypto/verification failure · 2 malformed / predicateType "
                     "confusion / lineage FAIL · 3 crypto OK but relations policy not satisfied. A "
                     "retracts statement never invalidates the target's crypto — it sets a visible "
                     "state; reject_retracted/reject_superseded turn continued automated use of the "
                     "target into an exit-3 block. Whether the issuer MAY declare the relation is a "
                     "relying-party policy decision (relation_signer pin)."))
    rs_verify.add_argument("envelope", help="path to the DSSE relation statement")
    rs_verify.add_argument("--pub", required=True, help="issuer Ed25519 public key (base64) to verify against")
    rs_verify.add_argument("--json", action="store_true", help="machine readable output")
    rs_verify.add_argument("--strict", action="store_true", help="enforce strict-v0.1 canonicality")
    rs_verify.add_argument("--policy", default=None,
                           help="trust policy JSON — the `relations` section (require_relation_resolution / "
                                "relation_signer / require_relation_target / reject_retracted / "
                                "reject_superseded) is enforced; a violation exits 3")
    rs_verify.add_argument("--with-related", dest="with_related", action="append", default=None, metavar="PATH",
                           help="attach the TARGET receipt's DSSE envelope for offline lineage resolution "
                                "(repeatable; same-key unless --related-pub given)")
    rs_verify.add_argument("--related-pub", dest="related_pub", action="append", default=None, metavar="B64",
                           help="position-paired issuer key (base64) for the i-th --with-related target "
                                "(cross-issuer); empty/absent = same-key (--pub)")
    rs_verify.add_argument("--require-derived-subject", dest="require_derived_subject", action="store_true",
                           help="fail closed (exit 2) unless the Statement subject is a DERIVED commitment "
                                "to the predicate — rejects a self-attested/rehung subject override")
    rs_verify.set_defaults(func=_cmd_relation_statement_verify)

    rs_inspect = rsub.add_parser("inspect", help="print a relation statement's predicate (no crypto verification)")
    rs_inspect.add_argument("receipt", help="path to a DSSE statement or a raw in-toto Statement")
    rs_inspect.set_defaults(func=_cmd_relation_statement_inspect)

    # ── anchor operations (OTS hardening + calendar-risk, EXPERIMENTAL, the [anchors] extra) ──
    anchor = sub.add_parser(
        "anchor",
        help="external time-anchor operations (EXPERIMENTAL): package an UPGRADED OpenTimestamps proof "
             "into a self-contained, calendar-independent evidence pack; verify one OFFLINE; inspect "
             "the lifecycle and the calendars carrying it")
    ansub = anchor.add_subparsers(dest="anchor_command", required=True)

    a_up = ansub.add_parser(
        "upgrade",
        help="bundle an UPGRADED OpenTimestamps proof into a self-contained evidence pack "
             "(calendar-independent verification). A still-PENDING proof is refused (exit 3)",
        description=("Exit codes: 0 self-contained pack written · 2 malformed input / unbound proof · "
                     "3 proof not upgraded yet (PENDING — upgrading embeds the Bitcoin block-header "
                     "path and needs the OpenTimestamps client after a Bitcoin confirmation, which is "
                     "time-gated; run `ots upgrade` first). The pack verifies OFFLINE against a "
                     "relying-party Bitcoin header — no calendar needed."))
    a_up.add_argument("--proof", required=True, help="path to the detached OpenTimestamps proof (.ots)")
    a_up.add_argument("--target-file", dest="target_file", default=None,
                      help="the exact bytes that were stamped; its SHA-256 is the canonical root the "
                           "proof must commit to")
    a_up.add_argument("--canonical-root-hex", dest="canonical_root_hex", default=None,
                      help="the canonical root as 64-char hex (alternative to --target-file)")
    a_up.add_argument("--calendar-declared", dest="calendar_declared", action="append", default=None,
                      metavar="URL",
                      help="a producer-DECLARED calendar URL (repeatable), recorded verbatim as "
                           "declaredCalendars with verified:false — documentation only, NOT audit evidence "
                           "and never counted toward operator redundancy. The proof-embedded calendar set "
                           "read from the proof's own attestations is itself an embedded-but-UNVERIFIED "
                           "transparency hint (a PendingAttestation URI is unauthenticated and "
                           "offline-constructible), NOT cryptographic evidence")
    a_up.add_argument("--bundled-header", dest="bundled_header", action="append", default=None,
                      metavar="HEIGHT:MERKLEROOT_HEX",
                      help="OPTIONAL Bitcoin block header (internal byte order) copied into the pack as "
                           "EVIDENCE only — never trusted at verify (WP-A1); the relying party still "
                           "supplies their own header to confirm")
    a_up.add_argument("--out", required=True, help="output path for the evidence pack JSON")
    a_up.add_argument("--json", action="store_true", help="machine readable output")
    a_up.set_defaults(func=_cmd_anchor_upgrade)

    a_vp = ansub.add_parser(
        "verify-pack",
        help="verify an evidence pack OFFLINE (no network, no calendar); confirms only against a "
             "relying-party Bitcoin header",
        description=("Exit codes: 0 confirmed · 1 hard fail (unbound / block mismatch / malformed "
                     "pack) · 2 malformed input · 3 pending or upgraded-without-a-relying-party-header "
                     "(honest not-pass). The pack's OWN bundled header is producer-controlled evidence "
                     "and is never trusted (WP-A1); supply your own header from a pruned Bitcoin node "
                     "or a trusted checkpoint."))
    a_vp.add_argument("pack", help="path to the evidence pack JSON")
    a_vp.add_argument("--bitcoin-header", dest="bitcoin_header", action="append", default=None,
                      metavar="HEIGHT:MERKLEROOT_HEX",
                      help="relying-party-supplied Bitcoin block header (internal byte order, from your "
                           "own pruned node or a trusted checkpoint); the pack's frozen header is never "
                           "trusted")
    a_vp.add_argument("--json", action="store_true", help="machine readable output")
    a_vp.set_defaults(func=_cmd_anchor_verify_pack)

    a_in = ansub.add_parser(
        "inspect",
        help="print the lifecycle state (pending/upgraded/self-contained) and the calendars/operators "
             "carrying an OpenTimestamps proof (.ots) or evidence pack — transparency, no crypto trust")
    a_in.add_argument("path", help="path to a detached OTS proof (.ots) or an evidence pack JSON")
    a_in.add_argument("--json", action="store_true", help="machine readable output")
    a_in.set_defaults(func=_cmd_anchor_inspect)

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
