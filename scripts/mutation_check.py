#!/usr/bin/env python3
"""Orthogonal mutation suite — proves the tests still KILL broken implementations (v1.3).

Anti-Goodhart guard: a green test suite only means something if it goes red when the code is
broken. Each operator below mutates ONE independent fault dimension (binding, framing, key
domain separation, quorum counting, fail-open, output truthfulness); the suite passes iff every
non-equivalent mutant is KILLED (strictly more red than the unmutated baseline — the baseline may
carry environment-only failures, so the comparison is differential, never absolute).

Documented-equivalent mutants are asserted to SURVIVE — if one starts getting killed, the
equivalence argument is stale and must be revisited (that is a failure too: honesty both ways).

Usage:  python3 scripts/mutation_check.py            # exit 0 = all as expected, 1 = gap found
CI:     runs in the mutation job (see .github/workflows/ci.yml).
"""
from __future__ import annotations

import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# (relative file, exact old text, new text, label, expect_killed)
MUTATIONS = [
    # v1.2 — KB-JWT / bundle / cosignature / CLI
    ("src/proofbundle/kbjwt.py",
     "if _b64url_nopad(h.digest()) != sd_hash:", "if False:",
     "kbjwt: sd_hash binding disabled", True),
    ("src/proofbundle/kbjwt.py",
     'if kb_header.get("typ") != "kb+jwt":', "if False:",
     "kbjwt: typ check disabled", True),
    ("src/proofbundle/bundle.py",
     "if kb is not None:", "if False:",
     "bundle: KB check unwired", True),
    ("src/proofbundle/checkpoint.py",
     "_COSIG_V1_SIG_TYPE = 0x04", "_COSIG_V1_SIG_TYPE = 0x01",
     "cosign: keyID domain separation removed", True),
    ("src/proofbundle/checkpoint.py",
     'return (_COSIG_V1_PREFIX + f"time {timestamp}\\n" + note_text).encode("utf-8")',
     'return (_COSIG_V1_PREFIX + "time 0\\n" + note_text).encode("utf-8")',
     "cosign: timestamp unbound from signature", True),
    ("src/proofbundle/bundle.py",
     'recomputed_b64 = base64.b64encode(recomputed).decode("ascii")',
     "recomputed_b64 = stated_b64",
     "cli --verbose: fake recomputed root", True),
    # v1.3 — tlog-proof / ML-DSA / status list
    ("src/proofbundle/tlogproof.py",
     'inclusion_ok = hmac.compare_digest(computed, log_res["root"])',
     "inclusion_ok = True",
     "tlogproof: inclusion check disabled", True),
    ("src/proofbundle/tlogproof.py",
     'return {"ok": log_ok and witnesses_ok and inclusion_ok,',
     'return {"ok": log_ok or witnesses_ok or inclusion_ok,',
     "tlogproof: verdict conjunction -> disjunction", True),
    ("src/proofbundle/checkpoint.py",
     "_MLDSA_LABEL = b\"subtree/v1\\n\\x00\"", "_MLDSA_LABEL = b\"subtree/v2\\n\\x00\"",
     "mldsa: domain separation label changed", True),
    ("src/proofbundle/statuslist.py",
     'if payload.get("sub") != expected_uri:', "if False:",
     "statuslist: sub/uri binding disabled", True),
    ("src/proofbundle/statuslist.py",
     "return (bit_array[byte_i] >> (slot * bits)) & ((1 << bits) - 1)",
     "return 0",
     "statuslist: every status reads VALID", True),
    # v1.4 — HF token / promptfoo adapter
    ("src/proofbundle/hf_evals.py",
     'if require_verified:', 'if False:',
     "hf: broken-receipt guard disabled", True),
    ("src/proofbundle/hf_evals.py",
     'return verify_bundle(bundle), bundle',
     'from .errors import VerificationResult as _VR; r=_VR(); r.add("x", True, ""); return r, bundle',
     "hf: token verify returns fake OK", True),
    ("src/proofbundle/adapters/promptfoo.py",
     'if version != 3:', 'if False:',
     "promptfoo: version gate disabled", True),
    ("src/proofbundle/adapters/promptfoo.py",
     'rate = (Decimal(successes) / Decimal(total)).quantize(Decimal(1).scaleb(-_SCALE))',
     'rate = (Decimal(successes) / Decimal(max(successes, 1))).quantize(Decimal(1).scaleb(-_SCALE))',
     "promptfoo: failures dropped from pass_rate", True),
    # v1.5 — per-sample tree / audit challenge
    ("src/proofbundle/persample.py",
     'if record.get("idx") != index:', "if False:",
     "persample: replay guard disabled", True),
    ("src/proofbundle/persample.py",
     'if not merkle.verify_inclusion(disclosure.encode("ascii"), index, n, proof, root):',
     "if False:",
     "persample: inclusion check disabled", True),
    ("src/proofbundle/persample.py",
     "if v >= limit:\n        return None", "if False:\n        return None",
     "challenge: rejection sampling removed", True),
    ("src/proofbundle/persample.py",
     '_CHALLENGE_DOMAIN = b"proofbundle/v2/audit-challenge"',
     '_CHALLENGE_DOMAIN = b"proofbundle/v3/audit-challenge"',
     "challenge: domain separation changed", True),
    ("src/proofbundle/persample.py",
     '_SALT_DOMAIN = b"proofbundle/v2/leaf-salt"',
     '_SALT_DOMAIN = b"proofbundle/v2/leaf-SALT"',
     "persample: salt domain changed", True),
    ("src/proofbundle/evalclaim.py",
     "if s_n != n:", "if False:",
     "claim: samples.n == n binding disabled", True),
    # v1.6 — external-review fixes (each must be killed by its regression test)
    ("src/proofbundle/bundle.py",
     "        elif not sd_res.get(\"sig_checked\"):", "        elif False:",
     "bundle: cnf-without-issuer-key fail-closed removed (P0)", True),
    ("src/proofbundle/evalclaim.py",
     " or s_n != c_n):",
     " or False):",
     "decode: verify-side samples.n==n binding removed", True),
    ("src/proofbundle/evalclaim.py",
     "if expected_context is not None and claim.get(\"context_binding\") != expected_context:",
     "if False:",
     "decode: context_binding enforcement removed", True),
    ("src/proofbundle/statuslist.py",
     "if exp is None and ttl is None:", "if False:",
     "statuslist: unbounded-token fresh=None removed", True),
    # v1.8 — provenance / prereg / HF value-consistency
    ("src/proofbundle/prereg.py",
     "if actual == expected:", "if True:",
     "prereg: hash match check bypassed", True),
    ("src/proofbundle/hf_evals.py",
     "if cmp_ok != bool(claim[\"passed\"]):", "if False:",
     "hf: value-vs-verdict consistency check removed", True),
    # v1.9 — public beacon audit binding
    ("src/proofbundle/beacon.py",
     "+ round_.to_bytes(8, \"big\") + bytes(pulse_randomness)).digest()",
     "+ bytes(pulse_randomness)).digest()",
     "beacon: round no longer bound into the nonce", True),
    # v1.9.1 — status-list self-issued trust-anchor separation
    ("src/proofbundle/statuslist.py",
     "_hmac.compare_digest(bytes(issuer_pubkey),", "_hmac.compare_digest(b\"\", ",
     "statuslist: self_issued compare defeated", True),
    # v2.0 preview — TEE-attestation binding
    ("src/proofbundle/experimental/enclave.py",
     "if not _match_nonce(claims.get(\"eat_nonce\"), expected_binding):", "if False:",
     "enclave: receipt-binding check disabled", True),
    # Documented-equivalent mutant (v1.2 report): oversized cosignature blobs already die at
    # verify_ed25519's hard 64-byte signature length check — must keep SURVIVING.
    ("src/proofbundle/checkpoint.py",
     "if len(payload) != blob_len:", "if len(payload) < blob_len:",
     "cosign: blob length exact -> lax (EQUIVALENT)", False),
    # v1.9.2 — F3: verify-path field-set enforcement (required-presence + unknown-rejection)
    ("src/proofbundle/evalclaim.py",
     "if (_REQUIRED - set(claim)) or (set(claim) - _REQUIRED - _OPTIONAL):", "if False:",
     "evalclaim: verify-path required/unknown-field enforcement (F3) disabled", True),
    # v1.9.2 — F4: expected_aud/nonce with no verifiable KB-JWT must fail closed (downgrade trap)
    ("src/proofbundle/bundle.py",
     "if (expected_aud is not None or expected_nonce is not None) and not kb_binding_checked:", "if False:",
     "bundle: expected_aud/nonce downgrade-trap enforcement (F4) disabled", True),
    # in-toto eval-result export — the commitment-only salt-leak guard must refuse a claim that still
    # carries a plaintext identifier / raw salt (Paket 2 test 1/14).
    ("src/proofbundle/intoto.py",
     "    if leaked:", "    if False:",
     "intoto: eval-result export salt-leak guard disabled", True),
    # SVR export — passing-only: a receipt that did NOT pass its threshold must get no SVR (Paket 3 test 11/14).
    ("src/proofbundle/intoto.py",
     'if not claim.get("passed"):', "if False:",
     "intoto: SVR passing-only guard disabled", True),
    # anchors (experimental) — the canonicalRoot↔target binding must fail closed (cross-target safety).
    ("src/proofbundle/anchors.py",
     "if canonical_root != expected_root:", "if False:",
     "anchors: canonicalRoot/target binding disabled (cross-target)", True),
    # WP-C1 — the duplicate-key reject must fire on every verify path (parser differential).
    ("src/proofbundle/_strict_json.py",
     "if key in obj:", "if False:",
     "strict-json: duplicate-key reject disabled (last-wins differential)", True),
    # WP-I1 — predicateType-confusion defense: disabling the type check must go red.
    ("src/proofbundle/intoto.py",
     "    ok = bool(sig_ok) and binding_ok and (type_ok is not False)",
     "    ok = bool(sig_ok) and binding_ok",
     "intoto: predicateType-confusion enforcement disabled", True),
    # chia-datalayer/v1 (first-party extension) — the offline Merkle checks must fail closed.
    ("src/proofbundle/anchors_chia.py",
     "if root != published_root:", "if False:",
     "chia-datalayer: Merkle inclusion (root) check disabled", True),
    ("src/proofbundle/anchors_chia.py",
     "if key_bytes != canonical_root:", "if False:",
     "chia-datalayer: key/canonicalRoot binding disabled", True),
    ("src/proofbundle/anchors_chia.py",
     "if clvm_atom_hash(key_bytes) != key_clvm:", "if False:",
     "chia-datalayer: key_clvm_hash binding disabled (relabel forgery)", True),
    # v3.0.0 — the four NEW breaking security defenses (release-audit F13): each disabled defense must
    # go red. Without these the mutation gate covered every check EXCEPT the ones 3.0.0 was cut to add.
    # WP-C2 — an unsigned sd_jwt_vc (no issuer_public_key_b64) must FAIL, not pass secure-by-default.
    ("src/proofbundle/bundle.py",
     '"sd-jwt-issuer-signature", False,', '"sd-jwt-issuer-signature", True,',
     "bundle: WP-C2 unsigned SD-JWT now-fails defense disabled", True),
    # WP-C1 (2nd lens) — a self-signed SD-JWT whose verifying key is NOT the disclosed issuer is a forged
    # identity; the fingerprint(issuer_pub) == disclosed issuer bind must hold.
    ("src/proofbundle/bundle.py",
     '"sd-jwt-issuer-identity", _disc_issuer == _verifying_fp,',
     '"sd-jwt-issuer-identity", True,',
     "bundle: WP-C1 SD-JWT issuer-identity bind disabled (forged identity)", True),
    # WP-C1 — cross-receipt credential substitution: the SD-JWT's always-open claims + root must match
    # THIS bundle; disabling the field comparison lets a lifted receipt bind to a foreign bundle.
    ("src/proofbundle/sdjwt_issue.py",
     "if field not in claim or p.get(field) != claim.get(field):", "if False:",
     "sdjwt_issue: WP-C1 bundle-binding field comparison disabled (cross-receipt substitution)", True),
    # WP-A1 — external time-anchor trust comes from the relying party; a self-frozen anchor with no RP
    # trust material must stay ok=False (needs_rp_trust). Re-enabling own-frozen self-trust must go red.
    # (killed by tests.test_anchors_ots / .test_anchors_rfc3161 + the forged-anchor-own-frozen conformance
    #  vector — all require the [anchors] extra, which the mutation CI job installs.)
    ("src/proofbundle/anchors_ots.py",
     '"ok": False, "warn": False, "status": "needs_rp_trust"',
     '"ok": True, "warn": False, "status": "needs_rp_trust"',
     "anchors_ots: WP-A1 needs_rp_trust self-trust re-enabled (backdating)", True),
    ("src/proofbundle/anchors_rfc3161.py",
     '"ok": False, "status": "needs_rp_trust"',
     '"ok": True, "status": "needs_rp_trust"',
     "anchors_rfc3161: WP-A1 needs_rp_trust self-trust re-enabled (backdating)", True),
    # 3.2.0 anchor-longevity (ADR 0006) — the new fail-closed defenses. Killed by the unittest property
    # tests in tests/test_anchor_longevity_property.py (which run under unittest discover).
    # B2 — a dual-hash leg that never actually compares the digest lets forged bytes verify.
    ("src/proofbundle/hashalg.py",
     "        match = isinstance(expected, str) and actual == expected.lower()",
     "        match = True",
     "hashalg: B2 dual-hash digest comparison disabled (forged bytes verify)", True),
    # B2 — a deprecated hash must never resolve by default (algorithm-confusion / RFC 7696).
    ("src/proofbundle/hashalg.py",
     '    if spec.status == "deprecated" and not allow_deprecated:',
     "    if False:",
     "hashalg: B2 deprecated-algorithm reject disabled", True),
    # B3 — the renewal covering check binds each ATS to its prior objects + data; disabling it lets a
    # tampered data object or a broken sequence verify silently.
    ("src/proofbundle/renewal.py",
     "            if a.covered_digest != expect:",
     "            if False:",
     "renewal: B3 ArchiveTimeStamp covering check disabled (tamper/break survives)", True),
    # B3↔B5 — the ATS time-authority signature is the real anchor; forcing it True lets a forged/absent
    # signature pass as an authenticated anchor.
    ("src/proofbundle/renewal.py",
     "        return pub is not None and verify_mldsa(pub, _dec(\"mldsa65\"), content)",
     "        return True",
     "renewal: B3<->B5 ATS ML-DSA signature check disabled (forged anchor)", True),
    # 3.2.1 hardening (final-audit findings) — each new fail-closed guard must be killed by its test.
    # F1 — require_pq reverted to a LABEL check accepts a PQ label with an unverified anchor (No-Fake).
    ("src/proofbundle/renewal.py",
     'pq_verified = anchored and anchor_mode == "authority signature" and "mldsa" in (newest.sig_alg or "")',
     'pq_verified = "mldsa" in (newest.sig_alg or "")',
     "renewal: F1 require_pq reverted to label-only (unverified PQ label passes)", True),
    # F2 — dropping the future-time guard lets a future-dated newest ATS read as perpetually fresh.
    ("src/proofbundle/renewal.py",
     "    if _ints and newest.time > now:",
     "    if False and _ints and newest.time > now:",
     "renewal: F2 future-dated ATS guard disabled (never overdue)", True),
    # R1 — forcing the hash-strength check green ignores require_current_hash on a deprecated newest hash.
    ("src/proofbundle/renewal.py",
     "        hash_ok = not (newest_dep and require_current_hash)",
     "        hash_ok = True",
     "renewal: R1 require_current_hash floor disabled (deprecated newest passes)", True),
    # R2 — dropping the version>1 chain requirement re-opens the version-2-genesis rotation bypass.
    ("src/proofbundle/trust_pack.py",
     "    if _is_int(ver) and ver >= 2 and pv is None:",
     "    if False and _is_int(ver) and ver >= 2 and pv is None:",
     "trust_pack: R2 version>1 prevVersionDigest requirement disabled (v2-genesis bypass)", True),
    # F7 — not collecting nested digests from a committed disclosure's value breaks recursive disclosures
    # AND (the security direction) would let nothing further be rooted; the recursive test kills it.
    ("src/proofbundle/sdjwt.py",
     "                    _collect_committed_digests(parsed[-1], committed)",
     "                    pass",
     "sdjwt: F7 recursive-disclosure collection disabled (valid recursive vectors fail)", True),
]


def _red_count() -> int:
    # Stale-bytecode defense (real incident during per-sample development): a same-size
    # mutation + coarse-mtime filesystem leaves a VALID-looking .pyc for the OLD code; -B only
    # stops WRITING caches — existing ones are still read; and cache dirs may be undeletable on
    # restricted mounts. The robust invalidation is touching every source mtime, forcing
    # recompilation regardless of what caches survive.
    import os  # noqa: PLC0415
    import shutil  # noqa: PLC0415
    for cache in ROOT.rglob("__pycache__"):
        shutil.rmtree(cache, ignore_errors=True)
    for src_file in ROOT.glob("src/**/*.py"):
        os.utime(src_file)
    proc = subprocess.run(
        [sys.executable, "-B", "-m", "unittest", "discover", "-s", "tests"],
        cwd=ROOT, capture_output=True, text=True,
        env={"PYTHONPATH": "src", "PATH": "/usr/bin:/bin:/usr/local/bin",
             "HOME": str(Path.home()), "PYTHONDONTWRITEBYTECODE": "1"})
    f = re.search(r"failures=(\d+)", proc.stderr)
    e = re.search(r"errors=(\d+)", proc.stderr)
    return (int(f.group(1)) if f else 0) + (int(e.group(1)) if e else 0)


def main() -> int:
    baseline = _red_count()
    print(f"baseline red (environment-only failures allowed): {baseline}")
    gaps = 0
    for rel, old, new, label, expect_killed in MUTATIONS:
        path = ROOT / rel
        src = path.read_text(encoding="utf-8")
        if old not in src:
            print(f"  GAP  [{label}] pattern not found — operator is stale")
            gaps += 1
            continue
        backup = path.with_suffix(path.suffix + ".mutbak")
        shutil.copy(path, backup)
        try:
            path.write_text(src.replace(old, new, 1), encoding="utf-8")
            red = _red_count()
            killed = red > baseline
            ok = killed == expect_killed
            verdict = "KILLED" if killed else "SURVIVED"
            expected = "expected" if ok else "*** UNEXPECTED ***"
            print(f"  {'ok  ' if ok else 'GAP '} [{label}] {verdict} (red={red}) {expected}")
            if not ok:
                gaps += 1
        finally:
            shutil.move(backup, path)
    final = _red_count()
    if final != baseline:
        print(f"GAP: baseline not restored ({final} != {baseline})")
        gaps += 1
    print(f"=> {'OK' if gaps == 0 else 'FAILED'} ({len(MUTATIONS)} operators, {gaps} gap(s))")
    return 0 if gaps == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
