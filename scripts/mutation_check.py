#!/usr/bin/env python3
"""Orthogonal mutation suite — proves the tests still KILL broken implementations (v1.4).

Anti-Goodhart guard: a green test suite only means something if it goes red when the code is
broken. Each operator below mutates ONE independent fault dimension (binding, framing, key
domain separation, quorum counting, fail-open, output truthfulness); the suite passes iff every
non-equivalent mutant is KILLED (strictly more red than the unmutated baseline — the baseline may
carry environment-only failures, so the comparison is differential, never absolute).

Documented-equivalent mutants are asserted to SURVIVE — if one starts getting killed, the
equivalence argument is stale and must be revisited (that is a failure too: honesty both ways).

Isolation contract (v1.4, incident 2026-07-23): mutants are applied in a THROWAWAY COPY of the
tracked tree under a tempdir; the real working tree is never written to, so even a SIGKILL
mid-probe cannot leave a live mutant (or a stray backup file) behind. try/finally alone cannot
give that guarantee: a hard kill skips finally, and exactly that left an `if False:` mutant plus
a .mutbak file in the working tree. Belt and braces, the run additionally compares
`git status --porcelain` before/after and fails closed on any left-over working tree change.

Usage:  python3 scripts/mutation_check.py            # exit 0 = all as expected, 1 = gap found
CI:     runs in the mutation job (see .github/workflows/ci.yml).
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# (relative file, exact old text, new text, label, expect_killed)
MUTATIONS = [
    # relation/v0.1 (3.3.0) — lineage profile: the three load-bearing guards.
    # BOTH cycle checks, because since #139 there are two and either one alone still catches.
    # The look-ahead was added on purpose ("detecting the back-edge first makes the cycle code
    # independent of sibling order"); it is not redundancy to remove, it is redundancy the
    # operator has to account for. Measured: one site alone -> suite green; both -> 4 tests red,
    # among them tests/test_relation_property.py::…test_injected_back_edge_onto_path_is_caught…
    ("src/proofbundle/relation.py",
     ("        if node_hex in path:",
      "            if nxt is not None and nxt in path:"),
     ("        if False and node_hex in path:",
      "            if False and nxt is not None and nxt in path:"),
     "relation: cycle detection disabled (both sites)", True),
    ("src/proofbundle/relation.py",
     'if not (isinstance(digest, str) and _SHA256_HEX.match(digest)):', "if False:",
     "relation: malformed-digest guard disabled (never-raise vector must catch)", True),
    # Same shape: the direct-edge arm and the ancestor walker both apply this gate since #139.
    # Laxening one lets the other catch the vector one level down.
    ("src/proofbundle/relation.py",
     ('elif target.get("verified") is not True:',
      '        if node.get("verified") is not True:'),
     ('elif target.get("verified") is False:',
      '        if node.get("verified") is False:'),
     "relation: verified-flag laxened at both arms (truthy sneaks past strict is-True)", True),
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
    # ORIGIN-SCHRANKE, zwei Lockerungen. Der Gate-Meta-Test der DEEP-Runde hat beide eingepflanzt
    # und gemessen, dass KEINER von 2030 Tests sie faengt: die zwei Origin-Tests prueften nur einen
    # voellig FREMDEN Wert, und gegen einen fremden Wert verhaelt sich ein gelockerter Vergleich
    # genau wie ein exakter. Der Beinahe-Treffer war der fehlende Fall -- und im Feld der
    # gefaehrliche, denn wer einen eigenen Log betreibt, waehlt dessen Namen selbst.
    # Gefangen werden sie jetzt von OriginVergleichIstExakt in
    # tests/test_verify_proof_expected_origin.py; diese zwei Operatoren halten fest, DASS sie es
    # tun -- ein Korpus ohne Mutant ist eine Behauptung ueber sich selbst.
    ("src/proofbundle/tlogproof.py",
     'log_ok = bool(log_res["ok"]) and (expected_origin is None or log_res["origin"] == expected_origin)',
     'log_ok = bool(log_res["ok"]) and (expected_origin is None or str(log_res["origin"]).startswith(str(expected_origin)))',
     "tlogproof: origin equality -> startswith (a prefix would pass)", True),
    ("src/proofbundle/tlogproof.py",
     'log_ok = bool(log_res["ok"]) and (expected_origin is None or log_res["origin"] == expected_origin)',
     'log_ok = bool(log_res["ok"]) and (expected_origin is None or str(log_res["origin"]).casefold() == str(expected_origin).casefold())',
     "tlogproof: origin comparison becomes case-insensitive", True),
    # DREI OPERATOREN, die eine Gegenlesung als fehlend GEMESSEN hat. Der Befund war nicht "der
    # Defekt kommt durch" — er kommt nicht durch —, sondern: fuenf Klassen haengen an EINER
    # Testdatei, und faellt sie je weg, meldet das Mutations-Tor still gruen statt SURVIVED. Ein
    # Operator ist die Anti-Goodhart-Ebene: er merkt, wenn das Korpus schrumpft.
    ("src/proofbundle/tlogproof.py",
     'log_ok = bool(log_res["ok"]) and (expected_origin is None or log_res["origin"] == expected_origin)',
     'log_ok = bool(log_res["ok"]) and (expected_origin is None or __import__("unicodedata").normalize("NFC", str(log_res["origin"])) == __import__("unicodedata").normalize("NFC", str(expected_origin)))',
     "tlogproof: origin comparison normalises canonically (NFC) — a decomposed name would pass", True),
    ("src/proofbundle/tlogproof.py",
     'log_ok = bool(log_res["ok"]) and (expected_origin is None or log_res["origin"] == expected_origin)',
     'log_ok = bool(log_res["ok"]) and (not expected_origin or log_res["origin"] == expected_origin)',
     "tlogproof: absent collapses into empty — an empty expectation would skip the check", True),
    ("src/proofbundle/cli.py",
     'f"log-signature: {_safe_line(str(res[\'origin\']))}{origin_note}")',
     'f"log-signature: {str(res[\'origin\'])}{origin_note}")',
     "cli: control-character neutralisation dropped on the origin line (forged verdict line)", True),
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
     "if not merkle.verify_inclusion(disclosure_bytes, index, n, proof, root):",
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
    # 2026-08-30: beide Zeilen auf den heutigen Quelltext gezogen. 38a672a normalisierte
    # `newest.sig_alg` in ein `_sig_label`; der Operator nannte weiter den alten Wortlaut und war
    # damit STALE — er meldete eine Luecke, die im PRUEFER lag und nicht im Code. Ersatz mitgezogen,
    # sonst mutierte er nebenbei die Normalisierung zurueck und aenderte zwei Dinge statt einem.
    ("src/proofbundle/renewal.py",
     'pq_verified = anchored and anchor_mode == "authority signature" and "mldsa" in _sig_label',
     'pq_verified = "mldsa" in _sig_label',
     "renewal: F1 require_pq reverted to label-only (unverified PQ label passes)", True),
    # F2 — dropping the future-time guard lets a future-dated newest ATS read as perpetually fresh.
    ("src/proofbundle/renewal.py",
     "    if _ints and newest.time > now:",
     "    if False and _ints and newest.time > now:",
     "renewal: F2 future-dated ATS guard disabled (never overdue)", True),
    # R1 — forcing the hash-strength check green ignores require_current_hash on a deprecated newest hash.
    ("src/proofbundle/renewal.py",
     "        hash_ok = newest_current if require_current_hash else True",
     "        hash_ok = True",
     "renewal: R1 require_current_hash floor disabled (deprecated/unknown newest passes)", True),
    # R2 — dropping the version>1 chain requirement re-opens the version-2-genesis rotation bypass.
    ("src/proofbundle/trust_pack.py",
     "    if _is_int(ver) and ver >= 2 and pv is None:",
     "    if False and _is_int(ver) and ver >= 2 and pv is None:",
     "trust_pack: R2 version>1 prevVersionDigest requirement disabled (v2-genesis bypass)", True),
    # F7 — not collecting nested digests from a committed disclosure's value breaks recursive disclosures
    # AND (the security direction) would let nothing further be rooted; the recursive test kills it.
    ("src/proofbundle/sdjwt.py",
     "                _collect_committed_digests(parsed[-1], newly)",
     "                pass",
     "sdjwt: F7 recursive-disclosure collection disabled (valid recursive vectors fail)", True),
    # Finding 20 / issue #27 (2026-07-15) — ES256 issuer-signature interop. Each new fail-closed /
    # alg-aware guard must be killed by its test, mirroring the v3.0.0 four-defenses convention above.
    # Removing the ES256 dispatch entry must fail the real (now cryptographically verified) vendored
    # ES256 vectors — tests/test_sdjwtvc_external_vectors.py's
    # TestSdjwtVcIssuerSignatureExternalVectors.test_all_examples_issuer_signature_verifies.
    ("src/proofbundle/sdjwt.py",
     '_ISSUER_SIG_VERIFIERS = {"EdDSA": verify_ed25519, "ES256": verify_ecdsa_p256}',
     '_ISSUER_SIG_VERIFIERS = {"EdDSA": verify_ed25519}',
     "sdjwt: Finding 20 ES256 issuer-signature dispatch removed (real ES256 vectors stop verifying)", True),
    # signature.verify_ecdsa_p256 fail-open: dropping the real cryptographic verify call while still
    # returning True would let ANY wrong key/tampered message/tampered signature "verify" — killed by
    # tests/test_signature.py's TestVerifyEcdsaP256 (wrong key / tampered message / tampered signature).
    ("src/proofbundle/signature.py",
     "        pub.verify(der_sig, bytes(message), ec.ECDSA(hashes.SHA256()))\n        return True",
     "        return True",
     "signature: ES256 verify_ecdsa_p256 crypto check bypassed (fail-open)", True),
    # SPIEGELBILD FUER Ed25519, und es fehlte — obwohl das der HAUPTPFAD ist. Ein Gate-Meta-Test hat
    # die Asymmetrie gemessen: derselbe Fail-open in `verify_ed25519` liess 70 Tests quer durch
    # dsse/checkpoint/decision/conformance rot werden, waehrend die Anti-Goodhart-Ebene fuer genau
    # diesen Pfad keinen Operator hatte. Die Testebene war also stark und der Waechter DARUEBER
    # blind: schruempfte das Korpus je, meldete das Tor still gruen statt SURVIVED.
    ("src/proofbundle/signature.py",
     "        Ed25519PublicKey.from_public_bytes(bytes(public_key)).verify(bytes(signature), bytes(message))\n        return True",
     "        return True",
     "signature: EdDSA verify_ed25519 crypto check bypassed (fail-open)", True),
    # bundle.py sd-jwt-issuer-identity fingerprint reverted to hardcoded "ed25519:" regardless of the
    # alg that actually verified — a false REJECT for a genuinely valid ES256-signed sd_jwt_vc that
    # discloses an "es256:"-prefixed issuer; killed by tests/test_bundle.py's
    # test_es256_sd_jwt_issuer_identity_uses_alg_aware_prefix.
    ("src/proofbundle/bundle.py",
     '_verified_alg = sd_res.get("alg")\n                _fp_prefix = {"EdDSA": "ed25519:", "ES256": "es256:"}.get(_verified_alg, "ed25519:") \\\n'
     '                    if isinstance(_verified_alg, str) else "ed25519:"',
     '_fp_prefix = "ed25519:"',
     "bundle: Finding 20 alg-aware sd-jwt-issuer-identity fingerprint reverted to hardcoded ed25519", True),
    # Crypto-review 2026-07-15 remediation — each new fail-closed guard must be killed by its own test.
    # C1: removing the DSSE signatures cap re-opens the O(n) verify-loop DoS (a million-entry signatures
    # list) — killed by tests/test_budget.py's TestDsseSignaturesCapDoS.
    ("src/proofbundle/dsse.py",
     '    DEFAULT_BUDGET.check("signatures", len(sigs))',
     "    pass",
     "dsse: C1 signatures-list DoS cap removed (oversized signatures list no longer refused)", True),
    # C2: forcing the require_external_token-absent branch off re-opens the fail-open where a MITM strips a
    # detached external_token from an authority-signed ATS — killed by test_renewal_external_token_glue.py's
    # test_require_external_token_fails_closed_when_absent.
    ("src/proofbundle/renewal.py",
     "    elif require_external_token:",
     "    elif False:",
     "renewal: C2 require_external_token absent-token fail-closed disabled (silent no-op require)", True),
    # C3: disabling the executor==receiver distinctness check lets an executor self-corroborate its own
    # outcome up to INDEPENDENTLY_ATTESTED — killed by test_outcome_receiver_corroboration.py's
    # test_receiver_ref_that_is_the_executor_is_not_independent.
    ("src/proofbundle/assurance.py",
     "    if not isinstance(executor_key_id, str) or not isinstance(receiver_key_id, str) or receiver_key_id == executor_key_id:",
     "    if False:",
     "assurance: C3 receiver-independence distinctness check disabled (self-corroboration / omitted-keyId / non-str-keyId reaches INDEPENDENTLY_ATTESTED)", True),
    # Refuter round 2 — dsse payload pre-decode DoS cap: removing it lets an oversized base64 payload be
    # fully decoded before any cap — killed by tests/test_budget.py's
    # test_verify_envelope_rejects_oversized_base64_payload_before_decode.
    ("src/proofbundle/dsse.py",
     "    if len(p) > DEFAULT_BUDGET.input_bytes:",
     "    if False:",
     "dsse: pre-decode base64 payload DoS cap removed (oversized payload decoded unbounded)", True),
    # Crypto-review 2026-07-15 refuter residuals — each new fail-closed guard killed by its own test.
    # C1.1: removing the raw-size cap re-opens the pre-parse DoS (a 50 MB envelope parses fully before the
    # signatures loop cap runs) — killed by tests/test_budget.py's test_rejects_oversized_raw_input_before_parse.
    ("src/proofbundle/_strict_json.py",
     "    if len(text) > b.input_bytes:",
     "    if False:",
     "_strict_json: C1.1 raw input_bytes pre-parse cap removed (oversized envelope parsed unbounded)", True),
    # json_nodes: disabling the node walk lets a wide-but-small-bytes structure (many nodes under the byte
    # cap) through — killed by test_rejects_excessive_node_count / test_json_nodes_default_is_wired_not_dead.
    ("src/proofbundle/_strict_json.py",
     "    while stack:",
     "    while False:",
     "_strict_json: json_nodes parsed-structure node-count cap disabled (high-density DoS)", True),
    # C1.2: dropping the non-list signatures fail-closed lets a non-list (JSON true / a huge dict) skip the
    # cap and raise an uncaught TypeError instead — killed by test_trust_pack.py's
    # test_non_list_signatures_rejected_cleanly.
    ("src/proofbundle/trust_pack.py",
     "    if not isinstance(_sigs, list) or not _sigs:",
     "    if False:",
     "trust_pack: C1.2 non-list signatures fail-closed removed (cap bypass / uncaught TypeError)", True),
    # relation/v0.1 3.4.0 — the five new load-bearing guards (WP-A signer, WP-A2 target/subject).
    # (i) key comparison degraded to length-only (any 32-byte key would match — the keyId-alias class):
    #     killed by test_relation_signer_target_340.TestSignerDecisionPath.test_pinned_non_member_unauthorized.
    ("src/proofbundle/relation.py",
     "    return len(ra) == 32 and ra == rb",
     "    return len(ra) == 32",
     "relation_signer: key byte-equality degraded to length-only (keyId-alias class)", True),
    # (ii) pinned-set membership ignored (successor always authorized): killed by the same test +
    #      the Hypothesis membership property.
    ("src/proofbundle/relation.py",
     "            if not any(_keys_equal(successor_key_b64, k) for k in keys):",
     "            if False:",
     "relation_signer: pinned-set membership ignored (never unauthorized)", True),
    # (iii) same-key verified_under binding removed (cross-issuer sneaks past same-key): killed by
    #       test_same_key_cross_issuer_rejected / verified-under-not-claim vector.
    ("src/proofbundle/relation.py",
     "if vu is None or not _keys_equal(successor_key_b64, vu):",
     "if False:",
     "relation_signer: same-key verified_under binding removed", True),
    # (iv) require_relation_target equality check disabled (the DECOY parent slips through): killed by
    #      test_decoy_parent_fails_closed / decoy-parent conformance vectors.
    ("src/proofbundle/relation.py",
     "        if not (isinstance(_td, str) and _td in set(allowed)):",
     "        if False:",
     "require_relation_target: parent equality check disabled (decoy parent passes)", True),
    # (v) targetSubjectDigest gegenpruefung inverted (O2 no longer catches a lying subject): killed by
    #     TestTargetSubjectDigestO2.test_wrong_subject_digest_fails_lineage (and the correct-subject one).
    ("src/proofbundle/relation.py",
     "if declared != actual:",
     "if declared == actual:",
     "targetSubjectDigest: O2 gegenpruefung inverted (lying subject not caught)", True),
    # relation-statement/v0.1 3.5.0 — three new load-bearing guards on the standalone profile.
    # (vi) exactly-one-edge structure gate removed (a multi-edge / zero-edge statement no longer fails):
    #      killed by test_relation_statement.TestValidation.test_exactly_one_edge_required.
    ("src/proofbundle/relation_statement.py",
     "        if isinstance(rels, list) and len(rels) != 1:",
     "        if False and isinstance(rels, list) and len(rels) != 1:",
     "relation-statement: exactly-one-edge structure gate removed", True),
    # (vii) reject_retracted self-assertion gate disabled (a verified retracts statement no longer
    #       blocks continued automated use): killed by TestPolicyGates.test_reject_retracted_blocks.
    # 2026-08-30: beide Zeilen auf den heutigen Quelltext gezogen. fd84e1d ("27 Mitgliedstests
    # hashten Angreiferdaten — die Klasse, nicht die 27 Zeilen") routete den Mitgliedstest durch
    # is_member; der Operator nannte weiter `rel0 in ...` und war damit STALE. Ersatz mitgezogen,
    # sonst mutierte er nebenbei die Haertung zurueck und aenderte zwei Dinge statt einem.
    ("src/proofbundle/relation_statement.py",
     "        if resolved and relations.get(\"reject_retracted\") and is_member(rel0, _SELF_ASSERTED_RETRACTORS):",
     "        if False and relations.get(\"reject_retracted\") and is_member(rel0, _SELF_ASSERTED_RETRACTORS):",
     "relation-statement: reject_retracted gate disabled (retracts no longer blocks)", True),
    # (viii) lattice violation — cryptoValid dropped from the aggregate `ok` (a forged statement with a
    #        valid structure would read ok): killed by TestEmitVerify.test_forged_signature_fails_and_no_trust_fields.
    ("src/proofbundle/relation_statement.py",
     "        r[\"crypto_ok\"] and r[\"structure_ok\"] and r[\"predicate_type_ok\"]",
     "        r[\"structure_ok\"] and r[\"predicate_type_ok\"]",
     "relation-statement: cryptoValid dropped from aggregate ok (lattice violation)", True),
    # 3.6.3 never-raise residual (adversarial re-audit r7) — three new fail-closed guards on
    # direct-low-level-API sinks. Each disabled guard re-opens a raw type-confusion crash caught by
    # tests/test_never_raise_surface_family_property.py::test_round5_nested_config_subfield_regression
    # (R7-1/R7-2/R7-3 pins). Generator-hardening: a future rewrite that drops one goes red HERE.
    # R7-1 — verify_relationship_edges subject_hex non-str coercion (unhashable {subject_hex} seed).
    ("src/proofbundle/relation.py",
     "    subject_hex = subject_hex if isinstance(subject_hex, str) else None",
     "    subject_hex = subject_hex",
     "relation: R7-1 subject_hex non-str coercion disabled (unhashable cycle-seed crash)", True),
    # R7-2 — evaluate_relations_policy non-dict edges-element filter (three sinks: relation/signer/target).
    ("src/proofbundle/relation.py",
     "    edges = [e for e in edges if isinstance(e, dict)]",
     "    edges = list(edges)",
     "relation: R7-2 non-dict edges-element filter disabled (e.get crash on all three sinks)", True),
    # R7-3 — _authenticate_trusted_checkpoint non-dict entry guard (entry.get before its own try/except).
    ("src/proofbundle/policy.py",
     "    if not isinstance(entry, dict):\n        return False, \"trusted checkpoint entry not an object\"",
     "    if False:\n        return False, \"trusted checkpoint entry not an object\"",
     "policy: R7-3 non-dict trusted_checkpoint entry guard disabled (entry.get crash)", True),
    # R7-2b (adversarial re-audit siblings, iter 1 -> 2) — three more evaluate_relations_policy sinks.
    ("src/proofbundle/relation.py",
     "    lineage_result = lineage_result if isinstance(lineage_result, dict) else {}",
     "    lineage_result = lineage_result",
     "relation: R7-2b non-dict lineage_result coercion disabled (reject_superseded .get crash)", True),
    ("src/proofbundle/relation.py",
     "        rule = signer.get(_rel) if isinstance(_rel, str) else None",
     "        rule = signer.get(_rel)",
     "relation: R7-2b unhashable relation signer-lookup guard disabled (dict-key TypeError)", True),
    ("src/proofbundle/relation.py",
     "        pinned = target_pin.get(_rel) if isinstance(_rel, str) else None",
     "        pinned = target_pin.get(_rel)",
     "relation: R7-2b unhashable relation target-lookup guard disabled (dict-key TypeError)", True),
]


# Repositoriumsweite Pruefungen, die je Mutante NICHTS aussagen (Owner-GO 2026-09-02T12:21:21Z).
#
# WARUM ES DAS GIBT. Das Tor faehrt die Suite 88 Mal. Gemessen am 02.09. traegt EINE Datei
# 174,5 s der 223,9 s langen Tor-Suite, also 78 Prozent — und sie prueft das REPOSITORIUM
# (baut zwei sdists und vergleicht sie byteweise, sweept den Baum auf verbotene Muster), nicht
# den mutierten Quelltext. Achtundachtzig Mal dieselbe Antwort auf dieselbe Frage.
#
# WAS DER AUSSCHLUSS NICHT DARF. Er gilt AUSSCHLIESSLICH fuer die Laeufe je Mutante. Baseline
# und Schlusslauf fahren die volle Suite, damit die Leftover-Pruefung und der differentielle
# Bezug unveraendert bleiben. Ein Ausschluss, der auch die Baseline betraefe, verschoebe den
# Bezugspunkt und machte das Tor blind statt schnell.
#
# WIE ES BELEGT WIRD. Abnahme ist NICHT Zeit, sondern Verdikt: alle 88 Operatoren laufen einmal
# mit Ausschluss und werden Operator fuer Operator gegen den kanonischen Lauf vom 30.08.
# verglichen (87 KILLED, 1 erwarteter SURVIVED). Stirbt ein Operator NUR durch eine
# ausgeschlossene Datei, bleibt sie fuer ihn drin oder bekommt einen Unit-Test als Ersatz.
_AUSSCHLUSS_JE_MUTANTE: dict[str, str] = {
    "test_audit_candidate_360": (
        "Repositoriumsweite Kandidaten-Matrix: neun evaluate()-Aufrufe ueber 33 Pruefungen, die "
        "den Baum, die Registry und zwei frisch gebaute sdists befragen. 174,5 s von 223,9 s der "
        "Tor-Suite (78 Prozent), gemessen 2026-09-02. Kein Eintrag darin liest den mutierten "
        "Quelltext, deshalb sagt sie je Mutante nichts."),
}

# Der Lauf je Mutante als Programm: `unittest discover` kennt keinen Ausschluss, und ein
# handgebauter Modulnamen-Aufruf haette andere Fehlersemantik (ein Importfehler wuerde hart
# abbrechen statt als _FailedTest zu zaehlen). Deshalb wird discover UNVERAENDERT gefahren und
# erst danach gefiltert — die Population bleibt dieselbe minus der benannten Dateien.
_FILTER_PROGRAMM = """
import sys, unittest
ausschluss = set(sys.argv[1:])
lader = unittest.TestLoader()
suite = lader.discover("tests", top_level_dir="tests")
def sieben(s):
    raus = unittest.TestSuite()
    for t in s:
        if isinstance(t, unittest.TestSuite):
            raus.addTest(sieben(t))
        elif t.__class__.__module__ not in ausschluss:
            raus.addTest(t)
    return raus
ergebnis = unittest.TextTestRunner(verbosity=1).run(sieben(suite))
sys.exit(0 if ergebnis.wasSuccessful() else 1)
"""


def _red_count(work: Path, *, ausschluss: bool = False) -> int:
    # Stale-bytecode defense (real incident during per-sample development): a same-size
    # mutation + coarse-mtime filesystem leaves a VALID-looking .pyc for the OLD code; -B only
    # stops WRITING caches — existing ones are still read; and cache dirs may be undeletable on
    # restricted mounts. The robust invalidation is touching every source mtime, forcing
    # recompilation regardless of what caches survive.
    import os  # noqa: PLC0415
    import shutil  # noqa: PLC0415
    for cache in work.rglob("__pycache__"):
        shutil.rmtree(cache, ignore_errors=True)
    for src_file in work.glob("src/**/*.py"):
        os.utime(src_file)
    # DER AUSDRUCK STEHT IM AUFRUF, NICHT DAVOR — und das ist kein Stilfrage.
    # `tests/test_dokumentierte_laeufer_koennen_die_suite_fahren.py::_startet_suite` erkennt einen
    # Suite-Laeufer daran, dass die Zeichenketten "unittest" und "discover" INNERHALB des
    # subprocess-Knotens stehen. Eine Zwischenvariable macht diese Datei fuer den Waechter
    # unsichtbar, obwohl sie die Suite unveraendert startet — beim ersten Versuch am 02.09.2026
    # genau so gemessen: der Waechter meldete den Laeufer als VERSCHWUNDEN.
    proc = subprocess.run(
        ([sys.executable, "-B", "-c", _FILTER_PROGRAMM, *sorted(_AUSSCHLUSS_JE_MUTANTE)]
         if ausschluss else
         [sys.executable, "-B", "-m", "unittest", "discover", "-s", "tests"]),
        cwd=work, capture_output=True, text=True,
        env={"PYTHONPATH": "src", "PATH": "/usr/bin:/bin:/usr/local/bin",
             "HOME": str(Path.home()), "PYTHONDONTWRITEBYTECODE": "1"})
    f = re.search(r"failures=(\d+)", proc.stderr)
    e = re.search(r"errors=(\d+)", proc.stderr)
    return (int(f.group(1)) if f else 0) + (int(e.group(1)) if e else 0)


def _tracked_files(repo: Path) -> list[str]:
    """Tracked paths (current working-tree bytes are copied, so uncommitted edits ARE tested)."""
    proc = subprocess.run(["git", "-C", str(repo), "ls-files", "-z"],
                          capture_output=True, text=True)
    if proc.returncode != 0:
        raise SystemExit("mutation_check: `git ls-files` failed; the isolated work tree needs "
                         "a git checkout (CI and dev clones both have one)")
    return [rel for rel in proc.stdout.split("\0") if rel]


def _prepare_workdir(repo: Path, work: Path) -> None:
    """Copy every tracked file into the throwaway work tree (CI runs on exactly this file set)."""
    for rel in _tracked_files(repo):
        src_p = repo / rel
        if not src_p.is_file():
            continue  # racy delete / submodule entry, the differential baseline absorbs it
        dst = work / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src_p, dst)


def _worktree_status(repo: Path) -> str:
    proc = subprocess.run(["git", "-C", str(repo), "status", "--porcelain"],
                          capture_output=True, text=True)
    return proc.stdout if proc.returncode == 0 else "<git status unavailable>"


def partition(gesamt: int, i: int, k: int) -> list[int]:
    """Die deterministische Partition der Operatorenliste — Indizes fuer Shard i von k.

    ROUND-ROBIN, nicht blockweise: die Operatoren sind nach Datei gruppiert, und ein Block wuerde
    einem Shard alle teuren Operatoren derselben Datei geben. Round-robin verteilt sie.

    Die Partition ist eine reine Funktion von (gesamt, i, k) — kein Zufall, keine Sortierung nach
    Laufzeit, keine Datei-Reihenfolge. Zwei Laeufe mit denselben Argumenten geben dieselbe Menge,
    und die Vereinigung ueber alle i ist LUECKENLOS die ganze Liste. Genau das prueft der
    Sammel-Job nach.
    """
    if not (1 <= i <= k):
        raise ValueError(f"shard {i}/{k}: i muss zwischen 1 und {k} liegen")
    return list(range(i - 1, gesamt, k))


#: Wo die Gewichte liegen. Fehlt die Datei oder ist sie unbrauchbar, faellt die Partition auf
#: Round-Robin zurueck — laut, nicht still.
GEWICHTE_DATEI = ROOT / "scripts" / "mutation_shard_weights.json"


def lade_gewichte(pfad: Path | None = None) -> tuple[dict[str, float], str]:
    """Die Gewichte je Operator lesen. Zweiter Rueckgabewert ist der GRUND, kein Statuscode.

    Drei Zustaende, nie zwei: Gewichte vorhanden · Datei fehlt · Datei unbrauchbar. Die letzten
    beiden fuehren zum selben Verhalten (Round-Robin), sind aber verschiedene Befunde — eine
    fehlende Datei ist ein Zustand, eine kaputte ist ein Defekt.
    """
    q = pfad or GEWICHTE_DATEI
    if not q.exists():
        return {}, f"keine Gewichtsdatei unter {q.name} — Round-Robin"
    try:
        d = json.loads(q.read_text(encoding="utf-8"))
        g = {str(k): float(v) for k, v in (d.get("sekunden") or {}).items()}
    except Exception as exc:                                   # noqa: BLE001
        return {}, f"Gewichtsdatei unbrauchbar ({type(exc).__name__}) — Round-Robin"
    if not g:
        return {}, "Gewichtsdatei enthaelt keine Sekunden — Round-Robin"
    return g, f"{len(g)} Gewichte aus {q.name} (Quelle {d.get('lauf_id', '?')}, {d.get('datum', '?')})"


def partition_gewichtet(labels: list[str], i: int, k: int,
                        gewichte: dict[str, float]) -> list[int]:
    """Longest-Processing-Time: der teuerste Operator zuerst, auf den bisher leichtesten Shard.

    WARUM NICHT ROUND-ROBIN. Die Wanduhr der Matrix haengt am LAENGSTEN Shard, nicht am Mittel.
    Gemessen am 02.09.2026 lagen die zehn Shards zwischen 931 s und 1232 s bei einem Mittel von
    1116 s — die Spanne von 301 s ist genau der Verlust, den eine gleichmaessigere Verteilung
    zurueckholt. Mehr Shards helfen dagegen wenig, solange ein einzelner teurer Operator einen
    Shard traegt.

    LPT ist deterministisch: absteigend nach Gewicht, bei Gleichstand nach Namen (nicht nach
    Eingabereihenfolge — die haengt an der Datei-Sortierung und aendert sich beim naechsten
    Operator). Bei gleichem Shard-Gewicht gewinnt der niedrigere Index.

    Fehlt ein Operator in den Gewichten, bekommt er das MEDIAN-Gewicht. Nicht 0 (er waere gratis
    und wuerde den letzten Shard ueberladen) und nicht das Maximum (er wuerde einen Shard fuer
    sich allein blockieren).
    """
    if not (1 <= i <= k):
        raise ValueError(f"shard {i}/{k}: i muss zwischen 1 und {k} liegen")
    bekannt = sorted(gewichte.get(lab) for lab in labels if lab in gewichte)
    median = bekannt[len(bekannt) // 2] if bekannt else 1.0
    paare = sorted(((gewichte.get(lab, median), lab, n) for n, lab in enumerate(labels)),
                   key=lambda x: (-x[0], x[1]))
    lasten = [0.0] * k
    koerbe: list[list[int]] = [[] for _ in range(k)]
    for gew, _label, idx in paare:
        ziel = min(range(k), key=lambda s: (lasten[s], s))
        lasten[ziel] += gew
        koerbe[ziel].append(idx)
    return sorted(koerbe[i - 1])


def _run_operators(work: Path, *, shard: tuple[int, int] | None = None) -> int:
    dauern: dict[str, float] = {}
    # SYMMETRIE DER MESSUNG (Stufe 2 Teil A, Befund
    # MUTATIONSTOR-BASELINE-UND-MUTANT-MESSEN-VERSCHIEDENE-SUITEN-01).
    #
    # `killed = red > baseline` vergleicht zwei Zahlen. Bis 2026-09-02 kamen sie aus
    # VERSCHIEDENEN Testmengen: die Baseline lief ohne `ausschluss`, der Mutantenlauf mit. Traegt
    # das ausgeschlossene Modul rot bei, steigt nur die eine Seite — und ein echter Kill wird
    # still zu SURVIVED, also zu einem uebersehenen Defekt.
    #
    # GEMESSEN, nicht argumentiert: mit EINEM gepflanzten roten Test in
    # `tests/test_audit_candidate_360.py` kippten in Shard 1/10 drei von neun Operatoren
    # (`bundle: expected_aud/nonce downgrade-trap`, `renewal: R1 require_current_hash floor`,
    # `dsse: pre-decode base64 payload DoS cap`) von KILLED auf SURVIVED. Ein Test, den das Tor
    # gar nicht mehr misst, entschied ueber drei Verdikte.
    #
    # Die Gesundheit des ausgeschlossenen Moduls wird NICHT aufgegeben: sie haengt an den
    # bindenden `test`-Jobs derselben CI, die die volle Suite fahren, und am kanonischen
    # Volllauf vor jedem Tag. Siehe docs/PRE_TAG_AUDIT.md.
    baseline = _red_count(work, ausschluss=True)
    print(f"baseline red (environment-only failures allowed): {baseline}")
    gaps = 0
    gewichte, gewicht_grund = lade_gewichte()
    print(f"partition: {gewicht_grund}")
    if shard is None:
        indizes = list(range(len(MUTATIONS)))
    else:
        i, k = shard
        # Gewichtet, wenn Gewichte da sind; sonst der bewaehrte Round-Robin. Der Rueckfall ist
        # LAUT (die `partition:`-Zeile oben nennt den Grund) — ein stiller Rueckfall saehe wie
        # eine gewichtete Partition aus und waere keine.
        labels = [m[3] for m in MUTATIONS]
        indizes = (partition_gewichtet(labels, i, k, gewichte) if gewichte
                   else partition(len(MUTATIONS), i, k))
        # Die Partition wird AUSGEGEBEN (Index und Label), damit der Sammel-Job und ein Mensch
        # nachrechnen koennen, welche Operatoren dieser Shard getragen hat. Ein Shard, der seine
        # Menge nicht nennt, laesst sich nicht gegen 88 aufaddieren.
        print(f"shard {i}/{k}: {len(indizes)} von {len(MUTATIONS)} Operatoren")
        for idx in indizes:
            print(f"  shard-item {idx} [{MUTATIONS[idx][3]}]")
    for idx in indizes:
        rel, old, new, label, expect_killed = MUTATIONS[idx]
        path = work / rel
        src = path.read_text(encoding="utf-8")
        # AN OPERATOR MAY NAME SEVERAL SITES, and since 2026-08-17 two of them must.
        #
        # The L4-01 fix (#139) gave the ancestor walker the same gates the direct-edge arm
        # already had — deliberately, because the gate had been distance-scoped and the
        # distance is attacker-chosen. The side effect: two operators that disable ONE line
        # no longer disable the PROPERTY. The other guard still catches the defect, the mutant
        # survives, and the gate reports a gap that is not one.
        #
        # Measured on 518d1ee7: `verified` laxened at the direct arm alone -> suite green;
        # laxened at BOTH -> tests/test_relation_profile.py::…test_verified_flag_must_be_exactly_true
        # goes red. Same shape for the two cycle checks. An operator whose label says
        # "disabled" must actually disable, or the gate measures the wrong thing in the safe
        # direction: it cries gap where the defence holds, and that is how a gate gets ignored.
        pairs = list(zip(old, new)) if isinstance(old, tuple) else [(old, new)]
        missing = [o for o, _ in pairs if o not in src]
        if missing:
            print(f"  GAP  [{label}] pattern not found — operator is stale")
            gaps += 1
            continue
        mutated = src
        for o, n in pairs:
            mutated = mutated.replace(o, n, 1)
        try:
            path.write_text(mutated, encoding="utf-8")
            _t0 = time.monotonic()
            red = _red_count(work, ausschluss=True)
            _dauer = time.monotonic() - _t0
            dauern[label] = round(_dauer, 1)
            killed = red > baseline
            ok = killed == expect_killed
            verdict = "KILLED" if killed else "SURVIVED"
            expected = "expected" if ok else "*** UNEXPECTED ***"
            # Die Dauer steht IN der Verdiktzeile, nicht daneben. Grund, gemessen 2026-09-02: die
            # Zeitstempel des CI-Logs tragen sie nicht — GitHub Actions puffert stdout und schreibt
            # alle Operatorzeilen mit DERSELBEN Marke (16:34:04.494…). Wer die Gewichte fuer die
            # Partition aus dem Log lesen will, findet dort ohne diese Zahl nichts.
            print(f"  {'ok  ' if ok else 'GAP '} [{label}] {verdict} "
                  f"(red={red}, {_dauer:.1f}s) {expected}")
            if not ok:
                gaps += 1
        finally:
            path.write_text(src, encoding="utf-8")  # restore the pristine bytes held in memory
    # Die Gewichtszeile fuer die naechste Partition. Sie steht als EINE Zeile mit JSON, damit ein
    # Leser sie ohne Parser-Heuristik aus dem Log holen kann.
    if dauern:
        print("MUTATION_DURATIONS " + json.dumps(dauern, sort_keys=True))
    final = _red_count(work, ausschluss=True)   # dieselbe Menge wie Baseline und Mutant
    if final != baseline:
        print(f"GAP: baseline not restored ({final} != {baseline})")
        gaps += 1
    return gaps


def main(argv: list[str] | None = None) -> int:
    import argparse  # noqa: PLC0415
    ap = argparse.ArgumentParser(description="mutation gate")
    ap.add_argument("--shard", default=None, metavar="i/K",
                    help="nur Shard i von K fahren (deterministische Round-robin-Partition)")
    # `parse_args(None)` liest sys.argv — unter pytest also DESSEN Argumente, und argparse
    # beendet den Prozess mit SystemExit(2). Genau das hat die CI gefangen:
    # tests/test_mutation_isolation.py ruft `main()` ohne Argumente auf, und der Lauf starb an
    # den pytest-Flags. `None` heisst hier deshalb KEINE Argumente, nicht "nimm sys.argv" —
    # den Prozess-Aufruf traegt der `__main__`-Block, der sys.argv[1:] ausdruecklich uebergibt.
    a = ap.parse_args([] if argv is None else argv)
    shard = None
    if a.shard:
        try:
            i_s, k_s = a.shard.split("/")
            shard = (int(i_s), int(k_s))
        except (ValueError, TypeError):
            raise SystemExit(f"--shard erwartet die Form i/K, bekam {a.shard!r}") from None
        if not (1 <= shard[0] <= shard[1]):
            raise SystemExit(f"--shard {a.shard}: i muss zwischen 1 und K liegen")
    status_before = _worktree_status(ROOT)
    with tempfile.TemporaryDirectory(prefix="proofbundle-mutation-") as tmp:
        work = Path(tmp) / "tree"
        _prepare_workdir(ROOT, work)
        print(f"isolated work tree: {work} (the real working tree is never mutated)")
        # DEN BESTEHENDEN AUFRUF UNVERAENDERT LASSEN, wenn nicht geshardet wird. Die CI hat
        # gefangen, warum das noetig ist: tests/test_mutation_isolation.py ersetzt
        # `_run_operators` durch eine Attrappe OHNE `shard`-Parameter, und ein bedingungslos
        # uebergebenes Schluesselwort bricht sie. Ein neuer Parameter darf den Vertrag des alten
        # Pfades nicht aendern - sonst passt man die Tests an den Code an statt umgekehrt.
        gaps = _run_operators(work) if shard is None else _run_operators(work, shard=shard)
    # Fail-closed leftover check: the probe run must not have changed the REAL working tree at
    # all (v1.4 isolation makes this structurally true; this assert catches any regression).
    status_after = _worktree_status(ROOT)
    if status_after != status_before:
        print("GAP: left-over working tree change after probe run:")
        before, after = set(status_before.splitlines()), set(status_after.splitlines())
        for line in sorted(after - before):
            print(f"  + {line}")
        for line in sorted(before - after):
            print(f"  - {line}")
        gaps += 1
    n_gefahren = len(MUTATIONS) if shard is None else len(partition(len(MUTATIONS), *shard))
    # Die Schlusszeile nennt die GEFAHRENE Zahl, nicht die Gesamtzahl. Ein Shard, der "88
    # operators" meldet, obwohl er elf gefahren hat, macht die Summenpruefung des Sammel-Jobs
    # wertlos — sie wuerde jedes Mal aufgehen.
    _shard_txt = "" if shard is None else f" shard={shard[0]}/{shard[1]}"
    print(f"=> {'OK' if gaps == 0 else 'FAILED'} ({n_gefahren} operators, {gaps} gap(s)){_shard_txt}")
    return 0 if gaps == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
