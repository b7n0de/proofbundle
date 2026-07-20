"""Generator-hardening property test (adversarial re-audit round 7 completeness lesson).

The never-raise sweep was applied surface-by-surface and repeatedly left an unswept sibling: a public
``verify_*`` / ``check_*`` / ``load_*`` / ``decode_*`` / ``count_*`` function that guards SOME arguments but
lets a non-str / non-bytes / non-dict PRIMARY (untrusted) argument reach an unguarded ``.split()`` / ``len()``
/ ``.get()`` and escape as a raw ``AttributeError`` / ``TypeError`` / ``RecursionError``.

This is the CLASS test, not another point patch: it fuzzes the primary argument of every such public surface
with every wrong type and asserts a fail-closed result — a returned verdict, or a TYPED
``ProofBundleError`` / ``ValueError`` — never a raw type-confusion crash. A new public verify/check surface
that forgets the guard fails here.
"""
import unittest

from proofbundle.errors import ProofBundleError

# The raw exception types a type-confused primary argument produces — none of these may escape a public
# verify/check surface (a typed ProofBundleError / ValueError fail-closed is fine, a returned verdict is fine).
FORBIDDEN_RAW = (AttributeError, TypeError, RecursionError, KeyError, IndexError, UnicodeDecodeError)

BAD_PRIMARIES = [None, 123, 1.5, True, b"bytes-not-str", ["a", "list"], {"k": "v"}, ("t", "u")]

_VALID_VC_POLICY = {"vctAllowlist": ["urn:x"]}


def _cases():
    """(label, call) where call(bad) invokes the surface with `bad` as its untrusted primary arg and valid
    stubs for the rest. Lazy imports so a collection error in one module cannot hide the others."""
    from proofbundle import verify_bundle
    from proofbundle.evalclaim import (
        check_freshness, decode_eval_claim, sd_jwt_hidden_count, verify_commitment,
    )
    from proofbundle.hf_evals import verify_receipt_token
    from proofbundle.kbjwt import verify_key_binding
    from proofbundle.persample import verify_sample_opening
    from proofbundle.sdjwt import verify_sd_jwt
    from proofbundle.sdjwt_issue import check_binds_bundle
    from proofbundle.sdjwt_vc import check_vc_profile, verify_sdjwt_vc
    from proofbundle.statuslist import verify_status_snapshot
    from proofbundle.tlogproof import parse_tlog_proof, verify_tlog_proof
    pk = b"\x00" * 32
    return [
        ("sdjwt.verify_sd_jwt", lambda x: verify_sd_jwt(x)),
        ("sdjwt_vc.check_vc_profile", lambda x: check_vc_profile(x, _VALID_VC_POLICY)),
        ("sdjwt_vc.verify_sdjwt_vc", lambda x: verify_sdjwt_vc(x, _VALID_VC_POLICY)),
        ("sdjwt_issue.check_binds_bundle", lambda x: check_binds_bundle(x, {"passed": True}, "AAAA")),
        ("evalclaim.verify_commitment[identifier]", lambda x: verify_commitment(x, b"s" * 16, "sha256:abc")),
        ("evalclaim.verify_commitment[salt]", lambda x: verify_commitment("gpt", x, "sha256:abc")),
        ("evalclaim.check_freshness", lambda x: check_freshness(x)),
        ("evalclaim.sd_jwt_hidden_count", lambda x: sd_jwt_hidden_count(x)),
        ("evalclaim.decode_eval_claim", lambda x: decode_eval_claim(x)),
        ("kbjwt.verify_key_binding", lambda x: verify_key_binding(x)),
        ("statuslist.verify_status_snapshot",
         lambda x: verify_status_snapshot(x, expected_uri="u", index=0, issuer_pubkey=pk)),
        ("persample.verify_sample_opening", lambda x: verify_sample_opening(x, "AAAA", 10)),
        ("tlogproof.verify_tlog_proof", lambda x: verify_tlog_proof(x, b"leaf", "log+aa+bb")),
        ("tlogproof.parse_tlog_proof", lambda x: parse_tlog_proof(x)),
        ("hf_evals.verify_receipt_token", lambda x: verify_receipt_token(x)),
        ("bundle.verify_bundle", lambda x: verify_bundle(x)),
    ]


class NeverRaisePrimaryArgProperty(unittest.TestCase):
    def test_no_public_verify_check_raises_raw_on_bad_primary(self):
        failures = []
        for label, call in _cases():
            for bad in BAD_PRIMARIES:
                try:
                    call(bad)  # a returned verdict is acceptable
                except (ProofBundleError, ValueError):
                    pass       # a TYPED fail-closed error is acceptable
                except FORBIDDEN_RAW as exc:
                    failures.append(f"{label} on {type(bad).__name__}: raw {type(exc).__name__}: {exc}")
        self.assertEqual(failures, [], "raw type-confusion escapes on public verify/check surfaces:\n"
                         + "\n".join(failures))


if __name__ == "__main__":
    unittest.main()
