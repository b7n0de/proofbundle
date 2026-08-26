"""Deep-Gate iter9 5th-round product fixes (makellose-500 Phase 5). The three surviving never-raise
findings, each with an executable regression:
- Linse A: verify_bundle -> sdjwt_issue.check_binds_bundle -> (receipt or {}).get on a truthy non-dict
  receipt raised a raw AttributeError out of the FLAGSHIP verify surface. Fixed via _membership.as_dict.
- Linse B: kbjwt.holder_key_from_cnf's except (ValueError, TypeError) missed BundleFormatError from
  _b64url_decode's DoS guard -> a typed crash instead of the documented None. Fixed by widening the except.
- Linse C: renewal (EXPERIMENTAL) raw crashes on a giant .time (magnitude), an unhashable hash_alg, and a
  non-iterable .signatures. Fixed at _ats_content / the hash lookups / the signature loop.
"""
import base64

import pytest

from proofbundle._membership import as_dict
from proofbundle.errors import ProofBundleError
from proofbundle.kbjwt import holder_key_from_cnf
from proofbundle.renewal import (ArchiveTimeStamp, _ats_content, build_initial_sequence,
                                 evaluate_renewal_policy, verify_sequence, RenewalPolicy)

_D = "ab" * 32


class TestLinseA_AsDict:
    @pytest.mark.parametrize("truthy_non_dict", ["str", [1, 2], 42, True, 3.14])
    def test_as_dict_neutralises_a_truthy_non_dict(self, truthy_non_dict):
        assert as_dict(truthy_non_dict) == {}
        assert as_dict(truthy_non_dict).get("root_b64") is None  # the exact crashing idiom, now safe

    def test_as_dict_passes_a_real_dict_through(self):
        assert as_dict({"root_b64": "x"}).get("root_b64") == "x"

    @pytest.mark.parametrize("bad_receipt", ["not-a-dict", [1, 2], 42, True])
    def test_check_binds_bundle_verdict_not_crash_on_bad_receipt(self, bad_receipt):
        import json
        from proofbundle.sdjwt_issue import check_binds_bundle
        claim = {"passed": True, "threshold": 0.8, "comparator": ">=", "suite": "s", "issuer": "i"}
        # a hand-built SD-JWT compact whose payload carries a truthy NON-DICT receipt (the exact shape
        # Linse A crashed on). check_binds_bundle must return a bool verdict, never a raw AttributeError.
        def _b64u(d):
            return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()
        header = _b64u({"alg": "EdDSA"})
        payload = _b64u({**claim, "receipt": bad_receipt})
        compact = f"{header}.{payload}.c2ln"  # header.payload.sig~ (no disclosures)
        assert check_binds_bundle(compact, claim, "some-root") is False


class TestLinseB_Kbjwt:
    def test_oversized_cnf_jwk_x_returns_none_not_typed_crash(self):
        r = holder_key_from_cnf({"cnf": {"jwk": {"kty": "OKP", "crv": "Ed25519", "x": "A" * 9_000_000}}})
        assert r is None

    def test_normal_key_still_extracted(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        pub = Ed25519PrivateKey.generate().public_key().public_bytes_raw()
        x = base64.urlsafe_b64encode(pub).rstrip(b"=").decode()
        assert holder_key_from_cnf({"cnf": {"jwk": {"kty": "OKP", "crv": "Ed25519", "x": x}}}) == pub


class TestLinseC_Renewal:
    def test_3a_ats_content_giant_time_is_typed_not_raw(self):
        with pytest.raises(ProofBundleError):
            _ats_content("sha256", _D, 10 ** 5000, "ed25519")

    def test_3a_signed_build_with_giant_time_is_typed(self):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        with pytest.raises(ProofBundleError):
            build_initial_sequence([_D], hash_alg="sha256", time=10 ** 5000,
                                   sig_alg="ed25519", signers={"ed25519": Ed25519PrivateKey.generate()})

    @pytest.mark.parametrize("bad_alg", [["not", "str"], {"a": 1}, {1, 2}])
    def test_3b_unhashable_hash_alg_is_a_verdict(self, bad_alg):
        a = ArchiveTimeStamp(bad_alg, _D, 1_700_000_000, "confirmed")
        assert verify_sequence([[a]], [_D]).ok is False
        r = evaluate_renewal_policy([[a]], policy=RenewalPolicy(max_ats_age=100), now=2000)
        assert hasattr(r, "ok")  # a verdict, not a raw TypeError

    @pytest.mark.parametrize("bad_sigs", [123, True, 3.14, object()])
    def test_3c_non_iterable_signatures_is_a_verdict(self, bad_sigs):
        a = ArchiveTimeStamp("sha256", _D, 1_700_000_000, "confirmed", sig_alg="ed25519", signatures=bad_sigs)
        assert verify_sequence([[a]], [_D], authority_keys={"ed25519": [b"\x00" * 32]}).ok is False
