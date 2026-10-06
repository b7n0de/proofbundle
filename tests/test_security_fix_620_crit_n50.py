"""Addendum 50 (`KRAXO-CLOUD-N50-CRIT-KOPF-FAIL-CLOSED-01`, Z309 / 6.2.0).

RFC 7515 section 4.1.11: a protected JWS header may carry ``crit``, a list of extension header
parameters the producer declares MUST be understood; a verifier that does not understand one MUST treat
the JWS as invalid. proofbundle understands NO JWS extension, so any ``crit`` present in a protected
header must fail closed. Before this addendum the local JWS verifiers read only ``typ``/``alg`` and
ignored ``crit``, so a genuinely signed token with ``crit`` reached a positive verdict (K5-01
``kbjwt.verify_key_binding`` ok True; K5-02 ``sdjwt.verify_sd_jwt`` structure_ok/sig_ok True; and the
siblings ``statuslist.verify_status_snapshot`` and ``experimental.enclave.verify_enclave_attestation``
ok True). The shared helper ``signature.reject_jws_crit`` is now the single decision site; each verifier
calls it right after reading the header and before any other field. Narrowing only; a header without
``crit`` is unchanged.

Each finding is measured RED at the base 8127b81a (crit reached a positive verdict) and GREEN at the
head (crit is refused, the control without crit still verifies). Counter-probes are rebuilt from the
repository fixtures and re-signed with the SAME test key; only ``crit`` is added to the protected header.
"""
from __future__ import annotations

import base64
import json
import unittest

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from proofbundle import generate_signer
from proofbundle.evalclaim import build_eval_claim, emit_eval_receipt
from proofbundle.kbjwt import verify_key_binding
from proofbundle.sdjwt import verify_sd_jwt
from proofbundle.sdjwt_issue import issue_sd_jwt, present_with_key_binding
from proofbundle.signature import reject_jws_crit
from proofbundle.statuslist import issue_status_list_token, verify_status_snapshot

_IAT = 1_780_000_000


def _raw(k) -> bytes:
    return k.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def _resign_jws(jws: str, signer, *, header_update: dict) -> str:
    """Rebuild a compact JWS equal to ``jws`` but with ``header_update`` merged into its protected
    header, re-signed with ``signer``. Isolates the header change: everything else is byte-identical."""
    h_b64, p_b64, _ = jws.split(".")
    header = json.loads(_b64u_dec(h_b64))
    header.update(header_update)
    new_h = _b64u(json.dumps(header).encode())
    si = (new_h + "." + p_b64).encode("ascii")
    return new_h + "." + p_b64 + "." + _b64u(signer.sign(si))


def _sd_compact(signer, holder) -> str:
    ev_claim, _ = build_eval_claim(
        suite="safety", suite_version="1", metric="acc", comparator=">=", threshold="0.8",
        score="0.9", n=100, model_id="m", dataset_id="d", issuer="placeholder",
        timestamp="2026-07-09T10:00:00Z", assurance_level="reproduced")
    plain = emit_eval_receipt(ev_claim, signer)
    real_root = (plain.get("merkle") or {}).get("root_b64")
    sd_claim = json.loads(base64.b64decode(plain["payload_b64"]))
    return issue_sd_jwt(sd_claim, signer, root_b64=real_root, exact_score="0.9",
                        holder_public_key=_raw(holder))


_CRIT_UNKNOWN = {"crit": ["future"], "future": True}


class K5_01_KbJwtCritFailsClosed(unittest.TestCase):
    """K5-01: a KB-JWT whose protected header carries an un-understood ``crit`` is refused. RED at
    8127b81a (ok True), GREEN at head (ok False, control without crit still ok True)."""

    def _presented(self):
        signer, holder = generate_signer(), generate_signer()
        compact = _sd_compact(signer, holder)
        presented = present_with_key_binding(compact, holder, aud="v.example", nonce="n", iat=_IAT)
        return presented, holder

    def test_crit_kb_header_is_refused(self):
        presented, holder = self._presented()
        sd_part, sep, kb = presented.rpartition("~")
        bad = sd_part + sep + _resign_jws(kb, holder, header_update=_CRIT_UNKNOWN)
        res = verify_key_binding(bad, expected_aud="v.example", expected_nonce="n")
        self.assertIs(res["present"], True)
        self.assertIs(res["ok"], False, "a KB-JWT with an un-understood crit must not verify")
        self.assertIn("crit", res["detail"])

    def test_control_without_crit_still_verifies(self):
        presented, _ = self._presented()
        res = verify_key_binding(presented, expected_aud="v.example", expected_nonce="n")
        self.assertIs(res["ok"], True, "the same presentation without crit still verifies")


class K5_02_SdJwtCritFailsClosed(unittest.TestCase):
    """K5-02: an SD-JWT whose issuer protected header carries ``crit`` fails closed — structure_ok stays
    False and no signature is checked. RED at 8127b81a (structure_ok/sig_ok True), GREEN at head."""

    def _compact_and_pub(self):
        signer, holder = generate_signer(), generate_signer()
        return _sd_compact(signer, holder), _raw(signer), signer

    def test_crit_issuer_header_is_refused(self):
        compact, pub, signer = self._compact_and_pub()
        issuer_jws, sep, rest = compact.partition("~")
        bad = _resign_jws(issuer_jws, signer, header_update=_CRIT_UNKNOWN) + sep + rest
        res = verify_sd_jwt(bad, pub)
        self.assertIs(res["structure_ok"], False, "an issuer JWS with crit is not structurally valid")
        self.assertIs(res["sig_ok"], False, "no signature verdict is formed once crit is rejected")
        self.assertIn("crit", res["detail"])

    def test_control_without_crit_still_verifies(self):
        compact, pub, _ = self._compact_and_pub()
        res = verify_sd_jwt(compact, pub)
        self.assertIs(res["structure_ok"], True)
        self.assertIs(res["sig_ok"], True)


class SiblingStatusListCritFailsClosed(unittest.TestCase):
    """Sibling (VERTRAG 6): a Status List Token with ``crit`` is refused. RED at 8127b81a (ok True)."""

    def _tok(self, signer):
        return issue_status_list_token([0, 1, 0], uri="https://example/sl/1", signer=signer, iat=_IAT, bits=2)

    def test_crit_is_refused(self):
        signer = generate_signer()
        bad = _resign_jws(self._tok(signer), signer, header_update=_CRIT_UNKNOWN)
        res = verify_status_snapshot(bad, expected_uri="https://example/sl/1", index=1, issuer_pubkey=_raw(signer))
        self.assertIs(res["ok"], False, "a Status List Token with an un-understood crit must not verify")
        self.assertIn("crit", res["detail"])

    def test_control_without_crit_still_verifies(self):
        signer = generate_signer()
        res = verify_status_snapshot(self._tok(signer), expected_uri="https://example/sl/1", index=1,
                                     issuer_pubkey=_raw(signer))
        self.assertIs(res["ok"], True)


class SiblingEnclaveCritFailsClosed(unittest.TestCase):
    """Sibling (VERTRAG 6): an enclave EAT with ``crit`` is refused. RED at 8127b81a (ok True)."""

    def test_crit_is_refused_and_control_verifies(self):
        from proofbundle.experimental.enclave import (issue_enclave_attestation,
                                                       verify_enclave_attestation)
        signer = generate_signer()
        binding = "sha256:" + "ab" * 32
        eat = issue_enclave_attestation(binding, signer, profile="tdx", tier="hardware", iat=_IAT)
        bad = _resign_jws(eat, signer, header_update=_CRIT_UNKNOWN)
        res = verify_enclave_attestation(bad, verifier_pubkey=_raw(signer), expected_binding=binding)
        self.assertIs(res["ok"], False, "an EAT with an un-understood crit must not verify")
        self.assertIn("crit", res["detail"])
        good = verify_enclave_attestation(eat, verifier_pubkey=_raw(signer), expected_binding=binding)
        self.assertIs(good["ok"], True, "the same EAT without crit still verifies")


class TheFiveCritForms(unittest.TestCase):
    """VERTRAG TESTS: one case each for crit unknown / empty / not-a-list / a registered name / a named
    parameter absent from the header — each refused at a real verifier (verify_sd_jwt), the control
    without crit positive. Plus the helper's own coverage of every form (single decision site)."""

    def _sd_with_header(self, header_update):
        signer, holder = generate_signer(), generate_signer()
        compact = _sd_compact(signer, holder)
        issuer_jws, sep, rest = compact.partition("~")
        bad = _resign_jws(issuer_jws, signer, header_update=header_update) + sep + rest
        return verify_sd_jwt(bad, _raw(signer))

    def test_unknown_extension_is_refused(self):
        self.assertIs(self._sd_with_header({"crit": ["future"], "future": True})["structure_ok"], False)

    def test_empty_crit_is_refused(self):
        self.assertIs(self._sd_with_header({"crit": []})["structure_ok"], False)

    def test_crit_not_a_list_is_refused(self):
        self.assertIs(self._sd_with_header({"crit": True})["structure_ok"], False)

    def test_crit_naming_a_registered_parameter_is_refused(self):
        self.assertIs(self._sd_with_header({"crit": ["alg"]})["structure_ok"], False)

    def test_crit_naming_an_absent_parameter_is_refused(self):
        self.assertIs(self._sd_with_header({"crit": ["future"]})["structure_ok"], False)

    def test_the_helper_rejects_every_form_and_accepts_no_crit(self):
        self.assertIsNone(reject_jws_crit({"alg": "EdDSA", "typ": "kb+jwt"}))
        self.assertIsNone(reject_jws_crit({"alg": "EdDSA"}))              # no crit member
        for header in (
            {"alg": "EdDSA", "crit": ["x"], "x": True},                  # unknown extension
            {"alg": "EdDSA", "crit": []},                                # empty
            {"alg": "EdDSA", "crit": True},                              # not a list
            {"alg": "EdDSA", "crit": ["alg"]},                           # registered name
            {"alg": "EdDSA", "crit": ["x"]},                             # named param absent
            {"alg": "EdDSA", "crit": ["x", "x"], "x": True},             # duplicate
            {"alg": "EdDSA", "crit": [1], "1": True},                    # non-string entry
        ):
            self.assertIsInstance(reject_jws_crit(header), str,
                                  f"crit form must be rejected: {header!r}")


class BundleWithCritKbJwtFailsClosed(unittest.TestCase):
    """VERTRAG TESTS: the result passes through verify_bundle — a bundle whose KB-JWT carries crit has a
    failing ``sd-jwt-key-binding`` check (the bundle's aggregate is not ok)."""

    def test_sd_jwt_key_binding_check_is_false(self):
        from proofbundle import verify_bundle
        signer, holder = generate_signer(), generate_signer()
        ev_claim, _ = build_eval_claim(
            suite="safety", suite_version="1", metric="acc", comparator=">=", threshold="0.8",
            score="0.9", n=100, model_id="m", dataset_id="d", issuer="placeholder",
            timestamp="2026-07-09T10:00:00Z", assurance_level="reproduced")
        plain = emit_eval_receipt(ev_claim, signer)
        real_root = (plain.get("merkle") or {}).get("root_b64")
        sd_claim = json.loads(base64.b64decode(plain["payload_b64"]))
        compact = issue_sd_jwt(sd_claim, signer, root_b64=real_root, exact_score="0.9",
                               holder_public_key=_raw(holder))
        presented = present_with_key_binding(compact, holder, aud="v", nonce="n", iat=_IAT)
        sd_part, sep, kb = presented.rpartition("~")
        bad_presented = sd_part + sep + _resign_jws(kb, holder, header_update=_CRIT_UNKNOWN)
        vc = {"compact": bad_presented,
              "issuer_public_key_b64": base64.b64encode(_raw(signer)).decode("ascii")}
        bundle = emit_eval_receipt(ev_claim, signer, sd_jwt=vc)
        result = verify_bundle(bundle)
        checks = {c.name: c for c in result.checks}
        self.assertIn("sd-jwt-key-binding", checks)
        self.assertIs(checks["sd-jwt-key-binding"].ok, False,
                      "a KB-JWT with an un-understood crit must fail the bundle's key-binding check")


if __name__ == "__main__":
    unittest.main()
