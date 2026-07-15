"""WP-B3 — trust policy v0.1 + `verify --policy`.

A relying party's trust decision is first-class, machine-readable, fail-closed and offline. Without a
policy `verify` makes NO trust decision (POLICY: NOT_EVALUATED); with one, a policy failure is exit 3,
distinct from a crypto failure (exit 1). A malformed policy or an aud/policy ambiguity is exit 2.
"""
import base64
import contextlib
import io
import json
import os
import tempfile
import unittest
from pathlib import Path

try:
    import jsonschema
except ImportError:  # pragma: no cover
    jsonschema = None

from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from proofbundle import generate_signer
from proofbundle.cli import main
from proofbundle.evalclaim import build_eval_claim, emit_eval_receipt
from proofbundle.policy import PolicyError, evaluate_policy, load_policy
from proofbundle.sdjwt_issue import issue_sd_jwt, present_with_key_binding

POLICY_SCHEMA = "proofbundle/trust-policy/v0.1"
_ROOT = Path(__file__).resolve().parents[1]
_IAT = 1_780_000_000


def _raw_pub(key) -> bytes:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _sd_jwt_bundle(*, with_issuer_key: bool = True, with_cnf: bool = True,
                   aud: str = "verifier.example", nonce: str = "n-1", vct: str | None = None) -> str:
    """A bundle carrying a real key-bound SD-JWT presentation. ``with_issuer_key=False`` is exactly
    the class where the issuer signature is never checked (the require_nonce fail-open, L1/L2).
    ``vct=None`` uses ``issue_sd_jwt``'s own default (Finding 20: ``sd_jwt.expected_vct`` tests pass
    an explicit value)."""
    from proofbundle.evalclaim import build_eval_claim, emit_eval_receipt  # noqa: PLC0415
    issuer = generate_signer()
    holder = generate_signer()
    # N1 (audit 2026-07-13): bind the eval-carrying SD-JWT to a real eval-claim bundle (grafting onto a
    # non-eval {"x":1} payload is now refused fail-closed).
    ev_claim, _ = build_eval_claim(
        suite="demo-suite", suite_version="1", metric="acc", comparator=">=", threshold="0.80",
        score="0.9", n=100, model_id="m", dataset_id="d", issuer="placeholder",
        timestamp="2026-07-09T10:00:00Z", assurance_level="reproduced")
    plain = emit_eval_receipt(ev_claim, issuer)
    root = plain["merkle"]["root_b64"]
    issuer_field = json.loads(base64.b64decode(plain["payload_b64"]))["issuer"]
    claim = {"passed": True, "threshold": "0.80", "comparator": ">=", "suite": "demo-suite",
             "issuer": issuer_field}
    compact = issue_sd_jwt(claim, issuer, root_b64=root, exact_score="0.9",
                           holder_public_key=_raw_pub(holder) if with_cnf else None,
                           **({"vct": vct} if vct is not None else {}))
    presented = present_with_key_binding(compact, holder, aud=aud, nonce=nonce, iat=_IAT)
    sd_jwt_vc = {"compact": presented}
    if with_issuer_key:
        sd_jwt_vc["issuer_public_key_b64"] = base64.b64encode(_raw_pub(issuer)).decode("ascii")
    bundle = emit_eval_receipt(ev_claim, issuer, sd_jwt=sd_jwt_vc)
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w") as f:
        json.dump(bundle, f)
    return path


def _receipt(*, assurance_level="reproduced", prereg=None, timestamp="2026-07-09T10:00:00Z"):
    """A signed eval receipt; returns (path, signer_public_key_b64)."""
    signer = generate_signer()
    claim, _ = build_eval_claim(
        suite="safety", suite_version="1", metric="acc", comparator=">=", threshold="0.8",
        score="0.9", n=100, model_id="m", dataset_id="d", issuer="placeholder",
        timestamp=timestamp, assurance_level=assurance_level,
        prereg_sha256=prereg)
    bundle = emit_eval_receipt(claim, signer)
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w") as f:
        json.dump(bundle, f)
    return path, bundle["signature"]["public_key_b64"]


def _policy_file(policy: dict) -> str:
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w") as f:
        json.dump(policy, f)
    return path


def _base_policy(**over) -> dict:
    p = {"schema": POLICY_SCHEMA, "policy_id": "test-policy"}
    p.update(over)
    return p


def _run(argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        rc = main(argv)
    return rc, out.getvalue()


class TestLoadPolicyFailClosed(unittest.TestCase):
    def test_unknown_top_level_field_rejected(self):
        with self.assertRaises(PolicyError):
            load_policy(_base_policy(surprise=True))

    def test_unknown_nested_field_rejected(self):
        with self.assertRaises(PolicyError):
            load_policy(_base_policy(sd_jwt={"require_nonce": True, "typo_field": 1}))

    def test_wrong_schema_rejected(self):
        with self.assertRaises(PolicyError):
            load_policy({"schema": "proofbundle/trust-policy/v9.9", "policy_id": "x"})

    def test_missing_policy_id_rejected(self):
        with self.assertRaises(PolicyError):
            load_policy({"schema": POLICY_SCHEMA})

    def test_bad_minimum_level_rejected(self):
        with self.assertRaises(PolicyError):
            load_policy(_base_policy(assurance={"minimum_level": "super_duper"}))

    def test_negative_max_iat_age_rejected(self):
        with self.assertRaises(PolicyError):
            load_policy(_base_policy(sd_jwt={"max_iat_age_seconds": -5}))

    def test_field_order_does_not_change_parse(self):
        a = load_policy({"schema": POLICY_SCHEMA, "policy_id": "p", "assurance": {"minimum_level": "reproduced"}})
        b = load_policy({"assurance": {"minimum_level": "reproduced"}, "policy_id": "p", "schema": POLICY_SCHEMA})
        self.assertEqual(a, b)


class TestEvaluatePolicyUnits(unittest.TestCase):
    def _bundle(self, path):
        with open(path) as f:
            return json.load(f)

    def _verify(self, bundle, **kw):
        from proofbundle.bundle import verify_bundle
        return verify_bundle(bundle, **kw)

    def test_signer_mismatch_fails(self):
        path, _pub = _receipt()
        bundle = self._bundle(path)
        os.unlink(path)
        policy = load_policy(_base_policy(
            allowed_issuers=[{"issuer": "Other", "public_key_b64": base64.b64encode(b"\x01" * 32).decode()}],
            signature={"require_expected_signer": True}))
        res = evaluate_policy(bundle, self._verify(bundle), policy)
        self.assertFalse(res["policy_ok"])
        self.assertTrue(any(not c["ok"] and "signer" in c["name"] for c in res["checks"]))

    def test_require_signer_with_empty_issuers_fails_closed(self):
        path, _pub = _receipt()
        bundle = self._bundle(path)
        os.unlink(path)
        policy = load_policy(_base_policy(signature={"require_expected_signer": True}))
        res = evaluate_policy(bundle, self._verify(bundle), policy)
        self.assertFalse(res["policy_ok"])

    def test_hash_alg_mismatch_fails(self):
        path, _pub = _receipt()
        bundle = self._bundle(path)
        os.unlink(path)
        policy = load_policy(_base_policy(merkle={"required_hash_alg": "sha512-something"}))
        res = evaluate_policy(bundle, self._verify(bundle), policy)
        self.assertFalse(res["policy_ok"])

    def test_status_requirement_fails_closed_no_snapshot(self):
        path, _pub = _receipt()
        bundle = self._bundle(path)
        os.unlink(path)
        policy = load_policy(_base_policy(status={"reject_self_issued": True}))
        res = evaluate_policy(bundle, self._verify(bundle), policy)
        self.assertFalse(res["policy_ok"])   # no status snapshot input in v0.1 → fail-closed
        self.assertTrue(any("status" in c["name"] for c in res["checks"]))

    def test_self_attested_without_prereg_rejected(self):
        path, _pub = _receipt(assurance_level="self_attested", prereg=None)
        bundle = self._bundle(path)
        os.unlink(path)
        policy = load_policy(_base_policy(assurance={"reject_self_attested_without_prereg": True}))
        res = evaluate_policy(bundle, self._verify(bundle), policy)
        self.assertFalse(res["policy_ok"])

    def test_self_attested_with_prereg_accepted(self):
        path, _pub = _receipt(assurance_level="self_attested", prereg="a" * 64)
        bundle = self._bundle(path)
        os.unlink(path)
        policy = load_policy(_base_policy(assurance={"reject_self_attested_without_prereg": True}))
        res = evaluate_policy(bundle, self._verify(bundle), policy)
        self.assertTrue(res["policy_ok"])

    def test_freshness_stale_fails(self):
        path, _pub = _receipt(timestamp="2020-01-01T00:00:00Z")
        bundle = self._bundle(path)
        os.unlink(path)
        policy = load_policy(_base_policy(sd_jwt={"max_iat_age_seconds": 10}))
        res = evaluate_policy(bundle, self._verify(bundle), policy)
        self.assertFalse(res["policy_ok"])   # a 2020 receipt is far older than 10s

    def test_field_order_does_not_change_verdict(self):
        path, pub = _receipt()
        bundle = self._bundle(path)
        os.unlink(path)
        p1 = load_policy(_base_policy(allowed_issuers=[{"public_key_b64": pub}],
                                      merkle={"required_hash_alg": "sha256-rfc6962"}))
        p2 = load_policy({"merkle": {"required_hash_alg": "sha256-rfc6962"},
                          "allowed_issuers": [{"public_key_b64": pub}],
                          "policy_id": "test-policy", "schema": POLICY_SCHEMA})
        r1 = evaluate_policy(bundle, self._verify(bundle), p1)
        r2 = evaluate_policy(bundle, self._verify(bundle), p2)
        self.assertEqual(r1["policy_ok"], r2["policy_ok"])
        self.assertTrue(r1["policy_ok"])


class TestVerifyPolicyCli(unittest.TestCase):
    def test_policy_pass_exit_zero(self):
        path, pub = _receipt(assurance_level="reproduced")
        pol = _policy_file(_base_policy(
            allowed_issuers=[{"issuer": "Lab", "public_key_b64": pub}],
            signature={"require_expected_signer": True},
            merkle={"required_hash_alg": "sha256-rfc6962"},
            assurance={"minimum_level": "reproduced"}))
        try:
            rc, out = _run(["verify", path, "--policy", pol])
        finally:
            os.unlink(path)
            os.unlink(pol)
        self.assertEqual(rc, 0)
        self.assertIn("POLICY: OK", out)

    def test_policy_fail_exit_three(self):
        path, pub = _receipt(assurance_level="reproduced")
        pol = _policy_file(_base_policy(assurance={"minimum_level": "enclave_attested"}))
        try:
            rc, out = _run(["verify", path, "--policy", pol])
        finally:
            os.unlink(path)
            os.unlink(pol)
        self.assertEqual(rc, 3)                # crypto OK but policy NOT satisfied → the new exit 3
        self.assertIn("CRYPTO: OK", out)
        self.assertIn("POLICY: FAIL", out)

    def test_policy_json_fields(self):
        path, pub = _receipt()
        pol = _policy_file(_base_policy(allowed_issuers=[{"public_key_b64": pub}]))
        try:
            _, out = _run(["verify", "--json", path, "--policy", pol])
            data = json.loads(out)
        finally:
            os.unlink(path)
            os.unlink(pol)
        self.assertTrue(data["crypto_ok"])
        self.assertTrue(data["policy_ok"])          # real result, not the WP-B2 null default
        self.assertEqual(data["policy_id"], "test-policy")
        self.assertIn("policy_checks", data)

    def test_missing_policy_is_not_evaluated(self):
        path, _pub = _receipt()
        try:
            rc, out = _run(["verify", path])
            _, jout = _run(["verify", "--json", path])
            data = json.loads(jout)
        finally:
            os.unlink(path)
        self.assertEqual(rc, 0)
        self.assertIn("POLICY: NOT_EVALUATED", out)
        self.assertIsNone(data["policy_ok"])         # crypto passes, policy not evaluated

    def test_malformed_policy_exit_two(self):
        path, _pub = _receipt()
        pol = _policy_file({"schema": POLICY_SCHEMA, "policy_id": "p", "bogus_field": 1})
        try:
            rc, _ = _run(["verify", path, "--policy", pol])
        finally:
            os.unlink(path)
            os.unlink(pol)
        self.assertEqual(rc, 2)                       # malformed policy → exit 2 (not 1 or 3)

    def test_aud_flag_policy_conflict_exit_two(self):
        path, _pub = _receipt()
        pol = _policy_file(_base_policy(sd_jwt={"expected_aud": "policy.example"}))
        try:
            rc, _out = _run(["verify", path, "--aud", "flag.example", "--policy", pol])
        finally:
            os.unlink(path)
            os.unlink(pol)
        self.assertEqual(rc, 2)                       # ambiguous aud → exit 2, never a silent override

    def test_crypto_fail_policy_not_checked(self):
        path, pub = _receipt()
        with open(path) as f:
            b = json.load(f)
        b["payload_b64"] = "AAAA"                     # tamper: crypto fails
        with open(path, "w") as f:
            json.dump(b, f)
        pol = _policy_file(_base_policy(allowed_issuers=[{"public_key_b64": pub}]))
        try:
            rc, out = _run(["verify", path, "--policy", pol])
            _, jout = _run(["verify", "--json", path, "--policy", pol])
            data = json.loads(jout)
        finally:
            os.unlink(path)
            os.unlink(pol)
        self.assertEqual(rc, 1)                        # crypto failure dominates
        self.assertIn("POLICY: NOT_EVALUATED (crypto failed", out)
        self.assertIsNone(data["policy_ok"])           # a policy is never evaluated on unverified bytes


class TestSchemaConsistency(unittest.TestCase):
    """The JSON Schema, the worked example, and the fail-closed load_policy parser MUST agree — a
    schema/code divergence is exactly how a policy field could silently stop being enforced."""

    def _schema(self) -> dict:
        return json.loads((_ROOT / "schemas" / "trust_policy_v0_1.schema.json").read_text(encoding="utf-8"))

    @unittest.skipIf(jsonschema is None, "jsonschema not installed (pip install -e .[dev])")
    def test_schema_is_valid_draft(self):
        jsonschema.Draft7Validator.check_schema(self._schema())

    @unittest.skipIf(jsonschema is None, "jsonschema not installed")
    def test_example_matches_schema(self):
        example = json.loads((_ROOT / "examples" / "trust_policy_strict.json").read_text(encoding="utf-8"))
        jsonschema.validate(instance=example, schema=self._schema())

    def test_example_loads_via_load_policy(self):
        # the fail-closed parser must accept the same example the schema does (schema↔code parity)
        policy = load_policy(str(_ROOT / "examples" / "trust_policy_strict.json"))
        self.assertEqual(policy["policy_id"], "example-strict-eval-policy")

    def test_schema_top_level_properties_match_parser(self):
        # every property the schema declares must be one the parser's allow-list knows, and vice
        # versa — no schema-only field the code silently ignores, no code field the schema rejects.
        from proofbundle.policy import _TOP_KEYS
        self.assertEqual(set(self._schema()["properties"]), _TOP_KEYS)

    def test_schema_merkle_properties_match_parser(self):
        # NESTED parity (audit 2026-07-13): the top-level check missed that the new merkle policy keys
        # require_authenticated_root / trusted_roots were added to the parser (_MERKLE_KEYS) but not the
        # schema, so an external validator rejected the very policy the code enforces.
        from proofbundle.policy import _MERKLE_KEYS
        self.assertEqual(set(self._schema()["properties"]["merkle"]["properties"]), set(_MERKLE_KEYS))

    @unittest.skipIf(jsonschema is None, "jsonschema not installed")
    def test_schema_accepts_authenticated_root_policy(self):
        # the production policy that closes the coherent-rewrap must validate against the SCHEMA, not
        # only the parser (an external / second implementation trusts the schema). A-P0-5: pins must
        # be real 32-byte roots since 3.1.3 (the parser hard-validates them at load).
        root32 = base64.b64encode(b"\x0b" * 32).decode("ascii")
        pol = {"schema": "proofbundle/trust-policy/v0.1", "policy_id": "p",
               "merkle": {"require_authenticated_root": True, "trusted_roots": [root32]}}
        jsonschema.validate(instance=pol, schema=self._schema())   # must not raise
        load_policy(pol)   # and the parser accepts it too


class TestVerifyLensFixes(unittest.TestCase):
    """Regression tests for the six-lens WP-B3 review findings."""

    # L4/L3 — type-confusion: a mistyped field must be a parse error, not a silent weakening.
    def test_allowed_algs_as_string_rejected(self):   # L4 F1 / L3 F1 — the substring-match bypass
        with self.assertRaises(PolicyError):
            load_policy(_base_policy(signature={"allowed_algs": "ed25519"}))   # a string, not a list

    def test_bool_fields_typechecked(self):   # L4 F2
        for section, field in [("signature", "require_expected_signer"),
                               ("status", "reject_self_issued"),
                               ("sd_jwt", "require_nonce"),
                               ("assurance", "reject_self_attested_without_prereg")]:
            with self.assertRaises(PolicyError):
                load_policy(_base_policy(**{section: {field: "false"}}))   # string, not bool

    def test_allowed_status_authorities_as_string_rejected(self):   # L4 F2
        with self.assertRaises(PolicyError):
            load_policy(_base_policy(status={"allowed_status_authorities": "key"}))

    def test_deeply_nested_policy_json_fails_closed(self):   # L3 F2
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w") as f:
            f.write("[" * 6000 + "]" * 6000)
        try:
            with self.assertRaises(PolicyError):   # RecursionError → PolicyError, never a raw traceback
                load_policy(path)
        finally:
            os.unlink(path)

    def test_defensive_copy_of_dict_input(self):   # L4 F4
        src = _base_policy(merkle={"required_hash_alg": "sha256-rfc6962"})
        loaded = load_policy(src)
        src["merkle"]["required_hash_alg"] = "TAMPERED"      # mutate the caller's dict after loading
        self.assertEqual(loaded["merkle"]["required_hash_alg"], "sha256-rfc6962")   # copy is immune

    # L2 — evaluate_policy enforces crypto-first itself, not only via the CLI caller.
    def test_evaluate_policy_gates_on_crypto_itself(self):   # L2 F2
        class _Failed:
            ok = False
            checks: list = []
        res = evaluate_policy({"schema": "proofbundle/v0.1"}, _Failed(),
                              load_policy(_base_policy(merkle={"required_hash_alg": "sha256-rfc6962"})))
        self.assertIsNone(res["policy_ok"])   # not True — a policy is never evaluated on failed crypto

    # L5 — all() vs any(): a mixed pass+fail must be an overall FAIL.
    def test_mixed_pass_and_fail_is_overall_fail(self):   # L5 F1
        path, pub = _receipt()
        with open(path) as f:
            bundle = json.load(f)
        os.unlink(path)
        from proofbundle.bundle import verify_bundle
        # merkle hash matches (pass) BUT the signer is not allowed (fail) → policy_ok must be False.
        policy = load_policy(_base_policy(
            merkle={"required_hash_alg": "sha256-rfc6962"},
            allowed_issuers=[{"public_key_b64": base64.b64encode(b"\x02" * 32).decode()}],
            signature={"require_expected_signer": True}))
        res = evaluate_policy(bundle, verify_bundle(bundle), policy)
        self.assertFalse(res["policy_ok"])
        self.assertTrue(any(c["ok"] for c in res["checks"]))       # at least one check passed
        self.assertTrue(any(not c["ok"] for c in res["checks"]))   # and at least one failed

    # L5 — allowed_schema_versions + allowed_algs pass and fail (were untested).
    def test_schema_version_and_alg_checks(self):   # L5 F2
        path, pub = _receipt()
        with open(path) as f:
            bundle = json.load(f)
        os.unlink(path)
        from proofbundle.bundle import verify_bundle
        good = load_policy(_base_policy(allowed_schema_versions=["proofbundle/v0.1"],
                                        signature={"allowed_algs": ["ed25519"]}))
        bad = load_policy(_base_policy(allowed_schema_versions=["proofbundle/v9.9"],
                                       signature={"allowed_algs": ["rsa"]}))
        self.assertTrue(evaluate_policy(bundle, verify_bundle(bundle), good)["policy_ok"])
        self.assertFalse(evaluate_policy(bundle, verify_bundle(bundle), bad)["policy_ok"])

    # L5 — freshness FRESH path (only stale was tested).
    def test_freshness_fresh_passes(self):   # L5 F4
        from datetime import datetime, timezone
        path, pub = _receipt(timestamp="2026-07-09T10:00:00Z")
        with open(path) as f:
            bundle = json.load(f)
        os.unlink(path)
        from proofbundle.bundle import verify_bundle
        policy = load_policy(_base_policy(sd_jwt={"max_iat_age_seconds": 3600}))
        now = datetime(2026, 7, 9, 10, 5, 0, tzinfo=timezone.utc)   # 5 min after the receipt
        res = evaluate_policy(bundle, verify_bundle(bundle), policy, now=now)
        self.assertTrue(res["policy_ok"])   # 300s age < 3600s bound → fresh

    # L1/L2 — require_nonce must not pass on an UNAUTHENTICATED nonce (the HIGH false-PASS).
    def test_require_nonce_fails_closed_without_verified_kb(self):   # L1 F1 / L2 F1 (WP-C2 re-pin)
        path = _sd_jwt_bundle(with_issuer_key=False, with_cnf=False)   # unsigned sd_jwt_vc (no issuer key)
        pol = _policy_file(_base_policy(sd_jwt={"require_nonce": True}))
        try:
            rc, out = _run(["verify", path, "--policy", pol])
        finally:
            os.unlink(path)
            os.unlink(pol)
        # WP-C2 (Owner-GO breaking): an unsigned sd_jwt_vc now fails the CRYPTO verify (exit 1) before
        # any policy check — the disclosures are unauthenticated. (Was exit 3 / policy-fail-closed, when
        # the unsigned SD-JWT still let crypto pass.)
        self.assertEqual(rc, 1)
        self.assertIn("CRYPTO: FAIL", out)

    def test_require_nonce_passes_on_verified_kb(self):   # L5 — the real True path
        path = _sd_jwt_bundle(with_issuer_key=True, with_cnf=True, nonce="n-1")
        pol = _policy_file(_base_policy(sd_jwt={"require_nonce": True}))
        try:
            rc, out = _run(["verify", path, "--policy", pol])
        finally:
            os.unlink(path)
            os.unlink(pol)
        self.assertEqual(rc, 0)
        self.assertIn("POLICY: OK", out)

    # L5 — policy-only expected_aud is actually bound (the flag-less fallback path).
    def test_policy_only_expected_aud_is_bound(self):   # L5 F3
        path = _sd_jwt_bundle(with_issuer_key=True, with_cnf=True, aud="verifier.example")
        pol = _policy_file(_base_policy(sd_jwt={"expected_aud": "WRONG.audience"}))
        try:
            rc, _out = _run(["verify", path, "--policy", pol])   # no --aud flag; policy aud must bind
        finally:
            os.unlink(path)
            os.unlink(pol)
        self.assertEqual(rc, 1)   # KB-JWT aud != policy expected_aud → crypto fails (aud bound via policy)


class TestExpectedVct(unittest.TestCase):
    """Finding 20 / issue #27 (PB-2026-07-15): sd_jwt.expected_vct — an exact-match RP verifier flag
    for the SD-JWT's disclosed vct, read ONLY from a VERIFIED issuer signature."""

    def test_expected_vct_matches_passes(self):
        path = _sd_jwt_bundle(with_issuer_key=True, with_cnf=True, vct="https://example.test/vct/mine")
        pol = _policy_file(_base_policy(sd_jwt={"expected_vct": "https://example.test/vct/mine"}))
        try:
            rc, out = _run(["verify", path, "--policy", pol])
        finally:
            os.unlink(path)
            os.unlink(pol)
        self.assertEqual(rc, 0)
        self.assertIn("POLICY: OK", out)

    def test_expected_vct_mismatch_fails(self):
        path = _sd_jwt_bundle(with_issuer_key=True, with_cnf=True, vct="https://example.test/vct/mine")
        pol = _policy_file(_base_policy(sd_jwt={"expected_vct": "https://example.test/vct/other"}))
        try:
            rc, out = _run(["verify", path, "--policy", pol])
        finally:
            os.unlink(path)
            os.unlink(pol)
        self.assertEqual(rc, 3)
        self.assertIn("POLICY: FAIL", out)

    def test_expected_vct_absent_adds_no_check(self):
        # opt-in only: a policy that never sets expected_vct must not gain a policy:expected_vct
        # check at all (vacuous-pass discipline — explain_policy/lint_policy parity, WP-TP1).
        from proofbundle.bundle import verify_bundle  # noqa: PLC0415
        path = _sd_jwt_bundle(with_issuer_key=True, with_cnf=True)
        with open(path) as f:
            bundle = json.load(f)
        os.unlink(path)
        policy = load_policy(_base_policy(sd_jwt={"require_key_binding_when_cnf_present": True}))
        res = evaluate_policy(bundle, verify_bundle(bundle), policy)
        self.assertTrue(res["policy_ok"], res)
        self.assertFalse(any(c["name"] == "policy:expected_vct" for c in res["checks"]))

    def test_expected_vct_null_is_treated_as_absent(self):
        with self.assertRaises(PolicyError):
            load_policy(_base_policy(sd_jwt={"expected_vct": 5}))   # wrong type still rejected
        load_policy(_base_policy(sd_jwt={"expected_vct": None}))    # explicit null is fine (= do not constrain)

    def test_expected_vct_gated_on_verified_issuer_signature(self):
        # unit-level (mirrors test_evaluate_policy_gates_on_crypto_itself's pattern): evaluate_policy
        # must NEVER trust a vct claim from an unverified issuer payload — even when the bundle's own
        # sd_jwt_vc.compact is well-formed and carries the "right" vct on its face. This is the
        # "verified vs. merely present" discipline policy:nonce_present already established.
        from proofbundle.errors import Check  # noqa: PLC0415

        class _Result:
            ok = True
            checks = [Check("ed25519-signature", True), Check("sd-jwt-disclosures", True),
                     Check("sd-jwt-issuer-signature", False, "unsigned")]

        issuer = generate_signer()
        compact = issue_sd_jwt(
            {"passed": True, "threshold": "0.8", "comparator": ">=", "suite": "x",
             "issuer": "placeholder"},
            issuer, root_b64="cm9vdA==", vct="https://attacker.example/vct")
        bundle = {"schema": "proofbundle/v0.1", "sd_jwt_vc": {"compact": compact}}
        policy = load_policy(_base_policy(sd_jwt={"expected_vct": "https://attacker.example/vct"}))
        res = evaluate_policy(bundle, _Result(), policy)
        self.assertFalse(res["policy_ok"])
        vct_check = next(c for c in res["checks"] if c["name"] == "policy:expected_vct")
        self.assertFalse(vct_check["ok"])

    def test_expected_vct_listed_in_explain(self):
        pol = load_policy(_base_policy(sd_jwt={"expected_vct": "https://example.test/vct/mine"}))
        from proofbundle.policy import explain_policy  # noqa: PLC0415
        self.assertTrue(any("vct" in x and "example.test" in x for x in explain_policy(pol)))


if __name__ == "__main__":
    unittest.main()
