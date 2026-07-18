"""relation-statement/v0.1 standalone profile (3.5.0 WP-A) — emit/verify, exit-code contract,
never-raise, lattice monotonicity, --json projection, and the reject_retracted/relation_signer gates.

A relation statement proves the ISSUER DECLARED the relation over exact bytes; it does NOT retract
the target's cryptographic validity (lattice monotonicity), and whether the issuer may declare it is
a relying-party policy decision.
"""
from __future__ import annotations

import base64
import contextlib
import io
import json
import pathlib
import tempfile
import unittest

try:
    from hypothesis import given, settings
    from hypothesis import strategies as st
except ImportError:  # PB-2026-0718-L6-01: hypothesis is a dev-only dep — clean skip from a bare sdist install
    import pytest
    pytest.skip("hypothesis not installed (dev-only dependency)", allow_module_level=True)

from proofbundle import anchors, dsse
from proofbundle.cli import main as cli
from proofbundle.decision import emit_decision_receipt
from proofbundle.emit import generate_signer
from proofbundle.relation_statement import (
    RELATION_STATEMENT_PREDICATE_TYPE,
    emit_relation_statement,
    validate_relation_statement_predicate,
    verify_relation_statement,
)

EXAMPLES = pathlib.Path(__file__).resolve().parents[1] / "examples"
BASE = json.loads((EXAMPLES / "decision_receipt_deny.json").read_text(encoding="utf-8"))


def _pub(sk) -> bytes:
    return sk.public_key().public_bytes_raw()


def _target(sk, decision_id="d-target"):
    env = emit_decision_receipt({**BASE, "decisionId": decision_id}, sk, strict=True)
    root = anchors.statement_content_root(dsse.load_payload(env)).hex()
    return env, root


def _edge(target_hex, relation="retracts", **extra):
    e = {"relation": relation,
         "targetReceiptDigest": {"digestAlgorithm": "jcs-sha256-v1", "digest": target_hex}}
    e.update(extra)
    return e


def _stmt(sk, target_hex, relation="retracts", statement_id="urn:uuid:s-1", **extra):
    pred = {"schemaVersion": "0.1.0", "statementId": statement_id,
            "relationships": [_edge(target_hex, relation, **extra)]}
    return emit_relation_statement(pred, sk)


def _attached(sk, target_root, verified=True, subject_digest=None):
    return {target_root: {"verified": verified, "relationships": None,
                          "verified_under": base64.b64encode(_pub(sk)).decode(),
                          "subject_digest": subject_digest}}


class TestValidation(unittest.TestCase):
    def test_valid_predicate(self):
        p = {"schemaVersion": "0.1.0", "statementId": "s", "relationships": [_edge("a" * 64)]}
        self.assertEqual(validate_relation_statement_predicate(p), [])

    def test_unknown_top_field_fail_closed(self):
        p = {"schemaVersion": "0.1.0", "statementId": "s", "relationships": [_edge("a" * 64)], "x": 1}
        self.assertTrue(any("unknown field" in e for e in validate_relation_statement_predicate(p)))

    def test_exactly_one_edge_required(self):
        p = {"schemaVersion": "0.1.0", "statementId": "s",
             "relationships": [_edge("a" * 64), _edge("b" * 64)]}
        self.assertTrue(any("EXACTLY ONE" in e for e in validate_relation_statement_predicate(p)))

    def test_zero_edges_rejected(self):
        p = {"schemaVersion": "0.1.0", "statementId": "s", "relationships": []}
        self.assertTrue(validate_relation_statement_predicate(p))

    def test_bad_schema_version(self):
        p = {"schemaVersion": "9.9.9", "statementId": "s", "relationships": [_edge("a" * 64)]}
        self.assertTrue(any("schemaVersion" in e for e in validate_relation_statement_predicate(p)))

    def test_empty_statement_id(self):
        p = {"schemaVersion": "0.1.0", "statementId": "", "relationships": [_edge("a" * 64)]}
        self.assertTrue(any("statementId" in e for e in validate_relation_statement_predicate(p)))

    def test_malformed_edge_digest(self):
        p = {"schemaVersion": "0.1.0", "statementId": "s", "relationships": [_edge("NOT_HEX")]}
        self.assertTrue(validate_relation_statement_predicate(p))


class TestEmitVerify(unittest.TestCase):
    def test_retracts_verified_no_policy(self):
        sk = generate_signer()
        pub = _pub(sk)
        tgt, root = _target(sk)
        env = _stmt(sk, root)
        r = verify_relation_statement(env, pub, related=_attached(sk, root))
        self.assertTrue(r["ok"])
        self.assertTrue(r["crypto_ok"])
        self.assertEqual(r["lineage"]["lineage"], "VERIFIED")
        self.assertIsNone(r["policy_ok"])
        self.assertTrue(r["predicate_type_ok"])

    def test_declared_unresolved_no_target(self):
        sk = generate_signer()
        pub = _pub(sk)
        _, root = _target(sk)
        env = _stmt(sk, root)
        r = verify_relation_statement(env, pub, related=None)
        self.assertTrue(r["ok"])
        self.assertEqual(r["lineage"]["lineage"], "DECLARED_UNRESOLVED")

    def test_predicate_type_is_relation_statement(self):
        sk = generate_signer()
        _, root = _target(sk)
        env = _stmt(sk, root)
        stmt = json.loads(dsse.load_payload(env).decode())
        self.assertEqual(stmt["predicateType"], RELATION_STATEMENT_PREDICATE_TYPE)

    def test_forged_signature_fails_and_no_trust_fields(self):
        sk = generate_signer()
        _, root = _target(sk)
        env = _stmt(sk, root)
        other = generate_signer()
        r = verify_relation_statement(env, _pub(other), related=_attached(sk, root))
        self.assertFalse(r["crypto_ok"])
        self.assertFalse(r["ok"])
        # On a forged envelope, no trust-derived lineage is computed.
        self.assertIsNone(r["lineage"])


class TestLatticeMonotonicity(unittest.TestCase):
    def test_retracts_never_lifts_crypto_on_bad_signature(self):
        # A verified retracts assertion must NEVER flip crypto_ok true on a forged statement.
        sk = generate_signer()
        _, root = _target(sk)
        env = _stmt(sk, root)
        # tamper the payload -> crypto must fail even though the (unauthenticated) edge is a retracts.
        body = json.loads(base64.b64decode(env["payload"]))
        body["predicate"]["statementId"] = "urn:uuid:tampered"
        env_t = dict(env, payload=base64.b64encode(json.dumps(body).encode()).decode())
        r = verify_relation_statement(env_t, _pub(sk), related=_attached(sk, root))
        self.assertFalse(r["crypto_ok"])

    def test_retracts_does_not_invalidate_target_crypto(self):
        # The target receipt stays crypto-valid for its bytes regardless of an existing retracts statement.
        sk = generate_signer()
        tgt, _root = _target(sk)
        from proofbundle.decision import verify_decision_receipt
        res = verify_decision_receipt(tgt, _pub(sk))
        self.assertTrue(res["crypto_ok"])


class TestPolicyGates(unittest.TestCase):
    def test_reject_retracted_blocks(self):
        sk = generate_signer()
        pub = _pub(sk)
        _, root = _target(sk)
        env = _stmt(sk, root, relation="retracts")
        r = verify_relation_statement(env, pub, related=_attached(sk, root),
                                      policy={"relations": {"reject_retracted": True}})
        self.assertFalse(r["policy_ok"])
        self.assertIn("LINEAGE_REQUIREMENT_FAILED", r["relations_policy_codes"])

    def test_reject_superseded_blocks_supersedes(self):
        sk = generate_signer()
        pub = _pub(sk)
        _, root = _target(sk)
        env = _stmt(sk, root, relation="supersedes")
        r = verify_relation_statement(env, pub, related=_attached(sk, root),
                                      policy={"relations": {"reject_superseded": True}})
        self.assertFalse(r["policy_ok"])

    def test_reject_retracted_does_not_fire_on_declared_only(self):
        # No target attached -> DECLARED_UNRESOLVED -> reject_retracted must NOT block (only VERIFIED does).
        sk = generate_signer()
        pub = _pub(sk)
        _, root = _target(sk)
        env = _stmt(sk, root)
        r = verify_relation_statement(env, pub, related=None,
                                      policy={"relations": {"reject_retracted": True}})
        self.assertTrue(r["policy_ok"])

    def test_relation_signer_unauthorized(self):
        sk = generate_signer()
        pub = _pub(sk)
        _, root = _target(sk)
        env = _stmt(sk, root)
        other = generate_signer()
        pol = {"relations": {"relation_signer": {"retracts": {
            "mode": "pinned", "keys": [base64.b64encode(_pub(other)).decode()]}}}}
        r = verify_relation_statement(env, pub, related=_attached(sk, root), policy=pol)
        self.assertFalse(r["policy_ok"])
        self.assertIn("RELATION_SIGNER_UNAUTHORIZED", r["relations_policy_codes"])

    def test_relation_signer_authorized(self):
        sk = generate_signer()
        pub = _pub(sk)
        _, root = _target(sk)
        env = _stmt(sk, root)
        pol = {"relations": {"relation_signer": {"retracts": {
            "mode": "pinned", "keys": [base64.b64encode(pub).decode()]}}}}
        r = verify_relation_statement(env, pub, related=_attached(sk, root), policy=pol)
        self.assertTrue(r["policy_ok"])


class TestNeverRaise(unittest.TestCase):
    """The verifier must RETURN a fail-closed result on garbage, never a raw crash (O6)."""

    def _wrap(self, env, pub, **kw):
        try:
            return verify_relation_statement(env, pub, **kw)
        except Exception as exc:  # noqa: BLE001 — only BundleFormatError on non-JSON payload is allowed
            from proofbundle.errors import ProofBundleError
            self.assertIsInstance(exc, ProofBundleError)
            return None

    def test_garbage_related_map(self):
        sk = generate_signer()
        pub = _pub(sk)
        _, root = _target(sk)
        env = _stmt(sk, root)
        for junk in ({root: None}, {root: 42}, {root: {"verified": "yes"}}, {}, None):
            r = self._wrap(env, pub, related=junk)
            if r is not None:
                self.assertIn(r["lineage"]["lineage"], ("VERIFIED", "DECLARED_UNRESOLVED", "FAIL"))

    def test_garbage_policy(self):
        sk = generate_signer()
        pub = _pub(sk)
        _, root = _target(sk)
        env = _stmt(sk, root)
        for pol in ({}, {"relations": "x"}, {"relations": {}}, {"relations": None}):
            r = self._wrap(env, pub, related=_attached(sk, root), policy=pol)
            self.assertIsNotNone(r)


class TestExitContractCLI(unittest.TestCase):
    def _run(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            rc = cli(argv)
        return rc, out.getvalue(), err.getvalue()

    def _write(self, tmp, name, obj):
        p = pathlib.Path(tmp) / name
        p.write_text(json.dumps(obj) if isinstance(obj, (dict, list)) else str(obj), encoding="utf-8")
        return str(p)

    def test_exit_codes_and_json_projection(self):
        sk = generate_signer()
        pub_b64 = base64.b64encode(_pub(sk)).decode()
        tgt, root = _target(sk)
        env = _stmt(sk, root)
        with tempfile.TemporaryDirectory() as tmp:
            envp = self._write(tmp, "stmt.json", env)
            tgtp = self._write(tmp, "target.json", tgt)
            polp = self._write(tmp, "pol.json",
                               {"schema": "proofbundle/trust-policy/v0.2", "policy_id": "p",
                                "relations": {"reject_retracted": True}})
            # exit 0: verified, no reject policy, --json projection carries the documented keys.
            rc, out, _ = self._run(["relation-statement", "verify", envp, "--pub", pub_b64, "--json",
                                    "--with-related", tgtp, "--related-pub", pub_b64])
            self.assertEqual(rc, 0)
            report = json.loads(out)
            for k in ("ok", "crypto_ok", "structure_ok", "predicate_type_ok", "lineage", "policy_ok"):
                self.assertIn(k, report)
            self.assertEqual(report["lineage"]["lineage"], "VERIFIED")

            # exit 3: reject_retracted policy blocks continued use.
            rc, out, _ = self._run(["relation-statement", "verify", envp, "--pub", pub_b64, "--json",
                                    "--with-related", tgtp, "--related-pub", pub_b64, "--policy", polp])
            self.assertEqual(rc, 3)

            # exit 1: wrong pub -> crypto fail.
            other_b64 = base64.b64encode(_pub(generate_signer())).decode()
            rc, _, _ = self._run(["relation-statement", "verify", envp, "--pub", other_b64])
            self.assertEqual(rc, 1)

    def test_init_template(self):
        # init -> template
        rc, out, _ = self._run(["relation-statement", "init"])
        self.assertEqual(rc, 0)
        template = json.loads(out)
        self.assertIn("relationships", template)
        self.assertEqual(len(template["relationships"]), 1)


class TestPropertyValidation(unittest.TestCase):
    @settings(max_examples=200, deadline=None)
    @given(
        sv=st.text(min_size=0, max_size=8),
        sid=st.text(min_size=0, max_size=8),
        n_edges=st.integers(min_value=0, max_value=3),
        extra_field=st.booleans(),
    )
    def test_validate_never_raises_and_flags_shape(self, sv, sid, n_edges, extra_field):
        edges = [_edge("a" * 64) for _ in range(n_edges)]
        pred = {"schemaVersion": sv, "statementId": sid, "relationships": edges}
        if extra_field:
            pred["surprise"] = 1
        errs = validate_relation_statement_predicate(pred)  # must never raise
        self.assertIsInstance(errs, list)
        # exactly-one-edge is the defining constraint: anything but 1 edge is invalid.
        if n_edges != 1:
            self.assertTrue(errs)
        if extra_field:
            self.assertTrue(any("unknown field" in e for e in errs))

    @given(blob=st.recursive(
        st.none() | st.booleans() | st.integers() | st.text(max_size=5),
        lambda c: st.lists(c, max_size=3) | st.dictionaries(st.text(max_size=3), c, max_size=3),
        max_leaves=8))
    @settings(max_examples=150, deadline=None)
    def test_validate_arbitrary_json_never_raises(self, blob):
        # Fail-closed on ANY shape, never a raw crash.
        errs = validate_relation_statement_predicate(blob)
        self.assertIsInstance(errs, list)


if __name__ == "__main__":
    unittest.main()
