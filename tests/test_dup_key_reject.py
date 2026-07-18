"""WP-C1 — duplicate JSON keys are rejected fail-closed on EVERY verify path.

``json.loads`` keeps the LAST duplicate (last-wins): two implementations parsing the same bytes can
disagree about which ``root_b64``/``sig_b64``/``predicateType`` they verified — a classic parser
differential (Bishop Fox 2021). The DSSE statement paths caught duplicates only INDIRECTLY (byte
inequality with the canonical re-serialization); the native bundle path accepted them silently.
Now every path rejects them EXPLICITLY, with a message naming the duplicate — these tests assert
the message, proving the strict parser fired (not an incidental downstream mismatch). The reject
is stdlib-only (``object_pairs_hook``), so it holds on a base install without the ``[eval]`` extra.
"""
import base64
import contextlib
import io
import json
import os
import tempfile
import unittest

from proofbundle import emit_bundle, generate_signer
from proofbundle._strict_json import loads_strict
from proofbundle.bundle import load_bundle
from proofbundle.cli import main
from proofbundle.errors import BundleFormatError


def _run(argv):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = main(argv)
    return rc, out.getvalue(), err.getvalue()


def _write(text: str) -> str:
    fd, path = tempfile.mkstemp(suffix=".json")
    with os.fdopen(fd, "w") as f:
        f.write(text)
    return path


def _dup_inject(json_text: str, obj_marker: str, dup_member: str) -> str:
    """Inject a duplicated member right after the opening brace of the object containing
    ``obj_marker`` (crude but deterministic for our compact test JSON)."""
    i = json_text.index(obj_marker)
    brace = json_text.rindex("{", 0, i)
    return json_text[:brace + 1] + dup_member + "," + json_text[brace + 1:]


class TestStrictLoads(unittest.TestCase):
    def test_top_level_and_nested_duplicates_raise(self):
        for text in ('{"a":1,"a":2}',
                     '{"outer":{"a":1,"a":2}}',
                     '{"list":[{"x":1},{"y":1,"y":2}]}'):
            with self.assertRaises(BundleFormatError) as ctx:
                loads_strict(text)
            self.assertIn("duplicate JSON key", str(ctx.exception))

    def test_clean_json_and_plain_syntax_errors_unchanged(self):
        self.assertEqual(loads_strict('{"a":{"b":1},"c":[1,2]}'), {"a": {"b": 1}, "c": [1, 2]})
        with self.assertRaises(ValueError):
            loads_strict("{ not json")


class TestNativeBundlePath(unittest.TestCase):
    """The P0: the native bundle accepted duplicates silently (last-wins)."""

    def _bundle_text(self) -> str:
        return json.dumps(emit_bundle(b'{"x":1}', generate_signer()))

    def test_duplicate_in_signature_object_exits_two(self):
        text = _dup_inject(self._bundle_text(), '"sig_b64"', '"sig_b64":"AAAA"')
        path = _write(text)
        try:
            rc, _, err = _run(["verify", path])
        finally:
            os.unlink(path)
        self.assertEqual(rc, 2)
        self.assertIn("duplicate JSON key", err)

    def test_duplicate_in_merkle_object_exits_two(self):
        text = _dup_inject(self._bundle_text(), '"root_b64"',
                           '"root_b64":"' + base64.b64encode(b"\x00" * 32).decode() + '"')
        path = _write(text)
        try:
            rc, _, err = _run(["verify", path])
        finally:
            os.unlink(path)
        self.assertEqual(rc, 2)
        self.assertIn("duplicate JSON key", err)

    def test_duplicate_top_level_payload_exits_two(self):
        text = self._bundle_text()
        # duplicate the whole payload_b64 member at top level (first position)
        payload_val = json.loads(text)["payload_b64"]
        text = text[0] + f'"payload_b64":"{payload_val}",' + text[1:]
        path = _write(text)
        try:
            rc, _, err = _run(["verify", path])
        finally:
            os.unlink(path)
        self.assertEqual(rc, 2)
        self.assertIn("duplicate JSON key", err)

    def test_load_bundle_raises_directly(self):
        path = _write(_dup_inject(self._bundle_text(), '"sig_b64"', '"sig_b64":"AAAA"'))
        try:
            with self.assertRaises(BundleFormatError) as ctx:
                load_bundle(path)
        finally:
            os.unlink(path)
        self.assertIn("duplicate JSON key", str(ctx.exception))

    def test_hf_token_with_duplicate_keys_rejected(self):
        import zlib
        from proofbundle.hf_evals import TOKEN_PREFIX, verify_receipt_token
        text = _dup_inject(self._bundle_text(), '"sig_b64"', '"sig_b64":"AAAA"')
        token = TOKEN_PREFIX + base64.urlsafe_b64encode(
            zlib.compress(text.encode())).rstrip(b"=").decode("ascii")
        with self.assertRaises(BundleFormatError) as ctx:
            verify_receipt_token(token)
        self.assertIn("duplicate JSON key", str(ctx.exception))


class TestDsseStatementPaths(unittest.TestCase):
    """Duplicates in a DSSE Statement now fail with an EXPLICIT duplicate error on every verify
    function — in both content-root modes (jcs and legacy), where they were previously caught only
    indirectly by the canonical byte-equality (with a generic 'not canonical' message), and on the
    legacy path only via re-serialization inequality."""

    def _eval_envelope(self, content_root_alg=None):
        from proofbundle.evalclaim import build_eval_claim
        from proofbundle.intoto import LEGACY_CONTENT_ROOT_ALG, export_eval_result_dsse
        claim, _ = build_eval_claim(
            suite="s", suite_version="1", metric="acc", comparator=">=", threshold="0.5",
            score="0.9", n=10, model_id="m", dataset_id="d", issuer="", timestamp="2026-07-11T00:00:00Z")
        signer = generate_signer()
        kwargs = {}
        if content_root_alg == "legacy":
            kwargs["content_root_alg"] = LEGACY_CONTENT_ROOT_ALG
        env = export_eval_result_dsse(claim, signer, **kwargs)
        pub = signer.public_key().public_bytes_raw()
        return env, pub

    def _with_dup_payload(self, env: dict) -> dict:
        body = base64.b64decode(env["payload"])
        text = body.decode("utf-8")
        text = text[0] + '"predicateType":"https://evil.example/x",' + text[1:]
        return {**env, "payload": base64.b64encode(text.encode()).decode("ascii")}

    def test_eval_result_verify_names_the_duplicate(self):
        # RE-GATE never-raise: a dup-key payload is a fail-closed VERDICT (ok=False) whose detail names the
        # duplicate — the strict parser still fires, but this dict-returning verify surface returns, not raises.
        from proofbundle.intoto import verify_eval_result_dsse
        for mode in (None, "legacy"):
            env, pub = self._eval_envelope(mode)
            r = verify_eval_result_dsse(self._with_dup_payload(env), pub)
            self.assertIs(r["ok"], False)
            self.assertIn("duplicate JSON key", r["content_root_detail"],
                          f"mode={mode}: the STRICT parser must fire, not a downstream mismatch")

    def test_svr_and_test_result_verify_reject_duplicates_both_modes(self):
        from proofbundle.intoto import (LEGACY_CONTENT_ROOT_ALG, export_intoto_dsse,
                                        export_svr_dsse, verify_intoto_dsse, verify_svr_dsse)
        from proofbundle.evalclaim import build_eval_claim, emit_eval_receipt
        claim, _ = build_eval_claim(
            suite="s", suite_version="1", metric="acc", comparator=">=", threshold="0.5",
            score="0.9", n=10, model_id="m", dataset_id="d", issuer="", timestamp="2026-07-11T00:00:00Z")
        signer = generate_signer()
        pub = signer.public_key().public_bytes_raw()
        receipt = emit_eval_receipt(claim, signer)
        for mode_kwargs in ({}, {"content_root_alg": LEGACY_CONTENT_ROOT_ALG}):
            # RE-GATE never-raise: dup-key -> fail-closed verdict (ok=False) with the duplicate named in detail.
            svr_env = export_svr_dsse(receipt, signer, **mode_kwargs)
            r = verify_svr_dsse(self._with_dup_payload(svr_env), pub)
            self.assertIs(r["ok"], False)
            self.assertIn("duplicate JSON key", r["content_root_detail"], f"svr {mode_kwargs}")
            tr_env = export_intoto_dsse(claim, signer, **mode_kwargs)
            r = verify_intoto_dsse(self._with_dup_payload(tr_env), pub)
            self.assertIs(r["ok"], False)
            self.assertIn("duplicate JSON key", r["content_root_detail"], f"test-result {mode_kwargs}")


class TestDecisionPath(unittest.TestCase):
    def _decision_envelope(self):
        from proofbundle.decision import emit_decision_receipt
        predicate = {
            "schemaVersion": "0.1.0",
            "decisionId": "urn:uuid:00000000-0000-0000-0000-000000000001",
            "decisionType": "preActionAuthorization",
            "decidedAt": "2026-07-11T00:00:00Z",
            "decisionMaker": {"id": "https://example.org/gate"},
            "agent": {"id": "agent://a"},
            "principal": {"id": "workload://p"},
            "proposedAction": {"actionType": "tool.call", "parametersDigest": {"sha256": "0" * 64}},
            "inputSnapshot": [{"digest": {"sha256": "0" * 64}}],
            "policyBoundary": {"policyEngine": "opa", "policyId": "p", "decisionPath": "d",
                               "policyDigest": {"sha256": "0" * 64}},
            "evidenceRefs": [],
            "decision": {"verdict": "DENY", "reasonCodes": ["r"]},
            "notChecked": [], "decisionChangeConditions": [],
            "privacy": {"rawInputsIncluded": False},
        }
        signer = generate_signer()
        env = emit_decision_receipt(predicate, signer, strict=False)
        return env, signer.public_key().public_bytes_raw()

    def test_decision_verify_rejects_duplicate_key(self):
        # PB-2026-0717-07: verify() is NEVER-RAISE (returns a stable fail-closed verdict); the explicit
        # verify_decision_receipt_or_raise() variant raises. Both reject a duplicate-key payload.
        from proofbundle.decision import verify_decision_receipt, verify_decision_receipt_or_raise
        env, pub = self._decision_envelope()
        body = base64.b64decode(env["payload"]).decode("utf-8")
        body = body[0] + '"predicateType":"https://evil.example/x",' + body[1:]
        env = {**env, "payload": base64.b64encode(body.encode()).decode("ascii")}
        # never-raise: a stable fail-closed verdict, the reason preserved in errors[]
        r = verify_decision_receipt(env, pub)
        self.assertFalse(r["ok"])
        self.assertFalse(r["structure_ok"])
        self.assertIsNot((r.get("automation") or {}).get("safeForAutomation"), True)
        self.assertTrue(any("duplicate JSON key" in e for e in r["errors"]), r["errors"])
        # explicit variant: raises
        with self.assertRaises(BundleFormatError) as ctx:
            verify_decision_receipt_or_raise(env, pub)
        self.assertIn("duplicate JSON key", str(ctx.exception))

    def test_decision_verify_cli_exits_two(self):
        env, pub = self._decision_envelope()
        body = base64.b64decode(env["payload"]).decode("utf-8")
        body = body[0] + '"predicateType":"https://evil.example/x",' + body[1:]
        env = {**env, "payload": base64.b64encode(body.encode()).decode("ascii")}
        path = _write(json.dumps(env))
        try:
            rc, _, err = _run(["decision", "verify", path,
                               "--pub", base64.b64encode(pub).decode("ascii")])
        finally:
            os.unlink(path)
        # PB-2026-0717-07: verify() is now never-raise, so the CLI reads a structured verdict instead of
        # catching a raised BundleFormatError. This payload was TAMPERED after signing (a duplicate key
        # injected into the signed bytes) → the signature no longer matches → crypto_ok=False, which is the
        # more accurate failure and takes exit-code precedence (1 = crypto fail). The malformed reason is
        # still surfaced in the printed errors (never masked).
        self.assertEqual(rc, 1)
        self.assertIn("duplicate JSON key", err)

    def test_decision_emit_refuses_duplicate_key_in_predicate_file(self):
        # emit side: a duplicate key must never survive into signed bytes.
        pred = '{"schemaVersion":"0.1.0","schemaVersion":"0.1.1"}'
        path = _write(pred)
        out = path + ".out"
        keyf = path + ".key"
        try:
            rc, _, err = _run(["decision", "emit", path, "--out", out, "--new-key", keyf])
        finally:
            os.unlink(path)
            for f in (out, keyf):
                if os.path.exists(f):
                    os.unlink(f)
        self.assertEqual(rc, 2)
        self.assertIn("duplicate JSON key", err)


class TestSixLensExtendedPaths(unittest.TestCase):
    """The six-lens review of the first C1 cut proved these paths still parsed last-wins."""

    def test_trust_policy_file_with_duplicate_key_rejected(self):
        from proofbundle.policy import PolicyError, load_policy
        path = _write('{"schema":"proofbundle/trust-policy/v0.1","policy_id":"x",'
                      '"allowed_issuers":[],"allowed_issuers":[{"public_key_b64":"QQ=="}]}')
        try:
            with self.assertRaises(PolicyError) as ctx:
                load_policy(path)
        finally:
            os.unlink(path)
        self.assertIn("duplicate JSON key", str(ctx.exception))

    def test_persample_disclosure_record_with_duplicate_key_fails(self):
        # A committed disclosure whose RECORD carries {"verdict":"PASS","verdict":"FAIL"}: the
        # leaf hash is over the raw string (inclusion passes), but the parsed record was
        # last-wins — the proven silent split between committed bytes and read record.
        from proofbundle import merkle
        from proofbundle.persample import verify_sample_opening
        disclosure_json = '["c2FsdHNhbHRzYWx0c2FsdA",{"idx":0,"verdict":"PASS","verdict":"FAIL"}]'
        disclosure = base64.urlsafe_b64encode(disclosure_json.encode()).rstrip(b"=").decode("ascii")
        root = merkle.merkle_tree_hash([disclosure.encode("ascii")])
        res = verify_sample_opening({"index": 0, "disclosure": disclosure, "proof_b64": []},
                                    base64.b64encode(root).decode("ascii"), 1)
        self.assertFalse(res["ok"])
        self.assertIn("duplicate JSON key", res["detail"])

    def test_statuslist_duplicate_status_list_key_rejected(self):
        # The PROVEN revocation split-brain: a signed token whose payload duplicates status_list
        # read VALID (first-wins) vs INVALID (last-wins). Build a REAL signed token, then inject
        # the duplicate into the payload segment (signature over the mutated segment re-done).
        import zlib
        from proofbundle.statuslist import verify_status_snapshot
        signer = generate_signer()
        pub = signer.public_key().public_bytes_raw()
        lst_valid = base64.urlsafe_b64encode(zlib.compress(bytes([0x00]), 9)).rstrip(b"=").decode()
        lst_invalid = base64.urlsafe_b64encode(zlib.compress(bytes([0x01]), 9)).rstrip(b"=").decode()
        payload = ('{"sub":"https://l.example/1","iat":1750000000,'
                   f'"status_list":{{"bits":1,"lst":"{lst_valid}"}},'
                   f'"status_list":{{"bits":1,"lst":"{lst_invalid}"}}}}')
        header = '{"alg":"EdDSA","typ":"statuslist+jwt"}'
        b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")  # noqa: E731
        signing_input = b64(header.encode()) + "." + b64(payload.encode())
        token = signing_input + "." + b64(signer.sign(signing_input.encode("ascii")))
        res = verify_status_snapshot(token, expected_uri="https://l.example/1", index=0,
                                     issuer_pubkey=pub)
        self.assertFalse(res["ok"])
        self.assertIn("duplicate JSON key", res["detail"])

    def test_enclave_eat_duplicate_claim_rejected(self):
        from proofbundle.experimental import enclave as enc
        signer = generate_signer()
        pub = signer.public_key().public_bytes_raw()
        b64 = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")  # noqa: E731
        header = '{"alg":"EdDSA","typ":"eat+jwt"}'
        claims = '{"eat_nonce":"AAA","eat_nonce":"BBB","eat_profile":"p","tier":"t"}'
        signing_input = b64(header.encode()) + "." + b64(claims.encode())
        eat = signing_input + "." + b64(signer.sign(signing_input.encode("ascii")))
        res = enc.verify_enclave_attestation(eat, verifier_pubkey=pub, expected_binding="BBB")
        self.assertFalse(res["ok"])
        self.assertIn("duplicate JSON key", res["detail"])

    def test_anchor_envelopes_reject_duplicates_fail_closed_no_raise(self):
        from proofbundle.anchors_chia import verify_chia_datalayer
        from proofbundle.anchors_markovian import verify_markovian
        chia = verify_chia_datalayer(b'{"key":"00","key":"11"}', b"\x00" * 32, frozen={})
        self.assertFalse(chia["ok"])
        mark = verify_markovian(b'{"schema":"markovian-provenance/v1","wallet":"a","wallet":"b"}',
                                b"\x00" * 32, frozen={})
        self.assertFalse(mark["ok"])
        self.assertEqual(mark["status"], "malformed")


if __name__ == "__main__":
    unittest.main()
