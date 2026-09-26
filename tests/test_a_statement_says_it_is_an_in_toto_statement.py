"""A signed statement says it is an in-toto Statement v1, and every verifier that reports structure_ok reads it.

WHERE THIS COMES FROM. Deep gate Z195 against main 5b53ab3e, finding L3-Z195-01 (P2, jury 3 of 3):
decision, outcome and relation-statement verify reported structure_ok=true, and decision verify under a
signer-pinning policy safeForAutomation=true, for a signed statement whose `_type` was absent, JSON null
or `Statement/v0.1`. Measured again on main 10f3466b before this change. Each of these verifiers builds
`_type` when it emits and none read it back. verification_summary, run_ledger and trust_pack had the same
code shape and report structure_ok as well.

WHAT IS PINNED. All six verifiers parse through `_statement_payload.load_statement_strict`, which reads
`_type`, and the --with-related resolver already did. For each: a positive control re-signed from the
emitter's own statement, then seven spellings of a wrong `_type`, each refused with structure_ok False.
The Rust verifier refuses the same bytes on both relation subcommands, as an attached target and on the
trust-pack threshold subcommand. A sweep fails when a module that reports structure_ok for an in-toto
Statement parses without the oracle, and a second one when a Rust function parses a DSSE payload
without `statement_typ_problem`.

WHAT IS NOT IN SCOPE. `intoto --verify` and `svr --verify` list what their `ok` covers, `_type` is not on
that list, and they report no structure_ok; the jury refuted L3-Z195-02 for that reason.
"""
from __future__ import annotations

import ast
import base64
import contextlib
import io
import json
import pathlib
import re
import subprocess
import sys
import tempfile
import unittest

import rfc8785

from proofbundle import anchors, dsse
from proofbundle._statement_payload import STATEMENT_TYPE, load_statement_strict
from proofbundle.emit import generate_signer
from proofbundle.errors import BundleFormatError

REPO = pathlib.Path(__file__).resolve().parents[1]
SRC = REPO / "src" / "proofbundle"
sys.path.insert(0, str(REPO / "conformance"))
from common_vocabulary import compare, exit_class, label_from_verify  # noqa: E402
PT = "application/vnd.in-toto+json"
_DELETE = object()

# Every wrong spelling of `_type` the oracle must refuse, by name.
WRONG_TYPES = {
    "absent": _DELETE,
    "null": None,
    "v0.1": "https://in-toto.io/Statement/v0.1",
    "trailing slash": STATEMENT_TYPE + "/",
    "upper case": STATEMENT_TYPE.upper(),
    "an integer": 1,
    "a list holding the right value": [STATEMENT_TYPE],
}


def _pub(sk) -> bytes:
    return sk.public_key().public_bytes_raw()


def _statement(env: dict) -> dict:
    return json.loads(dsse.load_payload(env))


def _with_type(statement: dict, value) -> dict:
    s = dict(statement)
    if value is _DELETE:
        s.pop("_type", None)
    else:
        s["_type"] = value
    return s


def _signed(statement: dict, sk) -> dict:
    """The statement as the emitters sign it: RFC 8785 bytes under the in-toto payload type."""
    return dsse.sign_envelope(rfc8785.dumps(statement), sk, payload_type=PT)


def _decision(sk) -> dict:
    from proofbundle.decision import emit_decision_receipt
    base = json.loads((REPO / "examples" / "decision_receipt_deny.json").read_text(encoding="utf-8"))
    return emit_decision_receipt(base, sk, strict=True)


def _outcome(sk) -> dict:
    from proofbundle.outcome import emit_outcome_receipt
    return emit_outcome_receipt({
        "schemaVersion": "0.1.0", "outcomeId": "outcome-0001", "decisionRef": {"sha256": "a" * 64},
        "executor": {"id": "executor:runner-7", "keyId": "kid-exec"},
        "requestedActionDigest": {"sha256": "c" * 64}, "status": "executed",
        "performedAt": "2026-07-14T10:00:00Z", "effectDigest": {"sha256": "c" * 64}}, sk)


def _relation_statement(sk, target_hex: str = "a" * 64) -> dict:
    from proofbundle.relation_statement import emit_relation_statement
    return emit_relation_statement({
        "schemaVersion": "0.1.0", "statementId": "urn:uuid:s-1",
        "relationships": [{"relation": "retracts", "targetReceiptDigest": {
            "digestAlgorithm": "jcs-sha256-v1", "digest": target_hex}}]}, sk)


def _summary(sk) -> dict:
    from proofbundle.verification_summary import emit_verification_summary
    return emit_verification_summary({
        "schemaVersion": "0.1.0", "summaryId": "summary-0001", "producedAt": "2026-07-14T10:00:00Z",
        "levels": [{"kind": "eval", "receiptRef": {"sha256": "a" * 64}, "status": "VERIFIED",
                    "evidenceClass": "authorship_integrity"}],
        "nonClaims": ["does not prove the eval number is true"]}, sk)


def _ledger(sk) -> dict:
    from proofbundle.run_ledger import emit_run_ledger, link_runs
    return emit_run_ledger({
        "schemaVersion": "0.1.0", "studyId": "study-0001", "runBudget": 5,
        "runs": link_runs(["1" * 64, "2" * 64]),
        "nonClaims": ["does not prove no run exists outside this ledger"]}, sk)


def _verify(name: str, env: dict, pub: bytes) -> dict:
    if name == "decision":
        from proofbundle.decision import verify_decision_receipt
        return verify_decision_receipt(env, pub, strict=True)
    if name == "outcome":
        from proofbundle.outcome import verify_outcome_receipt
        return verify_outcome_receipt(env, pub, strict=True)
    if name == "relation_statement":
        from proofbundle.relation_statement import verify_relation_statement
        return verify_relation_statement(env, pub)
    if name == "verification_summary":
        from proofbundle.verification_summary import verify_verification_summary
        return verify_verification_summary(env, pub, strict=True)
    if name == "run_ledger":
        from proofbundle.run_ledger import verify_run_ledger
        return verify_run_ledger(env, pub, strict=True)
    raise AssertionError(name)


SINGLE_SIGNER = {"decision": _decision, "outcome": _outcome, "relation_statement": _relation_statement,
                 "verification_summary": _summary, "run_ledger": _ledger}


class TheOracle(unittest.TestCase):

    def test_the_right_type_passes_and_every_wrong_one_is_named(self):
        good = {"_type": STATEMENT_TYPE, "subject": [], "predicateType": "x", "predicate": {}}
        self.assertEqual(load_statement_strict(json.dumps(good).encode()), good)
        for label, value in WRONG_TYPES.items():
            with self.subTest(type=label), self.assertRaises(BundleFormatError) as ctx:
                load_statement_strict(json.dumps(_with_type(good, value)).encode())
            self.assertIn("not an in-toto Statement v1: _type is", str(ctx.exception))


class EverySingleSignerVerifier(unittest.TestCase):

    def test_positive_control_the_re_signed_statement_verifies(self):
        """Without this, every refusal below could come from the re-signing, not from `_type`."""
        for name, emit in SINGLE_SIGNER.items():
            with self.subTest(verifier=name):
                sk = generate_signer()
                env = _signed(_statement(emit(sk)), sk)
                r = _verify(name, env, _pub(sk))
                self.assertIs(r["structure_ok"], True, r["errors"])
                self.assertIs(r["ok"], True, r["errors"])

    def test_a_wrong_type_is_a_structure_failure_everywhere(self):
        for name, emit in SINGLE_SIGNER.items():
            sk = generate_signer()
            stmt = _statement(emit(sk))
            for label, value in WRONG_TYPES.items():
                with self.subTest(verifier=name, type=label):
                    r = _verify(name, _signed(_with_type(stmt, value), sk), _pub(sk))
                    self.assertIs(r["crypto_ok"], True)
                    self.assertIs(r["structure_ok"], False)
                    self.assertIs(r["ok"], False)
                    if isinstance(r.get("automation"), dict):
                        self.assertIs(r["automation"]["safeForAutomation"], False)
                    self.assertTrue(any("_type" in e for e in r["errors"]), r["errors"])

    def test_the_raising_variants_raise(self):
        from proofbundle.decision import verify_decision_receipt_or_raise
        from proofbundle.outcome import verify_outcome_receipt_or_raise
        for name, emit, fn in (("decision", _decision, verify_decision_receipt_or_raise),
                               ("outcome", _outcome, verify_outcome_receipt_or_raise)):
            sk = generate_signer()
            env = _signed(_with_type(_statement(emit(sk)), None), sk)
            with self.subTest(verifier=name), self.assertRaises(BundleFormatError):
                fn(env, _pub(sk))

    def test_the_decision_finding_as_the_gate_measured_it(self):
        """L3-Z195-01 end to end: a pinned signer, --strict, a policy; a deleted `_type` was exit 0 and
        safeForAutomation=true on main 10f3466b."""
        from proofbundle.cli import main as cli
        sk = generate_signer()
        stmt = _statement(_decision(sk))
        pred = stmt["predicate"]
        pub_b64 = base64.b64encode(_pub(sk)).decode()
        policy = {"schema": "proofbundle/trust-policy/v0.2", "policy_id": "p",
                  "allowed_schema_versions": ["proofbundle/v0.1"],
                  "signature": {"allowed_algs": ["ed25519"], "require_expected_signer": True},
                  "decision_receipt": {"accepted_predicate_types": [stmt["predicateType"]],
                                       "trusted_decision_makers": [{"id": pred["decisionMaker"]["id"],
                                                                    "public_key_b64": pub_b64}],
                                       "allowed_decision_types": [pred["decisionType"]],
                                       "allowed_verdicts": ["ALLOW", "DENY"], "required_evidence_relations": [],
                                       "require_policy_digest": True, "require_external_anchor": False,
                                       "allow_pending": False}}
        with tempfile.TemporaryDirectory() as d:
            pol = pathlib.Path(d) / "pol.json"
            pol.write_text(json.dumps(policy), encoding="utf-8")
            for label, s in (("control", stmt), ("_type deleted", _with_type(stmt, _DELETE))):
                path = pathlib.Path(d) / "m.json"
                path.write_text(json.dumps(_signed(s, sk)), encoding="utf-8")
                out = io.StringIO()
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                    try:
                        rc = cli(["decision", "verify", str(path), "--pub", pub_b64, "--json", "--strict",
                                  "--policy", str(pol)])
                    except SystemExit as e:
                        rc = e.code
                j = json.loads(out.getvalue())
                with self.subTest(case=label):
                    if label == "control":
                        self.assertEqual((rc, j["automation"]["safeForAutomation"]), (0, True))
                    else:
                        self.assertEqual((rc, j["structure_ok"], j["automation"]["safeForAutomation"]),
                                         (2, False, False))


def _trust_pack():
    """A valid 1-of-1 root pack and its signer."""
    from proofbundle.trust_pack import sign_trust_pack
    sk = generate_signer()
    pred = {"schemaVersion": "0.1.0", "trustPackId": "tp", "version": 1,
            "expires": "2099-01-01T00:00:00Z", "prevVersionDigest": None,
            "roles": {"root": {"keyIds": ["r"], "threshold": 1}},
            "keys": {"r": {"publicKey": base64.b64encode(_pub(sk)).decode()}},
            "nonClaims": ["does not assert the key holders are honest"]}
    return sign_trust_pack(pred, {"r": sk}), sk


def _resigned_pack(statement: dict, sk) -> dict:
    body = rfc8785.dumps(statement)
    return {"payload": base64.b64encode(body).decode(), "payloadType": PT,
            "signatures": [{"keyid": "r", "sig": base64.b64encode(sk.sign(dsse.pae(PT, body))).decode()}]}


class TheTrustPack(unittest.TestCase):

    def test_the_pack_reads_its_type(self):
        from proofbundle.trust_pack import verify_trust_pack
        env, sk = _trust_pack()
        stmt = _statement(env)
        self.assertIs(verify_trust_pack(_resigned_pack(stmt, sk))["ok"], True)
        for label, value in WRONG_TYPES.items():
            with self.subTest(type=label):
                r = verify_trust_pack(_resigned_pack(_with_type(stmt, value), sk))
                self.assertIs(r["structure_ok"], False)
                self.assertIs(r["ok"], False)
                self.assertTrue(any("_type" in e for e in r["errors"]), r["errors"])


class TheResolver(unittest.TestCase):

    def test_an_attached_target_with_a_wrong_type_is_malformed(self):
        from proofbundle.cli import _load_related
        sk = generate_signer()
        stmt = _statement(_decision(sk))
        with tempfile.TemporaryDirectory() as d:
            for label, s, malformed in (("control", stmt, False), ("_type null", _with_type(stmt, None), True)):
                path = pathlib.Path(d) / f"{label}.json"
                env = _signed(s, sk)
                path.write_text(json.dumps(env), encoding="utf-8")
                related, errs = _load_related([str(path)], _pub(sk))
                root = anchors.statement_content_root(dsse.load_payload(env)).hex()
                with self.subTest(case=label):
                    self.assertEqual(errs, [])
                    self.assertEqual(bool(related[root]["payload_malformed"]), malformed)
                    self.assertIs(related[root]["verified"], not malformed)


RUST_DIR = REPO / "tools" / "pb_verify_rs"
RUST_BIN = RUST_DIR / "target" / "release" / "pb_verify_rs"


def _rust_binary():
    import shutil
    if RUST_BIN.exists():
        return RUST_BIN
    if not RUST_DIR.is_dir() or shutil.which("cargo") is None:
        return None
    b = subprocess.run(["cargo", "build", "--release"], cwd=RUST_DIR,  # noqa: S603,S607
                       capture_output=True, text=True, timeout=1800)
    return RUST_BIN if b.returncode == 0 and RUST_BIN.exists() else None


class RustParity(unittest.TestCase):
    """The same bytes, the same exit class and lineage on both verifiers."""

    @classmethod
    def setUpClass(cls):
        cls.rust = _rust_binary()
        if cls.rust is None:
            raise unittest.SkipTest("NOT MEASURABLE: tools/pb_verify_rs is missing or cargo is absent — "
                                    "the parity cases did NOT run (env_blocked, never green)")

    def _both(self, verb: str, sub: str, env: dict, sk, related=()):
        from proofbundle.cli import main as cli
        pub_b64 = base64.b64encode(_pub(sk)).decode()
        with tempfile.TemporaryDirectory() as d:
            path = pathlib.Path(d) / "env.json"
            path.write_text(json.dumps(env), encoding="utf-8")
            extra = []
            for i, rel in enumerate(related):
                rp = pathlib.Path(d) / f"rel{i}.json"
                rp.write_text(json.dumps(rel), encoding="utf-8")
                extra += ["--with-related", str(rp)]
            out = io.StringIO()
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                try:
                    py_rc = cli([verb, "verify", str(path), "--pub", pub_b64, "--json", *extra])
                except SystemExit as e:
                    py_rc = e.code
            rs = subprocess.run([str(self.rust), sub, str(path), pub_b64, *extra],
                                capture_output=True, text=True, timeout=120)
        # The ONE projection the cross-implementation differential uses (tools/pb_verify_rs/crosscheck.py),
        # on the two axes both verifiers carry: exit class and lineage.
        py = label_from_verify(py_rc, json.loads(out.getvalue()))
        rs_label = label_from_verify(rs.returncode, json.loads(rs.stdout))
        two = ("exitClass", "lineage")
        return {a: py[a] for a in two}, {a: rs_label[a] for a in two}

    def assertSameLabel(self, py: dict, rs: dict):
        """`compare` checks the axes the EXPECTED side pins, and treats a null lineage and NOT_EVALUATED
        as one observable fact; asked in both directions, it is a symmetric equality on these axes."""
        self.assertEqual(compare(py, rs)[1] + compare(rs, py)[1], [], (py, rs))

    def test_a_wrong_type_on_the_verified_statement(self):
        for verb, sub, emit in (("relation-statement", "verify-relation-statement", _relation_statement),
                                ("decision", "verify-relation", _decision),
                                ("outcome", "verify-relation", _outcome)):
            sk = generate_signer()
            stmt = _statement(emit(sk))
            for label, value in (("control", STATEMENT_TYPE), ("absent", _DELETE), ("null", None),
                                 ("v0.1", WRONG_TYPES["v0.1"])):
                with self.subTest(verifier=verb, type=label):
                    py, rs = self._both(verb, sub, _signed(_with_type(stmt, value), sk), sk)
                    self.assertSameLabel(py, rs)
                    self.assertEqual(py["exitClass"], exit_class(0 if label == "control" else 2))

    def test_a_wrong_type_on_an_attached_target(self):
        sk = generate_signer()
        target_stmt = _statement(_decision(sk))
        for label, value, want in (("control", STATEMENT_TYPE, (exit_class(0), "VERIFIED")),
                                   ("_type null", None, (exit_class(2), "FAIL"))):
            target = _signed(_with_type(target_stmt, value), sk)
            root = anchors.statement_content_root(dsse.load_payload(target)).hex()
            with self.subTest(target=label):
                py, rs = self._both("relation-statement", "verify-relation-statement",
                                    _relation_statement(sk, root), sk, related=[target])
                self.assertSameLabel(py, rs)
                self.assertEqual((py["exitClass"], py["lineage"]), want)

    def test_a_wrong_type_on_a_trust_pack(self):
        """Codex on PR 282: Python refused such a pack (structure_ok False) while the Rust slice met its
        threshold with exit 0, on the same bytes."""
        from proofbundle.trust_pack import verify_trust_pack
        env, sk = _trust_pack()
        stmt = _statement(env)
        for label, value in (("control", STATEMENT_TYPE), ("absent", _DELETE), ("null", None),
                             ("v0.1", WRONG_TYPES["v0.1"])):
            pack = _resigned_pack(_with_type(stmt, value), sk)
            py = verify_trust_pack(pack)
            with tempfile.TemporaryDirectory() as d:
                path = pathlib.Path(d) / "tp.json"
                path.write_text(json.dumps(pack), encoding="utf-8")
                rs = subprocess.run([str(self.rust), "verify-trust-pack-threshold", str(path)],
                                    capture_output=True, text=True, timeout=120)
            with self.subTest(type=label):
                if label == "control":
                    self.assertEqual((py["ok"], rs.returncode), (True, 0), rs.stdout)
                else:
                    self.assertEqual((py["structure_ok"], rs.returncode), (False, 2), rs.stdout)
                    self.assertIn("not an in-toto Statement v1: _type is", rs.stdout)


# Modules that report structure_ok for an in-toto Statement without the oracle, with the reason.
READS_TYPE_ITSELF = {
    "agent_review.py": "reads `_type` in its own statement reader and names STATEMENT_TYPE_ABSENT / "
                       "STATEMENT_TYPE_MISMATCH",
}


class TheSweep(unittest.TestCase):
    """Generator, not fixture: a new Statement verifier that reports structure_ok is classified."""

    def _statement_verifiers(self) -> dict:
        found = {}
        for path in sorted(SRC.rglob("*.py")):
            text = path.read_text(encoding="utf-8")
            if STATEMENT_TYPE not in text or '"structure_ok"' not in text:
                continue
            calls = {n.func.attr if isinstance(n.func, ast.Attribute) else getattr(n.func, "id", None)
                     for n in ast.walk(ast.parse(text)) if isinstance(n, ast.Call)}
            found[path.relative_to(SRC).as_posix()] = calls
        return found

    def test_every_statement_verifier_parses_through_the_oracle(self):
        stray = [rel for rel, calls in self._statement_verifiers().items()
                 if rel not in READS_TYPE_ITSELF
                 and ("load_statement_strict" not in calls or "loads_strict" in calls)]
        self.assertEqual(stray, [], "a module reports structure_ok for an in-toto Statement without "
                                    "_statement_payload.load_statement_strict; route it there or name it "
                                    "in READS_TYPE_ITSELF with its reason")

    def test_the_sweep_sees_the_six_and_the_named(self):
        """Counter-direction: a sweep that finds nothing proves nothing."""
        self.assertEqual(set(self._statement_verifiers()),
                         {"decision.py", "outcome.py", "relation_statement.py", "verification_summary.py",
                          "run_ledger.py", "trust_pack.py"} | set(READS_TYPE_ITSELF))


class TheRustSweep(unittest.TestCase):
    """The same generator on the Rust side: a function that decodes a DSSE payload (`b64_dsse`) and parses
    it (`strict_parse`) reads a Statement, and reads its `_type`. The trust-pack slice parsed the Statement
    and never asked (Codex on PR 282)."""

    def setUp(self):
        main_rs = RUST_DIR / "src" / "main.rs"
        if not main_rs.is_file():
            self.skipTest("NOT MEASURABLE: tools/pb_verify_rs/src/main.rs is not in this tree; the Rust "
                          "sweep did NOT run")
        self.text = main_rs.read_text(encoding="utf-8")

    @staticmethod
    def _payload_readers(text: str) -> dict:
        """{function: True when it asks `statement_typ_problem` after its parse and before it reads the
        predicate}, for each function that decodes and parses a DSSE payload. Comments are removed first
        (the reader of the key sweep, one reading for both), so a comment naming the oracle counts for
        nothing. It reads text, names a function by its `fn` line at column 0, and asks whether the oracle
        is CALLED in that place, not whether its answer is obeyed."""
        sys.path.insert(0, str(REPO))
        from tests.test_trust_anchor_keys_refused_on_every_surface import _rust_code_only
        code = _rust_code_only(text.split("#[cfg(test)]")[0])
        found, name, body = {}, None, []
        for line in code.splitlines() + ["fn end_of_file("]:
            start = re.match(r"(?:pub )?fn (\w+)", line)
            if start:
                fn = "\n".join(body)
                if name and "b64_dsse(" in fn and "strict_parse(" in fn:
                    parse = fn.index("strict_parse(")
                    oracle = fn.find("statement_typ_problem(", parse)
                    predicate = fn.find('get("predicate")', parse)
                    found[name] = oracle >= 0 and (predicate < 0 or oracle < predicate)
                name, body = start.group(1), []
            body.append(line)
        return found

    def test_every_rust_payload_reader_reads_the_type(self):
        blind = sorted(n for n, reads in self._payload_readers(self.text).items() if not reads)
        self.assertEqual(blind, [], "a Rust function parses a DSSE payload without statement_typ_problem "
                                    "before it reads the predicate")

    def test_the_rust_sweep_sees_the_three_readers(self):
        """Counter-direction: the two relation paths and the trust-pack slice."""
        self.assertEqual(set(self._payload_readers(self.text)),
                         {"verify_trust_pack_threshold", "load_related", "run_verify_relation"})

    def test_a_reader_without_the_oracle_is_caught(self):
        """Planted on the trust-pack slice: the check removed, commented out, and moved behind the
        predicate read; each leaves exactly that function blind."""
        check = ("    if let Some(p) = statement_typ_problem(&statement) {\n"
                 "        return Err(p);\n    }\n")
        read = '    let predicate = statement\n        .get("predicate")'
        self.assertEqual(self.text.count(check + read), 1, "the plant no longer hits the trust-pack slice")
        planted = {
            "removed": self.text.replace(check + read, read, 1),
            "in a comment": self.text.replace(check + read, "    // statement_typ_problem(&statement)\n" + read, 1),
            "after the predicate read": self.text.replace(
                check + read, read.replace("let predicate", "let _read_first") + ';\n' + check + read, 1),
        }
        for label, text in planted.items():
            with self.subTest(plant=label):
                self.assertNotEqual(text, self.text)
                self.assertEqual(sorted(n for n, ok in self._payload_readers(text).items() if not ok),
                                 ["verify_trust_pack_threshold"])


if __name__ == "__main__":
    unittest.main()
