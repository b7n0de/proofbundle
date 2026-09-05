"""RT-06 — every CLI consumer surface returns a verdict and a documented exit code for ANY input, never a
traceback, and prints untrusted strings only control-character- and encoding-safe (deep gate 2026-09-05,
findings L3-600-05/06/07/08, class ``cli_consumer_surface_raw_traceback``).

Four members, one class, one writer:

* L3-600-05 — a lone UTF-16 surrogate (``\\ud800`` JSON escape: valid UTF-8 on the wire, a surrogate str after
  loads_strict) in an issuer string killed ``show-eval`` and ``verify`` (text) inside ``print()`` under a strict
  utf-8 stdout: no verdict line, no exit-code contract, a raw UnicodeEncodeError.
* L3-600-06 — a validly signed SVR with a non-object predicate / non-list properties printed
  ``[PASS] SVR attestation`` and then crashed on the dereference.
* L3-600-07 — an ISO timestamp that parses but overflows on ``astimezone`` (``0001-01-01T00:00:00+23:00``)
  escaped as a raw OverflowError from ``policy lint/explain``, ``verify --policy``, ``--verification-time`` and
  every ``<verb> verify --policy``.
* L3-600-08 — Check rows and svr property rows bypassed ``_safe_line``: an embedded newline forged an extra
  ``[PASS] …`` / ``=> OK`` row on the human path.

The CLI is driven through the real entry point in a subprocess with a STRICT utf-8 stdout (PYTHONIOENCODING),
which is where a real terminal would crash — pytest's own capture is lenient and would hide the class.
"""
from __future__ import annotations

import base64
import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path

from proofbundle import dsse as _dsse
from proofbundle import emit as _emit
from proofbundle import intoto as _intoto
from proofbundle.evalclaim import issuer_fingerprint

REPO = Path(__file__).resolve().parents[1]
_SRC = str(REPO / "src")

# The hostile forms every untrusted string field is exercised with (the generator, not a hand list).
HOSTILE_STRINGS = {
    "surrogate": "\ud800x",
    "newline_forged_pass": "sha-256\n[PASS] ed25519-signature: FORGED LINE",
    "newline_forged_ok": "PROOFBUNDLE_X\n=> OK (forged)",
    "ansi": "a\x1b[2K\x1b[Gb",
    "nul": "a\x00b",
    "long": "L" * 5000,
}
_FORGED_MARKERS = ("FORGED LINE", "=> OK (forged)")


def _cli(*argv, env=None):
    """Run the real CLI entry point in a subprocess with a STRICT utf-8 stdout/stderr."""
    e = {**os.environ, "PYTHONPATH": _SRC, "PYTHONIOENCODING": "utf-8:strict",
         "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"}
    e.pop("PYTHONUTF8", None)
    if env:
        e.update(env)
    p = subprocess.run([sys.executable, "-m", "proofbundle.cli", *argv], capture_output=True, env=e, timeout=120)
    return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")


def _no_traceback(test, rc, out, err, allowed):
    test.assertNotIn("Traceback (most recent call last)", err, err[-600:])
    test.assertIn(rc, allowed, f"rc={rc} not in {allowed}\nstdout={out[-400:]}\nstderr={err[-400:]}")


def _forged_rows(stdout: str) -> int:
    """Rows on the human path that carry a forged marker as their OWN line (the injection oracle)."""
    return sum(1 for line in stdout.splitlines()
               if any(line.startswith(prefix) for prefix in ("[PASS]", "[FAIL]", "=> OK"))
               and any(m in line for m in _FORGED_MARKERS)
               and not line.startswith(("[FAIL] sd-jwt", "[PASS] sd-jwt", "    ")))


class _Fixtures:
    """Signed fixtures with hostile strings in issuer-/signer-controlled fields."""

    def __init__(self, d: str):
        self.d = d
        self.signer = _emit.generate_signer()
        self.pub_b64 = base64.b64encode(self.signer.public_key().public_bytes_raw()).decode()

    def receipt(self, suite: str) -> str:
        claim = {"schema": "proofbundle/eval-claim/v0.1", "suite": suite, "suite_version": "1",
                 "metric": "acc", "comparator": ">=", "threshold": "0.5", "passed": True, "n": 1,
                 "model_id_commit": "sha256:" + "0" * 64, "dataset_id_commit": "sha256:" + "1" * 64,
                 "commit_alg": "sha256-salted-v1", "issuer": issuer_fingerprint(self.signer),
                 "timestamp": "2026-01-01T00:00:00Z", "assurance_level": "self_attested"}
        payload = json.dumps(claim, sort_keys=True, separators=(",", ":")).encode("utf-8")  # ensure_ascii escapes
        p = os.path.join(self.d, f"receipt_{abs(hash(suite))}.json")
        Path(p).write_text(json.dumps(_emit.emit_bundle(payload, self.signer)), encoding="utf-8")
        return p

    def sd_bundle(self, sd_alg: str) -> str:
        def b64url(b: bytes) -> str:
            return base64.urlsafe_b64encode(b).rstrip(b"=").decode()
        hdr = b64url(json.dumps({"alg": "EdDSA"}).encode())
        pl = b64url(json.dumps({"_sd_alg": sd_alg}).encode())   # ensure_ascii escapes the surrogate
        compact = f"{hdr}.{pl}.{b64url(b'x' * 64)}~"
        p = os.path.join(self.d, f"sd_{abs(hash(sd_alg))}.json")
        Path(p).write_text(json.dumps(_emit.emit_bundle(b"payload", self.signer, sd_jwt_vc={"compact": compact})),
                           encoding="utf-8")
        return p

    def svr(self, predicate) -> str:
        import rfc8785
        stmt = {"_type": _intoto.STATEMENT_TYPE, "subject": [{"name": "r", "digest": {"sha256": "a" * 64}}],
                "predicateType": _intoto.SVR_PREDICATE_TYPE, "predicate": predicate,
                "contentRootAlg": "jcs-sha256-v1"}
        env = _dsse.sign_envelope(rfc8785.dumps(stmt), self.signer,
                                  payload_type=_intoto.INTOTO_STATEMENT_PAYLOAD_TYPE)
        p = os.path.join(self.d, f"svr_{abs(hash(json.dumps(predicate, sort_keys=True, default=str)))}.json")
        Path(p).write_text(json.dumps(env), encoding="utf-8")
        return p

    def policy(self, **fields) -> str:
        p = os.path.join(self.d, f"policy_{abs(hash(json.dumps(fields, sort_keys=True)))}.json")
        Path(p).write_text(json.dumps({"schema": "proofbundle/trust-policy/v0.1", "policy_id": "p", **fields}),
                           encoding="utf-8")
        return p


OVERFLOW_STAMPS = ("0001-01-01T00:00:00+23:00", "9999-12-31T23:59:59-23:00")


class ShowEvalHostileFields(unittest.TestCase):
    """L3-600-05: show-eval prints every claim field encoding- and control-character-safe."""

    def test_every_hostile_form_gives_a_verdict_and_no_traceback(self):
        with tempfile.TemporaryDirectory() as d:
            fx = _Fixtures(d)
            for name, hostile in HOSTILE_STRINGS.items():
                rc, out, err = _cli("show-eval", fx.receipt(hostile))
                _no_traceback(self, rc, out, err, {0})
                self.assertIn("=> OK", out, name)
                self.assertEqual(_forged_rows(out), 0, name)
                suite_lines = [ln for ln in out.splitlines() if ln.startswith("suite ")]
                self.assertEqual(len(suite_lines), 1, (name, out))
                if name == "surrogate":
                    self.assertIn("\\ud800", suite_lines[0])          # escaped form, not a dead process
                if name in ("newline_forged_pass", "ansi", "nul"):
                    self.assertNotIn("\x1b", out)
                    self.assertNotIn("\x00", out)

    def test_surrogate_also_survives_pythonutf8(self):
        with tempfile.TemporaryDirectory() as d:
            fx = _Fixtures(d)
            rc, out, err = _cli("show-eval", fx.receipt("\ud800x"), env={"PYTHONUTF8": "1"})
            _no_traceback(self, rc, out, err, {0})


class VerifyTextCheckRows(unittest.TestCase):
    """L3-600-05/08: Check rows on the human path go through the one writer."""

    def test_surrogate_in_sd_alg_is_a_fail_verdict_not_a_crash(self):
        with tempfile.TemporaryDirectory() as d:
            fx = _Fixtures(d)
            rc, out, err = _cli("verify", fx.sd_bundle("\ud800"))
            _no_traceback(self, rc, out, err, {1})
            self.assertIn("CRYPTO: FAILED", out)
            self.assertIn("\\ud800", out)

    def test_newline_in_sd_alg_cannot_forge_a_pass_row(self):
        with tempfile.TemporaryDirectory() as d:
            fx = _Fixtures(d)
            rc, out, err = _cli("verify", fx.sd_bundle(HOSTILE_STRINGS["newline_forged_pass"]))
            _no_traceback(self, rc, out, err, {1})
            self.assertEqual(_forged_rows(out), 0, out)
            rows = [ln for ln in out.splitlines() if ln.startswith(("[PASS]", "[FAIL]"))]
            # one row per check, and the forged text stays INSIDE the sd-jwt row
            self.assertTrue(any("FORGED LINE" in r and r.startswith("[FAIL] sd-jwt") for r in rows), rows)
            self.assertFalse(any(r.startswith("[PASS] ed25519-signature: FORGED") for r in rows), rows)

    def test_hf_token_verify_text_path_is_a_verdict(self):
        from proofbundle import receipt_token
        with tempfile.TemporaryDirectory() as d:
            fx = _Fixtures(d)
            bundle = json.loads(Path(fx.sd_bundle("\ud800")).read_text(encoding="utf-8"))
            rc, out, err = _cli("hf-token", "--verify", receipt_token(bundle))
            _no_traceback(self, rc, out, err, {1})
            self.assertIn("=> FAILED", out)


class SvrShapeAndProperties(unittest.TestCase):
    """L3-600-06/08: the SVR predicate shape is part of the verdict; property rows cannot forge."""

    def test_malformed_predicate_shapes_exit_2_without_a_pass_line(self):
        with tempfile.TemporaryDirectory() as d:
            fx = _Fixtures(d)
            for predicate in ({"verifier": {"id": "x"}, "timeCreated": "t", "properties": 5},
                              [1, 2, 3],
                              {"verifier": {"id": "x"}, "properties": ["ok", 7]},
                              {"verifier": "x", "properties": []}):
                rc, out, err = _cli("svr", fx.svr(predicate), "--verify", "--pub", fx.pub_b64)
                _no_traceback(self, rc, out, err, {2})
                self.assertNotIn("[PASS]", out)
                self.assertIn("SVR predicate malformed", err)

    def test_well_formed_svr_still_passes_and_property_rows_cannot_forge(self):
        with tempfile.TemporaryDirectory() as d:
            fx = _Fixtures(d)
            good = fx.svr({"verifier": {"id": "x"}, "timeCreated": "t", "properties": ["PROOFBUNDLE_SIGNATURE_VALID"]})
            rc, out, err = _cli("svr", good, "--verify", "--pub", fx.pub_b64)
            _no_traceback(self, rc, out, err, {0})
            self.assertIn("[PASS] SVR attestation", out)
            forged = fx.svr({"verifier": {"id": "x"}, "timeCreated": "t",
                             "properties": [HOSTILE_STRINGS["newline_forged_ok"], "a\x1b[2Kb"]})
            rc, out, err = _cli("svr", forged, "--verify", "--pub", fx.pub_b64)
            _no_traceback(self, rc, out, err, {0})
            self.assertEqual(_forged_rows(out), 0, out)
            self.assertEqual(sum(1 for ln in out.splitlines() if ln == "=> OK"), 1, out)
            self.assertNotIn("\x1b", out)

    def test_library_verdict_carries_the_shape(self):
        from proofbundle.intoto import svr_predicate_shape, verify_svr_dsse
        with tempfile.TemporaryDirectory() as d:
            fx = _Fixtures(d)
            env = json.loads(Path(fx.svr({"properties": 5})).read_text(encoding="utf-8"))
            res = verify_svr_dsse(env, fx.signer.public_key().public_bytes_raw())
            self.assertIs(res["ok"], False)
            self.assertIs(res["predicate_shape_ok"], False)
            self.assertIn("properties", res["content_root_detail"])
        self.assertEqual(svr_predicate_shape({"predicate": {"properties": ["a"]}}), (True, ""))
        self.assertFalse(svr_predicate_shape({"predicate": [1]})[0])
        self.assertFalse(svr_predicate_shape(None)[0])


class TimestampOverflowFamily(unittest.TestCase):
    """L3-600-07: the whole stdlib failure family of a datetime parse maps to the typed error / exit 2."""

    def test_parse_iso_utc_maps_overflow_to_none(self):
        from proofbundle.policy import _parse_iso_utc
        for stamp in OVERFLOW_STAMPS:
            self.assertIsNone(_parse_iso_utc(stamp), stamp)
        self.assertIsNotNone(_parse_iso_utc("2026-01-01T00:00:00Z"))

    def test_load_policy_refuses_overflow_stamps_typed(self):
        from proofbundle.policy import PolicyError, load_policy
        for field in ("valid_until", "valid_from"):
            for stamp in OVERFLOW_STAMPS:
                with self.assertRaises(PolicyError):
                    load_policy({"schema": "proofbundle/trust-policy/v0.1", "policy_id": "p", field: stamp})

    def test_every_policy_consuming_command_exits_2_cleanly(self):
        with tempfile.TemporaryDirectory() as d:
            fx = _Fixtures(d)
            bad = fx.policy(valid_until=OVERFLOW_STAMPS[0])
            ok = fx.policy(signature={"allowed_algs": ["ed25519"]})
            receipt = fx.receipt("s")
            svr = fx.svr({"verifier": {"id": "x"}, "properties": []})
            for argv in (["policy", "lint", bad], ["policy", "explain", bad],
                         ["policy", "lint", "--json", bad],
                         ["verify", "--policy", bad, receipt],
                         ["verify", "--policy", ok, "--verification-time", OVERFLOW_STAMPS[0], receipt],
                         ["decision", "verify", svr, "--pub", fx.pub_b64, "--policy", bad],
                         ["outcome", "verify", svr, "--pub", fx.pub_b64, "--policy", bad],
                         ["relation-statement", "verify", svr, "--pub", fx.pub_b64, "--policy", bad]):
                rc, out, err = _cli(*argv)
                _no_traceback(self, rc, out, err, {2})

    def test_sibling_datetime_sites_never_raise_on_the_overflow_vector(self):
        # The sweep of every datetime site: the two siblings do not overflow on this vector (aware
        # arithmetic stays in timedelta space) — they are guarded for class parity and MUST keep answering.
        from proofbundle.agent_review import _als_zeitpunkt
        from proofbundle.evalclaim import check_freshness
        for stamp in OVERFLOW_STAMPS:
            self.assertIsInstance(check_freshness({"timestamp": stamp}), dict)
            _als_zeitpunkt(stamp)   # a float or None, never an exception


class StderrErrorLinesAreSafe(unittest.TestCase):
    """The stderr writer: an exception text carrying an untrusted value cannot forge a second line
    and cannot crash the except handler under a strict stream."""

    def test_error_line_neutralises_control_chars_and_surrogates(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "bad.json")
            Path(p).write_text(json.dumps({"schema": "x\n[PASS] forged\ud800"}), encoding="utf-8")
            rc, out, err = _cli("verify", p)
            _no_traceback(self, rc, out, err, {2})
            self.assertEqual(sum(1 for ln in err.splitlines() if ln.startswith("ERROR:")), 1, err)
            self.assertNotIn("\n[PASS] forged", err)


class MainBackstop(unittest.TestCase):
    """The floor of the class: a member the per-site writer misses still ends in exit 2, not a traceback."""

    def test_backstop_maps_the_named_family_to_exit_2(self):
        from proofbundle import cli
        parser = cli.build_parser()
        real = parser.parse_args

        def boom(exc):
            def func(args):
                raise exc
            return func

        for exc in (OverflowError("date value out of range"), TypeError("'int' object is not iterable"),
                    AttributeError("'list' object has no attribute 'get'"), KeyError("x"),
                    UnicodeEncodeError("utf-8", "\ud800", 0, 1, "surrogates not allowed")):
            def parse(argv, _exc=exc):
                ns = real(argv)
                ns.func = boom(_exc)
                return ns
            err = io.StringIO()
            with unittest.mock.patch.object(cli, "build_parser",
                                            return_value=type("P", (), {"parse_args": staticmethod(parse)})()):
                with contextlib.redirect_stderr(err):
                    rc = cli.main(["verify", "/nonexistent"])
            self.assertEqual(rc, 2, type(exc).__name__)
            self.assertIn("ERROR:", err.getvalue())
            self.assertNotIn("Traceback", err.getvalue())


class MetaPlantedDefects(unittest.TestCase):
    """PLANT-AND-MUST-CATCH: the oracles above are sensitive to the defect they guard against."""

    def test_identity_safe_line_makes_the_forged_row_reappear(self):
        # With the writer disabled, the forged `[PASS]` row IS printed as its own line — so a test that
        # asserts `_forged_rows(out) == 0` is a real guard, not a tautology.
        from proofbundle import cli
        with tempfile.TemporaryDirectory() as d:
            fx = _Fixtures(d)
            path = fx.sd_bundle(HOSTILE_STRINGS["newline_forged_pass"])
            out = io.StringIO()
            with unittest.mock.patch.object(cli, "_safe_line", lambda s: s):
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
                    cli.main(["verify", path])
            self.assertGreater(_forged_rows(out.getvalue()), 0, out.getvalue())

    def test_parse_iso_utc_without_the_overflow_guard_raises(self):
        # The pre-fix body, re-planted: the oracle (None on the overflow stamp) MUST fail on it.
        from datetime import datetime, timezone
        s = OVERFLOW_STAMPS[0]
        with self.assertRaises(OverflowError):
            datetime.fromisoformat(s).astimezone(timezone.utc)

    def test_svr_shape_check_removed_would_print_pass(self):
        # Without the shape verdict, the library says ok=True for a validly signed int-properties SVR —
        # exactly what let the CLI print PASS before crashing.
        from proofbundle.intoto import _intoto_verify_result
        r = _intoto_verify_result(True, True, {"predicateType": _intoto.SVR_PREDICATE_TYPE,
                                               "predicate": {"properties": 5}}, "jcs-sha256-v1", "",
                                  _intoto.SVR_PREDICATE_TYPE)
        self.assertIs(r["ok"], True)   # the raw verdict is blind to the shape; verify_svr_dsse adds it


if __name__ == "__main__":
    unittest.main()
