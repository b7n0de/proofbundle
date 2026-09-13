"""An attached target is VERIFIED only if it verifies standalone — on every surface, at every hop.

THE CLASS (deep gate 2026-09-05, finding L4-01, P1): a parser-differential at the RESOLVER seam.
``cli._load_related`` verified an attached target's SIGNATURE and then parsed its payload leniently.
A ``loads_strict`` failure — a duplicate JSON key is the cheap one — was swallowed into
``relationships=None`` while the entry kept ``verified=True``. The chain walk then saw a verified,
edge-less ancestor and ended the path honestly "beyond the attached horizon". Measured on HEAD
049b3195, in Python AND in the Rust verifier:

    target payload with a duplicate `predicate` key, hiding an edge to a FAILING ancestor
      python: exit 0, lineage VERIFIED        rust: exit 0, lineage VERIFIED
    the SAME target verified standalone
      ok=False, "duplicate JSON key 'predicate' — rejected fail-closed (WP-C1)"

The clean twin of the same content FAILed, so the verdict of a chain depended on which parser read a
hop — and the hop's author chooses the bytes.

THE PROPERTY, executable below: for every target whose payload the strict oracle refuses, and at every
position in the chain, BOTH shipped verifiers report FAIL with exit 2 — while the well-formed twin is
unaffected. The oracle is ONE function (``_statement_payload.load_statement_strict``) that the loader
and the standalone verifier both call, so "well-formed" cannot mean two things.

ANTI-PARITY, and it is the half that makes this worth having: a resolver that refused EVERY target
would satisfy the property above and be useless. The positive control is asserted in the same matrix.
"""
from __future__ import annotations

import base64
import json
import pathlib
import subprocess
import tempfile
import unittest

from proofbundle import anchors, dsse
from proofbundle.cli import _load_related, main as cli_main
from proofbundle.emit import generate_signer
from proofbundle.relation import CODE_RELATION_TARGET_MALFORMED, LINEAGE_FAIL, LINEAGE_VERIFIED
from proofbundle.relation_statement import emit_relation_statement

REPO = pathlib.Path(__file__).resolve().parents[1]
RUST = REPO / "tools" / "pb_verify_rs" / "target" / "release" / "pb_verify_rs"
RUST_DEBUG = REPO / "tools" / "pb_verify_rs" / "target" / "debug" / "pb_verify_rs"
INTOTO = "application/vnd.in-toto+json"
HEX_A = "a" * 64


def _rust_bin() -> pathlib.Path | None:
    for b in (RUST, RUST_DEBUG):
        if b.exists():
            return b
    return None


def _edge(target_hex: str) -> dict:
    return {"relation": "supersedes",
            "targetReceiptDigest": {"digestAlgorithm": "jcs-sha256-v1", "digest": target_hex}}


def _pub_b64(signer) -> str:
    return base64.b64encode(signer.public_key().public_bytes_raw()).decode()


def _py_cli(args) -> tuple[int, str]:
    import contextlib
    import io
    out = io.StringIO()
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            rc = cli_main(args)
    except SystemExit as e:  # pragma: no cover - argparse paths only
        rc = e.code
    return rc, out.getvalue()


# ── THE MALFORMED FAMILY, enumerated as a PROPERTY, not as one fixture ────────────────────────────
#
# Each entry produces the raw payload BYTES of a target statement that a strict, canonical oracle must
# refuse. They are different defects on purpose: a list of one would pin the instance the gate happened
# to plant (a duplicate key), and the next neighbour would walk through.
def _payload_variants(edge_to_ancestor: dict) -> dict:
    from proofbundle import canonical
    # The control is CANONICALLY produced, never hand-spelled: JCS orders keys by UTF-16 code unit, so
    # `digest` precedes `digestAlgorithm` — a hand-written "obviously sorted" object is not canonical,
    # and a control that is itself malformed would make every case below pass for the wrong reason.
    clean = canonical.canonicalize_statement({
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "t", "digest": {"sha256": HEX_A}}],
        "predicateType": "https://example.invalid/t/v1",
        "predicate": {"relationships": [edge_to_ancestor]},
    })
    inner = json.dumps(edge_to_ancestor, separators=(",", ":"), sort_keys=True).encode()
    return {
        # canonical, well-formed: the POSITIVE CONTROL (anti-parity)
        "wellformed": clean,
        # WP-C1: last-key-wins parsers see a clean predicate, strict parsers refuse
        "dupkey": clean.replace(b'"predicate":{', b'"predicate":{"relationships":[' + inner + b']},"predicate":{', 1),
        # JCS cannot represent NaN; json.loads accepts it
        "nan": clean.replace(b'"predicate":{', b'"predicate":{"extra":NaN,', 1),
        # a UTF-8 BOM in front of the object
        "bom": b"\xef\xbb\xbf" + clean,
        # parses fine, but is not the canonical spelling of itself (whitespace)
        "noncanonical": clean.replace(b'{"_type"', b'{ "_type"'),
        # not an object at all
        "notobject": b'["_type","https://in-toto.io/Statement/v1"]',
    }


class AttachedTargetPayloadOracle(unittest.TestCase):
    """The resolver's verdict on a malformed target payload, and the chain verdict that follows."""

    def setUp(self):
        self.td = pathlib.Path(tempfile.mkdtemp(prefix="l4_01_"))
        self.addCleanup(lambda: __import__("shutil").rmtree(self.td, ignore_errors=True))
        self.signer = generate_signer()
        self.other = generate_signer()
        self.pub = self.signer.public_key().public_bytes_raw()
        self.pub64 = _pub_b64(self.signer)

    def _write(self, name: str, obj) -> str:
        p = self.td / name
        p.write_text(json.dumps(obj), encoding="utf-8")
        return str(p)

    def _ancestor_that_fails(self) -> tuple[str, str]:
        """An attached ancestor signed by a FOREIGN key: any chain through it must FAIL."""
        body = json.dumps({"_type": "https://in-toto.io/Statement/v1",
                           "subject": [{"name": "t2", "digest": {"sha256": HEX_A}}],
                           "predicateType": "https://example.invalid/t/v1", "predicate": {"n": 2}},
                          separators=(",", ":"), sort_keys=True).encode()
        env = dsse.sign_envelope(body, self.other, payload_type=INTOTO)
        return self._write("ancestor.json", env), anchors.statement_content_root(body).hex()

    def test_every_malformed_payload_is_a_typed_target_verdict(self):
        """The RESOLVER half: a refused payload is `payload_malformed` + verified=False, never
        'verified with no edges and no subject' (which is what absence looks like)."""
        _apath, aroot = self._ancestor_that_fails()
        for label, body in _payload_variants(_edge(aroot)).items():
            with self.subTest(variant=label):
                env = dsse.sign_envelope(body, self.signer, payload_type=INTOTO)
                root = anchors.statement_content_root(body).hex()
                tpath = self._write(f"t_{label}.json", env)
                related, errs = _load_related([tpath], self.pub, None)
                self.assertEqual(errs, [], "a malformed PAYLOAD is a target verdict, not a usage error")
                entry = related[root]
                if label == "wellformed":
                    self.assertIsNone(entry["payload_malformed"], entry)
                    self.assertTrue(entry["verified"], "the positive control must still verify")
                else:
                    self.assertIsNotNone(entry["payload_malformed"],
                                         f"{label}: the strict oracle accepted a malformed payload")
                    self.assertFalse(entry["verified"],
                                     f"{label}: a target whose payload fails standalone must not read verified")

    def test_the_chain_verdict_is_invariant_under_a_parser_differential_rewrite(self):
        """THE FINDING ITSELF, both hops, both binaries.

        hop 1: the receipt's own edge names the malformed target.
        hop 2: the malformed target sits BETWEEN the receipt and a failing ancestor — the position the
               attacker chooses, and the one the walk used to skip.
        """
        rust = _rust_bin()
        apath, aroot = self._ancestor_that_fails()
        for label, body in _payload_variants(_edge(aroot)).items():
            env = dsse.sign_envelope(body, self.signer, payload_type=INTOTO)
            root = anchors.statement_content_root(body).hex()
            tpath = self._write(f"chain_{label}.json", env)
            stmt = emit_relation_statement(
                {"schemaVersion": "0.1.0", "statementId": f"s-{label}",
                 "relationships": [_edge(root)]}, self.signer)
            spath = self._write(f"s_{label}.json", stmt)
            argv = ["relation-statement", "verify", spath, "--pub", self.pub64, "--json",
                    "--with-related", tpath, "--with-related", apath]
            rc, out = _py_cli(argv)
            lineage = (json.loads(out).get("lineage") or {}).get("lineage")
            with self.subTest(variant=label, verifier="python"):
                if label == "wellformed":
                    # ANTI-PARITY: the clean twin still FAILs, but for the ANCESTOR's reason — the
                    # resolver did not start refusing everything.
                    self.assertEqual(lineage, LINEAGE_FAIL)
                    self.assertIn("ancestor", json.dumps(json.loads(out)["lineage"]["errors"]))
                else:
                    self.assertEqual(rc, 2, f"{label}: exit {rc}, expected 2")
                    self.assertEqual(lineage, LINEAGE_FAIL, f"{label}: lineage {lineage}")
                    self.assertIn(CODE_RELATION_TARGET_MALFORMED,
                                  json.dumps(json.loads(out)["lineage"]["errors"]),
                                  f"{label}: the typed wire code is missing")
            if rust is None:
                continue
            with self.subTest(variant=label, verifier="rust"):
                p = subprocess.run([str(rust), "verify-relation-statement", spath, self.pub64,
                                    "--with-related", tpath, "--with-related", apath],
                                   capture_output=True, text=True, timeout=60)
                self.assertEqual(p.returncode, 2, f"{label}: rust exit {p.returncode}\n{p.stdout}{p.stderr}")
                self.assertIn('"lineage":"FAIL"', p.stdout, f"{label}: rust said {p.stdout!r}")

    def test_a_clean_chain_still_verifies(self):
        """The other anti-parity direction: with a well-formed target AND a verifying ancestor the
        chain is VERIFIED. Without this, a resolver that refused everything would pass every test above."""
        abody = json.dumps({"_type": "https://in-toto.io/Statement/v1",
                            "subject": [{"name": "t2", "digest": {"sha256": HEX_A}}],
                            "predicateType": "https://example.invalid/t/v1", "predicate": {"n": 2}},
                           separators=(",", ":"), sort_keys=True).encode()
        aenv = dsse.sign_envelope(abody, self.signer, payload_type=INTOTO)   # OUR key: verifies
        apath = self._write("good_ancestor.json", aenv)
        aroot = anchors.statement_content_root(abody).hex()
        body = _payload_variants(_edge(aroot))["wellformed"]
        env = dsse.sign_envelope(body, self.signer, payload_type=INTOTO)
        tpath = self._write("good_target.json", env)
        root = anchors.statement_content_root(body).hex()
        stmt = emit_relation_statement({"schemaVersion": "0.1.0", "statementId": "ok",
                                        "relationships": [_edge(root)]}, self.signer)
        spath = self._write("s_ok.json", stmt)
        rc, out = _py_cli(["relation-statement", "verify", spath, "--pub", self.pub64, "--json",
                           "--with-related", tpath, "--with-related", apath])
        self.assertEqual(rc, 0, out)
        self.assertEqual(json.loads(out)["lineage"]["lineage"], LINEAGE_VERIFIED, out)

    def test_META_a_resolver_that_swallows_the_parse_failure_is_caught(self):
        """PLANT-AND-MUST-CATCH: restore the pre-fix behaviour (parse failure -> 'no edges, verified')
        and the property test above must go red. A guard that cannot fail is decoration."""
        from proofbundle import relation as rel
        aroot = "c" * 64
        pre_fix_entry = {"verified": True, "relationships": None, "verified_under": self.pub64,
                         "subject_digest": None, "subject_digest_state": "absent"}
        # the pre-fix entry carries no payload verdict at all: the engine cannot see the defect
        self.assertIsNone(rel._target_payload_malformed(pre_fix_entry))
        lin = rel.verify_relationship_edges([_edge(aroot)], {aroot: pre_fix_entry}, subject_hex="f" * 64)
        self.assertEqual(lin["lineage"], LINEAGE_VERIFIED,
                         "the pre-fix shape no longer reproduces — this meta-test measures nothing")
        # with the verdict present, the SAME engine call FAILs: the fix is what changed the outcome
        post_fix_entry = dict(pre_fix_entry, verified=False,
                              payload_malformed="duplicate JSON key 'predicate'")
        lin2 = rel.verify_relationship_edges([_edge(aroot)], {aroot: post_fix_entry}, subject_hex="f" * 64)
        self.assertEqual(lin2["lineage"], LINEAGE_FAIL)
        self.assertIn(CODE_RELATION_TARGET_MALFORMED, json.dumps(lin2["errors"]))


class OneOracleForBothSurfaces(unittest.TestCase):
    """Loader and standalone verifier must not be able to disagree about "well-formed"."""

    def test_the_loader_and_the_standalone_verifier_call_the_same_function(self):
        cli_src = (REPO / "src" / "proofbundle" / "cli.py").read_text(encoding="utf-8")
        rs_src = (REPO / "src" / "proofbundle" / "relation_statement.py").read_text(encoding="utf-8")
        self.assertIn("load_statement_strict", cli_src,
                      "the resolver no longer uses the shared payload oracle")
        self.assertIn("load_statement_strict", rs_src,
                      "the standalone verifier no longer uses the shared payload oracle")

    def test_the_oracle_refuses_what_the_standalone_path_refuses(self):
        from proofbundle._statement_payload import load_statement_strict
        from proofbundle.errors import ProofBundleError
        for label, body in _payload_variants(_edge("c" * 64)).items():
            with self.subTest(variant=label):
                if label == "wellformed":
                    self.assertIsInstance(load_statement_strict(body, require_canonical=True), dict)
                else:
                    with self.assertRaises(ProofBundleError):
                        load_statement_strict(body, require_canonical=True)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
