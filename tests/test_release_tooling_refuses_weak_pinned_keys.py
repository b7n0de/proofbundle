"""The release tooling under scripts/ refuses a weak Ed25519 key it pins, like the package does.

WHERE THIS COMES FROM. The trust-anchor rule (SPEC section 4b, `signature.verify_ed25519_pinned`)
reached every surface of the package, and the sweep that holds it walked src/proofbundle only. Gate
iteration 3 on that change (lens A, A3-01..04) found four places under scripts/ that check a signature
under a PINNED key with the bare SPEC section 4a profile: the pre-tag receipt
(`pre_tag_receipt_lib.verify_receipt`, run by the release workflow and by the reader's verifier), the
readiness artefacts of the audit matrix (`audit_candidate_matrix._artifact_signature_ok`), the findings
register (`findings_register._signature_ok`) and the status page's receipt check
(`render_site_data._check_receipt`). Under a low-order key a signature made with no private key
verifies, so a receipt nobody signed was admitted once such a key stood in the anchor. The keys pinned
today pass the rule (`ThePinnedReleaseKeys` in the package's test file); this closes the path, not a
live attack.

WHAT IS PINNED HERE. Per surface, a record signed by nobody under the identity point, with that point
in the trust anchor: the precondition shows the bare profile accepts the signature, the case shows the
surface refuses it and names the reason from `signature.TRUST_ANCHOR_REFUSAL`. Then a sweep over
scripts/ and tools/ with the package's own sweep: every Ed25519 verification there goes through the
rule, except the in-band keys named with their reason.

WHAT THAT SWEEP COULD NOT SEE. It models the spellings of `cryptography`. Gate run 1 on this fix (lens
A, 231-1A-01) found a verification through another library: tools/scitt_ccf_datahash_vector/
reader_matrix.py checks Ed25519 signatures with pycose, and the sentence above was not true of it. So
every library these files import is now classified in a closed table (`THIRD_PARTY`), a new one is red
until it is, and an import of a signature library the sweep does not model counts as a use.
"""
from __future__ import annotations

import base64
import importlib.util
import subprocess
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
for _p in (str(REPO), str(REPO / "src"), str(REPO / "scripts")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from proofbundle.signature import (  # noqa: E402
    TRUST_ANCHOR_REFUSAL,
    ed25519_trust_anchor_weakness,
    verify_ed25519,
)
from tests.test_trust_anchor_keys_refused_on_every_surface import (  # noqa: E402
    I1,
    I2,
    I3,
    UNIV,
    WEAK,
    _sweep_source,
)

#: The three encodings of the identity point: under each, R = identity, S = 0 verifies for every
#: message, so one fixed signature serves every record below without a search.
IDENTITY = (I1, I2, I3)


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _by_path(name: str):
    """A script module loaded from THIS tree's scripts/, never whatever lies first on sys.path."""
    spec = importlib.util.spec_from_file_location(f"_t231_{name}", REPO / "scripts" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class _Precondition:
    def assert_forgery_is_live(self, key: bytes, msg: bytes):
        """Without this, a refusal below could come from a signature that never verified."""
        self.assertIs(verify_ed25519(key, UNIV, msg), True, key.hex())


class PreTagReceipt(unittest.TestCase, _Precondition):
    """A3-01: the receipt the release workflow requires before a tag, and the reader's verifier."""

    def _receipt(self, key: bytes, lib) -> dict:
        r = {"schema": lib.RECEIPT_SCHEMA, "version": "9.9.9", "subject_tree_digest": "a" * 64,
             "gate_source_digest": "b" * 64, "audit_command": "nobody ran this", "audit_exit_code": 0,
             "audit_output_digest": "c" * 64, "runner_identity": "nobody",
             "produced_at": "2026-09-26T00:00:00Z", "signer_pubkey": _b64(key), "signature": _b64(UNIV)}
        self.assert_forgery_is_live(key, lib.canonical_bytes(r))
        return r

    def test_a_receipt_nobody_signed_is_refused_under_a_weak_pinned_key(self):
        lib = _by_path("pre_tag_receipt_lib")
        for key in IDENTITY:
            with self.subTest(key=key.hex()):
                ok, reason = lib.verify_receipt(self._receipt(key, lib), trusted_pubkeys=[_b64(key)],
                                                expected_version="9.9.9",
                                                subject_tree_digest="a" * 64, gate_source_digest="b" * 64)
                self.assertIs(ok, False, reason)
                self.assertIn(TRUST_ANCHOR_REFUSAL[ed25519_trust_anchor_weakness(key)], reason)


class FindingsRegister(unittest.TestCase, _Precondition):
    """A3-03: the register whose count decides C12.2."""

    def test_a_register_nobody_signed_is_refused_under_a_weak_authorised_key(self):
        fr = _by_path("findings_register")
        for key in IDENTITY:
            with self.subTest(key=key.hex()):
                reg = {"schema": "proofbundle.findings_register.v1", "version": "9.9.9", "findings": []}
                self.assert_forgery_is_live(key, fr._canonical_bytes(reg))
                reg["signature"] = {"alg": "ed25519", "public_key_b64": _b64(key), "sig_b64": _b64(UNIV)}
                ok, reason = fr._signature_ok(reg, {_b64(key)})
                self.assertIs(ok, False, reason)
                self.assertIn(TRUST_ANCHOR_REFUSAL[ed25519_trust_anchor_weakness(key)], reason)


class AuditMatrixArtifact(unittest.TestCase, _Precondition):
    """A3-02: a readiness artefact (C6.2, C6.3, C8.2) under a key the committed anchor names."""

    def test_an_artifact_nobody_signed_is_refused_under_a_weak_anchor_key(self):
        m = _by_path("audit_candidate_matrix")
        from proofbundle import canonical
        role = next(iter(m._ANKER_ROLLEN))
        for key in IDENTITY:
            with self.subTest(key=key.hex()):
                body = {"schema": "x", "signer_role": role, "produced_at": "2026-09-26T00:00:00Z"}
                self.assert_forgery_is_live(key, canonical.canonicalize_statement(body))
                art = dict(body, signature={"alg": "ed25519", "public_key_b64": _b64(key),
                                            "sig_b64": _b64(UNIV)})
                trusted = {_b64(key): {"role": role, "not_after": "2099-12-31"}}
                state, reason = m._artifact_signature_ok(art, trusted, "ok")
                self.assertEqual(state, m.ART_UNTRUSTED, reason)
                self.assertIn(TRUST_ANCHOR_REFUSAL[ed25519_trust_anchor_weakness(key)], reason)


class StatusPageReceipt(unittest.TestCase, _Precondition):
    """A3-04: the receipt check that writes `passed` onto the public status page."""

    def _tree_with_anchor(self, tmp: Path, key: bytes) -> Path:
        (tmp / "scripts").mkdir()
        (tmp / "audit_artifacts").mkdir()
        (tmp / "scripts" / "pre_tag_receipt_lib.py").write_bytes(
            (REPO / "scripts" / "pre_tag_receipt_lib.py").read_bytes())
        (tmp / "audit_artifacts" / "pre_tag_trusted_pubkeys.txt").write_text(_b64(key) + "\n",
                                                                             encoding="utf-8")
        for cmd in (["init", "-q"], ["add", "-A"],
                    ["-c", "user.email=t@example.invalid", "-c", "user.name=t", "commit", "-qm", "anchor"]):
            subprocess.run(["git", "-C", str(tmp), *cmd], check=True, capture_output=True)
        return tmp

    def test_a_receipt_nobody_signed_is_not_passed_under_a_weak_pinned_key(self):
        import tempfile
        rsd = _by_path("render_site_data")
        for key in IDENTITY:
            with self.subTest(key=key.hex()), tempfile.TemporaryDirectory() as d:
                rsd.REPO = self._tree_with_anchor(Path(d), key)
                lib = _by_path("pre_tag_receipt_lib")
                r = {"schema": lib.RECEIPT_SCHEMA, "version": "9.9.9", "subject_tree_digest": "a" * 64,
                     "gate_source_digest": "b" * 64, "audit_command": "nobody ran this",
                     "audit_exit_code": 0, "audit_output_digest": "c" * 64, "runner_identity": "nobody",
                     "produced_at": "2026-09-26T00:00:00Z"}
                self.assert_forgery_is_live(key, lib.canonical_bytes(r))
                r.update(signer_pubkey=_b64(key), signature=_b64(UNIV))
                res = rsd._check_receipt(r, expected_version="9.9.9")
                self.assertNotEqual(res["state"], "passed", res)
                self.assertIn(TRUST_ANCHOR_REFUSAL[ed25519_trust_anchor_weakness(key)], res["reason"])


class EveryWeakKeyIsRefusedByName(unittest.TestCase):
    """The four surfaces over every WEAK entry, forged or not: the refusal names the weakness before
    any signature is checked, so no entry reaches the signature arithmetic."""

    def test_the_four_surfaces_name_the_weakness_for_every_weak_key(self):
        lib = _by_path("pre_tag_receipt_lib")
        fr = _by_path("findings_register")
        m = _by_path("audit_candidate_matrix")
        role = next(iter(m._ANKER_ROLLEN))
        for key, weakness in WEAK:
            text = TRUST_ANCHOR_REFUSAL[weakness]
            with self.subTest(key=key.hex()):
                r = {"schema": lib.RECEIPT_SCHEMA, "version": "9.9.9", "subject_tree_digest": "a" * 64,
                     "gate_source_digest": "b" * 64, "audit_command": "x", "audit_exit_code": 0,
                     "audit_output_digest": "c" * 64, "runner_identity": "x",
                     "produced_at": "2026-09-26T00:00:00Z", "signer_pubkey": _b64(key),
                     "signature": _b64(UNIV)}
                ok, reason = lib.verify_receipt(r, trusted_pubkeys=[_b64(key)], expected_version="9.9.9",
                                                subject_tree_digest="a" * 64, gate_source_digest="b" * 64)
                self.assertIs(ok, False)
                self.assertIn(text, reason)
                reg = {"schema": "proofbundle.findings_register.v1",
                       "signature": {"alg": "ed25519", "public_key_b64": _b64(key), "sig_b64": _b64(UNIV)}}
                ok, reason = fr._signature_ok(reg, {_b64(key)})
                self.assertIs(ok, False)
                self.assertIn(text, reason)
                art = {"schema": "x", "signer_role": role, "produced_at": "2026-09-26T00:00:00Z",
                       "signature": {"alg": "ed25519", "public_key_b64": _b64(key), "sig_b64": _b64(UNIV)}}
                state, reason = m._artifact_signature_ok(
                    art, {_b64(key): {"role": role, "not_after": "2099-12-31"}}, "ok")
                self.assertEqual(state, m.ART_UNTRUSTED)
                self.assertIn(text, reason)


# ── the sweep over scripts/ and tools/ ────────────────────────────────────────────────────────────

#: The places under scripts/ and tools/ that check an Ed25519 signature under a key that arrives WITH
#: the thing it signs, with their reason. Everything else goes through `verify_ed25519_pinned`.
IN_BAND_TOOLING = {
    "scripts/sign_readiness_artifact.py": "`assemble` checks the externally made signature against the "
                                           "public key handed in with it, before writing the artefact; "
                                           "the relying check is the audit matrix against the anchor",
    "scripts/pre_tag_receipt.py": "`assemble_receipt` checks the externally made signature against the "
                                  "public key handed in with it, before writing the receipt; the relying "
                                  "check is `pre_tag_receipt_lib.verify_receipt` against the anchor",
    # Until 6.2.0 this entry also covered the self-check of a finished carrier, `_signatur_lage`,
    # which is the one exit behind `pruefe_v2` and the generated views and relies on nothing else;
    # it goes through the rule now (tests/test_a_small_order_key_is_refused_at_every_carrier.py).
    "scripts/gen_findings_register.py": "`assemble` checks the handed-in pair before writing the v1 "
                                        "register; the relying check is findings_register against "
                                        "the anchor, which refuses a weak key",
    "tools/scitt_ccf_datahash_vector/nachrechnen.py": "recomputes a third party's published test vector "
                                                      "under the test key printed in that vector; it "
                                                      "trusts nothing",
    "tools/scitt_ccf_datahash_vector/mint_indefinite.py": "derives a variant of the same third-party "
                                                          "test vector under its printed test key; it "
                                                          "trusts nothing",
    "tools/scitt_ccf_datahash_vector/reader_matrix.py": "checks the same third-party test vector through "
                                                        "pycose, under the test key printed in that "
                                                        "vector, and a control message it signs with the "
                                                        "vector's printed seed; it trusts nothing",
}

#: Every library outside the standard library that a file under scripts/ or tools/ imports, and why it
#: does or does not reach an Ed25519 verification the sweep cannot see. Closed on purpose: a list of
#: signature libraries would be one short at the next one, so a new import is red here until it is
#: classified. SWEPT: `_sweep_source` models its spellings. UNMODELLED: it can verify a signature and the
#: sweep does not model it, so every file that imports it counts as a use below.
THIRD_PARTY = {
    "cryptography": "SWEPT",
    "pycose": "UNMODELLED",
    "cbor2": "a CBOR codec; it verifies no signature",
    "yaml": "a YAML parser; it verifies no signature",
    "opentimestamps": "checks timestamp attestations against block headers; no signature under a key",
    "_pytest": "pytest's internals, for a measurement script; it verifies no signature",
}

_LOCAL_BASES = ("scripts", "tools", "tests", "conformance", "src")


def _tooling_files():
    for base in ("scripts", "tools"):
        for path in sorted((REPO / base).rglob("*.py")):
            rel = path.relative_to(REPO).as_posix()
            if "/target/" in rel or "/.venv/" in rel:
                continue
            yield rel, path


def _import_roots(text: str):
    """(root, line) for every absolute import in `text`, and for `importlib.import_module` or
    `__import__` called with a literal name. What it does not see, as `_sweep_source` says of itself: a
    name built at run time and code run from a string by `exec` or `eval`."""
    import ast
    for node in ast.walk(ast.parse(text)):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name.split(".")[0], node.lineno
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            yield node.module.split(".")[0], node.lineno
        elif (isinstance(node, ast.Call) and node.args and isinstance(node.args[0], ast.Constant)
              and isinstance(node.args[0].value, str)
              and ((isinstance(node.func, ast.Attribute) and node.func.attr == "import_module")
                   or (isinstance(node.func, ast.Name) and node.func.id == "__import__"))
              and not node.args[0].value.startswith(".")):
            yield node.args[0].value.split(".")[0], node.lineno


def _local_roots() -> set:
    """Names a module of this repository answers to: every module and package directory under the
    places these files put on their path, and those places themselves."""
    names = {"proofbundle", *_LOCAL_BASES}
    for base in _LOCAL_BASES:
        for path in (REPO / base).rglob("*"):
            posix = path.as_posix()
            if "/target/" in posix or "/.venv/" in posix or "__pycache__" in posix:
                continue
            if path.suffix == ".py":
                names.add(path.stem)
            elif path.is_dir():
                names.add(path.name)
    return names


def _tooling_uses(rel: str, text: str) -> list:
    return _sweep_source(rel, text) + [(rel, line, f"import of {root}") for root, line in _import_roots(text)
                                       if THIRD_PARTY.get(root) == "UNMODELLED"]


class TheToolingSweep(unittest.TestCase):
    """The package's sweep, walked over scripts/ and tools/ (its own docstring named them outside)."""

    def _uses(self):
        found = []
        for rel, path in _tooling_files():
            found += _tooling_uses(rel, path.read_text(encoding="utf-8"))
        return found

    def test_no_tooling_check_reaches_the_bare_profile_outside_the_named_in_band_keys(self):
        stray = [f"{rel}:{line} {spelling}" for rel, line, spelling in self._uses()
                 if rel not in IN_BAND_TOOLING]
        self.assertEqual(stray, [], "a pinned key reaches the bare SPEC 4a profile; route it through "
                                    "verify_ed25519_pinned or name it in IN_BAND_TOOLING with its reason")

    def test_every_named_in_band_file_is_seen(self):
        """Counter-direction: an exemption for a file the sweep never finds anything in is stale."""
        self.assertEqual({rel for rel, _l, _s in self._uses()}, set(IN_BAND_TOOLING))

    def test_the_four_relied_on_surfaces_are_walked(self):
        walked = {rel for rel, _p in _tooling_files()}
        for rel in ("scripts/pre_tag_receipt_lib.py", "scripts/audit_candidate_matrix.py",
                    "scripts/findings_register.py", "scripts/render_site_data.py"):
            self.assertIn(rel, walked)

    def test_every_library_the_tooling_imports_is_classified(self):
        """Both directions: an import the table does not know, and an entry no file imports any more. A
        module of this repository named like a library would hide that library's import, so none may."""
        local = _local_roots()
        seen = {}
        for rel, path in _tooling_files():
            for root, line in _import_roots(path.read_text(encoding="utf-8")):
                if root in sys.stdlib_module_names or root in local or root == "__future__":
                    continue
                seen.setdefault(root, f"{rel}:{line}")
        self.assertEqual(set(seen), set(THIRD_PARTY), seen)
        self.assertEqual(set(THIRD_PARTY) & local, set(), "a module of this repository shadows a library")

    def test_an_unclassified_library_and_an_unmodelled_import_are_seen(self):
        planted = ("import nacl.signing\nfrom pycose.keys import OKPKey\nimport importlib\n"
                   "importlib.import_module('ed25519')\n__import__('jwcrypto.jwk')\nfrom . import sibling\n")
        self.assertEqual({r for r, _l in _import_roots(planted)},
                         {"nacl", "pycose", "importlib", "ed25519", "jwcrypto"})
        self.assertEqual([s for _r, _l, s in _tooling_uses("planted.py", planted)], ["import of pycose"])


if __name__ == "__main__":
    unittest.main()
