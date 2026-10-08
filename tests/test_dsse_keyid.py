"""Z239 F3: every DSSE envelope this package signs names its key by the keyid foreign tools look up.

The in-toto envelope layer says a keyid SHOULD be included for each signing key (in-toto/attestation
v1.2.0, spec/v1/envelope.md). Measured on claude/intoto-external at 13d8faa (Z225, finding F3): the
export wrote none, so securesystemslib 1.5.1 raised ``KeyError: 'keyid'`` in ``Envelope.from_dict`` and
GUAC 1.1.0 stopped at "failed to find key from key providers" before it read the statement.

The form written is OpenSSH's SHA256 fingerprint of the Ed25519 key (RFC 8709 section 4 wire form), the
keyid go-securesystemslib's ``dsse.SHA256KeyID`` derives and sigstore's key providers compare. The finding
is a class, not one call site: ``dsse.sign_envelope`` is the one signer of every DSSE producer here, so the
default lives there, and the three in-toto exports and both CLI commands are held to it.

Oracles:
- FOREIGN, recorded: go-securesystemslib ``dsse.SHA256KeyID`` gave the Z225 test key the keyid below
  (tools/intoto_external/results/results.json, ``cross_checks.keyid``, at 13d8faa).
- FOREIGN, live: the ``cryptography`` library's OpenSSH public-key encoding, hashed here.

A keyid is an unauthenticated hint that selects no key: among well-formed envelopes no verdict of this
package changes with its value, held below. It is JSON text like any other field, so a lone surrogate in
it makes the envelope malformed, and that boundary is held below too.
"""
from __future__ import annotations

import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from proofbundle import dsse, intoto
from proofbundle._wire_b64 import decode_b64_either
from proofbundle.cli import main
from proofbundle.evalclaim import build_eval_claim, emit_eval_receipt, issuer_fingerprint

REPO = Path(__file__).resolve().parents[1]
RUST = [REPO / "tools" / "pb_verify_rs" / "target" / build / "pb_verify_rs" for build in ("release", "debug")]

#: The Z225 test key and the keyid go-securesystemslib derived for it (recorded, see the docstring).
#: SHA-256 of the label below, written out, so the seed is visibly a throwaway literal
#: (tests/test_sdist_ohne_signierwerkzeug.py); TheKeyidForm holds it to the label.
Z225_KEY_LABEL = b"proofbundle Z225 foreign-tool measurement test key, trusts nothing"
Z225_SEED = b"Y\xdd\xe0\x94NM\x84\x12\xf1D\xbc<n\x1c\x18\xa6yZ\xae@)\xe8\x84\xbb\x873u\xf9\xb7\x1fA2"
Z225_KEYID_GO_SECURESYSTEMSLIB = "SHA256:wjwlWYX6X7KTNYJHUEGfZLwSCudesRmpA6ELAIZHj2k"


def _signer() -> Ed25519PrivateKey:
    """The Z225 test key."""
    return Ed25519PrivateKey.from_private_bytes(Z225_SEED)


def _raw_pub(signer: Ed25519PrivateKey) -> bytes:
    return signer.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _fingerprint_by_cryptography(signer: Ed25519PrivateKey) -> str:
    """The foreign computation: cryptography's OpenSSH line `ssh-ed25519 <base64 wire blob>`."""
    line = signer.public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).decode("ascii")
    kind, blob_b64 = line.split(" ")[:2]
    assert kind == "ssh-ed25519"
    digest = hashlib.sha256(decode_b64_either(blob_b64)).digest()
    import base64  # noqa: PLC0415 - encoding only, the strict decoder above is the repository's
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


def _claim(signer):
    claim, _salts = build_eval_claim(
        suite="safety-refusals", suite_version="1.2.0", metric="refusal_rate",
        comparator=">=", threshold="0.98", score="0.994", n=500,
        model_id="acme/model", dataset_id="acme/set",
        issuer=issuer_fingerprint(signer), timestamp="2026-09-27T00:00:00Z",
        model_salt=b"\x11" * 16, dataset_salt=b"\x22" * 16)
    return claim


def _keyids(envelope: dict) -> list:
    return [entry.get("keyid") for entry in envelope["signatures"]]


class TheKeyidForm(unittest.TestCase):
    def test_the_written_out_seed_is_the_z225_seed(self):
        self.assertEqual(Z225_SEED, hashlib.sha256(Z225_KEY_LABEL).digest())

    def test_the_z225_key_gets_the_keyid_go_securesystemslib_derived(self):
        self.assertEqual(dsse.openssh_sha256_keyid(_raw_pub(_signer())), Z225_KEYID_GO_SECURESYSTEMSLIB)

    def test_the_form_equals_the_openssh_encoding_of_cryptography_for_other_keys(self):
        for _ in range(8):
            signer = Ed25519PrivateKey.generate()
            self.assertEqual(dsse.openssh_sha256_keyid(_raw_pub(signer)), _fingerprint_by_cryptography(signer))

    def test_a_key_that_is_not_32_bytes_is_refused(self):
        for raw in (b"", b"\x00" * 31, b"\x00" * 33):
            with self.assertRaises(ValueError):
                dsse.openssh_sha256_keyid(raw)


class EveryEnvelopeCarriesIt(unittest.TestCase):
    def test_sign_envelope_writes_the_keyid_by_default(self):
        env = dsse.sign_envelope(b"{}", _signer(), payload_type="application/vnd.in-toto+json")
        self.assertEqual(_keyids(env), [Z225_KEYID_GO_SECURESYSTEMSLIB])

    def test_an_explicit_keyid_is_kept_and_an_empty_one_writes_none(self):
        env = dsse.sign_envelope(b"{}", _signer(), payload_type="t", keyid="mine")
        self.assertEqual(_keyids(env), ["mine"])
        env = dsse.sign_envelope(b"{}", _signer(), payload_type="t", keyid="")
        self.assertEqual(env["signatures"], [{"sig": env["signatures"][0]["sig"]}])

    def test_the_three_in_toto_exports_carry_it(self):
        signer = _signer()
        claim = _claim(signer)
        envelopes = {
            "test-result": intoto.export_intoto_dsse(claim, signer, root_b64="cm9vdA=="),
            "eval-result receipt": intoto.export_eval_result_dsse(claim, signer, root_b64="cm9vdA=="),
            "eval-result public-model": intoto.export_eval_result_dsse(
                claim, signer, subject_profile="public-model", subject_name="m", subject_sha256="a" * 64),
            "eval-result release-gate": intoto.export_eval_result_dsse(
                claim, signer, subject_profile="release-gate", subject_name="i", subject_sha256="b" * 64),
            "svr": intoto.export_svr_dsse(emit_eval_receipt(claim, signer), signer,
                                          time_created="2026-09-27T00:00:00Z"),
        }
        for name, env in envelopes.items():
            self.assertEqual(_keyids(env), [Z225_KEYID_GO_SECURESYSTEMSLIB], name)

    def test_the_intoto_and_svr_commands_write_it(self):
        signer = _signer()
        with tempfile.TemporaryDirectory() as tmp:
            d = Path(tmp)
            (d / "seed").write_bytes(Z225_SEED)
            (d / "receipt.json").write_text(json.dumps(emit_eval_receipt(_claim(signer), signer)), encoding="utf-8")
            self.assertEqual(main(["intoto", str(d / "receipt.json"), "--key", str(d / "seed"),
                                   "--out", str(d / "intoto.json")]), 0)
            self.assertEqual(main(["svr", str(d / "receipt.json"), "--key", str(d / "seed"),
                                   "--out", str(d / "svr.json")]), 0)
            for name in ("intoto.json", "svr.json"):
                env = json.loads((d / name).read_text(encoding="utf-8"))
                self.assertEqual(_keyids(env), [Z225_KEYID_GO_SECURESYSTEMSLIB], name)


class TheVerdictIgnoresIt(unittest.TestCase):
    """A keyid is not signed. Among well-formed envelopes, removing, changing or forging it never changes a
    verdict; a keyid that is not well-formed text makes the envelope malformed (Codex thread 4217984354 on
    pull request 287: the earlier text said no verdict depends on it at all)."""

    def test_eval_result_verdict_is_the_same_with_any_keyid(self):
        signer = _signer()
        env = intoto.export_eval_result_dsse(_claim(signer), signer, root_b64="cm9vdA==")
        pub = _raw_pub(signer)
        wrong_sig = dict(env, signatures=[dict(env["signatures"][0], sig="A" * 86 + "==")])
        for keyid in (Z225_KEYID_GO_SECURESYSTEMSLIB, "SHA256:" + "A" * 43, "", None):
            for base, want in ((env, True), (wrong_sig, False)):
                entry = {k: v for k, v in base["signatures"][0].items() if k != "keyid"}
                if keyid is not None:
                    entry = {"keyid": keyid, **entry}
                variant = dict(base, signatures=[entry])
                self.assertIs(intoto.verify_eval_result_dsse(variant, pub)["ok"], want, (keyid, want))
                self.assertIs(dsse.verify_envelope(variant, pub, payload_type=variant["payloadType"]), want)

    def test_a_keyid_that_is_not_well_formed_text_makes_the_envelope_malformed(self):
        """The boundary of the sentence above, measured: the same good envelope with a lone surrogate as its
        keyid is refused by the structural check every field passes, not by any reading of the keyid."""
        from proofbundle.errors import ProofBundleError
        signer = _signer()
        env = intoto.export_eval_result_dsse(_claim(signer), signer, root_b64="cm9vdA==")
        pub = _raw_pub(signer)
        kaputt = dict(env, signatures=[dict(env["signatures"][0], keyid="\ud800")])
        self.assertIs(intoto.verify_eval_result_dsse(kaputt, pub)["ok"], False)
        with self.assertRaises(ProofBundleError):
            dsse.verify_envelope(kaputt, pub, payload_type=kaputt["payloadType"])
        self.assertIs(intoto.verify_eval_result_dsse(env, pub)["ok"], True, "control: the same envelope as written")


class TheShippedCorpusNamesItsKeys(unittest.TestCase):
    """Codex thread 4217984342 on pull request 287: the agent-review vectors were regenerated, and 117 envelopes
    under conformance/relation, shipped in the sdist by `graft conformance`, still had no keyid. Every DSSE
    envelope under conformance/ names a keyid in the form this package writes, and where a key the case
    records verifies the signature, the keyid is that key's fingerprint."""

    def test_every_envelope_under_conformance_names_its_key(self):
        import base64  # noqa: PLC0415 - decoding the recorded keys of a case
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        def huellen(x):
            if isinstance(x, dict):
                if "payloadType" in x and isinstance(x.get("signatures"), list):
                    yield x
                for v in x.values():
                    yield from huellen(v)
            elif isinstance(x, list):
                for v in x:
                    yield from huellen(v)
        gezaehlt = 0
        for pfad in sorted((REPO / "conformance").rglob("*.json")):
            try:
                inhalt = json.loads(pfad.read_text(encoding="utf-8"))
            except ValueError:
                continue
            schluessel = set()
            for q in pfad.parent.glob("*.b64"):
                try:
                    schluessel.add(base64.b64decode(q.read_text(encoding="utf-8").strip()))
                except ValueError:
                    pass
            fall = pfad.parent / "case.json"
            if fall.is_file():
                schluessel |= {base64.b64decode(k) for k in json.loads(fall.read_text(encoding="utf-8")).get(
                    "relatedPubs", []) if isinstance(k, str)}
            for h in huellen(inhalt):
                for eintrag in h["signatures"]:
                    gezaehlt += 1
                    with self.subTest(file=str(pfad.relative_to(REPO))):
                        keyid = eintrag.get("keyid")
                        self.assertRegex(keyid or "", r"\ASHA256:[A-Za-z0-9+/]{43}\Z")
                        pae = dsse.pae(h["payloadType"], base64.b64decode(h["payload"]))
                        for k in (k for k in schluessel if len(k) == 32):
                            try:
                                Ed25519PublicKey.from_public_bytes(k).verify(base64.b64decode(eintrag["sig"]), pae)
                            except InvalidSignature:
                                continue
                            self.assertEqual(keyid, dsse.openssh_sha256_keyid(k))
        self.assertGreaterEqual(gezaehlt, 129, "the corpus holds 117 relation and 12 agent-review signatures")

    #: The shipped envelopes signed before the default keyid, kept with the bytes they were signed with.
    _ARCHIV = ("receipts/agent_review/", "tests/fixtures/kette_147/receipt.json")

    def test_every_shipped_envelope_without_a_keyid_is_a_named_archive(self):
        """Codex thread 4218670842 on pull request 287: the headline said every DSSE envelope names its key, and the
        sdist ships the archived agent-review receipts, which do not. Every envelope without a keyid in the trees the
        sdist ships lies in a named archive, and the changelog names both and scopes its headline to what this
        package signs."""
        def huellen(x):
            if isinstance(x, dict):
                if "payloadType" in x and isinstance(x.get("signatures"), list):
                    yield x
                for v in x.values():
                    yield from huellen(v)
            elif isinstance(x, list):
                for v in x:
                    yield from huellen(v)
        ohne = []
        for wurzel in ("conformance", "examples", "receipts", "tests/fixtures", "schemas"):
            for pfad in sorted((REPO / wurzel).rglob("*.json")):
                try:
                    inhalt = json.loads(pfad.read_text(encoding="utf-8"))
                except (ValueError, UnicodeDecodeError):
                    continue
                if any("keyid" not in e for h in huellen(inhalt) for e in h["signatures"] if isinstance(e, dict)):
                    ohne.append(pfad.relative_to(REPO).as_posix())
        self.assertTrue(ohne, "control: the archived receipts are found by this walk")
        self.assertEqual([p for p in ohne if not p.startswith(self._ARCHIV)], [])
        text = " ".join((REPO / "CHANGELOG.md").read_text(encoding="utf-8").split())
        eintrag = text[text.index("names its signing key") - 80:text.index("cosign's image-digest match")]
        self.assertIn("Every DSSE envelope this package signs names its signing key", eintrag)
        for archiv in self._ARCHIV:
            self.assertIn(archiv.rstrip("/"), eintrag)


@unittest.skipUnless(any(b.exists() for b in RUST), "pb_verify_rs is not built")
class BothVerifiersIgnoreIt(unittest.TestCase):
    """AGENTS.md: Python and the Rust verifier agree on the same bytes. The same envelope, with its
    keyid as written, removed and forged, and with a good and a broken signature, gets one verdict from
    `dsse.verify_envelope` and from `pb_verify_rs verify-dsse`."""

    def test_python_and_rust_give_the_same_verdict_whatever_the_keyid(self):
        import base64  # noqa: PLC0415 - encoding the public key for the command line only
        binary = next(b for b in RUST if b.exists())
        signer = _signer()
        pub = _raw_pub(signer)
        env = dsse.sign_envelope(b'{"a":1}', signer, payload_type="application/vnd.in-toto+json")
        broken = dict(env, signatures=[dict(env["signatures"][0], sig="A" * 86 + "==")])
        with tempfile.TemporaryDirectory() as tmp:
            for keyid in ("as written", None, "SHA256:" + "B" * 43):
                for base, want in ((env, True), (broken, False)):
                    entry = dict(base["signatures"][0])
                    if keyid is None:
                        entry.pop("keyid")
                    elif keyid != "as written":
                        entry["keyid"] = keyid
                    variant = dict(base, signatures=[entry])
                    path = Path(tmp) / "env.json"
                    path.write_text(json.dumps(variant), encoding="utf-8")
                    py = dsse.verify_envelope(variant, pub, payload_type=variant["payloadType"])
                    rs = subprocess.run([str(binary), "verify-dsse", str(path),
                                         base64.b64encode(pub).decode("ascii")],
                                        capture_output=True, text=True, timeout=60).returncode
                    self.assertEqual((py, rs == 0), (want, want), (keyid, want, rs))


if __name__ == "__main__":
    unittest.main()
