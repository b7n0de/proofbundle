"""The offline signing-package verifier: every state it can reach, and the ones it must refuse.

This tool decides whether a human signs. Its three states are the point: a pass, a finding, and
NOT MEASURABLE -- the last one being the state a careless tool silently turns into the first. Each
case below builds a real package on disk, because a verifier that is only tested against mocks has
never met a file that does not exist.
"""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import pathlib

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = pathlib.Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location("vsp", ROOT / "scripts" / "verify_signing_package.py")
vsp = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(vsp)

SK = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
PUB_B64 = base64.b64encode(SK.public_key().public_bytes_raw()).decode("ascii")
HEAD = "a" * 40


def _canon(obj: dict) -> bytes:
    import rfc8785
    return rfc8785.dumps(obj)


def _package(tmp_path: pathlib.Path, *, binds: bool = True, kind: str = "statement",
             body_extra: dict | None = None) -> pathlib.Path:
    pkg = tmp_path / "pkg"
    pkg.mkdir(parents=True, exist_ok=True)
    body = {"schema": "example/v1", "version": "1.2.3", "produced_at": "2026-09-22T00:00:00Z"}
    if binds:
        body["candidate"] = {"commit": HEAD, "tree_digest": "b" * 64,
                             "sdist_sha256": "c" * 64, "wheel_sha256": "d" * 64}
    body.update(body_extra or {})
    payload = _canon(body)
    (pkg / "art.body.json").write_text(json.dumps(body, indent=2) + "\n", encoding="utf-8")
    (pkg / "art.payload.bin").write_bytes(payload)
    manifest = {
        "anchor": {"public_key_b64": PUB_B64, "role": "release", "not_after": "2027-01-01"},
        "candidate": {"commit": HEAD, "tree_digest": "b" * 64,
                      "sdist_sha256": "c" * 64, "wheel_sha256": "d" * 64},
        "artifacts": [{
            "name": "art", "body": "art.body.json", "payload": "art.payload.bin",
            "body_sha256": hashlib.sha256((pkg / "art.body.json").read_bytes()).hexdigest(),
            "payload_sha256": hashlib.sha256(payload).hexdigest(),
            "target_rel": "audit_artifacts/art.json", "kind": kind, "binds_candidate": binds,
        }],
    }
    (pkg / vsp.DEFAULT_MANIFEST).write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    return pkg


# ── the three states ────────────────────────────────────────────────────────────────────────────

def test_a_consistent_package_passes(tmp_path, capsys):
    pkg = _package(tmp_path)
    assert vsp.before(pkg, anchor_pubkey=PUB_B64, expected_head=HEAD) == 0
    assert "everything checked and consistent" in capsys.readouterr().out


def test_without_a_canonicalizer_the_answer_is_NOT_MEASURABLE(tmp_path, monkeypatch, capsys):
    """The state that matters most: a tool that cannot recompute the derivation must say so and
    exit 2, not shrug and pass. Exit 2 is what a release checklist can branch on."""
    pkg = _package(tmp_path)
    monkeypatch.setattr(vsp, "_canonicalizer", lambda: (None, "simulated: no canonicalizer"))
    rc = vsp.before(pkg, anchor_pubkey=PUB_B64)
    out = capsys.readouterr().out
    assert rc == 2
    assert "NOT MEASURABLE" in out and "not a pass" in out


def test_a_payload_that_does_not_match_its_body_is_refused(tmp_path, capsys):
    pkg = _package(tmp_path)
    p = pkg / "art.payload.bin"
    p.write_bytes(p.read_bytes().replace(b"1.2.3", b"9.9.9"))
    rc = vsp.before(pkg, anchor_pubkey=PUB_B64)
    assert rc == 1
    assert "DIFFERS from the manifest" in capsys.readouterr().out


def test_a_payload_that_matches_its_digest_but_not_the_body_is_refused(tmp_path, capsys):
    """THE CASE THE DIGESTS ALONE DO NOT CATCH. Change the payload AND its manifest digest: every
    digest agrees, and the bytes still say something else than the body a human reads."""
    pkg = _package(tmp_path)
    tampered = _canon({"schema": "example/v1", "version": "9.9.9", "produced_at": "2026-09-22T00:00:00Z"})
    (pkg / "art.payload.bin").write_bytes(tampered)
    m = json.loads((pkg / vsp.DEFAULT_MANIFEST).read_text())
    m["artifacts"][0]["payload_sha256"] = hashlib.sha256(tampered).hexdigest()
    (pkg / vsp.DEFAULT_MANIFEST).write_text(json.dumps(m))
    rc = vsp.before(pkg, anchor_pubkey=PUB_B64)
    out = capsys.readouterr().out
    assert rc == 1
    assert "derivation DIFFERS" in out


# ── what a package must not contain ─────────────────────────────────────────────────────────────

def test_a_body_that_already_carries_a_signature_is_refused(tmp_path, capsys):
    pkg = _package(tmp_path, body_extra={"signature": {"sig_b64": "x"}})
    assert vsp.before(pkg, anchor_pubkey=PUB_B64) == 1
    assert "already carries signature" in capsys.readouterr().out


def test_a_non_binding_artifact_must_not_carry_a_candidate(tmp_path, capsys):
    pkg = _package(tmp_path, binds=False,
                   body_extra={"candidate": {"commit": HEAD}, "version": "1.2.3"})
    rc = vsp.before(pkg, anchor_pubkey=PUB_B64)
    assert rc == 1
    assert "a binding nobody checks" in capsys.readouterr().out


def test_a_non_binding_artifact_without_a_version_binds_nothing(tmp_path, capsys):
    pkg = _package(tmp_path, binds=False)
    body = json.loads((pkg / "art.body.json").read_text())
    del body["version"]
    (pkg / "art.body.json").write_text(json.dumps(body, indent=2) + "\n")
    payload = _canon(body)
    (pkg / "art.payload.bin").write_bytes(payload)
    m = json.loads((pkg / vsp.DEFAULT_MANIFEST).read_text())
    m["artifacts"][0]["body_sha256"] = hashlib.sha256((pkg / "art.body.json").read_bytes()).hexdigest()
    m["artifacts"][0]["payload_sha256"] = hashlib.sha256(payload).hexdigest()
    (pkg / vsp.DEFAULT_MANIFEST).write_text(json.dumps(m))
    assert vsp.before(pkg, anchor_pubkey=PUB_B64) == 1
    assert "binds nothing at all" in capsys.readouterr().out


def test_an_unfinished_package_stops_the_run(tmp_path):
    pkg = _package(tmp_path)
    (pkg / vsp.IN_PROGRESS_MARKER).write_text("step 3 of 5", encoding="utf-8")
    with pytest.raises(SystemExit) as ctx:
        vsp.before(pkg)
    assert "did not finish" in str(ctx.value)


def test_a_damaged_manifest_is_a_finding_not_a_traceback(tmp_path):
    pkg = _package(tmp_path)
    (pkg / vsp.DEFAULT_MANIFEST).write_text("{not json", encoding="utf-8")
    with pytest.raises(SystemExit) as ctx:
        vsp.before(pkg)
    assert "not readable JSON" in str(ctx.value)


# ── the anchor key and the head are only checked when you supply them ───────────────────────────

def test_without_an_anchor_key_the_tool_says_it_compared_nothing(tmp_path, capsys):
    pkg = _package(tmp_path)
    vsp.before(pkg)
    out = capsys.readouterr().out
    assert "NOT checked against an independent source" in out
    assert "only compares the manifest with itself" in out


def test_a_wrong_anchor_key_is_a_finding(tmp_path, capsys):
    pkg = _package(tmp_path)
    other = base64.b64encode(Ed25519PrivateKey.generate().public_key().public_bytes_raw()).decode()
    assert vsp.before(pkg, anchor_pubkey=other) == 1
    assert "DIFFERS from the key you passed" in capsys.readouterr().out


def test_a_head_from_another_candidate_is_a_finding(tmp_path, capsys):
    pkg = _package(tmp_path)
    assert vsp.before(pkg, anchor_pubkey=PUB_B64, expected_head="f" * 40) == 1
    assert "is NOT the expected head" in capsys.readouterr().out


# ── after the signature ─────────────────────────────────────────────────────────────────────────

def _sign(pkg: pathlib.Path) -> pathlib.Path:
    sig = base64.b64encode(SK.sign((pkg / "art.payload.bin").read_bytes())).decode("ascii")
    f = pkg / "art.sig.b64"
    f.write_text(sig + "\n", encoding="utf-8")
    return f


def test_a_real_signature_verifies_and_assembles_a_preview(tmp_path, capsys):
    pkg = _package(tmp_path)
    rc = vsp.after(pkg, "art", _sign(pkg), anchor_pubkey=PUB_B64)
    out = capsys.readouterr().out
    assert rc == 0
    assert "VERIFIES over exactly these bytes" in out
    preview = json.loads((pkg / "art.signed.json").read_text())
    assert preview["signature"]["sig_b64"]
    assert preview["signature"]["public_key_b64"] == PUB_B64


def test_a_signature_over_other_bytes_does_not_verify(tmp_path, capsys):
    pkg = _package(tmp_path)
    f = pkg / "art.sig.b64"
    f.write_text(base64.b64encode(SK.sign(b"something else")).decode("ascii"), encoding="utf-8")
    assert vsp.after(pkg, "art", f, anchor_pubkey=PUB_B64) == 1
    assert "DOES NOT VERIFY" in capsys.readouterr().out


def test_a_receipt_gets_the_receipt_signature_shape(tmp_path, capsys):
    """A receipt carries the signature as a string plus signer_pubkey; the structured block belongs
    to a statement. Writing the wrong shape produces a file the gate rejects, and the rejection
    would read as a bad signature rather than a bad assembly."""
    pkg = _package(tmp_path, kind="receipt")
    vsp.after(pkg, "art", _sign(pkg), anchor_pubkey=PUB_B64)
    preview = json.loads((pkg / "art.signed.json").read_text())
    assert isinstance(preview["signature"], str)
    assert preview["signer_pubkey"] == PUB_B64


def test_an_unknown_artifact_names_the_ones_that_exist(tmp_path):
    pkg = _package(tmp_path)
    with pytest.raises(SystemExit) as ctx:
        vsp.after(pkg, "does-not-exist", pkg / "art.sig.b64")
    assert "['art']" in str(ctx.value)


def test_after_refuses_when_the_manifest_key_is_not_yours(tmp_path, capsys):
    pkg = _package(tmp_path)
    other = base64.b64encode(Ed25519PrivateKey.generate().public_key().public_bytes_raw()).decode()
    assert vsp.after(pkg, "art", _sign(pkg), anchor_pubkey=other) == 1
    assert "not the key you passed" in capsys.readouterr().out.lower()


# ── the nine receipt fields are IMPORTED, not copied ────────────────────────────────────────────

def test_the_receipt_form_comes_from_the_library(tmp_path):
    """The house tool this grew out of kept its own copy of the nine signed field names, and its
    own comments recorded the cost. Importing makes the drift impossible rather than detectable."""
    fn, source = vsp._receipt_payload()
    assert fn is not None, source
    assert "pre_tag_receipt_lib" in source
    import sys as _sys
    _sys.path.insert(0, str(ROOT / "scripts"))
    from pre_tag_receipt_lib import canonical_bytes
    assert fn is canonical_bytes


# ── what a foreign-family review found: "nothing to check" is not "everything is fine" ──────────

def test_a_package_with_no_artifacts_does_not_pass(tmp_path):
    """MEASURED 2026-09-22, and it passed before: an empty artefact list made the loop never run,
    so nothing was found, nothing was unmeasurable, and the tool printed its pass line with exit 0
    over a package it had not looked into. A review from another model family raised the class; the
    hole sat at a different spot than the one it guessed, which is why it was measured first."""
    pkg = tmp_path / "pkg"
    pkg.mkdir()
    (pkg / vsp.DEFAULT_MANIFEST).write_text(json.dumps(
        {"anchor": {"public_key_b64": PUB_B64}, "candidate": {}, "artifacts": []}), encoding="utf-8")
    with pytest.raises(SystemExit) as ctx:
        vsp.before(pkg)
    assert "nothing to check" in str(ctx.value)


def test_after_says_out_loud_when_it_only_checked_the_packages_own_key(tmp_path, capsys):
    """Self-attestation, named. The `before` path already said it; saying it in one place and not
    the other is how a reader learns to trust the quiet one."""
    pkg = _package(tmp_path)
    vsp.after(pkg, "art", _sign(pkg))
    out = capsys.readouterr().out
    assert "NOT checked against an independent source" in out
    assert "the key THE PACKAGE NAMES" in out


def test_a_missing_body_is_a_finding_AND_not_measurable(tmp_path, capsys):
    """The neighbouring case to the empty list: a file that is gone must not be skipped quietly.
    It is both -- a finding about the package and an unmeasurable derivation -- and the verdict
    must be the strict one of the two."""
    pkg = _package(tmp_path)
    (pkg / "art.body.json").unlink()
    rc = vsp.before(pkg, anchor_pubkey=PUB_B64)
    out = capsys.readouterr().out
    assert rc == 1
    assert "MISSING" in out and "NOT MEASURABLE" in out
