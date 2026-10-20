"""Three findings of the first Codex review of pull request 369, each held as a case that fails on the
first version of the verifier and passes on the fix.

1. A candidate binding with no fields compared nothing. `all(...)` ran over the fields the MANIFEST
   happened to name, so an empty `candidate` block, or one with a field left out, bound nothing and
   `before` still printed "candidate matches the package head" with exit 0.
2. `after` checked the signature over whatever payload lay in the package. A payload replaced after
   `before`, and signed in its new form, verified; so did a body changed after the signature, which
   then went into the preview. The integrity `before` established did not hold across the act.
3. The manifest named the files it lists, and nothing kept those names inside the package. An
   absolute path or `..` let `after` read a JSON file from anywhere on the signing machine into the
   preview, and an artefact name with `..` wrote the preview outside the package.

Each case builds a real package on disk, as the sibling file does.
"""
from __future__ import annotations

import base64
import hashlib
import json
import pathlib

import pytest

from tests.test_verify_signing_package import HEAD, PUB_B64, SK, _canon, _package, _reviewed, _sign, vsp

FIELDS = ("commit", "tree_digest", "sdist_sha256", "wheel_sha256")


def _rewrite(pkg: pathlib.Path, body: dict) -> None:
    """Write a new body and its payload, and keep the manifest digests consistent with both, so a
    case fails only for the property it is about."""
    (pkg / "art.body.json").write_text(json.dumps(body, indent=2) + "\n", encoding="utf-8")
    payload = _canon(body)
    (pkg / "art.payload.bin").write_bytes(payload)
    m = json.loads((pkg / vsp.DEFAULT_MANIFEST).read_text())
    m["artifacts"][0]["body_sha256"] = hashlib.sha256((pkg / "art.body.json").read_bytes()).hexdigest()
    m["artifacts"][0]["payload_sha256"] = hashlib.sha256(payload).hexdigest()
    (pkg / vsp.DEFAULT_MANIFEST).write_text(json.dumps(m), encoding="utf-8")


def _set_manifest(pkg: pathlib.Path, change) -> None:
    m = json.loads((pkg / vsp.DEFAULT_MANIFEST).read_text())
    change(m)
    (pkg / vsp.DEFAULT_MANIFEST).write_text(json.dumps(m), encoding="utf-8")


# ── 1. a binding has to name every field it promises ────────────────────────────────────────────

def test_an_empty_candidate_binds_nothing_and_is_a_finding(tmp_path, capsys):
    pkg = _package(tmp_path)
    body = json.loads((pkg / "art.body.json").read_text())
    del body["candidate"]
    _rewrite(pkg, body)
    _set_manifest(pkg, lambda m: m.__setitem__("candidate", {}))
    rc = vsp.before(pkg, anchor_pubkey=PUB_B64)
    out = capsys.readouterr().out
    assert rc == 1
    assert "candidate matches the package head" not in out


@pytest.mark.parametrize("field", FIELDS)
def test_a_candidate_field_left_out_on_both_sides_is_a_finding(tmp_path, capsys, field):
    pkg = _package(tmp_path)
    body = json.loads((pkg / "art.body.json").read_text())
    del body["candidate"][field]
    _rewrite(pkg, body)
    _set_manifest(pkg, lambda m: m["candidate"].pop(field))
    rc = vsp.before(pkg, anchor_pubkey=PUB_B64, expected_head=HEAD if field != "commit" else None)
    out = capsys.readouterr().out
    assert rc == 1, field
    assert field in out, field


def test_a_complete_binding_still_passes(tmp_path, capsys):
    """Counter-direction: a rule that refused every binding would pass the cases above."""
    pkg = _package(tmp_path)
    assert vsp.before(pkg, anchor_pubkey=PUB_B64, expected_head=HEAD) == 0
    assert "candidate matches the package head" in capsys.readouterr().out


# ── 2. after re-checks the bytes it is asked about ──────────────────────────────────────────────

def test_a_payload_replaced_and_signed_after_before_is_refused(tmp_path, capsys):
    pkg = _package(tmp_path)
    assert vsp.before(pkg, anchor_pubkey=PUB_B64, expected_head=HEAD) == 0
    capsys.readouterr()
    other = _canon({"schema": "example/v1", "version": "9.9.9", "produced_at": "2026-09-22T00:00:00Z"})
    (pkg / "art.payload.bin").write_bytes(other)
    rc = vsp.after(pkg, "art", _sign(pkg), anchor_pubkey=PUB_B64)
    out = capsys.readouterr().out
    assert rc == 1
    assert not (pkg / "art.signed.json").exists()
    assert "payload" in out and "DIFFERS" in out


def test_a_body_changed_after_the_signature_does_not_reach_the_preview(tmp_path, capsys):
    pkg = _package(tmp_path)
    sig = _sign(pkg)
    body = json.loads((pkg / "art.body.json").read_text())
    body["version"] = "9.9.9"
    (pkg / "art.body.json").write_text(json.dumps(body, indent=2) + "\n", encoding="utf-8")
    rc = vsp.after(pkg, "art", sig, anchor_pubkey=PUB_B64)
    out = capsys.readouterr().out
    assert rc == 1
    assert not (pkg / "art.signed.json").exists()
    assert "body" in out and "DIFFERS" in out


def test_after_without_a_canonicalizer_is_NOT_MEASURABLE(tmp_path, monkeypatch, capsys):
    """The derivation is part of what after now checks, so without the tool for it the answer is the
    third state, and no preview is written."""
    pkg = _package(tmp_path)
    sig = _sign(pkg)
    monkeypatch.setattr(vsp, "_canonicalizer", lambda: (None, "simulated: no canonicalizer"))
    rc = vsp.after(pkg, "art", sig, anchor_pubkey=PUB_B64)
    out = capsys.readouterr().out
    assert rc == 2
    assert "NOT MEASURABLE" in out
    assert not (pkg / "art.signed.json").exists()


@pytest.mark.parametrize("phase", ["before", "after"])
def test_a_receipt_body_without_its_signed_fields_is_a_finding_not_a_traceback(tmp_path, capsys, phase):
    """The neighbour the derivation in `after` exposed: a body marked as a receipt that lacks the
    signed fields cannot be put into the receipt form, and `canonical_bytes` raises. That is a finding
    about the package, in both phases, and no preview is written."""
    pkg = _package(tmp_path, kind="receipt")
    body = json.loads((pkg / "art.body.json").read_text())
    del body["audit_output_digest"]
    (pkg / "art.body.json").write_text(json.dumps(body, indent=2) + "\n", encoding="utf-8")
    _set_manifest(pkg, lambda m: m["artifacts"][0].__setitem__(
        "body_sha256", hashlib.sha256((pkg / "art.body.json").read_bytes()).hexdigest()))
    if phase == "before":
        rc = vsp.before(pkg, anchor_pubkey=PUB_B64)
    else:
        rc = vsp.after(pkg, "art", _sign(pkg), anchor_pubkey=PUB_B64)
    out = capsys.readouterr().out
    assert rc == 1
    assert "audit_output_digest" in out
    assert not (pkg / "art.signed.json").exists()


def test_an_untouched_package_still_verifies_after(tmp_path, capsys):
    pkg = _package(tmp_path)
    assert vsp.after(pkg, "art", _sign(pkg), anchor_pubkey=PUB_B64, reviewed_manifest_sha256=_reviewed(pkg)) == 0
    assert (pkg / "art.signed.json").is_file()


# ── 3. every path the manifest names stays inside the package ───────────────────────────────────

def _outside_json(tmp_path: pathlib.Path) -> pathlib.Path:
    secret = tmp_path / "outside" / "not_in_the_package.json"
    secret.parent.mkdir(parents=True, exist_ok=True)
    secret.write_text(json.dumps({"from": "outside the package"}), encoding="utf-8")
    return secret


@pytest.mark.parametrize("form", ["dotdot", "absolute"])
@pytest.mark.parametrize("role", ["body", "payload"])
def test_a_file_outside_the_package_is_refused(tmp_path, capsys, role, form):
    pkg = _package(tmp_path)
    outside = _outside_json(tmp_path)
    name = "../outside/not_in_the_package.json" if form == "dotdot" else str(outside)
    sig = _sign(pkg)
    _set_manifest(pkg, lambda m: m["artifacts"][0].__setitem__(role, name))
    for run in (lambda: vsp.before(pkg, anchor_pubkey=PUB_B64),
                lambda: vsp.after(pkg, "art", sig, anchor_pubkey=PUB_B64)):
        with pytest.raises(SystemExit) as ctx:
            run()
        assert "outside the package" in str(ctx.value), (role, form)
    assert not (pkg / "art.signed.json").exists()


@pytest.mark.parametrize("form", ["../escaped", "sub/../../escaped", "ABSOLUTE", ".."])
def test_an_artifact_name_cannot_place_the_preview_outside(tmp_path, capsys, form):
    # The absolute form points into tmp_path as well: on the first version of the verifier this case
    # WROTE its preview there, and a case that writes outside its own directory when it fails is a
    # second defect of its own (measured 2026-10-20 with /tmp/escaped).
    name = str(tmp_path / "escaped") if form == "ABSOLUTE" else form
    pkg = _package(tmp_path)
    sig = _sign(pkg)
    _set_manifest(pkg, lambda m: m["artifacts"][0].__setitem__("name", name))
    with pytest.raises(SystemExit) as ctx:
        vsp.after(pkg, name, sig, anchor_pubkey=PUB_B64)
    assert "artefact name" in str(ctx.value)
    assert not list(tmp_path.glob("**/escaped.signed.json"))
    assert not (tmp_path / "escaped.signed.json").exists()


def test_a_symlink_out_of_the_package_is_refused(tmp_path, capsys):
    """A name can stay inside the directory and still point out of it."""
    pkg = _package(tmp_path)
    outside = _outside_json(tmp_path)
    (pkg / "link.json").symlink_to(outside)
    _set_manifest(pkg, lambda m: m["artifacts"][0].__setitem__("body", "link.json"))
    with pytest.raises(SystemExit) as ctx:
        vsp.before(pkg, anchor_pubkey=PUB_B64)
    assert "outside the package" in str(ctx.value)


def test_a_file_in_a_subdirectory_of_the_package_is_allowed(tmp_path, capsys):
    """Counter-direction for the containment rule: inside is inside, at any depth."""
    pkg = _package(tmp_path)
    sub = pkg / "files"
    sub.mkdir()
    for f in ("art.body.json", "art.payload.bin"):
        (pkg / f).rename(sub / f)
    _set_manifest(pkg, lambda m: m["artifacts"][0].update(body="files/art.body.json",
                                                          payload="files/art.payload.bin"))
    assert vsp.before(pkg, anchor_pubkey=PUB_B64, expected_head=HEAD) == 0
    capsys.readouterr()
    sig = pkg / "art.sig.b64"
    sig.write_text(base64.b64encode(SK.sign((sub / "art.payload.bin").read_bytes())).decode("ascii"),
                   encoding="utf-8")
    assert vsp.after(pkg, "art", sig, anchor_pubkey=PUB_B64, reviewed_manifest_sha256=_reviewed(pkg)) == 0
