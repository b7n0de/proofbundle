"""The third Codex review of pull request 369, each finding held as a case that fails on the verifier of
7c113d05 and passes on the fix.

1. P1: a receipt is signed in its compact nine-field form, which carries no `candidate`. `before`
   reported the candidate as bound and `after` put it into the preview beside a valid signature, so a
   recipient could rewrite the candidate without touching the signature. Every field of a body now has
   to be covered by the signed form of its kind, and a receipt binds no candidate.
2. P2: the candidate fields were compared as truth values, so `tree_digest: "x"`, a number or a list,
   copied into the body, printed a match. A commit is a 40 or 64 digit object id, a digest 64 hex digits;
   the same class stood at `binds_candidate` and, from round two, at `kind`.
3. P2: the digest `after` is bound to says which manifest `before` read, not that `before` accepted it.
   A body whose candidate differed made `before` exit 1 and still print the digest, and `after` then
   assembled it. `after` now runs every check `before` runs on the artefact it assembles.
4. P2: a preview path could name an input of the package, so a successful `after` overwrote the body it
   had just checked. Such a manifest is refused, and a preview is never written through a link.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import re

import pytest

from tests.test_verify_signing_package import HEAD, PUB_B64, _canon, _package, _reviewed, _sign, vsp


def _digest(p: pathlib.Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def _set_manifest(pkg: pathlib.Path, change) -> None:
    m = json.loads((pkg / vsp.DEFAULT_MANIFEST).read_text())
    change(m)
    (pkg / vsp.DEFAULT_MANIFEST).write_text(json.dumps(m), encoding="utf-8")


def _rewrite_body(pkg: pathlib.Path, body: dict, kind: str = "statement") -> None:
    """A new body, its payload in the form of `kind`, and both manifest digests, so a case fails only for
    the property it is about."""
    (pkg / "art.body.json").write_text(json.dumps(body, indent=2) + "\n", encoding="utf-8")
    payload = vsp._receipt_payload()[0](body) if kind == "receipt" else _canon(body)
    (pkg / "art.payload.bin").write_bytes(payload)
    _set_manifest(pkg, lambda m: m["artifacts"][0].update(
        body_sha256=_digest(pkg / "art.body.json"), payload_sha256=hashlib.sha256(payload).hexdigest()))


def _both_phases(pkg: pathlib.Path) -> "tuple[int, int, str]":
    import contextlib
    import io
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        rb = vsp.before(pkg, anchor_pubkey=PUB_B64, expected_head=HEAD)
        ra = vsp.after(pkg, "art", _sign(pkg), anchor_pubkey=PUB_B64, reviewed_manifest_sha256=_reviewed(pkg))
    return rb, ra, buf.getvalue()


# ── 1. every field of a body is one the signature covers ────────────────────────────────────────────────

def test_a_receipt_that_claims_a_candidate_binds_none(tmp_path):
    pkg = _package(tmp_path, kind="receipt")
    # PRECONDITION, Codex's measurement: the candidate does not reach the signed bytes of a receipt.
    body = json.loads((pkg / "art.body.json").read_text())
    other = dict(body, candidate=dict(body["candidate"], tree_digest="1" * 64))
    assert vsp._receipt_payload()[0](body) == vsp._receipt_payload()[0](other)
    rb, ra, out = _both_phases(pkg)
    assert (rb, ra) == (1, 1), out[-600:]
    assert "a receipt's signed form carries no `candidate`" in out
    assert not (pkg / "art.signed.json").exists()


@pytest.mark.parametrize("extra", ['"note": "added after the review"', '"note": NaN'])
def test_a_receipt_field_outside_its_signed_form_is_a_finding(tmp_path, extra):
    """The class of the P1 beyond the candidate: any field the nine do not carry, NaN included, which the
    strict reader takes and the reading of round two found in a preview."""
    pkg = _package(tmp_path, kind="receipt", binds=False)
    text = (pkg / "art.body.json").read_text().rstrip().rstrip("}") + ", " + extra + "}\n"
    (pkg / "art.body.json").write_text(text, encoding="utf-8")
    _set_manifest(pkg, lambda m: m["artifacts"][0].update(body_sha256=_digest(pkg / "art.body.json")))
    rb, ra, out = _both_phases(pkg)
    assert (rb, ra) == (1, 1), out[-600:]
    assert "fields the signature does not cover: note" in out
    assert not (pkg / "art.signed.json").exists()


def test_a_receipt_without_a_candidate_passes_both_phases(tmp_path):
    """Counter-direction: a rule that refused every receipt would pass the two cases above."""
    pkg = _package(tmp_path, kind="receipt", binds=False)
    rb, ra, out = _both_phases(pkg)
    assert (rb, ra) == (0, 0), out[-600:]
    assert isinstance(json.loads((pkg / "art.signed.json").read_text())["signature"], str)


def test_a_statement_binds_its_candidate_because_it_signs_it(tmp_path):
    """Counter-direction for the statement: its signed form is the whole body, the candidate included."""
    pkg = _package(tmp_path)
    covered = json.loads((pkg / "art.payload.bin").read_bytes())
    assert "candidate" in covered
    rb, ra, out = _both_phases(pkg)
    assert (rb, ra) == (0, 0), out[-600:]
    assert "candidate matches the package head" in out


# ── 2. a discriminator and a candidate field are checked by their form ─────────────────────────────────

@pytest.mark.parametrize("field,value", [("commit", "x"), ("commit", HEAD.upper()), ("tree_digest", "x"),
                                         ("sdist_sha256", 5), ("wheel_sha256", ["d" * 64])])
def test_a_candidate_field_that_names_no_object_stops_the_run(tmp_path, field, value):
    pkg = _package(tmp_path)
    body = json.loads((pkg / "art.body.json").read_text())
    body["candidate"][field] = value
    _rewrite_body(pkg, body)
    _set_manifest(pkg, lambda m: m["candidate"].__setitem__(field, value))
    for run in (lambda: vsp.before(pkg, anchor_pubkey=PUB_B64, expected_head=HEAD),
                lambda: vsp.after(pkg, "art", _sign(pkg), anchor_pubkey=PUB_B64)):
        with pytest.raises(SystemExit) as ctx:
            run()
        assert f"candidate.{field}" in str(ctx.value), (field, value)


def test_a_commit_of_a_sha256_repository_is_a_commit(tmp_path, capsys):
    """Counter-direction: a 64 digit object id names a commit in a sha256 repository."""
    pkg = _package(tmp_path)
    body = json.loads((pkg / "art.body.json").read_text())
    body["candidate"]["commit"] = "e" * 64
    _rewrite_body(pkg, body)
    _set_manifest(pkg, lambda m: m["candidate"].__setitem__("commit", "e" * 64))
    assert vsp.before(pkg, anchor_pubkey=PUB_B64, expected_head="e" * 64) == 0


@pytest.mark.parametrize("key,value", [("kind", "recepit"), ("kind", None), ("binds_candidate", "no"),
                                       ("binds_candidate", 1)])
def test_a_discriminator_outside_its_values_stops_the_run(tmp_path, key, value):
    pkg = _package(tmp_path)
    _set_manifest(pkg, lambda m: m["artifacts"][0].__setitem__(key, value))
    for run in (lambda: vsp.before(pkg, anchor_pubkey=PUB_B64),
                lambda: vsp.after(pkg, "art", _sign(pkg), anchor_pubkey=PUB_B64)):
        with pytest.raises(SystemExit) as ctx:
            run()
        assert key in str(ctx.value), (key, value)


def test_an_artefact_without_a_kind_stops_the_run(tmp_path):
    pkg = _package(tmp_path)
    _set_manifest(pkg, lambda m: m["artifacts"][0].pop("kind"))
    with pytest.raises(SystemExit) as ctx:
        vsp.before(pkg, anchor_pubkey=PUB_B64)
    assert "kind" in str(ctx.value)


# ── 3. after makes every check before makes ─────────────────────────────────────────────────────────────

def test_a_finding_of_before_is_a_finding_of_after(tmp_path, capsys):
    """Codex's case: the body's tree digest differs from the manifest, every file digest and the derivation
    are coherent; `before` exits 1 and prints its digest, and `after` with that digest assembled the body."""
    pkg = _package(tmp_path)
    body = json.loads((pkg / "art.body.json").read_text())
    body["candidate"]["tree_digest"] = "1" * 64
    _rewrite_body(pkg, body)
    assert vsp.before(pkg, anchor_pubkey=PUB_B64, expected_head=HEAD) == 1
    printed = re.search(r"manifest\s*:\s*sha256 ([0-9a-f]{64})", capsys.readouterr().out).group(1)
    rc = vsp.after(pkg, "art", _sign(pkg), anchor_pubkey=PUB_B64, reviewed_manifest_sha256=printed)
    out = capsys.readouterr().out
    assert rc == 1, out[-600:]
    assert "candidate DIFFERS" in out
    assert not (pkg / "art.signed.json").exists()


@pytest.mark.parametrize("change", ["no version in a non-binding body", "a signature already in the body",
                                    "a body candidate that is no object"])
def test_the_other_checks_of_before_hold_in_after(tmp_path, change):
    pkg = _package(tmp_path, binds=change != "no version in a non-binding body")
    body = json.loads((pkg / "art.body.json").read_text())
    if change == "no version in a non-binding body":
        del body["version"]
    elif change == "a signature already in the body":
        body["signer_pubkey"] = PUB_B64
    else:
        body["candidate"] = HEAD
    _rewrite_body(pkg, body)
    rb, ra, out = _both_phases(pkg)
    assert (rb, ra) == (1, 1), (change, out[-600:])
    assert not (pkg / "art.signed.json").exists()


def test_after_compares_the_candidate_with_the_head_it_is_given(tmp_path, capsys):
    """The reading of the fix: `after` knew no expected head, so a package `before` refused against the head
    was assembled. It takes the head now, and says when it was not given one."""
    pkg = _package(tmp_path)
    other_head = "9" * 40
    assert vsp.before(pkg, anchor_pubkey=PUB_B64, expected_head=other_head) == 1
    capsys.readouterr()
    rc = vsp.after(pkg, "art", _sign(pkg), anchor_pubkey=PUB_B64, reviewed_manifest_sha256=_reviewed(pkg),
                   expected_head=other_head)
    assert rc == 1
    assert "is NOT the expected head" in capsys.readouterr().out
    assert not (pkg / "art.signed.json").exists()
    rc = vsp.after(pkg, "art", _sign(pkg), anchor_pubkey=PUB_B64, reviewed_manifest_sha256=_reviewed(pkg))
    assert rc == 0
    assert "expected head : NOT checked" in capsys.readouterr().out


def test_a_finding_in_another_artefact_stops_after(tmp_path, capsys):
    """The reading of the fix: `after` judged only the artefact it assembled. The whole package is judged."""
    pkg = _package(tmp_path)
    (pkg / "other.body.json").write_text("{not json", encoding="utf-8")

    def zwei(m):
        m["artifacts"].append(dict(m["artifacts"][0], name="other", body="other.body.json"))
    _set_manifest(pkg, zwei)
    assert vsp.before(pkg, anchor_pubkey=PUB_B64, expected_head=HEAD) == 1
    rc = vsp.after(pkg, "art", _sign(pkg), anchor_pubkey=PUB_B64, reviewed_manifest_sha256=_reviewed(pkg))
    assert rc == 1, capsys.readouterr().out[-400:]
    assert not (pkg / "art.signed.json").exists()


def test_an_artefact_name_given_twice_stops_the_run(tmp_path):
    pkg = _package(tmp_path)
    _set_manifest(pkg, lambda m: m["artifacts"].append(dict(m["artifacts"][0])))
    for run in (lambda: vsp.before(pkg, anchor_pubkey=PUB_B64),
                lambda: vsp.after(pkg, "art", _sign(pkg), anchor_pubkey=PUB_B64)):
        with pytest.raises(SystemExit) as ctx:
            run()
        assert "more than once" in str(ctx.value)


# ── 4. the preview never lands on an input ──────────────────────────────────────────────────────────────

@pytest.mark.parametrize("role", ["body", "payload"])
def test_a_preview_path_that_names_an_input_stops_the_run(tmp_path, role):
    pkg = _package(tmp_path)
    old = {"body": "art.body.json", "payload": "art.payload.bin"}[role]
    (pkg / old).rename(pkg / "art.signed.json")
    _set_manifest(pkg, lambda m: m["artifacts"][0].__setitem__(role, "art.signed.json"))
    kept = (pkg / "art.signed.json").read_bytes()
    for run in (lambda: vsp.before(pkg, anchor_pubkey=PUB_B64),
                lambda: vsp.after(pkg, "art", pkg / "nosig", anchor_pubkey=PUB_B64)):
        with pytest.raises(SystemExit) as ctx:
            run()
        assert "would be written over" in str(ctx.value), role
    assert (pkg / "art.signed.json").read_bytes() == kept


def test_a_preview_path_that_names_another_artefacts_input_stops_the_run(tmp_path):
    pkg = _package(tmp_path)
    (pkg / "art.body.json").rename(pkg / "other.signed.json")

    def two(m):
        m["artifacts"][0]["body"] = "other.signed.json"
        m["artifacts"].append(dict(m["artifacts"][0], name="other"))
    _set_manifest(pkg, two)
    with pytest.raises(SystemExit) as ctx:
        vsp.before(pkg, anchor_pubkey=PUB_B64)
    assert "the preview of 'other' would be written over the body of 'art'" in str(ctx.value)


def test_a_preview_path_that_links_to_the_manifest_stops_the_run(tmp_path):
    pkg = _package(tmp_path)
    (pkg / "art.signed.json").symlink_to(pkg / vsp.DEFAULT_MANIFEST)
    with pytest.raises(SystemExit) as ctx:
        vsp.before(pkg, anchor_pubkey=PUB_B64)
    assert "would be written over MANIFEST.json" in str(ctx.value)


@pytest.mark.parametrize("victim", ["art.body.json", "art.payload.bin", "MANIFEST.json"])
def test_a_second_hard_name_of_an_input_is_never_written(tmp_path, capsys, victim):
    """The reading of the fix, executed: a hard link under the preview name is a second name of the same
    file, which a resolved path does not show. At c561463b both phases gave exit 0 and the input, the signed
    payload and the manifest included, was overwritten."""
    import os
    pkg = _package(tmp_path)
    sig, reviewed = _sign(pkg), _reviewed(pkg)
    kept = (pkg / victim).read_bytes()
    os.link(pkg / victim, pkg / "art.signed.json")
    rc = vsp.after(pkg, "art", sig, anchor_pubkey=PUB_B64, reviewed_manifest_sha256=reviewed)
    assert rc == 1, victim
    assert "is the same file as" in capsys.readouterr().out
    assert (pkg / victim).read_bytes() == kept, victim


def test_the_signature_file_is_never_the_preview(tmp_path, capsys):
    pkg = _package(tmp_path)
    reviewed = _reviewed(pkg)
    sig = _sign(pkg).rename(pkg / "art.signed.json")
    kept = sig.read_bytes()
    rc = vsp.after(pkg, "art", sig, anchor_pubkey=PUB_B64, reviewed_manifest_sha256=reviewed)
    assert rc == 1
    assert sig.read_bytes() == kept


def test_a_preview_replaces_its_name_and_leaves_a_shared_file_alone(tmp_path, capsys):
    """Counter-direction for the write: a hard link to a file that is no input of the run is allowed, and
    the preview replaces the name instead of writing into the shared file."""
    import os
    pkg = _package(tmp_path)
    keep = pkg / "notes.txt"
    keep.write_text("keep me\n", encoding="utf-8")
    os.link(keep, pkg / "art.signed.json")
    assert vsp.after(pkg, "art", _sign(pkg), anchor_pubkey=PUB_B64, reviewed_manifest_sha256=_reviewed(pkg)) == 0
    assert keep.read_text(encoding="utf-8") == "keep me\n"
    assert json.loads((pkg / "art.signed.json").read_text())["signature"]["sig_b64"]


def test_a_preview_is_never_written_through_a_link(tmp_path, capsys):
    """The link points at a file of the package that is no input; the run is refused and the file kept."""
    pkg = _package(tmp_path)
    keep = pkg / "notes.txt"
    keep.write_text("keep me\n", encoding="utf-8")
    (pkg / "art.signed.json").symlink_to(keep)
    rc = vsp.after(pkg, "art", _sign(pkg), anchor_pubkey=PUB_B64, reviewed_manifest_sha256=_reviewed(pkg))
    assert rc == 1
    assert "symbolic link" in capsys.readouterr().out
    assert keep.read_text(encoding="utf-8") == "keep me\n"
