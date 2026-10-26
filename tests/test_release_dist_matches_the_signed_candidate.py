"""Before any upload, the tag run compares the sdist and wheel it built with the signed candidate pair.

FINDING (external review of the 6.4.0 preparation, 2026-10-26, RELEASEPLAN P4). The digest gate of
release.yml compares the files `publish-pypi` downloads with the digests `build-and-attest` recorded in
the SAME run. That protects the hand-over from the attested build to the upload. It never compared the
tag build with the pair that was frozen and approved before the tag, and nothing in the workflow read
such a pair: a tag build with other bytes than the frozen candidate would have been attested and
published.

WHERE THE EXPECTATION COMES FROM. Not from the tag build. The short soak (C6.2) and the Rust
differential (C8.2) are signed by the owner's key over a body whose `candidate` block names the sdist
and wheel digests of the frozen pair; the release plan requires that pair to be the one it records.
`scripts/release_dist_matches_signed_candidate.py` verifies each signature against the committed trust
anchor, requires the version of the tag, requires every source to name the same pair, and compares that
pair with the files in `dist/`. It does not decide whether the tagged commit may differ from the
measured one; that order is the release plan's (P7) and the audit matrix's.

The oracle here is independent: the expected digests are computed from the files this test writes.
"""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]
SKRIPT = REPO / "scripts" / "release_dist_matches_signed_candidate.py"
RELEASE_YML = REPO / ".github" / "workflows" / "release.yml"
for _sub in ("src", "scripts"):
    _p = str(REPO / _sub)
    if _p not in sys.path:
        sys.path.insert(0, _p)

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    _KRYPTO = True
except ImportError:                                          # pragma: no cover
    _KRYPTO = False

VERSION = "9.9.9"
SOAK_REL = "audit_artifacts/360/fuzz_soak_latest.json"
DIFF_REL = "audit_artifacts/360/rust_differential_matrix.json"
ROLLE = "readiness_und_register_signierer_600"


def _git(repo: pathlib.Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True,
                          check=True).stdout.strip()


def _commit(repo: pathlib.Path, nachricht: str) -> str:
    _git(repo, "add", "-A")
    _git(repo, "-c", "user.email=a@b", "-c", "user.name=a", "commit", "-q", "-m", nachricht)
    return _git(repo, "rev-parse", "HEAD")


def _sra():
    spec = importlib.util.spec_from_file_location("_sra_release_dist", str(REPO / "scripts" /
                                                                           "sign_readiness_artifact.py"))
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m


def _signiere(rumpf: dict, key) -> dict:
    from proofbundle import canonical
    msg = canonical.canonicalize_statement({k: v for k, v in rumpf.items() if k != "signature"})
    out = dict(rumpf)
    out["signature"] = {
        "alg": "ed25519",
        "public_key_b64": base64.b64encode(key.public_key().public_bytes_raw()).decode(),
        "sig_b64": base64.b64encode(key.sign(msg)).decode()}
    return out


@pytest.fixture
def welt():
    """A small git tree: the anchor in its own commit, then the candidate, then the signed evidence
    in a later commit, and a version-9.9.9 pair in dist/ (untracked, as a build leaves it)."""
    if not _KRYPTO:
        pytest.skip("NOT MEASURABLE: cryptography is missing")
    td = pathlib.Path(tempfile.mkdtemp(prefix="release_dist_"))
    try:
        if subprocess.run(["git", "init", "-q", str(td)], capture_output=True).returncode != 0:
            pytest.skip("NOT MEASURABLE: git is not usable here")
        key = Ed25519PrivateKey.generate()
        pub = base64.b64encode(key.public_key().public_bytes_raw()).decode()
        (td / "audit_artifacts" / "360").mkdir(parents=True)
        (td / "audit_artifacts" / "readiness_trusted_pubkeys.txt").write_text(
            f"# test anchor\n{pub} role={ROLLE} not_after=2099-12-31\n", encoding="utf-8")
        _commit(td, "anchor")
        (td / "pyproject.toml").write_text(f'[project]\nversion = "{VERSION}"\n', encoding="utf-8")
        kandidat = _commit(td, "candidate")
        dist = td / "dist"
        dist.mkdir()
        sdist = dist / f"proofbundle-{VERSION}.tar.gz"
        wheel = dist / f"proofbundle-{VERSION}-py3-none-any.whl"
        sdist.write_bytes(b"frozen sdist bytes\n")
        wheel.write_bytes(b"frozen wheel bytes\n")
        paar = (hashlib.sha256(sdist.read_bytes()).hexdigest(),
                hashlib.sha256(wheel.read_bytes()).hexdigest())
        yield {"repo": td, "key": key, "foreign": Ed25519PrivateKey.generate(), "commit": kandidat,
               "pair": paar, "anchor_digest": _sra().trust_anchor_digest(td)}
    finally:
        shutil.rmtree(td, ignore_errors=True)


QUELLEN = ((SOAK_REL, "proofbundle.fuzz_soak.v1"),
           (DIFF_REL, "proofbundle.rust_relation_differential_matrix.v1"))


def _beleg(welt, rel: str, schema: str, *, pair=None, version=VERSION, key=None, signiert=True,
           kandidat=True):
    sd, wh = pair or welt["pair"]
    rumpf = {"schema": schema, "version": version,
             "candidate": ({"commit": welt["commit"], "tree_digest": "a" * 64,
                            "sdist_sha256": sd, "wheel_sha256": wh} if kandidat
                           else {"commit": welt["commit"], "tree_digest": "a" * 64}),
             "signer_role": ROLLE, "trust_anchor_digest": welt["anchor_digest"],
             "produced_at": (datetime.now(timezone.utc) - timedelta(hours=1)).strftime(
                 "%Y-%m-%dT%H:%M:%SZ")}
    inhalt = _signiere(rumpf, key or welt["key"]) if signiert else rumpf
    (welt["repo"] / rel).write_text(json.dumps(inhalt, indent=2), encoding="utf-8")


def _beide(welt, **k):
    _beleg(welt, SOAK_REL, "proofbundle.fuzz_soak.v1", **k)
    _beleg(welt, DIFF_REL, "proofbundle.rust_relation_differential_matrix.v1", **k)
    _commit(welt["repo"], "signed evidence")


def _lauf(welt, version=VERSION):
    if not SKRIPT.is_file():
        pytest.fail(f"{SKRIPT.relative_to(REPO)} is missing: the tag run has no comparison")
    r = subprocess.run([sys.executable, str(SKRIPT), "--repo", str(welt["repo"]), "--version",
                        version], capture_output=True, text=True, timeout=120)
    return r.returncode, r.stdout + r.stderr


def test_the_control_passes_when_dist_is_the_signed_pair(welt):
    """[COUNTS] Anti-parity: real signed evidence and the frozen bytes in dist/ must pass, or a script
    that refuses everything would pass the cases below."""
    _beide(welt)
    rc, out = _lauf(welt)
    assert rc == 0, out
    assert welt["pair"][0] in out and welt["pair"][1] in out, out


@pytest.mark.parametrize("datei", ["whl", "tar.gz"])
def test_a_tag_build_with_other_bytes_is_refused(welt, datei):
    """[COUNTS] The finding itself: the tag run built other bytes than the signed pair."""
    _beide(welt)
    ziel = next((welt["repo"] / "dist").glob(f"*.{datei}"))
    ziel.write_bytes(b"bytes of another build\n")
    rc, out = _lauf(welt)
    assert rc == 1 and "NOT THE SIGNED CANDIDATE" in out, out


@pytest.mark.parametrize("schuldig", [0, 1], ids=["soak", "differential"])
@pytest.mark.parametrize("fehler", ["unsigned", "foreign_key", "missing", "other_version",
                                    "other_schema", "no_candidate_digests"])
def test_each_source_alone_stops_the_comparison(welt, schuldig, fehler):
    """[COUNTS] Without an owner-signed source of this version and kind there is no expectation, and
    no expectation is a stop. EACH source alone, while the other one is in order: a check made only
    on the first source would pass every case of the second (lens on the head before this commit)."""
    for i, (rel, schema) in enumerate(QUELLEN):
        if i != schuldig:
            _beleg(welt, rel, schema)
        elif fehler == "missing":
            continue
        elif fehler == "unsigned":
            _beleg(welt, rel, schema, signiert=False)
        elif fehler == "foreign_key":
            _beleg(welt, rel, schema, key=welt["foreign"])
        elif fehler == "other_version":
            _beleg(welt, rel, schema, version="9.9.8")
        elif fehler == "other_schema":
            _beleg(welt, rel, "proofbundle.something_else.v1")
        else:
            _beleg(welt, rel, schema, kandidat=False)
    _commit(welt["repo"], f"{fehler} in source {schuldig}")
    rc, out = _lauf(welt)
    assert rc == 1 and "NOT THE SIGNED CANDIDATE" in out, out


def test_two_sources_that_name_different_pairs_are_refused(welt):
    """[COUNTS] The two signed sources must name one pair; which one is meant is not chosen here."""
    _beleg(welt, SOAK_REL, "proofbundle.fuzz_soak.v1")
    _beleg(welt, DIFF_REL, "proofbundle.rust_relation_differential_matrix.v1",
           pair=(welt["pair"][0], "e" * 64))
    _commit(welt["repo"], "disagreeing pairs")
    rc, out = _lauf(welt)
    # THE REASON, NOT ONLY THE EXIT CODE: with the check dropped, a set of two pairs gives one of them
    # by hash order, and one of the two orders also ends in exit 1 against dist/. Measured: the mutant
    # survived one of two runs while this case read the exit code alone.
    assert rc == 1 and "the signed sources name different pairs" in out, out


def test_an_ambiguous_or_empty_dist_is_refused(welt):
    """[COUNTS] Two wheels of the version, or none, is no identified pair."""
    _beide(welt)
    extra = welt["repo"] / "dist" / f"proofbundle-{VERSION}-py3-none-manylinux.whl"
    extra.write_bytes(b"frozen wheel bytes\n")
    assert _lauf(welt)[0] == 1
    shutil.rmtree(welt["repo"] / "dist")
    assert _lauf(welt)[0] == 1


def test_a_later_commit_outside_the_evidence_paths_does_not_decide_the_bytes(welt):
    """[COUNTS] The comparison is about bytes. A commit after the evidence that touches a path the
    package does not ship (here a receipt under audit_artifacts/) leaves an equal pair equal."""
    _beide(welt)
    (welt["repo"] / "audit_artifacts" / "receipt.json").write_text("{}\n", encoding="utf-8")
    _commit(welt["repo"], "receipt after the evidence")
    assert _lauf(welt)[0] == 0


def _job_build_and_attest() -> dict:
    if not RELEASE_YML.is_file():
        # The sdist prunes .github/; this case has nothing to read there.
        pytest.skip(f"NOT MEASURABLE: {RELEASE_YML} is missing")
    # Only this case needs PyYAML; at module level the skip would also hide the cases above.
    yaml = pytest.importorskip("yaml", reason="NOT MEASURABLE: PyYAML is missing")
    return yaml.safe_load(RELEASE_YML.read_text(encoding="utf-8"))["jobs"]["build-and-attest"]


def test_release_yml_compares_after_the_build_and_before_any_upload():
    """[COUNTS] In release.yml the comparison runs after the only build and before the first step
    that attests or uploads (the provenance, the artifact for publish-pypi, the draft release)."""
    job = _job_build_and_attest()
    schritte = job["steps"]

    def index(pred):
        treffer = [i for i, s in enumerate(schritte) if pred(s)]
        return treffer[0] if treffer else None
    bau = index(lambda s: "build_reproducible.py" in str(s.get("run") or ""))
    vergleich = index(lambda s: "release_dist_matches_signed_candidate.py" in str(s.get("run") or ""))
    hochladen = index(lambda s: any(a in str(s.get("uses") or "") for a in (
        "actions/attest-build-provenance@", "actions/upload-artifact@", "softprops/action-gh-release@")))
    assert bau is not None and hochladen is not None, (bau, hochladen)
    assert vergleich is not None, "release.yml runs no comparison with the signed candidate"
    assert bau < vergleich < hochladen, (bau, vergleich, hochladen)
    s = schritte[vergleich]
    befehle = str(s.get("run"))
    assert "${GITHUB_REF_NAME#v}" in befehle, s
    # A failure of the comparison must stop the job: not allowed to fail at step or job level, not
    # made conditional, and not swallowed inside the shell (lens on the head before this commit).
    assert not s.get("continue-on-error") and "if" not in s, s
    assert not job.get("continue-on-error"), job.get("continue-on-error")
    for schlucker in ("|| true", "|| :", "set +e", "|| exit 0"):
        assert schlucker not in befehle, (schlucker, befehle)
