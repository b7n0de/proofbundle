"""The code that judges a receipt is the code of the commit it judges (lesson 2, Codex on PR 541, round lx4, P0 3).

FINDING. The release gate put `<repo>/src` in front of `sys.path` so that `verify_receipt` could import
`proofbundle.signature`, and the release step did the same for its own check of the committed receipt; the step also
ran the gate, the receipt library and the readiness module from the files on disk. Whoever could write the checkout
while the release ran could make a forged receipt verify, with HEAD and every blob that was read unchanged.

THE RULE, owner choice B (19 November 2026): the gate and the step serve the package `proofbundle` from the blobs of the
commit they hold (`pre_tag_receipt_lib.paket_aus_eintraegen`), and the step runs the chain beside it from the commit's
blobs as well, after comparing its own file with the commit. A commit without the package (a test tree judged with this
repository's tools) uses the interpreter's package, never one that lies inside the judged checkout.

WHAT IS NOT CLAIMED. The step's own module and the receipt library it imports at its start run from disk; a check they
ran on themselves would be answered by the code it looks at. In release.yml the outside verifier runs before them and
compares every file under scripts/ and src/ with the commit (tests/test_release_digests_resolve_at_the_tag.py holds the
order). The gate and the step run in subprocesses here, so that no package loaded by the test process hides the disk.
"""
from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import os
import pathlib
import shutil
import subprocess
import sys

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

REPO = pathlib.Path(__file__).resolve().parents[1]
VERSION = "6.6.1"
RECEIPT = "audit_artifacts/661/pre_tag_receipt_v6.6.1.json"
OUTPUT = "audit_artifacts/661/pre_tag_audit_output_v6.6.1.txt"
OUTPUT_BYTES = b"28245 passed, 158 skipped\n"
ANCHOR = "audit_artifacts/pre_tag_trusted_pubkeys.txt"
CHAIN = ("audit_output_aufloesbar.py", "pre_tag_audit_gate.py", "pre_tag_receipt_lib.py", "sign_readiness_artifact.py")
_TRUSTED = Ed25519PrivateKey.generate()
_OTHER = Ed25519PrivateKey.generate()
#: What a planted signature module answers: every signature verifies.
_FORGED_SIGNATURE = "\n\ndef verify_ed25519_pinned(*_a, **_k):\n    return True\n"
#: What a planted gate does: its library verifies every receipt.
_FORGED_GATE = ("\n\n_echte_bibliothek = _lib\n\n\ndef _lib():\n    m = _echte_bibliothek()\n"
                "    m.verify_receipt = lambda receipt, **kw: (True, 'FORGED')\n    return m\n")


def _pub(priv) -> str:
    return base64.b64encode(priv.public_key().public_bytes_raw()).decode()


def _module(name: str, file: str):
    spec = importlib.util.spec_from_file_location(name, str(REPO / "scripts" / file))
    m = importlib.util.module_from_spec(spec)
    sys.modules[name] = m
    spec.loader.exec_module(m)
    return m


def _git(repo: pathlib.Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, text=True,
                          check=True).stdout.strip()


def _commit(repo: pathlib.Path, files: dict, message: str) -> str:
    for rel, content in files.items():
        p = repo / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(content if isinstance(content, bytes) else content.encode("utf-8"))
    _git(repo, "add", "-A")
    _git(repo, "-c", "user.email=a@b", "-c", "user.name=a", "commit", "-q", "-m", message)
    return _git(repo, "rev-parse", "HEAD")


def _tree(tmp_path, *, chain: bool = False) -> pathlib.Path:
    """A release tree of 6.6.1 that carries the package `proofbundle` (and the release chain under scripts/ when
    `chain`), the trust anchor naming `_TRUSTED`, and nothing else."""
    repo = tmp_path / "t"
    repo.mkdir()
    _git(repo, "init", "-q")
    shutil.copytree(REPO / "src" / "proofbundle", repo / "src" / "proofbundle",
                    ignore=shutil.ignore_patterns("__pycache__"))
    files = {"pyproject.toml": f'[project]\nversion = "{VERSION}"\n', ANCHOR: _pub(_TRUSTED) + "\n",
             "audit_artifacts/661/README.md": "page\n", ".gitignore": "__pycache__/\n"}
    if chain:
        files.update({f"scripts/{name}": (REPO / "scripts" / name).read_bytes() for name in CHAIN})
    _commit(repo, files, "candidate")
    return repo


def _receipt(repo, *, output: bytes = OUTPUT_BYTES, signer=_TRUSTED, sign_as=None) -> str:
    """A receipt over the tree of `repo`'s head for 6.6.1, naming `output`. `signer` signs; `sign_as` is the key it
    claims (default: the signer's), so a signature by `_OTHER` claiming `_TRUSTED` is a forgery."""
    lib = _module("_lib_commit_package", "pre_tag_receipt_lib.py")
    r = {"schema": lib.RECEIPT_SCHEMA, "version": VERSION, "subject_tree_digest": lib.subject_tree_digest(repo),
         "gate_source_digest": hashlib.sha256((REPO / "scripts" / "pre_tag_audit_gate.py").read_bytes()).hexdigest(),
         "audit_command": "python -m pytest -q", "audit_exit_code": 0,
         "audit_output_digest": hashlib.sha256(output).hexdigest(), "runner_identity": "test",
         "produced_at": "2026-11-19T10:00:00Z"}
    if signer is not None:
        r["signature"] = base64.b64encode(signer.sign(lib.canonical_bytes(r))).decode()
        r["signer_pubkey"] = _pub(sign_as or signer)
    return json.dumps(r, indent=2) + "\n"


def _run(*argv, umgebung_dazu: dict | None = None) -> dict:
    """A script of the chain in a fresh interpreter, without PYTHONPATH and without writing bytecode, its JSON answer.
    Every subprocess here runs with `-B`: a `__pycache__` written into the scripts/ of a test tree went into the next
    commit of that tree, and a digest then moved for that reason alone (measured on the mutant B8)."""
    umgebung = {k: v for k, v in os.environ.items() if k not in ("PYTHONPATH", "PYTHONPYCACHEPREFIX")}
    umgebung.update(umgebung_dazu or {})
    r = subprocess.run([sys.executable, "-B", *map(str, argv), "--json"], capture_output=True, text=True, env=umgebung,
                       timeout=300, cwd=str(REPO.parent))
    assert r.stdout.strip(), f"no answer (exit {r.returncode}): {r.stderr[-2000:]}"
    return json.loads(r.stdout)


def _gate(repo, *, aus_dem_baum: bool = False, umgebung_dazu: dict | None = None) -> dict:
    """The gate of this repository, or (`aus_dem_baum`) the copy the judged tree carries under scripts/, which is the
    shape of the release: there the gate lies in the checkout it judges, and `sign_readiness_artifact.py`, loaded by
    the library, puts the `src/` beside it in front of `sys.path` (measured: run from outside the tree, the gate took
    the package of its own repository and never saw the judged tree's disk)."""
    wo = (repo if aus_dem_baum else REPO) / "scripts" / "pre_tag_audit_gate.py"
    return _run(wo, "--repo", repo, "--version", VERSION, umgebung_dazu=umgebung_dazu)


def _step(repo, *, umgebung_dazu: dict | None = None) -> dict:
    return _run(repo / "scripts" / "audit_output_aufloesbar.py", "--repo", repo, "--version", VERSION,
                umgebung_dazu=umgebung_dazu)


# ── THE GATE ─────────────────────────────────────────────────────────────────────────────────────────────────────────


def test_the_gate_verifies_a_signed_receipt_with_the_package_of_the_commit(tmp_path):
    """[COUNTS] GREEN CONTROL: a receipt the trusted key signed verifies, the package served from the commit."""
    repo = _tree(tmp_path)
    _commit(repo, {RECEIPT: _receipt(repo)}, "receipt")
    r = _gate(repo)
    assert (r["ok"], r["state"]) == (True, "verified"), r


def test_a_signature_module_planted_on_disk_does_not_judge(tmp_path):
    """[COUNTS] THE FINDING, at the gate. The committed receipt claims the trusted key and carries the signature of
    another one. On disk, `src/proofbundle/signature.py` answers that every signature verifies. Read from disk, the
    forgery was `verified`; read from the commit, the signature does not verify. The gate runs from the tree it judges,
    as in the release."""
    repo = _tree(tmp_path, chain=True)
    _commit(repo, {RECEIPT: _receipt(repo, signer=_OTHER, sign_as=_TRUSTED)}, "a forged receipt")
    vorher = _gate(repo, aus_dem_baum=True)
    assert vorher["state"] == "rejected", "control: the forgery is refused while the disk is the commit"
    with (repo / "src" / "proofbundle" / "signature.py").open("a", encoding="utf-8") as f:
        f.write(_FORGED_SIGNATURE)
    r = _gate(repo, aus_dem_baum=True)
    assert r["ok"] is False and r["state"] == "rejected", r
    assert "does not verify" in json.dumps(r["rejected_receipts"]), r


# ── THE STEP ─────────────────────────────────────────────────────────────────────────────────────────────────────────


def _release(tmp_path) -> pathlib.Path:
    """The chain and the package committed, then the receipt and the output beside it."""
    repo = _tree(tmp_path, chain=True)
    _commit(repo, {RECEIPT: _receipt(repo), OUTPUT: OUTPUT_BYTES}, "receipt and output")
    return repo


def test_the_step_resolves_with_the_chain_of_the_commit(tmp_path):
    """[COUNTS] GREEN CONTROL: the step lies in the judged checkout, equal to the commit, and resolves."""
    r = _step(_release(tmp_path))
    assert r["zustand"] == "AUFLOESBAR", r
    assert r["quittungen"][0]["treffer"] == [OUTPUT], r


def test_a_gate_planted_on_disk_does_not_judge_for_the_step(tmp_path):
    """[COUNTS] THE FINDING, at the step. The commit carries an UNSIGNED receipt naming the output; on disk the gate
    beside the step makes its library verify every receipt. Loaded from disk, the step resolved the forgery; loaded
    from the commit, the gate refuses it and the step measures nothing."""
    repo = _tree(tmp_path, chain=True)
    _commit(repo, {RECEIPT: _receipt(repo, signer=None), OUTPUT: OUTPUT_BYTES}, "an unsigned receipt")
    with (repo / "scripts" / "pre_tag_audit_gate.py").open("a", encoding="utf-8") as f:
        f.write(_FORGED_GATE)
    r = _step(repo)
    assert r["zustand"] == "NICHT_MESSBAR", r
    assert "FORGED" not in json.dumps(r), r


def test_a_bytecode_cache_beside_the_library_does_not_run(tmp_path):
    """[COUNTS] Codex on pull request 541, round lx5, P0 2. A `.pyc` of the receipt library with an unchecked hash lies in
    the tree's `scripts/__pycache__`, where Python takes it in place of the source and git does not see it. It writes a
    marker when it runs. The step imports the library at its start: it must take the source, so the marker stays
    absent and the step still resolves. The gate, run from the tree as well, loads its library by path behind its own
    bytecode directory (control)."""
    import importlib.util as ilu
    import py_compile

    repo = _release(tmp_path)
    marke = tmp_path / "pyc_ran"
    gefaelscht = tmp_path / "pre_tag_receipt_lib.py"
    gefaelscht.write_text((repo / "scripts" / "pre_tag_receipt_lib.py").read_text(encoding="utf-8")
                          + "\nimport os as _os\nopen(_os.environ['PB_PYC_MARKE'], 'w').write('ran')\n", encoding="utf-8")
    ziel = repo / "scripts" / "__pycache__" / pathlib.Path(ilu.cache_from_source(str(gefaelscht))).name
    py_compile.compile(str(gefaelscht), cfile=str(ziel), dfile=str(repo / "scripts" / "pre_tag_receipt_lib.py"),
                       doraise=True, invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH)
    assert ziel.is_file() and _git(repo, "status", "--porcelain") == "", "the cache must be invisible to git"
    r = _step(repo, umgebung_dazu={"PB_PYC_MARKE": str(marke)})
    assert not marke.exists(), "the step ran a .pyc beside its library instead of the source"
    assert r["zustand"] == "AUFLOESBAR", r
    _gate(repo, aus_dem_baum=True, umgebung_dazu={"PB_PYC_MARKE": str(marke)})
    assert not marke.exists(), "the gate ran a .pyc beside its library instead of the source"


def test_a_package_planted_under_the_temporary_directory_does_not_run(tmp_path):
    """[COUNTS] Found by the witness of this pull request before the hand-over (20 November 2026, with a probe). The step
    writes the chain of the commit into a fresh directory under $TMPDIR, and `sign_readiness_artifact.py`, loaded by the
    library, puts `parents[1] / "src"` in front of `sys.path`. With the chain directly in the fresh directory that was
    `$TMPDIR/src`, which any user of the machine can create, and a `cryptography` planted there ran and let a forged
    receipt resolve. The chain now lies in `scripts/` below the fresh directory: the plant never runs, and a receipt
    signed by another key than the one it names stays unmeasured."""
    repo = _tree(tmp_path, chain=True)
    _commit(repo, {RECEIPT: _receipt(repo, signer=_OTHER, sign_as=_TRUSTED), OUTPUT: OUTPUT_BYTES}, "a forged receipt")
    tmp = tmp_path / "tmp"
    paket = tmp / "src" / "cryptography"
    paket.mkdir(parents=True)
    marke = tmp_path / "plant_ran"
    (paket / "__init__.py").write_text("import os\nopen(os.environ['PB_PLANT_MARKE'], 'w').write('ran')\n"
                                       "raise ImportError('planted')\n", encoding="utf-8")
    r = _step(repo, umgebung_dazu={"TMPDIR": str(tmp), "PB_PLANT_MARKE": str(marke)})
    assert not marke.exists(), "a package under $TMPDIR/src ran in the step"
    assert r["zustand"] == "NICHT_MESSBAR", r


def test_a_step_on_disk_that_is_not_the_commit_measures_nothing(tmp_path):
    """[COUNTS] The step compares its own file with the blob the held commit carries at its path."""
    repo = _release(tmp_path)
    with (repo / "scripts" / "audit_output_aufloesbar.py").open("a", encoding="utf-8") as f:
        f.write("\n# one more line on disk\n")
    r = _step(repo)
    assert r["zustand"] == "NICHT_MESSBAR", r
    assert "not the file the held commit carries" in r["grund"], r


def test_the_step_refuses_a_commit_without_the_chain_beside_it(tmp_path):
    """[COUNTS] The step lies in the checkout, but the commit does not carry the gate beside it: there is no
    committed code to run, so it measures nothing instead of running the gate from disk. The receipt is signed over
    the tree without the gate, so a step that ran the gate from disk resolved it."""
    repo = _tree(tmp_path, chain=True)
    _git(repo, "rm", "-q", "--cached", "--", "scripts/pre_tag_audit_gate.py")
    _git(repo, "-c", "user.email=a@b", "-c", "user.name=a", "commit", "-q", "-m", "the gate only on disk")
    (repo / RECEIPT).write_text(_receipt(repo), encoding="utf-8")
    (repo / OUTPUT).write_bytes(OUTPUT_BYTES)
    _git(repo, "add", "--", RECEIPT, OUTPUT)                  # not `-A`: the gate stays out of the commit
    _git(repo, "-c", "user.email=a@b", "-c", "user.name=a", "commit", "-q", "-m", "receipt and output")
    assert _git(repo, "ls-tree", "HEAD", "scripts/pre_tag_audit_gate.py") == "", "the fixture committed the gate"
    r = _step(repo)
    assert r["zustand"] == "NICHT_MESSBAR", r
    assert "carries no regular file scripts/pre_tag_audit_gate.py" in r["grund"], r


#: Loads the step from this repository (outside the judged tree) and runs it with a gate that says `verified`, so
#: that only the step's own check of the committed receipt decides.
_TREIBER = """
import importlib.util, json, pathlib, sys
pfad, repo, quittung, tor = sys.argv[1:5]
spec = importlib.util.spec_from_file_location("_step_own_check", pfad)
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
lib = m._gate()._lib()
class Tor:
    def evaluate(self, repo, version):
        return {"ok": True, "state": "verified", "verified_receipts": [{"path": quittung, "reason": "x"}],
                "subject_tree_digest": lib.subject_tree_digest(repo), "gate_source_digest": tor}
    def _lib(self):
        return lib
print(json.dumps(m.fuer_version(pathlib.Path(repo), "6.6.1", gate=Tor())))
"""


def test_the_steps_own_check_of_the_receipt_uses_the_package_of_the_commit(tmp_path):
    """[COUNTS] The gate says `verified`; the step then verifies the committed receipt itself. The receipt claims the
    trusted key and carries another key's signature, and on disk the signature module verifies everything. The output
    was committed before the receipt was made, so the tree the receipt names is the tree that is measured: only the
    signature can stop it, and the commit's signature module does. The step and its library run from the tree they
    judge, as in the release (see `_gate`)."""
    repo = _tree(tmp_path, chain=True)
    _commit(repo, {OUTPUT: OUTPUT_BYTES}, "the output first")
    _commit(repo, {RECEIPT: _receipt(repo, signer=_OTHER, sign_as=_TRUSTED)}, "a forged receipt")
    with (repo / "src" / "proofbundle" / "signature.py").open("a", encoding="utf-8") as f:
        f.write(_FORGED_SIGNATURE)
    treiber = tmp_path / "treiber.py"
    treiber.write_text(_TREIBER, encoding="utf-8")
    tor = hashlib.sha256((REPO / "scripts" / "pre_tag_audit_gate.py").read_bytes()).hexdigest()
    umgebung = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}
    r = subprocess.run([sys.executable, "-B", str(treiber), str(repo / "scripts" / "audit_output_aufloesbar.py"), str(repo),
                        RECEIPT, tor], capture_output=True, text=True, env=umgebung, timeout=300, cwd=str(tmp_path))
    assert r.stdout.strip(), r.stderr[-2000:]
    aus = json.loads(r.stdout)
    assert aus["zustand"] == "NICHT_MESSBAR", aus
    assert "does not verify" in aus["quittungen"][0]["grund"], aus


_DIGEST = """
import importlib.util, sys
spec = importlib.util.spec_from_file_location("_lib_im_baum", sys.argv[1])
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
print(m.subject_tree_digest(sys.argv[2]))
"""


def test_the_digest_checks_the_signature_beside_the_output_with_the_package_of_the_commit(tmp_path):
    """[COUNTS] The digest leaves an output out only when a trusted signature binds it. A forged receipt (another key's
    signature, claiming the trusted one) names the output and attests the tree without it; on disk the signature
    module verifies everything. The library of the judged tree computes the digest in a fresh process: the output must
    stay in it, because the commit's signature module refuses the forgery."""
    repo = _tree(tmp_path, chain=True)
    skript = tmp_path / "digest.py"
    skript.write_text(_DIGEST, encoding="utf-8")
    umgebung = {k: v for k, v in os.environ.items() if k != "PYTHONPATH"}

    def digest():
        r = subprocess.run([sys.executable, "-B", str(skript), str(repo / "scripts" / "pre_tag_receipt_lib.py"),
                            str(repo)],
                           capture_output=True, text=True, env=umgebung, timeout=300, cwd=str(tmp_path))
        assert r.returncode == 0 and r.stdout.strip(), r.stderr[-2000:]
        return r.stdout.strip()

    vorher = digest()
    _commit(repo, {RECEIPT: _receipt(repo, signer=_OTHER, sign_as=_TRUSTED), OUTPUT: OUTPUT_BYTES},
            "a forged receipt and the output it names")
    with (repo / "src" / "proofbundle" / "signature.py").open("a", encoding="utf-8") as f:
        f.write(_FORGED_SIGNATURE)
    assert digest() != vorher, "the output left the digest on a signature that only the disk accepts"


# ── THE PACKAGE FROM THE COMMIT ──────────────────────────────────────────────────────────────────────────────────────


def test_the_package_comes_from_the_blobs_and_the_import_state_comes_back(tmp_path):
    """[COUNTS] Inside the block `proofbundle` is the committed blob, not the file on disk; a module the commit does
    not carry is refused even when the disk has it; afterwards the modules loaded before are back."""
    repo = tmp_path / "p"
    repo.mkdir()
    _git(repo, "init", "-q")
    _commit(repo, {"src/proofbundle/__init__.py": "MARKE = 'commit'\n"}, "package")
    (repo / "src" / "proofbundle" / "__init__.py").write_text("MARKE = 'disk'\n", encoding="utf-8")
    (repo / "src" / "proofbundle" / "nur_auf_der_platte.py").write_text("X = 1\n", encoding="utf-8")
    lib = _module("_lib_commit_package_unit", "pre_tag_receipt_lib.py")
    import proofbundle.signature  # noqa: F401 - loaded before the block, so it must come back (mutant B7)
    vorher = {n: m for n, m in sys.modules.items() if n == "proofbundle" or n.startswith("proofbundle.")}
    assert vorher, "no module of the package was loaded before the block"
    sys.path.insert(0, str(repo / "src"))
    try:
        with lib.paket_aus_commit(repo, "HEAD"):
            import proofbundle
            assert proofbundle.MARKE == "commit"
            with pytest.raises(ModuleNotFoundError, match="carries no module"):
                importlib.import_module("proofbundle.nur_auf_der_platte")
    finally:
        sys.path.remove(str(repo / "src"))
    nachher = {n: m for n, m in sys.modules.items() if n == "proofbundle" or n.startswith("proofbundle.")}
    assert nachher.keys() == vorher.keys() and all(nachher[n] is vorher[n] for n in vorher)


def test_without_a_committed_package_the_one_in_the_checkout_is_refused(tmp_path):
    """[COUNTS] A commit that carries no package uses the interpreter's, but not one inside the judged checkout."""
    repo = tmp_path / "q"
    repo.mkdir()
    _git(repo, "init", "-q")
    _commit(repo, {"README.md": "no package\n"}, "no package")
    (repo / "src" / "proofbundle").mkdir(parents=True)
    (repo / "src" / "proofbundle" / "__init__.py").write_text("MARKE = 'disk'\n", encoding="utf-8")
    lib = _module("_lib_commit_package_none", "pre_tag_receipt_lib.py")
    sys.path.insert(0, str(repo / "src"))
    try:
        with lib.paket_aus_commit(repo, "HEAD"):
            with pytest.raises(ModuleNotFoundError, match="lies in the judged checkout"):
                importlib.import_module("proofbundle")
    finally:
        sys.path.remove(str(repo / "src"))
    with lib.paket_aus_commit(repo, None):
        with pytest.raises(ModuleNotFoundError, match="could not be read"):
            importlib.import_module("proofbundle")
