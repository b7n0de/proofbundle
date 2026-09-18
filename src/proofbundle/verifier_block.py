"""The verifier block: WHICH build of proofbundle produced a receipt, and against WHICH vector set it stood.

THE QUESTION IT ANSWERS (asked on the SCITT list, 2026-09-10, and measured against this package on
2026-09-12). A relying party reading a receipt at T+n wants to know that the verifier instance
which produced it was an implementation that met the cited conformance floor, and that code and
configuration at T were the tested ones. proofbundle already binds what DECIDED (the policy, by a
digest over its bytes, recomputed at verify time) and what was decided ABOUT (subject, diff,
visible block, findings root). It did not bind what it was decided WITH: no receipt and no verify
result carried the version, the wheel digest or a build digest of the verifier. Two wheels of the
same version were indistinguishable from the receipt.

WHAT THE BLOCK CARRIES, and what each field is measured from:

  implementation   the package name, ``proofbundle``
  version          ``proofbundle.__version__`` -- a name, deliberately NOT the identity
  build            a digest over the package's OWN files, with its ``source``:
                     ``installed-record``  the sha256 of every ``proofbundle/`` row the installer
                                           wrote into ``RECORD`` (path and per-file sha256) -- the
                                           same for every install of the same wheel;
                     ``source-tree``       a digest over the package directory's files, for an
                                           editable install or a checkout on ``PYTHONPATH``.
                   The two sources are different measurements and are compared only with
                   themselves. Neither is the sha256 of the wheel file on PyPI; the block says
                   which one it is.
  vectorSet        the conformance corpus the build was held against: the manifest's schema name,
                   the number of cases, and a digest over the manifest AND every file of every case
                   directory it names -- not the manifest alone, because the manifest lists
                   directories, and a directory is not bytes.
  testResult       a reference to a SEPARATE signed object: an in-toto statement of predicate
                   type ``https://in-toto.io/attestation/test-result/v0.1`` whose subject is the
                   build digest and whose ``configuration`` names the vector set. The receipt
                   carries its result and its statement digest; a relying party joins the two by
                   equality of digests, without trusting the issuer for the join.
  assurance        always ``selfDeclared``. The producing build measures itself. A block observed
                   by a runner or witnessed independently needs a witness outside the producer,
                   which this version does not provide -- the same honest rung the agent-review
                   predicate carries since v0.1.

WHAT IT DOES NOT DO. It does not make the conformance claim TRUE: a producer that lies about its
build digest signs a lie, and the signature makes the lie forgery-resistant, not correct. What a
relying party gains is a joinable, digest-bound statement instead of a version string, and a
verify result that says whether the build verifying a receipt is the build that produced it.

Field names are lowerCamelCase (ITE-9). Like the rest of proofbundle this module is the enforced
validator; ``docs/VERIFIER_BLOCK.md`` explains it.
"""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from ._membership import is_member
from .errors import ProofBundleError

TEST_RESULT_PREDICATE_TYPE = "https://in-toto.io/attestation/test-result/v0.1"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
INTOTO_STATEMENT_PAYLOAD_TYPE = "application/vnd.in-toto+json"

IMPLEMENTATION = "proofbundle"
BUILD_SOURCES = frozenset(("installed-record", "source-tree"))
TEST_RESULTS = frozenset(("PASSED", "WARNED", "FAILED"))
#: The only honest rung: the producing build measures itself.
VERIFIER_BLOCK_ASSURANCE = "selfDeclared"

_SHA256_HEX = re.compile(r"\A[0-9a-f]{64}\Z")
_SEMVERISH = re.compile(r"\A[0-9]+\.[0-9]+\.[0-9]+[0-9A-Za-z.+-]*\Z")

_BLOCK_REQUIRED = ("implementation", "version", "build", "assurance")
_BLOCK_ALLOWED = frozenset(_BLOCK_REQUIRED) | {"vectorSet", "testResult"}
_BUILD_REQUIRED = ("digest", "source")
_BUILD_ALLOWED = frozenset(_BUILD_REQUIRED) | {"files"}
_VECTOR_REQUIRED = ("name", "digest", "cases")
_TEST_RESULT_REQUIRED = ("predicateType", "result", "statementDigest")

#: Files of the package that make up a source-tree build identity. Bytecode and caches are not
#: the build; they are what a particular interpreter left behind.
_SOURCE_TREE_SUFFIXES = (".py", ".json", ".typed")


class VerifierBlockError(ProofBundleError):
    """A verifier block, a test-result statement, or a measurement is malformed (fail-closed)."""


def _is_digest(obj: Any) -> bool:
    return (isinstance(obj, dict) and set(obj) == {"sha256"} and isinstance(obj.get("sha256"), str)
            and bool(_SHA256_HEX.match(obj["sha256"])))


def _sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def _listing_digest(lines: list[str]) -> str:
    """One digest over a sorted ``relpath\\0sha256`` listing. Sorted so two walks of the same
    files agree whatever order the filesystem returned them in."""
    return hashlib.sha256("\n".join(sorted(lines)).encode("utf-8")).hexdigest()


# ── measuring the build ───────────────────────────────────────────────────────────────────────
def _record_digest_of(p: Path) -> str:
    """RECORD's own encoding of a file hash: urlsafe base64 of the sha256, padding stripped."""
    import base64  # noqa: PLC0415
    return base64.urlsafe_b64encode(bytes.fromhex(_sha256_file(p))).rstrip(b"=").decode("ascii")


def _installed_record_rows(package_dir: Path):
    """The ``proofbundle/`` rows of the installer's RECORD, IF the running package is the
    installed one AND every file still carries the bytes RECORD names for it. ``None`` when there
    is no distribution, when the module files on disk are not the files the distribution
    installed (an editable install, a checkout on PYTHONPATH), or when any package file on disk
    no longer hashes to its RECORD row.

    THE LAST CONDITION IS THE ONE THE FIRST DRAFT LACKED (Codex round one on PR 224, P1,
    measured: an installed ``a.py`` edited in place while RECORD stayed untouched measured the
    identical ``installed-record`` digest before and after, and ``report`` called that a MATCH).
    RECORD is what the installer WROTE, not what is running now; a listing read from it without
    checking the bytes is a stale-metadata identity. Now every row is hashed against the file, and
    a mismatch makes the tree measure as what it is, ``source-tree`` over the actual bytes -- a
    modified install is another build, and it joins nothing that the shipped wheel signed.
    """
    try:
        import importlib.metadata as im  # noqa: PLC0415
        dist = im.distribution(IMPLEMENTATION)
        record = dist.read_text("RECORD")
    except Exception:  # noqa: BLE001 -- no distribution is a normal state, not an error
        return None
    if not record:
        return None
    try:
        installed_init = Path(str(dist.locate_file(f"{IMPLEMENTATION}/__init__.py"))).resolve()
    except Exception:  # noqa: BLE001
        return None
    if installed_init != (package_dir / "__init__.py").resolve():
        return None
    rows: list[str] = []
    for line in record.splitlines():
        # RECORD is CSV: path,sha256=<urlsafe b64 digest>,size -- a path with a comma is quoted,
        # which no file of this package has; split on the first two commas from the right.
        parts = line.rsplit(",", 2)
        if len(parts) != 3:
            continue
        pfad, digest, _size = parts
        if not pfad.startswith(IMPLEMENTATION + "/"):
            continue
        if "/__pycache__/" in pfad or pfad.endswith((".pyc", ".pyo")):
            # BYTECODE IS NOT THE BUILD (lens C, 2026-09-18, P0). `pip install` compiles by default
            # and writes `proofbundle/__pycache__/*.pyc,,` rows WITHOUT a hash into RECORD; the
            # first draft read such a row as "a package file without a hash" and returned None
            # for the whole listing -- every default install measured itself as `source-tree`,
            # and the one property the block exists for, telling an installed wheel apart,
            # was dead under the default. Same rule as the source-tree walk: what an
            # interpreter left behind is not the identity of what was shipped.
            continue
        if not digest.startswith("sha256="):
            # RECORD itself carries an empty hash; a package file without one cannot identify a
            # build, and a listing that silently skipped it would be a listing of the rest.
            return None
        try:
            auf_platte = Path(str(dist.locate_file(pfad)))
            if not auf_platte.is_file() or _record_digest_of(auf_platte) != digest[len("sha256="):]:
                return None
        except (OSError, ValueError):
            return None
        rows.append(f"{pfad}\0{digest[len('sha256='):]}")
    return rows or None


def _innerhalb(p: Path, wurzel: Path) -> bool:
    """Does the RESOLVED file lie under the root? A symlink that leads out of the tree is not a file
    of the tree: its target can change while every byte of the tree stays the same, and a digest
    that takes it along pins nothing (lens C, 2026-09-18, P1)."""
    try:
        return p.resolve().is_relative_to(wurzel.resolve())
    except (OSError, ValueError):
        return False


def _source_tree_rows(package_dir: Path) -> list[str]:
    rows: list[str] = []
    for p in sorted(package_dir.rglob("*")):
        if not p.is_file() or "__pycache__" in p.parts or p.suffix not in _SOURCE_TREE_SUFFIXES:
            continue
        if not _innerhalb(p, package_dir):
            raise VerifierBlockError(
                f"{p.relative_to(package_dir).as_posix()} resolves outside the package directory -- a "
                "link that leaves the tree cannot be part of the tree's identity")
        rel = p.relative_to(package_dir).as_posix()
        rows.append(f"{IMPLEMENTATION}/{rel}\0{_sha256_file(p)}")
    return rows


def measure_build(package_dir: "Path | None" = None) -> dict:
    """The identity of the running build, measured, with its ``source`` stated.

    Never a placeholder: a build that cannot be measured raises, because a block carrying a
    made-up digest would be worse than none -- the whole point of the field is that it can be
    joined against a test-result statement by equality.
    """
    package_dir = Path(package_dir) if package_dir is not None else Path(__file__).resolve().parent
    rows = _installed_record_rows(package_dir)
    source = "installed-record"
    if rows is None:
        rows = _source_tree_rows(package_dir)
        source = "source-tree"
    if not rows:
        raise VerifierBlockError(
            f"no package files found under {package_dir} -- a build with no files has no identity")
    return {"digest": {"sha256": _listing_digest(rows)}, "source": source, "files": len(rows)}


# ── measuring the vector set ──────────────────────────────────────────────────────────────────
def measure_vector_set(conformance_dir: "Path | str") -> dict:
    """The conformance corpus as bytes: manifest AND every file of every case directory it names.

    A missing case directory raises: a vector set whose manifest names cases that are not there is
    not a measurable set, and a digest over the rest would name something that was never run.
    """
    root = Path(conformance_dir)
    manifest_path = root / "manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise VerifierBlockError(f"conformance manifest not readable: {manifest_path}: {exc}") from exc
    cases = manifest.get("cases") if isinstance(manifest, dict) else None
    if not isinstance(cases, list) or not cases or not all(isinstance(c, str) and c for c in cases):
        raise VerifierBlockError(f"conformance manifest names no cases: {manifest_path}")
    if len(set(cases)) != len(cases):
        # A CASE LISTED TWICE IS NOT TWO CASES (lens C, P2): `cases` would count the listing, not
        # the corpus, and the runner would execute the same directory twice under one id.
        doppelt = sorted({c for c in cases if cases.count(c) > 1})
        raise VerifierBlockError(f"conformance manifest lists a case more than once: {doppelt}")
    # ... AND NEITHER IS A CASE LISTED UNDER TWO SPELLINGS (Codex round one on PR 224, P2,
    # measured with `['a', './a']`: accepted, hashed twice, `cases: 2`). Uniqueness is a property
    # of the directory, so it is judged on the resolved path; `./a`, `x/../a` and a symlink to `a`
    # are the same case as `a`.
    aufgeloest: dict[Path, str] = {}
    for rel in cases:
        ziel = (root / rel).resolve()
        if ziel in aufgeloest:
            raise VerifierBlockError(
                f"conformance manifest lists one case directory under two spellings: "
                f"{aufgeloest[ziel]!r} and {rel!r}")
        aufgeloest[ziel] = rel
    rows = [f"manifest.json\0{_sha256_file(manifest_path)}"]
    for rel in cases:
        d = root / rel
        if not d.is_dir() or not _innerhalb(d, root):
            raise VerifierBlockError(f"conformance manifest names a case directory that is absent or "
                                     f"outside the corpus: {rel}")
        gefunden = False
        for p in sorted(d.rglob("*")):
            if not p.is_file() or "__pycache__" in p.parts:
                continue
            if not _innerhalb(p, root):
                raise VerifierBlockError(
                    f"{p.relative_to(root).as_posix()} resolves outside the corpus -- a link that leaves "
                    "the corpus cannot be part of a digest-pinned vector set (CONFORMANCE.md rule 1)")
            gefunden = True
            rows.append(f"{p.relative_to(root).as_posix()}\0{_sha256_file(p)}")
        if not gefunden:
            raise VerifierBlockError(f"case directory carries no file: {rel}")
    name = manifest.get("schema") if isinstance(manifest.get("schema"), str) else "conformance/manifest.json"
    return {"name": name, "digest": {"sha256": _listing_digest(rows)}, "cases": len(cases)}


# ── the block ─────────────────────────────────────────────────────────────────────────────────
def validate_verifier_block(block: Any) -> list[str]:
    """Fail-closed errors for a verifier block (empty = valid). Closed key sets throughout: an
    unknown key is an error, never ignored, because a field nobody validates is a field a producer
    can put anything into."""
    errs: list[str] = []
    if not isinstance(block, dict):
        return [f"verifier block must be an object, got {type(block).__name__}"]
    for k in block:
        if k not in _BLOCK_ALLOWED:
            errs.append(f"unknown field {k!r} (additionalProperties:false)")
    for req in _BLOCK_REQUIRED:
        if req not in block:
            errs.append(f"missing required field {req!r}")
    impl = block.get("implementation")
    if "implementation" in block and not (isinstance(impl, str) and impl):
        errs.append("implementation must be a non-empty string")
    ver = block.get("version")
    if "version" in block and not (isinstance(ver, str) and _SEMVERISH.match(ver)):
        errs.append("version must be a release version string (e.g. 6.1.0)")
    if "assurance" in block and block.get("assurance") != VERIFIER_BLOCK_ASSURANCE:
        errs.append(f"assurance must be {VERIFIER_BLOCK_ASSURANCE!r} -- the producing build measures "
                    "itself, and a higher rung needs a witness outside the producer")
    b = block.get("build")
    if "build" in block:
        if not isinstance(b, dict):
            errs.append("build must be an object")
        else:
            for k in b:
                if k not in _BUILD_ALLOWED:
                    errs.append(f"build: unknown field {k!r}")
            for req in _BUILD_REQUIRED:
                if req not in b:
                    errs.append(f"build: missing {req!r}")
            if "digest" in b and not _is_digest(b.get("digest")):
                errs.append("build.digest must be a sha256 digest object ({\"sha256\": <64 hex>})")
            if "source" in b and not is_member(b.get("source"), BUILD_SOURCES):
                errs.append(f"build.source must be one of {sorted(BUILD_SOURCES)}")
            f = b.get("files")
            if "files" in b and (isinstance(f, bool) or not isinstance(f, int) or f < 1):
                errs.append("build.files must be a positive integer (a boolean is an int in Python "
                            "and is rejected explicitly)")
    v = block.get("vectorSet")
    if "vectorSet" in block:
        if not isinstance(v, dict):
            errs.append("vectorSet must be an object")
        else:
            for k in v:
                if k not in _VECTOR_REQUIRED:
                    errs.append(f"vectorSet: unknown field {k!r}")
            for req in _VECTOR_REQUIRED:
                if req not in v:
                    errs.append(f"vectorSet: missing {req!r}")
            if "name" in v and not (isinstance(v.get("name"), str) and v["name"]):
                errs.append("vectorSet.name must be a non-empty string")
            if "digest" in v and not _is_digest(v.get("digest")):
                errs.append("vectorSet.digest must be a sha256 digest object")
            c = v.get("cases")
            if "cases" in v and (isinstance(c, bool) or not isinstance(c, int) or c < 1):
                errs.append("vectorSet.cases must be a positive integer -- a vector set of zero "
                            "cases held nothing against the build")
    t = block.get("testResult")
    if "testResult" in block:
        # A CITED RUN NEEDS ITS VECTOR SET. The statement names the corpus it ran; a block that
        # cites the statement but names no corpus of its own could not be checked against it,
        # and `join_test_result` would then compare a result against nothing. Found by the
        # un-review of 2026-09-18 (P1): the join compared subject, digest and result, and a
        # statement about corpus A could be cited beside a block declaring corpus B.
        if "vectorSet" not in block:
            errs.append("testResult without vectorSet: a block that cites a conformance run must "
                        "name the vector set that run was held against, or the join has nothing "
                        "to compare the statement's configuration with")
        if not isinstance(t, dict):
            errs.append("testResult must be an object")
        else:
            for k in t:
                if k not in _TEST_RESULT_REQUIRED:
                    errs.append(f"testResult: unknown field {k!r}")
            for req in _TEST_RESULT_REQUIRED:
                if req not in t:
                    errs.append(f"testResult: missing {req!r}")
            if "predicateType" in t and t.get("predicateType") != TEST_RESULT_PREDICATE_TYPE:
                errs.append(f"testResult.predicateType must be {TEST_RESULT_PREDICATE_TYPE!r}")
            if "result" in t and not is_member(t.get("result"), TEST_RESULTS):
                errs.append(f"testResult.result must be one of {sorted(TEST_RESULTS)}")
            if "statementDigest" in t and not _is_digest(t.get("statementDigest")):
                errs.append("testResult.statementDigest must be a sha256 digest object")
    return errs


def require_valid_verifier_block(block: Any) -> None:
    errs = validate_verifier_block(block)
    if errs:
        raise VerifierBlockError("invalid verifier block: " + "; ".join(errs))


def build_verifier_block(*, build: dict, version: str, vector_set: "dict | None" = None,
                         test_result: "dict | None" = None,
                         implementation: str = IMPLEMENTATION) -> dict:
    """Assemble a block from measured parts and validate it. Absent parts are absent, not null:
    a key with a null value would read as "measured, and there was nothing"."""
    block: dict = {"implementation": implementation, "version": version, "build": dict(build),
                   "assurance": VERIFIER_BLOCK_ASSURANCE}
    if vector_set is not None:
        block["vectorSet"] = dict(vector_set)
    if test_result is not None:
        block["testResult"] = dict(test_result)
    require_valid_verifier_block(block)
    return block


def measure_verifier_block(*, conformance_dir: "Path | str | None" = None,
                           test_result_statement: "dict | None" = None,
                           package_dir: "Path | None" = None) -> dict:
    """Measure everything this process can measure about itself and return the block.

    ``conformance_dir`` is optional because an installed package carries no corpus; the block then
    names the build and says nothing about a vector set -- absent, not invented.
    """
    from . import __version__  # noqa: PLC0415
    build = measure_build(package_dir)
    vector_set = measure_vector_set(conformance_dir) if conformance_dir is not None else None
    ref = test_result_ref(test_result_statement) if test_result_statement is not None else None
    return build_verifier_block(build=build, version=__version__, vector_set=vector_set,
                                test_result=ref)


def attach(predicate: dict, block: dict) -> dict:
    """Put the block under ``producer.verifier`` of an agent-review predicate. Validates the block
    first; a predicate is never handed an invalid one. Returns the same predicate object."""
    require_valid_verifier_block(block)
    if not isinstance(predicate, dict):
        raise VerifierBlockError(f"predicate must be a dict, not {type(predicate).__name__}")
    producer = predicate.get("producer")
    if producer is None:
        producer = {}
        predicate["producer"] = producer
    if not isinstance(producer, dict):
        raise VerifierBlockError("predicate.producer must be an object to carry a verifier block")
    producer["verifier"] = dict(block)
    return predicate


# ── the test-result statement, the separate signed object ─────────────────────────────────────
def _rfc8785_bytes(obj: Any) -> bytes:
    from . import canonical  # noqa: PLC0415
    try:
        return canonical.canonicalize_statement(obj)
    except canonical.CanonicalizerUnavailable as exc:
        raise VerifierBlockError(
            "test-result statements need the RFC 8785 (JCS) canonicalizer -- proofbundle requires "
            "rfc8785 (core dependency)") from exc


def statement_digest(statement: dict) -> str:
    """sha256 hex over the RFC 8785 canonical bytes of the statement -- the value a receipt cites.
    The digest of the OBJECT, not of a file: a file can be re-indented without the object changing."""
    return hashlib.sha256(_rfc8785_bytes(statement)).hexdigest()


def build_test_result_statement(*, build: dict, vector_set: dict, results: list, version: str,
                                implementation: str = IMPLEMENTATION,
                                url: "str | None" = None) -> dict:
    """An in-toto test-result statement over a conformance run.

    ``results`` is what the conformance runner produced: one entry per case with ``caseId``,
    ``ok`` and the executed ``scope`` (``full`` / ``partial`` / ``none``). The mapping to the
    predicate's three-valued ``result`` follows the corpus rule that a skipped check is never a
    passed one: any failed case is FAILED; no failure but any case that ran partially or not at
    all is WARNED; PASSED only when every case ran in full and passed. A case that did not run in
    full is listed under ``warnedTests`` by name, so the reduction of scope is in the statement,
    not only in a headline.
    """
    if not isinstance(results, list) or not results:
        raise VerifierBlockError("a test-result statement needs at least one case result")
    passed, warned, failed = [], [], []
    for r in results:
        if not isinstance(r, dict) or not isinstance(r.get("caseId"), str) or not r["caseId"]:
            raise VerifierBlockError(f"case result without a caseId: {r!r}")
        if not r.get("ok"):
            failed.append(r["caseId"])
        elif r.get("scope") == "full":
            passed.append(r["caseId"])
        else:
            warned.append(r["caseId"])
    result = "FAILED" if failed else ("WARNED" if warned else "PASSED")
    block = build_verifier_block(build=build, version=version, vector_set=vector_set,
                                 implementation=implementation)
    predicate: dict = {
        "result": result,
        "configuration": [{
            "name": block["vectorSet"]["name"],
            "digest": dict(block["vectorSet"]["digest"]),
            "annotations": {"cases": block["vectorSet"]["cases"],
                            "implementation": implementation, "version": version,
                            "buildSource": block["build"]["source"]},
        }],
        "passedTests": sorted(passed),
        "warnedTests": sorted(warned),
        "failedTests": sorted(failed),
    }
    if url:
        predicate["url"] = url
    return {
        "_type": STATEMENT_TYPE,
        "subject": [{"name": f"{implementation}-{version}", "digest": dict(block["build"]["digest"])}],
        "predicateType": TEST_RESULT_PREDICATE_TYPE,
        "predicate": predicate,
    }


def validate_test_result_statement(statement: Any) -> list[str]:
    errs: list[str] = []
    if not isinstance(statement, dict):
        return ["statement must be a JSON object"]
    if statement.get("_type") != STATEMENT_TYPE:
        errs.append(f"_type must be {STATEMENT_TYPE!r}")
    if statement.get("predicateType") != TEST_RESULT_PREDICATE_TYPE:
        errs.append(f"predicateType must be {TEST_RESULT_PREDICATE_TYPE!r}")
    subj = statement.get("subject")
    if not (isinstance(subj, list) and len(subj) == 1 and isinstance(subj[0], dict)
            and isinstance(subj[0].get("name"), str) and subj[0]["name"]
            and _is_digest(subj[0].get("digest"))):
        errs.append("subject must be exactly one entry with a name and a sha256 digest (the build)")
    pred = statement.get("predicate")
    if not isinstance(pred, dict):
        return errs + ["predicate must be an object"]
    if not is_member(pred.get("result"), TEST_RESULTS):
        errs.append(f"predicate.result must be one of {sorted(TEST_RESULTS)}")
    conf = pred.get("configuration")
    if not (isinstance(conf, list) and conf and all(
            isinstance(c, dict) and isinstance(c.get("name"), str) and _is_digest(c.get("digest"))
            for c in conf)):
        errs.append("predicate.configuration must be a non-empty list of resource descriptors "
                    "with name and sha256 digest (the vector set)")
    listen_ok = True
    for k in ("passedTests", "warnedTests", "failedTests"):
        v = pred.get(k)
        if k in pred and not (isinstance(v, list) and all(isinstance(x, str) for x in v)):
            errs.append(f"predicate.{k} must be a list of strings")
            listen_ok = False
    if "url" in pred and not (isinstance(pred["url"], str) and pred["url"]):
        errs.append("predicate.url, when present, must be a non-empty string")
    # THE HEADLINE IS DERIVED FROM THE LISTS, NEVER ASSERTED BESIDE THEM (Codex round one on
    # PR 224, P1, measured: `result: PASSED` with `failedTests: ['definitely-failed']` validated
    # clean and could be joined as a passing run). The corpus rule that a skipped check is never
    # a pass is a rule about the LISTS; a result that the lists do not derive is a signed headline
    # contradicted by its own detail. Judged whenever any list is present; a name in two lists is
    # the same contradiction one level down.
    if listen_ok and any(k in pred for k in ("passedTests", "warnedTests", "failedTests")):
        failed = list(pred.get("failedTests") or [])
        warned = list(pred.get("warnedTests") or [])
        passed = list(pred.get("passedTests") or [])
        abgeleitet = "FAILED" if failed else ("WARNED" if warned else "PASSED")
        if is_member(pred.get("result"), TEST_RESULTS) and pred.get("result") != abgeleitet:
            errs.append(f"predicate.result {pred.get('result')!r} contradicts its own case lists, "
                        f"which derive {abgeleitet!r} ({len(failed)} failed, {len(warned)} warned, "
                        f"{len(passed)} passed)")
        alle = passed + warned + failed
        doppelt = sorted({x for x in alle if alle.count(x) > 1})
        if doppelt:
            errs.append(f"a case is listed under more than one outcome: {doppelt}")
    return errs


def test_result_ref(statement: dict) -> dict:
    """The three fields a receipt carries about the separate statement."""
    errs = validate_test_result_statement(statement)
    if errs:
        raise VerifierBlockError("invalid test-result statement: " + "; ".join(errs))
    return {"predicateType": TEST_RESULT_PREDICATE_TYPE,
            "result": statement["predicate"]["result"],
            "statementDigest": {"sha256": statement_digest(statement)}}


def join_test_result(block: dict, statement: dict) -> dict:
    """Does the statement belong to this block? Four equalities, each reported on its own, and
    ``ok`` only when all four hold. A relying party needs no issuer for this join: it recomputes
    the statement digest and compares digests."""
    fehler: list[str] = []
    r: dict[str, Any] = {"subject_matches_build": False, "digest_matches": False,
                         "result_matches": False, "vector_set_matches": False,
                         "ok": False, "errors": fehler}
    if validate_verifier_block(block):
        fehler.append("the block is not a valid verifier block")
        return r
    if "testResult" not in block:
        fehler.append("the block cites no test result -- nothing to join")
        return r
    errs = validate_test_result_statement(statement)
    if errs:
        fehler.extend(errs)
        return r
    r["subject_matches_build"] = statement["subject"][0]["digest"] == block["build"]["digest"]
    r["digest_matches"] = statement_digest(statement) == block["testResult"]["statementDigest"]["sha256"]
    r["result_matches"] = statement["predicate"]["result"] == block["testResult"]["result"]
    # THE FOURTH EQUALITY, and it was missing (un-review 2026-09-18, P1): the statement's
    # configuration names the vector set the run was held against, and the block declares one.
    # Without this comparison a statement over corpus A could be cited beside a block declaring
    # corpus B, and the join would report ok -- a result about the wrong question. Every
    # configuration entry with a digest must match the block's, and there must be one.
    konf = statement["predicate"]["configuration"]
    vs = block["vectorSet"]
    # BOTH HALVES ARE REQUIRED, NOT DEFAULTED (un round 2, 2026-09-18, P1). The first form read
    # `annotations.cases` with the block's own count as the default -- a configuration entry
    # without the annotation matched by construction. A presence-conditional check is an option
    # the producer can decline; this one is not. `validate_test_result_statement` already
    # guarantees a digest per entry, so `c["digest"]` cannot be absent here.
    def _entry_matches(c: dict) -> bool:
        ann = c.get("annotations")
        return (c["digest"] == vs["digest"]
                and isinstance(ann, dict) and ann.get("cases") == vs["cases"])
    r["vector_set_matches"] = bool(konf) and all(_entry_matches(c) for c in konf)
    if not r["subject_matches_build"]:
        fehler.append("the statement's subject is not this block's build digest")
    if not r["digest_matches"]:
        fehler.append("the statement's canonical digest is not the one the block cites")
    if not r["result_matches"]:
        fehler.append("the statement's result is not the one the block cites")
    if not r["vector_set_matches"]:
        fehler.append("the statement's configuration names a vector set that is not the one "
                      "the block declares")
    r["ok"] = bool(r["subject_matches_build"] and r["digest_matches"] and r["result_matches"]
                   and r["vector_set_matches"])
    return r


def sign_test_result_statement(statement: dict, signer, *, keyid: "str | None" = None) -> dict:
    """Wrap the statement in a DSSE envelope -- the same primitive every receipt of this package
    uses, no new crypto. The statement is validated first; an invalid one is not signed."""
    from . import dsse  # noqa: PLC0415
    errs = validate_test_result_statement(statement)
    if errs:
        raise VerifierBlockError("invalid test-result statement: " + "; ".join(errs))
    return dsse.sign_envelope(_rfc8785_bytes(statement), signer,
                              payload_type=INTOTO_STATEMENT_PAYLOAD_TYPE, keyid=keyid)


# ── what a verify result says about the block ─────────────────────────────────────────────────
def report(predicate: Any) -> dict:
    """The verifier's view of the block: present or not, what it names, and whether the build
    running THIS verification is the build the block names.

    ``matches_this_verifier`` has three states and the third is not a pass: MATCH, MISMATCH,
    NOT_EVALUATED (no block, no comparable measurement, or the two builds were measured from
    different sources). It is reported, never folded into ``ok``: a receipt produced by another
    build is not thereby invalid -- it is a receipt whose producer you can now name.
    """
    r: dict = {"present": False, "valid": None, "implementation": None, "version": None,
               "build_digest": None, "build_source": None, "vector_set_digest": None,
               "vector_set_cases": None, "test_result": None,
               "matches_this_verifier": "NOT_EVALUATED", "errors": []}
    if not isinstance(predicate, dict):
        return r
    producer = predicate.get("producer")
    if not isinstance(producer, dict) or "verifier" not in producer:
        return r
    block = producer["verifier"]
    r["present"] = True
    errs = validate_verifier_block(block)
    r["valid"] = not errs
    r["errors"].extend(f"producer.verifier: {e}" for e in errs)
    if errs:
        return r
    r["implementation"] = block["implementation"]
    r["version"] = block["version"]
    r["build_digest"] = block["build"]["digest"]["sha256"]
    r["build_source"] = block["build"]["source"]
    if "vectorSet" in block:
        r["vector_set_digest"] = block["vectorSet"]["digest"]["sha256"]
        r["vector_set_cases"] = block["vectorSet"]["cases"]
    if "testResult" in block:
        r["test_result"] = block["testResult"]["result"]
    try:
        mine = measure_build()
    except Exception:  # noqa: BLE001 -- a verifier that cannot measure itself says so
        return r
    if mine["source"] != r["build_source"]:
        return r
    r["matches_this_verifier"] = "MATCH" if mine["digest"]["sha256"] == r["build_digest"] else "MISMATCH"
    return r
