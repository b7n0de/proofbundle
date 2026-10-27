"""The guard of the strict decoding class: no new lax JSON or CBOR decode site without a named reason.

The strict decoding rule of this repository, stated here (since 2026-10-14): every reader of checked, signed or
evidential bytes in the scope below refuses duplicate keys, invalid encoding and bytes after the value, and a contract
test finds a new decode site that bypasses the strict helpers. Readers outside that scope are named at the end.

WHAT IT READS. The Python source under ``src/``, ``plugins/``, ``tools/`` and ``docs/scitt/``, parsed with ``ast``.
``plugins/`` came into the tree with the plugin line; its strict hooks and its readers outside a verify
path are listed below like every other.

A DECODE REFERENCE, BY A POSITIVE LIST. ``NOT_DECODING`` names the members of ``json`` and ``cbor2`` that do not
decode (the encoders, the tag and simple-value types, the error classes). Every other reference to either library
is a decode reference: ``json.loads`` and ``cbor2.loads`` called or not (``loads = json.loads`` counts where the name
is taken), ``json.JSONDecoder``, ``cbor2.decoder.loads``, a name imported from a decoding member or submodule
(``from cbor2 import decoder``, ``from cbor2.decoder import loads``), ``from json import *``, the module object itself
handed on (``getattr(json, "loads")``), and ``importlib.import_module`` or ``__import__`` of either library. A first
version listed the five lax calls it knew and missed each of these forms, as an adversarial review measured. A call
is strict, and not counted, only when its ``object_pairs_hook=`` names a function of ``STRICT_HOOKS`` that the same
module defines and does not rebind; a name alone, a lambda or an imported hook is counted.

WHAT IT REQUIRES. Every other reference is in ``EXCEPTIONS`` with the exact number per file and a reason outside a
verify path; the one entry on a verify path, the second reader of ``scitt_ccf`` (owner answer B on card
OA-c2b4d6d3e3), carries the reason it may stand there. A new reference turns this red, and so does one that went
away, so the list never outlives what it describes. Each function defined under a name in ``STRICT_HOOKS`` is run on duplicate member names, adjacent and not,
and must refuse each, and an ``assert`` in its body does not count, because ``python -O`` removes it. Where those
functions are defined is listed in ``STRICT_HOOK_SITES``, by the same rule.

TWO TREES. These tests run in a checkout and in the extracted sdist, which ships only part of the scope
(``IN_THE_PACKAGE``). Each listed path is judged on its own: present, it is measured; absent from a checkout, or absent
from a distribution whose MANIFEST.in promises it, it fails; absent from a distribution that does not promise it, it
is NOT MEASURED, as one skip that names it.

THE CBOR2 6 CLASS. Under a tag, at any depth, cbor2 6 returns an array as a tuple and a map as a frozendict, where
cbor2 5 returned a list and a dict (measured with 5.9.0 and 6.1.4; without a tag both return list and dict). A
reader that tests for ``list`` or ``dict`` behind cbor2 is therefore right under one version only. In every module
that imports cbor2, by any form of import, the names ``list``, ``dict``, ``List``, ``Dict``, ``MutableSequence`` and
``MutableMapping`` (also through an alias of an import) may stand only in a call or as its argument (``list(x)``,
``defaultdict(list)``), in an annotation, or in the type argument of ``isinstance``/``issubclass`` together with
``tuple`` or ``Sequence`` (for the sequences) and ``Mapping``, ``frozendict`` or ``FrozenDict`` (for the maps). Every
other place is a finding: ``type(v) is list``, ``isinstance(v, list | None)``, ``case list():``, ``LISTS = (list,)``.

HONEST LIMITS. It reads Python only; the Rust and Go readers are measured by their own runs. It does not see a
hand-written decoder such as ``cbor_min``; those are held by the shared corpus in ``test_strict_cbor``. Code that
reaches a decoder through an object handed in from elsewhere, without importing either library, is not seen, and
neither is a decoder of another library (``orjson``, ``pycose``). A container test by type name (``type(v).__name__``)
or through ``type([])`` is not seen. A hook that refuses on these probes but not on others passes.

OUTSIDE THE SCOPE, and therefore not held here: ``scripts/`` (release and office tooling), ``conformance/``,
``interop/``, ``examples/``, ``fuzz/`` and ``benchmarks/``. Among them are readers of signed bytes:
``scripts/verify_pre_tag_receipt.py`` reads the committed pre-tag receipt with ``json.loads`` before it verifies the
signature, and ``conformance/run_conformance.py`` and ``examples/verdict_contract/check_example.py`` read signed
envelopes the same way. Measured with this file's functions on 2026-10-15: 50 references in 27 files under
``scripts/``, 38 in 6 under ``conformance/``, 8 in 3 under ``interop/``, 7 in 4 under ``examples/``, 1 under ``fuzz/``
and 1 under ``benchmarks/``. Those numbers record that day; nothing holds them, because a count that moves with
unrelated pull requests would turn their work red.
"""
from __future__ import annotations

import ast
import builtins
from collections.abc import Mapping
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
ROOTS = ("src", "plugins", "tools", "docs/scitt")
OUTSIDE = ("scripts", "conformance", "interop", "examples", "fuzz", "benchmarks")


def _im_checkout(repo: Path = REPO) -> bool | None:
    """Repository checkout (True), an extracted sdist (False), or no basis to say (None)? Read from conftest's
    ``baumkontext``, which asks for positive evidence of each tree: a ``.git`` at the root for a checkout, a PKG-INFO
    of this project and no ``.git`` for a distribution (review round 22, R22-2). The first version asked
    ``running_in_repo_checkout``, which reads the absence of three markers as a distribution, and a checkout copy
    without them ran green. Without conftest there is no basis either.

    No path literal of the repository stands here on purpose: conftest's derivation reads such a literal as a module
    that needs the repository and skips the whole module outside a checkout, the tests on planted sources included
    (measured from the extracted sdist on 2026-10-15)."""
    c = _conftest()
    if c is None:
        return None
    art, _why = c.baumkontext(repo)
    return None if art is None else art == "checkout"


# TWO TREES, AND EACH LISTED PATH SAYS WHICH ONE IT IS IN (review round 21, R21-2). Measured on 2026-10-15 in the
# hermetic cleanroom of pull request 352, which runs the shipped suite from the extracted sdist: tools/, docs/scitt/
# and interop/ are not in the distribution, so the listed exceptions had no reference left, one strict hook was found
# instead of three, and interop/ did not exist. A count over that tree measured part of the repository and called it
# the whole. Skipping the tree-wide tests there, the first fix, measured nothing at all, the shipped part included.
#
# So a path is judged by where it is missing:
#   present                                          measured, in both trees;
#   absent from a checkout                           FAIL, a path the guard lists went away;
#   absent from a distribution that promises it      FAIL, the distribution lost it;
#   absent from a distribution that does not         NOT MEASURED, one skip that names the path.
# Whether a distribution promises a path is read from its MANIFEST.in the way conftest reads it for the derived skip
# set (`_manifest_verspricht`, `_manifest_zeilen`), the one reader of the template under tests/. No readable template
# is no basis, and no basis stays loud.
#
# WHICH TREE IT IS needs evidence of its own (review round 22, R22-2): a `.git` at the root for a checkout, a PKG-INFO
# of this project and no `.git` for a distribution, from conftest's `baumkontext`. A tree that shows neither is no
# basis and fails on an absent path. The absence of the paths this guard protects is never read as a distribution.

#: What the distribution carries of the directories this guard names: src/ through the package discovery of
#: pyproject.toml, scripts/ through its explicit list in MANIFEST.in, conformance/ and examples/ through `graft`.
#: Held against MANIFEST.in in both trees, so a change of the packaging shows here.
IN_THE_PACKAGE = {"src", "scripts", "conformance", "examples"}

#: A root this guard reads that is not in the tree yet, with the reason. It is NOT MEASURED until it lands, and the
#: day it lands its entry turns red, so the list never outlives what it describes. Found by the presence test below:
#: before it, a root that did not exist was passed over in silence.
NOT_YET_IN_THE_TREE: dict = {}


def _conftest():
    try:
        import conftest  # noqa: PLC0415
    except Exception:  # noqa: BLE001
        return None
    return conftest


def _promised(rel: str, repo: Path = REPO, directory: bool = False) -> bool | None:
    """Does the distribution at ``repo`` promise this file, or a file under this directory? None: no basis to say.

    A file is asked of conftest's ``_manifest_verspricht``, a directory of its ``_manifest_verspricht_verzeichnis``,
    which reads the template the same way and matches with the same glob (review round 22, R22-3). The first form here
    compared the segments of a line with those of the directory literally, so ``graft inter*`` did not promise
    ``interop``, although setuptools ships it."""
    c = _conftest()
    if c is None:
        return None
    if not (repo / "MANIFEST.in").is_file():
        return None
    if not directory:
        return c._manifest_verspricht(rel, repo)
    return c._manifest_verspricht_verzeichnis(rel, repo)


def _absent(rel: str, *, repo: Path = REPO, in_checkout: bool | None = None, directory: bool = False) -> tuple:
    """("FAIL", why) or ("NOT MEASURED", why) for a listed path that is absent from ``repo``. ``in_checkout`` None asks
    the tree; a tree that shows neither kind fails, because only a distribution may leave a path unmeasured."""
    if in_checkout is None:
        in_checkout = _im_checkout(repo)
    if in_checkout is None:
        c = _conftest()
        why = c.baumkontext(repo)[1] if c is not None else "conftest cannot be imported"
        return "FAIL", f"{rel} is absent and this tree shows neither a checkout nor a distribution: {why}"
    if in_checkout:
        return "FAIL", f"{rel} is absent from the checkout: a path this guard lists went away"
    promised = _promised(rel, repo, directory)
    if promised is None:
        return "FAIL", (f"{rel} is absent and this tree has no readable MANIFEST.in to tell a pruned path from a "
                        "lost one")
    if promised:
        return "FAIL", f"{rel} is absent although MANIFEST.in promises it: the distribution lost it"
    return "NOT MEASURED", f"{rel} is not shipped, MANIFEST.in does not promise it, so this tree cannot measure it"


def _directory_present_or_skip(top: str, *, repo: Path = REPO, in_checkout: bool | None = None,
                               not_yet: Mapping = NOT_YET_IN_THE_TREE) -> None:
    """A directory this guard names: one not in the tree yet is NOT MEASURED and fails once it is there, every
    other one is judged as any listed path."""
    if top in not_yet:
        if (repo / top).exists():
            pytest.fail(f"{top}/ is in the tree now: remove it from NOT_YET_IN_THE_TREE")
        pytest.skip(f"NOT MEASURED: {top}/ is not in this tree yet, {not_yet[top]}")
    _present_or_skip(top, repo=repo, in_checkout=in_checkout, directory=True)


def _present_or_skip(rel: str, *, repo: Path = REPO, in_checkout: bool | None = None,
                     directory: bool = False) -> None:
    path = repo / rel
    if path.is_dir() if directory else path.is_file():
        return
    verdict, why = _absent(rel, repo=repo, in_checkout=in_checkout, directory=directory)
    if verdict == "FAIL":
        pytest.fail(why)
    pytest.skip(f"NOT MEASURED: {why}")

#: json hooks that refuse a duplicate member name; every function defined under one of these names is run below.
STRICT_HOOKS = {"_reject_duplicate_keys", "no_duplicate_members",
                # the plugin's own: the gate's reader of evidence and of the declaration, the key signer's statement
                "_unique_pairs", "_no_duplicates", "_no_repeated_key"}

#: path -> number of functions defined there under a name of STRICT_HOOKS
STRICT_HOOK_SITES = {
    "src/proofbundle/_strict_json.py": 1,
    "tools/scitt_ccf_datahash_vector/json_strict.py": 1,
    "docs/scitt/statement_identification/package/verify.py": 1,
    "plugins/proofbundle/hooks/proofbundle_gate.py": 2,
    "plugins/proofbundle/pilot/key_signer.py": 1,
    "plugins/proofbundle/pilot/pilot_records.py": 1,
}

#: The members of each library that do not decode. Everything else the library has is a decode reference.
NOT_DECODING = {
    "json": {"dumps", "dump", "JSONEncoder", "JSONDecodeError"},
    "cbor2": {"dumps", "dump", "CBOREncoder", "CBORTag", "CBORSimpleValue", "undefined", "CBORError",
              "CBORDecodeError", "CBOREncodeError", "CBORDecodeValueError", "CBORDecodeEOF", "CBOREncodeTypeError",
              "CBOREncodeValueError", "FrozenDict"},
}

#: path -> (number of lax decode references, reason they lie outside a verify path, or for the second reader of
#: scitt_ccf the reason it may stand on one)
EXCEPTIONS = {
    "src/proofbundle/adapters/eee.py": (1, "reads the JSON schema file this package ships, not input"),
    "src/proofbundle/_scitt_second_reader.py": (
        2, "the second reader of scitt_ccf (ADR 0009, Decision 13): cbor2 reads only bytes the strict pre-scan of "
           "_cbor_prescan has already accepted, and must read the same values; a refusal of cbor2 or another value "
           "is a refusal, and cbor2 decides nothing alone (owner answer B on card OA-c2b4d6d3e3)"),
    "src/proofbundle/trust_pack.py": (1, "reads back the RFC 8785 bytes it just wrote from an already parsed object"),
    "tools/cap1_unabhaengige_umsetzung/lauf.py": (
        2, "measures the last-wins and first-wins readings of CAP-1 on purpose; the verdict table is the result"),
    "tools/cap1_unabhaengige_umsetzung/py/cap1_verify.py": (
        1, "the independent CAP-1 implementation, frozen at 8b581d7 by tests/test_cap1_teil_c_sonden.py; its command "
           "line is the last-wins reading that lauf.py and the README of that directory measure next to the strict one"),
    "tools/cap1_unabhaengige_umsetzung/sonden.py": (
        2, "builds the duplicate-key probes from the author's vectors; it writes test input, it judges nothing"),
    "tools/capability_matrix/measure.py": (
        6, "measurement harness: reads its own run outputs and the PyPI index, every verdict comes from the verifier"),
    "tools/merkle_accumulator/accumulator.py": (
        1, "reads back the canonical bytes of a state whose signature was verified one line before"),
    "tools/merkle_accumulator/render_runs.py": (1, "renders recorded run summaries for reading, decides nothing"),
    "tools/pb_verify_rs/crosscheck.py": (
        20, "differential harness: the verdicts compared are those of the Python and the Rust verifier; two sites "
            "under the alias _json build its own test inputs; four read the shared Transparent Statement and "
            "consistency receipt vectors and the Rust verifier's JSON result over them, which hold CBOR integers past "
            "the I-JSON range (a receipt iat of 2^64 - 1) that loads_strict refuses"),
    "tools/scitt_ccf_datahash_vector/reader_matrix.py": (
        2, "measures cbor2 itself: what the library accepts is the result"),
    # The measurement harnesses of tools/scitt_ccf_external, named when the scitt-ccf reader joined the strict rule
    # (owner answer B on card OA-c2b4d6d3e3). None is a verify path of the package: each reads its own run files,
    # corpora, stored results or the output of a tool it runs, and records a measurement, for some a verdict of
    # proofbundle.scitt_ccf, for others what a library or an independent transcription accepts.
    "tools/scitt_ccf_external/consistency_probe.py": (
        9, "measurement harness of consistency receipts: reads the output of the third-party Merkle oracle it runs, its "
           "own run files and stored result, the example bundle, and the service's receipts and proofs with cbor2 to "
           "rebuild them for its probes"),
    "tools/scitt_ccf_external/consistency_receipt_vectors.py": (
        1, "writes the shared consistency receipt vectors and reads them back for --check; they hold CBOR integers "
           "past the I-JSON range (an iat of 2^64 - 1) that loads_strict refuses, and the one other file it reads "
           "goes through loads_strict"),
    "tools/scitt_ccf_external/differential_corpus.py": (
        8, "builds and re-derives the differential corpus: reads the local ledger's configuration, version and quote "
           "responses, its own manifest and records, the example bundle and the build inputs, and the first receipt of "
           "a returned statement with cbor2 to store it"),
    "tools/scitt_ccf_external/differential_corpus_round2.py": (
        5, "round two of the differential corpus: reads its own manifest and records, the example bundle and the "
           "build inputs"),
    "tools/scitt_ccf_external/leafhash/measure.py": (
        2, "measures the leaf hash of a local ledger: reads the receipts its run wrote with cbor2 to take their proofs "
           "apart, and judges nothing"),
    "tools/scitt_ccf_external/leafhash/reader_forgery.py": (
        2, "builds forgery inputs for readers: reads its own input file and a receipt its run wrote; what the readers "
           "accept is the result"),
    "tools/scitt_ccf_external/leafhash/same_digests.py": (
        1, "reads the stored consistency result of its directory to compare digests"),
    "tools/scitt_ccf_external/local_ledger_probe.py": (
        2, "registers the example bundle on a local ledger: reads the example bundle and the build inputs it is given"),
    "tools/scitt_ccf_external/preimage_candidates.py": (
        6, "computes candidate preimages of the data-hash: reads stored receipts and requests with cbor2 to re-encode "
           "them, and its own manifest and records"),
    "tools/scitt_ccf_external/reader_crosscheck.py": (
        27, "measures cbor2 and pycose themselves against real statements: what each library accepts is the result"),
    "tools/scitt_ccf_external/recompute.py": (
        1, "reads its trust-store document strictly with its own hook `_no_duplicate_keys`, a name STRICT_HOOKS does "
           "not list"),
    "tools/scitt_ccf_external/rust_crosscheck.py": (
        2, "differential harness: reads the stored vector and the JSON output of the Rust verifier it compares"),
    "tools/scitt_ccf_external/section4_reader_go/run_section4.py": (
        1, "runs the Go reader of section 4 (pull request 411) on the vectors and prints a table: reads each vector "
           "file; the verdicts printed are the Go reader's"),
    "tools/scitt_ccf_external/section4_vectors/check_vectors.py": (
        11, "the independent checker of the section 4 vectors (pull request 411), written from the text of -05 "
            "without proofbundle: it decodes the stored receipts and proofs with cbor2 and reads the vector files and "
            "their manifest; its readings A and B are its own, held beside the reader's by "
            "tests/test_scitt_ccf_section4_vectors.py"),
    "tools/scitt_ccf_external/section4_vectors/generate_vectors.py": (
        13, "generator of the section 4 vectors (pull request 411): reads the ledger fixture and its leaves and "
            "decodes the receipts and proofs of that fixture and of the receipts it has just built; it writes test "
            "input and judges nothing"),
    "tools/scitt_ccf_external/transparent_statement_vectors.py": (
        1, "writes the shared Transparent Statement vectors and reads them back for --check; they hold CBOR integers "
           "past the I-JSON range (a receipt iat of 2^64 - 1) that loads_strict refuses, and every other file it "
           "reads goes through loads_strict"),
    "tools/scitt_ccf_external/vendored_encoder_probe.py": (
        3, "reads its own manifest, records and stored result to hold them to the corpus, offline"),
    "docs/scitt/statement_identification/package/build.py": (
        3, "producer of the package: reads back the statements it has just built"),
    "docs/scitt/statement_identification/package/verify.py": (
        4, "standalone checker for external readers; every cbor2 call runs behind its own pre-scan item_end, "
           "which refuses duplicate keys and bytes after the item, and decodes each map once more to refuse one that "
           "cbor2 reads with fewer entries than it has pairs; its decoding is held by test_strict_cbor"),
    # The plugin. Its readers of evidence, of the declaration and of a statement to sign are strict
    # (the hooks above); the receipts of the pilot are read strictly by pilot_records.py and the kept profile.
    "plugins/proofbundle/evals/_fixtures/make.py": (
        1, "builds the eval fixtures from the package's own template output; it judges nothing"),
    "plugins/proofbundle/evals/corpus_codex_hooks.py": (
        1, "eval harness: reads the replies of the Codex app server it drives; the verdicts are the gate's"),
    "plugins/proofbundle/hooks/proofbundle_answered.py": (
        3, "reads its own two state files in the plugin data folder and the host's hook event; no signed bytes"),
    "plugins/proofbundle/hooks/proofbundle_gate.py": (
        5, "reads the gate's own files (the work folders, the state of the autonomous answer, its log for the "
           "bilanz), the reasons the house form checker prints and the host's transcript; the evidence, the "
           "declaration and the done order go through strict_json, parse_declaration and parse_done"),
    "plugins/proofbundle/hooks/proofbundle_secrets.py": (
        1, "reads the host's hook event to compare the paths it names; it opens no file"),
    "plugins/proofbundle/pilot/key_signer.py": (
        2, "reads its configuration and the service's request; the statement it signs is decoded with "
           "_no_repeated_key before it signs"),
    "plugins/proofbundle/pilot/probe_signer.py": (
        1, "the probe signer of the tests, with keys from public labels; reads the request it is handed"),
    "plugins/proofbundle/pilot/signer_service.py": (
        2, "reads its configuration, the start file of the records and the request; the event and the statement "
           "are decoded again with the gate's strict_json, and it signs only the bytes of its own decision"),
    "plugins/proofbundle/server/proofbundle_mcp.py": (
        3, "reads the host's JSON-RPC messages, the gate's log lines and the package's own JSON output; every "
           "verdict is the package's"),
}

_SEQ, _MAP = {"tuple", "Sequence"}, {"Mapping", "frozendict", "FrozenDict"}
_TYPE_PARTNERS = {"list": _SEQ, "List": _SEQ, "MutableSequence": _SEQ,
                  "dict": _MAP, "Dict": _MAP, "MutableMapping": _MAP}
#: The modules a container type name can be imported from under another name.
_TYPE_MODULES = {"typing", "collections.abc", "builtins"}


def _library(module: str | None) -> str | None:
    top = (module or "").split(".")[0]
    return top if top in NOT_DECODING else None


def _aliases(tree: ast.AST) -> dict:
    """local name -> (library, member path or None for the library itself), for json and cbor2."""
    out: dict = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                lib = _library(a.name)
                if lib is None:
                    continue
                if a.asname is None:
                    out[a.name.split(".")[0]] = (lib, None)
                else:
                    out[a.asname] = (lib, a.name.split(".", 1)[1] if "." in a.name else None)
        elif isinstance(node, ast.ImportFrom) and _library(node.module):
            lib = _library(node.module)
            sub = node.module.split(".", 1)[1] if "." in node.module else None
            for a in node.names:
                if a.name != "*":
                    out[a.asname or a.name] = (lib, f"{sub}.{a.name}" if sub else a.name)
    return out


def _decoding(lib: str, member: str | None) -> bool:
    """A member decodes unless the name it ends in is one of NOT_DECODING: ``json.decoder.JSONDecodeError`` does not,
    ``json.decoder`` and ``cbor2.decoder.loads`` do."""
    return member is not None and member.split(".")[-1] not in NOT_DECODING[lib]


def _parents(tree: ast.AST) -> dict:
    return {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}


def _local_hooks(tree: ast.AST) -> set:
    """The names of STRICT_HOOKS this module defines as a function and never binds otherwise."""
    defined = {n.name for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name in STRICT_HOOKS}
    rebound = {t.id for n in ast.walk(tree) if isinstance(n, (ast.Assign, ast.AnnAssign, ast.AugAssign))
               for t in (n.targets if isinstance(n, ast.Assign) else [n.target]) if isinstance(t, ast.Name)}
    imported = {a.asname or a.name for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom)) for a in n.names}
    return defined - rebound - imported


def _strict_call(call: ast.AST | None, local_hooks: set = frozenset()) -> bool:
    if not isinstance(call, ast.Call):
        return False
    for kw in call.keywords:
        if kw.arg == "object_pairs_hook":
            return isinstance(kw.value, ast.Name) and kw.value.id in local_hooks
    return False


def _is_func_of(node: ast.AST, parent: ast.AST | None) -> bool:
    return isinstance(parent, ast.Call) and parent.func is node


def _import_call(node: ast.AST) -> str | None:
    """'cbor2' for importlib.import_module('cbor2') or __import__('cbor2...'), else None."""
    if not (isinstance(node, ast.Call) and isinstance(node.func, (ast.Name, ast.Attribute)) and node.args):
        return None
    name = node.func.id if isinstance(node.func, ast.Name) else node.func.attr
    arg = node.args[0]
    if name in ("import_module", "__import__") and isinstance(arg, ast.Constant) and isinstance(arg.value, str):
        return arg.value if _library(arg.value) else None
    return None


def sites(source: str) -> list:
    """The lax decode references of one module, as (line, what)."""
    tree = ast.parse(source)
    aliases, parents, hooks = _aliases(tree), _parents(tree), _local_hooks(tree)
    out = []
    for node in ast.walk(tree):
        imported = _import_call(node)
        if imported:
            out.append((node.lineno, f"import of {imported}"))
        elif isinstance(node, ast.ImportFrom) and _library(node.module) and any(a.name == "*" for a in node.names):
            out.append((node.lineno, f"from {node.module} import *"))
        elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) and node.value.id in aliases:
            lib, member = aliases[node.value.id]
            path = f"{member}.{node.attr}" if member else node.attr
            if _decoding(lib, path) and not (_is_func_of(node, parents.get(node)) and _strict_call(parents[node], hooks)):
                out.append((node.lineno, f"{lib}.{path}"))
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load) and node.id in aliases:
            lib, member = aliases[node.id]
            parent = parents.get(node)
            if isinstance(parent, ast.Attribute) and parent.value is node:
                continue                          # judged above, with the whole member path
            if member is None:
                out.append((node.lineno, f"{lib} handed on"))
            elif _decoding(lib, member) and not (_is_func_of(node, parent) and _strict_call(parent, hooks)):
                out.append((node.lineno, f"{lib}.{member}"))
    return sorted(out)


def _imports_cbor2(tree: ast.AST) -> bool:
    if any(lib == "cbor2" for lib, _ in _aliases(tree).values()):
        return True
    return any(_library(_import_call(n)) == "cbor2" for n in ast.walk(tree))


def _annotation_nodes(tree: ast.AST) -> set:
    roots = []
    for node in ast.walk(tree):
        if isinstance(node, ast.arg) and node.annotation is not None:
            roots.append(node.annotation)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.returns is not None:
            roots.append(node.returns)
        elif isinstance(node, ast.AnnAssign):
            roots.append(node.annotation)
    return {n for r in roots for n in ast.walk(r)}


def _type_aliases(tree: ast.AST) -> tuple:
    """(local name -> container type name for `from typing import Dict as D`, names bound to the builtins module)."""
    names, builtins_names = {}, set()
    for n in ast.walk(tree):
        if isinstance(n, ast.ImportFrom) and n.module in _TYPE_MODULES:
            for a in n.names:
                if a.name in _TYPE_PARTNERS:
                    names[a.asname or a.name] = a.name
        elif isinstance(n, ast.Import):
            for a in n.names:
                if a.name == "builtins":
                    builtins_names.add(a.asname or a.name)
    return names, builtins_names


def _type_name(node: ast.AST, names: dict = None, builtins_names: set = frozenset({"builtins"})) -> str | None:
    names = names or {}
    if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
        if node.id in _TYPE_PARTNERS:
            return node.id
        return names.get(node.id)
    if isinstance(node, ast.Attribute) and node.attr in ("List", "Dict", "MutableSequence", "MutableMapping"):
        return node.attr
    if (isinstance(node, ast.Attribute) and node.attr in ("list", "dict") and isinstance(node.value, ast.Name)
            and node.value.id in builtins_names | {"builtins"}):
        return node.attr
    return None


def _an_argument(node: ast.AST, parent: ast.AST | None) -> bool:
    """`defaultdict(list)`, `field(default_factory=list)`, `dict.fromkeys(k)`: the type is used, not tested."""
    if isinstance(parent, ast.Call) and not (isinstance(parent.func, ast.Name)
                                             and parent.func.id in ("isinstance", "issubclass")):
        return node in parent.args
    if isinstance(parent, ast.keyword):
        return True
    return isinstance(parent, ast.Attribute) and parent.value is node


def _names_in(node: ast.AST) -> set:
    return {n.id if isinstance(n, ast.Name) else n.attr for n in ast.walk(node)
            if isinstance(n, (ast.Name, ast.Attribute))}


def container_checks(source: str) -> list:
    """Lines where ``list``/``dict`` (or ``List``/``Dict``) stand outside a call, an annotation and an
    ``isinstance``/``issubclass`` that also names the cbor2 6 partner type, in a module that imports cbor2."""
    tree = ast.parse(source)
    if not _imports_cbor2(tree):
        return []
    parents, annotations = _parents(tree), _annotation_nodes(tree)
    names, builtins_names = _type_aliases(tree)
    out = []
    for node in ast.walk(tree):
        name = _type_name(node, names, builtins_names)
        parent = parents.get(node)
        if name is None or node in annotations or _is_func_of(node, parent) or _an_argument(node, parent):
            continue
        cur, ok = node, False
        while cur in parents:
            up = parents[cur]
            if (isinstance(up, ast.Call) and isinstance(up.func, ast.Name)
                    and up.func.id in ("isinstance", "issubclass") and len(up.args) == 2 and up.args[1] is cur):
                ok = bool(_TYPE_PARTNERS[name] & _names_in(cur))
                break
            cur = up
        if not ok:
            out.append(node.lineno)
    return sorted(set(out))


def _unlisted_hook_sites(hooks: list, sites: Mapping = STRICT_HOOK_SITES) -> list:
    return sorted({rel for rel, _ in hooks} - set(sites))


def _hook_definitions(source: str) -> list:
    return [n for n in ast.walk(ast.parse(source)) if isinstance(n, ast.FunctionDef) and n.name in STRICT_HOOKS]


#: Inputs a strict hook must refuse: the same name twice with the same and with another value, a duplicate that is not
#: adjacent, and one among more pairs.
DUPLICATE_PROBES = ([("a", 1), ("a", 1)], [("a", 1), ("a", 2)], [("a", 1), ("b", 2), ("a", 3)],
                    [("x", 0), ("y", 0), ("z", 0), ("y", 1)])
UNIQUE_PROBE = [("a", 1), ("b", 2), ("c", 3)]


def hook_refuses_a_duplicate(node: ast.FunctionDef, where: str) -> tuple:
    """Run one hook definition on its own: -> (refuses every input of DUPLICATE_PROBES, what it returns for
    UNIQUE_PROBE, whether its body uses `assert`). A name the hook reads from its module is bound to a fresh exception
    class, so a hook that raises its module's error still raises."""
    params = {a.arg for a in node.args.args}
    stored = {n.id for n in ast.walk(node) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)}
    free = {n.id for n in ast.walk(node) if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load)} - params - stored
    namespace: dict = {n: type(n, (ValueError,), {}) for n in free if not hasattr(builtins, n)}
    exec(compile(ast.Module(body=[node], type_ignores=[]), where, "exec"), namespace)  # noqa: S102 - this repo's code
    hook = namespace[node.name]

    def refuses(pairs):
        try:
            hook(pairs)
        except Exception:  # noqa: BLE001 - any refusal counts, its kind belongs to the module
            return True
        return False

    uses_assert = any(isinstance(n, ast.Assert) for n in ast.walk(node))
    return all(refuses(p) for p in DUPLICATE_PROBES), hook(list(UNIQUE_PROBE)), uses_assert


def _sources(roots=ROOTS, repo=REPO):
    for root in roots:
        base = repo / root
        if base.is_dir():
            for path in sorted(base.rglob("*.py")):
                yield path.relative_to(repo).as_posix(), path.read_text(encoding="utf-8")


def _measure(repo=REPO):
    found, type_findings, hooks = {}, {}, []
    for rel, source in _sources(repo=repo):
        s = sites(source)
        if s:
            found[rel] = s
        t = container_checks(source)
        if t:
            type_findings[rel] = t
        hooks.extend((rel, node) for node in _hook_definitions(source))
    return found, type_findings, hooks


@pytest.mark.parametrize("top", ROOTS + OUTSIDE)
def test_each_directory_the_guard_names_is_present_or_not_shipped(top):
    """In a checkout every root and every directory named outside the scope exists. In a distribution each one
    exists exactly when MANIFEST.in promises it; one it does not promise is NOT MEASURED, by name."""
    _directory_present_or_skip(top)


@pytest.mark.parametrize("top", ROOTS + OUTSIDE)
def test_in_the_package_states_what_the_distribution_promises(top):
    assert _promised(top, directory=True) is (top in IN_THE_PACKAGE), top


def test_no_lax_decode_reference_without_a_named_reason():
    found, _, _ = _measure()
    assert found, "the guard found no decode reference at all, so it measured nothing"
    new = {rel: s for rel, s in found.items() if rel not in EXCEPTIONS}
    assert not new, f"lax decode references without a named reason, use a strict helper: {new}"


@pytest.mark.parametrize("rel", sorted(EXCEPTIONS))
def test_every_listed_exception_has_exactly_its_count(rel):
    _present_or_skip(rel)
    found, listed = len(sites((REPO / rel).read_text(encoding="utf-8"))), EXCEPTIONS[rel][0]
    assert found == listed, (f"the number of lax references in {rel} changed, (found, listed): ({found}, {listed}); "
                             "a file with none left is removed from EXCEPTIONS")


def test_behind_cbor2_every_container_check_holds_under_cbor2_5_and_6():
    _, type_findings, _ = _measure()
    assert not type_findings, ("list or dict behind cbor2 outside a call, an annotation and an isinstance with "
                               f"tuple or Mapping (cbor2 6 returns tuples and frozendicts under a tag): {type_findings}")


def test_every_strict_hook_defined_in_the_scope_refuses_a_duplicate_member_name():
    _, _, hooks = _measure()
    assert hooks, "the guard found no strict hook definition at all, so it measured nothing"
    unlisted = _unlisted_hook_sites(hooks)
    assert not unlisted, f"strict hooks defined outside STRICT_HOOK_SITES, add them there: {unlisted}"
    for rel, node in hooks:
        refuses, result, uses_assert = hook_refuses_a_duplicate(node, rel)
        assert refuses, f"{rel}:{node.lineno} {node.name} does not refuse every duplicate member name"
        assert not uses_assert, f"{rel}:{node.lineno} {node.name} refuses with assert, which python -O removes"
        assert isinstance(result, Mapping) and dict(result) == dict(UNIQUE_PROBE), f"{rel}:{node.lineno} {node.name}"


@pytest.mark.parametrize("rel", sorted(STRICT_HOOK_SITES))
def test_every_listed_strict_hook_is_defined_where_it_is_listed(rel):
    _present_or_skip(rel)
    found = len(_hook_definitions((REPO / rel).read_text(encoding="utf-8")))
    listed = STRICT_HOOK_SITES[rel]
    assert found == listed, f"{rel} defines {found} strict hooks, STRICT_HOOK_SITES lists {listed}"


_PYPROJECT = '[project]\nname = "planted"\n\n[tool.setuptools.packages.find]\nwhere = ["src"]\n'


@pytest.mark.parametrize("in_checkout, manifest, rel, directory, verdict", [
    # The full source tree: an absent path is a failure, whatever the template says.
    (True, "prune tools\n", "tools/a.py", False, "FAIL"),
    (True, "prune interop\n", "interop", True, "FAIL"),
    # A distribution: a path its template promises and that is absent was lost.
    (False, "graft tools\n", "tools/a.py", False, "FAIL"),
    (False, "include scripts/a.py\n", "scripts/a.py", False, "FAIL"),
    (False, "include scripts/a.py\n", "scripts", True, "FAIL"),
    (False, "graft docs\n", "docs/scitt", True, "FAIL"),
    (False, "recursive-include docs *.md\n", "docs/scitt", True, "FAIL"),
    (False, "global-include *.py\n", "plugins", True, "FAIL"),
    (False, "", "src/pkg/a.py", False, "FAIL"),
    (False, "", "src", True, "FAIL"),
    # ... and a path it does not promise is not shipped.
    (False, "prune tools\n", "tools/a.py", False, "NOT MEASURED"),
    (False, "include scripts/a.py\n", "scripts/b.py", False, "NOT MEASURED"),
    (False, "graft docs/readiness_pack\n", "docs/scitt", True, "NOT MEASURED"),
    (False, "include docs/x.md\n", "docs/scitt", True, "NOT MEASURED"),
    (False, "prune interop\n", "interop", True, "NOT MEASURED"),
    # Without a template there is no basis, and no basis stays loud.
    (False, None, "tools/a.py", False, "FAIL"),
    (False, None, "interop", True, "FAIL"),
])
def test_both_trees_an_absent_path_is_judged_by_where_it_is_missing(tmp_path, in_checkout, manifest, rel,
                                                                    directory, verdict):
    """The rule of the two trees on planted trees, so that both ways run in either tree: a path that really went
    away from the full source tree still fails, and only a path the distribution never promised is NOT MEASURED."""
    (tmp_path / "pyproject.toml").write_text(_PYPROJECT, encoding="utf-8")
    if manifest is not None:
        (tmp_path / "MANIFEST.in").write_text(manifest, encoding="utf-8")
    assert _absent(rel, repo=tmp_path, in_checkout=in_checkout, directory=directory)[0] == verdict


def _tree(tmp_path, *, git: str | None = None, pkg_info_name: str | None = None) -> Path:
    """A planted tree: pyproject.toml of the project ``planted`` and a template that does not promise tools/, with a
    ``.git`` directory or worktree file and a PKG-INFO as asked."""
    (tmp_path / "pyproject.toml").write_text(_PYPROJECT, encoding="utf-8")
    (tmp_path / "MANIFEST.in").write_text("prune tools\n", encoding="utf-8")
    if git == "directory":
        (tmp_path / ".git").mkdir()
    elif git == "worktree file":
        (tmp_path / ".git").write_text("gitdir: /elsewhere/.git/worktrees/planted\n", encoding="utf-8")
    if pkg_info_name is not None:
        (tmp_path / "PKG-INFO").write_text(f"Metadata-Version: 2.1\nName: {pkg_info_name}\n", encoding="utf-8")
    return tmp_path


@pytest.mark.parametrize("git, pkg_info_name, verdict, words", [
    # Review round 22, R22-2: a checkout without .github/, tools/ and SPEC.md is still a checkout, a worktree too.
    ("directory", None, "FAIL", "went away"),
    ("worktree file", None, "FAIL", "went away"),
    # A distribution shows itself by its PKG-INFO; only there is a path the template does not promise unmeasured.
    (None, "planted", "NOT MEASURED", "not shipped"),
    (None, "Planted", "NOT MEASURED", "not shipped"),
    # No evidence, the evidence of another project, or evidence of both: no basis, and no basis stays loud.
    (None, None, "FAIL", "neither a checkout nor a distribution"),
    (None, "other-project", "FAIL", "neither a checkout nor a distribution"),
    ("directory", "planted", "FAIL", "neither a checkout nor a distribution"),
])
def test_both_trees_the_kind_of_tree_needs_evidence_and_the_absence_of_markers_is_none(tmp_path, git, pkg_info_name,
                                                                                      verdict, words):
    """None of these trees carries .github/, tools/ or SPEC.md, the markers whose absence the first version read as a
    distribution. The verdict on the absent tools/ follows what the tree shows of itself."""
    tree = _tree(tmp_path, git=git, pkg_info_name=pkg_info_name)
    got, why = _absent("tools", repo=tree, directory=True)
    assert (got, words in why) == (verdict, True), why


def test_both_trees_a_real_git_checkout_without_the_markers_fails_on_an_absent_path(tmp_path):
    """The same with a repository git itself initialised, so the evidence is the one a real checkout carries."""
    import shutil  # noqa: PLC0415
    import subprocess  # noqa: PLC0415

    if shutil.which("git") is None:
        pytest.skip("NOT MEASURED: no git on this machine")
    tree = _tree(tmp_path)
    subprocess.run(["git", "init", "-q", str(tree)], check=True, capture_output=True, timeout=60)
    got, why = _absent("tools", repo=tree, directory=True)
    assert got == "FAIL" and "went away" in why, why


_DIRECTORY_VECTORS = Path(__file__).parent / "fixtures" / "manifest_semantics" / "verzeichnisse.json"


@pytest.mark.parametrize("case", ["graft_star", "graft_question_mark", "recursive_include_star",
                                  "include_star_directory", "graft_literal"])
def test_both_trees_a_directory_a_glob_promised_and_that_went_missing_fails(tmp_path, case):
    """Review round 22, R22-3, on the trees a real sdist was: the files setuptools shipped for the template (recorded
    in verzeichnisse.json by tests/fixtures/manifest_semantics/erzeuge_vektoren.py), with its PKG-INFO, and then
    interop/ removed. A glob that promised interop/ makes its loss a failure; a directory no line promises stays NOT
    MEASURED, and the intact tree measures interop/."""
    import json  # noqa: PLC0415

    fall = json.loads(_DIRECTORY_VECTORS.read_text(encoding="utf-8"))["cases"][case]
    for rel in fall["shipped"]:
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text("x\n", encoding="utf-8")
    (tmp_path / "MANIFEST.in").write_text(fall["template"], encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(fall["pyproject"], encoding="utf-8")
    (tmp_path / "PKG-INFO").write_text("Metadata-Version: 2.1\nName: vektorprojekt\n", encoding="utf-8")
    assert _outcome(lambda: _present_or_skip("interop", repo=tmp_path, directory=True)) == "MEASURED"
    for rel in [r for r in fall["shipped"] if r.startswith("interop/")]:
        (tmp_path / rel).unlink()
    for d in sorted({p for p in tmp_path.rglob("*") if p.is_dir() and "interop" in p.parts}, reverse=True):
        d.rmdir()
    got, why = _absent("interop", repo=tmp_path, directory=True)
    assert got == "FAIL" and "promises it" in why, why
    assert _absent("outside", repo=tmp_path, directory=True)[0] == "NOT MEASURED"


def test_this_tree_shows_which_kind_it_is():
    """The guard's own tree must show one kind: a checkout by its .git, the extracted sdist by its PKG-INFO. Without
    that, every absent path here would fail, and the shipped suite with it."""
    c = _conftest()
    assert c is not None
    art, why = c.baumkontext(REPO)
    assert art in ("checkout", "distribution"), why


def _outcome(call) -> str:
    """MEASURED, FAIL or SKIP with the message. A skip is caught here as a value: raised out of a test, it would
    turn that test into a skip, and a helper that skips where it should fail would pass unseen (measured with the
    mutant that drops the fail branch of _present_or_skip)."""
    try:
        call()
    except pytest.fail.Exception as exc:
        return f"FAIL {exc}"
    except pytest.skip.Exception as exc:
        return f"SKIP {exc}"
    return "MEASURED"


def test_both_trees_a_present_path_is_measured_and_an_absent_one_is_failed_or_skipped(tmp_path):
    (tmp_path / "pyproject.toml").write_text(_PYPROJECT, encoding="utf-8")
    (tmp_path / "MANIFEST.in").write_text("include scripts/a.py\n", encoding="utf-8")
    (tmp_path / "tools").mkdir()
    (tmp_path / "tools" / "a.py").write_text("", encoding="utf-8")
    got = [_outcome(lambda: _present_or_skip("tools/a.py", repo=tmp_path, in_checkout=False)),
           _outcome(lambda: _present_or_skip("tools", repo=tmp_path, in_checkout=False, directory=True)),
           _outcome(lambda: _present_or_skip("scripts/a.py", repo=tmp_path, in_checkout=False)),
           _outcome(lambda: _present_or_skip("interop", repo=tmp_path, in_checkout=False, directory=True)),
           _outcome(lambda: _present_or_skip("interop", repo=tmp_path, in_checkout=True, directory=True))]
    assert got[:2] == ["MEASURED", "MEASURED"]
    assert got[2].startswith("FAIL ") and "promises it" in got[2], got[2]
    assert got[3].startswith("SKIP NOT MEASURED: interop is not shipped"), got[3]
    assert got[4].startswith("FAIL ") and "went away" in got[4], got[4]


@pytest.mark.parametrize("in_checkout", [True, False])
def test_a_root_not_in_the_tree_yet_is_not_measured_and_fails_once_it_lands(tmp_path, in_checkout):
    not_yet = {"plugins": "planted reason"}
    before = _outcome(lambda: _directory_present_or_skip("plugins", repo=tmp_path, in_checkout=in_checkout,
                                                         not_yet=not_yet))
    (tmp_path / "plugins").mkdir()
    after = _outcome(lambda: _directory_present_or_skip("plugins", repo=tmp_path, in_checkout=in_checkout,
                                                        not_yet=not_yet))
    other = _outcome(lambda: _directory_present_or_skip("tools", repo=tmp_path, in_checkout=True, not_yet=not_yet))
    assert before == "SKIP NOT MEASURED: plugins/ is not in this tree yet, planted reason", before
    assert after.startswith("FAIL ") and "remove it from NOT_YET_IN_THE_TREE" in after, after
    assert other.startswith("FAIL ") and "went away" in other, other


def test_counter_probe_the_three_measurements_reach_a_planted_tree(tmp_path):
    """The functions are held on strings below; this holds the walk over the tree that calls them."""
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "planted.py").write_text(
        "import json\nimport cbor2\njson.loads(x)\nisinstance(v, list)\n"
        "def _reject_duplicate_keys(pairs):\n    return dict(pairs)\n", encoding="utf-8")
    found, type_findings, hooks = _measure(tmp_path)
    assert found == {"src/planted.py": [(3, "json.loads")]}
    assert type_findings == {"src/planted.py": [4]}
    assert [(rel, n.name) for rel, n in hooks] == [("src/planted.py", "_reject_duplicate_keys")]
    assert _unlisted_hook_sites(hooks) == ["src/planted.py"]
    assert _unlisted_hook_sites(hooks, {"src/planted.py": 1}) == []
    assert hook_refuses_a_duplicate(hooks[0][1], "planted")[0] is False


@pytest.mark.parametrize("source, expected", [
    ("import json\njson.loads(x)\n", [(2, "json.loads")]),
    ("import json as j\nj.load(f)\n", [(2, "json.load")]),
    ("from json import loads as l\nl(x)\n", [(2, "json.loads")]),
    ("import cbor2\ncbor2.loads(b)\n", [(2, "cbor2.loads")]),
    ("from cbor2 import CBORDecoder\nCBORDecoder(f)\n", [(2, "cbor2.CBORDecoder")]),
    ("import json\njson.loads(x, object_pairs_hook=first_wins)\n", [(2, "json.loads")]),
    # Forms an adversarial review found that the first version missed.
    ("from json import JSONDecoder\nJSONDecoder().decode(x)\n", [(2, "json.JSONDecoder")]),
    ("import json\njson.JSONDecoder().raw_decode(x)\n", [(2, "json.JSONDecoder")]),
    ("import json\nloads = json.loads\nloads(x)\n", [(2, "json.loads")]),
    ("import json\nlist(map(json.loads, xs))\n", [(2, "json.loads")]),
    ("import cbor2\ncbor2.decoder.loads(b)\n", [(2, "cbor2.decoder")]),
    ("import cbor2.decoder\ncbor2.decoder.loads(b)\n", [(2, "cbor2.decoder")]),
    ("from cbor2 import decoder\ndecoder.loads(b)\n", [(2, "cbor2.decoder.loads")]),
    ("import cbor2.decoder as d\nd.loads(b)\n", [(2, "cbor2.decoder.loads")]),
    ("from cbor2.decoder import loads\nloads(b)\n", [(2, "cbor2.decoder.loads")]),
    ("import functools, json\nfunctools.partial(json.loads)\n", [(2, "json.loads")]),
    ("import json\ngetattr(json, 'loads')(x)\n", [(2, "json handed on")]),
    ("from json import *\nloads(x)\n", [(1, "from json import *")]),
    ("import importlib\nimportlib.import_module('cbor2').loads(b)\n", [(2, "import of cbor2")]),
    ("__import__('json').loads(x)\n", [(1, "import of json")]),
    # A hook name is not a hook: the module must define it as a function and keep it.
    ("import json\njson.loads(x, object_pairs_hook=_reject_duplicate_keys)\n", [(2, "json.loads")]),
    ("import json\n_reject_duplicate_keys = dict\njson.loads(x, object_pairs_hook=_reject_duplicate_keys)\n",
     [(3, "json.loads")]),
    ("import json\nno_duplicate_members = lambda p: dict(p)\njson.loads(x, object_pairs_hook=no_duplicate_members)\n",
     [(3, "json.loads")]),
    ("import json\nfrom os import _reject_duplicate_keys\njson.loads(x, object_pairs_hook=_reject_duplicate_keys)\n",
     [(3, "json.loads")]),
    ("import json\njson.load(f, object_pairs_hook=mod.no_duplicate_members)\n", [(2, "json.load")]),
    ("import json\njson.loads(x, object_pairs_hook=lambda p: dict(p))\n", [(2, "json.loads")]),
    ("import json\ndef _reject_duplicate_keys(p):\n    raise ValueError\n_reject_duplicate_keys = dict\n"
     "json.loads(x, object_pairs_hook=_reject_duplicate_keys)\n", [(5, "json.loads")]),
])
def test_counter_probe_a_planted_lax_site_is_found(source, expected):
    assert sites(source) == expected


_HOOK = "def _reject_duplicate_keys(pairs):\n    raise ValueError\n"


@pytest.mark.parametrize("source", [
    "import json\n" + _HOOK + "json.loads(x, object_pairs_hook=_reject_duplicate_keys)\n",
    "import json\n" + _HOOK + "json.load(f, cls=C, object_pairs_hook=_reject_duplicate_keys)\n",
    "import json\n" + _HOOK + "json.JSONDecoder(object_pairs_hook=_reject_duplicate_keys).decode(x)\n",
    "from json import loads\n" + _HOOK + "loads(x, object_pairs_hook=_reject_duplicate_keys)\n",
    "from json.decoder import JSONDecodeError\nimport cbor2\nfrom cbor2.types import CBORTag\n"
    "e = (cbor2.CBORDecodeValueError, cbor2.CBORDecodeEOF, cbor2.FrozenDict)\n",
    "from proofbundle._strict_json import loads_strict\nloads_strict(x)\n",
    "import json\njson.dumps(x)\njson.dump(x, f)\n",
    "import json\ntry:\n    pass\nexcept json.JSONDecodeError:\n    pass\n",
    "import cbor2\ncbor2.dumps(cbor2.CBORTag(18, [1]))\nisinstance(e, cbor2.CBORDecodeError)\n",
    "def loads(x):\n    return x\nloads(1)\n",
])
def test_control_strict_and_unrelated_calls_do_not_count(source):
    assert sites(source) == []


@pytest.mark.parametrize("source, lines", [
    ("import cbor2\nisinstance(v, list)\nisinstance(v, (list, dict))\n", [2, 3]),
    ("import cbor2\nisinstance(v, dict)\nisinstance(v, (bytes, dict))\n", [2, 3]),
    # Forms an adversarial review found that the first version missed.
    ("import cbor2\nfrom typing import List\nisinstance(v, List)\n", [3]),
    ("import cbor2\nimport typing\nisinstance(v, typing.Dict)\n", [3]),
    ("import cbor2\nisinstance(v, list | None)\n", [2]),
    ("import cbor2\nLISTS = (list,)\nisinstance(v, LISTS)\n", [2]),
    ("import cbor2\nisinstance(v, (list,) + EXTRA)\n", [2]),
    ("import cbor2\ntype(v) is list\ntype(v) == dict\nv.__class__ is list\n", [2, 3, 4]),
    ("import cbor2\nmatch v:\n    case list():\n        pass\n    case dict():\n        pass\n", [3, 5]),
    ("import builtins\nimport cbor2\nisinstance(v, builtins.list)\n", [3]),
    ("import cbor2.decoder\nisinstance(v, list)\n", [2]),
    ("from cbor2.decoder import loads\nisinstance(v, dict)\n", [2]),
    ("import importlib\nimportlib.import_module('cbor2')\nisinstance(v, list)\n", [3]),
    # Forms a second adversarial review found: the mutable abstract types and aliases of an import.
    ("import cbor2\nfrom collections.abc import MutableMapping\nisinstance(v, MutableMapping)\n", [3]),
    ("import cbor2\nimport collections.abc as abc\nisinstance(v, abc.MutableSequence)\n", [3]),
    ("import cbor2\nfrom typing import Dict as D\nisinstance(v, D)\n", [3]),
    ("import cbor2\nfrom builtins import list as L\nisinstance(v, L)\n", [3]),
    ("import cbor2\nimport builtins as b\nisinstance(v, b.list)\n", [3]),
])
def test_counter_probe_a_container_check_behind_cbor2_is_found(source, lines):
    assert container_checks(source) == lines


@pytest.mark.parametrize("source", [
    "import cbor2\nisinstance(v, (list, tuple))\n",
    "import cbor2\nfrom collections.abc import Mapping\nisinstance(v, Mapping)\nisinstance(v, (dict, Mapping))\n",
    "import cbor2\nimport collections.abc as abc\nisinstance(v, (dict, abc.Mapping))\n",
    "import cbor2\nx = list(y)\nd = dict(pairs)\n",
    "import cbor2\ndef f(x: list, y: dict | None = None) -> dict:\n    out: list = []\n    return {}\n",
    "import cbor2\nimport typing, collections\nv = typing.cast(list, v)\nd = collections.defaultdict(list)\n"
    "f = field(default_factory=dict)\ne = dict.fromkeys(k)\n",
    "import cbor2\nfrom collections.abc import MutableMapping, Mapping\nisinstance(v, (MutableMapping, Mapping))\n",
    "isinstance(v, list)\ntype(v) is dict\n",
])
def test_control_calls_annotations_and_checks_with_the_partner_do_not_count(source):
    assert container_checks(source) == []


@pytest.mark.parametrize("source, refuses, uses_assert", [
    ("def _reject_duplicate_keys(pairs):\n    return dict(pairs)\n", False, False),
    ("def no_duplicate_members(pairs):\n    out = {}\n    for k, v in pairs:\n        out.setdefault(k, v)\n"
     "    return out\n", False, False),
    # Laxer than strict on some input only: adjacent duplicates, at most two pairs, an assert.
    ("def _reject_duplicate_keys(pairs):\n    for (a, _), (b, _) in zip(pairs, pairs[1:]):\n        if a == b:\n"
     "            raise ValueError(a)\n    return dict(pairs)\n", False, False),
    ("def _reject_duplicate_keys(pairs):\n    if len(pairs) <= 2 and len({n for n, _ in pairs}) < len(pairs):\n"
     "        raise ValueError\n    return dict(pairs)\n", False, False),
    ("def _reject_duplicate_keys(pairs):\n    out = {}\n    for k, v in pairs:\n        assert k not in out\n"
     "        out[k] = v\n    return out\n", True, True),
    ("def _reject_duplicate_keys(pairs):\n    names = [n for n, _ in pairs]\n"
     "    if len(set(names)) != len(names):\n        raise Malformed('duplicate')\n    return dict(pairs)\n",
     True, False),
])
def test_counter_probe_a_hook_is_judged_by_what_it_does_not_by_its_name(source, refuses, uses_assert):
    (node,) = _hook_definitions(source)
    got_refuses, _result, got_assert = hook_refuses_a_duplicate(node, "<planted>")
    assert (got_refuses, got_assert) == (refuses, uses_assert)


def test_the_docstring_names_the_directories_outside_the_scope():
    """The scope statement above is held: it names each directory of OUTSIDE, and none of them is a root. That each
    exists where it should is held by test_each_directory_the_guard_names_is_present_or_not_shipped."""
    for top in OUTSIDE:
        assert f"``{top}/``" in __doc__, top
        assert top not in ROOTS
