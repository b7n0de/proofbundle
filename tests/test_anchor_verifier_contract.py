"""NACHGEZOGEN 2026-08-23, beim Landen dieses Zweigs auf den aktuellen main.

DIE VERTRAGSFRAGE, die hier entschieden wurde, und warum so. Dieser Zweig (31.07.) und main
(16.08., commit 2d25e0f) beantworten dieselbe Frage gegenteilig: was tut ein Anker-Verifier,
wenn `rp_trust` oder `frozen` KEIN Mapping ist?

  · dieser Zweig: ein Verdict zurueckgeben (`ok: False`) — "a verifier returns, it does not raise"
  · main:         einen typisierten `BundleFormatError` werfen — "the floor tests the interface"

Beide Seiten haben ein gutes Argument, und beide Test-Suiten liefen fuer sich gruen. Entschieden
wurde fuer main, aus drei Gruenden: es ist die SPAETERE Entscheidung, sie ist im Commit
ausfuehrlich begruendet (samt der Messung, dass jede Weiterverwendung `.get(...)` ist), und ein
typisierter fail-closed Fehler ist nach der repo-eigenen never-raise-Eigenschaft ausdruecklich
eine ZULAESSIGE Terminierung (`_ACCEPTED` enthaelt `ProofBundleError`). Was jene Eigenschaft
verbietet, ist ein Crash STATT einer Entscheidung — und ein typisierter Fehler ist eine.

Was der Zweig-Ansatz zusaetzlich kostete und was den Ausschlag gab: das stille Ersetzen durch
`{}` verschluckte die Diagnose. Ein Aufrufer, der Muell schickt, erfuhr es nie.

Die Tests unten pruefen ab jetzt dieselbe SACHE (kein Verifier faellt mit einem
Typverwechslungs-Crash aus), nur gegen die andere zulaessige Terminierungsform.

"""
from __future__ import annotations

import ast
import base64
import hashlib
import inspect
import json
import os
import pathlib
import tempfile

import pytest

from proofbundle import anchors
from proofbundle._anchor_contract import is_failclosed_anchor_verifier
from proofbundle.errors import ProofBundleError

SRC = pathlib.Path(__file__).resolve().parents[1] / "src" / "proofbundle"

try:  # the [anchors] extra; the deep fixtures need it, the rules themselves do not
    import opentimestamps  # noqa: F401
    _HAS_OTS = True
except ImportError:  # pragma: no cover - exercised by the minimal-environment matrix
    _HAS_OTS = False


# ── the hostile corpus ────────────────────────────────────────────────────────────────────────────────
#
# Derived from the DECISION SPACE of the rule, not from the list of shapes that refuted it last time. The
# wrapper decides on one property: "did the body terminate outside its verdict contract". The values below
# therefore span the argument shapes that can produce such a termination — every builtin category, the
# truthy/falsy split inside each (an `x or {}` idiom only replaces the FALSY member, which is exactly how
# the truthy non-mapping got through), nesting depth, self-reference, and objects whose own dunders are
# hostile.

class _HostileRepr:
    """An object whose rendering and comparison both fight back."""

    def __repr__(self):  # pragma: no cover - called only if something renders it
        raise RuntimeError("no repr for you")

    def __eq__(self, other):
        raise RuntimeError("no equality for you")

    __hash__ = None  # type: ignore[assignment]


def _deep_mapping(depth: int = 2000) -> dict:
    root: dict = {}
    cur = root
    for _ in range(depth):
        nxt: dict = {}
        cur["a"] = nxt
        cur = nxt
    cur["a"] = 1
    return root


def _hostile_values() -> list:
    recursive: list = []
    recursive.append(recursive)
    return [
        None, False, True, 0, 1, -1, 2 ** 70, -(2 ** 70), 0.0, 1.5, float("nan"),
        "", "x", "0" * 4096, b"", b"x", bytearray(b"x"),
        [], [1], (), (1,), set(), frozenset({1}),
        {}, {"k": "v"}, {"trusted_tsa_roots": "not-a-list"}, {"trusted_tsa_roots": [None]},
        {"trusted_tsa_policy_oids": 5}, {"trusted_tsa_policy_oids": ["not-an-oid"]},
        {"bitcoin_block_headers": "not-a-mapping"}, {"bitcoin_block_headers": {"800000": None}},
        {"rootCertsDerB64": 7}, {"intermediateCertsDerB64": "x"}, {"tsaCertDerB64": 5},
        {"bitcoinBlockHeaderMerkleRootsByHeight": 9},
        _deep_mapping(), recursive, _HostileRepr(), object(), type,
    ]


# ── proofs that get the corpus PAST the early parsing guards ──────────────────────────────────────────
#
# A corpus that never gets past `deserialize()` cannot reach the frozen/RP material at all, so a verifier
# would look floored for a reason other than the defence being tested. The sweep that produced the finding
# was shallow in exactly this way: it reported escapes only for rfc3161, whose defect sits BEFORE any
# library call, while `verify_opentimestamps` and `verify_markovian` hold the same shape behind a proof
# that has to deserialize first. These fixtures are what makes the difference visible.

_ROOT = hashlib.sha256(b"anchor-verifier-contract").digest()


def _ots_upgraded_proof(msg: bytes = _ROOT, height: int = 800000, nonce: bytes = b"\x00") -> bytes:
    from opentimestamps.core.notary import BitcoinBlockHeaderAttestation
    from opentimestamps.core.op import OpAppend, OpSHA256
    from opentimestamps.core.serialize import BytesSerializationContext
    from opentimestamps.core.timestamp import DetachedTimestampFile, Timestamp
    ts = Timestamp(msg)
    leaf = ts.ops.add(OpAppend(nonce)).ops.add(OpSHA256())
    leaf.attestations.add(BitcoinBlockHeaderAttestation(height))
    ctx = BytesSerializationContext()
    DetachedTimestampFile(OpSHA256(), ts).serialize(ctx)
    return ctx.getbytes()


def _markovian_envelope(msg: bytes = _ROOT) -> bytes:
    from proofbundle.anchors_markovian import ANCHOR_TYPE
    data_hash, salt, wallet = msg.hex(), "salt", "0xwallet"
    envelope = {
        "schema": ANCHOR_TYPE, "data_hash": data_hash, "salt": salt, "wallet": wallet,
        "merkle_root": hashlib.sha256(f"{data_hash}:{salt}:{wallet}".encode()).hexdigest(),
        "ots": base64.b64encode(_ots_upgraded_proof(msg)).decode(),
    }
    return json.dumps(envelope).encode()


def _chia_proof(msg: bytes = _ROOT) -> bytes:
    from proofbundle.anchors_chia import clvm_atom_hash, leaf_node_hash
    key_clvm = clvm_atom_hash(msg)
    value_clvm = clvm_atom_hash(msg)
    leaf = leaf_node_hash(key_clvm, value_clvm)
    return json.dumps({
        "key": msg.hex(), "key_clvm_hash": key_clvm.hex(), "value_clvm_hash": value_clvm.hex(),
        "node_hash": leaf.hex(), "inclusion_layers": [], "published_root": leaf.hex(),
    }).encode()


def _deep_inputs_for(anchor_type: str) -> list[tuple[bytes, bytes]]:
    """(proof, canonical_root) pairs that reach deep into THIS type's verifier.

    A type with no entry is swept with the generic pair only. That is a coverage statement, not a pass:
    :func:`test_every_registered_type_is_swept_beyond_its_first_guard` fails when a type is swept only
    generically AND its verifier is not carrying the contract, so a new type cannot be quietly shallow.
    """
    generic = [(b"", b"\x00" * 32), (b"\xff" * 64, _ROOT)]
    if anchor_type == "opentimestamps" and _HAS_OTS:
        return generic + [(_ots_upgraded_proof(), _ROOT)]
    if anchor_type == "markovian-provenance/v1" and _HAS_OTS:
        return generic + [(_markovian_envelope(), _ROOT)]
    if anchor_type == "chia-datalayer/v1":
        return generic + [(_chia_proof(), _ROOT)]
    return generic


# ── the probe ─────────────────────────────────────────────────────────────────────────────────────────

_FORBIDDEN_TERMINATIONS = (
    AttributeError, TypeError, KeyError, IndexError, ValueError, RecursionError,
    UnicodeDecodeError, ArithmeticError, LookupError,
)


def _sweep_verifier(fn, inputs, hostile) -> list[str]:
    """Every escape ``fn`` produces over (inputs x every argument x hostile).

    An escape is any termination that is not a mapping verdict. The verifier contract admits exactly one
    outcome — a verdict dict — so this needs no exception allowlist and cannot be weakened by one.
    """
    escapes: list[str] = []
    try:
        parameters = list(inspect.signature(fn).parameters)
    except (TypeError, ValueError):  # pragma: no cover - a C callable without a signature
        parameters = ["proof", "canonical_root", "frozen", "now", "rp_trust"]
    positional = parameters[:2]
    keyword = [p for p in parameters[2:]]
    for proof, root in inputs:
        for index, name in enumerate(positional):
            for value in hostile:
                args = [proof, root]
                args[index] = value
                escapes.extend(_one_call(fn, args, {}, name))
        for name in keyword:
            for value in hostile:
                escapes.extend(_one_call(fn, [proof, root], {name: value}, name))
    return escapes


def _one_call(fn, args, kwargs, argument: str) -> list[str]:
    try:
        verdict = fn(*args, **kwargs)
    except BaseException as exc:  # noqa: BLE001 - measuring terminations is the point
        return [f"{getattr(fn, '__name__', fn)}({argument}=...) raised {type(exc).__name__}"]
    if not isinstance(verdict, dict):
        return [f"{getattr(fn, '__name__', fn)}({argument}=...) returned {type(verdict).__name__}"]
    return []


@pytest.fixture()
def registry_with_markovian():
    """The registry with the third-party example type registered, restored afterwards.

    Registering it inside the rule's own population is the point: ``markovian-provenance/v1`` is not a
    built-in, so its presence here demonstrates that the sweep follows the REGISTRY rather than a list of
    modules — a seventh type is covered the moment it is registered.
    """
    from proofbundle import anchors_markovian
    anchors._ensure_builtin_types()
    before = dict(anchors._VERIFIERS)
    anchors_markovian.register()
    try:
        yield anchors.registered_anchor_types()
    finally:
        anchors._VERIFIERS.clear()
        anchors._VERIFIERS.update(before)


# ── 1. behaviour: the reproducers ─────────────────────────────────────────────────────────────────────

def test_rfc3161_non_mapping_frozen_returns_a_verdict():
    """The literal finding: ``frozen`` is read with ``.get`` without ever being typed."""
    from proofbundle.anchors_rfc3161 import verify_rfc3161
    verdict = verify_rfc3161(b"", b"\x00" * 32, frozen=[], now=None, rp_trust=None)
    assert isinstance(verdict, dict) and verdict["ok"] is False


def test_rfc3161_non_mapping_rp_trust_is_a_typed_error():
    """``rp_trust or {}`` only replaces a FALSY value, so a truthy non-mapping walked straight through."""
    from proofbundle.anchors_rfc3161 import verify_rfc3161
    with pytest.raises(BundleFormatError):
        verify_rfc3161(b"", b"\x00" * 32, frozen={}, now=None, rp_trust="trust-me")


@pytest.mark.skipif(not _HAS_OTS, reason="needs proofbundle[anchors] (opentimestamps)")
def test_opentimestamps_non_mapping_material_returns_a_verdict():
    """Reachable only behind a proof that deserializes — the reason the original sweep called this
    verifier 'shallow' and reported no escape for it."""
    from proofbundle.anchors_ots import verify_opentimestamps
    proof = _ots_upgraded_proof()
    for frozen, rp_trust in (([], None), ({}, "trust-me"), ({}, {"bitcoin_block_headers": "nope"})):
        verdict = verify_opentimestamps(proof, _ROOT, frozen=frozen, now=None, rp_trust=rp_trust)
        assert isinstance(verdict, dict) and verdict["ok"] is False


@pytest.mark.skipif(not _HAS_OTS, reason="needs proofbundle[anchors] (opentimestamps)")
def test_markovian_inherits_the_contract_through_delegation():
    """The composing verifier forwards ``frozen``/``rp_trust`` verbatim, so it inherited the defect."""
    from proofbundle.anchors_markovian import verify_markovian
    verdict = verify_markovian(_markovian_envelope(), _ROOT, frozen=[], now=None, rp_trust=7)
    assert isinstance(verdict, dict) and verdict["ok"] is False


def test_a_verifier_that_returns_a_non_mapping_is_itself_refused():
    """``verify_anchor`` calls ``res.get(...)``. A verifier returning something else would make the
    DISPATCHER the thing that crashes, so the contract covers the return value too."""
    from proofbundle._anchor_contract import failclosed_anchor_verifier

    @failclosed_anchor_verifier
    def broken(proof, canonical_root, *, frozen=None, now=None):
        return "not a verdict"

    verdict = broken(b"", b"", frozen={}, now=None)
    assert isinstance(verdict, dict) and verdict["ok"] is False


def test_the_wrapper_cannot_manufacture_a_pass():
    """Normalising trust material to ``{}`` REMOVES material, so it can only make a verdict more
    conservative. Pinned because a guard that could turn a failure into a pass would be worse than the
    defect it closes."""
    from proofbundle.anchors_rfc3161 import verify_rfc3161
    verdict = verify_rfc3161(b"", b"\x00" * 32, frozen={}, now=None, rp_trust="trust-me")
    assert verdict["ok"] is False
    assert verdict.get("status") == "needs_rp_trust", "a non-mapping rp_trust is NO trust material"


# ── 2. forcing function over the registry ─────────────────────────────────────────────────────────────

def test_no_registered_verifier_escapes_its_verdict_contract(registry_with_markovian):
    """The class rule. Population = the REGISTRY, so a type registered later is swept automatically."""
    hostile = _hostile_values()
    escapes: list[str] = []
    for anchor_type in registry_with_markovian:
        fn = anchors._VERIFIERS[anchor_type]
        found = _sweep_verifier(fn, _deep_inputs_for(anchor_type), hostile)
        escapes.extend(f"{anchor_type}: {e}" for e in found)
    assert not escapes, "registered anchor verifier(s) broke the contract:\n  " + "\n  ".join(
        sorted(set(escapes))[:40])


def test_the_swept_population_is_not_empty(registry_with_markovian):
    """The denominator. A rule over an empty registry passes for the wrong reason."""
    assert len(registry_with_markovian) >= 4, (
        f"only {len(registry_with_markovian)} anchor type(s) registered — the sweep is near-vacuous")
    assert len(_hostile_values()) >= 30, "the hostile corpus collapsed"


def test_every_registered_type_is_swept_beyond_its_first_guard(registry_with_markovian):
    """A type swept only by the generic pair may be floored by an early parse guard rather than by the
    contract. Such a type must at least CARRY the contract wrapper, so shallow coverage never reads as a
    clean bill of health."""
    shallow = []
    for anchor_type in registry_with_markovian:
        if len(_deep_inputs_for(anchor_type)) > 2:
            continue
        if not is_failclosed_anchor_verifier(anchors._VERIFIERS[anchor_type]):
            shallow.append(anchor_type)
    assert not shallow, (
        "these types are swept only by the generic corpus AND do not carry the fail-closed contract, so "
        f"nothing here proves they are floored: {sorted(shallow)}")


# ── 3. forcing function over the first-party verifiers, as shipped ────────────────────────────────────
#
# The registry rule covers what is registered AT RUNTIME. This one covers what is SHIPPED: every
# module-level ``verify_*`` in the anchor modules is discovered from the tree and must either carry the
# contract or be an enumerated exclusion. An exclusion list has to be complete to PERMIT something, so a
# verifier written tomorrow lands on the CHECKED side by default — the direction a list of known-good
# names gets wrong.

ANCHOR_VERIFIER_EXCLUSIONS = {
    # The dispatcher and the aggregator: they are the CALLERS of a verifier, and their contract is the
    # documented `BundleFormatError` on a schema violation, not a verdict for a proof.
    "anchors.py::verify_anchor": "DISPATCHER_NOT_A_VERIFIER",
    "anchors.py::verify_anchors": "DISPATCHER_NOT_A_VERIFIER",
    # A pure inner check over an already-decoded proof object, reached only through the wrapped
    # `verify_chia_datalayer` (and the writer's own self-check, which is allowed to raise).
    "anchors_chia.py::verify_offline_merkle": "INNER_CHECK_BEHIND_A_WRAPPED_VERIFIER",
}

_EXCLUSION_REASONS = {
    "DISPATCHER_NOT_A_VERIFIER":
        "Calls verifiers rather than being one; raising a typed schema error is its declared contract.",
    "INNER_CHECK_BEHIND_A_WRAPPED_VERIFIER":
        "Not registered and not reachable from untrusted input except through a wrapped verifier.",
}


def _shipped_anchor_verifiers() -> dict[str, str]:
    """{"<module>::<function>": module} for every module-level ``verify_*`` in the anchor modules."""
    found: dict[str, str] = {}
    for path in sorted(SRC.glob("anchors*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in tree.body:
            if isinstance(node, ast.FunctionDef) and node.name.startswith("verify_"):
                found[f"{path.name}::{node.name}"] = path.stem
    return found


def test_every_shipped_anchor_verifier_carries_the_contract_or_is_pinned():
    import importlib
    undecided = []
    for key, module_name in _shipped_anchor_verifiers().items():
        if key in ANCHOR_VERIFIER_EXCLUSIONS:
            continue
        fn = getattr(importlib.import_module(f"proofbundle.{module_name}"), key.split("::")[1])
        if not is_failclosed_anchor_verifier(fn):
            undecided.append(key)
    assert not undecided, (
        "these shipped anchor verifiers neither carry the fail-closed contract nor are pinned as a "
        f"deliberate exclusion: {sorted(undecided)}")


def test_the_exclusions_are_honest():
    """Every exclusion uses a reason from the closed vocabulary, and none of them is stale."""
    shipped = _shipped_anchor_verifiers()
    for key, reason in ANCHOR_VERIFIER_EXCLUSIONS.items():
        assert reason in _EXCLUSION_REASONS, f"{key} carries an undeclared reason code {reason!r}"
        assert key in shipped, f"{key} no longer exists — remove it so the exclusion set stays true"


def test_the_shipped_population_is_discovered_not_listed():
    shipped = _shipped_anchor_verifiers()
    assert len(shipped) >= 7, f"only {len(shipped)} shipped anchor verifiers found — discovery is broken"
    assert len(set(shipped.values())) >= 4, "discovery collapsed onto a single module"


# ── 4. anti-tautology: can any of this go red ─────────────────────────────────────────────────────────

def test_the_probe_catches_the_pre_fix_verifier():
    """The red-before proof, kept in the suite rather than quoted from a terminal.

    ``__wrapped__`` IS the pre-fix function — the same bytes that shipped, without the defence in front of
    it. The probe must report escapes on it. Varying the presence of the defence is the same axis the rule
    decides on, which is what makes this an anti-tautology twin rather than a restatement.
    """
    from proofbundle.anchors_rfc3161 import verify_rfc3161
    pre_fix = verify_rfc3161.__wrapped__
    escapes = _sweep_verifier(pre_fix, [(b"", b"\x00" * 32)], _hostile_values())
    assert escapes, "the probe found nothing on the unguarded verifier — it cannot go red"
    assert any("AttributeError" in e for e in escapes), (
        f"expected the reported AttributeError class, got: {sorted(set(escapes))[:5]}")
    # and the guarded one, over the identical corpus, is clean
    assert not _sweep_verifier(verify_rfc3161, [(b"", b"\x00" * 32)], _hostile_values())


def test_blinding_the_probe_stops_catching_the_pre_fix_verifier():
    """The other direction: with an empty corpus the probe reports nothing, so a green result from the
    real corpus is evidence about the subject and not about the probe's appetite."""
    from proofbundle.anchors_rfc3161 import verify_rfc3161
    pre_fix = verify_rfc3161.__wrapped__
    assert not _sweep_verifier(pre_fix, [(b"", b"\x00" * 32)], [])
    assert _sweep_verifier(pre_fix, [(b"", b"\x00" * 32)], _hostile_values())


def test_the_structural_rule_catches_an_unwrapped_registration():
    """Plant an unwrapped verifier in a COPY of the registry mapping (never in the live one) and show the
    predicate the structural rules stand on actually discriminates."""
    def unwrapped(proof, canonical_root, *, frozen=None, now=None):  # pragma: no cover - never called
        return {"ok": False}

    planted = dict(anchors._VERIFIERS)
    planted["planted/v1"] = unwrapped
    undecided = [t for t, fn in planted.items() if not is_failclosed_anchor_verifier(fn)]
    assert "planted/v1" in undecided, "the contract predicate did not notice an unwrapped verifier"
    # blind the predicate: with the marker ignored, the planted violation survives unseen
    blinded = [t for t, fn in planted.items() if not True]
    assert not blinded, "expected the blinded predicate to find nothing"


def test_the_shipped_discovery_sees_a_verifier_it_has_never_read():
    """The discovery walks the tree, so a verifier written in a module it has never seen is found without
    editing this file. Proven on a throwaway copy — the working tree is never the mutation surface."""
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        (root / "anchors_planted.py").write_text(
            "def verify_planted(proof, canonical_root):\n    return {'ok': False}\n", encoding="utf-8")
        found = {}
        for path in sorted(root.glob("anchors*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in tree.body:
                if isinstance(node, ast.FunctionDef) and node.name.startswith("verify_"):
                    found[f"{path.name}::{node.name}"] = path.stem
    assert "anchors_planted.py::verify_planted" in found


# ── 5. the neighbour in the same lane: prereg's argument type floor ───────────────────────────────────

def _termination(fn, *args):
    """The name of the exception a call terminates with, or None for a normal return."""
    try:
        fn(*args)
    except BaseException as exc:  # noqa: BLE001 - measuring the termination is the point
        return type(exc).__name__
    return None


def test_verify_prereg_returns_a_verdict_for_an_out_of_range_integer():
    """``os.stat`` reads an int as a file descriptor, and an out-of-range one raises ``OverflowError``,
    which comes from the ``ArithmeticError`` arm and was outside the exception set this surface caught."""
    from proofbundle.prereg import verify_prereg
    verdict = verify_prereg(2 ** 64, {"prereg_sha256": "a" * 64})
    assert isinstance(verdict, dict)
    assert verdict["ok"] is False and verdict["actual"] is None


def test_prereg_hash_refuses_a_non_path_with_a_typed_error():
    from proofbundle.prereg import prereg_hash
    for value in (2 ** 64, 3, 1.5, None, [], {}, object(), True):
        assert _termination(prereg_hash, value) in {"BundleFormatError"}, (
            f"prereg_hash({type(value).__name__}) terminated outside the declared typed contract")


def test_prereg_hash_does_not_consume_the_callers_file_descriptor():
    """The worse neighbour of the same root cause: an IN-RANGE integer was a successful hash — of the
    caller's open file, whose descriptor ``open(fd)`` then CLOSED underneath them. That is not an error
    path, so no wider ``except`` could ever have caught it. Only the type floor does."""
    from proofbundle.prereg import prereg_hash
    with tempfile.TemporaryDirectory() as tmp:
        target = pathlib.Path(tmp) / "protocol.md"
        target.write_bytes(b"the protocol")
        with open(target, "rb") as handle:
            # a DUPLICATE descriptor is offered, so a pre-fix run closes the duplicate and this test
            # reports the defect as an assertion rather than as a teardown error on a dead handle
            spare = os.dup(handle.fileno())
            try:
                assert _termination(prereg_hash, spare) == "BundleFormatError", (
                    "an integer was accepted as a path — the caller's open file was hashed")
                assert _termination(os.fstat, spare) is None, "the caller's descriptor was closed"
            finally:
                try:
                    os.close(spare)
                except OSError:
                    pass
            assert handle.read() == b"the protocol"


def test_prereg_hash_still_accepts_every_real_path_form():
    """Backward compatibility: the floor must not reject what a legitimate producer passes."""
    from proofbundle.prereg import prereg_hash
    with tempfile.TemporaryDirectory() as tmp:
        target = pathlib.Path(tmp) / "protocol.md"
        target.write_bytes(b"the protocol")
        expected = hashlib.sha256(b"the protocol").hexdigest()
        assert prereg_hash(str(target)) == expected
        assert prereg_hash(target) == expected
        assert prereg_hash(os.fsencode(str(target))) == expected


def test_the_prereg_probe_catches_the_pre_fix_shape():
    """Anti-tautology twin for the floor. The planted function is the pre-fix first statement — an
    ``os.stat`` on an argument whose type was never checked. The same two probes that report the fixed
    surface as clean must report this one as broken; blinding them must stop that."""
    def unfloored(protocol_path):
        os.stat(protocol_path)                      # the pre-fix first statement, verbatim in shape
        handle = open(protocol_path, "rb")
        try:
            return hashlib.sha256(handle.read()).hexdigest()
        finally:
            handle.close()

    assert _termination(unfloored, 2 ** 64) == "OverflowError", "the raise probe is asleep"
    with tempfile.TemporaryDirectory() as tmp:
        target = pathlib.Path(tmp) / "protocol.md"
        target.write_bytes(b"the protocol")
        with open(target, "rb") as handle:
            spare = os.dup(handle.fileno())         # only the duplicate is offered to the planted shape
            assert unfloored(spare) == hashlib.sha256(b"the protocol").hexdigest()
            consumed = _termination(os.fstat, spare) is not None
    assert consumed, "the descriptor-consumption probe is asleep"

    def _blind_termination(fn, *args):
        """The same probe with its eyes shut: every termination is acceptable."""
        try:
            fn(*args)
        except BaseException:  # noqa: BLE001 - deliberately blind
            pass
        return None

    assert _blind_termination(unfloored, 2 ** 64) is None, "the blinded probe still reported something"
    assert _termination(unfloored, 2 ** 64) is not None, "and the seeing probe still catches it"


def test_prereg_typed_error_is_inside_the_declared_set():
    """The floor raises a ``ProofBundleError``, which is what ``verify_prereg`` already catches — so the
    exported never-raise surface keeps returning a verdict without widening its except clause."""
    from proofbundle.errors import BundleFormatError
    assert issubclass(BundleFormatError, ProofBundleError)
