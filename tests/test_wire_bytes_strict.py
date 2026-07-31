"""Wire bytes are strict: one signed artefact has exactly one verifying byte form.

Two deep-gate findings live here.

**L5-02 — signed artefacts were byte-malleable.** ``base64.b64decode`` / ``urlsafe_b64decode``
DISCARD every character outside the alphabet unless ``validate=True`` is passed; RFC 4648 §3.3
says a decoder MUST reject them. A 1511-byte DSSE envelope inflated to 51511 bytes with 50000
injected junk characters verified ``ok=True``, and so did a status token that was 99.99% junk.
The strict idiom already existed in this repo (``bundle._b64d``), so this was the ledger class
``class_fix_landed_on_one_driver_siblings_kept_the_pre_fix_shape``: eight JWS/DSSE siblings kept
the pre-fix shape. The fix is one shared gate, :mod:`proofbundle._b64strict`.

**L2-01 — raw ``TypeError`` out of the never-raise surface ``verify_status_snapshot``** when a
signed token declares ``status_list.bits`` as a JSON float (``1.0 in (1, 2, 4, 8)`` is True, and
the float then indexes a ``bytes``). The identical floor existed three times in the same
function and was missing at ``bits`` — and, as the sweep below shows, at the caller's ``now``.

How the class is enforced, rather than the two instances:

* ``TestDecoderProvenanceGate`` scans the WHOLE package by AST DISCOVERY. Every call into a
  stdlib base64/binascii decoding primitive must either pass ``validate=True`` or live inside the
  shared gate module; a decoder added to a new file tomorrow is scanned without anyone editing
  this test. The rule is provenance-shaped ("the bytes came through the gate"), not a blocklist
  of known-bad spellings, so an unknown new spelling falls on the REJECTED side by default.
* ``TestStrictDecoderFamily`` finds every function in the package that routes through the gate by
  reading ``__code__.co_names`` (provenance again, not a name pattern) and property-tests each
  probeable one: clean base64 decodes, junked base64 raises.
* ``TestStatusListTypeFloorSweep`` walks a GENUINE signed payload and every parameter of
  ``verify_status_snapshot`` (via ``inspect.signature``) and injects a hostile value family. A
  numeric field or keyword added later is swept automatically.

Deliberate, enumerated gaps are pinned in ``KNOWN_UNGATED_MODULES`` and
``DELIBERATE_ALPHABET_COMPAT`` — a new member breaks the pin instead of slipping through.
"""

from __future__ import annotations

import ast
import base64
import binascii
import importlib
import inspect
import json
import math
import pathlib
import pkgutil
import warnings
import zlib

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import proofbundle
from proofbundle import _b64strict, dsse, statuslist

SRC_ROOT = pathlib.Path(proofbundle.__file__).resolve().parent

# The gate itself is where the primitive is legitimately called.
GATE_MODULE = "_b64strict.py"

# Files this lane owns and therefore had to clean. Zero tolerance here.
OWNED_MODULES = frozenset({
    "dsse.py", "sdjwt.py", "sdjwt_vc.py", "kbjwt.py", "persample.py", "hf_evals.py",
    "statuslist.py", "experimental/enclave.py",
})

# ENUMERATED GAP (honest, not silent): modules that still call a base64 decoding primitive without
# validate=True. They belong to other lanes of this fix round and were reported instead of edited.
# A module NOT in this set that starts decoding laxly fails the gate below — that is the point.
# Entries may be REMOVED once the owning lane migrates them; adding one requires a written reason.
KNOWN_UNGATED_MODULES = {
    "bundle.py": "core bundle reader (payload_b64 / eval-claim peek) — owned by another lane",
    "cli.py": "operator-supplied --pub / envelope payload arguments — owned by another lane",
    "evalclaim.py": "eval claim payload + signer key decode — owned by another lane",
    "sdjwt_issue.py": "SD-JWT issue-side re-read of its own output — owned by another lane",
    "checkpoint.py": "C2SP checkpoint vkey decode — owned by another lane",
    "anchors_rfc3161.py": "RFC 3161 certificate decode — owned by another lane",
    "anchors_rootcommit.py": "rootcommit line payload decode — owned by another lane",
}

# ENUMERATED GAP: the gate accepts BOTH RFC 4648 alphabets on the JWS/JWT surfaces (single alphabet
# per string, never mixed). Restricting them to §5 would reject bytes a third-party producer may have
# emitted and that 3.7.0 accepted, so it is a compatibility decision, not an oversight. This pin
# fails if someone tightens it silently.
DELIBERATE_ALPHABET_COMPAT = "standard-alphabet input is still accepted on base64url surfaces"


# --------------------------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------------------------
def _keypair():
    sk = Ed25519PrivateKey.generate()
    pub = sk.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return sk, pub


JUNK = "\n\t \r\x0b!*?[]{}"        # 12 characters, none of them in either base64 alphabet


def _inject_junk(segment: str, *, at: int = 2, times: int = 3) -> str:
    """Same bytes, different wire form: only characters OUTSIDE the base64 alphabet are added.

    NON-VACUITY: the number of injected characters is a multiple of 4, so ``-len(s) % 4`` — the
    padding arithmetic every decoder here performs — is IDENTICAL for the clean and the junked
    string. The only property that differs is alphabet membership, which is the exact axis the
    gate decides on. Without this, a rejection could come from a padding error instead of the
    defence being tested, and the seam would pass for a reason other than the one it names.
    """
    assert (len(JUNK) * times) % 4 == 0, "junk length must not change the padding arithmetic"
    return segment[:at] + JUNK * times + segment[at:]


def _lax_b64decode(value, *, alphabet=None):
    """The PRE-FIX decoder, for the anti-tautology twins: it drops non-alphabet characters."""
    text = value if isinstance(value, str) else value.decode("ascii")
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _package_python_files():
    return sorted(p for p in SRC_ROOT.rglob("*.py"))


def _rel(path: pathlib.Path) -> str:
    return path.relative_to(SRC_ROOT).as_posix()


def _decode_calls(source: str, *, primitive_names=None):
    """Discover every call into a stdlib base64/binascii DECODING primitive.

    Returns the list of (lineno, callee, gated) tuples. ``gated`` is True only when the call
    explicitly passes ``validate=True``. ``primitive_names`` exists so the anti-tautology twin can
    blind the detector.

    SCOPE, stated rather than implied: the attribute form matches ANY decoding member of ``base64``
    or ``binascii`` (including spellings that do not exist yet), and the bare-name form covers
    ``from base64 import ...``. It does NOT cover a base64 decode routed through ``codecs.decode``
    or through a third-party library — no such call exists in this package today (checked), and a
    decoder written that way would need its own gate.
    """
    bare = primitive_names if primitive_names is not None else frozenset({
        "b64decode", "urlsafe_b64decode", "standard_b64decode", "decodebytes",
        "b32decode", "b16decode", "b85decode", "a85decode", "a2b_base64",
    })
    found = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        callee = None
        if (isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name)
                and func.value.id in ("base64", "binascii")):
            # attribute form: any decoding member of the module, including spellings not yet invented
            if primitive_names is None and ("decode" in func.attr or func.attr.startswith("a2b")):
                callee = f"{func.value.id}.{func.attr}"
            elif primitive_names is not None and func.attr in bare:
                callee = f"{func.value.id}.{func.attr}"
        elif isinstance(func, ast.Name) and func.id in bare:
            callee = func.id
        if callee is None:
            continue
        gated = any(kw.arg == "validate" and isinstance(kw.value, ast.Constant)
                    and kw.value.value is True for kw in node.keywords)
        found.append((node.lineno, callee, gated))
    return found


def _ungated_modules(primitive_names=None):
    out = {}
    for path in _package_python_files():
        rel = _rel(path)
        if rel == GATE_MODULE:
            continue
        bad = [(ln, name) for ln, name, gated in
               _decode_calls(path.read_text(encoding="utf-8"), primitive_names=primitive_names)
               if not gated]
        if bad:
            out[rel] = bad
    return out


# --------------------------------------------------------------------------------------------
# L5-02 — the shared gate itself
# --------------------------------------------------------------------------------------------
class TestStrictGate:
    def test_rejects_every_non_alphabet_character(self):
        clean = base64.b64encode(b"proofbundle").decode("ascii")
        assert _b64strict.b64decode_strict(clean) == b"proofbundle"
        for ch in "\n\r\t \x0b!*?[]{}~,;:\"'\\|@#$%^&()":
            # four copies: the padding arithmetic is unchanged, only the alphabet differs
            with pytest.raises(binascii.Error):
                _b64strict.b64decode_strict(clean[:4] + ch * 4 + clean[4:])

    def test_accepts_both_alphabets_but_never_mixed(self):
        raw = bytes(range(256))
        std = base64.b64encode(raw).decode("ascii")
        url = base64.urlsafe_b64encode(raw).decode("ascii")
        assert "+" in std or "/" in std
        assert "-" in url or "_" in url
        assert _b64strict.b64decode_strict(std) == raw
        assert _b64strict.b64decode_strict(url) == raw
        assert _b64strict.b64decode_strict(std, alphabet=_b64strict.STANDARD) == raw
        with pytest.raises(binascii.Error):
            _b64strict.b64decode_strict(url, alphabet=_b64strict.STANDARD)
        mixed = std.replace("+", "-", 1) if "+" in std else std.replace("/", "_", 1)
        with pytest.raises(binascii.Error):
            _b64strict.b64decode_strict(mixed)

    def test_padding_stays_optional_for_the_jws_wire_form(self):
        raw = b"unpadded-jws-segment!!"
        for enc in (base64.b64encode(raw).decode(), base64.urlsafe_b64encode(raw).decode()):
            assert _b64strict.b64decode_strict(enc) == raw
            assert _b64strict.b64decode_strict(enc.rstrip("=")) == raw

    def test_non_text_input_is_a_rejection_not_a_crash(self):
        for value in (None, 7, 1.5, [], {}, object()):
            with pytest.raises(binascii.Error):
                _b64strict.b64decode_strict(value)
        assert _b64strict.b64decode_strict(b"QQ==") == b"A"

    def test_anti_tautology_the_pre_fix_decoder_would_accept_the_junk(self):
        """Twin: with the gate replaced by the pre-fix implementation, the junk is accepted again."""
        clean = base64.b64encode(b"proofbundle").decode("ascii")
        junked = _inject_junk(clean)
        assert _lax_b64decode(junked) == b"proofbundle"      # what shipped in 3.7.0
        with pytest.raises(binascii.Error):                   # what ships now
            _b64strict.b64decode_strict(junked)


# --------------------------------------------------------------------------------------------
# L5-02 — the class: every decoder in the package routes through the gate
# --------------------------------------------------------------------------------------------
class TestDecoderProvenanceGate:
    def test_owned_modules_have_no_ungated_decoder(self):
        ungated = _ungated_modules()
        offenders = {m: v for m, v in ungated.items() if m in OWNED_MODULES}
        assert offenders == {}, f"lane A modules must decode through the gate: {offenders}"

    def test_no_unpinned_module_decodes_laxly(self):
        ungated = _ungated_modules()
        unpinned = {m: v for m, v in ungated.items() if m not in KNOWN_UNGATED_MODULES}
        assert unpinned == {}, (
            "a base64 decoding primitive without validate=True appeared in a module that is neither "
            "gated nor pinned in KNOWN_UNGATED_MODULES: " + repr(unpinned))

    def test_every_pinned_gap_has_a_non_empty_reason(self):
        for module, reason in KNOWN_UNGATED_MODULES.items():
            assert isinstance(reason, str) and reason.strip(), module

    def test_the_gate_module_is_the_only_home_of_the_primitive(self):
        gate = (SRC_ROOT / GATE_MODULE).read_text(encoding="utf-8")
        assert any(not gated for _, _, gated in _decode_calls(gate)) or "validate=True" in gate

    def test_detector_sees_a_planted_violation_in_a_new_file_shape(self):
        """MUST-FAIL negative for the scanner, on source text — never on the real working tree."""
        planted = (
            "import base64\n"
            "def _decode(s):\n"
            "    return base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))\n")
        assert [(c, g) for _, c, g in _decode_calls(planted)] == [("base64.urlsafe_b64decode", False)]
        future_spelling = "import base64\nx = base64.b85decode(s)\n"
        assert [(c, g) for _, c, g in _decode_calls(future_spelling)] == [("base64.b85decode", False)]
        gated = "import base64\nx = base64.b64decode(s, validate=True)\n"
        assert [(c, g) for _, c, g in _decode_calls(gated)] == [("base64.b64decode", True)]
        through_gate = "from ._b64strict import b64decode_strict\nx = b64decode_strict(s)\n"
        assert _decode_calls(through_gate) == []

    def test_anti_tautology_blinded_scanner_stops_catching_the_violation(self):
        """Twin: gut the detector's own decision property and the planted violation survives."""
        planted = "import base64\nx = base64.urlsafe_b64decode(s)\n"
        assert _decode_calls(planted)                                  # detector works
        assert _decode_calls(planted, primitive_names=frozenset()) == []  # detector blinded
        # and the repo-wide sweep collapses to "nothing to check" once blinded
        assert _ungated_modules(primitive_names=frozenset()) == {}


# --------------------------------------------------------------------------------------------
# L5-02 — runtime: the family of functions that route through the gate
# --------------------------------------------------------------------------------------------
def _gate_routed_functions():
    """Discover, by PROVENANCE (co_names), every package function that calls the gate."""
    modules = []
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        for info in pkgutil.walk_packages([str(SRC_ROOT)], prefix="proofbundle."):
            try:
                modules.append(importlib.import_module(info.name))
            except Exception:  # noqa: BLE001 - an optional-dependency module is not a wire surface
                continue
    seen = {}
    for module in modules:
        for name, obj in vars(module).items():
            if not inspect.isfunction(obj) or obj.__module__ != module.__name__:
                continue
            if "b64decode_strict" not in obj.__code__.co_names:
                continue
            seen[f"{module.__name__}.{name}"] = obj
    return seen


# Functions that route through the gate but take more than one required argument, so they cannot be
# probed as plain decoders. Pinned so a NEW one is noticed and classified instead of silently unswept.
NON_PROBEABLE_GATE_CALLERS = {
    "proofbundle.hf_evals.to_eval_results_entry":
        "full entry builder; its gate call is the eval-claim schema peek, covered by test_hf_evals.py",
}


class TestStrictDecoderFamily:
    def test_family_is_discovered_and_covers_every_wire_module(self):
        found = _gate_routed_functions()
        modules = {name.rsplit(".", 1)[0].replace("proofbundle.", "").replace(".", "/") + ".py"
                   for name in found}
        missing = {m for m in OWNED_MODULES if m not in modules}
        assert missing == set(), f"owned wire module without a gate-routed decoder: {missing}"

    def test_every_probeable_decoder_rejects_junk_and_accepts_the_clean_form(self):
        found = _gate_routed_functions()
        probed = 0
        for name, fn in sorted(found.items()):
            required = [p for p in inspect.signature(fn).parameters.values()
                        if p.default is inspect.Parameter.empty
                        and p.kind not in (p.VAR_POSITIONAL, p.VAR_KEYWORD)]
            if len(required) != 1:
                assert name in NON_PROBEABLE_GATE_CALLERS, (
                    f"{name} routes through the gate but is not probeable and not pinned")
                continue
            clean = base64.urlsafe_b64encode(b"wire-bytes").decode("ascii").rstrip("=")
            assert fn(clean) == b"wire-bytes", name
            with pytest.raises((binascii.Error, ValueError, TypeError)):
                fn(_inject_junk(clean))
            probed += 1
        assert probed >= 8, f"expected the eight JWS/DSSE siblings to be probed, got {probed}"

    def test_pinned_non_probeable_entries_are_real(self):
        found = _gate_routed_functions()
        assert set(NON_PROBEABLE_GATE_CALLERS) <= set(found)


# --------------------------------------------------------------------------------------------
# L5-02 — the two exported surfaces named in the finding
# --------------------------------------------------------------------------------------------
class TestSignedArtefactsAreNotMalleable:
    def test_dsse_envelope_junk_is_rejected_payload_and_signature(self):
        sk, pub = _keypair()
        env = dsse.sign_envelope(b'{"_type":"test"}', sk, payload_type="application/vnd.test+json")
        assert dsse.verify_envelope(env, pub) is True

        inflated = dict(env, payload=env["payload"][:2] + "!" * 50000 + env["payload"][2:])
        with pytest.raises(Exception) as exc:      # noqa: PT011 - the documented signal is checked below
            dsse.verify_envelope(inflated, pub)
        assert "not valid base64" in str(exc.value)

        sig = env["signatures"][0]["sig"]
        junk_sig = dict(env, signatures=[{"sig": _inject_junk(sig)}])
        assert dsse.verify_envelope(junk_sig, pub) is False

    def test_dsse_still_accepts_both_alphabets_and_unpadded_forms(self):
        """Backward compatibility: DSSE verifiers MUST accept standard OR url-safe base64."""
        sk, pub = _keypair()
        body = bytes(range(256)) * 3
        env = dsse.sign_envelope(body, sk, payload_type="application/vnd.test+json")
        url = base64.urlsafe_b64encode(body).decode("ascii")
        assert any(c in url for c in "-_")
        assert dsse.verify_envelope(dict(env, payload=url), pub) is True
        assert dsse.verify_envelope(dict(env, payload=url.rstrip("=")), pub) is True
        std = base64.b64encode(body).decode("ascii")
        assert dsse.verify_envelope(dict(env, payload=std), pub) is True
        assert dsse.verify_envelope(dict(env, payload=std.rstrip("=")), pub) is True

    def test_status_token_junk_is_rejected(self):
        sk, pub = _keypair()
        token = statuslist.issue_status_list_token([0, 1, 0, 1], uri="https://x/l", signer=sk, iat=100)
        assert statuslist.verify_status_snapshot(
            token, expected_uri="https://x/l", index=1, issuer_pubkey=pub)["ok"] is True
        header, payload, sig = token.split(".")
        bloated = f"{header}.{payload}.{sig[:2] + '!' * 100000 + sig[2:]}"
        result = statuslist.verify_status_snapshot(
            bloated, expected_uri="https://x/l", index=1, issuer_pubkey=pub)
        assert result["ok"] is False
        assert "malformed" in result["detail"]

    def test_deliberate_gap_standard_alphabet_still_accepted_on_a_base64url_surface(self):
        """Pinned compatibility decision — see DELIBERATE_ALPHABET_COMPAT."""
        raw = bytes(range(256))
        std = base64.b64encode(raw).decode("ascii")
        assert "+" in std or "/" in std
        assert statuslist._b64url_decode(std) == raw, DELIBERATE_ALPHABET_COMPAT

    def test_anti_tautology_pre_fix_decoder_makes_the_junk_verify_again(self, monkeypatch):
        """Twin: restore the lax decoder and the SAME envelope verifies — the axis is the alphabet."""
        sk, pub = _keypair()
        env = dsse.sign_envelope(b'{"_type":"test"}', sk, payload_type="application/vnd.test+json")
        junked = dict(env, payload=_inject_junk(env["payload"]))
        with pytest.raises(Exception):  # noqa: B017, PT011 - fixed behaviour
            dsse.verify_envelope(junked, pub)
        monkeypatch.setattr(dsse, "b64decode_strict", _lax_b64decode)
        assert dsse.verify_envelope(junked, pub) is True   # pre-fix behaviour, reproduced on demand


# --------------------------------------------------------------------------------------------
# L2-01 — the type floor on every value used in arithmetic or indexing
# --------------------------------------------------------------------------------------------
def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _sign_status_token(sk, payload: dict) -> str:
    header = {"alg": "EdDSA", "typ": statuslist.TYP}
    signing_input = _b64u(json.dumps(header).encode()) + "." + _b64u(json.dumps(payload).encode())
    return signing_input + "." + _b64u(sk.sign(signing_input.encode("ascii")))


def _genuine_payload() -> dict:
    return {"sub": "https://x/l", "iat": 100, "exp": 9999, "ttl": 3600,
            "status_list": {"bits": 1, "lst": _b64u(zlib.compress(bytes([0b1010]), 9))}}


HOSTILE_VALUES = [1.0, 2.5, True, False, "1", [1], {"a": 1}, None,
                  float("nan"), float("inf"), 10 ** 4000, -1]


class TestStatusListTypeFloor:
    def test_float_bits_is_a_verdict_not_a_crash(self):
        sk, pub = _keypair()
        payload = _genuine_payload()
        payload["status_list"]["bits"] = 1.0        # 1.0 in (1, 2, 4, 8) is True
        token = _sign_status_token(sk, payload)
        result = statuslist.verify_status_snapshot(
            token, expected_uri="https://x/l", index=0, issuer_pubkey=pub)
        assert result["ok"] is False
        assert "bits" in result["detail"]

    def test_hostile_now_is_a_verdict_not_a_crash(self):
        sk, pub = _keypair()
        token = _sign_status_token(sk, _genuine_payload())
        for bad in ("soon", [1], {"t": 1}, object()):
            result = statuslist.verify_status_snapshot(
                token, expected_uri="https://x/l", index=0, issuer_pubkey=pub, now=bad)
            assert result["ok"] is False, bad
            assert "now" in result["detail"], bad

    def test_float_now_keeps_working(self):
        """time.time() is a float and a legitimate caller value — no breaking change."""
        sk, pub = _keypair()
        token = _sign_status_token(sk, _genuine_payload())
        result = statuslist.verify_status_snapshot(
            token, expected_uri="https://x/l", index=0, issuer_pubkey=pub, now=200.5)
        assert result["ok"] is True and result["fresh"] is True

    def test_verdict_shape_parity_happy_vs_fail_closed(self):
        sk, pub = _keypair()
        good = statuslist.verify_status_snapshot(
            _sign_status_token(sk, _genuine_payload()),
            expected_uri="https://x/l", index=0, issuer_pubkey=pub)
        bad_payload = _genuine_payload()
        bad_payload["status_list"]["bits"] = 1.0
        bad = statuslist.verify_status_snapshot(
            _sign_status_token(sk, bad_payload),
            expected_uri="https://x/l", index=0, issuer_pubkey=pub)
        assert set(good) == set(bad)

    def test_anti_tautology_removing_the_floor_restores_the_crash(self, monkeypatch):
        """Twin: gut the shared floor predicate and the SAME token crashes again."""
        sk, pub = _keypair()
        payload = _genuine_payload()
        payload["status_list"]["bits"] = 1.0
        token = _sign_status_token(sk, payload)
        monkeypatch.setattr(statuslist, "_is_plain_int", lambda value: True)
        with pytest.raises(TypeError):
            statuslist.verify_status_snapshot(
                token, expected_uri="https://x/l", index=0, issuer_pubkey=pub)


class TestStatusListTypeFloorSweep:
    """The CLASS, not the two instances: sweep every signed-payload value and every parameter."""

    def _leaf_paths(self, node, prefix=()):
        if isinstance(node, dict):
            for key, value in node.items():
                yield from self._leaf_paths(value, prefix + (key,))
        else:
            yield prefix

    def _set_path(self, payload, path, value):
        node = payload
        for key in path[:-1]:
            node = node[key]
        node[path[-1]] = value

    def test_every_signed_payload_leaf_survives_the_hostile_family(self):
        sk, pub = _keypair()
        paths = list(self._leaf_paths(_genuine_payload()))
        assert len(paths) >= 6, paths          # sub, iat, exp, ttl, status_list.bits, status_list.lst
        for path in paths:
            for hostile in HOSTILE_VALUES:
                payload = _genuine_payload()
                self._set_path(payload, path, hostile)
                token = _sign_status_token(sk, payload)
                result = statuslist.verify_status_snapshot(
                    token, expected_uri="https://x/l", index=0, issuer_pubkey=pub, now=500)
                assert isinstance(result, dict), (path, hostile)
                assert isinstance(result["ok"], bool), (path, hostile)
                if result["ok"]:
                    assert isinstance(result["status"], int), (path, hostile, result)
                    assert isinstance(result["status_label"], str), (path, hostile, result)
                    assert result["fresh"] in (None, True, False), (path, hostile, result)
                # A value that is neither an int, a string nor absent cannot be well-typed for ANY
                # slot of this payload (bool is excluded on purpose: True would index as 1), so an
                # accepting verdict for one is a false accept, not a policy decision.
                if isinstance(hostile, bool) or not isinstance(hostile, (int, str, type(None))):
                    assert result["ok"] is False, (path, hostile, result)

    def test_every_parameter_survives_the_hostile_family(self):
        sk, pub = _keypair()
        token = _sign_status_token(sk, _genuine_payload())
        base = dict(status_list_token=token, expected_uri="https://x/l", index=0,
                    issuer_pubkey=pub, now=500, receipt_issuer_pubkey=pub)
        parameters = list(inspect.signature(statuslist.verify_status_snapshot).parameters)
        assert set(parameters) == set(base), (parameters, sorted(base))
        for name in parameters:
            for hostile in HOSTILE_VALUES:
                kwargs = dict(base, **{name: hostile})
                result = statuslist.verify_status_snapshot(**kwargs)
                assert isinstance(result, dict), (name, hostile)
                assert isinstance(result["ok"], bool), (name, hostile)

    def test_no_nan_or_inf_leaks_into_a_true_freshness_verdict(self):
        sk, pub = _keypair()
        token = _sign_status_token(sk, _genuine_payload())
        for bad in (float("nan"), float("-inf")):
            result = statuslist.verify_status_snapshot(
                token, expected_uri="https://x/l", index=0, issuer_pubkey=pub, now=bad)
            assert result["fresh"] is not True, bad
            assert not (result["fresh"] and math.isnan(bad))
