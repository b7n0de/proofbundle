"""A producer reads a caller's key once, and what it judges is what it writes.

WHERE THIS COMES FROM. Lens run 7 at 75c3aa48, findings F1 and F2. Every producer that writes a
caller's Ed25519 key for someone to trust applied the trust-anchor rule, but the rule and the writer
read the key through different doors. `signature.ed25519_trust_anchor_weakness` reads `len(key)` and
`bytes(key)`, the caller's `__len__` and `__bytes__`; the writers read the key's own buffer (base64)
or its `__radd__` (a concatenation); and a key given as base64 text reached the rule through
`_wire_b64._as_bytes`, which called the caller's `encode`, while the producer wrote the text itself.
Measured by the lens at 75c3aa48 on 3.10.12 to 3.14.7: a `bytes` subclass whose `__bytes__` names a
real key while its own bytes are the identity point was bound by `issue_sd_jwt` and written by
`checkpoint.vkey` and `checkpoint.cosign_vkey`, 13 of 13 weak encodings each; a `bytearray` subclass
the same at `issue_sd_jwt`; and a `str` subclass whose `encode` names a real key was pinned by
`policy_profiles.instantiate_template`, signed into a pack by `trust_pack.sign_trust_pack`, written
by `trust_pack.build_trust_pack_statement` and by the three `assemble` steps under `scripts/`.

THE PROPERTY, for every producer of the sweep list below and every hostile form of its input: the
producer reads the value once, from its own storage, into an exact `bytes` or `str`, and uses only
that. So it refuses exactly when the key the value HOLDS is one the rule refuses, naming the rule's
reason, and otherwise writes exactly that key, with a key ID computed over it. Each form carries one
key in its storage and another in the methods it overrides, in both directions: a weak key stored and
a real key answered, and a real key stored and a weak key answered. The old reading fails the first
direction by writing the weak key, and the second by refusing the real key it holds for the weak key
its methods answered.

THE FORMS. `bytes` and `bytearray` subclasses whose `__bytes__` answers for the other key (what the
rule read); a `bytes` subclass whose `__radd__` does (what a concatenation read); a `bytes` subclass
whose `__buffer__` does (PEP 688: what base64, `memoryview` and `hashlib` read from Python 3.12 on;
on 3.10 and 3.11 the method is never called, which `test_where_buffer_steers` records); a `str`
subclass whose `encode` does (what the decoder read); a `str` subclass whose `encode`, `__getitem__`,
`startswith`, `__str__`, `__format__`, `__len__`, `__iter__`, `__add__` and `__radd__` all do (the
issuer parser sliced and prefix-tested); and, for the trust pack, a `dict` subclass whose `get` and
`__getitem__` answer for the other key while its stored item holds the first (what the validator read,
while the canonicaliser writes `items()`).

THE SWEEP LIST, every place under src/ and scripts/ that applies the rule to a caller's key and then
writes, hashes or signs over it (read at 75c3aa48 and after this fix); `_RULE_SITES` below holds
every call of the rule's helpers by file and function, and the scan checks it in both directions:

    src/proofbundle/sdjwt_issue.py        issue_sd_jwt                 holder key into cnf.jwk
    src/proofbundle/checkpoint.py         vkey, key_id                 log vkey and its key ID
    src/proofbundle/checkpoint.py         cosign_vkey, cosign_key_id   witness vkey and its key ID
    src/proofbundle/checkpoint.py         cosign_vkey_mldsa, cosign_key_id_mldsa
                                                                       ML-DSA witness vkey; no rule,
                                                                       the same two reads
    src/proofbundle/policy_profiles.py    instantiate_template         pinned issuer keys
    src/proofbundle/trust_pack.py         sign_trust_pack              the pack's keys, signed
    src/proofbundle/trust_pack.py         build_trust_pack_statement   the pack's keys, unsigned
    src/proofbundle/intoto.py             export_eval_result_dsse, export_intoto_dsse
                                                                       judge the claim's issuer and
                                                                       sign a statement over the
                                                                       claim; the issuer is not written
    scripts/gen_findings_register.py      assemble                     the register's signer key
    scripts/sign_readiness_artifact.py    assemble                     the artifact's signer key
    scripts/pre_tag_receipt.py            assemble_receipt             the receipt's signer key

Every other call of the rule is on a verifier's side, on bytes the verifier parsed itself or on a
caller's pin it only compares (`_RULE_SITES` names each with its reason).
"""
from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

REPO = Path(__file__).resolve().parents[1]
for _p in (str(REPO), str(REPO / "src")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from proofbundle.signature import TRUST_ANCHOR_REFUSAL, ed25519_trust_anchor_weakness  # noqa: E402
from tests.test_trust_anchor_keys_refused_on_every_surface import WEAK, _raw  # noqa: E402


def _not_shipped(rel: str) -> bool:
    """True only for a repository file this tree lacks BY DESIGN.

    MEASURED IN CI at 7feeb47a (published-artifact-gate / hermetic-cleanroom): the extracted sdist
    does not carry `scripts/gen_findings_register.py`, `scripts/pre_tag_receipt.py` or
    `scripts/render_site_data.py` (MANIFEST.in leaves them out on purpose), so two `assemble` cases
    and the scan failed there on files that are absent by design. The answer comes from
    `tests/conftest.py`, the one place that decides it: outside a git checkout a missing file is
    N/A only when the distribution's own file list does not name it. A file the list names and the
    tree lacks is a packaging error and stays loud, and in a checkout nothing is skipped. Without
    conftest there is no basis, and the case stays loud as well."""
    if (REPO / rel).exists():
        return False
    try:
        from conftest import _verteilung_sollte_enthalten, running_in_repo_checkout  # noqa: PLC0415
    except Exception:                                  # noqa: BLE001
        return False
    return not running_in_repo_checkout() and not _verteilung_sollte_enthalten(rel)


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


# ── the hostile forms: the key in storage, another key in the methods ─────────────────────────────

class BytesAnswersBytes(bytes):
    """Stores one key; `bytes(x)` answers for `self.other`."""
    other: bytes

    def __bytes__(self):
        return self.other


class BytearrayAnswersBytes(bytearray):
    """Stores one key; `bytes(x)` answers for `self.other`."""
    other: bytes

    def __bytes__(self):
        return self.other


class BytesAnswersRadd(bytes):
    """Stores one key; `prefix + x` answers `prefix + self.other`."""
    other: bytes

    def __radd__(self, left):
        return left + self.other


class BytesAnswersBuffer(bytes):
    """Stores one key; its buffer (PEP 688) is `self.other`. Called from Python 3.12 on only."""
    other: bytes

    def __buffer__(self, flags):
        return memoryview(self.other)


class TextAnswersEncode(str):
    """Holds one base64 text; `encode` answers for `self.other`."""
    other: str

    def encode(self, *a, **k):
        return self.other.encode(*a, **k)


class TextAnswersEverything(str):
    """Holds one text; every method a producer read answers for `self.other`."""
    other: str

    def encode(self, *a, **k):
        return self.other.encode(*a, **k)

    def __getitem__(self, i):
        return self.other[i]

    def startswith(self, *a):
        return self.other.startswith(*a)

    def __str__(self):
        return self.other

    def __format__(self, spec):
        return format(self.other, spec)

    def __len__(self):
        return len(self.other)

    def __iter__(self):
        return iter(self.other)

    def __add__(self, right):
        return self.other + right

    def __radd__(self, left):
        return left + self.other


class DictAnswers(dict):
    """Stores `{"publicKey": <one text>}`; `get` and `[...]` answer for `self.other`."""
    other: str

    def get(self, k, default=None):
        return self.other if k == "publicKey" else super().get(k, default)

    def __getitem__(self, k):
        return self.other if k == "publicKey" else super().__getitem__(k)


def _raw_form(cls, stored: bytes, other: bytes):
    v = cls(stored)
    v.other = other
    return v


def _text_form(cls, stored: str, other: str):
    v = cls(stored)
    v.other = other
    return v


RAW_FORMS = {"bytes subclass, __bytes__": BytesAnswersBytes,
             "bytearray subclass, __bytes__": BytearrayAnswersBytes,
             "bytes subclass, __radd__": BytesAnswersRadd,
             "bytes subclass, __buffer__": BytesAnswersBuffer}
TEXT_FORMS = {"str subclass, encode": TextAnswersEncode,
              "str subclass, every method": TextAnswersEverything}


def _pairs():
    """(stored, answered, label) per weak key, in both directions, with a fresh real key each."""
    for weak, _reason in WEAK:
        real = _raw(Ed25519PrivateKey.generate())
        yield weak, real, "weak key stored, real key answered"
        yield real, weak, "real key stored, weak key answered"


class _Contract(unittest.TestCase):
    """The one assertion every producer case makes."""

    def _holds(self, stored: bytes, outcome: "tuple[str, Any]"):
        """`outcome` is ("refused", message) or ("written", key bytes as written). A refusal is right
        exactly when the stored key is one the rule refuses, and names its reason; what is written is
        the stored key and nothing else."""
        grund = ed25519_trust_anchor_weakness(stored)
        kind, what = outcome
        if grund is not None:
            self.assertEqual(kind, "refused", f"a {grund} key held in storage was written: {what!r:.80}")
            self.assertIn(TRUST_ANCHOR_REFUSAL[grund], what)
        else:
            self.assertEqual(kind, "written", f"the key held in storage was refused: {what!r:.200}")
            self.assertEqual(what, stored, "the producer wrote another key than the one it holds")


# ── 1. the producers that take the raw key ─────────────────────────────────────────────────────────

class ProducersOfRawKeys(_Contract):

    @staticmethod
    def _claim():
        from _full_eval_claim import full_eval_claim  # noqa: PLC0415
        from proofbundle.evalclaim import issuer_fingerprint
        issuer = Ed25519PrivateKey.generate()
        # A whole claim: since D4 (PR 300) `issue_sd_jwt` refuses a claim `decode_eval_claim` refuses.
        return issuer, full_eval_claim(issuer_fingerprint(issuer), suite="s")

    def test_where_buffer_steers(self):
        """The measurement behind the `__buffer__` form, as a precondition, not as the property: from
        3.12 on a `bytes` subclass's `__buffer__` decides what `memoryview` and base64 read, before 3.12
        it is never called. The property below holds either way."""
        weak, real = WEAK[0][0], _raw(Ed25519PrivateKey.generate())
        v = _raw_form(BytesAnswersBuffer, real, weak)
        steered = memoryview(v).tobytes() == weak
        self.assertEqual(steered, sys.version_info >= (3, 12))
        self.assertEqual(base64.b64decode(base64.b64encode(v)) == weak, sys.version_info >= (3, 12))

    def _result_of(self, call, decode):
        from proofbundle.errors import BundleFormatError
        try:
            out = call()
        except (ValueError, BundleFormatError) as exc:
            return "refused", str(exc)
        return "written", decode(out)

    def test_issue_sd_jwt_binds_the_key_it_holds(self):
        from proofbundle.sdjwt_issue import issue_sd_jwt
        issuer, claim = self._claim()
        root = _b64(b"\x11" * 32)

        def written(compact):
            p = compact.split("~", 1)[0].split(".")[1]
            return _b64url_decode(json.loads(_b64url_decode(p))["cnf"]["jwk"]["x"])

        for name, cls in RAW_FORMS.items():
            for stored, other, label in _pairs():
                with self.subTest(form=name, key=(stored if "weak key stored" in label else other).hex(),
                                  direction=label):
                    v = _raw_form(cls, stored, other)
                    self._holds(stored, self._result_of(
                        lambda: issue_sd_jwt(claim, issuer, root_b64=root, holder_public_key=v), written))

    def test_the_vkeys_carry_the_key_they_hold_and_its_key_id(self):
        from proofbundle import checkpoint as cp
        for writer, key_id in ((cp.vkey, cp.key_id), (cp.cosign_vkey, cp.cosign_key_id)):
            for name, cls in RAW_FORMS.items():
                for stored, other, label in _pairs():
                    with self.subTest(vkey=writer.__name__, form=name, direction=label,
                                      key=(stored if "weak key stored" in label else other).hex()):
                        v = _raw_form(cls, stored, other)
                        got = self._result_of(lambda: writer("name", v), lambda s: s)
                        if got[0] == "written":
                            _name, kid_hex, keymat = got[1].split("+", 2)
                            material = base64.b64decode(keymat)[1:]
                            self.assertEqual(kid_hex, key_id("name", stored).hex(),
                                             "the key ID is not the ID of the key written")
                            got = ("written", material)
                        self._holds(stored, got)

    def test_a_key_id_is_taken_over_the_key_held(self):
        """`key_id` and `cosign_key_id` check the length and hash the key: one reading for both."""
        from proofbundle import checkpoint as cp
        for key_id in (cp.key_id, cp.cosign_key_id):
            for name, cls in RAW_FORMS.items():
                for stored, other, label in _pairs():
                    with self.subTest(key_id=key_id.__name__, form=name, direction=label):
                        v = _raw_form(cls, stored, other)
                        self.assertEqual(key_id("name", v), key_id("name", stored))

    def test_the_ml_dsa_vkey_carries_the_key_it_holds(self):
        """No rule applies to an ML-DSA-44 key; the key ID and the key material are the same reading."""
        from proofbundle import checkpoint as cp
        stored, other = os.urandom(1312), os.urandom(1312)
        for name, cls in RAW_FORMS.items():
            with self.subTest(form=name):
                v = _raw_form(cls, stored, other)
                _n, kid_hex, keymat = cp.cosign_vkey_mldsa("w", v).split("+", 2)
                self.assertEqual(base64.b64decode(keymat)[1:], stored)
                self.assertEqual(kid_hex, cp.cosign_key_id_mldsa("w", stored).hex())
                self.assertEqual(cp.cosign_key_id_mldsa("w", v), cp.cosign_key_id_mldsa("w", stored))

    def test_a_key_of_another_type_is_refused_for_its_type(self):
        """F3 of lens run 7. A real key as a `memoryview`, an `array('B')` or a ctypes byte array was
        written by `issue_sd_jwt` at a4e2fa5c and refused at 75c3aa48 with the rule's length reason,
        which is wrong for 32 bytes. Decided: such a buffer stays refused, because its only view is the
        buffer, which a subclass can steer from 3.12 on; the reason now says the key must be `bytes` or
        `bytearray`, and `bytes(...)` of it is written. The vkey producers refused them already and
        still do."""
        import array
        import ctypes
        from proofbundle import checkpoint as cp
        from proofbundle.errors import BundleFormatError
        from proofbundle.sdjwt_issue import issue_sd_jwt
        issuer, claim = self._claim()
        real = _raw(Ed25519PrivateKey.generate())
        forms = {"memoryview": memoryview(real), "array('B')": array.array("B", real),
                 "ctypes c_ubyte * 32": (ctypes.c_ubyte * 32).from_buffer_copy(real)}
        try:
            import numpy
            forms["numpy uint8"] = numpy.frombuffer(real, dtype=numpy.uint8).copy()
        except ImportError:
            pass
        for name, v in forms.items():
            with self.subTest(form=name):
                with self.assertRaises(ValueError) as ctx:
                    issue_sd_jwt(claim, issuer, root_b64=_b64(b"\x11" * 32), holder_public_key=v)
                self.assertIn("must be bytes or bytearray", str(ctx.exception))
                self.assertNotIn("exactly 32 bytes", str(ctx.exception))
                issue_sd_jwt(claim, issuer, root_b64=_b64(b"\x11" * 32), holder_public_key=bytes(v))
                for writer in (cp.vkey, cp.cosign_vkey):
                    with self.assertRaises(BundleFormatError):
                        writer("name", v)


# ── 2. the producers that take the key as base64 text ─────────────────────────────────────────────

class ProducersOfKeyText(_Contract):

    def _result_of(self, call, decode):
        from proofbundle.errors import ProofBundleError
        try:
            out = call()
        except ProofBundleError as exc:
            return "refused", str(exc)
        return "written", decode(out)

    def test_instantiate_template_pins_the_key_it_holds(self):
        from proofbundle.policy_profiles import instantiate_template

        def written(inst):
            return base64.b64decode(json.loads(json.dumps(inst))["allowed_issuers"][0]["public_key_b64"])

        for name, cls in TEXT_FORMS.items():
            for stored, other, label in _pairs():
                with self.subTest(form=name, direction=label):
                    v = _text_form(cls, _b64(stored), _b64(other))
                    self._holds(stored, self._result_of(lambda: instantiate_template(
                        "strict-eval-template-v1", issuer_keys=[v], policy_id="org/x"), written))

    @staticmethod
    def _pred(owner, w):
        return {"schemaVersion": "0.1.0", "trustPackId": "tp", "version": 1,
                "expires": "2099-01-01T00:00:00Z", "prevVersionDigest": None,
                "roles": {"root": {"keyIds": ["o", "w"], "threshold": 1}},
                "keys": {"o": {"publicKey": _b64(_raw(owner))}, "w": w},
                "nonClaims": ["does not assert the key holders are honest"]}

    def test_the_trust_pack_signs_and_writes_the_key_it_holds(self):
        from proofbundle.trust_pack import build_trust_pack_statement, sign_trust_pack
        owner = Ed25519PrivateKey.generate()

        def signed(env):
            return base64.b64decode(json.loads(base64.b64decode(env["payload"]))["predicate"]["keys"]["w"]["publicKey"])

        def stated(stmt):
            return base64.b64decode(json.loads(json.dumps(stmt))["predicate"]["keys"]["w"]["publicKey"])

        def holding_dict(stored_text: str, other_text: str) -> dict:
            w = DictAnswers(publicKey=stored_text)
            w.other = other_text
            return w

        forms = {name: (lambda s, o, cls=cls: {"publicKey": _text_form(cls, s, o)})
                 for name, cls in TEXT_FORMS.items()}
        forms["dict subclass, get and []"] = holding_dict
        for name, make in forms.items():
            for stored, other, label in _pairs():
                w = make(_b64(stored), _b64(other))
                for producer, call, decode in (
                        ("sign_trust_pack", lambda: sign_trust_pack(self._pred(owner, w), {"o": owner}), signed),
                        ("build_trust_pack_statement", lambda: build_trust_pack_statement(self._pred(owner, w)),
                         stated)):
                    with self.subTest(producer=producer, form=name, direction=label):
                        self._holds(stored, self._result_of(call, decode))

    def test_the_predicate_is_judged_in_the_form_that_is_signed(self):
        """Reading the predicate once through its RFC 8785 form changes a verdict for a PLAIN predicate,
        decided and pinned here. An integer field given as a float of integral value and an array given
        as a tuple were refused at 75c3aa48 by the validator's type checks, and are signed now, because
        the form that is signed does not carry the difference: the statement and the signed payload are
        byte-identical to the ones for the integer or the list. A value the form keeps apart stays
        refused (`1.5`, `True`)."""
        from proofbundle.trust_pack import TrustPackError, build_trust_pack_statement, sign_trust_pack
        owner = Ed25519PrivateKey.generate()
        plain = self._pred(owner, {"publicKey": _b64(_raw(Ed25519PrivateKey.generate()))})

        def with_role(**kw):
            return dict(plain, roles={"root": dict(plain["roles"]["root"], **kw)})

        stated = json.dumps(build_trust_pack_statement(plain), sort_keys=True)
        payload = sign_trust_pack(plain, {"o": owner})["payload"]
        same_form = {"version 1.0": dict(plain, version=1.0),
                     "threshold 1.0": with_role(threshold=1.0),
                     "keyIds as a tuple": with_role(keyIds=tuple(plain["roles"]["root"]["keyIds"])),
                     "nonClaims as a tuple": dict(plain, nonClaims=tuple(plain["nonClaims"]))}
        for name, pred in same_form.items():
            with self.subTest(written_as_the_plain_predicate=name):
                self.assertEqual(json.dumps(build_trust_pack_statement(pred), sort_keys=True), stated)
                self.assertEqual(sign_trust_pack(pred, {"o": owner})["payload"], payload)
        for name, pred in {"version 1.5": dict(plain, version=1.5),
                           "version True": dict(plain, version=True),
                           "threshold 1.5": with_role(threshold=1.5)}.items():
            for producer in (lambda p: build_trust_pack_statement(p),
                             lambda p: sign_trust_pack(p, {"o": owner})):
                with self.subTest(refused=name):
                    with self.assertRaises(TrustPackError):
                        producer(pred)


# ── 3. the three `assemble` steps under scripts/ ───────────────────────────────────────────────────

_PRODUCERS = {
    # script, the assemble function, the module whose `canonical_bytes` is signed, where the key lands
    "gen_findings_register": ("scripts/gen_findings_register.py", "assemble", "gen_findings_register",
                              ("signature", "public_key_b64")),
    "sign_readiness_artifact": ("scripts/sign_readiness_artifact.py", "assemble", "sign_readiness_artifact",
                                ("signature", "public_key_b64")),
    "pre_tag_receipt": ("scripts/pre_tag_receipt.py", "assemble_receipt", "pre_tag_receipt_lib",
                        ("signer_pubkey",)),
}

_BODIES = {
    "gen_findings_register": {"schema": "proofbundle.findings_register.v1", "version": "9.9.9",
                              "generated_at": "2026-09-26T00:00:00Z", "findings": []},
    "sign_readiness_artifact": {"schema": "x", "signer_role": "release-runner",
                                "produced_at": "2026-09-26T00:00:00Z"},
    "pre_tag_receipt": {"version": "9.9.9", "subject_tree_digest": "a" * 64,
                        "gate_source_digest": "b" * 64, "audit_command": "nobody ran this",
                        "audit_exit_code": 0, "audit_output_digest": "c" * 64, "runner_identity": "nobody",
                        "produced_at": "2026-09-26T00:00:00Z"},
}

#: Runs in a process of its own: pre_tag_receipt.py changes the process environment when it is imported.
#: The two text forms are defined again here, as above. Per case the driver makes a real key of its own,
#: so it can sign the body with it, and puts the case's weak key on the other side of the form.
_DRIVER = r'''
import base64, importlib.util, json, sys
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

class TextAnswersEncode(str):
    def encode(self, *a, **k): return self.other.encode(*a, **k)

class TextAnswersEverything(str):
    def encode(self, *a, **k): return self.other.encode(*a, **k)
    def __getitem__(self, i): return self.other[i]
    def startswith(self, *a): return self.other.startswith(*a)
    def __str__(self): return self.other
    def __format__(self, spec): return format(self.other, spec)
    def __len__(self): return len(self.other)
    def __iter__(self): return iter(self.other)
    def __add__(self, right): return self.other + right
    def __radd__(self, left): return left + self.other

FORMS = {"str subclass, encode": TextAnswersEncode, "str subclass, every method": TextAnswersEverything}

def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

def b64(b):
    return base64.b64encode(b).decode()

path, fn_name, lib_path, body, cases, where = sys.argv[1:7]
mod = load("producer", path)
fn, body, where = getattr(mod, fn_name), json.loads(body), json.loads(where)
lib = mod if lib_path == path else load("lib", lib_path)
if hasattr(lib, "RECEIPT_SCHEMA"):
    body = dict(body, schema=lib.RECEIPT_SCHEMA)
canon = lib.canonical_bytes(body)
out = []
for form, weak_hex, real_stored in json.loads(cases):
    k = Ed25519PrivateKey.generate()
    real, weak = k.public_key().public_bytes_raw(), bytes.fromhex(weak_hex)
    stored, other = (real, weak) if real_stored else (weak, real)
    v = FORMS[form](b64(stored))
    v.other = b64(other)
    # signed by the real key: the old reading judged the answered key, verified the pair and wrote
    # the stored text in the first direction, and refused a real stored key in the second
    try:
        res = fn(body, b64(k.sign(canon)), v)
    except SystemExit as exc:
        out.append([form, stored.hex(), other.hex(), "refused", str(exc.code)])
        continue
    written = json.loads(json.dumps(res))
    for step in where:
        written = written[step]
    out.append([form, stored.hex(), other.hex(), "written", written])
print(json.dumps(out))
'''


class TheAssembleSteps(_Contract):
    """Each `assemble` step is called in a process of its own with the key text as a hostile `str`
    and the signature made by the real one of the two keys over the body."""

    def _run(self, producer: str) -> list:
        path, fn, lib, where = _PRODUCERS[producer]
        for rel in (path, f"scripts/{lib}.py"):
            if _not_shipped(rel):
                self.skipTest(f"not shipped: {rel} is not in this distribution, so its `assemble` "
                              "step is N/A outside a git checkout")
        cases =[[form, weak.hex(), real_stored] for weak, _reason in WEAK for form in TEXT_FORMS
                 for real_stored in (False, True)]
        env = dict(os.environ, PYTHONPATH=str(REPO / "src"), PYTHONDONTWRITEBYTECODE="1")
        r = subprocess.run([sys.executable, "-B", "-c", _DRIVER, str(REPO / path), fn,
                            str(REPO / "scripts" / f"{lib}.py"), json.dumps(_BODIES[producer]),
                            json.dumps(cases), json.dumps(list(where))],
                           capture_output=True, text=True, timeout=300, env=env)
        if r.returncode != 0:
            raise AssertionError(f"driver for {producer} failed: {r.stderr[-1200:]}")
        return json.loads(r.stdout.strip().splitlines()[-1])

    def _check(self, producer: str):
        rows = self._run(producer)
        self.assertEqual(len(rows), len(WEAK) * len(TEXT_FORMS) * 2)
        for form, stored_hex, other_hex, kind, what in rows:
            stored = bytes.fromhex(stored_hex)
            label = ("weak key stored, real key answered" if ed25519_trust_anchor_weakness(stored)
                     else "real key stored, weak key answered")
            with self.subTest(form=form, direction=label):
                self._holds(stored, (kind, base64.b64decode(what) if kind == "written" else what))

    def test_gen_findings_register_assemble(self):
        self._check("gen_findings_register")

    def test_sign_readiness_artifact_assemble(self):
        self._check("sign_readiness_artifact")

    def test_pre_tag_receipt_assemble(self):
        self._check("pre_tag_receipt")


# ── 4. the exports that judge a claim's issuer before they sign ───────────────────────────────────

class TheExportsJudgeTheIssuerTheClaimHolds(_Contract):
    """`intoto.export_eval_result_dsse` and `export_intoto_dsse` refuse to sign a statement over a claim
    whose issuer key the rule refuses. They write no key; the property is that the refusal follows the
    issuer the claim HOLDS. At 75c3aa48 the parser prefix-tested and sliced the caller's `str`, so a
    subclass whose `startswith` and `__getitem__` answered for a real key passed a claim that holds the
    identity point, and refused one that holds a real key."""

    @classmethod
    def setUpClass(cls):
        from proofbundle import evalclaim as ec
        from proofbundle.emit import generate_signer
        signer = generate_signer()
        try:
            claim, _ = ec.build_eval_claim(
                suite="s", suite_version="1", metric="acc", comparator=">=", threshold="0.80",
                score="0.90", n=10, model_id="m", dataset_id="d", issuer=ec.issuer_fingerprint(signer),
                timestamp="2026-09-26T12:00:00Z", model_salt=b"0" * 16, dataset_salt=b"1" * 16)
        except ec.EvalClaimError as exc:
            raise unittest.SkipTest(f"NOT MEASURABLE: the [eval] extra is missing ({exc}); the export "
                                    "cases did NOT run") from exc
        cls.claim = ec.decode_eval_claim(ec.emit_eval_receipt(claim, signer))

    def test_the_refusal_follows_the_issuer_held(self):
        from proofbundle.emit import generate_signer
        from proofbundle.errors import BundleFormatError
        from proofbundle.intoto import export_eval_result_dsse, export_intoto_dsse
        v = generate_signer()
        for export in (export_eval_result_dsse, export_intoto_dsse):
            for name, cls in TEXT_FORMS.items():
                for stored, other, label in _pairs():
                    with self.subTest(export=export.__name__, form=name, direction=label):
                        issuer = _text_form(cls, "ed25519:" + _b64(stored), "ed25519:" + _b64(other))
                        try:
                            export(dict(self.claim, issuer=issuer), v)
                            got: "tuple[str, Any]" = ("written", stored)   # exported; no key is written
                        except BundleFormatError as exc:
                            got = ("refused", str(exc))
                        self._holds(stored, got)


# ── 5. the readers themselves ─────────────────────────────────────────────────────────────────────

class TheReaders(unittest.TestCase):
    """`signature.plain_bytes`, `signature.plain_text` and `_wire_b64.wire_value` run no method of the
    caller's and return the exact type. Imported here, not at the top, so that against a tree without
    them only these cases fail."""

    def test_no_method_of_the_callers_runs(self):
        from proofbundle._wire_b64 import decode_b64, wire_value
        from proofbundle.signature import plain_bytes, plain_text

        def boom(*_a, **_k):
            raise AssertionError("a method of the caller's ran")

        class B(bytes):
            __bytes__ = __buffer__ = __getitem__ = __len__ = __iter__ = __add__ = __radd__ = boom
            __eq__ = __ne__ = __hash__ = __bool__ = hex = boom

        class BA(bytearray):
            __bytes__ = __buffer__ = __getitem__ = __len__ = __iter__ = __add__ = __radd__ = boom

        class S(str):
            encode = __str__ = __getitem__ = __len__ = __iter__ = __format__ = __add__ = boom
            __radd__ = __eq__ = __ne__ = __hash__ = __bool__ = startswith = boom

        key = WEAK[0][0]
        for value, reader in ((B(key), plain_bytes), (BA(key), plain_bytes)):
            with self.subTest(value=type(value).__name__):
                got = reader(value)
                self.assertIs(type(got), bytes)
                self.assertEqual(got, key)
        text = plain_text(S(_b64(key)))
        self.assertIs(type(text), str)
        self.assertEqual(text, _b64(key))
        self.assertIs(type(wire_value(S(_b64(key)))), str)
        self.assertIs(type(wire_value(B(_b64(key).encode()))), bytes)
        self.assertEqual(decode_b64(S(_b64(key))), key, "the decoder reads the text held")
        self.assertEqual(decode_b64(B(_b64(key).encode())), key)
        for other in (memoryview(key), 5, None, [key]):
            self.assertIsNone(plain_bytes(other))
            self.assertIsNone(plain_text(other))


# ── 6. every call of the rule under src/ and scripts/ is read and named ────────────────────────────

#: The helpers that apply the trust-anchor rule, by name.
_RULE_NAMES = {"ed25519_trust_anchor_weakness", "_validate_pinned_ed25519_pubkey", "_refuse_weak_ed25519_vkey",
               "_issuer_key_weakness", "_pinned_key_refusal", "_pinned_key_forgeable", "_schwaeche"}

#: Every call of one of them, by file and function, with how many there are and what it judges. A
#: PRODUCER writes, hashes or signs over what it judged and is a case of this file; every other call
#: is named with the reason it writes nothing a caller's method could steer.
_RULE_SITES = {
    ("scripts/audit_candidate_matrix.py", "_artifact_signature_ok"): (1, "verifier: a key it decoded "
                                                                         "itself"),
    ("scripts/findings_register.py", "_signature_ok"): (1, "verifier: a key it decoded itself"),
    ("scripts/gen_findings_register.py", "_signatur_lage"): (1, "verifier of the register it reads"),
    ("scripts/gen_findings_register.py", "assemble"): (1, "PRODUCER, TheAssembleSteps"),
    ("scripts/pre_tag_receipt.py", "assemble_receipt"): (1, "PRODUCER, TheAssembleSteps"),
    ("scripts/pre_tag_receipt_lib.py", "verify_receipt"): (1, "verifier: a key it decoded itself"),
    ("scripts/render_site_data.py", "_check_receipt"): (1, "verifier: a key it decoded itself"),
    ("scripts/sign_readiness_artifact.py", "assemble"): (1, "PRODUCER, TheAssembleSteps"),
    ("src/proofbundle/adapters/agt_receipt.py", "_schwaeche"): (1, "verifier: plain text or bytes the "
                                                                   "list reader copied"),
    ("src/proofbundle/adapters/agt_receipt.py", "_vertrauensliste"): (3, "verifier: the same copies"),
    ("src/proofbundle/adapters/agt_receipt.py", "_pruefe_mit_gelesener_liste"): (2, "verifier: plain text "
                                                                                    "read by _als_text"),
    ("src/proofbundle/checkpoint.py", "_refuse_weak_ed25519_vkey"): (1, "the helper; its callers below"),
    ("src/proofbundle/checkpoint.py", "vkey"): (1, "PRODUCER, ProducersOfRawKeys"),
    ("src/proofbundle/checkpoint.py", "cosign_vkey"): (1, "PRODUCER, ProducersOfRawKeys"),
    ("src/proofbundle/checkpoint.py", "_parse_vkey"): (1, "verifier: bytes it decoded from the vkey text"),
    ("src/proofbundle/checkpoint.py", "_parse_witness_vkey"): (1, "verifier: the same"),
    ("src/proofbundle/cli.py", "_refuse_weak_issuer_pins"): (1, "a pin from argv, plain text; compared, "
                                                              "never written"),
    ("src/proofbundle/evalclaim.py", "_issuer_key_weakness"): (1, "the issuer parser, reads plain_text"),
    ("src/proofbundle/intoto.py", "_refuse_to_vouch_for_a_key_nobody_holds"): (
        1, "PRODUCER that writes no key, TheExportsJudgeTheIssuerTheClaimHolds"),
    ("src/proofbundle/policy.py", "_validate_pinned_ed25519_pubkey"): (1, "the helper; decodes text read "
                                                                         "through wire_value"),
    ("src/proofbundle/policy.py", "_pinned_key_refusal"): (1, "the helper"),
    ("src/proofbundle/policy.py", "_pinned_key_forgeable"): (1, "the helper"),
    # The loader's field rule moved out of load_policy into one function that load_policy and the three
    # evaluators call (deep gate at 7409b123): the three calls of load_policy are these three.
    ("src/proofbundle/policy.py", "_felder_pruefen"): (2, "the loader's field rule on a policy copy "
                                                          "(allowed_issuers, trusted_decision_makers); refuses, "
                                                          "keeps nothing of the key"),
    ("src/proofbundle/policy.py", "_relations_felder_pruefen"): (1, "the same rule for the pinned "
                                                                    "relation_signer keys"),
    ("src/proofbundle/policy.py", "evaluate_policy"): (1, "verifier: judges a pin and compares it; "
                                                         "writes nothing"),
    ("src/proofbundle/policy.py", "evaluate_decision_policy"): (1, "verifier: the same"),
    ("src/proofbundle/policy_profiles.py", "instantiate_template"): (1, "PRODUCER, ProducersOfKeyText"),
    ("src/proofbundle/sdjwt_issue.py", "issue_sd_jwt"): (1, "PRODUCER, ProducersOfRawKeys"),
    ("src/proofbundle/signature.py", "verify_ed25519_pinned"): (1, "the verify primitive"),
    ("src/proofbundle/trust_pack.py", "validate_trust_pack_predicate"): (
        1, "the validator; its producers read the predicate once first, ProducersOfKeyText"),
}


def _rule_sites() -> "dict[tuple[str, str], int]":
    import ast
    found: "dict[tuple[str, str], int]" = {}
    for root in ("src/proofbundle", "scripts"):
        for path in sorted((REPO / root).rglob("*.py")):
            rel = path.relative_to(REPO).as_posix()

            def walk(node, names):
                for child in ast.iter_child_nodes(node):
                    if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                        walk(child, names + [child.name])
                        continue
                    if isinstance(child, ast.Call):
                        f = child.func
                        called = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", None)
                        if called in _RULE_NAMES:
                            where = (rel, ".".join(names) or "<module>")
                            found[where] = found.get(where, 0) + 1
                    walk(child, names)

            walk(ast.parse(path.read_text(encoding="utf-8")), [])
    return found


class EveryCallOfTheRuleIsNamed(unittest.TestCase):

    def test_the_scan_and_the_list_agree_in_both_directions(self):
        found = _rule_sites()
        # A named site in a file this distribution leaves out by design cannot be scanned here; every
        # other named site must still be found (see `_not_shipped`).
        listed = {where: n for where, (n, _why) in _RULE_SITES.items() if not _not_shipped(where[0])}
        self.assertEqual({k: v for k, v in found.items() if listed.get(k) != v}, {},
                         "a call of the rule that no one has read and named")
        self.assertEqual({k: v for k, v in listed.items() if found.get(k) != v}, {},
                         "a named call that is no longer there")


if __name__ == "__main__":
    unittest.main()
