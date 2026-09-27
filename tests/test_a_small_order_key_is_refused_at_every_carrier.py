"""A small-order key is refused at every carrier: the AGT signer, the register view, the issuer pin.

WHERE THIS COMES FROM. SPEC section 4b: every Ed25519 key that is not the bundle's own
`signature.public_key_b64` must be canonical and must not be a point of small order, and the
bundle's own key may keep the section 4a profile only because "trust in it comes from a pin that
already carries this rule". #280 applied the rule to about twenty places and left three carriers.
Measured on 126ed1dc with the identity point `0100..00` as key and the signature R = identity,
S = 0, which the section 4a profile accepts for every message:

1. `adapters/agt_receipt.py`: the receipt's `signer_public_key` got the plain profile, `signature`
   True and `ok` True for a receipt nobody signed. AGT's authorization binds `receipt_payload_hash`
   and not the signer key, so the same swap under an externally authorized receipt kept the
   authorization and gave exit 0. The trust-anchor test listed the adapter as IN_BAND.
2. `scripts/gen_findings_register.py`, `_signatur_lage`: `VERIFIZIERT`, and both generated views
   printed "Signed and verified against the canonical body, ed25519."; 32 zero bytes as key and 64
   as signature gave `VERIFIZIERT` for 7 of 16 bodies of the line-610 carrier. Register entry
   `SMALL-ORDER-KEY-AT-CARRIER-SIGNATURE-01`, target 6.2.0.
3. `proofbundle show-eval --expect-issuer ed25519:<identity>`: exit 0 and "=> OK" for a PASS
   receipt nobody signed. The pin was compared as a string with a key the bundle check had accepted
   under section 4a, so the pin did not carry the rule the SPEC says it carries.

WHAT IS PINNED. Per carrier a signature made by nobody, with the precondition that the bare profile
accepts it, next to a positive control made by a real key. The refusal names the reason from
`signature.TRUST_ANCHOR_REFUSAL`. Where a key is AUTHORISED (the AGT relying party's
`trusted_authorizer_keys`, the `--expect-issuer` pin) it is refused there, before any receipt is
read, not only when a receipt happens to use it. Every case that is not a positive control failed
on 126ed1dc, measured by running this file against an export of that commit.
"""
from __future__ import annotations

import base64
import contextlib
import copy
import importlib.util
import inspect
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

REPO = Path(__file__).resolve().parents[1]
for _p in (str(REPO), str(REPO / "src")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from proofbundle.signature import (  # noqa: E402
    TRUST_ANCHOR_REFUSAL,
    verify_ed25519,
    verify_ed25519_pinned,
)
from tests.test_trust_anchor_keys_refused_on_every_surface import (  # noqa: E402
    I1,
    TORSION_R,
    UNIV,
    WEAK,
    _NO_SMALL_ORDER,
    _Nobody,
    _raw,
)

ZERO = b"\x00" * 32            # y = 0, a point of order 4
ZSIG = b"\x00" * 64            # R = the zero point, S = 0


def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")


def _numpy():
    """numpy, or None where it is not installed: it is no dependency of the package, so a case that
    needs it says NOT MEASURABLE in a subtest of its own and still runs its ctypes forms."""
    try:
        import numpy
    except ImportError:
        return None
    return numpy


# ── 1. the AGT receipt's signer key and the relying party's authorizer list ──────────────────────

_AGT = REPO / "tests" / "vektoren" / "agt_receipts"


def _agt(name: str) -> dict:
    return json.loads((_AGT / f"{name}.json").read_text(encoding="utf-8"))


def _agt_forged(key: bytes):
    """A receipt signed by nobody that the bare profile accepts under `key`: 01_allow with its own
    `payload_hash` dropped, `receipt_id` varied until a torsion point works as R with S = 0. None for
    the one WEAK entry of large order, which admits no forgery."""
    from proofbundle.adapters.agt_receipt import canonical_payload
    base = _agt("01_allow")
    base.pop("payload_hash", None)
    for i in range(64):
        r = dict(base, receipt_id=f"made-by-nobody-{i}", signer_public_key=key.hex())
        msg = canonical_payload(r)
        for big_r in TORSION_R:
            sig = big_r + b"\x00" * 32
            if verify_ed25519(key, sig, msg):
                return dict(r, signature=sig.hex())
    return None


class AgtSignerKey(unittest.TestCase):

    def test_precondition_the_forgery_is_live_against_the_bare_profile(self):
        from proofbundle.adapters.agt_receipt import canonical_payload
        r = _agt_forged(I1)
        self.assertIsNotNone(r)
        self.assertIs(verify_ed25519(I1, bytes.fromhex(r["signature"]), canonical_payload(r)), True)

    def test_a_receipt_nobody_signed_is_refused_for_every_weak_signer_key(self):
        from proofbundle.adapters.agt_receipt import exit_code, verify_agt_receipt
        for key, reason in WEAK:
            with self.subTest(key=key.hex()):
                r = _agt_forged(key)
                if key == _NO_SMALL_ORDER:
                    self.assertIsNone(r)
                    r = dict(_agt_forged(I1), signer_public_key=key.hex())
                else:
                    self.assertIsNotNone(r, "no forgery found; this entry would measure nothing")
                e = verify_agt_receipt(r)
                self.assertIs(e.ok, False)
                self.assertEqual(exit_code(e), 1, "a key that verifies nothing is a crypto failure")
                sig = [c for c in e.checks if c.name == "signature"]
                self.assertEqual([c.ok for c in sig], [False])
                self.assertIn("signer_public_key", sig[0].detail)
                self.assertIn(TRUST_ANCHOR_REFUSAL[reason], sig[0].detail)

    def test_an_authorized_receipt_with_its_signer_swapped_to_nobody_is_refused(self):
        """The authorization binds the payload hash, not the signer key, so on 126ed1dc it stayed
        valid over a receipt re-signed by nobody and the verdict was exit 0."""
        from proofbundle.adapters.agt_receipt import canonical_payload, exit_code, verify_agt_receipt
        r = _agt("03_extern_autorisiert")
        r.update(signer_public_key=I1.hex(), signature=UNIV.hex())
        self.assertIs(verify_ed25519(I1, UNIV, canonical_payload(r)), True)
        e = verify_agt_receipt(r, trusted_authorizer_keys=[r["authorizer_public_key"]])
        self.assertIs(e.ok, False)
        self.assertEqual(exit_code(e), 1)
        self.assertEqual([c.ok for c in e.checks if c.name == "signature"], [False])

    def test_positive_control_a_real_signer_key_verifies(self):
        from proofbundle.adapters.agt_receipt import canonical_payload, exit_code, verify_agt_receipt
        k = Ed25519PrivateKey.generate()
        r = _agt("01_allow")
        r.pop("payload_hash", None)
        r["signer_public_key"] = _raw(k).hex()
        r["signature"] = k.sign(canonical_payload(r)).hex()
        e = verify_agt_receipt(r)
        self.assertIs(e.ok, True, [c.detail for c in e.checks if not c.ok])
        self.assertEqual(exit_code(e), 0)
        self.assertIs(verify_agt_receipt(_agt("01_allow")).ok, True, "the real AGT vector")

    def test_the_path_taken_asks_for_the_key_check_and_no_pin_list(self):
        """The owner's condition for the signer: if the pinned verify wanted a pin list there, only
        the key check would be taken over and the trust chain would stay with the authorizer. It
        wants none: its parameters are the key, the signature and the message, and a receipt with no
        list and no authorization verifies under it (the control above). So the signer goes through
        `verify_ed25519_pinned`, which is exactly the key check followed by the signature."""
        self.assertEqual(list(inspect.signature(verify_ed25519_pinned).parameters),
                         ["public_key", "signature", "message"])
        k = Ed25519PrivateKey.generate()
        self.assertIs(verify_ed25519_pinned(_raw(k), k.sign(b"m"), b"m"), True)
        self.assertIs(verify_ed25519_pinned(I1, UNIV, b"m"), False)


class AgtAuthorizerList(unittest.TestCase):
    """The relying party's `trusted_authorizer_keys` is where a key is authorised."""

    def test_a_weak_key_on_the_list_is_refused_before_the_receipt_is_read(self):
        from proofbundle.adapters.agt_receipt import exit_code, verify_agt_receipt
        r = _agt("03_extern_autorisiert")
        for key, reason in WEAK:
            with self.subTest(key=key.hex()):
                e = verify_agt_receipt(r, trusted_authorizer_keys=[key.hex(), r["authorizer_public_key"]])
                self.assertIs(e.ok, False)
                self.assertEqual(exit_code(e), 2, "a weak pin makes the relying party's list malformed")
                self.assertEqual([c.name for c in e.checks], ["trusted-authorizer-keys"])
                self.assertIn(TRUST_ANCHOR_REFUSAL[reason], e.checks[0].detail)
                self.assertIn("trusted_authorizer_keys[0]", e.checks[0].detail)

    def test_the_refusal_does_not_depend_on_the_receipt(self):
        """Refused where it is authorised: an unreadable receipt gets the same answer."""
        from proofbundle.adapters.agt_receipt import exit_code, verify_agt_receipt
        e = verify_agt_receipt({"not": "a receipt"}, trusted_authorizer_keys=[I1.hex()])
        self.assertEqual((e.ok, exit_code(e), e.checks[0].name), (False, 2, "trusted-authorizer-keys"))

    def test_positive_control_and_the_entries_that_name_no_key(self):
        """A real list still authorises, and an entry that decodes to no 32-byte key is left as it
        was: it matches nothing (tests/test_agt_receipt_verifier.py uses one)."""
        from proofbundle.adapters.agt_receipt import exit_code, verify_agt_receipt
        r = _agt("03_extern_autorisiert")
        real = r["authorizer_public_key"]
        for liste in ([real], ["x", real], ["aa" * 31, real], (real,)):
            with self.subTest(liste=[str(x)[:8] for x in liste]):
                e = verify_agt_receipt(r, trusted_authorizer_keys=liste)
                self.assertIs(e.ok, True, [c.detail for c in e.checks if not c.ok])
        self.assertEqual(exit_code(verify_agt_receipt(r, trusted_authorizer_keys=["aa" * 32])), 3,
                         "a real key that is not the authorizer stays a relying-party miss")

    # ── K2-01 (lens run 1 at 053c7800): the refusal walked fewer containers than the comparison ──

    @staticmethod
    def _containers():
        """Every shape of collection the comparison further down walks, each as a FACTORY, so a one-shot
        iterator is built fresh per call. On 053c7800 only list, tuple, set and frozenset were walked by
        the refusal, while `set(trusted_authorizer_keys)` walks any iterable."""
        import collections
        return {"list": list, "tuple": tuple, "set": set, "frozenset": frozenset,
                "deque": collections.deque, "UserList": collections.UserList,
                "dict": dict.fromkeys, "dict.keys()": lambda xs: dict.fromkeys(xs).keys(),
                "generator": lambda xs: (x for x in xs)}

    def test_a_weak_key_is_refused_in_every_container_the_comparison_walks(self):
        from proofbundle.adapters.agt_receipt import exit_code, verify_agt_receipt
        r = _agt("03_extern_autorisiert")
        for name, make in self._containers().items():
            with self.subTest(container=name):
                e = verify_agt_receipt(r, trusted_authorizer_keys=make([I1.hex(), r["authorizer_public_key"]]))
                self.assertEqual((e.ok, exit_code(e), e.checks[0].name),
                                 (False, 2, "trusted-authorizer-keys"))
                self.assertIn(TRUST_ANCHOR_REFUSAL["low-order"], e.checks[0].detail)

    def test_positive_control_every_container_still_authorises_the_real_key(self):
        """A one-shot generator is walked ONCE: the refusal and the comparison read one materialised
        copy, so the real key is still found after the refusal looked at the list."""
        from proofbundle.adapters.agt_receipt import exit_code, verify_agt_receipt
        r = _agt("03_extern_autorisiert")
        for name, make in self._containers().items():
            with self.subTest(container=name):
                e = verify_agt_receipt(r, trusted_authorizer_keys=make(["aa" * 32, r["authorizer_public_key"]]))
                self.assertEqual((e.ok, exit_code(e)), (True, 0), [c.detail for c in e.checks if not c.ok])

    def test_a_raw_bytes_entry_is_judged_as_a_key(self):
        """32 raw bytes name a key and go through the rule; on 053c7800 the identity point as bytes next
        to the real key gave exit 0. A raw entry is still not TEXT, so it matches nothing: the
        comparison is by hex text (a named limit of the CHANGELOG entry), which errs on the closed side."""
        from proofbundle.adapters.agt_receipt import exit_code, verify_agt_receipt
        r = _agt("03_extern_autorisiert")
        real = r["authorizer_public_key"]
        for weak, reason in WEAK:
            with self.subTest(key=weak.hex()):
                for form in (bytes(weak), bytearray(weak)):
                    e = verify_agt_receipt(r, trusted_authorizer_keys=[form, real])
                    self.assertEqual((exit_code(e), e.checks[0].name), (2, "trusted-authorizer-keys"))
                    self.assertIn(TRUST_ANCHOR_REFUSAL[reason], e.checks[0].detail)
        self.assertEqual(exit_code(verify_agt_receipt(r, trusted_authorizer_keys=[bytes.fromhex(real)])), 3)
        self.assertEqual(exit_code(verify_agt_receipt(r, trusted_authorizer_keys=[b"\x01" * 31, real])), 0,
                         "bytes of another length name no key and match nothing, as text junk does")

    def test_an_entry_that_is_no_key_spelling_never_raises_and_names_no_key(self):
        """Out-of-scope finding 2 of the same lens run: a nested-list entry raised TypeError from
        `set(...)` (on main too). DECIDED: such an entry names no key and matches nothing, exactly like
        text that decodes to no key (`"x"`, pinned since 3c9c98c3). The list's only job is to name keys;
        a non-key entry cannot authorise anything, and refusing a list for a Python type while accepting
        junk text would give one question two answers. The check detail counts such entries, so the
        caller's slip is visible without being a refusal."""
        from proofbundle.adapters.agt_receipt import exit_code, verify_agt_receipt
        r = _agt("03_extern_autorisiert")
        real = r["authorizer_public_key"]
        for junk in ([I1.hex()], {"k": real}, 5, None, 1.5, object()):
            with self.subTest(entry=type(junk).__name__):
                e = verify_agt_receipt(r, trusted_authorizer_keys=[junk, real])      # must not raise
                self.assertEqual((e.ok, exit_code(e)), (True, 0), [c.detail for c in e.checks if not c.ok])
                trusted = [c for c in e.checks if c.name == "external-authorization-trusted"]
                self.assertIn("1 of which name no key", trusted[0].detail)
                e2 = verify_agt_receipt(r, trusted_authorizer_keys=[junk, I1.hex(), real])
                self.assertEqual(exit_code(e2), 2, "a weak key beside the junk is still refused")

    def test_a_one_shot_list_is_read_once_for_the_whole_chain(self):
        """The chain verifier hands the same object to every receipt. A generator read by the first
        receipt would be empty for the third, the one that carries the authorization, and the real
        authorizer would read as untrusted (exit 3); on 053c7800 the same call raised TypeError from
        `len(...)`. The chain reads the list once and passes the copy on."""
        from proofbundle.adapters.agt_receipt import exit_code, verify_agt_receipt_chain
        r1, r2, r3 = _agt("01_allow"), _agt("02_deny"), _agt("03_extern_autorisiert")
        real = r3["authorizer_public_key"]
        e = verify_agt_receipt_chain([r1, r2, r3], trusted_authorizer_keys=(k for k in [real]))
        self.assertEqual((e.ok, exit_code(e)), (True, 0), [c.detail for c in e.checks if not c.ok])
        e2 = verify_agt_receipt_chain([r1, r2, r3], trusted_authorizer_keys=(k for k in [I1.hex(), real]))
        self.assertEqual(exit_code(e2), 2)
        self.assertEqual(sum(1 for c in e2.checks if c.name.endswith("trusted-authorizer-keys")), 3,
                         "every receipt of the chain reports the refused list, not only the first")

    def test_a_container_that_cannot_be_walked_is_malformed_not_a_crash(self):
        """A non-iterable (an int) reached `set(...)` and raised TypeError on 053c7800. It is the
        relying party's own input and cannot be read as a list of keys: exit 2, reason named."""
        from proofbundle.adapters.agt_receipt import exit_code, verify_agt_receipt
        r = _agt("03_extern_autorisiert")
        for bad in (5, 1.5, object()):
            with self.subTest(container=type(bad).__name__):
                e = verify_agt_receipt(r, trusted_authorizer_keys=bad)               # must not raise
                self.assertEqual((e.ok, exit_code(e), e.checks[0].name),
                                 (False, 2, "trusted-authorizer-keys"))
                self.assertIn("not a collection", e.checks[0].detail)

    # ── K2-1 (lens run 2 at 8cf49247): reading the caller's list is where the caller's code runs ──

    def test_a_list_that_raises_while_it_is_read_is_refused_and_never_escapes(self):
        """K2-1-B. On 8cf49247 only a TypeError from `tuple(...)` was caught: a generator that yields
        the real key and then raises ValueError, a generator raising KeyError, a closed file, an
        `__iter__` that raises, and an entry whose `__class__` raises all escaped from both verifiers,
        for a receipt WITHOUT an authorization (01) as well as for 03. On 053c7800 receipt 01 gave exit
        0 under the first three. Every one is now a refusal of the list, and the reason names the type."""
        from proofbundle.adapters.agt_receipt import exit_code, verify_agt_receipt, verify_agt_receipt_chain
        r1, r2, r3 = _agt("01_allow"), _agt("02_deny"), _agt("03_extern_autorisiert")
        real = r3["authorizer_public_key"]

        def then_raise(exc, items):
            yield from items
            raise exc("the walk failed part-way")

        class IterRaises:
            def __iter__(self):
                raise RuntimeError("no walk")

        class ClassRaises:
            @property  # type: ignore[misc]  # the hostile override is the point
            def __class__(self):
                raise RuntimeError("no type")

        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "keys.txt"
            p.write_text(real + "\n", encoding="utf-8")

            def closed_file():
                f = open(p, encoding="utf-8")
                f.close()
                return f

            def released_view():
                v = memoryview(I1)
                v.release()
                return [v, real]

            cases = {
                "generator: the real key, then ValueError": (lambda: then_raise(ValueError, [real]), "ValueError"),
                "generator: KeyError before any entry": (lambda: then_raise(KeyError, []), "KeyError"),
                "closed file object": (closed_file, "ValueError"),
                "__iter__ raises": (IterRaises, "RuntimeError"),
                "an entry whose __class__ raises": (lambda: [ClassRaises(), real], "RuntimeError"),
                "a released memoryview entry": (released_view, "ValueError"),
            }
            for name, (make, typ) in cases.items():
                for label, receipt in (("01, no authorization", r1), ("03, authorized", r3)):
                    with self.subTest(case=name, receipt=label):
                        e = verify_agt_receipt(receipt, trusted_authorizer_keys=make())     # must not raise
                        self.assertEqual((e.ok, exit_code(e), [c.name for c in e.checks]),
                                         (False, 2, ["trusted-authorizer-keys"]))
                        self.assertIn(typ, e.checks[0].detail)
                        self.assertIn("could not be read to the end", e.checks[0].detail)
                with self.subTest(case=name, receipt="chain 01, 02, 03"):
                    e = verify_agt_receipt_chain([r1, r2, r3], trusted_authorizer_keys=make())
                    self.assertEqual(exit_code(e), 2)
                    self.assertEqual(sum(1 for c in e.checks if c.name.endswith("trusted-authorizer-keys")), 3)

    def test_a_list_entry_is_read_once_and_no_method_of_it_runs_later(self):
        """K2-1-B, the comparison half: a `str` subclass whose `__eq__` raises reached `e == a_key` on
        8cf49247 and escaped. The reader keeps plain `str`, so the entry is the text it holds, and the
        real key given that way authorises as the same text does."""
        from proofbundle.adapters.agt_receipt import exit_code, verify_agt_receipt, verify_agt_receipt_chain

        class EqRaises(str):
            def __eq__(self, other):
                raise RuntimeError("no comparison")
            __hash__ = str.__hash__

        r1, r2, r3 = _agt("01_allow"), _agt("02_deny"), _agt("03_extern_autorisiert")
        e = verify_agt_receipt(r3, trusted_authorizer_keys=[EqRaises(r3["authorizer_public_key"])])
        self.assertEqual((e.ok, exit_code(e)), (True, 0), [c.detail for c in e.checks if not c.ok])
        e = verify_agt_receipt_chain([r1, r2, r3], trusted_authorizer_keys=[EqRaises(r3["authorizer_public_key"])])
        self.assertEqual((e.ok, exit_code(e)), (True, 0), [c.detail for c in e.checks if not c.ok])

    def test_the_chain_refuses_a_half_read_list_and_does_not_read_it_again(self):
        """K2-1-A. On 8cf49247 the chain caught the TypeError of a list that yields the identity point,
        raises once and then yields the real key, and handed the HALF-READ iterator to the receipts:
        the first one then found only the real key, exit 0, where the single call gave exit 2. Now the
        chain reads the list through the same helper once, every receipt reports the same refusal, and
        the caller's iterator is not touched again after it failed."""
        from proofbundle.adapters.agt_receipt import exit_code, verify_agt_receipt, verify_agt_receipt_chain
        r1, r2, r3 = _agt("01_allow"), _agt("02_deny"), _agt("03_extern_autorisiert")
        real = r3["authorizer_public_key"]

        class Resuming:
            """Yields the identity point, raises TypeError once, then yields the real key."""
            def __init__(self):
                self.rest = [I1.hex(), TypeError, real]

            def __iter__(self):
                return self

            def __next__(self):
                if not self.rest:
                    raise StopIteration
                x = self.rest.pop(0)
                if x is TypeError:
                    raise TypeError("transient")
                return x

        single = verify_agt_receipt(r3, trusted_authorizer_keys=Resuming())
        self.assertEqual(exit_code(single), 2)
        for chain in ([r3], [r1, r2, r3]):
            with self.subTest(chain=len(chain)):
                it = Resuming()
                e = verify_agt_receipt_chain(chain, trusted_authorizer_keys=it)
                self.assertEqual(exit_code(e), exit_code(single), [(c.name, c.ok) for c in e.checks])
                refused = [c for c in e.checks if c.name.endswith("trusted-authorizer-keys")]
                self.assertEqual(len(refused), len(chain), "every receipt reports the one refusal")
                self.assertEqual(len({c.detail for c in refused}), 1)
                self.assertIn("TypeError", refused[0].detail)
                self.assertEqual(it.rest, [real], "the iterator was read again after it failed")
        with self.subTest(chain="a normalising generator: identity point, then TypeError"):
            e = verify_agt_receipt_chain(
                [r1, r2], trusted_authorizer_keys=(bytes.fromhex(k).hex() for k in [I1.hex(), None, real]))
            self.assertEqual(exit_code(e), 2, "on 8cf49247 this chain gave exit 0")

    def test_a_byte_string_entry_is_judged_whatever_its_python_type(self):
        """K2-1-C, entries. Judged by the buffer protocol, not by `bytes`/`bytearray`: on 8cf49247 the
        identity point as a `memoryview` or an `array('B', …)` next to the real key gave exit 0. A raw
        entry is judged and never authorises (the comparison is by hex text); numbers and a list of
        numbers still name no key."""
        import array
        from proofbundle.adapters.agt_receipt import exit_code, verify_agt_receipt
        r = _agt("03_extern_autorisiert")
        real = r["authorizer_public_key"]
        for weak, reason in WEAK:
            for form in (memoryview(weak), array.array("B", weak), memoryview(bytearray(weak))):
                with self.subTest(key=weak.hex(), form=type(form).__name__):
                    e = verify_agt_receipt(r, trusted_authorizer_keys=[form, real])
                    self.assertEqual((exit_code(e), e.checks[0].name), (2, "trusted-authorizer-keys"))
                    self.assertIn(TRUST_ANCHOR_REFUSAL[reason], e.checks[0].detail)
        with self.subTest(control="the real key as a memoryview is judged and matches nothing"):
            self.assertEqual(exit_code(verify_agt_receipt(
                r, trusted_authorizer_keys=[memoryview(bytes.fromhex(real))])), 3)
        with self.subTest(control="a number and a list of numbers name no key"):
            e = verify_agt_receipt(r, trusted_authorizer_keys=[int.from_bytes(I1, "little"), list(I1), real])
            self.assertEqual((e.ok, exit_code(e)), (True, 0), [c.detail for c in e.checks if not c.ok])
            trusted = [c for c in e.checks if c.name == "external-authorization-trusted"]
            self.assertIn("2 of which name no key", trusted[0].detail)

    def test_one_key_passed_instead_of_a_list_is_refused_as_a_single_key(self):
        """K2-1-C, the whole value. A str or a byte string passed AS the list was walked character by
        character or byte by byte, none of which names a key: on 8cf49247 the identity point as a bare
        string gave exit 0 for receipt 01, and the real key as a bare string exit 3 for receipt 03. It
        is one key, not a collection of keys, and it is refused as that, exit 2."""
        import array
        from proofbundle.adapters.agt_receipt import exit_code, verify_agt_receipt, verify_agt_receipt_chain
        r1, r2, r3 = _agt("01_allow"), _agt("02_deny"), _agt("03_extern_autorisiert")
        real = r3["authorizer_public_key"]
        values = {"str, identity point": I1.hex(), "str, the real key": real, "bytes": bytes(I1),
                  "bytearray": bytearray(I1), "memoryview": memoryview(I1), "array('B')": array.array("B", I1),
                  "bytes, the real key": bytes.fromhex(real), "empty str": ""}
        for name, value in values.items():
            for label, receipt in (("01, no authorization", r1), ("03, authorized", r3)):
                with self.subTest(value=name, receipt=label):
                    e = verify_agt_receipt(receipt, trusted_authorizer_keys=value)
                    self.assertEqual((e.ok, exit_code(e), [c.name for c in e.checks]),
                                     (False, 2, ["trusted-authorizer-keys"]))
                    self.assertIn("a single key, not a collection of keys", e.checks[0].detail)
            with self.subTest(value=name, receipt="chain 01, 02, 03"):
                e = verify_agt_receipt_chain([r1, r2, r3], trusted_authorizer_keys=value)
                self.assertEqual(exit_code(e), 2)
                self.assertEqual(sum(1 for c in e.checks if c.name.endswith("trusted-authorizer-keys")), 3)

    # ── lens run 3 at 481a1f26: a buffer is not always a byte string, and naming a type runs nothing ──

    @staticmethod
    def _reference_arrays():
        """Arrays of references or of multi-character text, each as a factory. The ctypes `py_object`
        array (format `<O`) needs no numpy; the two numpy forms join where numpy is installed."""
        import ctypes
        forms = {"ctypes py_object array": lambda xs: (ctypes.py_object * len(xs))(*xs)}
        np = _numpy()
        if np is not None:
            forms["numpy text array"] = lambda xs: np.array(list(xs))
            forms["numpy object array"] = lambda xs: np.array(list(xs), dtype=object)
        return forms

    def _numpy_not_measured(self):
        with self.subTest(numpy="not installed"):
            self.skipTest("NOT MEASURABLE: numpy is not installed here; its forms did NOT run")

    def test_an_array_of_keys_is_read_as_a_list_and_not_as_one_key(self):
        """F2 of lens run 3 at 481a1f26, a regression against main on a realistic caller form. Taking
        every value that exports a buffer as one byte string refused `np.array([key])` and the same
        array with `dtype=object` as "one ndarray value, a single key" (exit 2), where main 20e91c8e
        read the key and authorised it (exit 0): numpy exports a text array with the format `64w` and
        an object array with `O`. A buffer of references or of multi-character text is a collection and
        is walked as main walked it; `np.array([])`, a float array, is an empty list again. As an ENTRY
        such an array refuses the list (lens run 4 at d461b41a, K4-1): its bytes are addresses or code
        points, four references are 32 of them, which 481a1f26 judged as a key, and d461b41a let it
        pass as naming no key although the texts it holds may be keys. A nested list, which exports no
        buffer, still names no key."""
        from proofbundle.adapters.agt_receipt import exit_code, verify_agt_receipt, verify_agt_receipt_chain
        r1, r2, r3 = _agt("01_allow"), _agt("02_deny"), _agt("03_extern_autorisiert")
        real = r3["authorizer_public_key"]
        for name, make in self._reference_arrays().items():
            with self.subTest(form=name):
                for liste in ([real], ["x", real]):
                    e = verify_agt_receipt(r3, trusted_authorizer_keys=make(liste))
                    self.assertEqual((e.ok, exit_code(e)), (True, 0), [c.detail for c in e.checks if not c.ok])
                    e = verify_agt_receipt_chain([r1, r2, r3], trusted_authorizer_keys=make(liste))
                    self.assertEqual((e.ok, exit_code(e)), (True, 0), [c.detail for c in e.checks if not c.ok])
                self.assertEqual(exit_code(verify_agt_receipt(r3, trusted_authorizer_keys=make([real.upper()]))),
                                 3, "compared as text, as the entries of a list are")
                e = verify_agt_receipt(r3, trusted_authorizer_keys=[make([real] * 4), real])
                self.assertEqual((exit_code(e), [c.name for c in e.checks]), (2, ["trusted-authorizer-keys"]),
                                 "an array of texts or references as an entry refuses the list")
                self.assertIn("trusted_authorizer_keys[0] is a ", e.checks[0].detail)
                self.assertIn("whose buffer holds", e.checks[0].detail)
                e = verify_agt_receipt(r3, trusted_authorizer_keys=[[real] * 4, real])
                self.assertEqual((e.ok, exit_code(e)), (True, 0), "a nested list still names no key")
        np = _numpy()
        if np is None:
            self._numpy_not_measured()
            return
        with self.subTest(form="np.array([]), a float array"):
            self.assertEqual(exit_code(verify_agt_receipt(r3, trusted_authorizer_keys=np.array([]))), 3)
            self.assertEqual(exit_code(verify_agt_receipt(r1, trusted_authorizer_keys=np.array([]))), 0)

    def test_a_weak_key_inside_an_array_of_keys_is_refused_by_its_position(self):
        """F2, the other direction. Walked as a list, an array of keys has each entry judged, and the
        refusal names the entry and the reason; 481a1f26 refused the whole array as "one ndarray value"
        and never looked at the key. Every weak encoding of the rule, as hex text, in capitals, and as
        raw bytes inside an array of references, in first and in second place."""
        from proofbundle.adapters.agt_receipt import exit_code, verify_agt_receipt, verify_agt_receipt_chain
        r1, r2, r3 = _agt("01_allow"), _agt("02_deny"), _agt("03_extern_autorisiert")
        real = r3["authorizer_public_key"]
        for name, make in self._reference_arrays().items():
            spellings = {"hex": lambda k: k.hex(), "HEX": lambda k: k.hex().upper()}
            if name != "numpy text array":
                spellings["raw bytes"] = bytes
            for key, reason in WEAK:
                for spelling, spell in spellings.items():
                    for pos, liste in ((0, [spell(key), real]), (1, [real, spell(key)])):
                        with self.subTest(form=name, key=key.hex(), spelling=spelling, position=pos):
                            for receipt in (r1, r3):
                                e = verify_agt_receipt(receipt, trusted_authorizer_keys=make(liste))
                                self.assertEqual((exit_code(e), [c.name for c in e.checks]),
                                                 (2, ["trusted-authorizer-keys"]))
                                self.assertIn(f"trusted_authorizer_keys[{pos}]", e.checks[0].detail)
                                self.assertIn(TRUST_ANCHOR_REFUSAL[reason], e.checks[0].detail)
                            e = verify_agt_receipt_chain([r1, r2, r3], trusted_authorizer_keys=make(liste))
                            self.assertEqual(exit_code(e), 2)
        if _numpy() is None:
            self._numpy_not_measured()

    def test_a_buffer_of_numbers_is_judged_by_its_bytes_and_walked_as_numbers(self):
        """F2, the forms between the two. `array('I')`, `array('d')` or a numpy uint32 array hold
        numbers, and walked they name no key, which is how main 20e91c8e read them. Their bytes still
        spell one key, and 481a1f26 refused every weak key given that way; walked alone, the identity
        point as `array('I', …)` is eight numbers and would pass. So the bytes are judged first and the
        refusal names the reason, where 481a1f26 said "a single key" for every such value, weak or not.
        A value whose bytes are no weak key is walked: the real key as numbers names no key, exit 3 for
        the authorized receipt. A buffer of more than one dimension is no flat list and is refused whole
        (main raised TypeError on it): walked, its entries are arrays, which name no key."""
        import array
        from proofbundle.adapters.agt_receipt import exit_code, verify_agt_receipt, verify_agt_receipt_chain
        r1, r2, r3 = _agt("01_allow"), _agt("02_deny"), _agt("03_extern_autorisiert")
        real = r3["authorizer_public_key"]

        def arr(code):
            def make(k):
                a = array.array(code)
                a.frombytes(k)
                return a
            return make

        forms = {"array('I')": arr("I"), "array('d')": arr("d"), "memoryview cast to 'Q'": lambda k: memoryview(k).cast("Q")}
        np = _numpy()
        if np is not None:
            forms["numpy uint32"] = lambda k: np.frombuffer(k, dtype=np.uint32).copy()
        for key, reason in WEAK:
            for name, make in forms.items():
                with self.subTest(form=name, key=key.hex()):
                    for receipt in (r1, r3):
                        e = verify_agt_receipt(receipt, trusted_authorizer_keys=make(key))
                        self.assertEqual((exit_code(e), [c.name for c in e.checks]), (2, ["trusted-authorizer-keys"]))
                        self.assertIn("whose bytes spell one key", e.checks[0].detail)
                        self.assertIn(TRUST_ANCHOR_REFUSAL[reason], e.checks[0].detail)
                    e = verify_agt_receipt_chain([r1, r2, r3], trusted_authorizer_keys=make(key))
                    self.assertEqual(exit_code(e), 2)
        for name, make in forms.items():
            with self.subTest(form=name, key="the real key"):
                e = verify_agt_receipt(r3, trusted_authorizer_keys=make(bytes.fromhex(real)))
                self.assertEqual(exit_code(e), 3, [c.detail for c in e.checks if not c.ok])
                trusted = [c for c in e.checks if c.name == "external-authorization-trusted"]
                self.assertIn("of which name no key", trusted[0].detail)
                self.assertEqual(exit_code(verify_agt_receipt(r1, trusted_authorizer_keys=make(bytes.fromhex(real)))), 0)
        if np is None:
            self._numpy_not_measured()
            return
        for liste in ([[I1.hex(), real]], [[real]]):
            with self.subTest(form="numpy text array of two dimensions", liste=len(liste[0])):
                for receipt in (r1, r3):
                    e = verify_agt_receipt(receipt, trusted_authorizer_keys=np.array(liste))
                    self.assertEqual((exit_code(e), [c.name for c in e.checks]), (2, ["trusted-authorizer-keys"]))
                    self.assertIn("of 2 dimensions", e.checks[0].detail)

    def test_a_type_whose_name_raises_is_named_and_never_escapes(self):
        """F1 of lens run 3 at 481a1f26. `type(x).__name__` asks the metaclass, and a metaclass may
        define `__name__` as a property that raises. The list reader's `except` handler made that read,
        so a list that yields the real key and then raises such an exception made both verifiers raise
        `Boom` while `NamedBoom` was being handled. Every message that names a caller's type reads the
        name through `type` itself now: the handler, its two siblings (a value that cannot be walked,
        one byte string passed as the list), the shape checks of the receipt and of the chain, a chain
        element, and a decision that is not text."""
        from proofbundle.adapters.agt_receipt import exit_code, verify_agt_receipt, verify_agt_receipt_chain
        r1, r2, r3 = _agt("01_allow"), _agt("02_deny"), _agt("03_extern_autorisiert")
        real = r3["authorizer_public_key"]

        class Boom(Exception):
            pass

        class NameRaises(type):
            @property
            def __name__(cls):
                raise Boom("the metaclass refuses the name")

        class Unformattable:
            def __format__(self, spec):
                raise Boom("no format")

        class NameUnformattable(type):
            @property
            def __name__(cls):
                return Unformattable()

        class NamedBoom(Exception, metaclass=NameRaises):
            pass

        class FormatBoom(Exception, metaclass=NameUnformattable):
            pass

        class NotWalkable(metaclass=NameRaises):
            pass

        class OneKey(bytes, metaclass=NameRaises):
            pass

        class Decision(int, metaclass=NameRaises):
            pass

        def then_raise(exc):
            yield real
            raise exc("part-way")

        def verdict(call):
            """The verdict, or a plain AssertionError naming what escaped, with the escaped chain left
            out. Measured on 481a1f26: pytest's report hook read the name of `NamedBoom`, chained under
            the escaped `Boom`, through its metaclass and raised again, so the case was counted outright
            and its twelve failing subtests went uncounted."""
            try:
                return call()
            except Exception as escaped:  # noqa: BLE001 — an escape is the finding, named without its chain
                raise AssertionError(
                    f"the verifier raised {type.__dict__['__name__'].__get__(type(escaped))}") from None

        for exc, name in ((NamedBoom, "NamedBoom"), (FormatBoom, "FormatBoom")):
            for label, call in (
                    ("single 01", lambda: verify_agt_receipt(r1, trusted_authorizer_keys=then_raise(exc))),
                    ("single 03", lambda: verify_agt_receipt(r3, trusted_authorizer_keys=then_raise(exc))),
                    ("chain 01, 02, 03",
                     lambda: verify_agt_receipt_chain([r1, r2, r3], trusted_authorizer_keys=then_raise(exc)))):
                with self.subTest(exception=name, call=label):
                    e = verdict(call)                                       # must not raise
                    self.assertEqual(exit_code(e), 2)
                    refused = [c for c in e.checks if c.name.endswith("trusted-authorizer-keys")]
                    self.assertIn(f"raised {name} —", refused[0].detail)
        cases = {
            "a value that cannot be walked": (
                lambda: verify_agt_receipt(r1, trusted_authorizer_keys=NotWalkable()),
                "trusted_authorizer_keys is NotWalkable, not a collection of keys"),
            "one byte string passed as the list": (
                lambda: verify_agt_receipt(r1, trusted_authorizer_keys=OneKey(I1)),
                "trusted_authorizer_keys is one OneKey value, a single key"),
            "a receipt that is no object": (
                lambda: verify_agt_receipt(NotWalkable()), "receipt is NotWalkable, expected an object"),
            "a chain that is no list": (
                lambda: verify_agt_receipt_chain(NotWalkable()), "receipts is NotWalkable, expected a list"),
            "a chain element that is no object": (
                lambda: verify_agt_receipt_chain([r1, NotWalkable()]), "receipts[1] is NotWalkable, not an object"),
            "a decision that is not text": (
                lambda: verify_agt_receipt(dict(r1, cedar_decision=Decision(1))),
                "cedar_decision is Decision, expected a string"),
        }
        for label, (call, text) in cases.items():
            with self.subTest(case=label):
                e = verdict(call)                                           # must not raise
                self.assertEqual(exit_code(e), 2)
                self.assertTrue(any(text in c.detail for c in e.checks), [c.detail for c in e.checks])

    # ── lens run 4 at d461b41a: an entry that holds text or a reference in a buffer ──

    def _assert_entry_refused(self, make, pos: int, holds: str):
        """`make()` builds a fresh list; its entry at `pos` must refuse the list for a receipt without
        an authorization, for the authorized one and for the chain, and the reason names the entry."""
        from proofbundle.adapters.agt_receipt import exit_code, verify_agt_receipt, verify_agt_receipt_chain
        r1, r2, r3 = _agt("01_allow"), _agt("02_deny"), _agt("03_extern_autorisiert")
        for receipt in (r1, r3):
            e = verify_agt_receipt(receipt, trusted_authorizer_keys=make())
            self.assertEqual((exit_code(e), [c.name for c in e.checks]), (2, ["trusted-authorizer-keys"]),
                             [c.detail for c in e.checks])
            self.assertIn(f"trusted_authorizer_keys[{pos}] is a ", e.checks[0].detail)
            self.assertIn(f"whose buffer holds {holds}", e.checks[0].detail)
            self.assertIn("format", e.checks[0].detail)
        e = verify_agt_receipt_chain([r1, r2, r3], trusted_authorizer_keys=make())
        self.assertEqual(exit_code(e), 2)
        self.assertEqual(sum(1 for c in e.checks if c.name.endswith("trusted-authorizer-keys")), 3)

    def test_an_entry_holding_text_in_a_buffer_refuses_the_list(self):
        """K4-1 of lens run 4 at d461b41a. The identity point as hex text W inside `np.array(W)`,
        `np.array(W, dtype=object)`, `ctypes.c_wchar_p(W)`, `ctypes.create_unicode_buffer(W)`,
        `array('u', W)` or `np.array(list(W))`, next to the real key, gave exit 0 for receipt 01, for
        receipt 03 and for the chain, "1 of which name no key", where the plain str W gives exit 2.
        The text was never read as text: a buffer of references or of multi-character text at no
        dimension was taken for a collection, and single characters were handed on as their UCS-4 code
        units. DECIDED: such an entry refuses the list, naming its position, its type and its format.
        Reading the text would run code of the caller's or follow a pointer, and decoding the code
        units by hand would be a second reading. The real key held that way is refused as well: the
        entry is refused for what it is, not for the key inside."""
        import array
        import ctypes
        forms = {
            "ctypes.c_wchar_p": (ctypes.c_wchar_p, "references"),
            "ctypes.py_object": (ctypes.py_object, "references"),
            "ctypes.create_unicode_buffer": (ctypes.create_unicode_buffer, "text"),
            "ctypes c_wchar array": (lambda h: (ctypes.c_wchar * len(h))(*h), "text"),
            "array('u')": (lambda h: array.array("u", h), "text"),
        }
        np = _numpy()
        if np is not None:
            forms.update({
                "numpy text, no dimension": (np.array, "text"),
                "numpy big-endian text, no dimension": (lambda h: np.array(h, dtype=">U64"), "text"),
                "numpy object, no dimension": (lambda h: np.array(h, dtype=object), "references"),
                "numpy one-character texts": (lambda h: np.array(list(h)), "text"),
                "numpy text array of one": (lambda h: np.array([h]), "text"),
                "numpy object array of one": (lambda h: np.array([h], dtype=object), "references"),
            })
        real = _agt("03_extern_autorisiert")["authorizer_public_key"]
        keys = [(k.hex(), k.hex()) for k, _reason in WEAK] + [("the real key", real)]
        for name, (spell, holds) in forms.items():
            for label, h in keys:
                for pos in (0, 1):
                    with self.subTest(form=name, key=label, position=pos):
                        def make(spell=spell, h=h, pos=pos):
                            return [spell(h), real] if pos == 0 else [real, spell(h)]
                        self._assert_entry_refused(make, pos, holds)
        if np is None:
            self._numpy_not_measured()

    def test_a_pointer_entry_refuses_the_list_and_is_never_followed(self):
        """The same class for a pointer: `ctypes.c_char_p(key)` holds the raw key behind an address, and
        at d461b41a it named no key, so every weak key given that way next to the real key passed (384
        values in the lens's sweep). Following the pointer is no option: `c_char_p(12345).value` reads
        the address 12345 and ends the process with SIGSEGV. So a pointer entry refuses the list, a
        valid one and a bogus one alike, and the reader never dereferences it."""
        import ctypes
        real = _agt("03_extern_autorisiert")["authorizer_public_key"]
        keep = []                                      # the buffers the pointers below point into

        def buffer_of(k):
            buf = ctypes.create_string_buffer(k, len(k))
            keep.append(buf)
            return buf

        forms = {
            "ctypes.c_char_p": (lambda k: ctypes.c_char_p(k), "references"),
            "ctypes.c_void_p to the key": (lambda k: ctypes.c_void_p(ctypes.addressof(buffer_of(k))),
                                           "references"),
            "ctypes POINTER(c_char) to the key": (lambda k: ctypes.cast(buffer_of(k), ctypes.POINTER(ctypes.c_char)),
                                                  "records, pointers"),
        }
        keys = [(k.hex(), k) for k, _reason in WEAK] + [("the real key", bytes.fromhex(real))]
        for name, (make_entry, holds) in forms.items():
            for label, k in keys:
                for pos in (0, 1):
                    with self.subTest(form=name, key=label, position=pos):
                        def make(make_entry=make_entry, k=k, pos=pos):
                            return [make_entry(k), real] if pos == 0 else [real, make_entry(k)]
                        self._assert_entry_refused(make, pos, holds)
        for label, entry in (("c_char_p(12345)", lambda: ctypes.c_char_p(12345)),
                             ("c_wchar_p(12345)", lambda: ctypes.c_wchar_p(12345))):
            with self.subTest(form=f"a bogus address, {label}"):
                self._assert_entry_refused(lambda entry=entry: [real, entry()], 1, "references")

    def test_a_record_entry_refuses_the_list(self):
        """The record analogue, named by the lens: `np.genfromtxt(..., names=True)` over a CSV with a key
        column returns a structured array, and walked, its entries are records whose fields hold the
        key as text; at d461b41a the identity point in such a column gave exit 0 for receipt 01 and
        exit 3 for 03. A record's fields may be text or references, and its format names them in a
        syntax that a ctypes field name containing ':' makes ambiguous, so a record entry refuses the
        list whatever its fields hold. The key column itself, `table["key"]` or its list, is text and is
        read as text: a weak key in it is refused by its position, and the real key authorises.

        THE TABLE NAMES ITS FIELD TYPES, because numpy's own inference cannot read this CSV on every
        numpy the CI matrix installs. The identity point in hex is 64 digits and no letter, so numpy
        tries it as an integer first; numpy 2.2.6 (Python 3.10) then falls back to text, while numpy
        2.4.6 (3.11) and 2.5.3 (3.12 to 3.14) raise TypeError from inside `genfromtxt` (CI at a4e2fa5c,
        3 failed subtests on 3.11, reproduced on all four). `dtype="U64,U8"` with `names=True` gives
        the fields `key` `<U64` and `label` `<U8` on all three numpys, the record format
        `T{64w:key:8w:label:}` and the key column `64w`, which is the table numpy 2.2.6 inferred (its
        label was `<U4`). numpy's inference still reads the table whose first key has letters, on all
        three, and that table stays here as it was."""
        import ctypes
        from proofbundle.adapters.agt_receipt import exit_code, verify_agt_receipt, verify_agt_receipt_chain
        r1, r2, r3 = _agt("01_allow"), _agt("02_deny"), _agt("03_extern_autorisiert")
        real = r3["authorizer_public_key"]

        class TextRecord(ctypes.Structure):
            _fields_ = [("key", ctypes.c_wchar * 64)]

        class ByteRecord(ctypes.Structure):
            _fields_ = [("key", ctypes.c_ubyte * 32)]

        for key, _reason in WEAK:
            w = key.hex()
            with self.subTest(form="ctypes Structure, text field", key=w):
                self._assert_entry_refused(lambda w=w: [TextRecord(w), real], 0, "records, pointers")
            with self.subTest(form="ctypes Structure, byte field", key=w):
                self._assert_entry_refused(lambda key=key: [real, ByteRecord.from_buffer_copy(key)], 1,
                                           "records, pointers")
        np = _numpy()
        if np is None:
            self._numpy_not_measured()
            return
        import io
        import warnings
        weak = I1.hex()

        def table(*keys, dtype: Any = "U64,U8"):
            text = "key,label\n" + "".join(f"{k},row{i}\n" for i, k in enumerate(keys))
            with warnings.catch_warnings():            # numpy's own type inference warns about itself
                warnings.simplefilter("ignore", DeprecationWarning)
                return np.genfromtxt(io.StringIO(text), delimiter=",", names=True, dtype=dtype,
                                     encoding="utf-8")

        with self.subTest(precondition="the table is records with a text key column"):
            self.assertEqual(str(table(weak, real).dtype), "[('key', '<U64'), ('label', '<U8')]")
            self.assertEqual(memoryview(table(weak, real)).format, "T{64w:key:8w:label:}")
            self.assertEqual(str(table(real, "aa" * 32, dtype=None).dtype["key"]), "<U64")
        with self.subTest(form="np.genfromtxt(names=True), a weak row and the real row"):
            self._assert_entry_refused(lambda: table(weak, real), 0, "records, pointers")
        with self.subTest(form="np.genfromtxt(names=True), the real row alone"):
            self._assert_entry_refused(lambda: table(real, "aa" * 32), 0, "records, pointers")
        with self.subTest(form="np.genfromtxt(names=True, dtype=None), numpy's inference, the real row alone"):
            self._assert_entry_refused(lambda: table(real, "aa" * 32, dtype=None), 0, "records, pointers")
        structured = lambda: np.array([(weak,), (real,)], dtype=[("k", "U64")])     # noqa: E731
        with self.subTest(form="numpy structured array"):
            self._assert_entry_refused(structured, 0, "records, pointers")
        with self.subTest(form="np.rec.array"):
            self._assert_entry_refused(lambda: np.rec.array(structured()), 0, "records, pointers")
        with self.subTest(form="one numpy record as an entry"):
            self._assert_entry_refused(lambda: [real, structured()[0]], 1, "records, pointers")
        for label, column in (("the key column", lambda t: t["key"]), ("its list", lambda t: list(t["key"]))):
            with self.subTest(control=label):
                e = verify_agt_receipt(r3, trusted_authorizer_keys=column(table(weak, real)))
                self.assertEqual((exit_code(e), e.checks[0].name), (2, "trusted-authorizer-keys"))
                self.assertIn("trusted_authorizer_keys[0] (", e.checks[0].detail)
                self.assertIn(TRUST_ANCHOR_REFUSAL["low-order"], e.checks[0].detail)
                e = verify_agt_receipt_chain([r1, r2, r3], trusted_authorizer_keys=column(table(real, "aa" * 32)))
                self.assertEqual((e.ok, exit_code(e)), (True, 0), [c.detail for c in e.checks if not c.ok])

    # ── lens run 5 at c8c61651: a record whose buffer format names no record ──

    @staticmethod
    def _records_with_a_plain_format():
        """ctypes records that export the bare format `B`, each a factory of the record holding the hex
        text `h`. F1 of lens run 5 at c8c61651: ctypes cannot describe a Union, a Structure with
        `_pack_` (a big-endian one too) or an array of either, and exports `B`; read by that format, the
        record was numbers (the array one byte string), and its bytes named no key. That holds on 3.10
        and 3.11; from 3.12 on ctypes describes the packed Structures as records (see the case below)."""
        import ctypes

        def record(base, field, pack=None):
            namespace = {"_fields_": [("f", field)]}
            if pack is not None:
                namespace["_pack_"] = pack
            return type("Record", (base,), namespace)

        def holding(typ, value):
            def make(h):
                r = typ()
                r.f = value(h)
                return r
            return make

        wide = ctypes.c_wchar * 65
        text = lambda h: h                                          # noqa: E731
        ascii_ = lambda h: h.encode("ascii")                        # noqa: E731
        union = record(ctypes.Union, wide)
        packed = record(ctypes.Structure, wide, pack=1)

        def code_points(h):
            r = record(ctypes.BigEndianStructure, ctypes.c_uint32 * 64, pack=1)()
            for i, ch in enumerate(h):
                r.f[i] = ord(ch)
            return r

        def array_of(typ, n=1, depth=1):
            def make(h):
                a = (typ * n)()
                for i in range(n):
                    a[i].f = h
                for _ in range(depth - 1):
                    outer = (type(a) * 1)()
                    outer[0] = a
                    a = outer
                return a
            return make

        return {
            "Union, c_wchar * 65": holding(union, text),
            "Structure _pack_ = 1, c_wchar * 65": holding(packed, text),
            "Structure _pack_ = 8, c_wchar * 65": holding(record(ctypes.Structure, wide, pack=8), text),
            "BigEndianStructure _pack_ = 1, code points": code_points,
            "Union, c_wchar_p": holding(record(ctypes.Union, ctypes.c_wchar_p), text),
            "Union, c_char_p": holding(record(ctypes.Union, ctypes.c_char_p), ascii_),
            "Union, c_char * 65": holding(record(ctypes.Union, ctypes.c_char * 65), ascii_),
            "(Union * 1)": array_of(union),
            "((Union * 1) * 1)": array_of(union, depth=2),
            "(packed Structure * 2)": array_of(packed, n=2),
        }

    def test_a_record_that_exports_a_plain_format_refuses_the_list(self):
        """F1 of lens run 5 at c8c61651, on main 20e91c8e too. The identity point as hex text in a
        `c_wchar * 65` field of a `ctypes.Union` or of a `Structure` with `_pack_`, next to the real key,
        gave exit 0 for receipt 01, for receipt 03 and for the chain, and alone exit 3: ctypes exports
        such a record with the bare format `B`, and the reader took the format for the item. The kind is
        decided by the type as well now, and by whether the format sizes the item the buffer reports,
        so every such record, and an array of them at any depth, refuses the list as a record does. The
        raw key inside such a record is still judged by its bytes, as it was when the record passed for
        numbers. numpy did not hide a record this way where it was measured: each dtype with fields
        exported `T{...}`, and two overlay dtypes stand here as controls.

        WHAT A RECORD EXPORTS DEPENDS ON THE INTERPRETER, and the case asserts the refusal for what the
        running one exports. Measured on the five of the CI matrix: a Union and an array of Unions
        export `B` on 3.10 to 3.14, while a Structure with `_pack_`, the big-endian one and the array of
        packed Structures export `B` on 3.10 and 3.11 and describe themselves as a record from 3.12 on
        (`T{(65)<u:f:}`, `T{(64)>I:f:}`; CI at a4e2fa5c, 4 failed preconditions each on 3.12, 3.13 and
        3.14). So the precondition is that a record exports either the bare `B` or a record format, and
        every Union form exports `B` on every interpreter, which keeps the path F1 names measured
        everywhere; the refusal is demanded for every form whichever of the two it exports."""
        import ctypes
        import re
        from proofbundle.adapters.agt_receipt import exit_code, verify_agt_receipt
        r3 = _agt("03_extern_autorisiert")
        real = r3["authorizer_public_key"]
        keys = [(k.hex(), k.hex()) for k, _reason in WEAK] + [("the real key", real)]
        for name, make_record in self._records_with_a_plain_format().items():
            exported = memoryview(make_record(I1.hex())).format
            with self.subTest(form=name, precondition="the record exports B or a record format", format=exported):
                if "Union" in name:
                    self.assertEqual(exported, "B", "ctypes describes no Union on any interpreter measured")
                else:
                    self.assertTrue(exported == "B" or re.fullmatch(r"T\{.+\}", exported), exported)
            for label, h in keys:
                for pos in (0, 1):
                    with self.subTest(form=name, key=label, position=pos):
                        def make(make_record=make_record, h=h, pos=pos):
                            return [make_record(h), real] if pos == 0 else [real, make_record(h)]
                        self._assert_entry_refused(make, pos, "records, pointers")
            with self.subTest(form=name, list="the record alone"):
                e = verify_agt_receipt(r3, trusted_authorizer_keys=[make_record(I1.hex())])
                self.assertEqual((exit_code(e), [c.name for c in e.checks]), (2, ["trusted-authorizer-keys"]))

        def raw_record(base, pack=None):
            namespace = {"_fields_": [("k", ctypes.c_ubyte * 32)]}
            if pack is not None:
                namespace["_pack_"] = pack
            return type("RawRecord", (base,), namespace)

        for form, typ in (("Union", raw_record(ctypes.Union)),
                          ("Structure _pack_ = 1", raw_record(ctypes.Structure, pack=1))):
            for key, reason in WEAK:
                with self.subTest(control=f"a weak key's raw bytes in a {form} are still judged", key=key.hex()):
                    for keys_ in ([real, typ.from_buffer_copy(key)], [typ.from_buffer_copy(key), real]):
                        e = verify_agt_receipt(r3, trusted_authorizer_keys=keys_)
                        self.assertEqual(exit_code(e), 2)
                        self.assertIn(TRUST_ANCHOR_REFUSAL[reason], e.checks[0].detail)
                    e = verify_agt_receipt(r3, trusted_authorizer_keys=typ.from_buffer_copy(key))
                    self.assertEqual(exit_code(e), 2)
                    self.assertIn(TRUST_ANCHOR_REFUSAL[reason], e.checks[0].detail)
        np = _numpy()
        if np is None:
            self._numpy_not_measured()
            return
        overlays = {"fields over u4": np.dtype((np.uint32, {"c": ("U1", 0)})),
                    "fields over V256": np.dtype(("V256", {"t": ("U64", 0)}))}
        for name, dtype in overlays.items():
            with self.subTest(control=f"numpy {name} exports a record format and refuses the list"):
                self._assert_entry_refused(lambda dtype=dtype: [real, np.zeros(1, dtype=dtype)], 1,
                                           "records, pointers")

    def test_a_pointer_passed_as_the_whole_list_is_refused_and_never_walked(self):
        """Found next to F3 of lens run 5 at c8c61651. A ctypes pointer has no length, and walked it hands
        out one item after another from the address it holds and never stops: past the memory it points
        into, until the process faults. c8c61651 walked it; only a NULL pointer stopped, on the
        `ValueError` of its first item. It is refused as a pointer now, before anything is read. Only
        NULL pointers are used here, so that no run of this case reads memory it did not allocate."""
        import ctypes
        from proofbundle.adapters.agt_receipt import exit_code, verify_agt_receipt, verify_agt_receipt_chain
        r1, r2, r3 = _agt("01_allow"), _agt("02_deny"), _agt("03_extern_autorisiert")
        real = r3["authorizer_public_key"]

        class Record(ctypes.Union):
            _fields_ = [("f", ctypes.c_ubyte * 32)]

        for target in (ctypes.c_char, ctypes.c_ubyte, ctypes.c_wchar, Record):
            with self.subTest(pointer=f"POINTER({target.__name__})"):
                for call in (lambda: verify_agt_receipt(r1, trusted_authorizer_keys=ctypes.POINTER(target)()),
                             lambda: verify_agt_receipt(r3, trusted_authorizer_keys=ctypes.POINTER(target)()),
                             lambda: verify_agt_receipt_chain(
                                 [r1, r2, r3], trusted_authorizer_keys=ctypes.POINTER(target)())):
                    e = call()
                    self.assertEqual(exit_code(e), 2)
                    self.assertIn("pointer, not a collection of keys", e.checks[0].detail)
                    self.assertNotIn("could not be read to the end", e.checks[0].detail)
                self._assert_entry_refused(lambda target=target: [real, ctypes.POINTER(target)()], 1,
                                           "records, pointers")

    def test_a_buffer_of_pointer_sized_numbers_is_judged_by_its_bytes(self):
        """F4 of lens run 5 at c8c61651. `memoryview(key).cast('P')` and `(c_void_p * 4)` over a weak
        key's bytes, passed as the whole list, were walked as four addresses that name no key: exit 0
        for receipt 01 and exit 3 for the others, 96 values over the 48 weak encodings of the lens's
        oracle. A `P` item holds an address as a number, its bytes are the value it holds, and a whole
        such value is judged by them first, as a buffer of numbers is. The real key given that way
        is walked, as before, and names no key."""
        import ctypes
        from proofbundle.adapters.agt_receipt import exit_code, verify_agt_receipt, verify_agt_receipt_chain
        r1, r2, r3 = _agt("01_allow"), _agt("02_deny"), _agt("03_extern_autorisiert")
        real = bytes.fromhex(r3["authorizer_public_key"])
        forms = {"memoryview cast to 'P'": lambda k: memoryview(k).cast("P"),
                 "(c_void_p * 4)": lambda k: (ctypes.c_void_p * 4).from_buffer_copy(k)}
        for name, make in forms.items():
            for key, reason in WEAK:
                with self.subTest(form=name, key=key.hex()):
                    for receipt in (r1, r3):
                        e = verify_agt_receipt(receipt, trusted_authorizer_keys=make(key))
                        self.assertEqual((exit_code(e), [c.name for c in e.checks]), (2, ["trusted-authorizer-keys"]))
                        self.assertIn("whose bytes spell one key", e.checks[0].detail)
                        self.assertIn(TRUST_ANCHOR_REFUSAL[reason], e.checks[0].detail)
                    self.assertEqual(exit_code(verify_agt_receipt_chain([r1, r2, r3], trusted_authorizer_keys=make(key))), 2)
            with self.subTest(form=name, key="the real key"):
                self.assertEqual(exit_code(verify_agt_receipt(r3, trusted_authorizer_keys=make(real))), 3)
                self.assertEqual(exit_code(verify_agt_receipt(r1, trusted_authorizer_keys=make(real))), 0)


class AgtVerifySurfacesNeverRaise(unittest.TestCase):
    """The never-raise contract of `verify_agt_receipt` and `verify_agt_receipt_chain` over inputs of the
    wrong shape, the neighbour of lens run 3 at 481a1f26. Swept over the receipt, the chain value, each
    chain element, `now`, and every field of the five vectors replaced by 28 values of the wrong shape:
    3664 of 16324 calls raised, and main 20e91c8e raised on the same 3664. Four classes, one case each.
    Lens run 4 at d461b41a added two: an instant compared through a method of the caller's number, and
    the sweep of every other value the verifier compares or tests."""

    def test_a_chain_element_that_is_not_an_object_is_a_verdict(self):
        """`[r1, 5]` raised AttributeError from `receipts[i].get`, and so did every other non-object in
        a later place (22 kinds in the sweep). It is exit 2 now: the element's own `[i] readable` check
        names its type, and in a later place the link check names the position and the type."""
        from proofbundle.adapters.agt_receipt import exit_code, verify_agt_receipt_chain
        r1, r2 = _agt("01_allow"), _agt("02_deny")
        for bad in (5, "x", None, [1], 1.5, True, b"x", (1,), {1, 2}, object()):
            name = type(bad).__name__
            for chain, pos in (([r1, bad], 1), ([r1, bad, r2], 1), ([r1, r2, bad], 2), ([bad, r1], 0)):
                with self.subTest(element=name, position=pos, length=len(chain)):
                    e = verify_agt_receipt_chain(chain)                     # must not raise
                    self.assertEqual((e.ok, exit_code(e)), (False, 2))
                    own = [c.detail for c in e.checks if c.name == f"[{pos}] readable"]
                    self.assertEqual(own, [f"receipt is {name}, expected an object"])
                    if pos:
                        link = [c for c in e.checks if c.name == f"[{pos}] chain-link"]
                        self.assertEqual([c.ok for c in link], [False])
                        self.assertIn(f"receipts[{pos}] is {name}, not an object", link[0].detail)
            with self.subTest(element=name, list="refused"):
                e = verify_agt_receipt_chain([r1, bad], trusted_authorizer_keys=[I1.hex()])
                self.assertEqual(exit_code(e), 2)

    def test_a_field_the_serialiser_cannot_encode_is_unreadable(self):
        """`json.dumps` and the UTF-8 step raised out of both verifiers for every field of the receipt
        payload and of the authorization payload: TypeError for bytes, a set, an object or a dict with a
        tuple or with mixed keys, RecursionError for 5000 levels, ValueError for a list that holds itself,
        and UnicodeEncodeError for a lone surrogate, which `json.loads` produces from a receipt file.
        Each is a `readable` failure now, exit 2, and a chain names the link it could not check.

        5000 LEVELS WERE UNREADABLE ONLY WHERE THE SERIALISER GAVE UP. On 3.12, 3.13 and 3.14
        `json.dumps` writes 5000 levels, and the CI matrix at a4e2fa5c measured exit 1 there for all 11
        fields (exit 2 on 3.10 and 3.11). The depth is the module's own rule now: a form nesting arrays
        and objects more than 64 deep is refused, with one message, before anything is written. A field
        whose innermost array sits at level 65 is refused as well (exit 1 at a4e2fa5c on all five), and
        the message of both is the same on every interpreter."""
        from proofbundle.adapters.agt_receipt import (AGT_CANONICAL_FORM, exit_code, verify_agt_receipt,
                                                      verify_agt_receipt_chain)
        r1, r2, r3 = _agt("01_allow"), _agt("02_deny"), _agt("03_extern_autorisiert")
        real = r3["authorizer_public_key"]
        deep = [1]
        for _ in range(5000):
            deep = [deep]
        past_the_ceiling: Any = "x"
        for _ in range(64):                          # the field is level 2, its innermost array level 65
            past_the_ceiling = [past_the_ceiling]
        circular = []
        circular.append(circular)
        values = {"bytes": b"x", "set": {1, 2}, "object": object(), "tuple-key dict": {(1,): 2},
                  "mixed-key dict": {"a": 1, 1: 2}, "5000 levels": deep,
                  "an innermost array at level 65": past_the_ceiling, "a list that holds itself": circular,
                  "a lone surrogate": chr(0xD800), "a lone surrogate in a list": [chr(0xD800)]}
        too_deep = ("5000 levels", "an innermost array at level 65")
        payload = ("agent_did", "args_hash", "cedar_policy_id", "receipt_id", "timestamp", "tool_name",
                   "parent_receipt_hash", "session_id")
        authorization = ("authorizer_id", "authorization_nonce", "authorization_expires_at")
        for field in payload + authorization:
            for label, value in values.items():
                with self.subTest(field=field, value=label):
                    r = dict(r3, **{field: value})
                    e = verify_agt_receipt(r, trusted_authorizer_keys=[real])    # must not raise
                    self.assertEqual((e.ok, exit_code(e)), (False, 2))
                    readable = [c.detail for c in e.checks if c.name == "readable"]
                    self.assertEqual(len(readable), 1, [c.name for c in e.checks])
                    self.assertIn(f"cannot be written as {AGT_CANONICAL_FORM}", readable[0])
                    if label in too_deep:
                        self.assertIn("it nests arrays and objects more than 64 deep", readable[0])
                    self.assertEqual(exit_code(verify_agt_receipt_chain([r1, r2, r], trusted_authorizer_keys=[real])), 2)
                    if field in payload:
                        e = verify_agt_receipt_chain([r, r1])
                        self.assertEqual(exit_code(e), 2)
                        link = [c.detail for c in e.checks if c.name == "[1] chain-link"]
                        self.assertIn("the previous receipt is not readable", link[0])

    def test_a_decision_that_is_not_text_is_unreadable(self):
        """`_text` raised `AGTReceiptError` for a `cedar_decision` that is not a string, and it stood
        outside the guard that turns that error into the `readable` check: 450 of the escapes of the
        sweep. It is exit 2 now, and the reason names the type."""
        from proofbundle.adapters.agt_receipt import exit_code, verify_agt_receipt, verify_agt_receipt_chain
        r1, r2, r3 = _agt("01_allow"), _agt("02_deny"), _agt("03_extern_autorisiert")
        for value in (5, None, 1.5, True, [], {}, ["allow"], {"a": "allow"}):
            with self.subTest(value=repr(value)):
                for receipt in (r1, r3):
                    e = verify_agt_receipt(dict(receipt, cedar_decision=value))  # must not raise
                    self.assertEqual((e.ok, exit_code(e), [c.name for c in e.checks]), (False, 2, ["readable"]))
                    self.assertIn(f"cedar_decision is {type(value).__name__}, expected a string", e.checks[0].detail)
                self.assertEqual(exit_code(verify_agt_receipt_chain([r1, dict(r2, cedar_decision=value)])), 2)

    def test_an_instant_outside_the_float_range_is_compared_exactly(self):
        """`float(10**400)` raised OverflowError out of both verifiers, for a `timestamp` or an
        `authorization_expires_at` of that size and for such a `now`. Python compares an int with a
        float by value and never overflows, so the expiry check compares the two as they are."""
        from proofbundle.adapters.agt_receipt import exit_code, verify_agt_receipt, verify_agt_receipt_chain
        r1, r2, r3 = _agt("01_allow"), _agt("02_deny"), _agt("03_extern_autorisiert")
        real = r3["authorizer_public_key"]
        big = 10 ** 400

        def unexpired(e):
            return [c.ok for c in e.checks if c.name == "external-authorization-unexpired"]

        e = verify_agt_receipt(r3, trusted_authorizer_keys=[real], now=big)
        self.assertEqual((exit_code(e), unexpired(e)), (1, [False]), "an instant after any expiry")
        e = verify_agt_receipt(r3, trusted_authorizer_keys=[real], now=-big)
        self.assertEqual((exit_code(e), unexpired(e)), (0, [True]), "an instant before it")
        e = verify_agt_receipt(dict(r3, authorization_expires_at=big), trusted_authorizer_keys=[real])
        self.assertEqual((exit_code(e), unexpired(e)), (1, [True]), "the authorization signature fails")
        e = verify_agt_receipt(dict(r3, timestamp=-big), trusted_authorizer_keys=[real])
        self.assertEqual((exit_code(e), unexpired(e)), (1, [True]), "the receipt signature fails")
        e = verify_agt_receipt_chain([r1, r2, dict(r3, timestamp=big)], trusted_authorizer_keys=[real])
        self.assertEqual(exit_code(e), 1)

    # ── lens run 4 at d461b41a: a compared value is read as its plain value first ──

    def test_an_instant_is_read_as_its_plain_number_before_it_is_compared(self):
        """K4-2 of lens run 4 at d461b41a, on main 20e91c8e too. A receipt file whose
        `authorization_expires_at` is a JSON integer of 310 digits, judged at `now=np.float64(...)`,
        raised OverflowError out of both verifiers: `np.float64` is a float subclass, so it passed the
        `isinstance` test, and its own `__le__` converts the int with `float()`. An int or float
        subclass whose `__le__` raises escaped as RuntimeError (exit 0 at 481a1f26 and on main, which
        converted with `float()` first), and so did a `now` whose `__class__` raises, through
        `isinstance`. Each instant is read as its plain number now and compared exactly. The same
        exactness corrects a rounding: an expiry of 2**53 judged at 2**53 + 1 is expired, where
        481a1f26 and main rounded the instant down to 2**53 and called it unexpired."""
        from proofbundle.adapters.agt_receipt import exit_code, verify_agt_receipt, verify_agt_receipt_chain
        r1, r2, r3 = _agt("01_allow"), _agt("02_deny"), _agt("03_extern_autorisiert")
        real = r3["authorizer_public_key"]

        class IntLeRaises(int):
            def __le__(self, other):
                raise RuntimeError("no comparison")

            def __ge__(self, other):
                raise RuntimeError("no comparison")

        class FloatLeRaises(float):
            def __le__(self, other):
                raise RuntimeError("no comparison")

            def __ge__(self, other):
                raise RuntimeError("no comparison")

        class ClassRaises:
            @property  # type: ignore[misc]  # the hostile override is the point
            def __class__(self):
                raise RuntimeError("no type")

        def unexpired(e):
            return [c.ok for c in e.checks if c.name.endswith("external-authorization-unexpired")]

        cases = [  # label, receipt, now, the exit code, `external-authorization-unexpired`
            ("now: an int whose __le__ raises", r3, IntLeRaises(5), 0, [True]),
            ("now: a float whose __le__ raises", r3, FloatLeRaises(5.0), 0, [True]),
            ("now: a float whose __le__ raises, after the expiry", r3, FloatLeRaises(10.0 ** 300), 1, [False]),
            ("now: a value whose __class__ raises", r3, ClassRaises(), 1, [False]),
            ("the receipt's timestamp as a float whose __le__ raises",
             dict(r3, timestamp=FloatLeRaises(r3["timestamp"])), None, 0, [True]),
        ]
        np = _numpy()
        if np is not None:
            hostile = json.loads(json.dumps(dict(r3, authorization_expires_at="@@")).replace('"@@"', "1" + "0" * 309))
            self.assertEqual(type(hostile["authorization_expires_at"]), int, "precondition: JSON gives an int")
            cases += [
                ("the lens's case: a 310-digit expiry at now=np.float64", hostile, np.float64(1.7e9), 1, [True]),
                ("the receipt's timestamp as np.float64, a 310-digit expiry",
                 dict(hostile, timestamp=np.float64(r3["timestamp"])), None, 1, [True]),
            ]
        for label, receipt, now, code, verdict in cases:
            with self.subTest(case=label):
                for keys in (None, [real]):
                    e = verify_agt_receipt(receipt, trusted_authorizer_keys=keys, now=now)   # must not raise
                    self.assertEqual(unexpired(e), verdict)
                    # without a list the authorization is not evaluated: exit 3, unless a check fails
                    self.assertEqual(exit_code(e), code if keys is not None or code == 1 else 3)
                e = verify_agt_receipt_chain([r1, r2, receipt], trusted_authorizer_keys=[real], now=now)
                self.assertEqual((exit_code(e), unexpired(e)), (code, verdict))
        for label, now, verdict in (("2**53 + 1", 2 ** 53 + 1, [False]), ("2**53", 2 ** 53, [True]),
                                    ("2**53 - 1", 2 ** 53 - 1, [True]), ("float(2**53)", float(2 ** 53), [True])):
            with self.subTest(expiry="2**53", now=label):
                e = verify_agt_receipt(dict(r3, authorization_expires_at=2 ** 53), trusted_authorizer_keys=[real],
                                       now=now)
                self.assertEqual(unexpired(e), verdict)
        if np is None:
            with self.subTest(numpy="not installed"):
                self.skipTest("NOT MEASURABLE: numpy is not installed here; the np.float64 cases did NOT run")

    def test_a_value_compared_or_tested_runs_no_method_of_the_callers(self):
        """The sweep of K4-2 over every comparison and type test on a value read out of a receipt. At
        d461b41a each of these escaped from both verifiers: `assurance_level` or `parent_receipt_hash`
        as an int whose `__eq__` raises (the comparison with the claim and with the digest ran it); a
        text field as a `str` subclass whose methods raise (`not signatur` ran `__bool__`, the set
        lookup of the decision `__hash__`); a field or the receipt itself whose `__class__` raises (the
        `isinstance` test asked for it). And an int whose `__eq__` answers True linked any two
        receipts. Every such value is read as its plain value now, through `type()`: a str subclass
        as the text it holds, so the verdict is the one the plain text gets, anything else as no text."""
        from proofbundle.adapters.agt_receipt import exit_code, verify_agt_receipt, verify_agt_receipt_chain
        r1, r2, r3 = _agt("01_allow"), _agt("02_deny"), _agt("03_extern_autorisiert")
        real = r3["authorizer_public_key"]

        class IntEqRaises(int):
            def __eq__(self, other):
                raise RuntimeError("no comparison")
            __hash__ = int.__hash__

        class IntEqTrue(int):
            def __eq__(self, other):
                return True
            __hash__ = int.__hash__

        def boom(*_a, **_k):
            raise RuntimeError("a method of the caller's ran")

        class StrRaises(str):
            __eq__ = __ne__ = __hash__ = __len__ = __getitem__ = __bool__ = __repr__ = boom
            __contains__ = __iter__ = __str__ = __format__ = boom

        class ClassRaises:
            @property  # type: ignore[misc]  # the hostile override is the point
            def __class__(self):
                raise RuntimeError("no type")

        def verdict(call):
            try:
                return call()
            except Exception as escaped:  # noqa: BLE001 — an escape is the finding
                raise AssertionError(f"the verifier raised {type(escaped).__name__}: {escaped}") from None

        with self.subTest(field="assurance_level", value="an int whose __eq__ raises"):
            e = verdict(lambda: verify_agt_receipt(dict(r1, assurance_level=IntEqRaises(5))))
            self.assertEqual((e.ok, exit_code(e)), (True, 0), "a number claims no authorization")
        with self.subTest(field="assurance_level", value="the claim as a str whose methods raise"):
            e = verdict(lambda: verify_agt_receipt(dict(r1, assurance_level=StrRaises("externally_authorized"))))
            self.assertEqual(exit_code(e), 1, "the claim is read as the text it holds and owes an authorization")
        for value, label, code in ((IntEqRaises(5), "an int whose __eq__ raises", 1),
                                   (IntEqTrue(5), "an int equal to everything", 1),
                                   (ClassRaises(), "a value whose __class__ raises, which JSON cannot encode", 2)):
            with self.subTest(field="parent_receipt_hash", value=label):
                e = verdict(lambda value=value: verify_agt_receipt_chain([r1, dict(r2, parent_receipt_hash=value)]))
                self.assertEqual(exit_code(e), code)
                self.assertEqual([c.ok for c in e.checks if c.name == "[1] chain-link"], [False])
        for field, receipt in (("signature", r1), ("signer_public_key", r1), ("payload_hash", r1),
                               ("cedar_decision", r1), ("authorization_signature", r3),
                               ("authorizer_public_key", r3)):
            with self.subTest(field=field, value="a str whose methods raise"):
                plain = verify_agt_receipt(receipt, trusted_authorizer_keys=[real])
                e = verdict(lambda field=field, receipt=receipt: verify_agt_receipt(
                    dict(receipt, **{field: StrRaises(receipt[field])}), trusted_authorizer_keys=[real]))
                self.assertEqual([(c.name, c.ok, c.detail) for c in e.checks],
                                 [(c.name, c.ok, c.detail) for c in plain.checks])
        for field, receipt, code in (("signature", r1, 1), ("signer_public_key", r1, 1), ("payload_hash", r1, 0),
                                     ("authorization_signature", r3, 1), ("authorizer_public_key", r3, 1)):
            with self.subTest(field=field, value="a value whose __class__ raises"):
                e = verdict(lambda field=field, receipt=receipt: verify_agt_receipt(
                    dict(receipt, **{field: ClassRaises()}), trusted_authorizer_keys=[real]))
                self.assertEqual(exit_code(e), code)
        with self.subTest(value="a receipt whose __class__ raises"):
            e = verdict(lambda: verify_agt_receipt(ClassRaises()))
            self.assertEqual((exit_code(e), e.checks[0].name), (2, "readable"))
        with self.subTest(value="a chain whose __class__ raises"):
            self.assertEqual(exit_code(verdict(lambda: verify_agt_receipt_chain(ClassRaises()))), 2)
        with self.subTest(value="a chain element whose __class__ raises"):
            e = verdict(lambda: verify_agt_receipt_chain([r1, ClassRaises()]))
            self.assertEqual(exit_code(e), 2)
            self.assertIn("receipts[1] is ClassRaises, not an object",
                          [c.detail for c in e.checks if c.name == "[1] chain-link"][0])

    # ── lens run 5 at c8c61651: every serialisation of a receipt ends in a verdict ──

    def test_a_nested_receipt_is_a_verdict_at_every_caller_depth(self):
        """F2 of lens run 5 at c8c61651, on main 20e91c8e too. A plain JSON receipt whose `tool_name` is
        a list nested N deep and whose `payload_hash` is a string made both verifiers raise
        `AGTReceiptError … RecursionError`: the payload was serialised once inside the guard and again
        through `payload_hash`, one frame deeper and outside every `try`, so one N passed the first and
        failed the second. The window moves with the caller's stack and exists at every depth (the
        lens: N = 988 at no extra frame, 488 at 500). Each receipt is serialised once now, and every
        hash is taken from those bytes.

        WHERE THE VERDICT TURNS FROM 1 TO 2 IS THE MODULE'S CEILING, NOT THE SERIALISER'S LIMIT. The
        first form of this case demanded both verdicts across the serialiser's limit, and the CI matrix
        at a4e2fa5c showed that limit is no property of the receipt: 3.12, 3.13 and 3.14 write every N of
        that window, so the sweep saw exit 1 only (10 failed subtests on each). The sweep now runs N
        across the ceiling of 64 levels and across the old window, at five caller depths, and demands the
        same verdict for the same N at every depth: exit 1 up to N = 63 (the payload is written, its
        hash and signature no longer match), exit 2 from N = 64 on (the innermost array at level 65),
        with one message for every refused N. At a4e2fa5c N = 64 to the old window gave exit 1 on
        every interpreter."""
        from proofbundle.adapters.agt_receipt import exit_code, verify_agt_receipt, verify_agt_receipt_chain
        from proofbundle.budget import DEFAULT_BUDGET
        r1 = _agt("01_allow")
        limit = sys.getrecursionlimit()
        ceiling = 64                     # a literal: no load here is built from a budget value
        self.assertEqual(DEFAULT_BUDGET.json_depth, ceiling, "precondition: the house ceiling of the rule")

        def depth():
            frame, n = sys._getframe(), 0
            while frame is not None:
                frame, n = frame.f_back, n + 1
            return n

        def nested(n):
            v: Any = "x"
            for _ in range(n):
                v = [v]
            return v

        def at_depth(extra, call):
            return call() if extra == 0 else at_depth(extra - 1, call)

        def refusal(e):
            return {c.detail for c in e.checks if c.name.endswith("readable") and not c.ok}

        here = depth()
        self.assertLess(here + 500 + 150, limit, "precondition: the deepest caller fits under the limit")
        for extra in (0, 10, 50, 200, 500):
            top = limit - here - extra
            sweep = sorted(set(range(ceiling - 12, ceiling + 12)) | set(range(top - 100, top + 5)) | {5000})
            for label, verify in (("single", lambda r: verify_agt_receipt(r)),
                                  ("chain", lambda r: verify_agt_receipt_chain([r, r1]))):
                with self.subTest(extra_frames=extra, call=label):
                    exits, messages, escaped = {}, set(), []
                    for n in sweep:
                        receipt = dict(r1, tool_name=nested(n), payload_hash="ab" * 32)
                        try:
                            e = at_depth(extra, lambda: verify(receipt))
                        except Exception as escape:  # noqa: BLE001 — an escape is the finding
                            escaped.append((n, type(escape).__name__))
                            continue
                        exits[n] = exit_code(e)
                        messages |= refusal(e)
                    self.assertEqual(escaped, [], f"the verifier raised at nesting {escaped[:3]}")
                    wrong = {n: x for n, x in exits.items() if x != (1 if n < ceiling else 2)}
                    self.assertEqual(wrong, {}, "exit 1 up to N = 63 and exit 2 from N = 64, at every depth")
                    self.assertEqual(messages, {"the receipt payload cannot be written as sortkeys-json-utf8: it "
                                                "nests arrays and objects more than 64 deep, and this verifier "
                                                "writes none deeper, on every interpreter"})

    def test_a_depth_read_through_a_callers_methods_is_measured_in_what_was_written(self):
        """The neighbour of the ceiling, found by the sweep of this fix. `json.dumps` reads a `list`
        subclass through its `__iter__` and a `dict` subclass with stored items through its `items()`,
        so what it writes can be deeper than anything stored. Measured at a4e2fa5c: such a value
        holding 100 levels in its methods and nothing deeper in its storage was written, exit 1, on all
        five interpreters, and 5000 levels gave exit 2 on 3.10 and 3.11 and exit 1 from 3.12 on. The
        depth is measured in the form the serialiser wrote now, and each method still runs once."""
        from proofbundle.adapters.agt_receipt import (canonical_authorization_payload, canonical_payload, exit_code,
                                                      verify_agt_receipt, verify_agt_receipt_chain)
        r1, r3 = _agt("01_allow"), _agt("03_extern_autorisiert")
        real = r3["authorizer_public_key"]
        calls = []

        def nested(n):
            v: Any = "x"
            for _ in range(n):
                v = [v]
            return v

        class Iterates(list):
            def __iter__(self):
                calls.append("__iter__")
                return iter([self.inner])

        class Items(dict):
            def items(self):
                calls.append("items")
                return [("k", self.inner)]

        def holding(kind, inner):
            value = kind() if kind is Iterates else kind(stored=1)
            value.inner = inner            # the form writes the field at level 2, `inner` at level 3
            return value

        for kind in (Iterates, Items):
            # the innermost array of `nested(n)` sits at level n + 2: 62 is the last level written
            for n, code in ((62, 1), (63, 2), (100, 2), (5000, 2)):
                for field, receipt, keys in (("tool_name", dict(r1, payload_hash="ab" * 32), None),
                                             ("authorizer_id", r3, [real])):
                    with self.subTest(kind=kind.__name__, levels=n, field=field):
                        calls.clear()
                        e = verify_agt_receipt(dict(receipt, **{field: holding(kind, nested(n))}),
                                               trusted_authorizer_keys=keys)
                        self.assertEqual(exit_code(e), code, [(c.name, c.detail) for c in e.checks if not c.ok])
                        self.assertEqual(len(calls), 1, "the caller's method ran more or less than once")
                        if code == 2 and n <= 100:     # 5000 may meet the serialiser's own limit first
                            self.assertIn("it nests arrays and objects more than 64 deep",
                                          " ".join(c.detail for c in e.checks))
                        chain = verify_agt_receipt_chain([dict(receipt, **{field: holding(kind, nested(n))}), r1])
                        self.assertEqual(exit_code(chain), code)
            with self.subTest(kind=kind.__name__, control="brackets, quotes and backslashes inside strings are no level"):
                text = '\\"[{' * 100
                e = verify_agt_receipt(dict(r1, payload_hash="ab" * 32, tool_name=holding(kind, {text: [text, text]})))
                self.assertEqual(exit_code(e), 1, [(c.name, c.detail) for c in e.checks if not c.ok])
                self.assertEqual(exit_code(verify_agt_receipt(dict(r1, payload_hash="ab" * 32, tool_name=text))), 1)
        with self.subTest(control="a value shared many times over is walked once per container and level"):
            shared: Any = "x"
            for _ in range(60):                   # 2**60 paths, 61 containers, the deepest at level 61
                shared = [shared, shared]
            e = verify_agt_receipt(dict(r1, agent_did=b"x", tool_name=shared))   # bytes are refused first
            self.assertEqual(exit_code(e), 2)
            self.assertIn("raised TypeError", e.checks[0].detail)
        with self.subTest(public="canonical_payload and canonical_authorization_payload at the ceiling"):
            from proofbundle.adapters.agt_receipt import AGTReceiptError
            self.assertIsInstance(canonical_payload(dict(r1, tool_name=nested(63))), bytes)
            self.assertIsInstance(canonical_authorization_payload(dict(r3, authorizer_id=nested(63))), bytes)
            with self.assertRaises(AGTReceiptError):
                canonical_payload(dict(r1, tool_name=nested(64)))
            with self.assertRaises(AGTReceiptError):
                canonical_authorization_payload(dict(r3, authorizer_id=nested(64)))

    def test_the_payload_is_serialised_once_and_every_hash_is_taken_from_those_bytes(self):
        """The sibling of F2 the lens named: a value whose own `items()` raises on its second call
        escaped from both verifiers whenever the receipt carries a `payload_hash`, because the payload
        was serialised a second time for the self-consistency check (and a third time inside the
        authorization payload, a fourth for the chain link). Counted here: one serialisation per
        receipt, for the single call, for the authorized receipt and for a chain."""
        from proofbundle.adapters.agt_receipt import exit_code, verify_agt_receipt, verify_agt_receipt_chain
        r1, r3 = _agt("01_allow"), _agt("03_extern_autorisiert")
        real = r3["authorizer_public_key"]

        class ReadOnce(dict):
            calls = 0

            def items(self):
                type(self).calls += 1
                if type(self).calls > 1:
                    raise ValueError("the value was read a second time")
                return super().items()

        cases = {
            "single, 01": lambda: verify_agt_receipt(dict(r1, tool_name=ReadOnce(a=1), payload_hash="ab" * 32)),
            "single, 03 with its authorization": lambda: verify_agt_receipt(
                dict(r3, tool_name=ReadOnce(a=1)), trusted_authorizer_keys=[real]),
            "chain, the receipt first": lambda: verify_agt_receipt_chain(
                [dict(r1, tool_name=ReadOnce(a=1)), _agt("02_deny")]),
        }
        self.assertIsInstance(r3.get("payload_hash"), str, "precondition: 03 carries its payload_hash")
        for label, call in cases.items():
            with self.subTest(case=label):
                ReadOnce.calls = 0
                try:
                    e = call()
                except Exception as escape:  # noqa: BLE001 — an escape is the finding
                    self.fail(f"the verifier raised {type(escape).__name__}")
                self.assertEqual(ReadOnce.calls, 1, "the payload was serialised more than once")
                self.assertEqual(exit_code(e), 1, [(c.name, c.ok) for c in e.checks])

    def test_the_receipt_and_the_chain_are_read_through_their_own_storage(self):
        """F7 of lens run 5 at c8c61651, and the two limits the fourth run named. A field lookup
        compares the name with every stored key of the same hash: one key object whose hash equals
        `hash("agent_did")` and whose `__eq__` raises made both verifiers raise RuntimeError from a
        plain dict, on main 20e91c8e too. A dict subclass whose `get` raises, and a list subclass
        whose `__len__` raises as the chain, escaped the same way. The receipt is read through
        `dict.items` and the chain through `list.__iter__` or `tuple.__iter__` now, which walk the
        stored items and call no method of the caller's; a key that is no text names no field."""
        from proofbundle.adapters.agt_receipt import exit_code, verify_agt_receipt, verify_agt_receipt_chain
        r1, r2 = _agt("01_allow"), _agt("02_deny")

        class Collides:
            armed = False

            def __init__(self, name):
                self.h = hash(name)

            def __hash__(self):
                return self.h

            def __eq__(self, other):
                if Collides.armed:
                    raise RuntimeError("a key's __eq__ ran")
                return False

        def verdict(call):
            try:
                return call()
            except Exception as escaped:  # noqa: BLE001 — an escape is the finding
                raise AssertionError(f"the verifier raised {type(escaped).__name__}: {escaped}") from None

        for name in ("agent_did", "cedar_decision", "timestamp", "signature", "payload_hash"):
            with self.subTest(key=f"an object hashing like {name!r}"):
                Collides.armed = False
                receipt = {Collides(name): 1}
                receipt.update(r1)
                Collides.armed = True
                try:
                    self.assertEqual(exit_code(verdict(lambda: verify_agt_receipt(receipt))), 0)
                    self.assertEqual(exit_code(verdict(lambda: verify_agt_receipt_chain([receipt, r2]))), 0)
                finally:
                    Collides.armed = False
        with self.subTest(key="an object hashing like 'parent_receipt_hash', in the linked receipt"):
            linked = {Collides("parent_receipt_hash"): 1}
            linked.update(r2)
            Collides.armed = True
            try:
                self.assertEqual(exit_code(verdict(lambda: verify_agt_receipt_chain([r1, linked]))), 0)
            finally:
                Collides.armed = False

        def boom(*_a, **_k):
            raise RuntimeError("a method of the caller's container ran")

        class MappingRaises(dict):
            get = __getitem__ = __contains__ = items = keys = values = __iter__ = __len__ = boom

        class ListRaises(list):
            __len__ = __iter__ = __getitem__ = __bool__ = __reversed__ = boom

        class TupleRaises(tuple):
            __len__ = __iter__ = __getitem__ = __bool__ = boom

        with self.subTest(container="a dict subclass whose methods raise"):
            self.assertEqual(exit_code(verdict(lambda: verify_agt_receipt(MappingRaises(r1)))), 0)
            self.assertEqual(exit_code(verdict(
                lambda: verify_agt_receipt_chain([MappingRaises(r1), MappingRaises(r2)]))), 0)
        for label, chain in (("a list subclass whose methods raise", ListRaises([r1, r2])),
                             ("a tuple subclass whose methods raise", TupleRaises((r1, r2)))):
            with self.subTest(container=label):
                self.assertEqual(exit_code(verdict(lambda chain=chain: verify_agt_receipt_chain(chain))), 0)
        with self.subTest(control="a str subclass key names the field it spells"):

            class Name(str):
                pass

            receipt = {Name(k) if k == "agent_did" else k: v for k, v in r1.items()}
            self.assertEqual(exit_code(verify_agt_receipt(receipt)), 0)


# ── 2. the findings register's carrier: `_signatur_lage` and the views ──────────────────────────

_TRAEGER = REPO / "audit_artifacts" / "600" / "findings_register_v2.json"
_TRAEGER_610 = REPO / "audit_artifacts" / "610" / "findings_register_v2.json"


def _gen():
    spec = importlib.util.spec_from_file_location("_t_d3_gfr", REPO / "scripts" / "gen_findings_register.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _signed(doc: dict, key: bytes, sig: bytes) -> dict:
    d = copy.deepcopy(doc)
    d["signature"] = {"alg": "ed25519", "public_key_b64": _b64(key), "sig_b64": _b64(sig)}
    return d


class RegisterCarrier(unittest.TestCase):
    g: Any                   # the generator script, loaded once in setUpClass
    doc: dict

    @classmethod
    def setUpClass(cls):
        if not _TRAEGER.is_file():
            raise unittest.SkipTest(f"NOT MEASURABLE: {_TRAEGER} is missing; the carrier cases did NOT run")
        cls.g = _gen()
        cls.doc = json.loads(_TRAEGER.read_text(encoding="utf-8"))

    def _signature_errors(self, d) -> list:
        return [f for f in self.g.pruefe_v2(d, REPO) if f.startswith("Signatur")]

    def test_the_identity_point_is_refused_and_no_view_says_verified(self):
        d = _signed(self.doc, I1, UNIV)
        self.assertIs(verify_ed25519(I1, UNIV, self.g.canonical_bytes(d)), True, "precondition")
        state, detail = self.g._signatur_lage(d)
        self.assertEqual(state, "KEY_REFUSED")
        self.assertIn(TRUST_ANCHOR_REFUSAL["low-order"], detail)
        line = self.g._signaturzeile(d)
        self.assertFalse(line.startswith("Signed"), line)
        self.assertIn("unauthenticated", line)
        for view in (self.g.ansicht_uebersicht(d), self.g.ansicht_html(d)):
            self.assertNotIn("Signed and verified", view)
            self.assertIn("cannot stand as a trusted key", view)
        self.assertTrue(self._signature_errors(d), "pruefe_v2 must count a refused key as an error")

    def test_the_zero_key_is_refused_for_every_body(self):
        """The register entry's own case: 32 zero bytes as key, 64 as signature. It is a point of
        order four, so the forgery holds for some bodies and not others; every one is refused. Over
        the line-610 carrier, where the bare profile accepted 7 of these 16 bodies on 126ed1dc (the
        line-600 carrier admits 1 of 16, too few to lean on). `_signatur_lage` reads no line state,
        so the exit and the view line are measured here; `pruefe_v2` is held above."""
        if not _TRAEGER_610.is_file():
            self.skipTest(f"NOT MEASURABLE: {_TRAEGER_610} is missing; the zero-key case did NOT run")
        doc = json.loads(_TRAEGER_610.read_text(encoding="utf-8"))
        live = 0
        for rev in range(16):
            with self.subTest(register_revision=rev):
                d = _signed(dict(doc, register_revision=rev), ZERO, ZSIG)
                live += verify_ed25519(ZERO, ZSIG, self.g.canonical_bytes(d))
                self.assertEqual(self.g._signatur_lage(d)[0], "KEY_REFUSED")
                self.assertFalse(self.g._signaturzeile(d).startswith("Signed"))
        self.assertGreater(live, 0, "no body admitted the forgery; this case would measure nothing")

    def test_every_weak_key_is_refused_by_name(self):
        for key, reason in WEAK:
            with self.subTest(key=key.hex()):
                state, detail = self.g._signatur_lage(_signed(self.doc, key, UNIV))
                self.assertEqual(state, "KEY_REFUSED")
                self.assertIn(TRUST_ANCHOR_REFUSAL[reason], detail)

    def test_positive_control_a_real_signature_verifies_and_the_view_says_so(self):
        k = Ed25519PrivateKey.generate()
        d = _signed(self.doc, _raw(k), b"\x00" * 64)
        d["signature"]["sig_b64"] = _b64(k.sign(self.g.canonical_bytes(d)))
        self.assertEqual(self.g._signatur_lage(d), ("VERIFIZIERT", "ed25519"))
        self.assertTrue(self.g._signaturzeile(d).startswith("Signed and verified"))
        self.assertEqual(self._signature_errors(d), [])

    def test_a_key_of_the_wrong_length_stays_a_broken_block(self):
        """Not a weak key and not a new state: before the rule it failed in the key constructor."""
        self.assertEqual(self.g._signatur_lage(_signed(self.doc, b"\x01" * 31, UNIV))[0], "GEBROCHEN")


# ── 3. `show-eval --expect-issuer`, the pin the SPEC says carries the rule ───────────────────────

def _cli(*args) -> "tuple[int, str, str]":
    from proofbundle.cli import main
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        rc = main(list(args))
    return rc, out.getvalue(), err.getvalue()


class ShowEvalIssuerPin(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        from proofbundle import evalclaim as ec
        from proofbundle.emit import emit_bundle, generate_signer
        cls.tmp = tempfile.TemporaryDirectory()
        d = Path(cls.tmp.name)
        cls.issuer_i1 = "ed25519:" + _b64(I1)
        try:
            claim, _ = ec.build_eval_claim(
                suite="s", suite_version="1", metric="acc", comparator=">=", threshold="0.80",
                score="0.10", n=10, model_id="m", dataset_id="d", issuer=cls.issuer_i1,
                timestamp="2026-09-26T12:00:00Z", model_salt=b"0" * 16, dataset_salt=b"1" * 16)
            forged = emit_bundle(ec.canonicalize(dict(claim, passed=True, issuer=cls.issuer_i1)), _Nobody())
            cls.signer = generate_signer()
            real = ec.emit_eval_receipt(claim, cls.signer)
        except ec.EvalClaimError as exc:
            cls.tmp.cleanup()
            raise unittest.SkipTest(f"NOT MEASURABLE: the [eval] extra is missing ({exc}); the "
                                    "show-eval cases did NOT run") from exc
        cls.forged, cls.real = d / "forged.json", d / "real.json"
        cls.forged.write_text(json.dumps(forged), encoding="utf-8")
        cls.real.write_text(json.dumps(real), encoding="utf-8")
        cls.issuer_real = ec.issuer_fingerprint(cls.signer)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_precondition_the_receipt_nobody_signed_passes_in_the_self_attested_scope(self):
        """Without a pin the bundle's own key is the SPEC's in-band exception; the pin is the guard."""
        rc, out, _ = _cli("show-eval", str(self.forged))
        self.assertEqual(rc, 0)
        self.assertIn("passed     True", out)

    def test_a_small_order_pin_is_refused_typed_and_fail_closed(self):
        rc, out, err = _cli("show-eval", str(self.forged), "--expect-issuer", self.issuer_i1)
        self.assertEqual(rc, 2, out + err)
        self.assertNotIn("=> OK", out)
        self.assertIn("refused as a trusted key", err)
        self.assertIn(TRUST_ANCHOR_REFUSAL["low-order"], err)

    def test_every_weak_pin_is_refused_before_the_receipt_is_read(self):
        """Against a REAL receipt, so the refusal cannot come from the forgery: on 126ed1dc these
        were an ordinary issuer mismatch, exit 1."""
        for key, reason in WEAK:
            with self.subTest(key=key.hex()):
                rc, out, err = _cli("show-eval", str(self.real), "--expect-issuer", "ed25519:" + _b64(key))
                self.assertEqual(rc, 2, out + err)
                self.assertIn(TRUST_ANCHOR_REFUSAL[reason], err)
        rc, out, err = _cli("show-eval", str(self.real), "--expect-issuer", self.issuer_real,
                            "--expect-issuer", self.issuer_i1)
        self.assertEqual(rc, 2, "one weak pin in a rotation list refuses the list")

    def test_positive_control_a_normal_pin_behaves_as_before(self):
        rc, out, err = _cli("show-eval", str(self.real), "--expect-issuer", self.issuer_real)
        self.assertEqual(rc, 0, err)
        self.assertIn("=> OK", out)
        rc, out, err = _cli("show-eval", str(self.real), "--expect-issuer", "ed25519:alt",
                            "--expect-issuer", self.issuer_real)
        self.assertEqual(rc, 0, err)
        other = "ed25519:" + _b64(_raw(Ed25519PrivateKey.generate()))
        rc, out, err = _cli("show-eval", str(self.real), "--expect-issuer", other)
        self.assertEqual(rc, 1)
        self.assertIn("issuer mismatch", err)
        rc, out, err = _cli("show-eval", str(self.forged), "--expect-issuer", self.issuer_real)
        self.assertEqual(rc, 1, "the forgery against a real pin stays a mismatch")


# ── 4. the producers: where a key ENTERS a carrier ─────────────────────────────────────────────────
#
# The three `assemble` steps under scripts/ wrap a signature made elsewhere and the public key handed
# in with it, and write the carrier. Until the follow-up to D3 they checked the pair under the bare
# SPEC section 4a profile and relied on the verifiers that read their output to refuse a weak key.
# Measured on 3c9c98c3: each of the three wrote a carrier under the identity point with the signature
# R = identity, S = 0, and exited 0. The class is "a weak key is accepted where a key enters", so the
# refusal belongs here too, before anything is written.

_PRODUCERS = {
    # script, the assemble function, the module whose `canonical_bytes` the producer signs over
    "gen_findings_register": ("scripts/gen_findings_register.py", "assemble", "gen_findings_register"),
    "sign_readiness_artifact": ("scripts/sign_readiness_artifact.py", "assemble", "sign_readiness_artifact"),
    "pre_tag_receipt": ("scripts/pre_tag_receipt.py", "assemble_receipt", "pre_tag_receipt_lib"),
}


def _script_module(name: str):
    spec = importlib.util.spec_from_file_location(f"_t_d3_{name}", REPO / "scripts" / f"{name}.py")
    assert spec is not None and spec.loader is not None, name
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _body(producer: str) -> dict:
    """A body each producer accepts in shape; what it says does not matter, who signed it does."""
    if producer == "gen_findings_register":
        return {"schema": "proofbundle.findings_register.v1", "version": "9.9.9",
                "generated_at": "2026-09-26T00:00:00Z", "findings": []}
    if producer == "sign_readiness_artifact":
        return {"schema": "x", "signer_role": "release-runner", "produced_at": "2026-09-26T00:00:00Z"}
    lib = _script_module("pre_tag_receipt_lib")
    return {"schema": lib.RECEIPT_SCHEMA, "version": "9.9.9", "subject_tree_digest": "a" * 64,
            "gate_source_digest": "b" * 64, "audit_command": "nobody ran this", "audit_exit_code": 0,
            "audit_output_digest": "c" * 64, "runner_identity": "nobody",
            "produced_at": "2026-09-26T00:00:00Z"}


def _canonical(producer: str, body: dict) -> bytes:
    return _script_module(_PRODUCERS[producer][2]).canonical_bytes(body)


def _assemble_cli(producer: str, body: dict, pub: bytes, sig: bytes, tmp: Path):
    """The producer's own `--assemble` command line, in a process of its own: pre_tag_receipt.py
    changes the process environment when it is imported, and a test must not inherit that."""
    import os
    import subprocess
    ctx, sig_file, out = tmp / "context.json", tmp / "sig.b64", tmp / "carrier.json"
    ctx.write_text(json.dumps(body), encoding="utf-8")
    sig_file.write_text(_b64(sig), encoding="utf-8")
    env = dict(os.environ, PYTHONPATH=str(REPO / "src"), PYTHONDONTWRITEBYTECODE="1")
    r = subprocess.run([sys.executable, "-B", str(REPO / _PRODUCERS[producer][0]), "--assemble",
                        "--context-in", str(ctx), "--sig-file", str(sig_file),
                        "--signer-pubkey", _b64(pub), "--out", str(out)],
                       capture_output=True, text=True, timeout=120, env=env, cwd=str(tmp))
    return r, out


_DRIVER = """
import importlib.util, json, sys
spec = importlib.util.spec_from_file_location("producer", sys.argv[1])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
fn, body = getattr(mod, sys.argv[2]), json.loads(sys.argv[3])
out = []
for pub, sig in json.loads(sys.argv[4]):
    try:
        fn(body, sig, pub)
        out.append(["ACCEPTED", ""])
    except SystemExit as exc:
        out.append(["REFUSED", str(exc.code)])
print(json.dumps(out))
"""


def _assemble_every_weak_key(producer: str, body: dict) -> list:
    """The producer's `assemble` called once per WEAK key, in one process of its own."""
    import os
    import subprocess
    path, fn, _lib = _PRODUCERS[producer]
    cases = [[_b64(key), _b64(UNIV)] for key, _reason in WEAK]
    env = dict(os.environ, PYTHONPATH=str(REPO / "src"), PYTHONDONTWRITEBYTECODE="1")
    r = subprocess.run([sys.executable, "-B", "-c", _DRIVER, str(REPO / path), fn, json.dumps(body),
                        json.dumps(cases)], capture_output=True, text=True, timeout=120, env=env)
    if r.returncode != 0:
        raise AssertionError(f"driver for {producer} failed: {r.stderr[-800:]}")
    return json.loads(r.stdout.strip().splitlines()[-1])


class ProducerSelfChecks(unittest.TestCase):
    """One refusal and one control per producer."""

    def _refuses(self, producer: str):
        body = _body(producer)
        self.assertIs(verify_ed25519(I1, UNIV, _canonical(producer, body)), True,
                      "precondition: the bare profile accepts the signature nobody made")
        with tempfile.TemporaryDirectory() as d:
            r, out = _assemble_cli(producer, body, I1, UNIV, Path(d))
            self.assertNotEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertFalse(out.exists(), "a carrier under a weak key was written")
            self.assertIn(TRUST_ANCHOR_REFUSAL["low-order"], r.stderr)
        for (key, reason), (verdict, message) in zip(WEAK, _assemble_every_weak_key(producer, body)):
            with self.subTest(key=key.hex()):
                self.assertEqual(verdict, "REFUSED", message)
                self.assertIn(TRUST_ANCHOR_REFUSAL[reason], message)

    def _control(self, producer: str):
        body = _body(producer)
        k = Ed25519PrivateKey.generate()
        with tempfile.TemporaryDirectory() as d:
            r, out = _assemble_cli(producer, body, _raw(k), k.sign(_canonical(producer, body)), Path(d))
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            carrier = json.loads(out.read_text(encoding="utf-8"))
        self.assertIn(_b64(_raw(k)), json.dumps(carrier), "the carrier does not name the signer key")
        with tempfile.TemporaryDirectory() as d:     # and a real key under a wrong signature still refuses
            r, out = _assemble_cli(producer, body, _raw(k), k.sign(b"another body"), Path(d))
            self.assertNotEqual(r.returncode, 0)
            self.assertFalse(out.exists())

    def test_gen_findings_register_assemble_refuses_a_weak_key(self):
        self._refuses("gen_findings_register")

    def test_gen_findings_register_assemble_control_with_a_real_key(self):
        self._control("gen_findings_register")

    def test_sign_readiness_artifact_assemble_refuses_a_weak_key(self):
        self._refuses("sign_readiness_artifact")

    def test_sign_readiness_artifact_assemble_control_with_a_real_key(self):
        self._control("sign_readiness_artifact")

    def test_pre_tag_receipt_assemble_refuses_a_weak_key(self):
        self._refuses("pre_tag_receipt")

    def test_pre_tag_receipt_assemble_control_with_a_real_key(self):
        self._control("pre_tag_receipt")


# ── 5. what proofbundle SIGNS itself: no statement over a receipt a key nobody holds "signed" ────────
#
# Out-of-scope finding 3 of lens run 1 at 053c7800. SPEC section 4b lets the bundle's own key keep the
# section 4a profile when a receipt is VERIFIED, because trust in it comes from a pin. An export that
# SIGNS is different: proofbundle then vouches, under a real key, for what it read. Measured on
# 053c7800: `export_svr_dsse` signed PROOFBUNDLE_SIGNATURE_VALID and PROOFBUNDLE_THRESHOLD_MET over a
# PASS receipt signed by nobody under the identity point, and the SVR verified under the real key.

class ProofbundleDoesNotVouchForAKeyNobodyHolds(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        from proofbundle import evalclaim as ec
        from proofbundle.emit import emit_bundle, generate_signer
        cls.tmp = tempfile.TemporaryDirectory()
        d = Path(cls.tmp.name)
        cls.issuer_i1 = "ed25519:" + _b64(I1)
        try:
            claim, _ = ec.build_eval_claim(
                suite="s", suite_version="1", metric="acc", comparator=">=", threshold="0.80",
                score="0.90", n=10, model_id="m", dataset_id="d", issuer=cls.issuer_i1,
                timestamp="2026-09-26T12:00:00Z", model_salt=b"0" * 16, dataset_salt=b"1" * 16)
        except ec.EvalClaimError as exc:
            cls.tmp.cleanup()
            raise unittest.SkipTest(f"NOT MEASURABLE: the [eval] extra is missing ({exc})") from exc
        cls.forged = emit_bundle(ec.canonicalize(claim), _Nobody())
        cls.real = ec.emit_eval_receipt(claim, generate_signer())
        cls.forged_path, cls.real_path = d / "forged.json", d / "real.json"
        cls.forged_path.write_text(json.dumps(cls.forged), encoding="utf-8")
        cls.real_path.write_text(json.dumps(cls.real), encoding="utf-8")
        cls.forged_claim = ec.decode_eval_claim(cls.forged)
        cls.real_claim = ec.decode_eval_claim(cls.real)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_precondition_the_forged_receipt_verifies_in_band(self):
        from proofbundle.bundle import verify_bundle
        self.assertIs(verify_bundle(self.forged).ok, True)
        self.assertIsNotNone(self.forged_claim, "decode_eval_claim accepts it under section 4a")
        self.assertEqual(self.forged_claim["issuer"], self.issuer_i1)

    def test_the_svr_export_refuses_to_vouch(self):
        from proofbundle.emit import generate_signer
        from proofbundle.errors import BundleFormatError
        from proofbundle.intoto import export_svr_dsse
        with self.assertRaises(BundleFormatError) as ctx:
            export_svr_dsse(self.forged, generate_signer())
        self.assertIn(TRUST_ANCHOR_REFUSAL["low-order"], str(ctx.exception))
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "svr.json"
            rc, _o, err = _cli("svr", str(self.forged_path), "--out", str(out), "--new-key", str(Path(d) / "k"))
            self.assertEqual(rc, 2, err)
            self.assertFalse(out.exists(), "an SVR was written for a receipt nobody signed")
            self.assertIn("refused", err)

    def test_the_eval_result_export_refuses_to_vouch(self):
        from proofbundle.emit import generate_signer
        from proofbundle.errors import BundleFormatError
        from proofbundle.intoto import export_eval_result_dsse
        with self.assertRaises(BundleFormatError) as ctx:
            export_eval_result_dsse(self.forged_claim, generate_signer())
        self.assertIn(TRUST_ANCHOR_REFUSAL["low-order"], str(ctx.exception))
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "att.json"
            rc, _o, err = _cli("intoto", str(self.forged_path), "--out", str(out), "--new-key", str(Path(d) / "k"))
            self.assertEqual(rc, 2, err)
            self.assertFalse(out.exists())

    def test_the_test_result_export_refuses_to_vouch(self):
        from proofbundle.emit import generate_signer
        from proofbundle.errors import BundleFormatError
        from proofbundle.intoto import export_intoto_dsse
        with self.assertRaises(BundleFormatError) as ctx:
            export_intoto_dsse(self.forged_claim, generate_signer())
        self.assertIn(TRUST_ANCHOR_REFUSAL["low-order"], str(ctx.exception))

    def test_every_weak_issuer_is_refused_by_name(self):
        """The claim exporters read the issuer with the same parser `--expect-issuer` uses and ask the
        shared rule; every encoding the rule refuses is refused, with its own reason."""
        from proofbundle.emit import generate_signer
        from proofbundle.errors import BundleFormatError
        from proofbundle.intoto import export_eval_result_dsse, export_intoto_dsse
        for key, reason in WEAK:
            claim = dict(self.real_claim, issuer="ed25519:" + _b64(key))
            for export in (export_eval_result_dsse, export_intoto_dsse):
                with self.subTest(key=key.hex(), export=export.__name__):
                    with self.assertRaises(BundleFormatError) as ctx:
                        export(claim, generate_signer())
                    self.assertIn(TRUST_ANCHOR_REFUSAL[reason], str(ctx.exception))

    def test_positive_control_a_real_receipt_still_exports(self):
        from proofbundle import dsse
        from proofbundle.emit import generate_signer
        from proofbundle.intoto import (INTOTO_STATEMENT_PAYLOAD_TYPE, export_eval_result_dsse,
                                        export_intoto_dsse, export_svr_dsse, verify_svr_dsse)
        v = generate_signer()
        env = export_svr_dsse(self.real, v)
        self.assertIs(verify_svr_dsse(env, _raw(v))["ok"], True)
        self.assertIs(dsse.verify_envelope(export_eval_result_dsse(self.real_claim, v), _raw(v),
                                           payload_type=INTOTO_STATEMENT_PAYLOAD_TYPE), True)
        export_intoto_dsse(self.real_claim, v)
        claim_without_issuer = {k: val for k, val in self.real_claim.items() if k != "issuer"}
        export_eval_result_dsse(claim_without_issuer, v)       # no issuer named: nothing to judge
        with tempfile.TemporaryDirectory() as d:
            out = Path(d) / "svr.json"
            rc, _o, err = _cli("svr", str(self.real_path), "--out", str(out), "--new-key", str(Path(d) / "k"))
            self.assertEqual(rc, 0, err)
            self.assertTrue(out.exists())


# ── 6. where a producer AUTHORISES a key the caller hands it ───────────────────────────────────────
#
# A Codex review of pull request 293 at a4e2fa5c: `sdjwt_issue.issue_sd_jwt` checked the holder key
# only for its length, wrote it into `cnf.jwk` and signed. The class: a place that writes a caller's
# Ed25519 key into something a relying party will trust (a holder binding, a verifier key, a pinned
# issuer, a trust pack) checks it with the rule its verifier uses, before it writes. Measured at
# a4e2fa5c: `issue_sd_jwt`, `checkpoint.vkey` and `checkpoint.cosign_vkey` wrote all 13 weak
# encodings; the policy template and the trust pack refused all 13 already. At the tags v6.0.0 and
# v6.1.0 the verifiers did not refuse them either: an SD-JWT bound to the identity point and a Key
# Binding JWT signed by nobody gave "key binding valid", and all 13 weak vkeys parsed.
#
# THE SWEEP LIST, every producer under src/ that writes an Ed25519 public key (read at 76c900ea):
#   sdjwt_issue.issue_sd_jwt              caller's holder key into `cnf.jwk`   rule since this fix
#   checkpoint.vkey                       caller's key as a log vkey           rule since this fix
#   checkpoint.cosign_vkey                caller's key as a witness vkey       rule since this fix
#   policy_profiles.instantiate_template  caller's issuer keys as pins         refused, a control
#   trust_pack.sign_trust_pack            the predicate's keys                 refused, a control
#   trust_pack.build_trust_pack_statement the same keys, unsigned              refused (same check)
#   emit.emit_bundle, its `sd_jwt_vc`     a foreign issuer's key, copied verbatim and outside what
#                                         the bundle signs; `verify_bundle` checks the SD-JWT under
#                                         it with the rule (`sdjwt._ISSUER_SIG_VERIFIERS`)
# Every other writer puts down the key of the private key it signs with (the bundle signature of
# `emit_bundle`, the issuer of `emit_eval_receipt`), a key ID derived from that key
# (`sign_checkpoint`, `cosign_checkpoint`), or a key ID the caller names (`dsse.sign_envelope` and
# the statement emitters that call it); the key of a real private key is never of small order.
# The exports that sign a verdict over a receipt (`intoto.export_svr_dsse`,
# `export_eval_result_dsse`, `export_intoto_dsse`) write no key and refuse to vouch for an issuer
# key the rule refuses: section 5. Under scripts/, the three `assemble` steps that write a key
# handed in with its signature are section 4; this round did not sweep scripts/ again.
# All of this holds for a plain value. Given as a subclass whose own methods answer for another key,
# each producer above judged one reading and wrote another at 75c3aa48 (lens run 7, F1 and F2), the
# two "refused" controls included; tests/test_a_producer_reads_a_callers_key_once.py holds every
# producer of this list, and the ones under scripts/, to one reading of the key.

_SRC = REPO / "src" / "proofbundle"

#: Every comparison of a `len(...)` with the literal 32 under src/, by file and function, with how many
#: there are and why each is no carrier of the class. A place that checks a key by its length alone is
#: one; a new comparison turns the case below red until it is read and named here.
_LENGTH_32 = {
    ("adapters/agt_receipt.py", "_schluesselbytes"): (1, "names a key; `_schwaeche` applies the rule to it"),
    ("anchors_chia_add.py", "anchor_add"): (1, "a canonical root, no key"),
    ("assurance.py", "classify_receiver_corroboration"): (1, "compares the key a caller's resolver "
                                                          "returns with the pack's key; writes nothing"),
    ("cap1.py", "_is_digest"): (1, "a digest, no key"),
    ("checkpoint.py", "key_id"): (1, "a key ID, a hash input; `vkey` applies the rule before it writes"),
    ("checkpoint.py", "cosign_key_id"): (1, "a key ID, a hash input; `cosign_vkey` applies the rule"),
    ("checkpoint.py", "_mldsa_cosigned_message"): (1, "a root, no key"),
    ("cli.py", "_build_rp_trust"): (1, "a root, no key"),
    ("cli.py", "_resolve_canonical_root"): (1, "a root, no key"),
    ("cli.py", "_parse_bundled_headers"): (1, "a root, no key"),
    ("evalclaim.py", "_issuer_key_weakness"): (1, "followed by the rule"),
    ("evalclaim.py", "build_eval_claim"): (1, "a root, no key"),
    ("evalclaim.py", "decode_eval_claim"): (1, "a root, no key"),
    ("kbjwt.py", "holder_key_from_cnf"): (1, "reads cnf.jwk; the KB-JWT is checked with verify_ed25519_pinned"),
    ("outcome.py", "pack_key_binds_signer"): (2, "compares the pack's key with the key the receipt was "
                                                 "verified under; writes nothing"),
    ("outcome.py", "verify_outcome_receipt._expected_key"): (1, "reads the pack's key for that comparison"),
    ("persample.py", "audit_challenge"): (1, "a root, no key"),
    ("policy.py", "_validate_pinned_ed25519_pubkey"): (1, "followed by the rule"),
    ("policy.py", "_validate_root_b64"): (1, "a root, no key"),
    ("relation.py", "_keys_equal"): (1, "compares two keys; writes nothing"),
    ("sdjwt_issue.py", "issue_sd_jwt"): (1, "the holder key; followed by the rule since this fix"),
    ("signature.py", "ed25519_trust_anchor_weakness"): (1, "the rule itself"),
    ("signature.py", "verify_ed25519"): (1, "the SPEC 4a verify profile"),
    ("tlogproof.py", "format_tlog_proof"): (1, "a hash, no key"),
    ("tlogproof.py", "parse_tlog_proof"): (1, "a hash, no key"),
}


def _length_32_sites() -> "dict[tuple[str, str], int]":
    """Each `len(...)` compared with the literal 32 under src/, counted per file and function."""
    import ast
    found: "dict[tuple[str, str], int]" = {}
    for path in sorted(_SRC.rglob("*.py")):
        rel = path.relative_to(_SRC).as_posix()

        def walk(node, names):
            for child in ast.iter_child_nodes(node):
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                    walk(child, names + [child.name])
                    continue
                if isinstance(child, ast.Compare):
                    parts = [child.left, *child.comparators]
                    if (any(isinstance(p, ast.Call) and isinstance(p.func, ast.Name) and p.func.id == "len"
                            for p in parts)
                            and any(isinstance(p, ast.Constant) and type(p.value) is int and p.value == 32
                                    for p in parts)):
                        where = (rel, ".".join(names) or "<module>")
                        found[where] = found.get(where, 0) + 1
                walk(child, names)

        walk(ast.parse(path.read_text(encoding="utf-8")), [])
    return found


class ProducersRefuseAKeyNobodyHolds(unittest.TestCase):

    @staticmethod
    def _claim():
        from proofbundle.evalclaim import issuer_fingerprint
        issuer = Ed25519PrivateKey.generate()
        claim = {"passed": True, "threshold": "0.80", "comparator": ">=", "suite": "s",
                 "issuer": issuer_fingerprint(issuer)}
        return issuer, claim, _b64(b"\x11" * 32)

    def test_issue_sd_jwt_binds_no_weak_holder_key(self):
        from proofbundle.sdjwt_issue import issue_sd_jwt
        issuer, claim, root = self._claim()
        for key, reason in WEAK:
            for form in (bytes(key), bytearray(key)):
                with self.subTest(key=key.hex(), form=type(form).__name__):
                    with self.assertRaises(ValueError) as ctx:
                        issue_sd_jwt(claim, issuer, root_b64=root, holder_public_key=form)
                    self.assertIn("holder_public_key", str(ctx.exception))
                    self.assertIn(TRUST_ANCHOR_REFUSAL[reason], str(ctx.exception))

    def test_positive_control_a_real_holder_key_is_bound_and_proves_possession(self):
        from proofbundle.kbjwt import verify_key_binding
        from proofbundle.sdjwt_issue import issue_sd_jwt, present_with_key_binding
        issuer, claim, root = self._claim()
        holder = Ed25519PrivateKey.generate()
        compact = issue_sd_jwt(claim, issuer, root_b64=root, holder_public_key=_raw(holder))
        kb = present_with_key_binding(compact, holder, aud="v", nonce="n", iat=1_780_000_000)
        self.assertIs(verify_key_binding(kb, expected_aud="v", expected_nonce="n")["ok"], True)
        with self.assertRaises(ValueError):
            issue_sd_jwt(claim, issuer, root_b64=root, holder_public_key=b"\x01" * 31)

    def test_no_vkey_is_written_for_a_weak_key(self):
        from proofbundle import checkpoint as cp
        from proofbundle.errors import BundleFormatError
        for key, reason in WEAK:
            for label, write in (("log vkey", cp.vkey), ("witness vkey", cp.cosign_vkey)):
                with self.subTest(key=key.hex(), vkey=label):
                    with self.assertRaises(BundleFormatError) as ctx:
                        write("name", key)
                    self.assertIn(TRUST_ANCHOR_REFUSAL[reason], str(ctx.exception))

    def test_positive_control_a_real_key_gets_its_vkeys_and_they_verify(self):
        from proofbundle import checkpoint as cp
        log, witness = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
        note = cp.sign_checkpoint("example.com/log", 5, b"\x11" * 32, log, "log")
        self.assertIs(cp.verify_checkpoint(note, cp.vkey("log", _raw(log)))["ok"], True)
        note = cp.cosign_checkpoint(note, witness, "w", 1_700_000_000)
        self.assertIs(cp.verify_cosignature(note, cp.cosign_vkey("w", _raw(witness)))["ok"], True)

    def test_the_producers_that_refused_already_still_refuse(self):
        """The rest of the sweep over the producers that write a caller's key: the policy template pins
        issuer keys and the trust pack writes its root keys; both refused every weak key at a4e2fa5c."""
        from proofbundle.policy import PolicyError
        from proofbundle.policy_profiles import instantiate_template
        from proofbundle.trust_pack import TrustPackError, sign_trust_pack
        owner = Ed25519PrivateKey.generate()
        for key, reason in WEAK:
            with self.subTest(key=key.hex(), producer="policy_profiles.instantiate_template"):
                with self.assertRaises(PolicyError) as ctx:
                    instantiate_template("strict-eval-template-v1", issuer_keys=[_b64(key)], policy_id="org/x")
                self.assertIn(TRUST_ANCHOR_REFUSAL[reason], str(ctx.exception))
            with self.subTest(key=key.hex(), producer="trust_pack.sign_trust_pack"):
                pred = {"schemaVersion": "0.1.0", "trustPackId": "tp", "version": 1,
                        "expires": "2099-01-01T00:00:00Z", "prevVersionDigest": None,
                        "roles": {"root": {"keyIds": ["o", "w"], "threshold": 1}},
                        "keys": {"o": {"publicKey": _b64(_raw(owner))}, "w": {"publicKey": _b64(key)}},
                        "nonClaims": ["does not assert the key holders are honest"]}
                with self.assertRaises(TrustPackError) as ctx:
                    sign_trust_pack(pred, {"o": owner})
                self.assertIn(TRUST_ANCHOR_REFUSAL[reason], str(ctx.exception))

    def test_every_length_check_on_32_under_src_is_read_and_named(self):
        """The search question of the finding: a place that checks a key by its length alone carries the
        class. Every such comparison under src/ is listed in `_LENGTH_32` with the reason it is none,
        and the scan and the list must agree in both directions. This scan does not see a length
        compared with a name (`trust_pack`'s `want_len`, followed by the rule there;
        `anchors_chia._hexbytes` with `_HASH_LEN`, a hash) or with 33, a key behind its type
        byte (`checkpoint._parse_vkey` and `checkpoint._parse_witness_vkey`, each followed by
        the rule). A wider scan at 76c900ea (the literals 32, 33, 43 and 44, module names bound
        to them, literal tuples holding them) found those three beside the sites in
        `_LENGTH_32`, and no other."""
        found = _length_32_sites()
        listed = {where: count for where, (count, _why) in _LENGTH_32.items()}
        self.assertEqual({k: v for k, v in found.items() if listed.get(k) != v},
                         {}, "a comparison with 32 that no one has read and named")
        self.assertEqual({k: v for k, v in listed.items() if found.get(k) != v},
                         {}, "a named comparison that is no longer there")


if __name__ == "__main__":
    unittest.main()
