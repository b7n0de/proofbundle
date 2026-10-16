"""The signer interface: bytes in; signature, algorithm and key id out (Z380).

WHAT A PRODUCER OF THIS PACKAGE ASKS OF A SIGNER. Every producer signs through two calls on the object it is
given: ``sign(data) -> bytes`` and ``public_key()``, whose answer gives the raw 32-byte Ed25519 key
(``emit.emit_bundle``, ``evalclaim.issuer_fingerprint``, ``dsse.sign_envelope``, ``checkpoint``,
``sdjwt_issue``, ``intoto`` and the rest). An ``Ed25519PrivateKey`` of ``cryptography`` answers both, and so
does every :class:`Signer` here. :meth:`Signer.sign_bytes` is the same act with its whole answer: the
signature, the algorithm and the key id.

THE KEY FILE STAYS THE DEFAULT. ``proofbundle emit --key FILE`` passes the key ``emit.load_signer`` returns
to the producer, as before; nothing in this module sits in that path. :class:`FileSigner` is the same key
behind the interface, for a caller who wants one type for both kinds of key, and it signs exactly as the
key does, so its receipts are byte-identical to the key's. A key file suits a pipeline that signs without
a person present.

ONE ALGORITHM. The verifier of this package checks receipt signatures as Ed25519, so a signer here signs
Ed25519 and nothing else (:data:`SIGNER_ALGORITHMS`). A key or a token that offers another algorithm is
refused with a clear error before anything is signed, and no signer converts or wraps another algorithm.

A KEY HELD ELSEWHERE. :class:`ExternalSigner` is the interface for a key the process cannot read: a
PKCS#11 token, an HSM, a cloud KMS. A subclass gives the public key and implements ``_sign_external``; the
base checks every signature it returns against that public key before anything uses it, so a token or a
service that answers with a wrong signature, or one made with another key, makes no receipt. This package
ships no KMS provider: the interface is what one would implement.

PKCS#11, OPTIONAL. :class:`Pkcs11Signer` selects a key in a token by a PKCS#11 URI (RFC 7512) and needs the
``[pkcs11]`` extra (python-pkcs11). It suits signatures a person gives on purpose: an audit, an official
release, a record of a sensitive decision. The PIN never stands in a URI, on a command line, in a file or in
a log: it comes from a prompt (:func:`pin_from_prompt`) or from an environment variable the caller names
(:func:`pin_from_env`), and the signer does not keep it after the login. When the token fails (a wrong PIN,
a missing object, a mechanism it lacks, the token gone) the signer raises :class:`SignerError` and nothing
is signed; there is no fallback to a key file.

WHAT A RECEIPT DOES NOT SAY. A receipt carries the public key and the signature. It does not say whether the
key sat in a file or in a token, and a verifier cannot tell: the same key signs the same bytes either way
(Ed25519 is deterministic). That the key lives in hardware is the signer's own statement, never a property
a verifier checks.
"""
from __future__ import annotations

import base64
import os
import re
import stat
from dataclasses import dataclass
from typing import Any, Callable, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from ._membership import is_member
from .canonical import _bytes_von, _draussen, _ein_stand, _puffer_von, _zeichen_von
from .errors import ProofBundleError

__all__ = [
    "SIGNER_ALGORITHMS",
    "SignerError",
    "SignatureRecord",
    "Signer",
    "FileSigner",
    "ExternalSigner",
    "Pkcs11Uri",
    "parse_pkcs11_uri",
    "pin_from_env",
    "pin_from_prompt",
    "Pkcs11Signer",
    "key_id_of",
]

#: The signature algorithms a signer of this package may produce: the ones the verifier checks a receipt
#: signature with. One, today.
SIGNER_ALGORITHMS: Tuple[str, ...] = ("ed25519",)

_NO_FALLBACK = "nothing was signed, and there is no fallback to a key file"


class SignerError(ProofBundleError):
    """A signer refused its configuration or could not sign.

    Its message never carries a PIN, a value of a PKCS#11 URI, the name of the variable that holds a PIN, or
    the text of a token's or a provider's own error (only its type name): each of them can carry what was
    typed in place of something else, and a refusal is printed and logged."""


@dataclass(frozen=True)
class SignatureRecord:
    """The answer of :meth:`Signer.sign_bytes`: the raw signature, the algorithm that made it and the key id
    of the key that made it (:func:`key_id_of`)."""

    signature: bytes
    algorithm: str
    key_id: str


@_ein_stand
def key_id_of(public_key_raw: Any) -> str:
    """The key id of a raw 32-byte Ed25519 public key: ``ed25519:`` and the standard base64 of the key.

    It is the form a receipt names its issuer in (``evalclaim.issuer_fingerprint``), so a key id can be
    pinned as it is (``show-eval --expect-issuer``). A key that no one can hold a secret for gets no key id
    (``signature.ed25519_trust_anchor_weakness``, which also refuses anything but 32 raw bytes): a key id is
    what a relying party pins, and a pin on a low-order key would trust a signature made with no private key."""
    from .signature import TRUST_ANCHOR_REFUSAL, ed25519_trust_anchor_weakness  # noqa: PLC0415
    raw = _bytes_von(public_key_raw)
    weakness = ed25519_trust_anchor_weakness(raw)
    if weakness is not None:
        raise SignerError(f"no key id for a {weakness} Ed25519 public key: {TRUST_ANCHOR_REFUSAL[weakness]}")
    return "ed25519:" + base64.b64encode(raw).decode("ascii")


class _PublicKey:
    """The public half of a key held elsewhere, as the producers of this package read it: ``public_bytes`` with
    ``Encoding.Raw`` and ``PublicFormat.Raw``, and ``public_bytes_raw()``, both the 32 raw bytes. It has no
    ``verify``: a signature under a key this package trusts is checked through
    ``signature.verify_ed25519_pinned`` only, never through a key object's own method."""

    __slots__ = ("_raw",)

    def __init__(self, raw: bytes):
        self._raw = raw

    def public_bytes(self, encoding: Any, format: Any) -> bytes:  # noqa: A002 - the name cryptography uses
        if encoding is not Encoding.Raw or format is not PublicFormat.Raw:
            raise SignerError("the public key of an external signer is given as raw bytes only "
                              "(Encoding.Raw, PublicFormat.Raw)")
        return self._raw

    def public_bytes_raw(self) -> bytes:
        return self._raw


def _data(data: Any) -> bytes:
    """The bytes to sign, read once by what they hold (``canonical._puffer_von``): ``bytes``, ``bytearray``
    or a ``memoryview``."""
    raw = _puffer_von(data)
    if raw is None:
        raise SignerError(f"a signer signs bytes, got {type(data).__name__}")
    return raw


class Signer:
    """The interface: ``sign(data) -> bytes`` and ``public_key()``, which every producer of this package
    calls, and :meth:`sign_bytes`, which gives the signature with its algorithm and key id."""

    #: The algorithm of every signature this signer makes. Always one of :data:`SIGNER_ALGORITHMS`.
    algorithm: str = "ed25519"

    def public_key(self) -> Any:
        """An object whose ``public_bytes(Encoding.Raw, PublicFormat.Raw)`` gives the raw public key."""
        raise NotImplementedError

    def sign(self, data: Any) -> bytes:
        raise NotImplementedError

    def public_key_raw(self) -> bytes:
        """The raw 32-byte public key."""
        return self.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    @property
    def key_id(self) -> str:
        """The key id of the public key (:func:`key_id_of`)."""
        return key_id_of(self.public_key_raw())

    def sign_bytes(self, data: Any) -> SignatureRecord:
        """Sign ``data``: bytes in; signature, algorithm and key id out."""
        raw = _data(data)
        return SignatureRecord(signature=self.sign(raw), algorithm=self.algorithm, key_id=self.key_id)


class FileSigner(Signer):
    """The default kind of key: an Ed25519 key in the process, from a 32-byte raw seed file
    (``emit.load_signer``) or generated. It signs exactly as the key does, and a receipt made through it is
    byte-identical to the receipt the key makes."""

    def __init__(self, key: Ed25519PrivateKey):
        # By the type of the object itself (an identity walk of its class), not `isinstance`, which reads a
        # caller's `__class__`. `cryptography` registers its key class with the abstract one.
        if not issubclass(type(key), Ed25519PrivateKey):
            raise SignerError(f"a file signer holds an Ed25519 private key, got {type(key).__name__}")
        self._key = key

    @classmethod
    @_ein_stand(aussen={"cls": "klasse", "path": "pfad"})
    def load(cls, path: Any) -> "FileSigner":
        """The key of a 32-byte raw seed file, read by ``emit.load_signer``."""
        from .emit import load_signer  # noqa: PLC0415
        return FileSigner(load_signer(path))

    @classmethod
    @_ein_stand(aussen={"cls": "klasse"})
    def generate(cls) -> "FileSigner":
        """A fresh key, generated by ``emit.generate_signer``."""
        from .emit import generate_signer  # noqa: PLC0415
        return FileSigner(generate_signer())

    def public_key(self) -> Any:
        return self._key.public_key()

    def sign(self, data: Any) -> bytes:
        return self._key.sign(_data(data))


class ExternalSigner(Signer):
    """A key held where the process cannot read it: a PKCS#11 token, an HSM, a cloud KMS.

    A subclass passes the raw public key to ``__init__`` and implements ``_sign_external(data) -> bytes``.
    :meth:`sign` checks every signature that comes back against the public key before it returns it, so a
    signature made with another key, a corrupted one or one of the wrong length is refused and never used.
    Any exception of ``_sign_external`` that is no :class:`SignerError` becomes one that names only its type.

    The public key is refused when no one can hold a secret for it (``signature.ed25519_trust_anchor_weakness``):
    under a low-order key a signature made with no private key verifies, so a receipt naming it as issuer
    could be forged by anyone. The algorithm must be one of :data:`SIGNER_ALGORITHMS`.

    This is the interface a KMS adapter would implement; this package ships none."""

    def __init__(self, public_key_raw: Any, *, algorithm: str = "ed25519"):
        from .signature import TRUST_ANCHOR_REFUSAL, ed25519_trust_anchor_weakness  # noqa: PLC0415
        name = _zeichen_von(algorithm)
        if name is None or name not in SIGNER_ALGORITHMS:
            raise SignerError("a signer of this package signs with ed25519 only, the one signature algorithm its "
                              "verifier checks; the algorithm given is not supported")
        raw = _bytes_von(public_key_raw)
        weakness = ed25519_trust_anchor_weakness(raw)   # "malformed" for anything but 32 raw bytes
        if weakness is not None:
            raise SignerError(f"the public key of the signer is {weakness}: {TRUST_ANCHOR_REFUSAL[weakness]}")
        self.algorithm = name
        self._public_raw = raw
        self._public = _PublicKey(raw)

    def public_key(self) -> Any:
        return self._public

    def public_key_raw(self) -> bytes:
        return self._public_raw

    def _sign_external(self, data: bytes) -> bytes:
        """The signature of the key held elsewhere over ``data``. A subclass implements it."""
        raise NotImplementedError("an external signer implements _sign_external")

    def sign(self, data: Any) -> bytes:
        from .signature import verify_ed25519_pinned  # noqa: PLC0415
        raw = _data(data)
        try:
            signature = self._sign_external(raw)
        except SignerError:
            raise
        except Exception as exc:  # noqa: BLE001 - a key held elsewhere fails in its own ways; each is one refusal
            raise SignerError(f"the external signer failed ({type(exc).__name__}); {_NO_FALLBACK}") from None
        signature = _bytes_von(signature)
        if signature is None or len(signature) != 64:
            raise SignerError(f"the external signer returned no 64-byte Ed25519 signature; {_NO_FALLBACK}")
        if not verify_ed25519_pinned(self._public_raw, signature, raw):
            raise SignerError("the signature the external signer returned does not verify under its public key, "
                              f"so it is not used; {_NO_FALLBACK}")
        return signature


# ── the PKCS#11 URI (RFC 7512) ───────────────────────────────────────────────────────────────────────

_ALPHA_DIGIT = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
_UNRESERVED = _ALPHA_DIGIT | frozenset("-._~")                       # RFC 3986 2.3
_RES_AVAIL = frozenset(":[]@!$'()*+,=")                             # RFC 7512 2.3, pk11-res-avail
_PCHAR = _UNRESERVED | _RES_AVAIL | frozenset("&")                  # pk11-pchar without pct-encoded
_QCHAR = _UNRESERVED | _RES_AVAIL | frozenset("/?|")                # pk11-qchar without pct-encoded
_NAME_CHAR = _ALPHA_DIGIT | frozenset("-_")                         # pk11-v-attr-nm-char
_HEX = frozenset("0123456789abcdefABCDEF")

#: The text attributes of the path, each with the size of its field in the PKCS#11 structure it maps to
#: (RFC 7512 2.3: a value the PKCS#11 specification would not accept MUST make the URI invalid). ``object``
#: maps to CKA_LABEL, which has no fixed size.
_PATH_TEXT = {
    "token": 32, "manufacturer": 32, "model": 16, "serial": 16,
    "library-manufacturer": 32, "library-description": 32,
    "slot-manufacturer": 32, "slot-description": 64,
    "object": None,
}
_PATH_ATTRIBUTES = frozenset(_PATH_TEXT) | frozenset({"library-version", "type", "id", "slot-id"})
_TYPES = ("public", "private", "cert", "secret-key", "data")
_DIGITS = re.compile(r"[0-9]+\Z")
_VERSION = re.compile(r"([0-9]+)(?:\.([0-9]+))?\Z")
_ULONG_MAX = (1 << 64) - 1


@dataclass(frozen=True)
class Pkcs11Uri:
    """A PKCS#11 URI as :func:`parse_pkcs11_uri` read it: each path attribute decoded (``None`` when the URI
    does not name it, which RFC 7512 2.5 reads as matching everything), and the one query attribute this
    reader takes, ``module-path``."""

    token: Optional[str] = None
    manufacturer: Optional[str] = None
    model: Optional[str] = None
    serial: Optional[str] = None
    library_manufacturer: Optional[str] = None
    library_description: Optional[str] = None
    library_version: Optional[Tuple[int, int]] = None
    slot_manufacturer: Optional[str] = None
    slot_description: Optional[str] = None
    slot_id: Optional[int] = None
    object: Optional[str] = None
    type: Optional[str] = None
    id: Optional[bytes] = None
    module_path: Optional[str] = None


def _unescape(value: str, allowed: frozenset) -> Optional[bytes]:
    """The octets of a URI value: each ``%HH`` one octet, each allowed character itself. None for a value
    that holds a character outside ``allowed`` or an escape that is not ``%`` and two hex digits."""
    out = bytearray()
    i = 0
    while i < len(value):
        ch = value[i]
        if ch == "%":
            pair = value[i + 1:i + 3]
            if len(pair) != 2 or not all(is_member(c, _HEX) for c in pair):
                return None
            out.append(int(pair, 16))
            i += 3
        elif is_member(ch, allowed):
            out += ch.encode("ascii")
            i += 1
        else:
            return None
    return bytes(out)


def _attributes(part: str, separator: str, where: str) -> list:
    """The ``name=value`` pairs of the path or the query, names checked, values as written."""
    pairs = []
    for item in part.split(separator):
        name, eq, value = item.partition("=")
        if not item or not eq or not name or not all(is_member(c, _NAME_CHAR) for c in name):
            raise SignerError(f"the {where} of the PKCS#11 URI holds an element that is no attribute=value pair "
                              "(an empty element, a trailing separator or a malformed name)")
        pairs.append((name, value))
    return pairs


def _text_value(name: str, value: str) -> str:
    raw = _unescape(value, _PCHAR)
    if raw is None:
        raise SignerError(f"the value of {name} holds a character that must be percent-encoded, or a malformed "
                          "percent-encoding (RFC 7512 2.3)")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise SignerError(f"the value of {name} is not UTF-8 (RFC 7512 2.3)") from None
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in text):
        raise SignerError(f"the value of {name} holds a control character")
    size = _PATH_TEXT[name]
    if size is not None and len(raw) > size:
        raise SignerError(f"the value of {name} is longer than its {size}-byte PKCS#11 field (RFC 7512 2.3)")
    if name == "serial" and not all(0x20 <= b < 0x7F for b in raw):
        raise SignerError("the value of serial is no printable ASCII, as the PKCS#11 serial number is")
    return text


@_ein_stand
def parse_pkcs11_uri(uri: Any) -> Pkcs11Uri:
    """Read a PKCS#11 URI (RFC 7512) that selects a key, strictly.

    Refused, each with :class:`SignerError`: a value that is no text; a scheme other than ``pkcs11:`` (in
    any case, RFC 3986 3.1); any character outside the grammar of RFC 7512 2.3, whitespace and ``#``
    included; a malformed percent-encoding; a text value that is not UTF-8, holds a control character or
    exceeds its PKCS#11 field; a path attribute named twice (2.3, MUST NOT); a ``type``,
    ``library-version`` or ``slot-id`` outside its grammar; a path attribute this reader does not know,
    vendor attributes included (2.5 reads it as matching nothing, so it can never select a key).

    In the query, only ``module-path`` is taken, once, as an absolute path (2.4 says a relative one SHOULD
    be refused). Refused there: ``pin-value`` and ``pin-source``, because a PIN never stands in a URI or a
    file here; ``module-name``, because it names a module to search for, and this reader loads only the
    module the URI names by its path; and any other query attribute. RFC 7512 2.5 says an unrecognised
    query attribute SHOULD be ignored. This reader refuses it instead, so that no part of a URI that
    selects a signing key is silently dropped.

    No refusal repeats a value of the URI or an attribute name it does not know: a URI is often pasted, and
    what was pasted in place of a value can be a PIN."""
    text = _zeichen_von(uri)
    if text is None:
        raise SignerError(f"a PKCS#11 URI is text, got {type(uri).__name__}")
    if text[:7].lower() != "pkcs11:":
        raise SignerError("a PKCS#11 URI begins with 'pkcs11:' (RFC 7512)")
    path, has_query, query = text[7:].partition("?")
    found: dict = {}
    if path:
        for name, value in _attributes(path, ";", "path"):
            if not is_member(name, _PATH_ATTRIBUTES):
                raise SignerError("the PKCS#11 URI names a path attribute this reader does not know (not shown); "
                                  "RFC 7512 2.5 reads it as matching nothing, so no key can be selected")
            if name in found:
                raise SignerError(f"the PKCS#11 URI names {name} twice (RFC 7512 2.3: MUST NOT)")
            if is_member(name, _PATH_TEXT):
                found[name] = _text_value(name, value)
            elif name == "id":
                raw = _unescape(value, _PCHAR)
                if raw is None:
                    raise SignerError("the value of id holds a character that must be percent-encoded, or a "
                                      "malformed percent-encoding (RFC 7512 2.3)")
                found[name] = raw
            elif name == "type":
                if value not in _TYPES:
                    raise SignerError("the value of type is none of public, private, cert, secret-key, data")
                found[name] = value
            elif name == "library-version":
                m = _VERSION.match(value)
                if m is None or int(m.group(1)) > 255 or int(m.group(2) or 0) > 255:
                    raise SignerError("library-version is M or M.N, two decimal numbers of one byte each")
                found[name] = (int(m.group(1)), int(m.group(2) or 0))
            else:   # slot-id
                if _DIGITS.match(value) is None or int(value) > _ULONG_MAX:
                    raise SignerError("slot-id is a decimal number of a CK_SLOT_ID")
                found[name] = int(value)
    module_path = None
    if has_query and query:
        for name, value in _attributes(query, "&", "query"):
            if name in ("pin-value", "pin-source"):
                raise SignerError(f"the PKCS#11 URI carries {name}; a PIN never stands in a URI or a file here: "
                                  "it comes from a prompt or from an environment variable you name")
            if name == "module-name":
                raise SignerError("module-name is not taken: name the module by its absolute path, "
                                  "?module-path=/path/to/module.so")
            if name != "module-path":
                raise SignerError("the PKCS#11 URI names a query attribute this reader does not know (not shown); "
                                  "it is refused rather than ignored, so no part of the URI is dropped")
            if module_path is not None:
                raise SignerError("the PKCS#11 URI names module-path twice (RFC 7512 2.4: MUST NOT)")
            raw = _unescape(value, _QCHAR)
            try:
                path_text = raw.decode("utf-8") if raw is not None else None
            except UnicodeDecodeError:
                path_text = None
            if path_text is None or "\x00" in path_text or not os.path.isabs(path_text):
                raise SignerError("module-path must be an absolute path, well percent-encoded UTF-8 "
                                  "(RFC 7512 2.4: a relative path SHOULD be rejected)")
            module_path = path_text
    return Pkcs11Uri(
        token=found.get("token"), manufacturer=found.get("manufacturer"), model=found.get("model"),
        serial=found.get("serial"), library_manufacturer=found.get("library-manufacturer"),
        library_description=found.get("library-description"), library_version=found.get("library-version"),
        slot_manufacturer=found.get("slot-manufacturer"), slot_description=found.get("slot-description"),
        slot_id=found.get("slot-id"), object=found.get("object"), type=found.get("type"), id=found.get("id"),
        module_path=module_path)


# ── the PIN ───────────────────────────────────────────────────────────────────────────────────────────

_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


@_ein_stand
def pin_from_env(name: Any) -> Callable[[], str]:
    """A PIN source that reads the environment variable ``name`` when the token asks for the PIN.

    ``name`` is the NAME of the variable and must look like one. The variable must be set and not empty
    now, and again when it is read. No refusal shows the name: a PIN typed in place of the name must not
    reach a terminal or a log."""
    text = _zeichen_von(name)
    if text is None or _ENV_NAME.match(text) is None:
        raise SignerError("the PIN is named by an environment variable name ([A-Za-z_][A-Za-z0-9_]*); the "
                          "value given is not one and is not shown, in case it is a PIN")
    unset = ("the environment variable named for the PIN is unset or empty (its name is not shown, in case "
             "a PIN was given in its place)")
    if not os.environ.get(text):
        raise SignerError(unset)

    def read() -> str:
        value = os.environ.get(text)
        if not value:
            raise SignerError(unset)
        return value
    return read


@_ein_stand
def pin_from_prompt(prompt: str = "PKCS#11 user PIN: ") -> Callable[[], str]:
    """A PIN source that asks on the terminal, without echo (``getpass``). Without a terminal it does not
    fall back to reading standard input, where a PIN could come from a pipe or a file: it raises
    :class:`SignerError` and names ``--pin-env``."""
    def ask() -> str:
        import getpass  # noqa: PLC0415
        import warnings  # noqa: PLC0415
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            try:
                value = getpass.getpass(prompt)
            except (getpass.GetPassWarning, EOFError, OSError):
                raise SignerError("there is no terminal to ask for the PIN; name an environment variable that "
                                  "holds it with --pin-env (in the library: pin_from_env)") from None
        if not value:
            raise SignerError("no PIN was entered")
        return value
    return ask


# ── the PKCS#11 signer ────────────────────────────────────────────────────────────────────────────────

#: CKA_EC_PARAMS of an Ed25519 key, in the two forms PKCS#11 3.0 allows for an Edwards curve: the object
#: identifier id-Ed25519 (1.3.101.112, RFC 8410) and the printable string "edwards25519".
_ED25519_PARAMS = frozenset({bytes.fromhex("06032b6570"), b"\x13\x0cedwards25519"})


def _import_pkcs11() -> Any:
    try:
        import pkcs11  # noqa: PLC0415
        import pkcs11.defaults  # noqa: PLC0415
    except ImportError:
        raise SignerError("PKCS#11 signing needs the optional extra: pip install 'proofbundle[pkcs11]' "
                          "(python-pkcs11)") from None
    # The signer calls `key.sign(data)` and lets python-pkcs11 choose the mechanism by the key type; 0.10.0
    # chooses CKM_EDDSA for an Edwards key (`pkcs11/defaults.py`). A version that chose another is refused here,
    # so the mechanism is a checked fact and no second argument names it (an argument there is how an ECDSA call
    # looks, and the package's ECDSA inventory counts every such call).
    if pkcs11.defaults.DEFAULT_SIGN_MECHANISMS.get(pkcs11.KeyType.EC_EDWARDS) != pkcs11.Mechanism.EDDSA:
        raise SignerError("this python-pkcs11 does not sign an Edwards key with CKM_EDDSA by default; the signer "
                          "supports the measured version only (python-pkcs11 0.10.0)")
    return pkcs11


def _module(pkcs11: Any, path: str) -> Any:
    try:
        mode = os.stat(path).st_mode
    except OSError as exc:
        raise SignerError(f"the module named by module-path cannot be read ({type(exc).__name__})") from None
    if not stat.S_ISREG(mode):
        raise SignerError("module-path names no regular file")
    try:
        return pkcs11.lib(path)
    except Exception as exc:  # noqa: BLE001 - loading a foreign module fails in its own ways
        raise SignerError(f"the PKCS#11 module could not be loaded ({type(exc).__name__})") from None


def _text(value: Any) -> Optional[str]:
    """A PKCS#11 string field as python-pkcs11 gives it (``str``, or ``bytes`` for the serial number),
    without the space padding of the field."""
    if isinstance(value, bytes):
        try:
            value = value.decode("ascii")
        except UnicodeDecodeError:
            return None
    return value.rstrip(" ") if isinstance(value, str) else None


def _same(wanted: Any, actual: Any) -> bool:
    return wanted is None or wanted == actual


def _token(pkcs11: Any, lib: Any, sel: Pkcs11Uri) -> Any:
    """The one initialised token that matches the URI. Every slot is read: a slot that cannot be read is an
    error, not a slot to skip, so a second token of the same name cannot hide behind it."""
    if not (_same(sel.library_manufacturer, _text(lib.manufacturer_id))
            and _same(sel.library_description, _text(lib.library_description))
            and _same(sel.library_version, tuple(lib.library_version))):
        raise SignerError("the module named by module-path does not match the URI's library attributes")
    try:
        slots = list(lib.get_slots(token_present=True))
    except pkcs11.exceptions.PKCS11Error as exc:
        raise SignerError(f"the module could not list its slots ({type(exc).__name__}); {_NO_FALLBACK}") from None
    matches = []
    for slot in slots:
        try:
            token = slot.get_token()
            initialised = bool(token.flags & pkcs11.TokenFlag.TOKEN_INITIALIZED)
            fields = (slot.slot_id, _text(slot.slot_description), _text(slot.manufacturer_id), _text(token.label),
                      _text(token.manufacturer_id), _text(token.model), _text(token.serial))
        except pkcs11.exceptions.PKCS11Error as exc:
            raise SignerError(f"a slot of the module could not be read ({type(exc).__name__}); no token is chosen "
                              f"while a slot is unreadable; {_NO_FALLBACK}") from None
        wanted = (sel.slot_id, sel.slot_description, sel.slot_manufacturer, sel.token, sel.manufacturer,
                  sel.model, sel.serial)
        if initialised and all(_same(w, a) for w, a in zip(wanted, fields)):
            matches.append(token)
    if not matches:
        raise SignerError(f"no initialised token matches the URI (it may be absent or removed); {_NO_FALLBACK}")
    if len(matches) > 1:
        raise SignerError("more than one token matches the URI; name the token more precisely (token, serial)")
    return matches[0]


def _mechanism(pkcs11: Any, token: Any) -> None:
    try:
        mechanisms = token.slot.get_mechanisms()
        signs = (pkcs11.Mechanism.EDDSA in mechanisms
                 and pkcs11.MechanismFlag.SIGN in token.slot.get_mechanism_info(pkcs11.Mechanism.EDDSA).flags)
    except pkcs11.exceptions.PKCS11Error as exc:
        raise SignerError(f"the token's mechanisms could not be read ({type(exc).__name__}); {_NO_FALLBACK}") from None
    if not signs:
        raise SignerError("the token offers no CKM_EDDSA signing mechanism; proofbundle signs with Ed25519 only, the "
                          "one algorithm its verifier checks")


_PIN_REFUSALS = {
    "PinIncorrect": "the token refused the PIN (CKR_PIN_INCORRECT)",
    "PinLocked": "the token's user PIN is locked (CKR_PIN_LOCKED)",
    "PinExpired": "the token's user PIN has expired (CKR_PIN_EXPIRED)",
    "PinInvalid": "the token refused the form of the PIN (CKR_PIN_INVALID)",
    "PinLenRange": "the token refused the length of the PIN (CKR_PIN_LEN_RANGE)",
    "UserPinNotInitialized": "the token has no user PIN set (CKR_USER_PIN_NOT_INITIALIZED)",
}


def _login(pkcs11: Any, token: Any, pin: Callable[[], Any]) -> Any:
    with _draussen():   # the PIN source is the caller's code (`canonical._draussen`)
        value = pin()
    # Read once as the exact text or bytes it stores, so no method of a caller's subclass decides the PIN. A PKCS#11
    # PIN is UTF-8 text (CK_UTF8CHAR), and python-pkcs11 0.10.0 takes text only: bytes raised a raw AttributeError
    # in `Token.open` (measured), so bytes are decoded strictly here and anything else is no PIN.
    text = _zeichen_von(value)
    if text is None:
        raw = _bytes_von(value)
        try:
            text = raw.decode("utf-8") if raw is not None else None
        except UnicodeDecodeError:
            text = None
    pin_value = text
    value = raw = None
    if pin_value is None or not pin_value:
        raise SignerError("the PIN source gave no PIN")
    try:
        return token.open(user_pin=pin_value)
    except pkcs11.exceptions.PKCS11Error as exc:
        name = type(exc).__name__
        reason = _PIN_REFUSALS.get(name, f"the token could not open a session ({name})")
        raise SignerError(f"{reason}; {_NO_FALLBACK}") from None
    finally:
        text = pin_value = None


def _private_key(pkcs11: Any, session: Any, sel: Pkcs11Uri) -> Tuple[Any, bytes]:
    """The one private key the URI selects, checked to be an Ed25519 signing key, and its raw public key."""
    Attribute, ObjectClass = pkcs11.Attribute, pkcs11.ObjectClass
    template: dict = {Attribute.CLASS: ObjectClass.PRIVATE_KEY}
    if sel.object is not None:
        template[Attribute.LABEL] = sel.object
    if sel.id is not None:
        template[Attribute.ID] = sel.id
    try:
        keys = list(session.get_objects(template))
        if not keys:
            raise SignerError(f"no private key on the token matches the URI's object and id; {_NO_FALLBACK}")
        if len(keys) > 1:
            raise SignerError("more than one private key matches the URI; name the key with object or id")
        key = keys[0]
        key_type = key[Attribute.KEY_TYPE]
        if key_type != pkcs11.KeyType.EC_EDWARDS:
            raise SignerError(f"the selected key has key type {getattr(key_type, 'name', key_type)}; proofbundle "
                              "signs with Ed25519 only, the one algorithm its verifier checks")
        if not is_member(bytes(key[Attribute.EC_PARAMS]), _ED25519_PARAMS):
            raise SignerError("the selected key is an Edwards key on another curve than Ed25519 (Ed448?); "
                              "proofbundle signs with Ed25519 only, the one algorithm its verifier checks")
        if key[Attribute.SIGN] is not True:
            raise SignerError("the selected key may not sign (CKA_SIGN is false)")
        ckid = bytes(key[Attribute.ID])
        public_template: dict = {Attribute.CLASS: ObjectClass.PUBLIC_KEY, Attribute.KEY_TYPE: pkcs11.KeyType.EC_EDWARDS}
        if ckid:
            public_template[Attribute.ID] = ckid
        else:
            public_template[Attribute.LABEL] = key[Attribute.LABEL]
        publics = list(session.get_objects(public_template))
        if len(publics) != 1:
            raise SignerError(f"the token holds {'no' if not publics else 'more than one'} public key object for "
                              "the selected private key; the signer needs exactly one, to state its key and to "
                              "check each signature")
        if not is_member(bytes(publics[0][Attribute.EC_PARAMS]), _ED25519_PARAMS):
            raise SignerError("the public key object of the selected key is not on Ed25519")
        point = bytes(publics[0][Attribute.EC_POINT])
    except pkcs11.exceptions.PKCS11Error as exc:
        raise SignerError(f"the token could not show the selected key ({type(exc).__name__}); {_NO_FALLBACK}") from None
    if len(point) == 34 and point[:2] == b"\x04\x20":   # DER OCTET STRING of the 32 key bytes (PKCS#11 3.0)
        point = point[2:]
    return key, point   # any other length is refused by ExternalSigner, which takes 32 raw bytes only


class Pkcs11Signer(ExternalSigner):
    """A signer whose Ed25519 key sits in a PKCS#11 token, selected by an RFC 7512 URI (:meth:`open`).

    Each signature is made by the token with CKM_EDDSA and checked against the token's public key before it
    is returned (:class:`ExternalSigner`). A token that fails raises :class:`SignerError`, and nothing is
    signed: there is no fallback to a key file. Close the signer when done (it is a context manager); the
    session ends with the process otherwise."""

    def __init__(self, public_key_raw: bytes, *, _session: Any, _key: Any, _pkcs11: Any):
        super().__init__(public_key_raw)
        self._session = _session
        self._key = _key
        self._pkcs11 = _pkcs11
        self._closed = False

    @classmethod
    @_ein_stand(aussen={"cls": "klasse", "pin": "rueckruf"})
    def open(cls, uri: Any, *, pin: Callable[[], Any]) -> "Pkcs11Signer":
        """Open the token the URI selects, log in with the PIN ``pin()`` gives, and select the one Ed25519
        private key the URI names.

        ``uri`` must name the module with ``module-path`` (:func:`parse_pkcs11_uri`), and it may select only
        private keys (no ``type``, or ``type=private``). ``pin`` is a function that returns the PIN
        (:func:`pin_from_env`, :func:`pin_from_prompt`); it is called once, after the token is found and
        before the key is searched, and the PIN is not kept. Raises :class:`SignerError` for every refusal."""
        sel = parse_pkcs11_uri(uri)
        if sel.type not in (None, "private"):
            raise SignerError(f"the URI selects type={sel.type} objects; a signature needs a private key "
                              "(type=private, or no type)")
        if sel.module_path is None:
            raise SignerError("the URI names no module-path: give the absolute path of the PKCS#11 module, "
                              "e.g. ?module-path=/usr/lib/softhsm/libsofthsm2.so")
        if not callable(pin):
            raise SignerError("pin is a function that returns the PIN (pin_from_env, pin_from_prompt); a PIN "
                              "given as a value would sit in the caller's code or arguments")
        pkcs11 = _import_pkcs11()
        lib = _module(pkcs11, sel.module_path)
        # python-pkcs11 raises more than its own PKCS11Error: a PIN given as bytes ended in a raw AttributeError
        # inside `Token.open` (measured on 0.10.0). Each step below names its own refusals; anything else that
        # comes out of the token dialog, or out of the caller's PIN source, is one refusal that names its type.
        try:
            token = _token(pkcs11, lib, sel)
            _mechanism(pkcs11, token)
            session = _login(pkcs11, token, pin)
        except SignerError:
            raise
        except Exception as exc:  # noqa: BLE001 - see above; the refusal names only the type
            raise SignerError(f"the token could not be opened ({type(exc).__name__}); {_NO_FALLBACK}") from None
        try:
            key, public_raw = _private_key(pkcs11, session, sel)
            return Pkcs11Signer(public_raw, _session=session, _key=key, _pkcs11=pkcs11)
        except BaseException as exc:  # the session is closed on every way out but the return
            try:
                session.close()
            except Exception:  # noqa: BLE001 - the refusal is the error to report
                pass
            if isinstance(exc, SignerError) or not isinstance(exc, Exception):
                raise
            raise SignerError(f"the token could not show the selected key ({type(exc).__name__}); "
                              f"{_NO_FALLBACK}") from None

    def _sign_external(self, data: bytes) -> bytes:
        if self._closed:
            raise SignerError(f"the PKCS#11 signer is closed; {_NO_FALLBACK}")
        try:
            return self._key.sign(data)   # CKM_EDDSA, checked in `_import_pkcs11`
        except self._pkcs11.exceptions.PKCS11Error as exc:
            raise SignerError(f"the token did not sign ({type(exc).__name__}); {_NO_FALLBACK}") from None

    def close(self) -> None:
        """End the session with the token. A closed signer does not sign."""
        if not self._closed:
            self._closed = True
            try:
                self._session.close()
            except Exception:  # noqa: BLE001 - a token already gone has no session to close
                pass

    def __enter__(self) -> "Pkcs11Signer":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()
