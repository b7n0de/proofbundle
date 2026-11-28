"""Base64 (RFC 4648 Section 4, padded) and base64url (Section 5, unpadded), canonical only."""
import base64
import re

_B64 = re.compile(r"\A(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?\Z")
_B64URL = re.compile(r"\A[A-Za-z0-9_-]*\Z")


def std_alphabet_ok(s):
    return bool(_B64.match(s))


def std_decode_canonical(s):
    """Returns (bytes or None, reason). Canonical: re-encoding gives the same string."""
    if not isinstance(s, str) or not _B64.match(s):
        return None, "not base64 alphabet with padding"
    b = base64.b64decode(s, validate=True)
    if base64.b64encode(b).decode("ascii") != s:
        return None, "not the canonical encoding (non-zero padding bits)"
    return b, None


def url_decode_canonical(s):
    """base64url without padding; canonical."""
    if not isinstance(s, str) or not _B64URL.match(s) or len(s) % 4 == 1:
        return None, "not base64url without padding"
    b = base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    if base64.urlsafe_b64encode(b).decode("ascii").rstrip("=") != s:
        return None, "not the canonical encoding"
    return b, None


def std_encode(b):
    return base64.b64encode(b).decode("ascii")


def url_encode(b):
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")
