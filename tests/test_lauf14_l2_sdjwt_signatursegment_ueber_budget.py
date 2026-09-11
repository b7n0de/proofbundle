"""Lauf 14, Linse L2, F1 (11.09.2026): `verify_sd_jwt` crashte, wenn das SIGNATUR-Segment eines
SD-JWT den input_bytes-Deckel ueberschritt. `_b64url_decode` wirft dann `BundleFormatError` (ein
`ProofBundleError`, KEIN `ValueError`); die Aufrufstelle fing nur `ValueError`. Header und Payload
zwei Bloecke darueber fingen laengst `ProofBundleError` — der Signatur-Aufruf war der Nachbar, den
der Fix von damals nicht erreicht hatte. Dieselbe Ausnahme lief ungefangen durch
`verify_sdjwt_vc`, und `sdjwt_vc` trug eine DRITTE Kopie von `_b64url_decode` ohne Vor-Deckel
(40 MiB wurden dort voll dekodiert, bevor irgendeine Schranke griff).

Vertrag (sdjwt.py, neunmal im Modul): eine dict-zurueckgebende verify-Flaeche liefert IMMER ein
Verdikt, nie einen rohen Crash. Klasse: die except-Klausel folgt der beim Schreiben bekannten
Fehlerquelle statt dem Vertrag der aufgerufenen Funktion.
"""
from __future__ import annotations

import base64
import json

import pytest

from proofbundle import sdjwt, sdjwt_vc
from proofbundle.budget import DEFAULT_BUDGET
from proofbundle.errors import BundleFormatError


def _b64u(obj) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()


def _compact_mit_uebergrossem_signatursegment() -> str:
    header = _b64u({"alg": "EdDSA", "typ": "dc+sd-jwt"})
    payload = _b64u({"sub": "x", "vct": "urn:x"})
    return f"{header}.{payload}." + "A" * (DEFAULT_BUDGET.input_bytes + 10)


def test_verify_sd_jwt_liefert_ein_verdikt_statt_zu_crashen():
    r = sdjwt.verify_sd_jwt(_compact_mit_uebergrossem_signatursegment(), issuer_pubkey=b"\x00" * 32)
    assert r["sig_checked"] is True
    assert r["sig_ok"] is False
    assert "input_bytes" in r["detail"]


def test_verify_sdjwt_vc_liefert_ein_verdikt_statt_zu_crashen():
    r = sdjwt_vc.verify_sdjwt_vc(_compact_mit_uebergrossem_signatursegment(),
                                 {"vctAllowlist": ["urn:x"], "requireKeyBinding": False},
                                 issuer_pubkey=b"\x00" * 32)
    assert r["ok"] is False
    assert r["issuer"] is not None and r["issuer"]["sig_ok"] is False


def test_sdjwt_vc_dekodiert_mit_demselben_gedeckelten_dekoder_wie_sdjwt():
    # EINE Quelle fuer den Vor-Deckel, nicht drei Kopien — und die Schranke greift VOR dem Dekodieren.
    assert sdjwt_vc._b64url_decode is sdjwt._b64url_decode
    with pytest.raises(BundleFormatError):
        sdjwt_vc._b64url_decode("A" * (DEFAULT_BUDGET.input_bytes + 1))


def test_positivkontrolle_eine_bloss_ungueltige_signatur_bleibt_ein_gewoehnliches_verdikt():
    header = _b64u({"alg": "EdDSA"})
    payload = _b64u({"sub": "x"})
    r = sdjwt.verify_sd_jwt(f"{header}.{payload}.AAAA", issuer_pubkey=b"\x00" * 32)
    assert r["sig_checked"] is True and r["sig_ok"] is False
    assert r["detail"] == "0 disclosure(s)"
