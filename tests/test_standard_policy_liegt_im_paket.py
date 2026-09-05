"""Die Standard-Policy fuer agent-review liegt IM PAKET — gemessen vom Cleanroom-Tor an PR 185.

WAS DAS TOR FAND (04.09.2026, published-artifact-gate, Schritt "shipped test suite from the
EXTRACTED sdist"): `load_policy()` fiel im frisch installierten Paket mit
`policy not readable: /tmp/clean/lib/python3.12/conformance/agent_review/policies/default_v1.json`.
`standard_policy_path()` rechnete von `__file__` drei Ebenen hinauf zur Repo-Wurzel; installiert
ist drei Ebenen hinauf `lib/python3.12/`. Im Checkout gruen, im Paket rot — die eine Umgebung, die
ein Fremder hat, war die Ausnahme.

Seither liegt die Datei unter `proofbundle/policies/` (package-data) und wird ueber
`importlib.resources` gefunden, wie die uebrigen Policy-Profile. Die Kopie im Korpus bleibt fuer
die Leser der Vektoren und ist byte-gleich; wer eine Seite aendert, aendert beide, sonst gibt es
zwei Digests fuer "dieselbe" Policy.
"""
from __future__ import annotations

import hashlib
import pathlib

from proofbundle import agent_review as ar

REPO = pathlib.Path(__file__).resolve().parents[1]
KORPUS_KOPIE = REPO / "conformance" / "agent_review" / "policies" / "default_v1.json"


def test_die_standard_policy_liegt_im_paketordner_und_nicht_im_repo_baum():
    p = ar.standard_policy_path()
    paket = pathlib.Path(ar.__file__).resolve().parent
    assert p.exists(), f"Standard-Policy fehlt: {p}"
    assert p.resolve().is_relative_to(paket), (
        f"{p} liegt ausserhalb des Pakets {paket} — im installierten Paket gibt es keinen Repo-Baum")
    assert "conformance" not in p.resolve().parts, "der Pfad zeigt in den Korpus, nicht ins Paket"


def test_paketdatei_und_korpuskopie_sind_byte_gleich():
    """EIN Digest. Der Runner meldet `policy_digest` aus der gelesenen Datei; zwei verschiedene
    Bytes unter demselben Namen `agent-review/default` waeren zwei Policies mit einem Etikett."""
    if not KORPUS_KOPIE.is_file():
        import pytest
        pytest.skip("Korpuskopie nicht im Baum (sdist ohne Korpus) — die Paketdatei allein traegt")
    a = ar.standard_policy_path().read_bytes()
    b = KORPUS_KOPIE.read_bytes()
    assert hashlib.sha256(a).hexdigest() == hashlib.sha256(b).hexdigest(), (
        "Paketdatei und Korpuskopie weichen ab — beide Seiten aendern, nicht eine")


def test_load_policy_ohne_argument_liest_das_paket_und_nennt_seinen_digest():
    d = ar.load_policy()
    assert d.get("name") == ar.STANDARD_POLICY_NAME
    assert str(d.get("_digest", "")).startswith("sha256:")
    assert pathlib.Path(d["_path"]).resolve() == ar.standard_policy_path().resolve()


def test_fangnachweis_ein_pfad_aus_der_repo_wurzel_faellt_im_paket(monkeypatch, tmp_path):
    """Der Mutant ist die alte Rechnung. Aus einem Ort ohne Repo-Baum aufgerufen — hier ein leerer
    Ordner als 'Installationsort' — findet sie nichts; die Paketaufloesung findet die Datei."""
    alt = tmp_path / "lib" / "python3.12" / "site-packages" / "proofbundle" / "agent_review.py"
    alt.parent.mkdir(parents=True)
    alter_pfad = alt.resolve().parents[2] / "conformance" / "agent_review" / "policies" / "default_v1.json"
    assert not alter_pfad.exists(), "die alte Rechnung darf im Paket nichts finden"
    assert ar.standard_policy_path().exists()
