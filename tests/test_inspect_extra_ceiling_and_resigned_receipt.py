"""The inspect_ai ceiling is one number, and INTEGRATIONS.md says what verify does with a re-signed receipt.

Finding B32 (2026-11-09). INTEGRATIONS.md named the `inspect` extra's ceiling, and the ceiling stands twice more in
pyproject.toml, in the `inspect` extra and in the `dev` extra; nothing held the three equal, and a bump that moves one
leaves the others behind. The ceiling must also be the version the newest "THE MEASURED BUMP" paragraph of
pyproject.toml names as its target, because what is admitted is what was measured.

INTEGRATIONS.md also did not say that `proofbundle verify` accepts a receipt someone changed and signed again with
their own key: verify checks the signature against the key the receipt carries, not against a key the reader trusts.
Measured at 6b63cda8: a claim changed and signed with a fresh key gives `verify` exit 0 and
`show-eval --expect-issuer <original issuer>` exit 1. The doc now says so, and the round trip below holds the code to it.
"""
from __future__ import annotations

import contextlib
import io
import json
import re
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
FIXTURE = REPO / "tests" / "fixtures" / "lm_eval_arc_easy_real.json"
_PIN = re.compile(r"inspect_ai>=0\.3\.112,<=(0\.3\.\d+)")
_BUMP = re.compile(r"THE MEASURED BUMP (0\.3\.\d+) -> (0\.3\.\d+)")


def _section(text: str, heading: str) -> str:
    start = text.index(heading)
    nxt = text.find("\n## ", start + len(heading))
    return text[start:] if nxt < 0 else text[start:nxt]


def _ceilings() -> dict:
    py = (REPO / "pyproject.toml").read_text(encoding="utf-8")
    inspect_line = next(line for line in py.splitlines() if line.startswith("inspect = "))
    dev_block = py[py.index("\ndev = ["):]
    dev_block = dev_block[:dev_block.index("]") + 1]
    integrations = _section((REPO / "INTEGRATIONS.md").read_text(encoding="utf-8"), "## inspect_ai")
    found = {}
    for name, text in (("pyproject inspect", inspect_line), ("pyproject dev", dev_block),
                       ("INTEGRATIONS.md", integrations)):
        pins = _PIN.findall(text)
        assert len(pins) == 1, (name, pins)
        found[name] = pins[0]
    return found


def test_the_three_places_name_one_ceiling():
    ceilings = _ceilings()
    assert len(set(ceilings.values())) == 1, ceilings


#: An upper bound of inspect_ai in a line, as the pin writes it (`<=0.3.N`) or as prose says it (`up to 0.3.N`).
_STATED = re.compile(r"inspect_ai\b[^\n]*?(?:<=|up to )(0\.3\.\d+)")


def test_every_current_page_that_states_the_ceiling_states_the_same_one():
    """The entry page docs/INSPECT_HAPPY_PATH.md said "up to 0.3.281" when the ceiling had moved to 0.3.288
    (2026-11-10): it states the ceiling in prose, which `_PIN` does not read, so the three places above stayed equal
    while a fourth fell behind. Every page in the root and under docs/ that names an upper bound of inspect_ai must
    name the ceiling of pyproject.toml. CHANGELOG.md, docs/archive/ and docs/release_scope/ record what was true when
    they were written and are left out."""
    ceiling = _ceilings()["pyproject inspect"]
    docs = REPO / "docs"
    pages = sorted(REPO.glob("*.md")) + sorted(
        p for p in docs.rglob("*.md") if p.relative_to(docs).parts[0] not in ("archive", "release_scope"))
    found = {}
    for page in pages:
        if page.name == "CHANGELOG.md":
            continue
        for number, line in enumerate(page.read_text(encoding="utf-8").splitlines(), 1):
            for m in _STATED.finditer(line):
                found[f"{page.relative_to(REPO).as_posix()}:{number}"] = m.group(1)
    assert any(k.startswith("docs/INSPECT_HAPPY_PATH.md:") for k in found), found
    assert any(k.startswith("INTEGRATIONS.md:") for k in found), found
    assert {k: v for k, v in found.items() if v != ceiling} == {}, (ceiling, found)


def test_the_ceiling_is_the_target_of_the_newest_measured_bump():
    bumps = _BUMP.findall((REPO / "pyproject.toml").read_text(encoding="utf-8"))
    assert bumps, "pyproject.toml carries no measured bump of inspect_ai"
    newest = max(bumps, key=lambda b: tuple(int(p) for p in b[1].split(".")))[1]
    assert set(_ceilings().values()) == {newest}, (_ceilings(), newest)


def test_integrations_says_verify_accepts_a_re_signed_receipt_and_names_the_pin():
    section = _section((REPO / "INTEGRATIONS.md").read_text(encoding="utf-8"), "## inspect_ai")
    flat = " ".join(section.split())
    satz = [s for s in re.split(r"(?<=\.)\s", flat) if "re-signed" in s]
    assert len(satz) == 1, satz
    assert "`proofbundle verify`" in satz[0], satz
    assert "--expect-issuer" in satz[0], satz
    # Codex pre-review 1 of B32: the signature covers the signed payload, not the receipt's Merkle wrapper, which a
    # coherent root rewrap changes without a key (THREAT_MODEL.md). The sentence names what is signed and claims no
    # unchanged receipt.
    assert "signed payload" in satz[0], satz
    assert "unchanged" not in satz[0], satz


def _run(argv):
    from proofbundle.cli import main
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        return main(argv)


def test_the_sentence_holds_verify_passes_a_re_signed_receipt_and_the_pin_refuses_it(tmp_path):
    from proofbundle.adapters import from_lm_eval_results
    from proofbundle.emit import generate_signer
    from proofbundle.evalclaim import decode_eval_claim, emit_eval_receipt

    claim, _ = from_lm_eval_results(FIXTURE, "arc_easy", "acc", comparator=">=", threshold="0.30",
                                    timestamp="2026-07-01T12:00:00Z")
    original = emit_eval_receipt(claim, generate_signer())
    issuer = decode_eval_claim(original)["issuer"]
    changed = {k: v for k, v in decode_eval_claim(original).items() if k != "issuer"}
    changed["threshold"] = "0.10"
    resigned = emit_eval_receipt(changed, generate_signer())
    assert decode_eval_claim(resigned)["issuer"] != issuer

    orig_path, resigned_path = tmp_path / "orig.json", tmp_path / "resigned.json"
    orig_path.write_text(json.dumps(original), encoding="utf-8")
    resigned_path.write_text(json.dumps(resigned), encoding="utf-8")

    assert _run(["verify", str(resigned_path)]) == 0
    assert _run(["show-eval", str(resigned_path), "--expect-issuer", issuer]) == 1
    assert _run(["show-eval", str(orig_path), "--expect-issuer", issuer]) == 0
