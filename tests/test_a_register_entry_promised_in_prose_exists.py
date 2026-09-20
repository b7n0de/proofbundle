"""A risk sheet that says "Register entry X" must be able to point at an X that exists.

MEASURED 2026-09-20 against `ba29df8`: five such promises are made across the shipped risk sheets
and NONE of the five names an identifier any register carries. Four of them arrived with the 6.1.0
cut; the fifth has been in `RESTRISIKO_600.md` since before it, so the class is older than the cut
that made it visible.

The promise and the artefact are written by different steps -- the prose by hand, the register by
`scripts/gen_findings_register.py` -- and nothing compared them. A sentence that names a register
entry reads like a reference and costs nothing to write, so it is the cheapest possible place for a
claim to detach from what backs it. That is the defect class this file exists for, not the five
instances: the instances get fixed by generating the entries, the class gets fixed by making the
prose unable to promise something absent.

WHAT THIS DOES NOT CLAIM. It does not check that the register entry SAYS the right thing, only that
the identifier exists. A register line whose target version or state is wrong passes here and is
caught by the audit matrix, which is a different instrument with a different question.
"""
from __future__ import annotations

import json
import pathlib
import re
import unittest

REPO = pathlib.Path(__file__).resolve().parents[1]

#: The prose form, measured rather than assumed: `Register entry` followed by a backticked token,
#: with an optional colon and any run of whitespace between them -- the sentence wraps across lines
#: in every shipped occurrence, so a line-wise pattern would find none of them.
#:
#: THE TOKEN IS CAPTURED WITHOUT JUDGING ITS ALPHABET, and that is a repair. The first version
#: asked for `[A-Z0-9][A-Z0-9-]{8,}`, an ASCII class that `re` does not widen to Unicode. An
#: adversarial lens measured the consequence on 2026-09-20: one Cyrillic А (U+0410) at the front
#: of an identifier makes the promise INVISIBLE to this guard -- not unbacked, not reported,
#: simply absent from the candidate set, while a human reading the rendered Markdown sees a
#: perfectly ordinary promise. A guard that judges the alphabet before it judges the promise can
#: be silenced by a character nobody can see.
#:
#: So the pattern takes the token as it stands, and the check for what a well formed identifier
#: looks like happens AFTERWARDS, where a violation becomes a FINDING instead of a blind spot.
_ZUSAGE = re.compile(r"Register entry[:\s]+`([^`\s]{8,})`")

#: What an identifier of this house looks like: ASCII capitals, digits and hyphens. A token that
#: fails this is not silently dropped, it is reported -- see `_zusagen_im_blatt`.
_KENNUNG_ASCII = re.compile(r"\A[A-Z0-9][A-Z0-9-]{7,}\Z")

#: Where an identifier may live. Every shipped register counts: an entry is present or it is not,
#: and which file carries it is not what the prose promises.
#:
#: FOUND BY GLOB, NOT BY A LIST. The first version named two files. A register line added later --
#: and one was, `audit_artifacts/610/`, on the same day -- would not have been read, and the guard
#: would have reported a promise as unbacked while its entry sat in a file the tuple did not name.
#: A contract that hangs on a spelling loses its reach the moment the thing it guards is extended.
_REGISTER_GLOB = "audit_artifacts/**/findings_register*.json"


def _risikoblaetter(wurzel: pathlib.Path | None = None) -> list[pathlib.Path]:
    return sorted(p for p in (wurzel or REPO).glob("RESTRISIKO*.md") if p.is_file())


#: The schema values a real register carries. A file is a register because it SAYS SO in the form
#: the producer writes, not because its name matches a pattern.
#:
#: MEASURED 2026-09-20 by an adversarial lens: a hand written
#: `audit_artifacts/x/findings_register_backup.json` with one invented entry turned this guard
#: fully green for a promise nothing backs. The glob was chosen for reach, and reach without a
#: property check means any file that imitates a name is believed. That is the same substitution
#: this file was written against, one level up: a token standing in for the property.
_REGISTER_SCHEMATA = ("proofbundle.findings_register.v1", "proofbundle.findings_register.v2")


def _register_dateien(wurzel: pathlib.Path | None = None) -> list[pathlib.Path]:
    w = wurzel or REPO
    return sorted({*w.glob(_REGISTER_GLOB), *w.glob("audit_artifacts/findings_register*.json")})


def _zusagen_im_blatt(text: str) -> tuple[list[str], list[str]]:
    """(well formed identifiers, malformed ones). A malformed token is a finding, not a gap."""
    gut, schlecht = [], []
    for roh in _ZUSAGE.findall(text):
        (gut if _KENNUNG_ASCII.match(roh) else schlecht).append(roh)
    return gut, schlecht


def _register_kennungen(wurzel: pathlib.Path | None = None) -> set[str]:
    """The identifiers the registers actually CARRY, read from the entries, not from the file text.

    MEASURED 2026-09-20, against the first version of this file: a single prose note added to a
    register, naming all five identifiers and creating no entry at all, turned this guard GREEN.
    It asked whether a string OCCURS in the file, and the promise it is meant to protect is that an
    ENTRY EXISTS. That is the same defect class the guard was written against, one level up -- the
    presence of a token standing in for the property it is supposed to prove.

    The identity of an entry lives in its `id`, under `findings` in the 361 register and under
    `records` in the v2 register. Anything outside those lists is prose and does not count, however
    convincingly it spells a name.
    """
    kennungen: set[str] = set()
    for p in _register_dateien(wurzel):
        if not p.is_file():
            continue
        try:
            d = json.loads(p.read_text(encoding="utf-8", errors="replace"))
        except ValueError:
            continue
        if not isinstance(d, dict):
            continue
        if d.get("schema") not in _REGISTER_SCHEMATA:
            continue                      # a file that only carries the NAME of a register
        for feld in ("findings", "records"):
            for eintrag in d.get(feld) or ():
                if isinstance(eintrag, dict) and isinstance(eintrag.get("id"), str):
                    kennungen.add(eintrag["id"])
    return kennungen


class EineRegisterzusageHatEinenTraeger(unittest.TestCase):

    def test_jede_zusage_nennt_eine_kennung_die_es_gibt(self):
        """[ZAEHLT] Every `Register entry X` in a shipped risk sheet resolves to a real X."""
        register = _register_kennungen()
        self.assertTrue(register,
                        "no register entry is readable in this tree, so this case would pass by "
                        "measuring nothing")
        offen = []
        for blatt in _risikoblaetter():
            for kennung in _ZUSAGE.findall(blatt.read_text(encoding="utf-8", errors="replace")):
                if kennung not in register:
                    offen.append(f"{blatt.name}: {kennung}")
        self.assertEqual(offen, [], "a risk sheet promises a register entry that no register "
                                    "carries:\n  " + "\n  ".join(offen))

    def test_KONTROLLE_das_muster_findet_die_ausgelieferten_zusagen(self):
        """A guard that matches nothing is green for the wrong reason.

        Measured 2026-09-20: the shipped sheets carry five of these promises. The control binds
        that the pattern still SEES them, so a later rewording cannot turn this file into a
        silent no-op -- the failure mode the sheets themselves keep finding elsewhere.
        """
        gefunden = sum(len(_ZUSAGE.findall(b.read_text(encoding="utf-8", errors="replace")))
                       for b in _risikoblaetter())
        self.assertGreater(gefunden, 0,
                           "the pattern matches no promise at all, so the case above proves "
                           "nothing about any tree")

    def test_KONTROLLE_eine_prosanotiz_im_register_traegt_keine_zusage(self):
        """[ZAEHLT] The guard must reject a register that only NAMES the identifiers in prose.

        This is the attack that broke the first version of this file, kept as an executable case
        rather than as a sentence about it. A register carrying a note that spells all the promised
        identifiers, and not a single entry, turned the guard green -- because it asked whether a
        string occurs rather than whether an entry exists.
        """
        import tempfile  # noqa: PLC0415
        with tempfile.TemporaryDirectory() as d:
            w = pathlib.Path(d)
            (w / "audit_artifacts").mkdir()
            (w / "RESTRISIKO_PROBE.md").write_text(
                "Register entry `ERFUNDENE-KENNUNG-FUER-DIE-PROBE-01`.\n", encoding="utf-8")
            (w / "audit_artifacts" / "findings_register_probe.json").write_text(
                json.dumps({"schema": "proofbundle.findings_register.v2", "records": [],
                            "note": "covers ERFUNDENE-KENNUNG-FUER-DIE-PROBE-01"}),
                encoding="utf-8")
            self.assertEqual(
                _register_kennungen(w), set(),
                "a prose note is not an entry; if this set is non-empty the guard is back to "
                "measuring the presence of a token")
            # And the other direction in the same probe: a REAL entry is seen.
            (w / "audit_artifacts" / "findings_register_probe.json").write_text(
                json.dumps({"schema": "proofbundle.findings_register.v2",
                            "records": [{"id": "ERFUNDENE-KENNUNG-FUER-DIE-PROBE-01"}]}),
                encoding="utf-8")
            self.assertEqual(_register_kennungen(w), {"ERFUNDENE-KENNUNG-FUER-DIE-PROBE-01"},
                             "a real entry must be seen, otherwise the case above is green "
                             "because the reader is broken rather than because the attack fails")
            # THE THIRD DIRECTION, measured by a lens on 2026-09-20: a file carrying only the
            # NAME of a register was authoritative. Now it has to say what it is.
            (w / "audit_artifacts" / "findings_register_probe.json").write_text(
                json.dumps({"records": [{"id": "ERFUNDENE-KENNUNG-FUER-DIE-PROBE-01"}]}),
                encoding="utf-8")
            self.assertEqual(
                _register_kennungen(w), set(),
                "a file that only carries the NAME of a register must not be authoritative")


if __name__ == "__main__":
    unittest.main()
