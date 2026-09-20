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

import pytest

REPO = pathlib.Path(__file__).resolve().parents[1]


def _im_checkout() -> bool:
    """Repo checkout or an extracted sdist? Read from conftest, the ONE source for it.

    Not rebuilt here: checking the repo-only markers a second time would be a second measuring
    point for the same quantity, and that is the next drift. Without conftest the fallback is the
    observable fact rather than an assumption.
    """
    try:
        from conftest import running_in_repo_checkout  # noqa: PLC0415
    except Exception:                                  # noqa: BLE001
        return any((REPO / m).exists() for m in ("RESTRISIKO_600.md", "audit_artifacts"))
    return running_in_repo_checkout()


# THIS FILE IS SHIPPED AND ITS SUBJECT IS NOT.
#
# MEASURED 2026-09-20 in the hermetic cleanroom, which extracts the sdist to /tmp/sdisttree and
# runs the shipped suite there: both risk sheets and all registers are pruned from the
# distribution, so the scan finds zero promises and the register set is empty. Exactly the two
# anti-vacuous assertions of this file then fire — "0 not greater than 0" and "no register entry
# is readable in this tree" — and they are RIGHT: in that tree the case would pass by measuring
# nothing. What is wrong is the verdict, not the assertion. An absence the distribution creates on
# purpose is N/A, never a failure, and the house already says so one file over.
#
# The guard stays sharp everywhere its subject exists. Only outside a checkout is it skipped, with
# its reason.
if not _im_checkout():
    pytest.skip(
        "nicht ausgeliefert: dieses Modul prueft die Risikoblaetter und die Register, und die "
        "Verteilung enthaelt beide nicht — N/A ausserhalb eines git-Checkouts",
        allow_module_level=True)

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


#: WHERE A PROMISE MAY STAND. Every shipped Markdown document, not the file name that happened to
#: carry the promises when this was written.
#:
#: MEASURED 2026-09-20, repo wide: today there is not one `Register entry` outside the risk
#: sheets, so this widening changes nothing about the current verdict. It closes a reach gap
#: rather than a defect — the same gap a lens found one level over, at the register glob, where a
#: file name stood in for the property. A proposal or a release note can make this promise just as
#: a risk sheet can, and a guard scoped to `RESTRISIKO*` would not have seen it.
#:
#: `audit_artifacts/` is excluded, with its reason: the evidence files there are BYTE COPIES of the
#: promise paragraphs, so scanning them would count every promise a second time at a place that is
#: not its source. The generated views quote identifiers for the same reason. Their source is
#: already scanned, which is where the promise is made.
_BLATT_GLOB = "**/*.md"
_NICHT_BLATT = ("audit_artifacts/",)


def _risikoblaetter(wurzel: pathlib.Path | None = None) -> list[pathlib.Path]:
    w = wurzel or REPO
    return sorted(p for p in w.glob(_BLATT_GLOB)
                  if p.is_file()
                  and not any(str(p.relative_to(w)).startswith(x) for x in _NICHT_BLATT))


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
        # THROUGH THE DECLARED VALIDATION, not past it.
        #
        # A review round measured that `_zusagen_im_blatt` had NO CALLERS while its docstring
        # promised "a malformed token is a finding". The verdict iterated the raw pattern, so a
        # promise for an identifier with one Cyrillic capital, plus a register record carrying
        # that same id, produced an empty finding list. A validation path nobody walks is a
        # sentence, not a check, and this file exists against exactly that substitution.
        #
        # THE REGISTER SIDE IS DELIBERATELY NOT FILTERED BY THE SAME SHAPE, and the reason is
        # measured rather than assumed: real identifiers of line 600 are `N1`, `S5`, `A1`, which
        # are shorter than a promise token may be. Whether a register id is well formed is the
        # producer's own gate (`_kennung_form` in `scripts/gen_findings_register.py`), and it runs
        # there. Refusing the malformed PROMISE closes the attack on its own, because a promise
        # that never becomes a candidate can never be matched against anything.
        offen, missgebildet = [], []
        for blatt in _risikoblaetter():
            gut, schlecht = _zusagen_im_blatt(blatt.read_text(encoding="utf-8", errors="replace"))
            missgebildet += [f"{blatt.name}: {k!r}" for k in schlecht]
            offen += [f"{blatt.name}: {k}" for k in gut if k not in register]
        self.assertEqual(
            missgebildet, [],
            "a promise names a token that is not an identifier of this house, so it can never "
            "resolve and a reader cannot tell why:\n  " + "\n  ".join(missgebildet))
        self.assertEqual(offen, [], "a risk sheet promises a register entry that no register "
                                    "carries:\n  " + "\n  ".join(offen))

    def test_KONTROLLE_das_muster_findet_die_ausgelieferten_zusagen(self):
        """A guard that matches nothing is green for the wrong reason.

        Measured 2026-09-20: the shipped sheets carry five of these promises. The control binds
        that the pattern still SEES them, so a later rewording cannot turn this file into a
        silent no-op -- the failure mode the sheets themselves keep finding elsewhere.
        """
        gefunden = sum(sum(len(x) for x in
                           _zusagen_im_blatt(b.read_text(encoding="utf-8", errors="replace")))
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


    def test_eine_zusage_ausserhalb_der_risikoblaetter_faellt_auf(self):
        """[ZAEHLT] The reach of the scan, measured rather than assumed.

        A promise can be made anywhere prose ships. Before this case the scan was bound to files
        named `RESTRISIKO*`, so a proposal making the same promise would have passed unseen. The
        case builds that exact document in a throwaway tree.
        """
        import tempfile  # noqa: PLC0415
        with tempfile.TemporaryDirectory() as d:
            w = pathlib.Path(d)
            (w / "docs" / "proposals").mkdir(parents=True)
            (w / "docs" / "proposals" / "irgendeine_vorlage.md").write_text(
                "Register entry `NUR-IN-EINER-VORLAGE-VERSPROCHEN-01`.\n", encoding="utf-8")
            gefunden = [k for b in _risikoblaetter(w)
                        for k in _zusagen_im_blatt(b.read_text(encoding="utf-8"))[0]]
            self.assertIn("NUR-IN-EINER-VORLAGE-VERSPROCHEN-01", gefunden,
                          "a promise outside the risk sheets must be seen, otherwise the scope of "
                          "this guard is a file name rather than a property")

    def test_FANG_eine_zusage_mit_fremdem_zeichen_wird_GEMELDET(self):
        """[ZAEHLT] The attack of the review round, as an executable case.

        A promise whose identifier carries one Cyrillic capital, together with a register record
        holding that very id, left the verdict empty before this: the token failed the ASCII shape
        and was therefore never a candidate, so nothing was ever compared. Reported now, which is
        what the validation always claimed to do.
        """
        gut, schlecht = _zusagen_im_blatt("Register entry `\u0410BCDEFGH-01`.\n")
        self.assertEqual(gut, [], "a token with a foreign capital must not count as well formed")
        self.assertEqual(len(schlecht), 1, f"the malformed token is not reported: {schlecht}")
        # The counter-direction in the same case: an ordinary promise still lands in `gut`, so the
        # validation did not become a rule that rejects everything.
        gut2, schlecht2 = _zusagen_im_blatt("Register entry `ABCDEFGH-01`.\n")
        self.assertEqual((gut2, schlecht2), (["ABCDEFGH-01"], []), (gut2, schlecht2))

    def test_KONTROLLE_die_erzeugten_belege_zaehlen_nicht_doppelt(self):
        """[ZAEHLT] The exclusion has a reason, and the reason is checked.

        The evidence files under `audit_artifacts/` are byte copies of the promise paragraphs. If
        they were scanned, every promise would be counted a second time at a place that is not its
        source.
        """
        gescannt = {str(b.relative_to(REPO)) for b in _risikoblaetter()}
        assert not any(p.startswith("audit_artifacts/") for p in gescannt), sorted(gescannt)[:3]


if __name__ == "__main__":
    unittest.main()
