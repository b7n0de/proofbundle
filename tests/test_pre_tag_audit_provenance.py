"""The pre-tag gate derives its verdict from a RECORD, never from prose.

THE CLASS (deep gate wf_cfe249d0-ee8, finding L5-02, P1). The gate granted PASS from a discipline
MARKER minus a NEGATION blocklist. Measured attack: a CHANGELOG line saying the audit had been DROPPED
passed ``--strict`` — "dropped" was not among the ~30 enumerated negations. Enumerating negations does
not terminate against natural language (Ranum; CWE-183 inverted), so every fix of that shape is one more
word and the next phrasing walks through.

This is the SAME shape as L5-01 one file over: there a blocklist of invisible characters, here a
blocklist of negation words. Both were replaced by establishing the property instead of forbidding the
form.

THE INVERSION: one canonical attesting line, matched as a WHOLE line, carrying the version it attests.
Prose cannot move the verdict in EITHER direction — it neither grants a pass nor withholds one.

HONEST LIMIT, stated in the gate too: this is provenance-SHAPED, not provenance. The finding's end state
is a runner-signed record bound to the tag candidate's digest; this repo has no signing path for that
yet. What IS closed is that prose no longer decides.
"""
from __future__ import annotations

import importlib.util
import pathlib
import shutil
import unittest

REPO = pathlib.Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location("_ptag", REPO / "scripts" / "pre_tag_audit_gate.py")
g = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(g)

VERSION = "9.9.9"
TOKEN = "999"
ATTEST = f"pre-tag-adversarial-audit: RUN | version={VERSION}"

# >= 30 ways to say "the audit did not happen", deliberately using vocabulary the old blocklist did NOT
# enumerate. Each MUST fail. The point is not that these 30 are caught — it is that no list was needed.
NEGATIONEN = [
    "the adversarial audit was dropped for this release",
    "six-lens audit: waived by agreement",
    "adversarial review disregarded this cycle",
    "master-prompt audit shelved until after the tag",
    "N-lens pass: outstanding",
    "the adversarial audit remains inconclusive",
    "adversarial audit: superseded by the external review",
    "six lenses: rolled forward to the next release",
    "master-prompt audit was descoped",
    "the adversarial pass lapsed",
    "N-lens audit: moot",
    "adversarial audit forgone",
    "six-lens review: bypassed",
    "the adversarial audit is on hold",
    "master-prompt audit: parked",
    "adversarial audit relegated to post-tag",
    "the six-lens pass was curtailed",
    "N-lens audit: suspended",
    "adversarial review: benched",
    "master-prompt audit sidelined",
    "the adversarial audit lapsed into the next quarter",
    "six-lens coverage: partial at best",
    "adversarial audit: substituted with a smoke test",
    "the master-prompt audit is nominal only",
    "N-lens audit: rubber-stamped",
    "adversarial review happened for a DIFFERENT release",
    "six-lens audit ran against an older tree",
    "master-prompt audit: results discarded",
    "the adversarial audit was rolled back",
    "N-lens pass: void",
    "adversarial audit: assumed",
    "six-lens audit: to be revisited",
]

# Lines that MENTION the vocabulary for unrelated reasons. None attests anything.
IRRELEVANTE_ERWAEHNUNGEN = [
    "refactored the adversarial fixture loader into its own module",
    "renamed six-lens.md to sechs_linsen.md",
    "the master-prompt template gained a new placeholder",
    "docs: explain what an N-lens audit is",
    "test helper `make_adversarial_payload` moved to conftest",
    "CI: cache the adversarial corpus between jobs",
]


def _baum(tmp: pathlib.Path, *, record_text: str | None, changelog_text: str) -> pathlib.Path:
    (tmp / "audit_artifacts" / TOKEN).mkdir(parents=True, exist_ok=True)
    (tmp / "pyproject.toml").write_text(f'version = "{VERSION}"\n', encoding="utf-8")
    (tmp / "CHANGELOG.md").write_text(
        f"## [{VERSION}] - 2026-08-08\n\n{changelog_text}\n", encoding="utf-8")
    if record_text is not None:
        (tmp / "audit_artifacts" / TOKEN / "audit.md").write_text(record_text, encoding="utf-8")
    return tmp


class ProsaEntscheidetNicht(unittest.TestCase):

    def setUp(self):
        self.tmp = pathlib.Path(__import__("tempfile").mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)

    # ── Korpus 1: die Verneinungen ──────────────────────────────────────────────────────────
    def test_keine_verneinung_erteilt_einen_pass(self):
        """Der Angriff des Fundes, ueber 32 Formulierungen statt ueber eine."""
        for satz in NEGATIONEN:
            with self.subTest(satz=satz[:48]):
                # Der Satz steht im CHANGELOG **und** im Beleg — beide Wege muessen scheitern.
                r = g.evaluate(_baum(self.tmp, record_text=f"# audit\n\n{satz}\n", changelog_text=satz),
                               VERSION)
                self.assertFalse(r["ok"], f"{satz!r} hat einen PASS erteilt")

    def test_die_korpusgroesse_ist_nicht_stillschweigend_geschrumpft(self):
        """Der Fund verlangt >= 30 Formulierungen. Ein Korpus, der schrumpft, misst weniger und sagt nichts."""
        self.assertGreaterEqual(len(NEGATIONEN), 30, "der Verneinungs-Korpus ist unter die Vorgabe gefallen")

    # ── Korpus 2: die unbeteiligten Erwaehnungen ────────────────────────────────────────────
    def test_keine_unbeteiligte_erwaehnung_erteilt_einen_pass(self):
        for satz in IRRELEVANTE_ERWAEHNUNGEN:
            with self.subTest(satz=satz[:48]):
                r = g.evaluate(_baum(self.tmp, record_text=f"# notes\n\n{satz}\n", changelog_text=satz),
                               VERSION)
                self.assertFalse(r["ok"], f"{satz!r} hat einen PASS erteilt")

    # ── Der Provenienz-Arm ──────────────────────────────────────────────────────────────────
    def test_ohne_beleg_kein_pass_egal_was_das_changelog_sagt(self):
        """Selbst ein CHANGELOG, das die Attestierung woertlich fuehrt, erteilt nichts."""
        r = g.evaluate(_baum(self.tmp, record_text=None,
                             changelog_text=f"six-lens adversarial audit run.\n{ATTEST}"), VERSION)
        self.assertFalse(r["ok"], "das CHANGELOG hat einen PASS erteilt — es ist praesentational")
        self.assertTrue(r["changelog_is_presentational"])

    def test_ein_beleg_fuer_eine_ANDERE_version_attestiert_diese_nicht(self):
        """Bis hierher genuegte ein markertragender Beleg IM richtigen Ordner. Ein aus einem frueheren
        Release herueberkopierter Beleg attestierte damit das neue, indem er am richtigen Platz lag."""
        r = g.evaluate(_baum(self.tmp,
                             record_text="# audit\n\npre-tag-adversarial-audit: RUN | version=1.2.3\n",
                             changelog_text="six-lens adversarial audit run."), VERSION)
        self.assertFalse(r["ok"], "ein Beleg fuer 1.2.3 hat 9.9.9 attestiert")

    def test_ein_markertragender_beleg_ohne_attestierung_wird_benannt(self):
        """Kein stummes MISSING: der wahrscheinlichste Grund fuer eine ueberraschende Ablehnung steht drin."""
        r = g.evaluate(_baum(self.tmp, record_text="# audit\n\nsix-lens adversarial audit run.\n",
                             changelog_text="nothing here"), VERSION)
        self.assertFalse(r["ok"])
        self.assertTrue(r["marker_only_records"], "der Marker-Beleg wurde nicht benannt")

    # ── Gegenrichtung: der Riegel darf nicht ALLES ablehnen ─────────────────────────────────
    def test_gegenrichtung_ein_echter_beleg_erteilt_den_pass(self):
        r = g.evaluate(_baum(self.tmp, record_text=f"# audit\n\n{ATTEST}\n",
                             changelog_text="nothing about audits here at all"), VERSION)
        self.assertTrue(r["ok"], f"ein echter Beleg wurde abgelehnt: {r['reason']}")
        self.assertEqual(len(r["attesting_records"]), 1)

    def test_gegenrichtung_das_echte_repo_besteht_weiterhin(self):
        """Ohne diese Zeile waere jede Verschaerfung 'erfolgreich' — ein Riegel, der alles ablehnt.

        Gemessen am 2026-08-08: fuer 3.7.0 erteilte die CHANGELOG-Prosa ohnehin keinen Pass
        (changelog_records_audit war bereits False), der Beleg tat es. Die Umkehr blockt also nichts Echtes.
        """
        r = g.evaluate(REPO)
        self.assertTrue(r["ok"], f"das echte Repo wurde ueberblockt: {r['reason']}")
        self.assertTrue(r["attesting_records"], "kein attestierender Beleg im echten Repo")

    def test_die_attestierung_ist_eine_ganze_zeile_kein_teilstring(self):
        """Sonst waere die Allowlist nur eine weitere Substring-Suche und beliebig einbettbar."""
        for bosartig in (f"NOT {ATTEST}",
                         f"we will write '{ATTEST}' once the audit runs",
                         f"<!-- {ATTEST} -->  (placeholder, audit still open)"):
            with self.subTest(form=bosartig[:44]):
                self.assertFalse(
                    g.attests_version(bosartig, VERSION),
                    f"{bosartig!r} wurde als Attestierung gelesen")


if __name__ == "__main__":
    unittest.main()
