"""The shard partition and the CLI contract of mutation_check.

Both defects these tests cover were found by CI, not by me, and both are the same class: a new
parameter that quietly changed an existing contract.

1. ``main()`` called with no arguments passed ``None`` to ``parse_args``, and argparse reads
   ``sys.argv`` for ``None`` -- under pytest, that is pytest's own flags, and the run died with
   ``SystemExit(2)``. ``parse_args(None)`` is not ``parse_args([])``.
2. The sharded call passed ``shard=`` unconditionally, which broke the test stubs that replace
   ``_run_operators`` with a function that has no such parameter.
"""
from __future__ import annotations

import importlib.util
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("_mc", ROOT / "scripts" / "mutation_check.py")
mc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mc)


class ThePartitionIsGaplessAndDeterministic(unittest.TestCase):
    def test_every_operator_lands_in_exactly_one_shard(self):
        n = len(mc.MUTATIONS)
        for k in (1, 2, 3, 8, 10, 16, n):
            parts = [set(mc.partition(n, i, k)) for i in range(1, k + 1)]
            union = set().union(*parts)
            self.assertEqual(union, set(range(n)), f"K={k}: the union has a gap")
            self.assertEqual(sum(len(p) for p in parts), n, f"K={k}: shards overlap")

    def test_the_same_arguments_give_the_same_shard(self):
        self.assertEqual(mc.partition(88, 3, 10), mc.partition(88, 3, 10))

    def test_shards_are_balanced_within_one(self):
        sizes = [len(mc.partition(88, i, 10)) for i in range(1, 11)]
        self.assertLessEqual(max(sizes) - min(sizes), 1, f"unbalanced: {sizes}")

    def test_round_robin_not_blockwise(self):
        """Operators are grouped by file; a block would hand one shard every expensive one."""
        first = mc.partition(88, 1, 10)
        self.assertNotEqual(first, list(range(len(first))), "this looks blockwise, not round-robin")

    def test_an_index_outside_the_range_is_refused(self):
        for i, k in ((0, 10), (11, 10), (-1, 10)):
            with self.assertRaises(ValueError):
                mc.partition(88, i, k)

    def test_k_equal_to_n_gives_one_operator_each(self):
        n = len(mc.MUTATIONS)
        self.assertTrue(all(len(mc.partition(n, i, n)) == 1 for i in range(1, n + 1)))


class TheCliContractHolds(unittest.TestCase):
    def test_main_with_no_arguments_does_not_read_sys_argv(self):
        """The defect CI found: parse_args(None) reads sys.argv, which under pytest is its flags."""
        gerufen = {}

        def stub(work):
            gerufen["shard"] = "not passed"
            return 0

        echt_run, echt_prep, echt_status = mc._run_operators, mc._prepare_workdir, mc._worktree_status
        mc._run_operators = stub
        mc._prepare_workdir = lambda root, work: None
        mc._worktree_status = lambda root: ""
        alt_argv = sys.argv
        sys.argv = ["pytest", "-q", "--tb=short", "tests/"]
        try:
            rc = mc.main()
        finally:
            sys.argv = alt_argv
            mc._run_operators, mc._prepare_workdir, mc._worktree_status = echt_run, echt_prep, echt_status
        self.assertEqual(rc, 0)
        self.assertEqual(gerufen["shard"], "not passed")

    def test_the_unsharded_call_keeps_the_old_signature(self):
        """A stub without a shard parameter must still work; that is the existing contract."""
        echt_run, echt_prep, echt_status = mc._run_operators, mc._prepare_workdir, mc._worktree_status
        mc._run_operators = lambda work: 0
        mc._prepare_workdir = lambda root, work: None
        mc._worktree_status = lambda root: ""
        try:
            self.assertEqual(mc.main([]), 0)
        finally:
            mc._run_operators, mc._prepare_workdir, mc._worktree_status = echt_run, echt_prep, echt_status

    def test_a_malformed_shard_argument_is_refused(self):
        for bad in ("1", "1/", "/10", "a/b", "0/10", "11/10"):
            with self.assertRaises(SystemExit, msg=f"--shard {bad} should be refused"):
                mc.main(["--shard", bad])


if __name__ == "__main__":
    unittest.main()


# ── Stufe 2 Teil B: die gewichtete Partition ──────────────────────────────────────────────────

class GewichtetePartition(unittest.TestCase):
    """Die Wanduhr haengt am LAENGSTEN Shard, nicht am Mittel.

    Gemessen am 02.09.2026 lagen die zehn Shards zwischen 931 s und 1232 s bei einem Mittel von
    1116 s. Die Spanne von 301 s ist genau der Verlust, den eine gleichmaessigere Verteilung
    zurueckholt — und mehr Shards helfen dagegen wenig, solange ein einzelner teurer Operator
    einen Shard traegt.
    """

    LABELS = [f"op-{i:02d}" for i in range(88)]
    # Ein realistisch schiefes Profil: wenige teure, viele billige.
    GEWICHTE = {f"op-{i:02d}": (90.0 if i % 7 == 0 else 10.0) for i in range(88)}

    def _teile(self, k=10, gewichte=None):
        return [mc.partition_gewichtet(self.LABELS, i, k,
                                                   self.GEWICHTE if gewichte is None else gewichte)
                for i in range(1, k + 1)]

    def _lasten(self, teile, gewichte=None):
        g = self.GEWICHTE if gewichte is None else gewichte
        return [sum(g.get(self.LABELS[x], 0.0) for x in t) for t in teile]

    def test_die_vereinigung_ist_lueckenlos(self):
        alle = sorted(x for t in self._teile() for x in t)
        self.assertEqual(alle, list(range(88)))

    def test_kein_operator_doppelt(self):
        alle = [x for t in self._teile() for x in t]
        self.assertEqual(len(alle), len(set(alle)))

    def test_SIE_BALANCIERT_BESSER_ALS_ROUND_ROBIN(self):
        """Die Gegenprobe, und ohne sie waere der ganze Einbau Schmuck: balanciert LPT nicht
        besser, ist die zusaetzliche Gewichtsdatei reine Komplexitaet."""
        lpt = self._lasten(self._teile())
        rr = self._lasten([mc.partition(88, i, 10) for i in range(1, 11)])
        self.assertLess(max(lpt) - min(lpt), max(rr) - min(rr))

    def test_deterministisch(self):
        self.assertEqual(self._teile(), self._teile())

    def test_gleichstand_wird_nach_namen_gebrochen_nicht_nach_eingabereihenfolge(self):
        """Die Eingabereihenfolge haengt an der Datei-Sortierung und aendert sich beim naechsten
        Operator — eine Partition, die daran haengt, ist nicht reproduzierbar."""
        gleich = {lab: 5.0 for lab in self.LABELS}
        a = self._teile(gewichte=gleich)
        gedreht = list(reversed(self.LABELS))
        b = [mc.partition_gewichtet(gedreht, i, 10, gleich) for i in range(1, 11)]
        # Dieselben LABELS je Shard, unabhaengig von der Eingabereihenfolge.
        self.assertEqual(sorted(sorted(self.LABELS[x] for x in t) for t in a),
                         sorted(sorted(gedreht[x] for x in t) for t in b))

    def test_ein_unbekannter_operator_bekommt_das_MEDIAN_gewicht(self):
        """Nicht 0 (er waere gratis und ueberlaedt den letzten Shard) und nicht das Maximum
        (er blockiert einen Shard fuer sich allein)."""
        luecke = {lab: v for lab, v in self.GEWICHTE.items() if lab != "op-05"}
        teile = self._teile(gewichte=luecke)
        alle = sorted(x for t in teile for x in t)
        self.assertEqual(alle, list(range(88)))

    def test_ungueltiger_shard_index_wirft(self):
        with self.assertRaises(ValueError):
            mc.partition_gewichtet(self.LABELS, 0, 10, self.GEWICHTE)
        with self.assertRaises(ValueError):
            mc.partition_gewichtet(self.LABELS, 11, 10, self.GEWICHTE)


class DerRueckfallIstLAUT(unittest.TestCase):
    """Ein stiller Rueckfall auf Round-Robin saehe wie eine gewichtete Partition aus."""

    def test_fehlende_datei_gibt_leere_gewichte_und_einen_grund(self):
        g, grund = mc.lade_gewichte(Path("/nirgends/gewichte.json"))
        self.assertEqual(g, {})
        self.assertIn("Round-Robin", grund)

    def test_kaputte_datei_nennt_den_defekt_und_faellt_zurueck(self):
        import tempfile
        d = Path(tempfile.mkdtemp()) / "w.json"
        d.write_text("{kaputt")
        g, grund = mc.lade_gewichte(d)
        self.assertEqual(g, {})
        self.assertIn("unbrauchbar", grund)

    def test_leere_sekunden_sind_kein_gewicht(self):
        import tempfile
        d = Path(tempfile.mkdtemp()) / "w.json"
        d.write_text('{"sekunden": {}}')
        self.assertEqual(mc.lade_gewichte(d)[0], {})


class DieGemeldeteZahlIstDieGEFAHRENEMenge(unittest.TestCase):
    """Beim Volllesen fuer den Fix an `_rote_aus_text` gefunden (2026-09-07), dieselbe Klasse eine
    Stufe weiter: eine Groesse wird NEU BERECHNET statt GEMESSEN.

    Die Schlusszeile nannte `len(partition(len(MUTATIONS), *shard))` — IMMER round-robin —, waehrend
    der Lauf laengst `partition_gewichtet(...)` faehrt. Zwei Rechnungen ueber dieselbe Frage, und nur
    eine davon war die gefahrene. Heute faellt es nicht auf: 100 Operatoren auf 10 Shards gehen in
    beiden Verfahren glatt auf (gemessen ueber alle zehn Shards: 10/10 in beiden). Der Kommentar an
    der Schlusszeile warnt woertlich vor dem Fall ("ein Shard, der 88 operators meldet, obwohl er elf
    gefahren hat, macht die Summenpruefung des Sammel-Jobs wertlos") — die Rechnung darunter konnte
    ihn nicht einhalten, und die Summenpruefung ginge trotzdem auf, weil sie dieselbe falsche Zahl
    addiert.
    """

    def test_die_schlusszeile_nennt_die_menge_des_laufs_und_nicht_eine_zweite_rechnung(self):
        """DER FANGNACHWEIS. Beide Stellen muessen aus DERSELBEN Quelle lesen; wird die Quelle
        ersetzt, muss sich auch die gemeldete Zahl bewegen."""
        gemeldet = {}
        echt = (mc._run_operators, mc._prepare_workdir, mc._worktree_status,
                mc._indizes_des_laufs, __builtins__["print"] if isinstance(__builtins__, dict)
                else __builtins__.print)
        mc._run_operators = lambda work, **kw: 0
        mc._prepare_workdir = lambda root, work: None
        mc._worktree_status = lambda root: ""
        mc._indizes_des_laufs = lambda shard: [0, 1, 2]          # DREI Operatoren, nicht zehn
        import builtins
        builtins.print = lambda *a, **k: gemeldet.setdefault("zeilen", []).append(" ".join(map(str, a)))
        try:
            mc.main(["--shard", "1/10"])
        finally:
            (mc._run_operators, mc._prepare_workdir, mc._worktree_status,
             mc._indizes_des_laufs) = echt[:4]
            builtins.print = echt[4]
        schluss = [z for z in gemeldet.get("zeilen", []) if z.startswith("=>")]
        self.assertTrue(schluss, "keine Schlusszeile ausgegeben")
        self.assertIn("(3 operators", schluss[-1],
                      f"Die Schlusszeile nennt nicht die gefahrene Menge: {schluss[-1]!r}. Sie "
                      f"rechnet die Zahl ein zweites Mal aus, statt die des Laufs zu melden.")

    def test_die_zwei_rechnungen_divergieren_nachweislich(self):
        """WARUM DAS KEIN KOSMETIK-FIX IST, gemessen statt behauptet: sobald die Operatorenzahl
        nicht durch die Shardzahl teilbar ist, geben die beiden Verfahren verschieden grosse
        Shards. Genau dann meldete die Schlusszeile eine Menge, die dieser Shard nie fuhr."""
        labels = [f"op-{i:02d}" for i in range(100)]
        gewichte = {lab: (90.0 if i % 7 == 0 else 10.0) for i, lab in enumerate(labels)}
        divergenzen = [
            (i, k) for k in (3, 7, 8, 9, 12)
            for i in range(1, k + 1)
            if len(mc.partition_gewichtet(labels, i, k, gewichte)) != len(mc.partition(100, i, k))
        ]
        self.assertTrue(divergenzen,
                        "die beiden Verfahren geben nie verschieden grosse Shards — dann waere der "
                        "Fix belanglos und dieser Fall bestuende ohne Aussage")

    def test_ANTI_PARITAET_die_eine_quelle_bleibt_lueckenlos_und_ueberschneidungsfrei(self):
        """Die Gegenrichtung: die gemeinsame Quelle darf die Partition nicht kaputtmachen."""
        for k in (1, 3, 7, 10):
            teile = [set(mc._indizes_des_laufs((i, k))) for i in range(1, k + 1)]
            self.assertEqual(set().union(*teile), set(range(len(mc.MUTATIONS))),
                             f"K={k}: die Vereinigung hat eine Luecke")
            self.assertEqual(sum(len(t) for t in teile), len(mc.MUTATIONS),
                             f"K={k}: die Shards ueberschneiden sich")
        self.assertEqual(mc._indizes_des_laufs(None), list(range(len(mc.MUTATIONS))),
                         "ohne Shard muss die volle Liste gefahren werden")


class DieErwartungDesSammelJobsKommtAusDemLauf(unittest.TestCase):
    """Gefunden beim Lesen des Sammel-Jobs waehrend des Fix-Zyklus (2026-09-07), und es war der
    blockierende Fund der Runde.

    `.github/workflows/ci.yml` hielt die erwartete Operatorenzahl als getippte Konstante
    `ERWARTET=88`. Am 2026-09-06 kamen zwoelf Operatoren fuer die Release-Entscheidungsflaeche dazu
    (`15d05ab`), die Liste steht seither auf 100. Der Riegel, der eine LUECKE in der Partition
    finden soll, haette damit bei JEDEM vollstaendigen Lauf eine gemeldet, die es nicht gibt — und
    der naechste Kettenschritt dieses Releases ist genau so ein Lauf.

    Dieselbe Klasse wie der Nachbar darueber: eine Groesse wird an zwei Orten gefuehrt, und sie
    driftet. Der Unterschied ist nur, wie weit die beiden Orte auseinanderliegen — dort zwei
    Funktionen in einer Datei, hier ein Skript und ein Workflow.
    """

    WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"

    def test_die_schlusszeile_nennt_die_gesamtzahl(self):
        """DER FANGNACHWEIS. Ohne `total=` in der Schlusszeile hat der Sammel-Job keine Quelle und
        muesste wieder tippen."""
        gemeldet = []
        echt = (mc._run_operators, mc._prepare_workdir, mc._worktree_status)
        mc._run_operators = lambda work, **kw: 0
        mc._prepare_workdir = lambda root, work: None
        mc._worktree_status = lambda root: ""
        import builtins
        echt_print = builtins.print
        builtins.print = lambda *a, **k: gemeldet.append(" ".join(map(str, a)))
        try:
            mc.main(["--shard", "3/10"])
        finally:
            mc._run_operators, mc._prepare_workdir, mc._worktree_status = echt
            builtins.print = echt_print
        schluss = [z for z in gemeldet if z.startswith("=>")]
        self.assertTrue(schluss, "keine Schlusszeile")
        self.assertIn(f"total={len(mc.MUTATIONS)}", schluss[-1],
                      f"Die Schlusszeile nennt die Gesamtzahl nicht: {schluss[-1]!r}. Dann muss der "
                      f"Sammel-Job sie tippen, und eine getippte Zahl driftet.")

    def test_der_workflow_tippt_die_erwartung_NICHT_mehr(self):
        """Die zweite Haelfte: die Zahl darf im Workflow nicht als Konstante stehen.

        Geprueft wird die ZUWEISUNG einer Zahl an die Erwartung, nicht das Wort — der Fix liest sie
        aus den Shard-Dateien, das Wort steht also weiterhin da.
        """
        text = self.WORKFLOW.read_text(encoding="utf-8")
        getippt = re.findall(r"(?m)^\s*ERWARTET=([0-9]+)\s*$", text)
        self.assertFalse(getippt, (
            f"Der Sammel-Job tippt die erwartete Operatorenzahl wieder: {getippt}. Genau diese "
            f"Konstante stand am 2026-09-07 auf 88, waehrend die Liste 100 trug — der Riegel gegen "
            f"eine Partitionsluecke haette bei jedem vollstaendigen Lauf eine erfunden."))
        self.assertIn("total=", text,
                      "Der Sammel-Job liest keine Gesamtzahl aus den Shard-Ergebnissen")

    def test_die_summe_der_shards_ist_die_gesamtzahl(self):
        """Die Rechnung, die der Sammel-Job anstellt, hier gegen den echten Operatorensatz."""
        summe = sum(len(mc._indizes_des_laufs((i, 10))) for i in range(1, 11))
        self.assertEqual(summe, len(mc.MUTATIONS),
                         f"Die zehn Shards fahren zusammen {summe} von {len(mc.MUTATIONS)} "
                         f"Operatoren — dann hat die Partition eine Luecke oder eine Ueberschneidung")
