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

    def test_die_schlusszeile_nennt_die_menge_die_der_ECHTE_lauf_gefahren_hat(self):
        """DER FANGNACHWEIS — ZWEITE FASSUNG, weil die erste blind war.

        DIE ERSTE FASSUNG ERSETZTE `_run_operators` DURCH EINEN STUB. Damit prueft sie nur, woraus
        `main()` seine Druckzeile liest — nie, woraus der ECHTE Lauf liest. Die Bestaetigungsrunde
        (Lauf 5, Linse 1, 2026-09-07) hat genau das ausgenutzt: sie baute den historischen Fund
        wieder ein (der Lauf rechnet ueber `partition()` round-robin, die Schlusszeile ueber
        `_indizes_des_laufs`), und ALLE Faelle dieser Datei blieben gruen. Ein Stub an der Stelle,
        deren Verhalten geprueft werden soll, prueft das Verhalten des Stubs.

        Diese Fassung laesst `_run_operators` LAUFEN und faengt ab, welche Indizes es wirklich
        anfasst. Die Schlusszeile muss dieselbe Menge nennen. Divergieren die beiden Quellen, faellt
        der Fall — unabhaengig davon, welche Rechnung wo steht.
        """
        import builtins  # noqa: PLC0415
        gemeldet: dict = {"zeilen": []}
        gefahren: list = []

        # Der Lauf wird ECHT gefahren, nur die teure Suite wird ersetzt: `_red_count` liefert eine
        # konstante Roete, sodass jeder Operator sofort ein Urteil bekommt. Die Auswahl der
        # Operatoren — das Gemessene — bleibt unberuehrt.
        echt = (mc._red_count, mc._prepare_workdir, mc._worktree_status, builtins.print)
        mutationen_original = mc.MUTATIONS

        def _protokolliere(work, *a, **k):
            return 0

        def _lege_ziel_an(root, work):
            """Der Wegwerfbaum bekommt genau die eine Datei, die die Operatoren anfassen — der
            Lauf soll ECHT laufen, nur nicht das ganze Repo kopieren."""
            ziel = work / "src" / "x.py"
            ziel.parent.mkdir(parents=True, exist_ok=True)
            ziel.write_text("\n".join(f"alt{i}" for i in range(20)) + "\n", encoding="utf-8")

        try:
            mc._red_count = _protokolliere
            mc._prepare_workdir = _lege_ziel_an
            mc._worktree_status = lambda root: ""
            builtins.print = lambda *a, **k: gemeldet["zeilen"].append(" ".join(map(str, a)))
            # Ein winziger Operatorensatz, damit der echte Lauf schnell durchlaeuft. Die Ziele
            # existieren nicht — jeder Operator meldet GAP und wird trotzdem GEFAHREN, und genau
            # die gefahrene MENGE ist der Gegenstand.
            mc.MUTATIONS = [("src/x.py", f"alt{i}", f"neu{i}", f"op-{i}", True) for i in range(20)]
            # Die Erwartung wird BERECHNET, SOLANGE die Liste die des Laufs ist. Ein Aufruf nach dem
            # Wiederherstellen laege gegen die echten 100 Operatoren — der Vergleich wuerde dann
            # etwas anderes messen als das Gefahrene.
            erwartet = sorted(mc._indizes_des_laufs((2, 5)))
            mc.main(["--shard", "2/5"])
        finally:
            mc.MUTATIONS = mutationen_original
            mc._red_count, mc._prepare_workdir, mc._worktree_status, builtins.print = echt

        # Was der ECHTE Lauf angefasst hat, steht in seinen eigenen shard-item-Zeilen.
        gefahren = sorted(int(z.split()[1]) for z in gemeldet["zeilen"]
                          if z.strip().startswith("shard-item"))
        schluss = [z for z in gemeldet["zeilen"] if z.startswith("=>")]
        self.assertTrue(schluss, f"keine Schlusszeile: {gemeldet['zeilen'][:5]}")
        self.assertTrue(gefahren, "der Lauf hat seine Menge nicht ausgegeben")

        # DIE MITGLIEDSCHAFT, NICHT DIE ANZAHL — und das ist die dritte Fassung dieses Falls.
        # Die zweite verglich `len(gefahren)` gegen die Zahl in der Schlusszeile und blieb deshalb
        # GRUEN, als der historische Fund wieder eingebaut wurde: beide Partitionsverfahren liefern
        # gleich GROSSE Shards, nur mit anderen Operatoren darin. Gemessen an der echten Liste
        # dieses Repos unterscheiden sich die Mitgliedschaften bei 10 von 10 Shards, die Groessen
        # bei keinem einzigen. Eine Anzahl kann eine Partition nicht unterscheiden.
        self.assertEqual(gefahren, erwartet, (
            f"Der Lauf hat die Operatoren {gefahren} angefasst, `_indizes_des_laufs` liefert aber "
            f"{erwartet}. Damit rechnen Lauf und Schlusszeile aus verschiedenen Quellen — genau der "
            f"Fund, den dieser Fall binden soll."))
        self.assertIn(f"({len(gefahren)} operators", schluss[-1], (
            f"Die Schlusszeile nennt {schluss[-1]!r}, der Lauf hat aber {len(gefahren)} Operatoren "
            f"angefasst."))

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


class DerSammelJobWirdALSPROGRAMMGefahren(unittest.TestCase):
    """Die Gegenlesung hat den vorigen Fall dieser Datei widerlegt, und der Befund sass.

    `test_der_workflow_tippt_die_erwartung_NICHT_mehr` prueft den TEXT des Workflows: steht dort
    noch eine getippte Zahl? Das ist eine notwendige Frage und eine schwache. Gemessen am
    2026-09-07 mit zehn synthetischen Shard-Dateien: der neue Extraktionscode lief unter
    `set -euo pipefail`, und `grep` liefert 1, wenn es nichts findet. Eine Shard-Datei OHNE
    `total=` — genau der Fall, den die Pruefung abfangen soll — brach das Skript deshalb sofort
    ab, mitten in der Schleife. Die Shards danach wurden nie gelesen, und die eigens dafuer
    geschriebene Meldung war unerreichbarer Code.

    Der Texttest blieb dabei GRUEN, weil im Workflow ja keine Zahl mehr stand. Ein Orakel, das
    die Form prueft statt das Verhalten, kann einen Riegel nicht von seinem Absturz unterscheiden.
    Diese Faelle fahren den Block als das, was er ist: ein Programm.
    """

    WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"

    @classmethod
    def _shell_block(cls) -> str:
        """Der `run:`-Rumpf des Sammel-Schritts, aus dem Workflow geholt und entrueckt."""
        text = cls.WORKFLOW.read_text(encoding="utf-8")
        marke = "Fail closed on missing, red or incomplete shards"
        i = text.index(marke)
        j = text.index("run: |", i) + len("run: |\n")
        zeilen = []
        for zeile in text[j:].splitlines():
            if zeile.strip() and not zeile.startswith("          "):
                break
            zeilen.append(zeile[10:] if zeile.startswith("          ") else zeile)
        rumpf = "\n".join(zeilen)
        assert "MUTATION_RESULT" in rumpf and "summe" in rumpf, "Rumpf nicht erkannt"
        return rumpf

    def _fahre(self, shards: dict[int, str], ergebnis: str = "success"):
        """Den Block in einem Wegwerfordner fahren. shards: Nummer -> Dateiinhalt (fehlt = keine Datei).

        `ergebnis` IST EIN PARAMETER UND WAR ES NICHT (Riegel-Sweep auf Owner-Auftrag, 2026-09-07).
        Er stand als "success" fest verdrahtet in ALLEN neun Faellen dieser Klasse — und damit war
        der erste der drei dokumentierten Riegel des Sammel-Jobs ("ein Shard ist ROT") von keinem
        einzigen gebunden. Gemessen: den ganzen `if`-Block entfernt, alle neun Faelle blieben gruen.
        """
        import subprocess  # noqa: PLC0415
        import tempfile  # noqa: PLC0415
        with tempfile.TemporaryDirectory(prefix="sammeljob-") as d:
            for i, inhalt in shards.items():
                Path(d, f"mutation-shard-{i}.txt").write_text(inhalt, encoding="utf-8")
            return subprocess.run(["bash", "-c", self._shell_block()], cwd=d,
                                  capture_output=True, text=True, timeout=120,
                                  env={"MUTATION_RESULT": ergebnis, "PATH": "/usr/bin:/bin"})

    @staticmethod
    def _gut(n: int = 10, gesamt: int = 100):
        """Zehn Shards, round-robin partitioniert — Groessen UND Mitgliedschaften."""
        return {i: (f"shard={i} operators={gesamt // n} total={gesamt} "
                    f"indizes={','.join(str(x) for x in range(i - 1, gesamt, n))}\n")
                for i in range(1, n + 1)}

    def test_ein_ROTER_shard_laesst_den_sammel_job_scheitern(self):
        """DER RIEGEL, DEN KEIN FALL BAND (Riegel-Sweep auf Owner-Auftrag, 2026-09-07, P0).

        Der Sammel-Job hat DREI dokumentierte Riegel: ein Shard fehlt, ein Shard ist ROT, die
        Partition ist unvollstaendig. Zwei davon waren gebunden. Der mittlere nicht — weil alle
        neun Faelle dieser Klasse `MUTATION_RESULT=success` fest verdrahtet mitgaben und die
        Variable damit nie den Wert trug, gegen den der Riegel prueft.

        WAS DAS BEDEUTET, und es ist die gefaehrlichste der drei Luecken: meldet ein Shard einen
        UEBERLEBENDEN Mutanten, druckt `mutation_check.py` seine Schlusszeile trotzdem vollstaendig
        (`total=`, `indizes=`). Summen- und Mitgliedschaftspruefung saehen eine saubere Partition
        und meldeten OK. Der `MUTATION_RESULT`-Zweig ist die EINZIGE Stelle, die den roten Lauf
        sieht — und sie war ungeprueft. Ein Tor, dessen Rot-Erkennung niemand testet, ist ein Tor,
        das nur den Normalfall kennt.
        """
        r = self._fahre(self._gut(), ergebnis="failure")
        self.assertEqual(r.returncode, 1, (
            "Der Sammel-Job besteht, obwohl die Mutations-Matrix FAILURE meldet. Die Shard-Dateien "
            "sind hier absichtlich makellos: eine vollstaendige, disjunkte Partition ueber 100 "
            f"Operatoren. Genau so sieht ein Lauf aus, in dem eine Mutante UEBERLEBT hat.\n"
            f"stdout:\n{r.stdout}\nstderr:\n{r.stderr}"))
        self.assertIn("mindestens ein Shard ist rot", r.stdout + r.stderr,
                      "Der Job scheitert, aber nicht mit SEINER Meldung — dann faengt etwas anderes")

    def test_ANTI_PARITAET_der_rot_riegel_nimmt_den_gruenen_lauf_NICHT_mit(self):
        """Die Kontrolle: ohne sie bestuende der Fall oben auch bei einem Job, der IMMER scheitert.

        Dieselbe makellose Shard-Menge, nur mit `success` — sie MUSS bestehen. Und ein dritter Wert
        ist mitgeprueft, weil `!= "success"` mehr Zustaende kennt als `failure`: GitHub setzt bei
        einer abgebrochenen Matrix `cancelled`, und der gehoert genauso gefangen.
        """
        self.assertEqual(self._fahre(self._gut(), ergebnis="success").returncode, 0,
                         "der saubere Lauf scheitert am Rot-Riegel — dann ist er ein Dauerrot")
        r = self._fahre(self._gut(), ergebnis="cancelled")
        self.assertEqual(r.returncode, 1, (
            "Eine ABGEBROCHENE Matrix (`cancelled`) besteht. Der Riegel prueft auf `!= success` und "
            "muss deshalb jeden Nicht-Erfolg fangen, nicht nur `failure` — sonst waere er eine "
            "Aufzaehlung statt einer Bedingung."))

    def test_der_gute_fall_besteht(self):
        """Die Positivkontrolle. Ohne sie sagen die Faelle unten nur, dass immer etwas faellt."""
        r = self._fahre(self._gut())
        self.assertEqual(r.returncode, 0, f"der saubere Fall scheitert:\n{r.stdout}\n{r.stderr}")
        self.assertIn("mutation-summary OK", r.stdout)
        self.assertIn("100 Operatoren", r.stdout)

    def test_EIN_SHARD_OHNE_total_bekommt_eine_MELDUNG_und_keinen_absturz(self):
        """DER FANGNACHWEIS ZUM BEFUND DER GEGENLESUNG.

        Ohne `| tail -1` starb der Block hier an `set -e`, bevor irgendeine Meldung kam.
        """
        shards = self._gut()
        shards[5] = "shard=5 operators=10\n"          # kein total= — alter Runner neben neuem
        r = self._fahre(shards)
        self.assertNotEqual(r.returncode, 0, "ein Shard ohne Gesamtzahl muss den Job faellen")
        gesamtausgabe = r.stdout + r.stderr
        self.assertIn("::error::", gesamtausgabe, (
            f"Der Job scheitert OHNE Fehlermeldung — er ist abgestuerzt, statt zu urteilen. "
            f"stdout={r.stdout!r} stderr={r.stderr!r}"))
        self.assertIn("shard 10:", r.stdout, (
            "Die Schleife hat die Shards nach dem luecken haften nicht mehr gelesen — der Block "
            "brach mitten in der Auswertung ab, statt sie zu Ende zu fuehren."))

    def test_uneinige_gesamtzahlen_werden_benannt(self):
        """Zwei Codestaende in einer Matrix: die Summe sagt dann nichts, egal wie sie ausfaellt."""
        shards = self._gut()
        shards[3] = "shard=3 operators=10 total=88\n"
        r = self._fahre(shards)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("verschiedene Gesamtzahlen", r.stdout + r.stderr)

    def test_eine_luecke_in_der_partition_wird_benannt(self):
        """Die eigentliche Aufgabe des Riegels: Summe != Gesamtzahl."""
        shards = self._gut()
        shards[7] = "shard=7 operators=3 total=100\n"     # sieben Operatoren fehlen
        r = self._fahre(shards)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("Luecke", r.stdout + r.stderr)

    def test_ein_fehlender_shard_wird_benannt(self):
        shards = self._gut()
        del shards[4]
        r = self._fahre(shards)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("fehlende Shards", r.stdout + r.stderr)

    def test_UEBERLAPPUNG_die_sich_mit_einer_LUECKE_aufhebt_wird_gefangen(self):
        """DER FANGNACHWEIS ZU LINSE 1 DER BESTAETIGUNGSRUNDE (2026-09-07).

        Bis zu diesem Fix prueft der Sammel-Job nur `Summe == Gesamtzahl`. Das ist notwendig und
        NICHT hinreichend: acht Shards mit je zehn, einer mit fuenfzehn und einer mit fuenf ergeben
        ebenfalls 100. Eine Ueberschneidung, die sich mit einer Luecke aufhebt, kommt so durch —
        und genau das soll der Riegel verhindern.
        """
        # DIE KONSTRUKTION IST DER GANZE FALL, und der erste Versuch war falsch: er VERSCHOB fuenf
        # Indizes von Shard 7 nach Shard 3. Eine Verschiebung ist aber weiterhin eine gueltige
        # Partition — Summe 100, Vereinigung vollstaendig, disjunkt —, und der Riegel liess sie zu
        # Recht durch. Gebraucht wird eine ECHTE Ueberlappung, die eine Luecke ausgleicht: Shard 3
        # nimmt fuenf Indizes von Shard 7 DAZU, waehrend Shard 7 sie BEHAELT (Ueberlappung), und
        # dafuer fallen Shard 7s andere fuenf ganz weg (Luecke). Summe bleibt 100.
        s7 = [str(x) for x in range(6, 100, 10)]
        shards = self._gut()
        idx3 = [str(x) for x in range(2, 100, 10)] + s7[:5]     # 15, davon 5 doppelt
        idx7 = s7[:5]                                            # 5, dieselben fuenf
        shards[3] = f"shard=3 operators=15 total=100 indizes={','.join(idx3)}\n"
        shards[7] = f"shard=7 operators=5 total=100 indizes={','.join(idx7)}\n"
        r = self._fahre(shards)
        self.assertNotEqual(r.returncode, 0, (
            "Eine Ueberlappung, die sich mit einer Luecke aufhebt, kommt durch. Die Summe ist 100 "
            "und stimmt — die Partition ist es nicht."))
        self.assertIn("ueberschneiden", r.stdout + r.stderr)

    def test_ein_shard_OHNE_mitgliedschaft_ist_nicht_nachrechenbar(self):
        """Die Mitgliedschaft ist die Grundlage der Rechnung. Fehlt sie, ist die Aussage
        'lueckenlos und ueberschneidungsfrei' nur behauptet — und das muss auffallen."""
        shards = self._gut()
        shards[6] = "shard=6 operators=10 total=100\n"      # kein indizes=
        r = self._fahre(shards)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("keine Mitgliedschaft", r.stdout + r.stderr)

    def test_eine_LUECKE_ohne_ausgleichende_ueberlappung_wird_weiterhin_gefangen(self):
        """Die Kontrolle in die andere Richtung: der alte Summenriegel muss weiter greifen."""
        shards = self._gut()
        idx9 = [str(x) for x in range(8, 100, 10)][:7]
        shards[9] = f"shard=9 operators=7 total=100 indizes={','.join(idx9)}\n"
        r = self._fahre(shards)
        self.assertNotEqual(r.returncode, 0)
        self.assertIn("Luecke", r.stdout + r.stderr)

    def test_ANTI_PARITAET_die_echte_partition_dieses_repos_besteht(self):
        """Ohne diesen Fall bestuenden die drei oben auch bei einem Riegel, der IMMER faellt.

        Gefahren wird die WIRKLICHE Partition dieses Repos, so wie `_indizes_des_laufs` sie liefert —
        nicht eine nachgebaute. Sie muss durchkommen.
        """
        g, _ = mc.lade_gewichte()
        shards = {}
        for i in range(1, 11):
            idx = mc._indizes_des_laufs((i, 10), g)
            shards[i] = (f"shard={i} operators={len(idx)} total={len(mc.MUTATIONS)} "
                         f"indizes={','.join(str(x) for x in idx)}\n")
        r = self._fahre(shards)
        self.assertEqual(r.returncode, 0, (
            f"Die echte Partition dieses Repos faellt am eigenen Riegel:\n{r.stdout}\n{r.stderr}"))
        self.assertIn("Vereinigung vollstaendig und paarweise disjunkt", r.stdout)
