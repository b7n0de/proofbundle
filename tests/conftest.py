"""Shared pytest configuration.

PKG-2026-0718-01 (RE-GATE): the sdist ships tests/ (MANIFEST graft) so `pip install <sdist> && pytest`
is a genuinely self-testable package. A SPECIFIC SET of tests, however, assert facts about the
REPO / CI / Rust / docs LAYOUT — the contents of `.github/workflows`, the Rust verifier source under
`tools/`, `SPEC.md` / `README.md` / `CITATION.cff`, and the audit records — material the sdist
DELIBERATELY prunes (it is not a Python-package artifact; shipping the 138M Rust tree or the CI configs
in a Python sdist is a category error). Those tests are meaningless outside a git checkout, so they SKIP
when the repo-only markers are absent (i.e. when running from an extracted sdist / installed wheel),
turning false runtime FAILURES into honest SKIPs — the sdist then runs clean. In a real checkout (CI)
every marker is present, NOTHING is skipped, and coverage is exactly as before (this file is a pure no-op
in the repo). This is the No-Fake honest form of "self-testable" — with a MEASURED limit that this sentence
used to hide. It said "the package-level tests run". A share of them does NOT, because the skip is decided
PER MODULE: one repo-touching test drags its package-clean siblings with it (`test_fork_pr_secret_isolation`:
34 skipped, 1 needed — so all but one of its security-scanner tests never run from the package; `test_audit_marker_line_wrap`:
9 skipped, 0 needed — that module had already solved it per-test, three-state, and the blanket skip overrides
the better solution). The trade is deliberate and documented; what was NOT honest was claiming the cost away.
The repo-layout tests announce themselves as N/A rather than failing or being silently dropped.

TWO NUMBERS USED TO STAND HERE, AND BOTH HAD GONE STALE — the collateral-skip count and the
false-failure count, both measured 2026-09-02. Deep gate lens 3 re-measured them on the 6.0.0 candidate
(2026-09-07) and returned REJECT: the collateral count had grown by more than a factor of two, confirmed
two independent ways (a real `pytest -rs` run out of the built sdist, and the derivation itself applied to
the collected items). Test files created AFTER the measurement date carried, on their own, more skips than
the whole number that stood here.

THE EXACT FIGURES ARE DELIBERATELY NOT REPEATED IN THIS PARAGRAPH, and that is the second correction.
The first attempt at this text named them — and an adversarial lens caught it the same day: naming a
measured aggregate in prose re-creates the very defect the paragraph describes, one commit after
removing it. Prose cannot be re-derived. Whoever wants the number runs the derivation; whoever wants the
history reads the lens report in the audit record.

The sharper point is not the drift, it is that this docstring PREDICTED it ("the number was never
re-derived after the suite grew") and the prediction changed nothing: `tests/conftest.py` was edited four
more times, twice on the day of the freeze, and no edit re-derived the figure. A warning that does not
become a mechanism is a warning that will be right and useless.

So the count is no longer typed here at all. It is DERIVED and BOUND by
`tests/test_paketgrenze_zahlen_sind_abgeleitet.py`, which applies this module's own
`modul_ist_repo_kontext` + `_REPO_CONTEXT_TESTS` to the collected suite. The number lives in the run, not
in prose, and the day the suite grows it moves with it.

THE FALSE-FAILURE COUNT IS NOT BOUND, and that is deliberate rather than forgotten. Measuring it means
disabling the skip and actually RUNNING the affected tests; lens 3 tried, and
`test_audit_candidate_360` alone spawns a real `audit_candidate_matrix.py` subprocess per case, so a full
measurement runs over an hour. What IS established: it is a LOWER BOUND from 2026-09-02, and it has since
grown — commit `29fb3af` added nine more measured runtime failures on 2026-09-07 without the figure moving.
A bound that says "at least, as of this date" is honest; a precise-looking number nobody re-derives is not.
"""
import pathlib

import pytest

_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
# A git checkout always carries these; the sdist prunes/omits them (.github, the Rust tree, the spec
# source). Their ABSENCE means we are running from a distributed artifact, not the repo.
_REPO_ONLY_MARKERS = (".github", "tools", "SPEC.md")

# The exact repo-context tests (module stem :: test method) whose assertions are about the repo/CI/Rust/
# docs LAYOUT rather than the installed package. Derived from the from-sdist run: these read files the
# sdist does not (and should not) ship. Explicit + documented — a new repo-context test adds its id here.
# NOTE: test_renewal_policy::test_shipped_example_policy_loads_and_evaluates is NOT here — its example
# (docs/adr/renewal_policy.example.json) is a genuinely shipped artifact, fixed by `graft docs/adr`.
_REPO_CONTEXT_TESTS = frozenset({
    # DER RUECKFALL, GEMESSEN statt angenommen. Diese Tests erreichen das Repo NICHT ueber ein
    # Pfad-Literal im eigenen Modul (Import aus scripts/, dynamisches Laden, glob auf .github), also kann
    # die Ableitung sie nicht sehen. Ermittelt, indem die Liste im entpackten sdist GELEERT und die Suite
    # gefahren wurde: was dann faellt, gehoert hierher — und nur das.
    #
    # Eine erste Fassung dieses Fixes strich auf drei Module zusammen, weil ich die uebrigen fuer
    # redundant HIELT. Sieben Tests fielen daraufhin. Die Menge ist messbar; sie zu schaetzen war der
    # Fehler.
    #
    # test_audit_candidate_360 / test_roadmap_frontload_foundations: importieren scripts/*.py und laufen
    #   ueber DEREN Repo-Zugriffe.
    "test_audit_candidate_360::test_matrix_is_ready_and_has_33_checks",
    "test_audit_candidate_360::test_c12_2_green_on_real_repo",
    "test_audit_candidate_360::test_c1_1_green_on_real_repo",
    "test_audit_candidate_360::test_c12_2_fails_on_tampered_register",
    "test_audit_candidate_360::test_c12_2_fails_on_foreign_key_register",
    "test_roadmap_frontload_foundations::test_pack_is_grounded_in_real_artifacts",
    "test_roadmap_frontload_foundations::test_released_version_has_audit_record",
    # test_pre_tag_receipt_commit_flow: faehrt scripts/pre_tag_receipt.py als PROZESS. Seit dem
    #   Owner-Entscheid 2026-09-06 (Karte OA-8b1a31cc4f) ist genau dieses Skript aus dem sdist
    #   ausgeschlossen — es traegt den Inline-Signierweg, der nur auf der Maschine des
    #   Schluesselhalters laufen soll. Im sdist gibt es die Datei also nicht, und der Test kann seine
    #   Eigenschaft dort nicht messen. Das ist kein Mangel des Pakets, sondern der Zweck des
    #   Ausschlusses; im Checkout laeuft er unveraendert.
    "test_pre_tag_receipt_commit_flow::test_committed_receipt_verifies_and_src_change_is_rejected",
    # test_claims_hygiene: scannt die Doku ueber scripts/claims_hygiene_check, das seine Pfadmenge selbst
    #   fuehrt.
    "test_claims_hygiene::test_real_docs_are_clean",
    "test_claims_hygiene::test_every_default_doc_exists_and_scan_covers_all",
    "test_claims_hygiene::test_injected_overclaim_in_every_listed_doc_fails",
    "test_claims_hygiene::test_main_default_run_includes_cli_surface",
    "test_claims_hygiene::test_new_priority_docs_are_in_scan_set_and_clean",
    # test_rust_parity_gate: prueft den Rust-Baum ueber scripts/rust_parity_gate.
    "test_rust_parity_gate::test_real_repo_main_rs_has_the_expected_subcommands",
    "test_rust_parity_gate::test_real_repo_registry_is_honest_strict_mode_exits_0",
    # test_fork_pr_secret_isolation: glob ueber .github/workflows, kein benanntes Literal.
    "test_fork_pr_secret_isolation::test_repo_workflows_are_isolation_safe",
    # ── NEUN EINTRAEGE, 2026-09-07, Owner-Karte OA-f32d8c7013 Antwort A ────────────────────────
    #
    # WARUM DIE ABLEITUNG SIE NICHT SIEHT, und das ist genau der Fall, fuer den die Liste als
    # dokumentierter Rueckfall stehenblieb. `modul_ist_repo_kontext` fragt: nennt das Modul einen
    # wurzelrelativen Pfad, den es HIER nicht gibt? test_not_after_… nennt
    # "scripts/audit_candidate_matrix.py" — und diese Datei IST im sdist (MANIFEST.in Zeile 88).
    # Die Ableitung sieht also alles vorhanden. Was fehlt, liegt eine Ebene tiefer im Skript.
    #
    # DER TRAGENDE GRUND IST NICHT DIE FEHLENDE DATEI, SONDERN DAS FEHLENDE REPOSITORIUM
    # (Gegenlesung 07.09.2026, Linse 2; meine erste Fassung nannte nur die schwaechere Haelfte).
    # `_trust_anchor` in scripts/audit_candidate_matrix.py:352-357 liest den COMMITTETEN BLOB ueber
    # `git show HEAD:audit_artifacts/readiness_trusted_pubkeys.txt`, nicht die Datei von der Platte.
    # Der Anker waere also auch dann unlesbar, wenn das sdist ihn MITLIEFERTE — kein sdist und kein
    # Wheel bringt je ein `.git` mit. Gemessen im entpackten Baum, in dem die Datei sogar noch
    # physisch lag: `zustand='unmeasurable'`, Ursache `fatal: not a git repository`. Dasselbe bei
    # test_release_text_hygiene: `betreffs_seit("HEAD")` faehrt `git log HEAD..HEAD`.
    #
    # DIE KLASSE, und deshalb steht sie hier statt nur der Instanz: ein Test, der das Repo ueber GIT
    # erreicht statt ueber ein Pfad-Literal, ist fuer eine statische Pfad-Ableitung strukturell
    # unsichtbar — unabhaengig davon, was MANIFEST.in ausliefert. Genau dafuer ist der Rueckfall da.
    # Dass `audit_artifacts` zusaetzlich geprunt ist (MANIFEST.in Zeile 119), ist wahr und aendert
    # nichts: es ist die zweite Absicherung, nicht der Grund.
    #
    # GEMESSEN, nicht vermutet: hermetic-cleanroom auf Kopf 7c9826d meldet
    # `9 failed, 3339 passed, 472 skipped, 843 subtests, 408,80 s`, Fehlerbild durchgaengig
    # `'unmeasurable' != 'ok'` ("der Anker ist hier nicht lesbar; ohne ihn misst nichts").
    # Dasselbe Tor ist auch auf 37eab91, 733a8c4, 83a25e6 und 5e9aa66 rot — die neun sind
    # VORBESTEHEND, keiner stammt aus der Arbeit dieses Tages.
    #
    # KEIN DEFEKT DES KANDIDATEN: die Tests messen im Paketkontext einen Gegenstand, den es dort
    # nicht gibt. Im Checkout laufen sie unveraendert; dort ist dieser ganze Pfad ein No-op.
    "test_not_after_gilt_auch_auf_dem_registerpfad::test_evidenz_einen_tag_nach_der_frist_ist_unzulaessig",
    "test_not_after_gilt_auch_auf_dem_registerpfad::test_evidenz_einen_tag_vor_der_frist_ist_zulaessig",
    "test_not_after_gilt_auch_auf_dem_registerpfad::test_evidenz_GENAU_am_letzten_tag_ist_noch_zulaessig",
    "test_not_after_gilt_auch_auf_dem_registerpfad::test_abgelaufener_schluessel_ist_fuer_C12_2_nicht_autorisiert",
    "test_not_after_gilt_auch_auf_dem_registerpfad::test_ANTI_PARITAET_2_die_zweite_frist_sperrt_nicht_den_gueltigen_fall",
    "test_not_after_gilt_auch_auf_dem_registerpfad::test_ANTI_PARITAET_gueltiger_schluessel_bleibt_autorisiert",
    "test_not_after_gilt_auch_auf_dem_registerpfad::test_ohne_messzeitpunkt_autorisiert_niemand",
    "test_not_after_gilt_auch_auf_dem_registerpfad::test_RUECKDATIERUNG_aktiviert_keinen_abgelaufenen_schluessel",
    # test_release_text_hygiene: prueft einen Commitbereich, also die git-Historie — im entpackten
    # sdist gibt es kein Repository, und ein leerer Bereich ist dort kein Fehlerfall, sondern der
    # Normalzustand.
    "test_release_text_hygiene::test_ein_leerer_commitbereich_bricht_ab",
    # ── 2026-09-08, gemessen aus der entpackten sdist heraus ─────────────────────────────────────
    #
    # Der Gegenstand dieses Falls ist, WAS DER SAMMLER DES MUTATIONSTORS SIEHT. Das Tor laeuft im
    # Checkout und nie aus einer Verteilung heraus; der Fall erreicht den Baum ueber einen
    # UNTERPROZESS (`_gesehene_dateien` faehrt `pytest --collect-only` gegen `tests`), also genau
    # ueber den Weg, fuer den diese Liste als dokumentierter Rueckfall stehengeblieben ist — eine
    # statische Pfad-Ableitung kann ihn nicht sehen, weil das einzige genannte Literal `tests` ist
    # und das gibt es hier.
    #
    # WARUM ER AUS DER SDIST FAELLT, und warum das KEIN Abdeckungsverlust ist: seit dem Fix zu
    # L6-600-01 wird `tests/test_budget_axis_measurement.py` in einer Verteilung beim Import
    # uebersprungen (sein Skript ist nicht ausgeliefert, Owner-Entscheid OA-dc37e26295). Es liefert
    # dort also null Tests, und der Riegel meldet es als blinde Flaeche. Im Checkout liefert es
    # unveraendert seine fuenf — gemessen am selben Tag: 3948 gesammelte Tests im Checkout gegen
    # 3941 vor dieser Runde, die Differenz sind genau die sieben neuen Faelle.
    #
    # Die Alternative waere gewesen, die Datei in `_OHNE_TESTS_ERLAUBT` einzutragen. Das waere
    # FALSCH: dort steht "diese Datei darf dauerhaft keinen Test liefern", und im Checkout — dem
    # einzigen Ort, an dem das Tor laeuft — liefert sie fuenf. Der Eintrag haette echte Abdeckung
    # stillgelegt, um eine Messung an der falschen Flaeche gruen zu bekommen.
    "test_mutationstor_sammler_sieht_die_freigabeflaeche::test_der_sammler_des_tors_sieht_JEDE_testdatei",
})


def running_in_repo_checkout() -> bool:
    """True iff the repo-only markers are present (a git checkout / CI), False from a distributed sdist."""
    return any((_REPO_ROOT / m).exists() for m in _REPO_ONLY_MARKERS)


# ── The skip set is DERIVED, not enumerated (deep gate finding L6-01, P1) ────────────────────────────
#
# The frozenset above IS the defect. Commit 2c5e7a5 already appended ids to it once, and the gate found six
# MORE tests failing from an extracted sdist at HEAD — because a list of ids cannot know about the method
# somebody adds tomorrow to a module that is already on it. The finding is explicit: appending the six is
# the instance fix and it re-opens.
#
# So the question is answered by MEASUREMENT instead: does this test module read a ROOT-relative path that
# does not exist here? If it does, we are outside a checkout and the module's assertions are about material
# the sdist deliberately prunes — an honest SKIP, never a FAIL. A method added to such a module tomorrow is
# covered the moment it is written, because nothing has to be remembered.
#
# GRANULARITY, deliberately the module. A single item's file reads cannot be attributed statically without
# guessing, and guessing here means either a false FAIL (loud, and the pressure is then to loosen the guard)
# or a false PASS. Skipping the module is the honest, conservative direction: from the sdist it announces
# N/A instead of running less than it claims. In a checkout every path exists and this whole path is a no-op.
_ROOT_NAMEN = {"REPO", "ROOT", "REPO_ROOT", "_REPO_ROOT", "PROJECT_ROOT"}


def _wurzel_relative_pfade(quelle: str, tiefe: int | None = None) -> set[str]:
    """String literals used as ``<repo-root-ish> / "literal"`` in this module's source.

    ``tiefe`` = wie viele ``.parent``-Schritte von DIESEM Modul aus die Repo-Wurzel treffen. Ohne
    Angabe wird eine aus ``__file__`` abgeleitete Wurzel NICHT gebunden — lieber nichts sehen als
    das Falsche sehen (Gegenlesung 2026-08-30, Fund C: ``Path(__file__).parent`` ist das
    tests-Verzeichnis, nicht die Wurzel; 29 Stellen im Baum schreiben genau das, und ein
    ``fixtures`` daraus als wurzelrelativ zu lesen wuerde diese Module ausserhalb eines Checkouts
    still ueberspringen).
    """
    import ast  # noqa: PLC0415 - only needed on the from-sdist path

    try:
        baum = ast.parse(quelle)
    except SyntaxError:
        return set()

    def _ist_dateiabgeleitet(knoten) -> bool:
        """``Path(__file__)`` mit mindestens einem ``.parent``/``.parents[...]`` darauf.

        WARUM DAS EINE EIGENE PRUEFUNG IST (Fix 2026-08-30): `_ist_wurzel` erkannte eine Wurzel am
        NAMEN aus `_ROOT_NAMEN` — alles gross geschrieben. Ein Modul, das seine Wurzel in eine LOKALE
        Variable legt (`root = Path(__file__).resolve().parent.parent`), war damit VOLLSTAENDIG
        unsichtbar: nicht nur der eine Pfad, das ganze Modul. Live gefallen ist daran
        `test_classify_eval_claim` im hermetic-cleanroom-Lauf, weil es `docs/…` liest und `docs/`
        vom sdist geprunt wird.

        DIE NAMENSLISTE ZU OEFFNEN WAERE DER FALSCHE FIX, gemessen: sie ist der UNTERSCHEIDER
        zwischen einer modulweiten Konstante (meint konventionell die Repo-Wurzel) und einer lokalen
        Variable (meint meist etwas anderes). Nimmt man Kleinschreibung einfach dazu, gelten
        `root = self._copy_corpus()` (kopiertes Korpusverzeichnis) und `repo = tmp_path / "r"`
        (Temp-Verzeichnis) als Wurzeln, und ihre relativen Fragmente werden als fehlende Repo-Pfade
        gelesen — 14 Falsch-Positiv-Pfade in zwei Modulen, die dann ausserhalb eines Checkouts still
        uebersprungen wuerden.

        DESHALB SEMANTISCH STATT NAMENSBASIERT: gebunden wird nur, was NACHWEISLICH aus `__file__`
        abgeleitet ist. Der Name spielt keine Rolle mehr, die Herkunft schon.
        """
        return _schritte(knoten) == tiefe if tiefe is not None else False

    def _schritte(knoten):
        """Zahl der parent-Schritte auf einer __file__-Kette, sonst None.

        GEZAEHLT STATT GERATEN. `.parent` und `.parents[n]` ohne Tiefenpruefung zu akzeptieren war
        eine Ueberdehnung: `Path(__file__).parent` ist das tests-Verzeichnis. Erst wenn die Zahl der
        Schritte genau der Entfernung DIESES Moduls zur Repo-Wurzel entspricht, ist es die Wurzel.
        """
        if isinstance(knoten, ast.Subscript):                       # …parents[n] -> n+1 Schritte
            n = _schritte(knoten.value)
            if n is None:
                return None
            idx = knoten.slice
            if isinstance(idx, ast.Constant) and isinstance(idx.value, int):
                return n + idx.value + 1
            return None                                             # variabler Index: unbestimmbar
        if isinstance(knoten, ast.Attribute):
            if knoten.attr == "parent":
                n = _schritte(knoten.value)
                return None if n is None else n + 1
            if knoten.attr == "parents":
                return _schritte(knoten.value)                      # zaehlt erst mit dem Subscript
            return _schritte(knoten.value)                          # .resolve() usw. durchreichen
        if isinstance(knoten, ast.Call):
            if _ist_dateiquelle(knoten):
                return 0
            return _schritte(knoten.func)
        return None

    def _ist_dateiquelle(knoten) -> bool:
        """``Path(__file__)`` bzw. eine Kette darauf, OHNE dass schon ein parent genommen wurde."""
        if isinstance(knoten, ast.Call):
            if (isinstance(knoten.func, ast.Name) and knoten.func.id in ("Path", "PosixPath")
                    and any(isinstance(a, ast.Name) and a.id == "__file__" for a in knoten.args)):
                return True
            return _ist_dateiquelle(knoten.func)
        if isinstance(knoten, ast.Attribute):
            return _ist_dateiquelle(knoten.value)
        return False

    # Lokale Namen, die NACHWEISLICH eine aus __file__ abgeleitete Wurzel tragen. Ermittelt aus den
    # Zuweisungen des Moduls — eine Zuweisung ist der Beleg, den der blosse Name nicht liefert.
    _gebunden: set[str] = set()
    for _z in ast.walk(baum):
        if isinstance(_z, ast.Assign) and _ist_dateiabgeleitet(_z.value):
            for _ziel in _z.targets:
                if isinstance(_ziel, ast.Name):
                    _gebunden.add(_ziel.id)

    # SCHLEIFENVARIABLEN UEBER EINEM LITERAL-TUPEL, und ausdruecklich NUR darueber.
    #
    # `_kette` verwirft ein variables Segment mit der Begruendung "macht den Rest unbestimmbar", und
    # das ist im allgemeinen richtig. EIN Fall ist aber vollstaendig entscheidbar: laeuft die Schleife
    # ueber ein Tupel oder eine Liste aus lauter String-KONSTANTEN, nimmt die Variable genau diese
    # Werte an — mehr Aufloesung braucht es nicht, und es ist keine Variablenverfolgung im
    # allgemeinen Sinn.
    #
    # ANLASS (2026-08-30): `for rel in ("docs/…", "CONFORMANCE.md"): (root / rel)` blieb unsichtbar,
    # obwohl beide Werte woertlich im Modul stehen. Zusammen mit der Namensblindheit oben machte das
    # den hermetic-cleanroom-Fehlschlag aus. Eine Schleife ueber etwas anderes als Konstanten bleibt
    # unbestimmbar und wird weiterhin verworfen.
    # DIE BINDUNG IST AUF DEN SCHLEIFENKOERPER BESCHRAENKT, und das ist kein Detail.
    # Eine erste Fassung band modulweit NACH NAMEN — und leckte prompt: dasselbe Modul hat zwei
    # Schleifen ueber `rel`, eine ueber Manifest-Faelle (nicht konstant) und eine ueber ein
    # Literal-Tupel. Die Werte der zweiten landeten in der Kette der ersten und erzeugten Pfade, die
    # es nirgends gibt (`conformance/CONFORMANCE.md`). Gemeint ist nie "der Name", immer "diese
    # Schleife".
    _schleifen: list[tuple[str, tuple[str, ...], list]] = []
    for _f in ast.walk(baum):
        if not isinstance(_f, ast.For) or not isinstance(_f.target, ast.Name):
            continue
        if not isinstance(_f.iter, (ast.Tuple, ast.List)):
            continue
        werte = [e.value for e in _f.iter.elts
                 if isinstance(e, ast.Constant) and isinstance(e.value, str)]
        if not (werte and len(werte) == len(_f.iter.elts)):   # ALLE Elemente konstant, sonst unbestimmbar
            continue
        # Wird die Variable im Koerper NEU zugewiesen, gilt die Kopfbindung dort nicht mehr —
        # dann lieber nichts binden (Gegenlesung 2026-08-30, Fund A; live 0 Vorkommen, aber die
        # Ueberdehnung zeigt in die schaedliche Richtung: ein erfundener Pfad laesst ein Modul
        # ausserhalb eines Checkouts still ausfallen).
        if any(isinstance(_x, ast.Assign)
               and any(isinstance(_t, ast.Name) and _t.id == _f.target.id for _t in _x.targets)
               for _st in _f.body for _x in ast.walk(_st)):
            continue
        _schleifen.append((_f.target.id, tuple(werte), _f.body))

    _schleifenwerte: dict[str, tuple[str, ...]] = {}       # je Durchgang gesetzt, s.u.

    def _ist_wurzel(knoten) -> bool:
        # REPO / "x"  ·  _REPO_ROOT / "x"  ·  (Path(__file__).resolve().parents[1]) / "x"  ·  REPO / "a" / "b"
        # dazu seit 2026-08-30: ein LOKALER Name, dem im selben Modul eine aus __file__ abgeleitete
        # Wurzel zugewiesen wurde (siehe _ist_dateiabgeleitet).
        if isinstance(knoten, ast.Name):
            return knoten.id in _ROOT_NAMEN or knoten.id in _gebunden
        if isinstance(knoten, ast.Subscript):
            return _ist_wurzel(knoten.value)
        if isinstance(knoten, ast.Attribute):
            return knoten.attr == "parents" or _ist_wurzel(knoten.value)
        if isinstance(knoten, ast.Call):
            return _ist_wurzel(knoten.func)
        if isinstance(knoten, ast.BinOp) and isinstance(knoten.op, ast.Div):
            return _ist_wurzel(knoten.left)
        return False

    def _kette(knoten):
        """(ist_wurzelrelativ, segmente) — die GANZE Kette, nicht ihre Teile.

        Die erste Fassung sammelte jedes Segment einzeln, sodass aus
        ``parents[1] / "src" / "proofbundle"`` auch ``proofbundle`` als wurzelrelativ galt. Das liegt
        aber unter ``src/``, existiert an der Wurzel nicht, und so meldete die Ableitung 23 Module
        selbst in einem vollstaendigen Checkout. Ein zerlegter Pfad ist ein anderer Pfad.
        """
        if isinstance(knoten, ast.BinOp) and isinstance(knoten.op, ast.Div):
            links_ok, linke = _kette(knoten.left)
            if not links_ok:
                return (False, [])
            teile = linke[0] if len(linke) == 1 else None
            if teile is None:            # mehrere linke Ketten: je Kette weiterfuehren
                if isinstance(knoten.right, ast.Constant) and isinstance(knoten.right.value, str):
                    return (True, [t + [knoten.right.value] for t in linke])
                return (False, [])
            if isinstance(knoten.right, ast.Constant) and isinstance(knoten.right.value, str):
                return (True, [teile + [knoten.right.value]])
            if (isinstance(knoten.right, ast.Name)
                    and knoten.right.id in _schleifenwerte):   # entscheidbarer Sonderfall, s.o.
                return (True, [teile + [w] for w in _schleifenwerte[knoten.right.id]])
            return (False, [])          # ein variables Segment macht den Rest unbestimmbar
        return (_ist_wurzel(knoten), [[]])

    def _sammle(knoten_menge) -> None:
        for x in knoten_menge:
            if not (isinstance(x, ast.BinOp) and isinstance(x.op, ast.Div)):
                continue
            ok, ketten = _kette(x)
            if not ok:
                continue
            for teile in ketten:
                if teile:
                    gefunden.add("/".join(teile))

    gefunden: set[str] = set()
    _sammle(ast.walk(baum))                                # Durchgang 1: nur konstante Ketten
    for _name, _werte, _koerper in _schleifen:             # Durchgang 2: je Schleife, NUR ihr Koerper
        _schleifenwerte = {_name: _werte}
        for _stmt in _koerper:
            _sammle(ast.walk(_stmt))
    _schleifenwerte = {}
    return gefunden


def _dieser_baum_ist_das_repo(wurzel: pathlib.Path) -> bool:
    """Is ``wurzel`` ITSELF the root of a git work tree — not merely a directory inside one?

    ``git -C X rev-parse --is-inside-work-tree`` says yes for any subdirectory of any repository, which
    is the wrong question here: an extracted sdist under ``vendor/`` of a consumer's checkout is inside
    a work tree that has nothing to do with it. ``--show-toplevel`` names WHICH tree, and only when that
    equals ``wurzel`` do this repository's ignore rules describe these files (L6-600-01).

    Three outcomes collapse to False on purpose (no git, not a repository, an enclosing repository):
    all three mean "the ignore rule cannot speak about this tree", and the caller's fail-safe for that
    is the stricter pre-fix behaviour, never a lenient one."""
    import subprocess  # noqa: PLC0415 - only on this path
    try:
        r = subprocess.run(["git", "-C", str(wurzel), "rev-parse", "--show-toplevel"],
                           capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return False
    if r.returncode != 0:
        return False
    try:
        return pathlib.Path(r.stdout.strip()).resolve() == pathlib.Path(wurzel).resolve()
    except (OSError, ValueError):
        return False


def _ist_bauartefakt(wurzel: pathlib.Path, rel: str) -> bool:
    """Is this absent path a BUILD OUTPUT rather than a source path the sdist pruned?

    TWO KINDS OF ABSENCE, and the first version of the derivation had one rule for both.
    `tests/test_relation_statement_rust_parity.py` names `tools/pb_verify_rs/target/release/pb_verify_rs`.
    That file is absent in a COMPLETE checkout too — until someone runs `cargo build`. Its absence
    says nothing about whether we are in an sdist, which is the only question this derivation asks.

    Measured on the branch head: five of the nine root-relative paths that module names are build
    outputs under `target/`, and all five are gitignored. The two real source paths it names
    (`tools/pb_verify_rs/crosscheck.py`, `scripts`) are not — and neither is `docs/IN_TOTO_PROFILE.md`,
    the pruned-leaf case this derivation exists for. The repository's own ignore rules are therefore
    exactly the discriminator, and they are the RIGHT one: enumerating build-output directory names
    (`target`, `build`, `dist`, …) would be listing forms again, which is the mistake the comment
    below already warns about.

    ONLY MEANINGFUL IN A CHECKOUT. In an unpacked sdist there is no git and no ignore file, and there
    the old rule is what we want — an absent path there really does mean "not shipped". Any failure
    (git missing, not a repo, non-zero exit) therefore falls back to "not a build artifact", which
    keeps the previous, stricter behaviour.

    THE QUESTION IS ASKED OF THIS TREE, NEVER OF AN ENCLOSING ONE (deep gate 2026-09-05, finding
    L6-600-01, P2). ``git -C <sdist root> check-ignore`` answers from whatever repository CONTAINS the
    directory — and a downstream packager extracts an sdist exactly where one does: ``vendor/``,
    ``build/``, ``.tox/`` inside their own checkout. There every path is reported ignored, so every
    pruned path read as "unbuilt build artifact", the derived skip switched off, and the shipped suite
    ran 40 tests it cannot pass from a distributed artifact (measured: 40 failed under a gitignored
    dir, 1 under a non-ignored one, 0 in a plain dir — same sdist bytes, three different answers).
    The ignore rule is only OUR discriminator when the repository asking is OUR tree, so the toplevel
    is compared first. Not our tree means no git answer at all, which is the stricter old behaviour."""
    if not _dieser_baum_ist_das_repo(wurzel):
        return False
    import subprocess  # noqa: PLC0415 - only on this path
    try:
        r = subprocess.run(["git", "-C", str(wurzel), "check-ignore", "-q", rel],
                           capture_output=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return False
    return r.returncode == 0


def modul_ist_repo_kontext(pfad: pathlib.Path, wurzel: pathlib.Path = _REPO_ROOT) -> bool:
    """True iff this test module reads a root-relative path that is ABSENT here.

    Absence is the whole signal, so an unreadable module is NOT silently treated as fine: it cannot be
    shown to be package-only, and outside a checkout the safe answer is to skip it.

    A path that is absent because it has not been BUILT is not the same signal (see
    `_ist_bauartefakt`) and does not count.
    """
    try:
        quelle = pfad.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return True
    # THE FULL PATH, and it has to be the full path: the sdist prunes LEAVES under shipped directories
    # too (``docs/`` is grafted but ``docs/IN_TOTO_PROFILE.md`` is pruned), so a first-segment rule misses
    # exactly the six tests this finding is about. An intermediate attempt used the first segment because
    # the full-path form flagged 23 modules even in a complete checkout — but that was never the rule's
    # fault: the path CHAINS were being decomposed (see _kette), so ``src`` / ``proofbundle`` was read as
    # a root-level ``proofbundle``. With the chain joined correctly the full-path rule is precise, and the
    # narrowing would have traded a real defect for a comfortable green.
    try:
        # parts fuer tests/test_x.py = ('tests','test_x.py') -> ZWEI parent-Schritte treffen die
        # Wurzel. Die erste Fassung zog eins ab und akzeptierte damit genau das tests-Verzeichnis
        # als Wurzel — die Ueberdehnung, die dieser Fix schliessen soll.
        # GEGEN `wurzel`, nicht gegen die globale _REPO_ROOT: der Parameter existiert, damit
        # gegen einen anderen Baum geprueft werden kann (Tests, entpacktes sdist). Die erste Fassung
        # nahm die Konstante — dann liegt ein Testmodul nicht unter ihr, relative_to wirft, und die
        # Bindung faellt still aus. Gefangen von den neuen Tests, nicht von meiner Durchsicht.
        tiefe = len(pfad.resolve().relative_to(pathlib.Path(wurzel).resolve()).parts)
    except (ValueError, OSError):
        tiefe = None                       # Modul liegt nicht unter der Wurzel: nicht binden
    return any(not (wurzel / rel).exists() and not _ist_bauartefakt(wurzel, rel)
               for rel in _wurzel_relative_pfade(quelle, tiefe))


def pytest_collection_modifyitems(config, items):
    if running_in_repo_checkout():
        return  # a real checkout: run everything (the CI path — coverage unchanged, pure no-op)
    skip = pytest.mark.skip(reason="repo-context test: asserts repo/CI/Rust/docs layout not shipped in the "
                                   "sdist — N/A outside a git checkout (PKG-2026-0718-01)")
    entschieden: dict[str, bool] = {}
    for item in items:
        datei = pathlib.Path(str(getattr(item, "fspath", "")))
        stem = datei.stem
        method = getattr(item, "originalname", None) or item.name
        if stem not in entschieden:
            entschieden[stem] = modul_ist_repo_kontext(datei)
        # DERIVED first; the explicit list stays as a documented fallback for modules whose repo
        # dependency is not visible as a path literal (an env probe, a subprocess into the tree).
        if entschieden[stem] or f"{stem}::{method}" in _REPO_CONTEXT_TESTS:
            item.add_marker(skip)


# ── Ein Importfehler darf das SAMMELN nicht abbrechen ────────────────────────────────────────────
#
# HERKUNFT: deep gate Lauf 5 auf dem 6.0.0-Kandidaten (2026-09-08), Fund L6-600-01 /
# L3-600-SDIST-COLLECT-01, P0, zwei unabhaengige Linsen, Jury 3/3 — und belegt vom CI-Job selbst:
# `published-artifact-gate / hermetic-cleanroom` brach mit `exit code 2` ab, weil
# `tests/test_budget_axis_measurement.py` beim MODULIMPORT `scripts/budget_axis_measurement.py`
# ausfuehrt, das der sdist seit dem Owner-Entscheid zu OA-dc37e26295 nicht mehr ausliefert.
# `Interrupted: 1 error during collection`, Rueckgabewert 2 — und dann laeuft KEIN einziger der
# 3935 uebrigen Tests.
#
# WARUM `pytest_collection_modifyitems` DAS NICHT AUFFANGEN KANN: der Hook laeuft NACH dem Import.
# Was ein Modul auf MODULEBENE tut, ist zu diesem Zeitpunkt laengst gescheitert. Der Schutz muss
# eine Phase frueher greifen.
#
# WARUM NICHT STATISCH. Die erste Fassung dieses Fixes fragte den Syntaxbaum: "nennt dieses Modul
# auf Modulebene einen Pfad, den es hier nicht gibt?" Eine adversariale Gegenlesung hat sie mit
# FUENF ausgefuehrten Faellen widerlegt, alle mit Rueckgabewert 2, alle dieselbe Klasse:
#
#   teil = "scripts"; (REPO / teil / "x.py").read_text()     variables Segment
#   os.path.join(str(REPO), "scripts", "x.py")               kein `/`-Operator
#   REPO.joinpath("scripts", "x.py")                         kein `/`-Operator
#   basis = Path.cwd(); (basis / "scripts" / "x.py")         Wurzel nicht aus __file__
#   from helfer import X                                     der Zugriff steht im NACHBARMODUL
#
# Jede dieser Formen ist semantisch dasselbe und syntaktisch etwas anderes. Eine Form-Erkennung
# muss hier verlieren: sie zaehlt Schreibweisen, waehrend der Defekt "der Import wirft" heisst.
# Das ist dieselbe Verwechslung von Form und Wirkung, gegen die dieses Repo an mehreren Stellen
# antritt — begangen im Riegel dagegen.
#
# DESHALB AM EFFEKT. Wir lassen den Import laufen und fangen sein Scheitern: wirft er, weil eine
# Datei UNTERHALB DIESES BAUMS fehlt, dann traegt die Verteilung sie nicht, und das Modul meldet
# sich ehrlich als SKIP statt die ganze Sammlung mitzureissen. Ein Importfehler aus einem anderen
# Grund (fehlendes Paket, Syntaxfehler, ein Pfad ausserhalb des Baums) bleibt unangetastet — er ist
# eine andere Klasse und soll laut sein.
#
# IM CHECKOUT EIN REINER NO-OP: dort ist eine fehlende Datei der Fehler des Autors und muss beim
# Sammeln knallen, nicht weggeraeumt werden.
#
# ZWEI GRENZEN, benannt statt versteckt (adversariale Gegenlesungen 2026-09-08, beide ausgefuehrt;
# ausfuehrlich als S30 in RESTRISIKO_600.md):
#   1. Ein TIPPFEHLER im Pfad (`scirpts/…` statt `scripts/…`) sieht wie eine nicht ausgelieferte
#      Datei aus und wird uebersprungen. Am Artefakt allein ist das nicht unterscheidbar. Dagegen
#      steht nur, dass das Ueberspringen mit Modul und Datei GEMELDET wird — sichtbar, aber nicht rot.
#   2. Ein `conftest.py` in einem UNTERverzeichnis von `tests/` laedt pytest ueber
#      `_importconftest`, einen anderen Weg; dort bricht das Sammeln unveraendert ab. Gemessen gibt
#      es im Kandidaten genau EIN `conftest.py` — die Luecke ist latent, nicht lebend.
_UEBERSPRUNGEN_BEIM_IMPORT: dict[str, str] = {}


def _liegt_im_baum(datei: object, wurzel: pathlib.Path = _REPO_ROOT) -> bool:
    """Zeigt der Dateiname des Fehlers in DIESEN Baum?

    Die Frage grenzt die Klasse ab: nur was die Verteilung haette mitbringen koennen, wird zu einem
    ehrlichen SKIP. Ein fehlendes `/etc/...` oder ein Pfad im Zwischenspeicher eines fremden
    Pakets bleibt ein Fehler.
    """
    if not datei:
        return False
    try:
        return pathlib.Path(str(datei)).resolve().is_relative_to(pathlib.Path(wurzel).resolve())
    except (OSError, ValueError):
        return False


def _verteilung_sollte_enthalten(rel: str, wurzel: pathlib.Path = _REPO_ROOT) -> bool:
    """Fuehrt die Verteilung diese Datei in ihrer EIGENEN Dateiliste?

    WARUM DIESE FRAGE ZWISCHEN DEM FEHLER UND DEM SKIP STEHT — ohne sie waere dieser ganze Riegel
    eine Verschlechterung. `published-artifact-gate / hermetic-cleanroom` existiert, um zu finden,
    dass die AUSGELIEFERTEN Bytes kaputt sind. Wer jeden fehlenden Pfad zu einem SKIP macht,
    verwandelt "eine Fixture wurde versehentlich nicht mitgeliefert" in einen gruenen Lauf mit
    einem Skip — der Riegel gegen den Sammelabbruch haette den Riegel gegen falsche Paketierung
    entwaffnet, dieselbe Klasse eine Ebene hoeher.

    GEFRAGT WIRD DAS ARTEFAKT SELBST, NICHT `MANIFEST.in`. Eine erste Fassung las die
    Auslieferungsliste — und eine Gegenlesung aus einer FREMDEN Modellfamilie hat das als
    schwaechste Stelle bezeichnet: `MANIFEST.in` ist eine DEKLARATION, die finale Dateiliste
    berechnet setuptools daraus PLUS Vorgaben (`packages`, `package_data`, Projektdateien) — und,
    wie am 2026-09-08 gemessen, plus einem alten `SOURCES.txt`, das eine gestrichene Zeile
    ueberlebt (Restrisiko S27). Beide Quellen sind an genau dieser Stelle nachweislich
    auseinandergelaufen. `SOURCES.txt` IST das Ergebnis dieser Rechnung und liegt in jedem sdist.

    GEMESSEN am entpackten Kandidaten-sdist: 912 Eintraege, und in der Richtung, auf die es hier
    ankommt, exakt — von allen gelisteten Dateien fehlte KEINE. (Umgekehrt liegen im Baum Dateien,
    die nicht gelistet sind; das sind Spuren des Laufens wie `.hypothesis/`, nicht der Verteilung.)

      * Die Liste fuehrt den Pfad, er fehlt trotzdem -> PAKETIERUNGSFEHLER, laut lassen.
      * Die Liste fuehrt ihn nicht                   -> die Verteilung trug ihn nie, ehrlicher SKIP.

    FAIL-CLOSED: gibt es keine Liste oder ist sie unlesbar, gilt "sollte enthalten sein" — dann
    bleibt der Fehler laut. Ein Riegel, der ohne Grundlage nachgibt, ist genau dann am weichsten,
    wenn am wenigsten bekannt ist.
    """
    wurzel = pathlib.Path(wurzel)
    for liste in sorted(wurzel.glob("*/*.egg-info/SOURCES.txt")) + \
            sorted(wurzel.glob("*.egg-info/SOURCES.txt")):
        try:
            eintraege = {z.strip() for z in liste.read_text(encoding="utf-8").splitlines() if z.strip()}
        except OSError:
            continue
        if eintraege:
            return rel in eintraege
    return True                                    # keine Grundlage -> nicht nachgeben


def _verteilung_kennt_den_ort(rel: str, wurzel: pathlib.Path = _REPO_ROOT) -> bool:
    """Liefert die Verteilung ueberhaupt IRGENDETWAS an diesem Ort des Baums?

    Die Frage trennt "eine Datei DIESES Projekts wurde nicht mitgeliefert" von "ein FREMDES Paket
    ist nicht installiert". Beide erscheinen als ModuleNotFoundError, und nur die erste darf ein
    SKIP werden: `import scripts.irgendwas` bei einer Verteilung, die `scripts/` kennt, ist der
    erste Fall; `import numpy` ist der zweite und bleibt ein Fehler, sonst verschluckt dieser
    Riegel eine fehlende Abhaengigkeit.

    Gefragt wird nach dem ersten Pfadsegment, weil genau das die Zugehoerigkeit traegt. Ein
    Top-Level-Modul ohne Verzeichnis (`helfer.py` in der Wurzel) faellt damit durch — fail-closed
    und gewollt: dort ist "gehoert zum Projekt" nicht vom Ort ablesbar, und im Zweifel bleibt der
    Fehler laut.
    """
    kopf = rel.split("/", 1)[0]
    if not kopf or kopf == rel:                    # kein Verzeichnis -> nicht entscheidbar
        return False
    wurzel = pathlib.Path(wurzel)
    for liste in sorted(wurzel.glob("*/*.egg-info/SOURCES.txt")) + \
            sorted(wurzel.glob("*.egg-info/SOURCES.txt")):
        try:
            eintraege = [z.strip() for z in liste.read_text(encoding="utf-8").splitlines() if z.strip()]
        except OSError:
            continue
        if eintraege:
            return any(e.startswith(kopf + "/") for e in eintraege)
    return False


def _fehlende_datei_aus(fehler: BaseException, wurzel: pathlib.Path = _REPO_ROOT):
    """Der Pfad einer Datei DIESES Baums, an deren FEHLEN der Import gescheitert ist — oder None.

    WARUM NICHT DIE AUSNAHMEKLASSE ENTSCHEIDET (Gegenlesung 08.09.2026, zwei Linsen unabhaengig):
    die erste Fassung fing `FileNotFoundError`. Ausfuehrbar gemessen, ein Baum, eine fehlende
    Datei, zwei Zugriffsformen: `Path.read_text` ergab den ehrlichen SKIP, `from scripts.X import
    ...` dagegen `Interrupted: 1 error during collection` — also genau den P0, den dieser Riegel
    schliessen soll. `ModuleNotFoundError` erbt von `ImportError`, nicht von `OSError`; auch
    `PermissionError` und `IsADirectoryError` sind nur GESCHWISTER von `FileNotFoundError`.

    Das ist dieselbe Klasse, die schon die Fassung davor erledigt hatte: ich hatte den Riegel
    bewusst von der FORM (einem AST-Muster ueber Zugriffs-Schreibweisen) auf die WIRKUNG
    umgestellt — und mit `except FileNotFoundError` prompt eine neue Form eingezogen. Eine
    Ausnahmeklasse IST eine Form des Zugriffs. Die Wirkung ist: der Import scheitert an etwas, das
    im Baum fehlt und laut Verteilung auch fehlen soll. Danach wird hier gefragt, in zwei
    Spielarten, weil eine Ausnahme ihren Gegenstand auf zwei Weisen benennt.
    """
    wurzel = pathlib.Path(wurzel).resolve()

    # DIE GANZE URSACHENKETTE, nicht nur die aeusserste Ausnahme (gemessen 08.09.2026): pytest
    # REICHT einen FileNotFoundError aus dem Modulimport durch, VERPACKT einen ImportError aber in
    # eine eigene Sammelmeldung. Wer nur `fehler.name` der aeussersten Ausnahme liest, sieht beim
    # Import-Fall nichts — und genau daran scheiterte die erste Fassung dieses Fixes, obwohl sie
    # `ModuleNotFoundError` ausdruecklich behandeln wollte. Dieselbe Klasse ein drittes Mal: die
    # Wirkung stand nicht dort, wo ich sie abgefragt habe.
    #
    # ABER NUR SOLANGE DIE KETTE DEN GRUND TRAEGT (Gegenlesung 08.09.2026, GESAMT REJECT).
    # Die erste Fassung lief die GANZE Kette ab und nahm den ersten Treffer auf JEDEM Glied.
    # Ausfuehrbar gemessen, was das anrichtet:
    #
    #     try:
    #         from scripts.optional_nicht_geliefert import hilf
    #     except ImportError:
    #         raise RuntimeError("KONFIGURATION KAPUTT: DB_URL fehlt")
    #
    #   -> "1 skipped: nicht ausgeliefert". Die echte Fehlermeldung war SPURLOS weg.
    #
    # Das ist schlimmer als der P0, gegen den dieser Riegel antrat: der machte einen Lauf laut
    # ROT, diese Fassung machte einen echten Fehler STILL. Und es ist dieselbe Klasse wie die
    # zwei Fassungen davor, ein drittes Mal — die Bindung fragte "gab es IRGENDWO in der Kette
    # eine fehlende Datei" statt "scheitert der Import AN einer fehlenden Datei".
    #
    # DIE REGEL, gemessen statt vermutet: JEDES Glied — auch das erste — muss selbst von der Art
    # sein, die "der Zugriff auf eine Ressource scheiterte" BEDEUTET (ImportError oder OSError).
    # Sobald eine andere Klasse auftaucht, hat jemand den urspruenglichen Fehler in einen ANDEREN
    # uebersetzt; ab da traegt die Kette nicht mehr seinen Grund, sondern nur noch seine
    # Vorgeschichte, und die entscheidet hier nichts.
    #
    # GEMESSEN IM ECHTEN PFAD, in pytests collect() statt per importlib daneben — und erst das
    # zeigte die Trennung:
    #     modulweiter `raise RuntimeError` nach `except ImportError`
    #         builtins.RuntimeError            -> builtins.ModuleNotFoundError
    #     `from scripts.X import y`
    #         _pytest.nodes.CollectError       -> builtins.ModuleNotFoundError
    #     `import fremdes_paket`
    #         _pytest.nodes.CollectError       -> builtins.ModuleNotFoundError
    #
    # Der Unterschied ist NICHT die Kettenlaenge — beide sind zweistufig — sondern WER verpackt
    # hat: pytest selbst, oder das Testmodul. Eine Zwischenfassung erlaubte der aeussersten
    # Ausnahme alles und liess damit die Modul-eigene Uebersetzung durch; die naechste verlangte
    # von JEDEM Glied den Grund und brach damit den legitimen Import-Fall, weil pytests
    # CollectError kein ImportError ist. Beide Male hatte ich die Kette NEBEN dem echten Pfad
    # gemessen (per importlib), wo sie einstufig aussieht.
    #
    # Durchlaessig ist die Kette daher genau durch pytests EIGENE Sammelmeldung — nicht durch
    # eine fremde Uebersetzung. Ein Modul, das seinen Importfehler in einen eigenen Fehler
    # umwandelt, hat damit etwas anderes gesagt, und das Gesagte gilt.
    _TRAEGT_DEN_GRUND = (ImportError, OSError)
    _NUR_VERPACKUNG = ("_pytest.",)   # pytests eigene Sammelmeldung, kein Grund fuer sich
    kette = []
    gesehen = set()
    aktuell = fehler
    while aktuell is not None and id(aktuell) not in gesehen and len(kette) < 20:
        _ist_verpackung = type(aktuell).__module__.startswith(_NUR_VERPACKUNG)
        if not _ist_verpackung and not isinstance(aktuell, _TRAEGT_DEN_GRUND):
            break                    # uebersetzt in eine andere Klasse: der Grund ist ein anderer
        gesehen.add(id(aktuell))
        kette.append(aktuell)
        aktuell = aktuell.__cause__ or aktuell.__context__

    for glied in kette:
        # (1) ein DATEIzugriff nennt seinen Pfad selbst — FileNotFoundError.filename
        datei = getattr(glied, "filename", None)
        if datei:
            kandidat = pathlib.Path(str(datei))
            if _liegt_im_baum(kandidat, wurzel) and not kandidat.exists():
                return kandidat

        # (2) ein IMPORT nennt den Modulnamen — ModuleNotFoundError.name
        #
        # GEMESSEN 08.09.2026 von einer Gegenlesung, an einem echten pytest-Subprozess: die erste
        # Fassung ging die zwei Formen einzeln durch und sprang bei einer VORHANDENEN mit
        # `continue` zur naechsten. `from scripts.mutation_check import nichtvorhanden` — Datei da,
        # in SOURCES.txt gefuehrt, nur das SYMBOL fehlt — wirft ein gewoehnliches ImportError mit
        # `.name == "scripts.mutation_check"`. `scripts/mutation_check.py` existierte, also weiter;
        # `scripts/mutation_check/__init__.py` existierte nicht und `scripts/` ist der Verteilung
        # bekannt, also wurde ein Pfad als "fehlend" gemeldet, DEN ES NIE GAB. Ergebnis: ein echter
        # Programmierfehler (entferntes oder umbenanntes Symbol) lief als gruener, freundlich
        # begruendeter SKIP durch — genau die Tarnung, gegen die dieser Riegel steht.
        #
        # Die Formen gehoeren zusammen, weil sie EIN Modul beschreiben: existiert eine von ihnen,
        # ist das Modul da und der Import scheiterte an etwas anderem. Erst wenn KEINE existiert,
        # ist ueberhaupt eine Datei abwesend, ueber die zu reden sich lohnt.
        #
        # DAS VERZEICHNIS IST DIE DRITTE FORM, und sie hat gefehlt. Eine fremdfamiliaere
        # Gegenlesung (qwen, 08.09.2026) hat auf Namespace-Pakete gezeigt: seit Python 3.3 ist ein
        # Verzeichnis OHNE `__init__.py` ein gueltiges Paket. Dieser Baum fuehrt zehn davon
        # (`scripts/`, `tests/`, `conformance/`, …). Gemessen an einem gebauten Fall: bei
        # vorhandenem `scripts/` meldete der Riegel `scripts/__init__.py` als fehlend — und gab
        # damit dieselbe Antwort wie fuer ein Verzeichnis, das WIRKLICH fehlt. Er konnte die
        # beiden Lagen nicht unterscheiden.
        #
        # Die Aufzaehlung von zwei Formen war also selbst der Fehler, nicht ihre Reihenfolge: die
        # Frage lautet "existiert dieses Modul in IRGENDEINER Form", und darauf antwortet auch ein
        # Verzeichnis mit Ja. (Erweiterungsmodule .so/.pyd waeren die vierte Form — dieser Baum
        # fuehrt gemessen keine, deshalb stehen sie hier als benannte Grenze und nicht im Code.)
        name = getattr(glied, "name", None)
        if isinstance(name, str) and name:
            stamm = name.replace(".", "/")
            formen = (f"{stamm}.py", f"{stamm}/__init__.py")
            if (wurzel / stamm).is_dir() or any((wurzel / rel).exists() for rel in formen):
                continue          # das Modul IST da — der Grund ist ein anderer
            for rel in formen:
                if _verteilung_kennt_den_ort(rel, wurzel):
                    return wurzel / rel
    return None


class _ModulDasFehlendeDateienEhrlichMeldet(pytest.Module):
    """Ein Testmodul, dessen Import an einer fehlenden Datei des Baums scheitern DARF.

    `pytest_make_collect_report` behandelt ein aus `collect()` geworfenes `Skipped` als
    uebersprungene Sammlung — das Modul erscheint als SKIP mit Grund, statt als Sammelfehler, der
    den ganzen Lauf abbricht. Es verschwindet also NICHT still; genau darauf kommt es an.
    """

    def collect(self):
        try:
            return super().collect()
        except Exception as fehler:  # noqa: BLE001 — die WIRKUNG entscheidet, nicht die Klasse
            # NUR FileNotFoundError, und die Datei muss WIRKLICH fehlen.
            #
            # Eine erste Fassung fing jeden `OSError`. Eine adversariale Gegenlesung hat daran DREI
            # Faelle ausgefuehrt, in denen die Datei EXISTIERT und trotzdem uebersprungen wurde:
            # `PermissionError` (vorhanden, unlesbar), `IsADirectoryError` (ein Verzeichnis steht,
            # wo eine Datei erwartet wird) und `NotADirectoryError` (eine ausgelieferte Datei wird
            # faelschlich als Verzeichnis behandelt). In allen dreien behauptete die Meldung "diese
            # Verteilung enthaelt das nicht" — eine falsche Tatsachenbehauptung ueber eine Datei,
            # die nachweislich da ist. Solche Fehler sind eine ANDERE Klasse und bleiben laut.
            datei = _fehlende_datei_aus(fehler)
            if datei is None:
                raise                  # kein FEHLEN im Baum: eine andere Klasse, bleibt laut
            rel = str(datei.resolve().relative_to(pathlib.Path(_REPO_ROOT).resolve())).replace("\\", "/")
            if _verteilung_sollte_enthalten(rel):
                raise                                # sollte mitgeliefert sein: Paketierungsfehler
            _UEBERSPRUNGEN_BEIM_IMPORT[self.path.name] = str(datei)
            pytest.skip(
                f"nicht ausgeliefert: der Import dieses Moduls braucht {datei!s}, das diese "
                f"Verteilung nicht enthaelt — N/A ausserhalb eines git-Checkouts "
                f"(PKG-2026-0718-01, deep gate L6-600-01)",
                allow_module_level=True)


def pytest_pycollect_makemodule(module_path, parent):
    if running_in_repo_checkout():
        return None                     # ein Checkout: alles wie bisher, reiner No-op
    return _ModulDasFehlendeDateienEhrlichMeldet.from_parent(parent, path=module_path)


def pytest_terminal_summary(terminalreporter, exitstatus, config):
    """Der Grund steht im LAUF, auch ohne `-rs`.

    Ein `1 skipped` ohne seinen Grund ist eine Zahl, die alles heissen kann. Die erste Fassung
    dieser Meldung hing an `pytest_report_header` — der laeuft VOR dem Sammeln, die Menge war dort
    immer leer, und es erschien nie eine Zeile. Gemessen an der Ausgabe des entpackten sdist:
    keine einzige.
    """
    if not _UEBERSPRUNGEN_BEIM_IMPORT:
        return
    terminalreporter.write_sep("-", "beim Import uebersprungen (nicht ausgeliefert)")
    for name in sorted(_UEBERSPRUNGEN_BEIM_IMPORT):
        terminalreporter.write_line(f"{name}: braucht {_UEBERSPRUNGEN_BEIM_IMPORT[name]}")
