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


def _manifest_verspricht(rel: str, wurzel: pathlib.Path = _REPO_ROOT) -> bool:
    """Does this distribution's own MANIFEST.in PROMISE this path (graft, include, recursive-include)?

    DEEP GATE Z195, FINDING L6-Z195-01 (P2, jury 3 of 3). The derived skip below counted every absent
    root-relative path as "the sdist deliberately prunes this". It never asked whether the distribution
    was supposed to carry the path. Measured with one appended line, `exclude
    examples/trust_policy_strict.json`, while `graft examples` still stood: the built sdist lacked the
    file, tests/test_trust_policy.py went from 47 passed to 47 skipped with the reason "repo-context
    test", and the whole shipped suite stayed rc=0. The import guard further down asks SOURCES.txt,
    but an `exclude` removes the path from SOURCES.txt as well, so that list cannot tell an intended
    omission from an accidental one. The allowlist can: a path under a `graft` line, named by an
    `include` line or matched by a `recursive-include` line was promised, and its absence is a
    packaging failure, never a reason to skip.

    WHY MANIFEST.in AND NOT A SECOND LIST. setuptools ships MANIFEST.in in every sdist, and it is the
    document that states the promise. Another list would be the same promise written twice.

    READ AS SETUPTOOLS READS IT (gate on this change, lenses 227-A and 227-B). The first version split
    each physical line on whitespace and matched with `fnmatch`, and a lens built four templates it read
    differently from setuptools 59 and 69: a `recursive-include` continued with a backslash promised
    nothing, so its absence was skipped again, the very defect this closes (227A-01); `fnmatch` lets `*`
    cross `/`, so `include docs/*.md` promised `docs/adr/x.md`, which setuptools does not ship (227A-03);
    words of an inline comment became patterns (227A-04). The lines are now read as setuptools'
    `read_template` reads them (`TextFile` with comments stripped, `\\#` kept, continuations joined,
    whitespace stripped, blank lines skipped), a line setuptools refuses (an unknown action, a wrong
    number of words) promises nothing, and the patterns match as setuptools matches them:
    `include`, `recursive-include` and `graft` through setuptools' own glob (`*` and `?` stay inside one
    path segment, `**` spans segments only where setuptools globs recursively, hidden files are NOT
    ignored), `global-include` through its `translate_pattern`. Proven against setuptools itself:
    `tests/fixtures/manifest_semantics/` carries vectors a real `build_sdist` produced.

    A NEGATIVE LINE DOES NOT WITHDRAW A PROMISE, and that is the design, not an omission (lens 227-A
    measured it as a difference from setuptools, 227A-02, and it is one). The defect this closes is an
    `exclude` that removes a file a `graft` promised; a reader that let the `exclude` win would call that
    file unpromised and skip it again. So `exclude`, `prune`, `recursive-exclude` and `global-exclude`
    are not read here. The cost is named: a path under a positive line that a negative line removes ON
    PURPOSE fails loudly from the sdist instead of skipping. In this repository no negative line cuts
    into a positive one except `global-exclude` for caches and build output (`__pycache__`, `*.py[cod]`,
    `*.so`, `*.rs`, `*.orig`), which no test reads.

    WHAT SETUPTOOLS ADDS ON ITS OWN is promised too (227B-01): the template itself (`manifest_maker`
    appends it to every sdist), `pyproject.toml`, `setup.cfg`, `setup.py`, `PKG-INFO`, the README
    variants and the license files. Without that, a test that binds "the sdist carries MANIFEST.in"
    was skipped by this very rule the moment MANIFEST.in was missing, because its module names the file.
    setuptools adds each of these only when the source tree has it (gate run 2, lens 227-A, 227-2-02:
    a project without `setup.py` ships none). A distribution cannot show which ones its source had, so
    all of them count as promised. That is the loud direction on purpose: a test naming one the project
    never had fails in a checkout just the same.

    AND WHAT BUILD_PY SHIPS (227-2-01): the modules of every package the project's package discovery
    finds, and the package data it declares, go into the sdist whatever the template says
    (`sdist._add_defaults_python`). This repository's template never mentions `src/`, so a test naming
    `src/proofbundle/agent_review.py` was skipped as repo-context the moment packaging lost that module.
    `_build_py_verspricht` reads `[tool.setuptools]` of pyproject.toml the way setuptools does, and the
    vectors hold it against a real `build_sdist`. NAMED LIMITS: automatic discovery (no `packages` and no
    `packages.find`), `py-modules`, `exclude-package-data` and extension modules are not read; a project
    relying on them gets no promise from this part, which is the old rule.

    NO BASIS, NO PROMISE. Without a readable MANIFEST.in and without a PKG-INFO (a throwaway tree in a
    test, say) nothing is promised and the old rule stands. A tree that carries PKG-INFO is a
    distribution, and a distribution without its template is itself the packaging failure."""
    import fnmatch  # noqa: PLC0415 - only on the from-sdist path
    wurzel = pathlib.Path(wurzel)
    try:
        text: str | None = (wurzel / "MANIFEST.in").read_text(encoding="utf-8")
    except OSError:
        text = None
    if text is None and not (wurzel / "PKG-INFO").is_file():
        return False
    pfad = [s for s in rel.split("/") if s not in ("", ".")]
    if rel in _SETUPTOOLS_VORGABEN or (len(pfad) == 1 and any(
            fnmatch.fnmatchcase(pfad[0], m) for m in _SETUPTOOLS_LIZENZMUSTER)):
        return True
    if _build_py_verspricht(pfad, wurzel):
        return True
    if text is None:
        return False
    for zeile in _manifest_zeilen(text):
        worte = zeile.split()
        befehl, args = worte[0], worte[1:]
        if befehl == "include" and args:
            if any(not m.endswith("/") and _glob_trifft(_segmente(m), pfad, rekursiv=False) for m in args):
                return True
        elif befehl == "recursive-include" and len(args) >= 2:
            if any(_glob_trifft(_segmente(args[0]) + ["**"] + _segmente(m), pfad, rekursiv=True)
                   for m in args[1:]):
                return True
        elif befehl == "graft" and len(args) == 1:
            # glob(dir) findet die Verzeichnisse, findall darunter JEDE Datei: mindestens ein Segment
            if _glob_trifft(_segmente(args[0]) + ["**", "*"], pfad, rekursiv=True):
                return True
        elif befehl == "global-include" and args:
            if any(_translate_pattern("/".join(["**"] + _segmente(m))).match(rel) for m in args):
                return True
    return False


#: What setuptools puts into every sdist without a template line: `manifest_maker.add_defaults` appends
#: the template, `sdist._add_defaults_standards` a README and `setup.py`, `_add_defaults_optional`
#: `setup.cfg` and (setuptools) `pyproject.toml`; PKG-INFO is written into the sdist root. Read from the
#: setuptools 69.5.1 source on 2026-09-26.
_SETUPTOOLS_VORGABEN = frozenset({"MANIFEST.in", "pyproject.toml", "setup.cfg", "setup.py", "PKG-INFO",
                                  "README", "README.rst", "README.txt", "README.md"})
#: setuptools' default `license_files` patterns, matched at the root only.
_SETUPTOOLS_LIZENZMUSTER = ("LICEN[CS]E*", "COPYING*", "NOTICE*", "AUTHORS*")


def _paketkonfiguration(wurzel: pathlib.Path) -> dict | None:
    """`[tool.setuptools]` of pyproject.toml ({} when absent), or None when the file cannot be read."""
    try:
        import tomllib  # noqa: PLC0415
    except ModuleNotFoundError:            # Python 3.10, see _projektname
        import tomli as tomllib  # noqa: PLC0415
    try:
        daten = tomllib.loads((pathlib.Path(wurzel) / "pyproject.toml").read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return None
    werkzeug = daten.get("tool")
    konf = werkzeug.get("setuptools") if isinstance(werkzeug, dict) else None
    return konf if isinstance(konf, dict) else {}


def _paket_von(pfad: list[str], konf: dict, wurzel: pathlib.Path,
               angefragt: str | None = None) -> tuple[str, int] | None:
    """(dotted package name, number of path segments of its directory) if the directory holding the
    last segment of `pfad` is a package setuptools would build, else None.

    `packages.find` as `setuptools.discovery.PackageFinder._find_iter` (69.5.1) walks: no directory with
    a dot in its name, with `namespaces = false` every directory needs an `__init__.py`, `include` and
    `exclude` are fnmatch patterns over the dotted name (`ez_setup` and `*__pycache__` are always
    excluded), and a directory under an exclude written `name*` or `name.*` is not descended into.
    An explicit `packages` list is read with `package-dir`.

    `angefragt` is the path the caller really asks about, when `pfad` is a probe built from it. A
    missing `__init__.py` counts as present only when it IS that path: an absent package file is
    promised, which is the loud direction. The probe for package data builds `<dir>/__init__.py`
    itself, and the first version compared the probe with itself, so a directory without
    `__init__.py` under `namespaces = false` read as a package and its data as promised (gate run 3,
    measured against a real sdist setuptools built without that directory)."""
    import fnmatch  # noqa: PLC0415
    pakete = konf.get("packages")
    if isinstance(pakete, list):
        paketwurzel = konf.get("package-dir") if isinstance(konf.get("package-dir"), dict) else {}
        for name in pakete:
            if not isinstance(name, str):
                continue
            ort = paketwurzel.get(name)
            if not isinstance(ort, str):
                basis = paketwurzel.get("", "")
                ort = "/".join(_segmente(basis if isinstance(basis, str) else "") + name.split("."))
            teile = _segmente(ort)
            if pfad[:len(teile)] == teile and len(pfad) == len(teile) + 1:
                return name, len(teile)
        return None
    finden = pakete.get("find") if isinstance(pakete, dict) else None
    if not isinstance(finden, dict):
        return None                                   # automatic discovery: not read (named limit)
    orte = finden.get("where", ["."])
    einschluss = finden.get("include", ["*"])
    ausschluss = ["ez_setup", "*__pycache__"] + list(finden.get("exclude", []))
    namensraeume = finden.get("namespaces", True) is not False
    for ort in (orte if isinstance(orte, list) else []):
        basis = _segmente(ort) if isinstance(ort, str) else None
        if basis is None or pfad[:len(basis)] != basis:
            continue
        verzeichnisse = pfad[len(basis):-1]
        if not verzeichnisse:
            continue
        gueltig = True
        for k in range(1, len(verzeichnisse) + 1):
            teil, name = verzeichnisse[k - 1], ".".join(verzeichnisse[:k])
            init = "/".join(basis + verzeichnisse[:k] + ["__init__.py"])
            if "." in teil or not (namensraeume or (pathlib.Path(wurzel) / init).is_file()
                                   or init == (angefragt if angefragt is not None else "/".join(pfad))):
                gueltig = False
                break
            if k < len(verzeichnisse) and (f"{name}*" in ausschluss or f"{name}.*" in ausschluss):
                gueltig = False                            # setuptools does not descend here
                break
        name = ".".join(verzeichnisse)
        if (gueltig and any(fnmatch.fnmatchcase(name, m) for m in einschluss if isinstance(m, str))
                and not any(fnmatch.fnmatchcase(name, m) for m in ausschluss if isinstance(m, str))):
            return name, len(basis) + len(verzeichnisse)
    return None


def _build_py_verspricht(pfad: list[str], wurzel: pathlib.Path) -> bool:
    """Would setuptools' `build_py` put this path into the sdist without a template line: a module
    (`*.py`) directly in a package it builds, or a file its `package-data` names for that package?"""
    konf = _paketkonfiguration(wurzel)
    if not konf or not pfad:
        return False
    # the package that holds the file directly: a module, or package data at the package's top level
    treffer = _paket_von(pfad, konf, wurzel)
    if treffer is not None and pfad[-1].endswith(".py"):
        return True
    daten = konf.get("package-data") if isinstance(konf.get("package-data"), dict) else {}
    # package data may lie below its package: try every enclosing directory as the package
    for tiefe in range(len(pfad) - 1, 0, -1):
        paket = _paket_von(pfad[:tiefe] + ["__init__.py"], konf, wurzel, angefragt="/".join(pfad))
        if paket is None:
            continue
        name, laenge = paket
        muster = [m for schluessel in (name, "*", "") for m in (daten.get(schluessel) or [])
                  if isinstance(m, str)]
        if any(_glob_trifft(_segmente(m), pfad[laenge:], rekursiv=True) for m in muster):
            return True
    return False


def _manifest_zeilen(text: str) -> list[str]:
    """The logical lines of a MANIFEST.in as setuptools' `read_template` gets them: `TextFile` with
    strip_comments, skip_blanks, join_lines, lstrip_ws, rstrip_ws and collapse_join all on. A `#` starts a
    comment unless a backslash precedes it (then `\\#` becomes `#`); a comment-only line is dropped BEFORE
    it can end a continuation; a line ending in a backslash joins the next, whose leading whitespace is
    dropped; a continuation at the end of the file stands as it is."""
    ergebnis: list[str] = []
    aufbau = ""
    for roh in text.splitlines(keepends=True) + [None]:
        zeile = roh
        if zeile is not None:
            pos = zeile.find("#")
            if pos != -1:
                if pos == 0 or zeile[pos - 1] != "\\":
                    zeile = zeile[:pos] + ("\n" if zeile.endswith("\n") else "")
                    if zeile.strip() == "":
                        continue
                else:
                    zeile = zeile.replace("\\#", "#")
        if aufbau:
            if zeile is None:
                ergebnis.append(aufbau)
                break
            zeile = aufbau + zeile.lstrip()
            aufbau = ""
        elif zeile is None:
            break
        zeile = zeile.strip()
        if not zeile:
            continue
        if zeile.endswith("\\"):
            aufbau = zeile[:-1]
            continue
        ergebnis.append(zeile)
    return ergebnis


def _segmente(muster: str) -> list[str]:
    return [s for s in muster.split("/") if s not in ("", ".")]


def _glob_trifft(muster: list[str], pfad: list[str], *, rekursiv: bool) -> bool:
    """Would setuptools' glob (`setuptools/glob.py`, hidden files NOT ignored) yield this path?

    Segment by segment with `fnmatch`, which is what its `glob1` does; `**` is zero or more whole
    segments only where setuptools globs with `recursive=True` (`recursive-include`, and the walk under a
    `graft`), elsewhere it is an ordinary one-segment pattern."""
    import fnmatch  # noqa: PLC0415
    import functools  # noqa: PLC0415

    @functools.lru_cache(maxsize=None)
    def ab(i: int, j: int) -> bool:
        if i == len(muster):
            return j == len(pfad)
        if rekursiv and muster[i] == "**":
            return any(ab(i + 1, k) for k in range(j, len(pfad) + 1))
        return j < len(pfad) and fnmatch.fnmatchcase(pfad[j], muster[i]) and ab(i + 1, j + 1)
    return ab(0, 0)


def _translate_pattern(glob: str):
    """`setuptools.command.egg_info.translate_pattern` (69.5.1), which `global-include` uses. It differs
    from the glob above on purpose, because setuptools differs: a character class is taken literally
    (`[a-c]` is the set of `a`, `-` and `c`), and `**` spans segments wherever it stands."""
    import re  # noqa: PLC0415
    pat, chunks = "", glob.split("/")
    for c, chunk in enumerate(chunks):
        last = c == len(chunks) - 1
        if chunk == "**":
            pat += ".*" if last else "(?:[^/]+/)*"
            continue
        i = 0
        while i < len(chunk):
            char = chunk[i]
            if char == "*":
                pat += "[^/]*"
            elif char == "?":
                pat += "[^/]"
            elif char == "[":
                j = i + 1
                if j < len(chunk) and chunk[j] == "!":
                    j += 1
                if j < len(chunk) and chunk[j] == "]":
                    j += 1
                while j < len(chunk) and chunk[j] != "]":
                    j += 1
                if j >= len(chunk):
                    pat += re.escape(char)
                else:
                    inner = chunk[i + 1:j]
                    klasse = ""
                    if inner[0] == "!":
                        klasse, inner = "^", inner[1:]
                    pat += "[%s]" % (klasse + re.escape(inner))
                    i = j
            else:
                pat += re.escape(char)
            i += 1
        if not last:
            pat += "/"
    return re.compile(pat + r"\Z", flags=re.MULTILINE | re.DOTALL)


def modul_ist_repo_kontext(pfad: pathlib.Path, wurzel: pathlib.Path = _REPO_ROOT) -> bool:
    """True iff this test module reads a root-relative path that is ABSENT here.

    Absence is the whole signal, so an unreadable module is NOT silently treated as fine: it cannot be
    shown to be package-only, and outside a checkout the safe answer is to skip it.

    A path that is absent because it has not been BUILT is not the same signal (see
    `_ist_bauartefakt`) and does not count. Neither is a path the distribution's MANIFEST.in promised
    (see `_manifest_verspricht`): its absence is a packaging failure, and the module runs and fails.
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
    fehlend = [rel for rel in _wurzel_relative_pfade(quelle, tiefe)
               if not (wurzel / rel).exists() and not _ist_bauartefakt(wurzel, rel)]
    # A PROMISED ABSENCE WINS. A module that reads a pruned path AND a promised one that is missing
    # must not be skipped for the first, or the second, a packaging failure, would vanish into the
    # same skip it is being told apart from.
    if any(_manifest_verspricht(rel, wurzel) for rel in fehlend):
        return False
    return bool(fehlend)


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


# ── Which SOURCES.txt is THIS distribution's: one selector for every reader under tests/ ─────────
#
# FOUR READERS ASKED THE SAME QUESTION and answered it the same way: the two functions below, the
# class guard in `tests/test_kein_blanker_import_eines_nicht_ausgelieferten.py` and the two-truths
# case in `tests/test_bare_install_degrades_to_clean_skips.py` each took the first non-empty
# SOURCES.txt in alphabetical glob order. Order is not identity. An adversarial lens showed on
# 2026-09-24 that an egg-info sorting before the real one decides the answer, and measured on
# 2026-09-25 the main checkout carries exactly such a stranger: beside `src/proofbundle.egg-info`
# lies an `UNKNOWN.egg-info` from 2026-08-08 with 26 scripts. The order picked the right one only
# because the one-level glob is searched first.
#
# THE RULE: a SOURCES.txt belongs to this distribution when the PKG-INFO beside it names the
# project `pyproject.toml` names, compared as normalised distribution names (PEP 503). Every sdist
# carries both files. THREE OUTCOMES: exactly one non-empty list of this project is the answer;
# none is no basis; more than one is no basis as well, because choosing between two lists of one
# project is the guess this replaces. What a reader does without a basis stays its own rule.
#
# IT LIVES HERE AND NOT IN A HELPER MODULE, on purpose: tests copy this file alone into throwaway
# trees (`tests/test_sammelabbruch_vor_dem_import.py::_baum`), and a conftest that needs a sibling
# file would fail to load there. The two checkout readers load this file by path instead.


def _normalisierter_name(name: str) -> str:
    import re  # noqa: PLC0415
    return re.sub(r"[-_.]+", "-", name).lower()


def _projektname(wurzel: pathlib.Path) -> str | None:
    """`name` under `[project]` in pyproject.toml, or None when it cannot be read.

    PARSED AS TOML, NOT SEARCHED AS TEXT. The first version used two regular expressions, and a
    review lens refuted it the same day: a comment after the `[project]` header hid the name, so
    one real list became "no basis", and a `name = ...` line inside a multi-line string before the
    real key picked another distribution's list. Searching text for a structure is the class this
    selector replaces. `tomllib` is in the standard library from 3.11; on 3.10 pytest itself
    depends on `tomli`, and this file is only ever loaded where pytest runs.
    """
    try:
        import tomllib  # noqa: PLC0415
    except ModuleNotFoundError:            # Python 3.10
        import tomli as tomllib  # noqa: PLC0415
    try:
        daten = tomllib.loads((pathlib.Path(wurzel) / "pyproject.toml").read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return None
    projekt = daten.get("project")
    name = projekt.get("name") if isinstance(projekt, dict) else None
    return name if isinstance(name, str) and name else None


def _eintraege_von(liste: pathlib.Path) -> set[str] | None:
    try:
        return {z.strip() for z in liste.read_text(encoding="utf-8").splitlines() if z.strip()}
    except OSError:
        return None


def _quellenliste_waehlen(wurzel: pathlib.Path) -> tuple[pathlib.Path | None, str]:
    """(the SOURCES.txt of this project, "") or (None, why there is no basis)."""
    wurzel = pathlib.Path(wurzel)
    projekt = _projektname(wurzel)
    if projekt is None:
        return None, "no [project] name readable in pyproject.toml, so no list can be attributed"
    kandidaten = sorted(set(wurzel.glob("*/*.egg-info/SOURCES.txt"))
                        | set(wurzel.glob("*.egg-info/SOURCES.txt")))

    def _name(liste: pathlib.Path) -> str:
        try:
            for zeile in (liste.parent / "PKG-INFO").read_text(
                    encoding="utf-8", errors="replace").splitlines():
                if zeile.startswith("Name:"):
                    return zeile.split(":", 1)[1].strip()
        except OSError:
            pass
        return ""

    zugeordnet = [k for k in kandidaten
                  if _normalisierter_name(_name(k)) == _normalisierter_name(projekt)]
    # ONE ENTRY PER FILE, not per path: a symlink to the same egg-info is one list, and counting it
    # twice turned one real list into a false ambiguity (review lens, 2026-09-25).
    #
    # ATTRIBUTED FIRST, DEDUPLICATED AFTER, and the order is the point. The first version merged
    # aliases by resolved file before reading any PKG-INFO and kept whichever path sorted first.
    # Codex measured on 2026-09-25 what that does: a foreign `aaa/y.egg-info` whose SOURCES.txt
    # links to this project's list sorts first, only the foreign alias survives, and the real list
    # is gone, so path order decided identity again. Each path is attributed by the PKG-INFO beside
    # it, and only aliases that all belong to this project collapse into one.
    je_datei: dict[pathlib.Path, pathlib.Path] = {}
    for k in zugeordnet:
        je_datei.setdefault(k.resolve(), k)
    eigene = list(je_datei.values())
    brauchbar = [k for k in eigene if _eintraege_von(k)]
    if not brauchbar:
        fremde = [str(k.relative_to(wurzel)) for k in kandidaten if k not in zugeordnet]
        return None, (f"no non-empty SOURCES.txt of {projekt} in this tree"
                      + (f"; lists of other distributions ignored: {fremde}" if fremde else ""))
    if len(brauchbar) > 1:
        return None, (f"{len(brauchbar)} non-empty SOURCES.txt of {projekt}: "
                      f"{[str(k.relative_to(wurzel)) for k in brauchbar]}; picking one is a guess")
    return brauchbar[0], ""


def _verteilungsliste(wurzel: pathlib.Path) -> tuple[set[str] | None, str]:
    """The entries of the list `_quellenliste_waehlen` chose, or (None, why there is no basis)."""
    liste, grund = _quellenliste_waehlen(wurzel)
    if liste is None:
        return None, grund
    eintraege = _eintraege_von(liste)
    if not eintraege:
        return None, f"{liste} became unreadable or empty after it was chosen"
    return eintraege, ""


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

    WHICH LIST is decided by `_quellenliste_waehlen`, the one selector for all four readers of
    SOURCES.txt under tests/. It takes the list whose PKG-INFO names this project, not the first in
    alphabetical order; an ambiguous tree counts as no basis, which here means staying loud.
    """
    eintraege, _grund = _verteilungsliste(pathlib.Path(wurzel))
    if eintraege is None:
        return True                                # no basis -> do not give way
    return rel in eintraege


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
    eintraege, _grund = _verteilungsliste(pathlib.Path(wurzel))
    if eintraege is None:
        return False                               # no basis -> stays loud, as before
    return any(e.startswith(kopf + "/") for e in eintraege)


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
