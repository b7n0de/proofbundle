"""Auto-enumerated never-raise class-closure test (adversarial deep-gate v4 centerpiece, proof-of-concept in-repo).

The round-by-round adversarial re-audits converged 11 -> 3 -> 2 -> 1 but never to zero in one round because the fix
target was "the one repro" and the SURFACE FAMILY was never made an explicit, machine-checked denominator. This
test IS that denominator: it AUTO-DISCOVERS every public never-raise surface (verify_*/check_*/load_*/decode_*/
count_*/recompute_*/receipt_canonical_root/sd_jwt_hidden_count) across the package via ``__all__``/``inspect``,
and fuzzes each surface's untrusted PRIMARY argument with every wrong type. A surface that terminates outside the
accepted typed set (a returned verdict, or a ``ProofBundleError`` / ``ValueError``) — i.e. a raw
``AttributeError`` / ``TypeError`` / ``RecursionError`` / ``KeyError`` / ``IndexError`` — is an escape.

Unlike the hand-curated ``test_never_raise_primary_arg_property.py`` (precise per-function args, 16 surfaces),
this test's value is the AUTO-ENUMERATED denominator: a newly-added public verify/check surface is automatically
in scope, so it fails HERE the moment it forgets a primary-arg guard, not in a future re-gate round. The empirical
one-pass sweep at authoring time: 43 surfaces x 8 bad primaries = 344 calls, zero escapes.
"""
import importlib
import inspect
import re
import unittest

from proofbundle.errors import ProofBundleError

# Modules that expose a public never-raise verify/check/load surface over untrusted input.
_MODULES = [
    "bundle", "sdjwt", "sdjwt_vc", "sdjwt_issue", "evalclaim", "kbjwt", "statuslist", "persample",
    "tlogproof", "hf_evals", "checkpoint", "merkle", "policy", "anchors", "dsse", "intoto", "decision",
    "outcome", "verification_summary", "relation_statement", "trust_pack", "run_ledger", "evidence_pack",
    "renewal", "hashalg", "prereg", "evalcard",
    # adversarial re-audit round 8 (v4 denominator broadening — the completeness critic found these were outside
    # the sweep, hiding the decision/outcome/subject_binding RecursionError class):
    "subject_binding", "relation", "assurance", "automation_verdict", "beacon", "public_transparency",
    "signature", "policy_profiles", "canonical",
    # 2026-08-16: the population was hand-maintained and had drifted 14 modules behind the package.
    # A coverage guard (tests/test_never_raise_population_guard.py) now derives the expected set from
    # the tree, so a module added to the package can no longer sit outside this property unnoticed.
    # These seven carried 11 matching surfaces the property had never entered.
    "anchors_chia", "anchors_markovian", "anchors_ots", "anchors_rfc3161", "anchors_rootcommit",
    "emit", "pqsig",
    # 2026-09-05: CAP-1 (draft-hillier-coverage-attestation-00) als Paketfunktion, Thema 7 Teil B.
    # check_cap1_document ist never-raise per Vertrag; load_cap1_document wirft die TYPISIERTE
    # Cap1DuplicateKey(ValueError) bei doppelten Namen — fail-closed, in _ACCEPTED.
    "cap1",
    # 2026-08-17: the coverage guard itself globbed the top level only, so a module inside a
    # SUBPACKAGE was outside the ground truth — and therefore outside the guard that exists to prove
    # nothing is outside. Measured after widening it to `rglob`: 50 modules -> 56, and of the six new
    # ones exactly this one carries a matching surface. It ships, it has a documented import path,
    # and it is its own CLI subcommand (`verify-enclave`).
    "experimental.enclave",
    # 2026-08-31: agent-review/v0.1. Der Populations-Riegel meldete drei Flaechen ausserhalb der
    # Eigenschaft, und er hatte recht — von Hand gemessen fiel eine ROHE TypeError aus
    # `verify_agent_review`, wenn ein Produzent einen unhashbaren Wert im Feld `assurance`
    # liefert (`unhashable type: 'list'` statt ok=False). Der Defekt ist behoben; die Fläche
    # gehoert jetzt in die Population, damit die Frage nicht wieder nur von Hand gestellt wird.
    "agent_review",
    # 2026-09-03: C5 des anbieterbezeugten Inferenz-Wegs. Der Populations-Riegel meldete
    # `check_on_receipt` als Flaeche ausserhalb der Eigenschaft, und er hatte recht — die erste
    # Fassung warf `BundleFormatError` auf eine Nicht-Abbildung. Wer nach einem Urteil greift, muss
    # ein Urteil bekommen; die strikte Schicht bleibt `evidence_digest`, die Grenze benennt jetzt
    # `evidence.malformed` und faellt fail-closed auf `attestation_failure`.
    "experimental.attested_inference",
]
# Broadened name family (round 8): the predicate-validation surfaces a relying party actually calls
# (validate_*/require_valid_*/require_derived_*/classify_*/derive_*) were entirely outside the old pattern.
# Round 4 (v4): + the verdict families evaluate_*/audit_*/automation_*/evidence_ladder_* — the G2 gap the
# round-4 re-gate proved (evaluate_policy/evaluate_public_transparency/automation_summary/evidence_ladder_*).
_NAME_PATTERN = re.compile(
    r"^(verify_|check_|load_|decode_|count_|recompute_|receipt_canonical|sd_jwt_hidden"
    # Explizit wie `receipt_canonical`/`sd_jwt_hidden`: ein Praedikat ueber einen vom AUFRUFER
    # gelieferten Wert, dessen Name in keine Praefix-Familie faellt. Es MUSS urteilen statt zu
    # crashen — der Riegel unten hat es beim ersten Lauf gemeldet, das ist die Entscheidung.
    r"|expected_origin_wellformed"
    # 2026-09-05, CAP-1 Teil B: `is_conformant` ist ein Praedikat ueber ein vom Aufrufer geliefertes
    # Dokument (untrusted) und muss urteilen statt zu crashen — in den Nenner, wie das Vorbild eine
    # Zeile darueber. `check_cap1_document`/`load_cap1_document` fallen ueber ihre Praefixe hinein.
    r"|is_conformant"
    # 2026-08-18, Deep-Gate-Linse 2 Befund 1: `split_key_binding` und `holder_key_from_cnf`
    # standen in der Ausschlussmenge unter ERZEUGER ("baut aus eigenen, bereits geprueften
    # Werten"). Das traf auf sie nie zu — beide nehmen ihr PRIMAERargument aus einer
    # halter-gelieferten Praesentation und sind damit Parser untrusted Eingabe. Gemessen
    # verliessen 7 von 7 bzw. 6 von 6 feindliche Formen sie als roher AttributeError. Sie
    # gehoeren in den NENNER, nicht daneben; die Typboeden sitzen jetzt an der Quelle.
    r"|split_key_binding|holder_key_from_cnf"
    # `require_` statt `require_valid_|require_derived_` (2026-08-18). DIE URSPRUENGLICHE
    # BEGRUENDUNG HIER WAR FALSCH und ist korrigiert (Deep-Gate-Linse 1, Befund 3): sie nannte
    # einen Pruefer `require_wellformed_expected_origin` als Anlass. Den gibt es im Baum NICHT —
    # er war der erste Entwurf und wurde durch das BERICHTENDE `expected_origin_wellformed`
    # ersetzt, weil der repo-eigene Test `OriginVergleichIstExakt` das harte Ablehnen widerlegte.
    # Die Begruendung blieb stehen und lehrte damit einen Gegenstand, den es nicht gibt.
    # GEMESSEN, was die Oeffnung wirklich bewirkt: Nenner 91 -> 98, und alle sieben Zugaenge sind
    # `cosign_*`/`expected_origin_wellformed` — kein einziges `require_*` kommt hinzu. Die
    # Verallgemeinerung ist heute WIRKUNGSLOS und bleibt trotzdem stehen: sie ist die richtige
    # Form fuer die Familie (ein `require_`-Pruefer gehoert hier hin, sobald es einen gibt), und
    # sie einzuengen waere eine Aenderung ohne Anlass. Was nicht bleiben durfte, ist eine
    # Begruendung, die auf etwas Nichtexistierendes zeigt.
    r"|validate_|require_|classify_|derive_"
    r"|evaluate_|audit_|automation_|evidence_ladder_"
    # Round 5 (2026-08-18, Befund PB-COSIGN-SIGN-SIDE-NEVER-RAISE-COVERAGE-01): die cosign_*-Seite
    # war NIE im Nenner. Sie ist keine reine Erzeuger-Seite: `cosign_checkpoint` und
    # `cosign_checkpoint_mldsa` nehmen eine vom LOG gelieferte, also untrusted, Note entgegen —
    # genau die Eingabe, gegen die diese Eigenschaft schuetzt. Dass vier Nachbarn derselben Klasse
    # (iter1-4 des 4.0.0-Gates) nacheinander durchrutschten, hing an diesem Loch im Nenner, nicht
    # an vier unabhaengigen Fehlern.
    r"|cosign_)")

# ACCEPTED terminations: a returned value, or a TYPED fail-closed error. ProofBundleError covers
# BundleFormatError / BudgetExceeded / PQUnavailable / UnsupportedError / CanonicalizerUnavailable / PolicyError
# / SdjwtVcError / EvalClaimError-as-PBError; ValueError covers EvalClaimError + the rfc8785 domain family.
# `FileNotFoundError` added 2026-08-16 — and the FIRST attempt added `OSError`, which was wrong in a
# way worth recording, because the mistake and the claim contradicted each other. The commit text said
# "widens by a single measured case, not by a guess"; the mechanism widened the whole hierarchy.
# `OSError` is the base class of `PermissionError`, `TimeoutError`, `BrokenPipeError` and more. A
# `PermissionError` on an anchor file is not a missing file — it can be an indicator that something
# blocked access, and swallowing it silently is fail-open on exactly the axis this property defends.
# The counter-read caught it (un, REJECT, 2026-08-16): admit the measured case, not its family.
#
# Why this ONE subclass is admissible: the contract forbids a surface CRASHING INSTEAD OF DECIDING —
# the type-confusion signatures in `_FORBIDDEN`. A loader reporting "this path does not exist" is the
# opposite: fail-closed, informative, and it produces no verdict a relying party could mistake for a
# pass. Measured across all 90 discovered surfaces and the full corpus: ZERO forbidden escapes and
# exactly ONE unclassified case (`emit.load_signer` on `b"bytes-not-str"` → `FileNotFoundError`).
#
# Any OTHER `OSError` subclass therefore still lands in the unclassified branch below and is REPORTED,
# which is the point: the next one gets a decision, not an inherited pass.
_ACCEPTED = (ProofBundleError, ValueError, FileNotFoundError)
# FORBIDDEN raw terminations = the type-confusion crash signatures a public verify surface must never emit.
_FORBIDDEN = (AttributeError, TypeError, RecursionError, KeyError, IndexError, UnicodeDecodeError, MemoryError)

_BAD_PRIMARIES = [None, 123, 1.5, True, b"bytes-not-str", ["a", "list"], {"k": "v"}, ("t", "u")]


def _discover_surfaces():
    """Every public never-raise surface DEFINED in one of the modules (not merely imported into it).

    Round 8 (v4): the name pattern is the public-surface signal — do NOT gate on ``__all__``. The completeness
    critic found ``evalclaim.load_claim_text`` is a documented never-raise ``load_`` primitive that is NOT in
    ``evalclaim.__all__``, so the old ``__all__`` gate silently dropped it from the denominator. A non-underscore
    function whose name matches the never-raise family IS in scope regardless of ``__all__``."""
    out = []
    for mod_name in _MODULES:
        try:
            mod = importlib.import_module(f"proofbundle.{mod_name}")
        except Exception:  # noqa: BLE001 - an optional-extra module that will not import is out of scope here
            continue
        for name, fn in inspect.getmembers(mod, inspect.isfunction):
            if fn.__module__ != mod.__name__ or name.startswith("_"):
                continue
            if _NAME_PATTERN.match(name):
                out.append((mod_name, name, fn))
    return out



# ── Der Nenner darf nicht mehr STILL altern (2026-08-18, Befund PB-COSIGN-SIGN-SIDE-…-01) ──────────
#
# WAS PASSIERT IST: `_NAME_PATTERN` ist eine Allowlist von Namensfamilien. Die gesamte `cosign_*`-
# Seite stand nie darin — und nichts sagte es. Der Bodentest unten wacht nur gegen KOLLAPS des
# Nenners (>= 65), nicht gegen das Fehlen einer ganzen Familie: 91 entdeckte Surfaces sehen gesund
# aus, auch wenn sechs Verbraucher-Surfaces daneben liegen. Vier Nachbarn derselben Klasse sind
# waehrend des 4.0.0-Gates nacheinander durchgerutscht (iter1-4); das war kein Zufall, sondern
# dieses Loch.
#
# WAS DER RIEGEL TUT: jede oeffentliche Funktion der gescannten Module muss ENTWEDER im Nenner
# stehen ODER hier namentlich als ausserhalb gefuehrt sein. Eine NEUE oeffentliche Funktion, die
# keins von beidem ist, laesst den Test FAILEN — sie erzwingt eine Entscheidung, statt lautlos
# ausserhalb zu liegen. Das ist die positive Regel: nicht "was ist gefaehrlich" aufzaehlen
# (unvollstaendig per Konstruktion), sondern "was ist geprueft" gegen "was ist bewusst nicht".
#
# WARUM DIESE 122 NAMEN AUSSERHALB LIEGEN — nach Familie, nicht pauschal:
#   build_* / emit_* / sign_* / issue_* / create_* / save_* / to_* / export_*  ERZEUGER. Sie bauen
#       aus EIGENEN, bereits geprueften Werten ein Artefakt. Ein TypeError bei falschem Aufrufer-
#       Argument ist dort die richtige Antwort, nicht der Defekt, den diese Eigenschaft sucht.
#   policy_* / profile-/template-Helfer / list_* / describe_* / explain_* / lint_*  BESCHREIBEND,
#       ohne Verdikt fuer eine verlassende Partei.
#   *_proven / *_trusted_by_role / *_violations / *_warning / *_gaps  URTEILE ueber bereits
#       validierte Strukturen — ihre Eingabe hat die never-raise-Schicht schon passiert.
#   Krypto-/Kodier-Primitive (pae, clvm_atom_hash, eip191_recover_address, key_id, vkey, …)
#       arbeiten auf Bytes mit engem Vertrag; sie sind ueber ihre Aufrufer abgedeckt.
# WER EINE DIESER FUNKTIONEN ZU EINEM VERBRAUCHER MACHT (untrusted Eingabe), nimmt sie hier heraus
# und in den Nenner — genau diese Bewegung war bei `cosign_*` faellig und fand nie statt.
_OUT_OF_SCOPE = frozenset({
    # 2026-09-04, Teil A2 des v0.2-Vorgabewechsels. DREI neue oeffentliche Flaechen, und nur EINE
    # gehoert hierher — die Trennung ist die Entscheidung, die dieser Riegel erzwingt:
    #
    # `standard_policy_path` nimmt GAR KEINE Eingabe entgegen. Sie kann keine unvertraute Eingabe
    # bekommen, also kann sie die Eigenschaft nicht verletzen; ein Eintrag im Nenner waere eine
    # Pruefung ohne Gegenstand. Sie liegt ausserhalb, weil sie NICHTS konsumiert.
    #
    # `load_policy` und `evaluate_limitation_policy` stehen ausdruecklich NICHT hier: beide nehmen
    # Aufrufer-Eingabe (einen Pfad, ein Predicate, eine Policy) und muessen urteilen statt zu
    # crashen. Beide haben die Eigenschaft beim ersten Lauf verletzt — `load_policy` mit rohem
    # TypeError ueber sieben Typen (vom Riegel gefangen), `evaluate_limitation_policy` mit rohem
    # AttributeError ueber 72 Kombinationen. Beide sind behoben.
    #
    # KORREKTUR am selben Tag, von einer Gegenlese-Linse gemessen: hier stand zuerst, der Riegel
    # probiere "nur einstellige Flaechen". Das trifft den Mechanismus NICHT. Er ruft mehrstellige
    # Funktionen sehr wohl auf (`if not params: continue` greift nur bei NULL Parametern) — aber
    # nur ARGUMENT 0 bekommt den feindlichen Wert, jeder andere Pflichtparameter einen plausiblen
    # Stub, und Parameter mit Default werden gar nicht erst gesetzt (Zeilen 380-388). Die Groesse,
    # die zaehlt, ist die POSITION, nicht die Stelligkeit. Gemessen: 87 von 114 Flaechen sind
    # mehrstellig, und an Position >= 1 entkommen 16 rohe TypeError — alle in
    # `check_on_receipt` (request_bytes/response_bytes). Diese Grenze ist von Anfang an im
    # Modulkopf dokumentiert ("untrusted PRIMARY argument"); falsch war meine Paraphrase, nicht
    # der Riegel.
    "standard_policy_path",
    # 2026-09-03, C5 des anbieterbezeugten Inferenz-Wegs — VIER Funktionen, DREI davon hier, und
    # die Trennung ist der Zwei-Schichten-Vertrag dieses Hauses, nicht Bequemlichkeit.
    #
    # `check_on_receipt` ist die GRENZE und steht deshalb NICHT hier: sie konsumiert die Evidenz
    # eines fremden Anbieters und muss urteilen statt zu crashen. Sie faellt ueber `check_` in
    # `_NAME_PATTERN` und hat die Eigenschaft beim ersten Lauf sofort verletzt (roher
    # RecursionError bei tiefer Verschachtelung, behoben mit `_MAX_DEPTH`).
    #
    # `evidence_digest` und `normalise_provider_evidence` sind die STRIKTE Schicht darunter. Sie
    # werfen `BundleFormatError` auf eine Nicht-Abbildung, und das soll so bleiben: genau EINE
    # Normalisierungsgrenze liegt dazwischen, und das ist `check_on_receipt`, das den Wurf faengt
    # und als `evidence.malformed` benennt. Zwei Grenzen waeren zwei Wahrheiten darueber, was ein
    # Fehler ist.
    "evidence_digest",
    "normalise_provider_evidence",
    # `binding_present` ist ein PRAEDIKAT und wirft schon heute nicht — es gibt bei jeder
    # untauglichen Eingabe False zurueck. Es hier zu fuehren ist eine bewusste Entscheidung gegen
    # die bequemere: es in `_NAME_PATTERN` aufzunehmen haette bedeutet, das Muster um seinen Namen
    # zu erweitern, und ein Muster, das je Fund um den gefundenen Namen waechst, misst am Ende die
    # Liste seiner Funde statt eine Eigenschaft.
    "binding_present",
    # `counts_as_own_domain` liest UNSER eigenes Pruefergebnis, keine fremden Bytes. Es ist die
    # Zaehlregel eines Panels, nicht eine Pruefflaeche.
    "counts_as_own_domain",
    # 2026-08-31, agent-review/v0.1 — NEUN Funktionen, EINE Entscheidung, und sie ist inhaltlich.
    # Der never-raise-Vertrag gilt der Seite, die FREMDE Bytes konsumiert: `verify_agent_review`
    # faengt ihn ueber `_NAME_PATTERN` und gehoert dort hin. Die neun hier sind ERZEUGER-seitig —
    # sie bekommen UNSERE Daten und muessen bei Unfug LAUT werfen, weil das die Kernentscheidung
    # des Predicates ist: eine zu hohe Assurance-Stufe, eine externe Zeitbehauptung ohne Beleg
    # oder ein doppelter Offenlegungsblock werden BEIM ERZEUGEN verweigert, nicht beim Pruefen
    # gemeldet. Ein Receipt, das nicht gebaut werden kann, erreicht keinen Leser.
    #
    # EHRLICHE GRENZE, die zu dieser Einstufung gehoert: `body_core_bytes` und `body_core_digest`
    # KOENNEN von einem Konsumenten ueber einen fremden PR-Rumpf gerufen werden. Sie werfen dann
    # `AgentReviewError` bei einem mehrdeutigen Block — fail-closed und dokumentiert. Wer sie so
    # benutzt, faengt diese Ausnahme; `verify_agent_review` selbst ruft sie NICHT.
    #
    # NACHTRAG 01.09.2026, P0.2 und P0.4: drei weitere Funktionen, dieselbe Entscheidung aus
    # demselben Grund. `disclosure_core_bytes`/`disclosure_core_digest` sind die Schwestern von
    # `body_core_*` und teilen deren Grenze woertlich — sie werfen fail-closed bei einem
    # mehrdeutigen Block, und `verify_agent_review` ruft sie nicht direkt, sondern ueber
    # `_pruefe_sichtbaren_block`, das die `AgentReviewError` faengt und in NOT_MEASURABLE
    # uebersetzt. Der never-raise-Vertrag der oeffentlichen Flaeche ist damit gewahrt, ohne dass
    # die Bausteine still werden. `derive_limitation_codes` ist reiner Erzeuger: es LIEST ein
    # Predicate, das wir selbst bauen, und wirft ueberhaupt nicht.
    # NACHTRAG 01.09.2026, Zeitsemantik-Policytests 9 bis 20: vier weitere, und die Entscheidung
    # ist bei jeder eine andere Begruendung, nicht dieselbe viermal.
    #   `receipt_digest` und `resolve_receipt_chain` bekommen UNSERE eigenen Umschlaege und ordnen
    #   sie; `resolve_receipt_chain` faengt kaputte Umschlaege bereits selbst ab und ueberspringt
    #   sie (ein eigener Test haelt das fest), `receipt_digest` wirft bei fehlendem payload
    #   ABSICHTLICH — ein Digest ueber nichts waere eine Zahl, die wie eine Tatsache aussieht.
    #   `apply_time_evidence` und `evaluate_time_policy` bekommen die Achsen, die wir selbst
    #   berechnet haben, und eine Policy, die der AUFRUFER benennt — sie konsumieren keine fremden
    #   Bytes und werfen nicht.
    "receipt_digest", "resolve_receipt_chain", "apply_time_evidence", "evaluate_time_policy",
    "disclosure_core_bytes", "disclosure_core_digest", "derive_limitation_codes",
    "body_core_bytes", "body_core_digest", "build_agent_review_statement", "emit_agent_review",
    "findings_root", "prepare_body_for_disclosure", "render_disclosure_block",
    "render_disclosure_line", "replace_disclosure_block",
    "action_outcome_proven",  "anchor_proof_digest",  "build_preimage",  "beacon_audit_challenge",  "beacon_nonce",
    "build_decision_statement",  "build_eval_claim",  "build_evidence_pack",
    "build_initial_sequence",  "build_outcome_statement",  
    "build_relation_statement",  "build_run_ledger_statement",  "build_sample_tree",
    "build_summary_statement",  "build_trust_pack_statement",  "calendar_operator",
    "calendar_operators",  "calendar_uris",  "canonical_profile_name",  "canonicalize",
    "canonicalize_statement",  "catch_probability",  "checkpoint_note",  "claim_warnings",
    "clvm_atom_hash",  "compute_digest",  "compute_dual_hash",  "consistency_proof",
    "create_rfc3161_anchor",  "describe_proof",  "detect_outcome_sequence_gaps",
    "eip191_recover_address",  "emit_bundle",  "emit_decision_receipt",  "emit_eval_receipt",
    "emit_outcome_receipt",  "emit_relation_statement",  "emit_run_ledger",
    "emit_verification_summary",  "enclave_assurance_proven",  "enclave_binding_for",
    "eval_evidence_class",  "eval_results_yaml",  "evaluation_card_hash",
    "executor_trusted_by_role",  "expected_key_id",  "explain_policy",  "export_eval_result_dsse",
    "export_intoto_dsse",  "export_svr_dsse",  "format_tlog_proof",  "generate_mldsa",
    "generate_signer",  "inclusion_proof",  "instantiate_template",
    "issue_enclave_attestation",  "issue_sd_jwt",  "issue_status_list_token",  "issuer_fingerprint",
    "issuer_matches",  "key_id",  "last_ats",  "leaf_hash",  "leaf_node_hash",  "link_runs",
    "lint_policy",  "list_profiles",  "make_disclosure",  "merkle_root_from_layers",
    "merkle_tree_hash",  "nested_closure_violations",  "ots_upgraded_proof_is_self_contained",
    "outcome_execution_proven",  "pae",  "parse_checkpoint_head",  "parse_tlog_proof",
    "policy_anchor_trust",  "policy_expected_aud",  "policy_expired",  "policy_not_yet_valid",
    "policy_warnings",  "prereg_canonical_root",  "prereg_hash",  "present_with_key_binding",
    "profile_aliases",  "profile_path",  "receipt_token",  "receiver_trusted_by_role",  "register",
    "register_anchor_type",  "registered_anchor_types",  "renew_hashtree",  "renew_timestamp",
    "resolve_evidence_ref",  "resolve_hash_alg",  "resolve_policy_source",  "resolve_receiver_ref",
    "resolve_subject",  "root_authenticity_summary",  "root_bytes_from_b64",  "root_from_inclusion",
    "salted_commit",  "sample_opening",  "save_signer",  "sign_checkpoint",  "sign_envelope",
    "sign_mldsa",  "sign_trust_pack",  "statement_content_root",
    "status_claim",  "successor_warning",  "svr_properties",  "tlog_proof_for_bundle",
    "to_eval_result_predicate",  "to_eval_result_statement",  "to_eval_results_entry",
    "to_intoto_statement",  "to_test_result_statement",  "vkey",  "witness_quorum",
})


def _unclassified_public_functions():
    """Oeffentliche Funktionen, die WEDER im Nenner noch bewusst ausserhalb sind. Muss leer sein."""
    entdeckt = {name for _, name, _ in _discover_surfaces()}
    offen = []
    for mod_name in _MODULES:
        try:
            mod = importlib.import_module(f"proofbundle.{mod_name}")
        except Exception:  # noqa: BLE001
            continue
        for name, fn in inspect.getmembers(mod, inspect.isfunction):
            if fn.__module__ != mod.__name__ or name.startswith("_"):
                continue
            if name in entdeckt or name in _OUT_OF_SCOPE:
                continue
            offen.append(f"{mod_name}.{name}")
    return sorted(offen)

def _structural_corpus():
    """Structural hostile inputs on VALID-typed dicts/lists (round 8 — the old sweep only fuzzed 8 wrong TYPES,
    so the recursion/DoS classes were outside the auto-enumerated test by design; the decision/outcome/
    subject_binding RecursionError proved it). Built lazily so import stays cheap."""
    def deep_d(n):
        o = {}
        cur = o
        for _ in range(n):
            nxt = {}
            cur["a"] = nxt
            cur = nxt
        cur["a"] = 1
        return o

    def deep_l(n):
        x = [1]
        for _ in range(n):
            x = [x]
        return x
    return [deep_d(4000), deep_l(4000), {"pad": list(range(200_050))},
            float("nan"), float("inf"), 2 ** 53, 10 ** 400]


def _stub_for(param):
    """A neutral, valid-typed stub for a non-primary required argument (so a missing-arg TypeError is not a
    false escape); the primary argument is the fuzz target, everything else must be plausibly-shaped."""
    ann = str(param.annotation).lower()
    if "bytes" in ann:
        return b""
    if "str" in ann:
        return ""
    if "int" in ann:
        return 0
    if "dict" in ann or "mapping" in ann:
        return {}
    if "bool" in ann:
        return False
    if "sequence" in ann or "list" in ann:
        return []
    return b""


class NeverRaiseSurfaceFamilyProperty(unittest.TestCase):
    def test_discovery_finds_the_expected_surface_family(self):
        surfaces = _discover_surfaces()
        # A regression floor on the denominator itself: if this drops sharply, discovery silently broke and the
        # property below would vacuously pass. 70 at round-8 broadening; allow growth, guard against collapse.
        self.assertGreaterEqual(len(surfaces), 65,
                                f"surface discovery collapsed to {len(surfaces)} — the denominator is broken")

    def test_keine_unklassifizierte_oeffentliche_funktion(self):
        """Der Nenner altert nicht mehr still: neue oeffentliche Funktion -> Entscheidung erzwungen.

        Genau dieser Riegel haette `cosign_*` gemeldet, als es dazukam. Er ersetzt den Bodentest
        NICHT (der wacht gegen Kollaps), er schliesst die andere Richtung: eine Familie, die nie
        drin war.
        """
        offen = _unclassified_public_functions()
        self.assertEqual(
            offen, [],
            "Diese oeffentlichen Funktionen sind weder im never-raise-Nenner noch bewusst "
            "ausserhalb gefuehrt. ENTSCHEIDE je Funktion: nimmt sie untrusted Eingabe entgegen? "
            "Dann gehoert ihr Namensmuster in _NAME_PATTERN. Sonst gehoert sie mit Begruendung "
            f"in _OUT_OF_SCOPE. Unklassifiziert: {offen}")

    def test_no_public_surface_raises_raw_on_hostile_primary(self):
        # Round 8 (v4): sweep BOTH the 8 wrong TYPES and the STRUCTURAL hostile inputs (deep-nest / node-heavy /
        # NaN·Inf·bigint on valid-typed dicts) — the old test fuzzed only types, so every recursion/DoS class
        # was outside the denominator by design (the decision/outcome/subject_binding RecursionError proved it).
        import warnings
        warnings.filterwarnings("ignore")
        corpus = _BAD_PRIMARIES + _structural_corpus()
        escapes = []
        for mod_name, name, fn in _discover_surfaces():
            try:
                params = list(inspect.signature(fn).parameters.values())
            except (ValueError, TypeError):
                continue
            if not params:
                continue
            for bad in corpus:
                args, kwargs = [], {}
                for i, p in enumerate(params):
                    if p.kind in (p.VAR_POSITIONAL, p.VAR_KEYWORD):
                        continue
                    if i == 0:
                        val = bad
                    elif p.default is not inspect.Parameter.empty:
                        continue
                    else:
                        val = _stub_for(p)
                    if p.kind == p.KEYWORD_ONLY:
                        kwargs[p.name] = val
                    else:
                        args.append(val)
                try:
                    fn(*args, **kwargs)              # a returned verdict is acceptable
                except _ACCEPTED:
                    pass                              # a typed fail-closed error is acceptable
                except _FORBIDDEN as exc:
                    escapes.append(f"{mod_name}.{name} on {type(bad).__name__}: raw "
                                   f"{type(exc).__name__}: {exc}")
                except Exception as exc:              # noqa: BLE001 — see below, this is the point
                    # UNCLASSIFIED IS REPORTED, NOT SWALLOWED (2026-08-16). Until this branch existed, an
                    # exception that was neither _ACCEPTED nor _FORBIDDEN propagated straight out of this
                    # loop: the test ended as ERROR and every surface AFTER the offending one was never
                    # reached. The taxonomy's gap did not under-report, it STOPPED MEASURING — and the
                    # damage scaled with iteration position, not with severity. Measured when found:
                    # `emit.load_signer` sat at position 87 of 90, so three surfaces went untested; the
                    # same gap at position 1 would have cost 89.
                    #
                    # A third axis of the same instrument. The module axis (population) and the argument
                    # axis (only position 0) were already known; this is the exception-taxonomy axis.
                    escapes.append(f"{mod_name}.{name} on {type(bad).__name__}: UNCLASSIFIED "
                                   f"{type(exc).__name__}: {exc} — neither accepted nor forbidden; "
                                   f"decide which it is instead of letting it abort the sweep")
        self.assertEqual(escapes, [], "raw type-confusion escapes over the AUTO-DISCOVERED surface family:\n"
                         + "\n".join(escapes))


    def test_var_positional_surfaces_fuzzed_with_hostile_args(self):
        """Round-4 v4 (G4): the primary sweep SKIPS *var_positional params, so *fields aggregators
        (evidence_ladder_*) were called with ZERO args and never fuzzed. Here every all-*args public surface is
        called with hostile elements — this is where the evidence_ladder non-comparable-level escape lived."""
        import warnings
        warnings.filterwarnings("ignore")
        hostile_args = [(123,), ("x",), (None,), ({"level": 1}, {"level": "z"}), ({"level": object()},), (b"b",)]
        escapes = []
        for mod_name, name, fn in _discover_surfaces():
            try:
                params = list(inspect.signature(fn).parameters.values())
            except (ValueError, TypeError):
                continue
            if not any(p.kind == p.VAR_POSITIONAL for p in params):
                continue
            if any(p.kind not in (p.VAR_POSITIONAL, p.VAR_KEYWORD)
                   and p.default is inspect.Parameter.empty for p in params):
                continue  # has a required non-*args param -> covered by the primary/regression tests
            for args in hostile_args:
                try:
                    fn(*args)
                except _ACCEPTED:
                    pass
                except _FORBIDDEN as exc:
                    escapes.append(f"{mod_name}.{name}(*{args!r}): raw {type(exc).__name__}: {exc}")
        self.assertEqual(escapes, [], "raw *var_positional escapes:\n" + "\n".join(escapes))

    def test_round4_nonprimary_regression(self):
        """Generator-hardening (adversarial deep-gate v3): each round-4 re-gate escape becomes a PERMANENT corpus entry so it
        can never silently regress. These are the exact 12 confirmed escapes at HEAD 956cbe5 — a VALID primary
        plus a hostile NON-PRIMARY / nested-sub-field / non-comparable value. Each must terminate fail-closed
        (a returned verdict or a typed _ACCEPTED error), never a raw _FORBIDDEN. Auto-fuzzing cannot reach these
        (they need a valid primary to reach the non-primary sink), so they are pinned explicitly."""
        from proofbundle.evalclaim import check_freshness
        from proofbundle.automation_verdict import automation_summary
        from proofbundle.assurance import evidence_ladder_summary, evidence_ladder_best
        from proofbundle.public_transparency import evaluate_public_transparency
        from proofbundle.policy import evaluate_decision_policy, evaluate_policy
        from proofbundle.relation import evaluate_relations_policy
        C = {"timestamp": "2026-01-01T00:00:00Z"}
        cases = [
            ("check_freshness now=int", lambda: check_freshness(C, None, 123)),
            ("check_freshness max_age=str", lambda: check_freshness(C, "x", None)),
            ("automation references=int", lambda: automation_summary({}, required_checks={"references": 5})),
            ("automation references=bool", lambda: automation_summary({}, required_checks={"references": True})),
            ("evidence_ladder mixed-level", lambda: evidence_ladder_summary({"level": 1}, {"level": "z"})),
            ("evidence_ladder obj-level", lambda: evidence_ladder_best({"level": 1}, {"level": object()})),
            ("evidence_ladder level-only", lambda: evidence_ladder_best({"level": 1})),
            ("evaluate_public_transparency vkeys=int",
             lambda: evaluate_public_transparency("x", {"witnessQuorum": {"threshold": 1}}, witness_vkeys=5)),
            ("evaluate_public_transparency vkeys=bool",
             lambda: evaluate_public_transparency("x", {"witnessQuorum": {"threshold": 1}}, witness_vkeys=True)),
            ("evaluate_decision_policy evidenceRefs=int",
             lambda: evaluate_decision_policy(
                 {"predicate": {"evidenceRefs": 5}}, {"ok": True},
                 {"schema": "proofbundle/trust-policy/v0.2", "policy_id": "p",
                  "decision_receipt": {"required_evidence_relations": ["r"]}}, signer_public_key_b64="abc")),
            ("evaluate_policy non-dict-policy", lambda: evaluate_policy({}, {"ok": True}, 5)),
            ("evaluate_relations require_res=int",
             lambda: evaluate_relations_policy({"require_relation_resolution": 5}, {"edges": []},
                                               successor_key_b64=None)),
            ("evaluate_relations signer=int",
             lambda: evaluate_relations_policy({"relation_signer": 5}, {"edges": [{"relation": "x"}]},
                                               successor_key_b64=None)),
        ]
        escapes = []
        for label, fn in cases:
            try:
                fn()
            except _ACCEPTED:
                pass
            except _FORBIDDEN as exc:
                escapes.append(f"{label}: raw {type(exc).__name__}: {exc}")
        self.assertEqual(escapes, [], "round-4 non-primary regression escapes:\n" + "\n".join(escapes))

    def test_round6_nonprimary_bytes_regression(self):
        """Runde 6, gefunden 04.09.2026 von einer Gegenlese-Linse, NICHT vom Riegel darueber.

        WARUM DER RIEGEL IHN NICHT FAND, und das ist der eigentliche Inhalt dieses Tests: er
        fuzzt AUSSCHLIESSLICH Argument 0 (Zeilen 380-388) — jeder andere Pflichtparameter bekommt
        einen plausiblen Stub, Parameter mit Default werden gar nicht gesetzt. Gemessen sind 87
        von 114 Flaechen mehrstellig; an Position >= 1 entkamen 16 rohe TypeError, alle in
        `check_on_receipt` bei `request_bytes` / `response_bytes`.

        DAS IST BESONDERS SCHARF, WEIL DIE FUNKTION SICH SELBST WIDERSPRACH: ihr eigener
        Kommentar sagt "a caller reaching for a verdict must get a verdict ... this boundary
        catches that and NAMES it instead of propagating it". Genau das tat sie fuer diese zwei
        Parameter nicht.

        DER FIX BRAUCHTE ZWEI STELLEN, und die erste allein war schlimmer als keine: `req_h` auf
        None zu setzen verschob den Absturz nur nach `req_h[:16]`. Beide Punkte sind hier
        gebunden, damit ein Rueckfall an einem von beiden auffaellt.
        """
        import itertools
        from proofbundle.experimental import attested_inference as ai
        werte = (None, 5, 5.0, True, [], {}, (), "x", b"ok", bytearray(b"y"))
        entkommen = []
        for rb, resb in itertools.product(werte, repeat=2):
            try:
                r = ai.check_on_receipt({}, provider="p", nonce="n",
                                        request_bytes=rb, response_bytes=resb)
            except Exception as exc:                              # noqa: BLE001 — das ist der Test
                entkommen.append(f"{type(exc).__name__} bei ({type(rb).__name__}, "
                                 f"{type(resb).__name__}): {exc}")
                continue
            self.assertIsInstance(r, dict, "eine Flaeche, die ein Urteil verspricht, liefert eines")
        self.assertEqual(entkommen, [], "rohe Ausnahmen an Nicht-Primaer-Parametern:\n"
                                        + "\n".join(entkommen))

    def test_round6_der_grund_ist_benannt_nicht_nur_kein_absturz(self):
        """DIE GEGENRICHTUNG. Ein Guard, der nur nicht mehr abstuerzt, aber schweigt, waere die
        naechste Klasse: der Aufrufer bekaeme ein Urteil ohne zu erfahren, dass eine Achse gar
        nicht gemessen wurde. Der Grund steht deshalb im Ergebnis, mit EIGENEM Code — nicht unter
        `evidence.malformed`, denn dort ist die EVIDENZ kaputt und hier die Frage des Aufrufers.

        DAS FELD HEISST `not_measurable`, NICHT `unmeasurable` — die interne Liste traegt den
        einen Namen, das ausgelieferte Feld den anderen. Die erste Fassung dieses Tests las den
        internen Namen und war deshalb rot, obwohl der Guard griff: ein `dict.get` auf einen nie
        geschriebenen Schluessel liefert None und liest sich wie ein fehlender Grund."""
        from proofbundle.experimental import attested_inference as ai
        r = ai.check_on_receipt({}, provider="p", nonce="n", request_bytes=None, response_bytes=b"")
        self.assertIn(ai.REASON_BYTES_NOT_BYTES, (r.get("not_measurable") or []) + (r.get("reasons") or []),
                      f"der Grund muss benannt sein, gemessen: {r}")
        heil = ai.check_on_receipt({}, provider="p", nonce="n", request_bytes=b"a", response_bytes=b"b")
        self.assertNotIn(ai.REASON_BYTES_NOT_BYTES,
                         (heil.get("not_measurable") or []) + (heil.get("reasons") or []),
                         "heile Bytes, trotzdem der Code — dann ordnet er nichts")

    def test_round5_nested_config_subfield_regression(self):
        """Generator-hardening r5: der r5-Re-Gate fand die never-raise-Klasse NICHT konvergierend (5->12->16),
        weil das systemische ``(cfg.get(k) or {})``-Idiom nur FALSY ersetzte und truthy Nicht-Container +
        Listen-Elemente durchliess. Der Klassen-Fix (_as_dict/_as_list + Element-Guards) wird hier gepinnt:
        jedes nested Config-Sub-Feld der verdict-Surfaces mit hostilen Werten (nested + Element-Ebene) MUSS
        fail-closed terminieren, nie ein rohes _FORBIDDEN."""
        from proofbundle import policy, relation
        DP = {"schema": "proofbundle/trust-policy/v0.2", "policy_id": "p"}
        S = {"predicate": {"decisionMaker": {"id": "x"}, "decisionType": "t",
                           "decision": {"verdict": "v"}, "evidenceRefs": [], "policyBoundary": {}},
             "predicateType": "pt"}

        class _R:
            ok = True
            checks = []
        B = {"schema": "v1", "signature": {"alg": "ed25519", "public_key_b64": "a"}, "merkle": {}}
        BAD = [5, "x", [5], {"a": 1}, [{"a": 1}], True, None, [None], ["x", 5]]
        escapes = []

        def run(label, fn):
            try:
                fn()
            except _ACCEPTED:
                pass
            except _FORBIDDEN as exc:
                escapes.append(f"{label}: raw {type(exc).__name__}: {exc}")

        for fld in ("trusted_decision_makers", "allowed_decision_types", "allowed_verdicts",
                    "required_evidence_relations", "accepted_predicate_types", "require_policy_digest"):
            for b in BAD:
                run(f"decision.{fld}={b!r}", lambda f=fld, x=b: policy.evaluate_decision_policy(
                    S, {"ok": True}, {**DP, "decision_receipt": {f: x}}, signer_public_key_b64="abc"))
        for fld in ("signature", "merkle", "anchors", "sd_jwt", "allowed_issuers", "allowed_schema_versions"):
            for b in BAD:
                run(f"policy.{fld}={b!r}", lambda f=fld, x=b: policy.evaluate_policy(B, _R(), {f: x}))
        for fld in ("require_relation_resolution", "relation_signer", "require_relation_target",
                    "reject_superseded"):
            for b in BAD + [{"p": 5}, {"p": {"a": 1}}, {"p": [{"a": 1}]}]:
                run(f"relation.{fld}={b!r}", lambda f=fld, x=b: relation.evaluate_relations_policy(
                    {f: x}, {"edges": [{"relation": "p", "targetDigest": "d", "resolution": "x"}]},
                    successor_key_b64=None))

        # 3.6.3 never-raise residual (adversarial re-audit r7): three P3/P4 direct-low-level-API sinks
        # one param / one list-ELEMENT over from the r5 fix. Each must fail-closed (a returned verdict or a
        # typed _ACCEPTED error), never a raw _FORBIDDEN. See roadmap/3_6_3_never_raise_residual.md.
        # R7-1 — verify_relationship_edges subject_hex: a TRUTHY UNHASHABLE value crashed the {subject_hex}
        #        cycle seed on a RESOLVED edge (TypeError: unhashable type).
        _r7_edge = [{"relation": "supersedes",
                     "targetReceiptDigest": {"digestAlgorithm": "jcs-sha256-v1", "digest": "a" * 64}}]
        _r7_related = {"a" * 64: {"verified": True}}
        for sh in ([1], {1: 2}, {1, 2}, bytearray(b"x"), 5, True):
            run(f"R7-1 verify_relationship_edges subject_hex={type(sh).__name__}",
                lambda x=sh: relation.verify_relationship_edges(_r7_edge, _r7_related, subject_hex=x))
        # R7-2 — evaluate_relations_policy edges ELEMENT non-dict: protects ALL THREE sinks
        #        (relation/resolution :466, signer :481, target :508/510 loops).
        for _sec in ({}, {"require_relation_resolution": ["supersedes"]},
                     {"relation_signer": {"supersedes": {"mode": "same-key"}}},
                     {"require_relation_target": {"supersedes": ["d"]}}):
            for _bad_edges in ([5], ["x"], [None], [[1]], [{"relation": "supersedes"}, 5]):
                run(f"R7-2 evaluate_relations_policy edges={_bad_edges!r}",
                    lambda s=_sec, be=_bad_edges: relation.evaluate_relations_policy(
                        s, {"edges": be}, successor_key_b64=None))
        # R7-2b (3.6.3 adversarial re-audit siblings, iter 1 → 2): non-dict lineage_result crashed the
        # reject_superseded branch (lineage_result.get outside the edges isinstance guard); and an
        # UNHASHABLE edge['relation']/edge['targetDigest'] crashed the dict-key lookup / set-membership.
        for _lr in BAD:
            run(f"R7-2b lineage_result={_lr!r}",
                lambda x=_lr: relation.evaluate_relations_policy({"reject_superseded": True}, x,
                                                                 successor_key_b64=None))
        _full_sec = {"require_relation_resolution": ["supersedes"],
                     "relation_signer": {"supersedes": {"mode": "same-key"}},
                     "require_relation_target": {"supersedes": ["d"]}}
        for _k in ("relation", "targetDigest", "resolution", "verified_under"):
            for _hv in ([1], {1: 2}, {1, 2}, bytearray(b"x"), 5, None):
                run(f"R7-2b edge[{_k}]={type(_hv).__name__}",
                    lambda kk=_k, x=_hv: relation.evaluate_relations_policy(_full_sec, {"edges": [
                        {"relation": "supersedes", "resolution": "VERIFIED", "targetDigest": "d",
                         "verified_under": "vu", kk: x}]}, successor_key_b64="s"))
        # R7-3 — evaluate_policy merkle.trusted_checkpoints ELEMENT non-dict: entry.get('hashAlg') ran
        #        BEFORE _authenticate_trusted_checkpoint's own try/except and escaped raw.
        for _bad_cp in (5, "x", None, [1], True):
            run(f"R7-3 evaluate_policy trusted_checkpoints=[{_bad_cp!r}]",
                lambda c=_bad_cp: policy.evaluate_policy(B, _R(), {"merkle": {"trusted_checkpoints": [c]}}))
        self.assertEqual(escapes, [], "round-5 nested-config-subfield escapes:\n" + "\n".join(escapes))


if __name__ == "__main__":
    unittest.main()
